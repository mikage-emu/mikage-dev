#pragma once

#include <framework/bit_field_new.hpp>
#include <framework/formats.hpp>

#include <range/v3/algorithm/max.hpp>
#include <range/v3/view/transform.hpp>

#include <boost/endian/arithmetic.hpp>
#include <boost/hana/define_struct.hpp>

#include <boost/mp11.hpp>

#include <array>
#include <cstdint>

namespace FileFormat {

using namespace boost::endian;

// Strong typedef of the given argument type to represent a media unit (0x200 bytes)
template<typename T>
struct MediaUnit {
    BOOST_HANA_DEFINE_STRUCT(MediaUnit<T>,
        (T, raw)
    );

    // TODO: Static assert this is representable
    uint64_t ToBytes() const {
        return uint64_t{raw} * 0x200;
    }

    static MediaUnit FromBytes(uint64_t bytes) {
        return { static_cast<T>(bytes / 0x200) };
    }
};
using MediaUnit32 = MediaUnit<uint32_t>;

using Bytes32 = uint32_t;


struct NCCHHeader {
    struct TypeFlags {
        enum ContentType {
            Unspecified          = 0,
            SystemUpdate         = 1,
            InstructionManual    = 2,
            DLPChild             = 3,
            Trial                = 4,
            ExtendedSystemUpdate = 5,
        };
        
        enum FormType {
            NotAssigned            = 0,
            SimpleContent          = 1,
            ExecutableWithoutRomFS = 2,
            Executable             = 3,
        };
        
        BOOST_HANA_DEFINE_STRUCT(TypeFlags,
            (uint8_t, raw)
        );
        
        constexpr auto form_type() { return BitField::v3::MakeFieldOn<0, 2>(this); }
        constexpr auto content_type() { return BitField::v3::MakeFieldOn<2, 6>(this); }
        
        static TypeFlags Make() {
            return TypeFlags{};
        }
    };
    
    BOOST_HANA_DEFINE_STRUCT(NCCHHeader,
        (std::array<uint8_t, 0x100>, signature), // RSA-2048 signature
        (std::array<uint8_t, 4>, magic),         // always "NCCH"

        (MediaUnit32, content_size),             // total size of this file

        (uint64_t, partition_id),                // Always the same as the title id?

        (std::array<uint8_t, 0x8>, unknown),
        (uint64_t, program_id),                  // Always the same as the title id?

        (std::array<uint8_t, 0x10>, unknown2a),

        // Only since system version 5.0 (TODO: Is there some indicator for the presence of this field?)
        (std::array<uint8_t, 0x20>, logo_sha256),

        (std::array<uint8_t, 0x10>, unknown2b),

        (std::array<uint8_t, 0x20>, exheader_sha256),

        // Reduced size of the extended header: Only refers to System Control Info and Access Control Info
        (Bytes32, exheader_size),

        (std::array<uint8_t, 0x7>, unknown3),

        // If non-zero, an additional layer of encryption is used for RomFS and parts of ExeFS
        (uint8_t, crypto_method),

        // 1 = Old3DS, 2 = New3DS
        (uint8_t, platform),

        // Content Type: 0 = Unspecified, 1 = System Update, 2 = Instruction Manual, 3 = Download Play Child, 4 = Trial (Demo), 5 = Extended System Update
        // Form Type: 0 = Not Assigned, 1 = Simple Content, 2 = Executable without RomFS, 3 = Executable
        (uint8_t, type_mask),

        // logarithmic unit size in MediaUnits: unit_size_bytes = 0x200 * 2^unit_size_log2
        (uint8_t, unit_size_log2),

        // 1 = fixed encryption key, 2 = don't mount the romfs, 4 = no content encryption, 0x20 = use 9.6.0 keyY generator
        (uint8_t, flags),

        (MediaUnit32, plain_data_offset),   // Unencrypted plain data
        (MediaUnit32, plain_data_size),
        (MediaUnit32, logo_offset),         // logo (introduced in 5.0.0, it seems?)
        (MediaUnit32, logo_size),
        (MediaUnit32, exefs_offset),        // offset from the start of this file
        (MediaUnit32, exefs_size),
        (MediaUnit32, exefs_hash_message_size),
        (std::array<uint8_t, 0x4>, unknown4),

        (MediaUnit32, romfs_offset),         // offset from the start of this file
        (MediaUnit32, romfs_size),
        (MediaUnit32, romfs_hash_message_size),

        (std::array<uint8_t, 0x4>, unknown5),

        (std::array<uint8_t, 0x20>, exefs_sha256),
        (std::array<uint8_t, 0x20>, romfs_sha256)
    );

    struct Tags : expected_size_tag<0x200> {};

    // Followed by:
    // ExHeader (optional?); 3dbrew erratum: it seems the "access descriptor" that was documented to follow the exheader is already part of this exheader
    // plaintext binary region (optional, CXI only)
    // plaintext logo region (optional, CXI only)
    // ExeFS (optional)
    // RomFS (optional)
};

// Extended Header
struct ExHeader {
    struct CodeSetInfo {
        BOOST_HANA_DEFINE_STRUCT(CodeSetInfo,
            (uint32_t, address),
            (uint32_t, size_pages),
            (uint32_t, size_bytes)
        );
    };

    struct Flags {
        BOOST_HANA_DEFINE_STRUCT(Flags,
            (uint8_t, storage)
        );

        using Fields = v2::BitField::Fields<uint8_t>;

        /// If set, the ExeFS:/.code section is compressed with a LZ77 variant
        auto compress_exefs_code() const { return Fields::MakeOn<0, 1>(this); }
    };

    /// Flags for AccessControlInfo
    struct ACIFlags {
        BOOST_HANA_DEFINE_STRUCT(ACIFlags,
            (uint32_t, storage)
        );

        using Fields = v2::BitField::Fields<uint32_t>;

        /**
         * @note flag1 bits in the primary ACI may be set only if the secondary ACI has them set
         */
        auto flag1() const { return Fields::MakeOn<0, 8>(this); }

        auto flag2() const { return Fields::MakeOn<8, 8>(this); }
        auto flag0() const { return Fields::MakeOn<16, 8>(this); }

        auto ideal_processor() const { return Fields::MakeOn<16, 2>(this); }

        /**
         * Thread priority
         * @todo Figure out whether this is the "default" thread priority
         *       or just the priority of the main thread
         */
        auto priority() const { return Fields::MakeOn<24, 8>(this); }
    };

    /**
     * Descriptor for some kernel capability: There are a number of different
     * descriptor types, each of which has their own structure and fields.
     * The descriptor type is determined by the number of leading ones in
     * the bit pattern of the raw descriptor value.
     *
     * We expose this structure using a visitor pattern: The visit() method
     * checks the descriptor type according to the raw storage value,
     * constructs an appropriate strongly-typed descriptor (see children of the
     * DescriptorTypeBase structure), and calls (an appropriate overload of)
     * the given function object with this descriptor.
     */
    struct ARM11KernelCapabilityDescriptor {
        BOOST_HANA_DEFINE_STRUCT(ARM11KernelCapabilityDescriptor,
            (uint32_t, storage)
        );

        using Fields = v2::BitField::Fields<uint32_t>;

        template<typename CRTP, size_t IdentifierPos>
        struct DescriptorTypeBase {
            uint32_t storage;

            static_assert(IdentifierPos < 32, "Invalid identifying field position: Must be smaller than 32");

            constexpr auto id_field() const { return BitField::v3::MakeFieldOn<IdentifierPos, 32 - IdentifierPos>(static_cast<const CRTP*>(this)); }
            static constexpr auto id_field_ref() { return CRTP{}.id_field().MaxValue() - 1; }

            static CRTP Make() {
                return CRTP{}.id_field().Set(id_field_ref());
            }

            operator ARM11KernelCapabilityDescriptor() const {
                return { storage };
            }
        };

        /// A group of these make up a mask of SVCs that are accessible to the application
        struct SVCMaskTableEntry : DescriptorTypeBase<SVCMaskTableEntry, 27> {
            auto entry_index() const { return Fields::MakeOn<24, 3>(this); }
            auto mask() const { return Fields::MakeOn<0, 24>(this); }
        };

        struct HandleTableInfo : DescriptorTypeBase<HandleTableInfo, 24> {
            // TODO: Verify this is given in terms of handles rather than bytes
            auto num_handles() const { return Fields::MakeOn<0, 19>(this); }
        };

        struct MappedMemoryPage : DescriptorTypeBase<MappedMemoryPage, 20> {
            auto page_index() const { return Fields::MakeOn<0, 20>(this); }
        };

        struct MappedMemoryRange : DescriptorTypeBase<MappedMemoryRange, 22> {
            // TODO: What about bit 21 within storage? Does it need always need to be 0? (it does according to 3dbrew!)

            auto page_index() const { return Fields::MakeOn<0, 20>(this); }

            // TODO: Verify this field...
            auto read_only() const { return Fields::MakeOn<20, 1>(this); }

        };

        struct KernelFlags : DescriptorTypeBase<KernelFlags, 23> {
            /// Allow this application to be debugged (TODO: Verify)
            auto allow_debug() const { return Fields::MakeOn<0, 1>(this); }

            /// Force other applications to be debugged even if they don't have "allow_debug" set (TODO: Verify)
            auto force_debug() const { return Fields::MakeOn<1, 1>(this); }

            /// "Allow non-alphanum" according to 3dbrew?
            auto unknown2() const { return Fields::MakeOn<2, 1>(this); }

            /// If set, the shared page will be mapped with write-permissions into this process
            auto shared_page_writeable() const { return Fields::MakeOn<3, 1>(this); }

            /// "privilege priority" according to 3dbrew?
            auto unknown4() const { return Fields::MakeOn<4, 1>(this); }

            /// "allow main args" according to 3dbrew?
            auto unknown5() const { return Fields::MakeOn<5, 1>(this); }

            /// "shared device memory" according to 3dbrew?
            auto unknown6() const { return Fields::MakeOn<6, 1>(this); }

            /// "Runnable on sleep" according to 3dbrew?
            auto unknown7() const { return Fields::MakeOn<7, 1>(this); }

            /**
             * System/Memory/Base
             * @todo Verify that this does really occupy 4 bits
             * @todo Use the kernel MemoryType enum for this
             */
            auto memory_type() const { return Fields::MakeOn<8, 4>(this); }

            /**
             * If set, the application code is mapped to a virtual memory
             * address specified in the exheader. Otherwise, the standard
             * starting address 0x00100000 is used.
             */
            auto nonstandard_code_address() const { return Fields::MakeOn<12, 1>(this); }

            /// Enable access to the second CPU core (New3DS only)
            auto enable_second_cpu_core() const { return Fields::MakeOn<13, 1>(this); }
        };

        template<typename F>
        struct CheckDescriptorType {
            uint32_t descriptor;
            F& visitor;

            /// Set to true if we found at least one match
            bool match_found = false;

            template<typename T>
            void operator()(boost::mp11::mp_identity<T>) {
                T typed_descriptor = { descriptor };

                auto actual_field = typed_descriptor.id_field()();
                if (actual_field != typed_descriptor.id_field_ref())
                    return;

                match_found = true;

                T ret;
                ret.storage = descriptor;
                visitor(ret);
            }
        };

        /**
         * Determines the type of this descriptor, constructs a strongly-typed
         * variant of it (see children of DescriptorTypeBase), and calls the
         * given visitor with it.
         *
         * If no known strongly-typed descriptor exists (or the raw descriptor
         * is just an invalid descriptor in the first place), the visitor is
         * called with the raw uint32_t descriptor value.
         */
        template<typename F>
        auto visit(F&& visitor) {
            using namespace boost::mp11;

            // TODO: Order these by increasing number of leading zeroes
            using all_types = mp_transform<mp_identity, mp_list<SVCMaskTableEntry, HandleTableInfo, MappedMemoryPage, MappedMemoryRange, KernelFlags>>;

            auto checker = CheckDescriptorType<F>{storage, visitor};
            auto checker2 = boost::mp11::mp_for_each<all_types>(checker);
            if (!checker2.match_found)
                return visitor(storage);
        }
    };

    struct AccessControlInfo {
        BOOST_HANA_DEFINE_STRUCT(AccessControlInfo,
            // "ARM11 Local System Capabilities"
            (uint64_t, program_id),

            // Checked against the lower word in the FIRM title id?
            (uint32_t, version),

            (ACIFlags, flags),

            // Resource limit descriptors + storage info
            (std::array<uint8_t, 0x40>, unknown5),
            (std::array<std::array<uint8_t, 8>, 0x20>, service_access_list),
            (std::array<uint8_t, 0x20>, unknown6),

            (std::array<ARM11KernelCapabilityDescriptor, 28>, arm11_kernel_capabilities),

            // "ARM9 access control"
            (std::array<uint8_t, 0x20>, unknown7)
        );

        struct Tags : expected_size_tag<0x200> {};
    };

    BOOST_HANA_DEFINE_STRUCT(ExHeader,
        // Begin of "System Control Info"
        (std::array<unsigned char, 8>, application_title),

        (std::array<unsigned char, 5>, unknown),

        (Flags, flags),

        (uint16_t, remaster_version), // ???

        (CodeSetInfo, section_text),
        (uint32_t, stack_size),
        (CodeSetInfo, section_ro),
        (std::array<uint8_t, 0x4>, unknown3),
        // data section information is exclusive of bss
        (CodeSetInfo, section_data),
        (uint32_t, bss_size),

        // Title IDs of dependencies (0 if entry unused)
        (std::array<uint64_t, 0x30>, dependencies),

        (uint64_t, save_data_size),

        (uint64_t, jump_id), // Seems to be some sort of title id???
        (std::array<uint8_t, 0x30>, unknown4),
        // End of "System Control Info"

        /**
         * Primary ACI. Specifies the actual parameters that are used for
         * access control, while the secondary ACI (see below) restricts the
         * set of valid parameters specified in the primary one. This scheme
         * allows game developers to choose what privileges to give to their
         * applications while keeping the console vendor in control over the
         * maximum set of privileges they can possibly have.
         */
        (AccessControlInfo, aci),

        /// RSA2048-SHA256 signature covering ncch_sig_pub_key and aci_limits
        (std::array<uint8_t, 0x100>, subsignature),

        /// Public key for use in NCCH RSA2048-SHA256 signatures
        (std::array<uint8_t, 0x100>, ncch_sig_pub_key),

        /**
         * The secondary ACI, signed by Nintendo (signature given above) as a
         * limitation to the first ACI; if the first ACI does not match the
         * contents of the second, the system will refuse to boot this title.
         *
         * For retail applications, there is not much point in this since the
         * entity who signed the ExHeader will likely be the same as the one
         * who signed the second ACI. However, for debug unit builds (where
         * game developers can self-sign their titles), the second ACI can
         * not be changed without breaking the signature, hence it keeps
         * developers from requesting privileges for the application that
         * they should not be using on retail units.
         *
         * @todo Figure out and document what specifically "limitation" means here
         */
        (AccessControlInfo, aci_limits)
    );

    struct Tags : expected_size_tag<0x800> {};
};

struct ExeFSHeader {
    struct FileHeader {
        BOOST_HANA_DEFINE_STRUCT(FileHeader,
            (std::array<uint8_t, 8>, name), // ".code", "logo", "banner", or "icon"
            (uint32_t, offset),            // byte offset starting after the ExeFS header
            (uint32_t, size_bytes)
        );
    };

    BOOST_HANA_DEFINE_STRUCT(ExeFSHeader,
        // TODO: Confirm that 10 files is indeed the maximum
        (std::array<FileHeader, 10>, files),
        (std::array<uint8_t, 0x20>, unknown),
        // Hashes for each ExeFS file; stored in reverse order, i.e. the last hashes element corresponds to the first file
        (std::array<std::array<uint8_t, 0x20>, 10>, hashes)
    );

    uint64_t GetExeFSSize() const {
        using ranges::v3::max;
        using ranges::v3::view::transform;
        auto end_offset = [](auto& file) { return file.offset + file.size_bytes; };

        // TODO: Don't hardcode the header size!
        return 0x200 + max(files | transform(end_offset));
    }

    struct Tags : expected_size_tag<0x200> {};

    static constexpr const char code_section_name[8] = ".code\0\0";
};

struct RomFSLevel3Header {
    BOOST_HANA_DEFINE_STRUCT(RomFSLevel3Header,
        (uint32_t, header_size), // in bytes
        // Offsets and sizes are measured in bytes.
        // Offsets are all from start of this header.
        (uint32_t, dir_hash_offset),
        (uint32_t, dir_hash_size),
        (uint32_t, dir_metadata_offset),
        (uint32_t, dir_metadata_size),
        (uint32_t, file_hash_offset),
        (uint32_t, file_hash_size),
        (uint32_t, file_metadata_offset),
        (uint32_t, file_metadata_size),
        (uint32_t, file_data_offset)
    );

    struct Tags : expected_size_tag<0x28> {};
};

struct RomFSFileMetadata {
    BOOST_HANA_DEFINE_STRUCT(RomFSFileMetadata,
        // Offsets and sizes are all measured in bytes.
        (uint32_t, parent_dir_index), // index within directory metadata table
        (uint32_t, unknown2),
        (uint64_t, data_offset),      // from start of file data section
        (uint64_t, data_size),
        (uint32_t, unknown5),
        (uint32_t, name_size)         // length of name in bytes (NOTE: Actual filename data size is aligned to 4 bytes)
    );

    struct Tags : expected_size_tag<0x20> {};
};

struct NCSDHeader {
    struct Partition {
        BOOST_HANA_DEFINE_STRUCT(Partition,
            (MediaUnit32, offset), // from start of file
            (MediaUnit32, size)
        );
    };
    
    struct CartHeader {
        BOOST_HANA_DEFINE_STRUCT(CartHeader,
            (std::array<uint8_t, 32>, exheader_sha256),
            (uint32_t, additional_header_size),
            (uint32_t, sector0_offset),
            (uint64_t, partition_flags),
            (std::array<uint64_t, 8>, partition_id_table),
            (std::array<uint8_t, 0x30>, unknown)
        );
        
        struct Tags : expected_size_tag<0xA0> {};
    };
    
    struct NANDHeader {
        BOOST_HANA_DEFINE_STRUCT(NANDHeader,
            (std::array<uint8_t, 0x5E>, unknown),
            (std::array<uint8_t, 0x42>, encrypted_twl_mbr)
        );
        
        struct Tags : expected_size_tag<0xA0> {};
    };
    
    union NCSDExtendedHeader {
        BOOST_HANA_DEFINE_STRUCT(NCSDExtendedHeader,
            (CartHeader, cart_header),
            (NANDHeader, nand_header)
        );
        
        struct Tags : expected_size_tag<0xA0> {};
    };

    BOOST_HANA_DEFINE_STRUCT(NCSDHeader,
        (std::array<uint8_t, 0x100>, signature), // RSA-2048 SHA-256 signature of this header (starting from magic?)
        (std::array<uint8_t, 4>, magic),         // always "NCSD"
        (MediaUnit32, size),                     // total NCSD size
        (std::array<uint8_t, 0x18>, unknown),
        (std::array<Partition, 8>, partition_table),
        (NCSDExtendedHeader, extended_header)
    );

    struct Tags : expected_size_tag<0x200> {};
};

}  // namespace FileFormat
