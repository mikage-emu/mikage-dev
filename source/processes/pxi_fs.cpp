#include "fs_common.hpp"
#include "pxi.hpp"
#include "os.hpp"

#include "platform/crypto.hpp"
#include "platform/file_formats/ncch.hpp"
#include "platform/pxi.hpp"

#include <framework/exceptions.hpp>

#include "pxi_fs.hpp"
#include "pxi_fs_file_buffer_emu.hpp"
#include "range/v3/algorithm/transform.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

#include <range/v3/algorithm/copy.hpp>
#include <range/v3/algorithm/equal.hpp>
#include <range/v3/algorithm/fill.hpp>
#include <range/v3/view/counted.hpp>
#include <range/v3/view/reverse.hpp>
#include <range/v3/view/zip.hpp>

#include <sstream>
#include <iomanip>

#include <fmt/ranges.h>

// Hardcoded size for PXI buffers.
// TODO: These buffers should only be 0x1000 bytes large, but our PXI tables currently may span more than that because they map individual pages as entries
const auto pxi_static_buffer_size = 0x2000;

namespace HLE {

// namespace OS {

namespace PXI {

std::array<uint8_t, 16> GenerateAESKey(const std::array<uint8_t, 16>& key_x, const std::array<uint8_t, 16>& key_y) {
    std::array<uint8_t, 16> key_gen_constant = { 0x1f, 0xf9, 0xe9, 0xaa, 0xc5, 0xfe, 0x04, 0x08, 0x02, 0x45, 0x91, 0xdc, 0x5d, 0x52, 0x76, 0x8a };

    std::array<uint8_t, 16> key = key_x;

    // ROL 2
    for (unsigned i = 0, overflow = (key[0] >> 6); i < key.size(); ++i) {
        auto new_overflow = key[15 - i] >> 6;
        key[15 - i] <<= 2;
        key[15 - i] |= overflow;
        overflow = new_overflow;
    }

    std::transform(key.begin(), key.end(), key_y.begin(), key.begin(), std::bit_xor<>{}); // (X ROL 2) XOR Y

    // Add constant
    for (int i = key.size() - 1, carry = 0; i >= 0; --i) {
        auto result = uint16_t { key[i] } + key_gen_constant[i] + carry;
        key[i] = static_cast<uint8_t>(result);
        carry = result >> 8;
    }

    // ... ROR 41 == ROL 88 and ROR 1
    std::rotate(key.begin(), key.begin() + 11, key.end());
    for (unsigned i = 0, overflow = (key.back() & 1); i < key.size(); ++i) {
        auto new_overflow = key[i] & 1;
        key[i] >>= 1;
        key[i] |= overflow << 7;
        overflow = new_overflow;
    }

    return key;
}

using PAddr = OS::PAddr;
using Thread = OS::Thread;

PXIBuffer::PXIBuffer(const IPC::StaticBuffer& other) : IPC::StaticBuffer(other) {
}

template<typename DataType>
DataType PXIBuffer::Read(Thread& thread, uint32_t offset) const {
    static_assert(Meta::is_same_v<DataType, uint8_t> || Meta::is_same_v<DataType, uint32_t> || Meta::is_same_v<DataType, uint64_t>, "");

    if (offset != (offset & uint32_t{~uint32_t{sizeof(DataType) - 1}}))
        throw std::runtime_error("Improper address alignment: Might cross the page boundary");

    auto& process = thread.GetParentProcess();
    auto address = LookupAddress(thread, offset);

    if (std::is_same<DataType, uint8_t>::value)
        return process.ReadPhysicalMemory(address);
    else if (std::is_same<DataType, uint32_t>::value)
        return process.ReadPhysicalMemory32(address);
    else if (std::is_same<DataType, uint64_t>::value)
        return uint64_t{process.ReadPhysicalMemory32(address)} | (uint64_t{process.ReadPhysicalMemory32(address + 4)} << uint64_t{32});
    // TODO: Other sizes...
}

template uint8_t PXIBuffer::Read(Thread&, uint32_t) const;
template uint32_t PXIBuffer::Read(Thread&, uint32_t) const;
template uint64_t PXIBuffer::Read(Thread&, uint32_t) const;

template<typename DataType>
void PXIBuffer::Write(Thread& thread, uint32_t offset, DataType value) const {
    static_assert(Meta::is_same_v<DataType, uint8_t> || Meta::is_same_v<DataType, uint32_t> || Meta::is_same_v<DataType, uint64_t>, "");

    if (offset != (offset & uint32_t{~uint32_t{sizeof(DataType) - 1}}))
        throw std::runtime_error("Improper address alignment: Might cross the page boundary");

    auto& process = thread.GetParentProcess();
    auto address = LookupAddress(thread, offset);
    if (std::is_same<DataType, uint8_t>::value)
        return process.WritePhysicalMemory(address, value);
    else if (std::is_same<DataType, uint32_t>::value)
        return process.WritePhysicalMemory32(address, value);
    else if (std::is_same<DataType, uint64_t>::value) {
        process.WritePhysicalMemory32(address + 0, value & 0xFFFFFFFF);
        process.WritePhysicalMemory32(address + 4, value >> 32);
        return;
    }
    // TODO: Other sizes...
}

uint32_t PXIBuffer::LookupAddress(Thread& thread, uint32_t offset) const {
    auto& process = thread.GetParentProcess();

    if (chunks.empty()) {
        // Cache static buffer data

        uint32_t table_addr = addr;
        while (table_addr - addr < size) {
            if (table_addr - addr >= pxi_static_buffer_size)
                throw std::runtime_error("Given PXI table exceeds PXI static buffer size");

            // TODO: This currently assumes the page table is contiguous in memory!
            //       This is normally not an issue (since the PXI page table only occupies one page),
            //       but as an internal workaround we currently have our PXI services use two pages for the tables,
            //       so this assumption might break...
            PAddr chunk_addr = process.ReadPhysicalMemory32(table_addr);
            PAddr current_chunk_size = process.ReadPhysicalMemory32(table_addr + 4);

            // NOTE: The current PXI buffer memory access logic is optimized
            //       for the assumption that all memory chunks (other than the
            //       first and last one) are exactly 0x1000 bytes large. Since
            //       we currently control the generation of all PXI buffer
            //       descriptors, this is not an issue, but this assumption
            //       will need to be dropped once we low-level emulate the
            //       official ARM11 PXI module. To make sure this will not be
            //       forgotten, we add a safety check here.
            if (!chunks.empty() && !(current_chunk_size == 0x1000 || table_addr - addr + 8 == size))
                throw std::runtime_error(fmt::format("Invalid chunk of size {:#x} at address {:#x}: Apart from the first and last chunk, all chunks must be page-sized",
                                                     current_chunk_size, table_addr));

            if (chunks.size() < 2)
                chunk_size = current_chunk_size;

            chunks.emplace_back(ChunkDescriptor{chunk_addr, current_chunk_size});

            table_addr += 8;
        }

        if (chunks.empty())
            throw std::runtime_error("Malformed PXI buffer descriptor");
    }

    // Special-case for the first address since that one may be smaller than a page
    PAddr first_chunk_size = chunks[0].size_in_bytes;
    if (offset < first_chunk_size)
        return chunks[0].start_addr + offset;

    // All chunks other than the first and last one are page-sized, so we
    // rebase the offset to the second chunk address so that we can find the
    // chunk index easily by dividing the new offset by the page size
    offset -= first_chunk_size;

    auto chunk_index = 1 + (offset / chunk_size);
    if (chunk_index >= chunks.size())
        throw std::runtime_error(fmt::format("Trying to access PXI buffer at invalid offset {:#x}", offset));

    auto& chunk = chunks[chunk_index];
    PAddr current_chunk_size = chunk.size_in_bytes;

    if (current_chunk_size < (offset & (chunk_size - 1)))
        throw std::runtime_error(fmt::format("Trying to access PXI buffer at invalid offset {:#x} (selected chunk size is {:#x})", offset, current_chunk_size));

    return chunk.start_addr + (offset & (chunk_size - 1));
}

template void PXIBuffer::Write(Thread&, uint32_t, uint8_t) const;
template void PXIBuffer::Write(Thread&, uint32_t, uint32_t) const;
template void PXIBuffer::Write(Thread&, uint32_t, uint64_t) const;

} // namespace PXI

// } // namespace OS

namespace PXI {

namespace FS {

using OS::Result;
using OS::FakeThread;
using OS::Thread;
using OS::RESULT_OK;
using OS::ThreadPrinter;
using OSImpl = OS::OS;

std::string PrintEntirePXIBuffer(Thread& thread, const PXIBuffer& buf, size_t size, const char* prefix) {
    // TODO: Re-enable, or something
    std::stringstream ss;
//     ss << '\n'; // whatever, just make it easy to filter out the mess that spdlog adds at the beginning
//     for (size_t i = 0; i < size; ++i) {
//         if ((i % 4) == 0)
//             ss << prefix << " ";
//         ss << std::hex << std::setw(2) << std::setfill('0') << +buf.Read<uint8_t>(thread, i);
//         if ((i % 4) == 3)
//             ss << '\n';
//     }
    return ss.str();
}


void FileBufferInHostMemory::Write(char* source, uint32_t num_bytes) {
    if (num_bytes > size) {
        throw std::runtime_error("Writing out of FileBuffer bounds");
    }
    memcpy(memory, source, num_bytes);
}

void File::Fail() {
    throw std::runtime_error("Unspecified error in PXI file operation");
}

OS::ResultAnd<> File::Open(FileContext& context, OpenFlags flags) {
    return Open(context, flags);
}

OS::ResultAnd<uint32_t> File::Read(FileContext&, uint64_t offset, uint32_t num_bytes, FileBuffer&& dest) {
    Fail();
}

OS::ResultAnd<uint32_t> File::Overwrite(FakeThread& thread, uint64_t offset, uint32_t num_bytes, const PXIBuffer& data) {
    Fail();
}

std::pair<Result,std::unique_ptr<File>> Archive::OpenFile(FakeThread& thread, const HLE::CommonPath& path) {
    auto handler = [&,this](const auto& path) { return OpenFile(thread, path); };
    return path.Visit(handler, handler);;
}

std::pair<Result,std::unique_ptr<File>> Archive::OpenFile(FakeThread& thread, const HLE::Utf8PathType& path) {
    thread.GetLogger()->info("OpenFile on dummy archive: Stubbed");
    return { 0, nullptr };
}

std::pair<Result,std::unique_ptr<File>> Archive::OpenFile(FakeThread& thread, const HLE::BinaryPathType& path) {
    thread.GetLogger()->info("OpenFile on dummy archive: Stubbed");
    return { 0, nullptr };
}


class Archive0x567890b0 final : public Archive {
    // Unimplemented
};

class ArchiveSystemSaveData final : public Archive {
    std::string base_path;

    std::pair<Result,std::unique_ptr<File>> OpenFile(FakeThread& thread, const HLE::BinaryPathType& path) override {
        if (path.size() != 8)
            throw std::runtime_error("Invalid file path for SystemSaveData archive: Expected 8 bytes describing the save id");

        auto file_path = base_path;

        boost::endian::little_uint64_buf_t saveid_buf;
        memcpy(&saveid_buf, path.data(), path.size());
        uint64_t saveid = saveid_buf.value();
        file_path += fmt::format("{:08x}", saveid & 0xFFFFFFFF);
        file_path += "/";
        file_path += fmt::format("{:08x}", saveid >> 32);

        // TODO: Drop now unused and unimplemented HostFile::PatchHash
        auto file = std::make_unique<HostFile>(file_path, HostFile::PatchHash);
        return std::make_pair(RESULT_OK, std::move(file));
    }

public:
    ArchiveSystemSaveData(Settings::Settings& settings, uint32_t media_type) {
        switch (media_type) {
        case 0:
            // TODO: This ID is actually generated from data in moveable.sed
            std::array<uint8_t, 0x10> id0;
            ranges::fill(id0, 0);
            base_path = (GetRootDataDirectory(settings) / "data" / fmt::format("{:02x}", fmt::join(id0, "")) / "sysdata").string();
            break;

        default:
            throw std::runtime_error("Unknown media type");
        }
    }
};

class AESDecryptingFileBufferView : public FileBuffer {
    FileBuffer& buffer;
    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption& dec;

public:
    AESDecryptingFileBufferView(FileBuffer& buffer, CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption& dec) : buffer(buffer), dec(dec) {

    }

    void Write(char* source, uint32_t num_bytes) override {
        // TODO: Use a CryptoPP pipeline instead to avoid the heap allocation?
        std::vector<CryptoPP::byte> data(num_bytes);
        dec.ProcessData(data.data(), reinterpret_cast<const CryptoPP::byte*>(source), num_bytes);
        buffer.Write(reinterpret_cast<char*>(data.data()), num_bytes);
    }
};

class AESEncryptedFile final : public File {
    std::unique_ptr<File> file;
    uint64_t aes_offset;
    std::array<uint8_t, 16> key;
    std::array<uint8_t, 16> iv;

public:
    AESEncryptedFile(std::unique_ptr<File> file, uint64_t aes_offset, const std::array<uint8_t, 16>& key, const std::array<uint8_t, 16>& iv)
        : file(std::move(file)), aes_offset(aes_offset), key(key), iv(iv) {
    }

    OS::ResultAnd<> Open(FileContext& context, OpenFlags flags) override {
        return file->Open(context, flags);
    }

    OS::ResultAnd<uint64_t> GetSize(FileContext& context) override {
        return file->GetSize(context);
    }

    OS::ResultAnd<uint32_t> Read(FileContext& context, uint64_t offset, uint32_t num_bytes, FileBuffer&& dest) override {
        if (num_bytes == 0) {
            return std::make_pair(OS::RESULT_OK, uint32_t { 0 });
        }

        CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), sizeof(key), iv.data());
        dec.Seek(aes_offset + offset);

        AESDecryptingFileBufferView dest_view { dest, dec };
        return file->Read(context, offset, num_bytes, std::move(dest_view));
    }
};

class DummyExeFSFile final : public File {
public:
    DummyExeFSFile() {}

    OS::ResultAnd<> Open(FileContext&, OpenFlags) override {
        return { RESULT_OK };
    }

    OS::ResultAnd<uint64_t> GetSize(FileContext&) override {
        return { RESULT_OK, uint64_t { 1 } };
    }

    OS::ResultAnd<uint32_t> Read(FileContext&, uint64_t off, uint32_t num_bytes, FileBuffer&& buf) override {
        if (off != 0) {
            throw std::runtime_error("ERROR");
        }
        char null = 0;
        for (; off != num_bytes; ++off) {
            buf.Write(&null, 1);
        }
        return { RESULT_OK, uint32_t { num_bytes } };
    }

    void Close() override {
    }
};

// @pre "Open" must have been called on ncch before using this function
std::unique_ptr<File> NCCHOpenExeFSSection(spdlog::logger& logger, FileContext& file_context, const KeyDatabase& keydb, std::unique_ptr<File> ncch, uint8_t sub_file_type, std::basic_string_view<uint8_t> requested_exefs_section_name) {
    auto ncch_offset = uint64_t{0};
    auto read_host_file = [&](char* dest, size_t size) {
        ncch->Read(file_context, ncch_offset, static_cast<uint32_t>(size), FileBufferInHostMemory { dest, static_cast<uint32_t>(size) });
        ncch_offset += size;
    };

    auto ncch_header = FileFormat::SerializationInterface<FileFormat::NCCHHeader>::Load(read_host_file);
    if (memcmp(ncch_header.magic.data(), "NCCH", sizeof(ncch_header.magic)) != 0) {
        throw std::runtime_error("NCCH header word not found. Corrupt ROM?");
    }

    bool is_encrypted = !(ncch_header.flags & 4);
    std::array<uint8_t, 16> keys[2] {}; // 0: Secure1 (system version < 7.x), 1: Secure2 (system version >= 7.x)
    std::array<uint8_t, 16> iv {};
    if (!is_encrypted) {
        // No encryption
    } else if ((ncch_header.flags & 1) && (ncch_header.program_id >> 32) != 0x40130) {
        // Encrypt with an all-zeroes key
    } else if (is_encrypted) {
        if (ncch_header.crypto_method > 1) {
            throw Mikage::Exceptions::Invalid("Invalid NCCH encryption method");
        }

        const std::array<uint8_t, 16>& key_x_0x25 = keydb.aes_slots[0x25].x.value();
        const std::array<uint8_t, 16>& key_x_0x2c = keydb.aes_slots[0x2c].x.value();
        std::array<uint8_t, 16> key_y;
        memcpy(key_y.data(), &ncch_header, sizeof(key_y));
        keys[0] = GenerateAESKey(key_x_0x2c, key_y);
        keys[1] = GenerateAESKey(key_x_0x25, key_y);

        // First 8 bytes are the partition id interpreted as big-endian
        // TODO: Should be version dependent? version==1 has different behavior, apparently
        memcpy(iv.data(), &ncch_header.partition_id, sizeof(ncch_header.partition_id));
        std::reverse(iv.begin(), iv.begin() + 8);
    }

    // TODO: Check if seed encryption is enabled

    switch (sub_file_type) {
    case 0: // RomFS
    {
        iv[8] = 3;

        // TODO: Cleanup. Currently adapted from FS-HLE code
        // TODO: Verify the given archive even has a RomFS!
        auto offset = ncch_header.romfs_offset.ToBytes();
        auto romfs_size = ncch_header.romfs_size.ToBytes();

        auto ncch_start = 0;
        auto ivfc_start = ncch_start + static_cast<std::ifstream::off_type>(offset);

// TODO: Apply decryption to this check
        char ivfc_header[5] {};
        ncch->Read(file_context, ivfc_start, 4, FileBufferInHostMemory { ivfc_header, 4 });
        if (is_encrypted && ivfc_header == std::string_view { "IVFC" }) {
            // Signature present even though encryption flags are set => override
            is_encrypted = false;
        }
        if (ivfc_header != std::string_view { "IVFC" } && !is_encrypted) {
            throw Mikage::Exceptions::Invalid("Invalid RomFS");
        }

/*        std::cerr << "ivfc offset: 0x" << std::hex << ivfc_start-ncch_start << std::endl;
ncch.seekg(ivfc_start + static_cast<std::ifstream::off_type>(0x3c)); // offset in IVFC to level 3 entry offset
boost::endian::little_uint32_t level3_offset;
ncch.read(reinterpret_cast<char*>(&level3_offset), sizeof(level3_offset));
std::cerr << "level3 offset: 0x" << std::hex << level3_offset << std::endl;*/

        // Close so that FileView can open it again (TODO: Can we design this less stupidly?)
        ncch->Close(/*thread*/);
        std::unique_ptr<File> ret = std::make_unique<FileView>(std::move(ncch), ivfc_start, romfs_size);
        if (is_encrypted) {
            ret = std::make_unique<AESEncryptedFile>(std::move(ret), 0, keys[ncch_header.crypto_method], iv);
        }
        return ret;
    }

    // Open the ExeFS section specified by the remainder of the file path
    case 1:
    case 2:
    {
        // Titles built for firmware 5.0.0 or newer don't store the logo in the
        // ExeFS but instead in the plaintext NCCH region.
        const char logo_name[8] = { 0x6c, 0x6f, 0x67, 0x6f };
        if (ranges::equal(logo_name, requested_exefs_section_name) &&
            ncch_header.logo_offset.ToBytes() && ncch_header.logo_size.ToBytes()) {
            return std::make_unique<FileView>(std::move(ncch), ncch_header.logo_offset.ToBytes(), ncch_header.logo_size.ToBytes(), ncch_header.logo_sha256);
        }

        iv[8] = 2;

        // TODO: Verify the given archive even has an ExeFS!
        ncch_offset = ncch_header.exefs_offset.ToBytes();
        FileFormat::ExeFSHeader exefs_header;// = FileFormat::SerializationInterface<FileFormat::ExeFSHeader>::Load(read_host_file);
        read_host_file(reinterpret_cast<char*>(&exefs_header), sizeof(exefs_header)); // TODO: Use SerializationInterface

        // TODO: Look for common section strings instead
        if (is_encrypted && exefs_header.files[0].offset == 0) {
            // Looks like a decrypted ExeFS => override encryption flags
            is_encrypted = false;
        }

if (is_encrypted) {
        // ExeFS header always uses Secure1 for encryption
        CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(keys[0].data(), sizeof(keys[0]), iv.data());
        dec.ProcessData(reinterpret_cast<CryptoPP::byte*>(&exefs_header), reinterpret_cast<const CryptoPP::byte*>(&exefs_header), sizeof(exefs_header));
}

        // SerializationInterface not used currently because it triggers subcomplete reads on 3DSX files
//        auto exefs_header = FileFormat::SerializationInterface<FileFormat::ExeFSHeader>::Load(read_host_file);
        for (auto exefs_section_and_hash : ranges::views::zip(exefs_header.files, exefs_header.hashes | ranges::views::reverse)) {
            auto& exefs_section = std::get<0>(exefs_section_and_hash);
            auto& section_hash = std::get<1>(exefs_section_and_hash);
            if (ranges::equal(exefs_section.name, requested_exefs_section_name)) {
                // TODO: Print the actual section name in the log
                logger.info("Found section at post-exefs-header offset {:#x} with {:#x} bytes (ExeFS at {:#x})",
                            exefs_section.offset, exefs_section.size_bytes, ncch_offset);
                auto data_offset = ncch_header.exefs_offset.ToBytes() + FileFormat::ExeFSHeader::Tags::expected_serialized_size + exefs_section.offset;

                // Close so that FileView can open it again (TODO: Can we design this less stupidly?)
                ncch->Close(/*thread*/);
                std::unique_ptr<File> ret = std::make_unique<FileView>(std::move(ncch), data_offset, exefs_section.size_bytes, section_hash);
                if (is_encrypted) {
                    // TODO: The former check doesn't work!
//                    const auto& key = (!ranges::equal(requested_exefs_section_name, "icon") && !ranges::equal(requested_exefs_section_name, "banner")) ? keys[ncch_header.crypto_method] : keys[0];
//                    const auto& key = (requested_exefs_section_name[0] != 'i' && requested_exefs_section_name[0] != 'l' && requested_exefs_section_name[0] != 'b') ? keys[ncch_header.crypto_method] : keys[0];
                    const auto& key = keys[ncch_header.crypto_method ? (requested_exefs_section_name[0] == '.') : 0];
                    ret = std::make_unique<AESEncryptedFile>(std::move(ret), FileFormat::ExeFSHeader::Tags::expected_serialized_size + exefs_section.offset, key, iv);
                }
                return ret;
            }
        }

        // No match => Panic
        throw std::runtime_error(fmt::format("Couldn't find section {} in ExeFS", reinterpret_cast<const char*>(requested_exefs_section_name.data())));
    }

    default:
        throw std::runtime_error(fmt::format("Unknown ArchiveProgramDataFromTitleId sub file type {:#x}", sub_file_type));
    }
}

std::unique_ptr<File> OpenNCCHSubFile(Thread& thread, Platform::FS::ProgramInfo program_info, uint32_t content_id, uint32_t sub_file_type, std::basic_string_view<uint8_t> file_path, Loader::GameCard* gamecard) {
    std::unique_ptr<File> ncch;

    if (program_info.media_type == 0) {
        // If this title is HLEed, return a dummy ExeFS
        auto hle_title_name = GetHLEModuleName(program_info.program_id);
        if (hle_title_name && thread.GetOS().ShouldHLEProcess(*hle_title_name)) {
            if (content_id != Meta::to_underlying(Loader::NCSDPartitionId::Executable) ||
                sub_file_type != 1) {
                throw std::runtime_error("Reading this type of NCCH data is not supported for HLEed titles");
            }
            return std::make_unique<DummyExeFSFile>();
        }

        auto ncch_filename =    GetRootDataDirectory(thread.GetOS().settings) /
                                fmt::format("{:08x}/{:08x}/content/{:08x}.cxi",
                                            program_info.program_id >> 32, program_info.program_id & 0xFFFFFFFF, content_id);
        ncch = std::make_unique<HostFile>(ncch_filename.string(), HostFile::Default);
    } else if (gamecard && program_info.media_type == 2) {
        if (content_id > Meta::to_underlying(Loader::NCSDPartitionId::UpdateData)) {
            throw Mikage::Exceptions::Invalid("Invalid NCSD partition index {}", content_id);
        }

        auto ncch_opt = gamecard->GetPartitionFromId(static_cast<Loader::NCSDPartitionId>(content_id));
        if (!ncch_opt)
            throw std::runtime_error("Couldn't open gamecard image");

        ncch = *std::move(ncch_opt);
    } else {
        ValidateContract(false);
    }

    FileContext file_context { *thread.GetLogger() };
    auto result = ncch->OpenReadOnly(file_context);
    if (std::get<0>(result) != RESULT_OK) {
        throw std::runtime_error(fmt::format(   "Tried to access non-existing title {:#x} from emulated NAND.\n\nPlease dump the title from your 3DS and install it manually to this path:\n{}",
                                                program_info.program_id, (char*)file_path.data()));
    }

    return NCCHOpenExeFSSection(*thread.GetLogger(), file_context,
                                thread.GetParentProcess().interpreter_setup.keydb,
                                std::move(ncch), sub_file_type, file_path);
}


namespace {

/**
 * Interface for the application to access RomFS and ExeFS data from any
 * program's NCCH. The FS interface takes a Process Manager program handle
 * to identify different programs, which we translate to a ProgramInfo.
 */
class ArchiveProgramDataFromTitleId : public Archive {
    Platform::FS::ProgramInfo program_info;

    Loader::GameCard* gamecard; // nullptr if none present

protected:
    std::pair<Result,std::unique_ptr<File>> OpenFile(FakeThread& thread, const HLE::BinaryPathType& path) override {
        if (path.size() != 20)
            throw std::runtime_error("Invalid file path for ProgramDataInternal archive: Expected 20 bytes");

        // File path structure (according to archive 0x234567a):
        // * NCCH (0) or save data (1)
        // * TMD content index or NCSD partition index
        // * 0 for romfs (and for save data), 1 for exefs code section, 2 for exefs non-code section
        // * ExeFS section name (two words)

        std::array<boost::endian::little_uint32_buf_t, 3> file_path_u32;
        memcpy(file_path_u32.data(), path.data(), sizeof(file_path_u32));
        uint32_t is_save_data = file_path_u32[0].value();
        uint32_t content_id = file_path_u32[1].value(); // NCSD partition index for game cards
        uint32_t sub_file_type = file_path_u32[2].value();

        if (is_save_data) {
            throw Mikage::Exceptions::NotImplemented("Cannot open save data with this archive yet");
        }

        if (sub_file_type > 2) {
            // TODO: Value 5 has been observed when booting IronFall: Invasion
            throw Mikage::Exceptions::Invalid("Invalid sub file type {}", sub_file_type);
        }

        auto sub_file = OpenNCCHSubFile(thread, program_info, content_id, sub_file_type, std::basic_string_view<uint8_t> { path.data() + 0xc, 8 }, gamecard);
        return std::make_pair(RESULT_OK, std::move(sub_file));
    }

public:
    ArchiveProgramDataFromTitleId(const Platform::FS::ProgramInfo& program_info, Loader::GameCard* gamecard) : program_info(program_info), gamecard(gamecard) {
        if (program_info.media_type == 2) {
            if (!gamecard) {
                throw Mikage::Exceptions::Invalid("Attempted to open game card archive without a game card inserted");
            }
        } else if (program_info.media_type != 0) {
            throw Mikage::Exceptions::NotImplemented("Unknown media type {} (SD is not supported yet)", program_info.media_type);
        }
    }

    virtual ~ArchiveProgramDataFromTitleId() = default;
};

class ArchiveProgramDataFromProgramId final : public ArchiveProgramDataFromTitleId {
    std::pair<Result,std::unique_ptr<File>> OpenFile(FakeThread& thread, const HLE::BinaryPathType& path) override {
        if (path.size() != 12)
            throw std::runtime_error("Invalid file path for ProgramData archive: Expected 12 bytes");

        // Forward this call to ArchiveProgramDataFromTitleId::OpenFile using
        // a new path:
            // * Word 0: NCCH (0) or save data (1)
            // * Word 1: TMD content index or NCSD partition index
            // * Word 2: 0 for romfs (and for save data), 1 for exefs code section, 2 for exefs non-code section
            // * Words 3+4: ExeFS section name
        HLE::BinaryPathType new_file_path;
        new_file_path.resize(20);
        // First word is zero (=NCCH access)
        // Second word is zero (=first content)
        // The remaining data is copied verbatimly
        ranges::copy(ranges::views::counted(path.data(), static_cast<std::ptrdiff_t>(path.size())), new_file_path.begin() + 8);

        return ArchiveProgramDataFromTitleId::OpenFile(thread, new_file_path);
    }

public:
    ArchiveProgramDataFromProgramId(const Platform::FS::ProgramInfo& program_info, Loader::GameCard* gamecard) : ArchiveProgramDataFromTitleId(program_info, gamecard) {
    }
};

} // anonymous namespace

static std::tuple<Result, uint64_t> OpenFile(FakeThread& thread, Context& context, uint32_t transaction, uint64_t archive_handle,
                                             uint32_t path_type, uint32_t path_size, uint32_t flags,
                                             uint32_t attributes, const PXIBuffer& path) {
    thread.GetLogger()->info("{}received OpenFile with archive_handle={:#x}, transaction={:#x}, path_type={:#x}, path_size={:#x}, flags={:#x}, attributes={:#x}",
                             ThreadPrinter{thread}, archive_handle, transaction, path_type, path.size, flags, attributes);

    thread.GetLogger()->info("{}", PrintEntirePXIBuffer(thread, path, path_size, "PXIPXI recv"));

    auto archive_it = context.archives.find(archive_handle);
    if (archive_it == context.archives.end())
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);

    auto& archive = archive_it->second;

    // TODO: Support attributes other than zero! (Currently, this restricts support to non-hidden and writeable files, and excludes support for directories and archives)
    if (attributes != 0) {
        throw Mikage::Exceptions::NotImplemented("Attribute combination {:#x} not supported", attributes);
    }

    HLE::CommonPath common_path(thread, path_type, path_size, path);

    Result result;
    std::unique_ptr<File> file;
    std::tie(result,file) = archive->OpenFile(thread, common_path);
    if (result != RESULT_OK) {
        thread.GetLogger()->error("Failed to get file open handler");
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);
    }

    // TODO: Respect flags & ~0x4 ... in particular, write/read-only!
    if (file) {// TODO: Remove this check! We only do this so that we don't need to implement archive 0x56789a0b0 properly...
    FileContext file_context { *thread.GetLogger() };
    std::tie(result) = file->Open(file_context, { .create = (flags & 0x4) != 0 });
    }
    if (result != RESULT_OK) {
        thread.GetLogger()->warn("Failed to open file");
        return std::make_tuple(result, 0);
    }

    auto file_handle = context.next_file_handle++;
    context.files.emplace(std::make_pair(file_handle, std::move(file)));
    return std::make_tuple(result, file_handle);
}

static std::tuple<Result> DeleteFile(FakeThread& thread, Context& context, uint32_t transaction, uint64_t archive_handle,
                                                 uint32_t path_type, uint32_t path_size, const PXIBuffer& path) {
    thread.GetLogger()->info("{}received STUBBED DeleteFile with archive_handle={:#x}, transaction={:#x}, path_type={:#x}, path_size={:#x}",
                             ThreadPrinter{thread}, archive_handle, path_type, path_size, path.size);

    thread.GetLogger()->info("{}", PrintEntirePXIBuffer(thread, path, path_size, "PXIPXI recv"));
    // TODO: Implement!

    std::string binary_path;
    for (uint32_t offset = 0; offset < path_size; ++offset)
        binary_path += fmt::format("{:02x}", +path.Read<uint8_t>(thread, offset));

    thread.GetLogger()->info(binary_path);

    return std::make_tuple(RESULT_OK);
}

static std::tuple<Result,uint32_t> ReadFile(FakeThread& thread, Context& context, FileHandle file_handle, uint64_t offset, uint32_t num_bytes, const PXIBuffer& dest) {
    thread.GetLogger()->info("{}received ReadFile with file_handle={:#x}: {:#x} bytes from offset={:#x}",
                             ThreadPrinter{thread}, file_handle, num_bytes, offset);

    auto file_it = context.files.find(file_handle);
    if (file_it == context.files.end())
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);

    auto& file = file_it->second;
    thread.GetLogger()->info("File kind: {}", typeid(*file).name());

    FileContext file_context { *thread.GetLogger() };
    auto result_and_bytesread = file->Read(file_context, offset, num_bytes, FileBufferInEmulatedMemory { thread, dest });
    if (std::get<0>(result_and_bytesread) != RESULT_OK /*|| std::get<1>(result_and_bytesread) != num_bytes*/ /* TODO: TESTING ONLY: Works around lack of promo video */)
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);

    thread.GetLogger()->info("{}", PrintEntirePXIBuffer(thread, dest, num_bytes, "PXIPXI send"));

    return result_and_bytesread;
}

static std::tuple<Result> GetFileSHA256(FakeThread& thread, Context& context, FileHandle file_handle, uint32_t buffer_size, const PXIBuffer& dest) {
    thread.GetLogger()->info("{}received GetFileSHA256 with file_handle={:#x}",
                             ThreadPrinter{thread}, file_handle);

    if (buffer_size != 0x20)
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);

    auto file_it = context.files.find(file_handle);
    if (file_it == context.files.end())
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);

    auto* file_view = dynamic_cast<FileView*>(file_it->second.get());
    auto hash = file_view->GetFileHash(thread);

    std::string hash_string;
    for (auto i = 0; i < hash.size(); ++i) {
        dest.Write<uint8_t>(thread, i, hash[i]);
        hash_string += fmt::format("{:02x}", hash[i]);
    }
    thread.GetLogger()->info("Returning hash {}", hash_string);

    thread.GetLogger()->info("{}", PrintEntirePXIBuffer(thread, dest, buffer_size, "PXIPXI send"));

    return std::make_tuple(RESULT_OK);
}

static std::tuple<Result,uint32_t> WriteFile(FakeThread& thread, Context& context, FileHandle file_handle,
                                             uint64_t offset, uint32_t num_bytes, uint32_t flags,
                                             const PXIBuffer& input) {
    thread.GetLogger()->info("{}received WriteFile with file_handle={:#x}: {:#x} bytes to offset={:#x}, flags={:#x}",
                             ThreadPrinter{thread}, file_handle, num_bytes, offset, flags);

    thread.GetLogger()->info("{}", PrintEntirePXIBuffer(thread, input, num_bytes, "PXIPXI recv"));

    auto file_it = context.files.find(file_handle);
    if (file_it == context.files.end())
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);

    auto& file = file_it->second;

    // TODO: Respect the flush flags
    auto result_and_byteswritten = file->Overwrite(thread, offset, num_bytes, input);
    if (std::get<0>(result_and_byteswritten) != RESULT_OK)
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);

    return result_and_byteswritten;
}

static std::tuple<Result> CalcSavegameMAC(FakeThread& thread, Context& context, FileHandle file_handle,
                                          uint32_t output_size, uint32_t input_size,
                                          const PXIBuffer& input, const PXIBuffer& output) {
    thread.GetLogger()->info("{}received CalcSavegameMAC with file_handle={:#x}, input_size={:#x}, output_size={:#x}, input_paddr={:#x}, output_paddr={:#x}",
                             ThreadPrinter{thread}, file_handle, input_size, output_size, input.addr, output.addr);

    thread.GetLogger()->info("{}", PrintEntirePXIBuffer(thread, input, input_size, "PXIPXI recv"));

    // TODO: Properly compute this... Currently, we just return the first 0x10 bytes from the input, which should usually be the expected MAC
    for (unsigned offset = 0; offset < output_size; ++offset) {
//         output.Write<uint8_t>(thread, offset, (offset < 0x10) ? input.Read<uint8_t>(thread, offset) : 0x00);
        // Copying the XDS hack!
        output.Write<uint8_t>(thread, offset, 0x11);
    }

    thread.GetLogger()->info("{}", PrintEntirePXIBuffer(thread, output, output_size, "PXIPXI send"));

    return std::make_tuple(0);
}

static std::tuple<Result, uint64_t> GetFileSize(FakeThread& thread, Context& context, uint64_t file_handle) {
    thread.GetLogger()->info("{}received GetFileSize with file_handle={:#x}",
                             ThreadPrinter{thread}, file_handle);

    auto file_it = context.files.find(file_handle);
    if (file_it == context.files.end())
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);

    auto& file = file_it->second;

    auto file_context = FileContext { *thread.GetLogger() };
    auto result_and_size = file->GetSize(file_context);
    if (std::get<0>(result_and_size) != RESULT_OK)
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);

    return result_and_size;
}

static std::tuple<Result> SetFileSize(FakeThread& thread, Context& context, uint64_t new_size, uint64_t file_handle) {
    thread.GetLogger()->info("{}received SetFileSize with file_handle={:#x} and new_size={:#x}",
                             ThreadPrinter{thread}, file_handle, new_size);

    auto file_it = context.files.find(file_handle);
    if (file_it == context.files.end())
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);

    auto& file = file_it->second;

    Result result;
    std::tie(result) = file->SetSize(thread, new_size);
    if (result != RESULT_OK)
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);

    return std::make_tuple(result);
}

static std::tuple<Result> CloseFile(FakeThread& thread, Context& context, uint64_t file_handle) {
    thread.GetLogger()->info("{}received CloseFile with file_handle={:#x}",
                             ThreadPrinter{thread}, file_handle);

    auto file_it = context.files.find(file_handle);
    if (file_it == context.files.end())
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);

    context.files.erase(file_it);

    return std::make_tuple(RESULT_OK);
}

static std::tuple<Result, uint64_t> OpenArchive(FakeThread& thread, Context& context,
                                                    uint32_t archive_id, uint32_t path_type,
                                                    uint32_t path_size, const PXIBuffer& path) {
    thread.GetLogger()->info("{}received OpenArchive with archive_id={:#x}, path_type={:#x}, path_size={:#x}",
                             ThreadPrinter{thread}, archive_id, path_type, path_size);

    thread.GetLogger()->info("{}", PrintEntirePXIBuffer(thread, path, path_size, "PXIPXI recv"));

    // TODO: Shouldn't check the PXIBuffer table size but instead its actual size!
//     if (path_size > path.size) {
//         thread.GetLogger()->error("{}invalid parameters: Expected at least {:#x} bytes of data, got {:#x}",
//                                   ThreadPrinter{thread}, path_size, path.size);
//         thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);
//     }

    std::string binary_path = "Archive path: ";
    for (uint32_t offset = 0; offset < path_size; ++offset)
        binary_path += fmt::format("{:02x}", +path.Read<uint8_t>(thread, offset));

    thread.GetLogger()->info(binary_path);

    auto& settings = thread.GetOS().settings;

    switch (archive_id) {
    case 0x567890b0:
    {
        // Purpose unknown. This is opened during startup of the FS module
        // but not immediately used.
        auto archive = std::make_unique<Archive0x567890b0>();
        auto archive_handle = context.next_archive_handle++;
        context.archives.emplace(std::make_pair(archive_handle, std::move(archive)));
        return std::make_tuple(RESULT_OK, archive_handle);
    }

    case 0x1234567c:
    {
        // System SaveData stored on NAND
        // TODO: Should we verify that not more than 4 bytes have been given?
        // NOTE: Media type only considers the lowest byte. Services like CFG pass in garbage in the upper bytes.
        auto media_type = path.Read<uint8_t>(thread, 0);
        auto archive = std::make_unique<ArchiveSystemSaveData>(settings, media_type);
        auto archive_handle = context.next_archive_handle++;
        context.archives.emplace(std::make_pair(archive_handle, std::move(archive)));
        return std::make_tuple(RESULT_OK, archive_handle);
    }

    // TODO: Verify this works the same way for both FS and PXIFS
    case 0x2345678a:
    {
        auto program_info = Platform::PXI::PM::ProgramInfo { path.Read<uint64_t>(thread, 0), static_cast<uint8_t>(path.Read<uint32_t>(thread, 0x8) & 0xff) };
        // This has actually been observed to be used when menu tries reading the logos of titles returned from AM::GetTitleList
        // TODO: 3dbrew has a few recent notes about this...
//         if (path.Read<uint32_t>(thread, 0xc) != 0)
//             thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);

        auto archive = std::make_unique<ArchiveProgramDataFromTitleId>(program_info, thread.GetOS().setup.gamecard.get());
        auto archive_handle = context.next_archive_handle++;
        context.archives.emplace(std::make_pair(archive_handle, std::move(archive)));
        return std::make_tuple(RESULT_OK, archive_handle);
    }

    case 0x2345678e:
    {
        auto program_handle = Platform::PXI::PM::ProgramHandle{path.Read<uint64_t>(thread, 0)};
        auto program_info_it = context.programs.find(program_handle);
        if (program_info_it == context.programs.end()) {
            thread.GetLogger()->error("Couldn't find handle {:#x} in program handle table", program_handle.value);
            thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);
        }

        auto& program_info = program_info_it->second.first;
        thread.GetLogger()->info("Opening ArchiveProgramDataFromProgramId for title id {:#x}, media_type {:#x}", program_info.program_id, program_info.media_type);
        auto archive = std::unique_ptr<Archive>(new ArchiveProgramDataFromProgramId(program_info, thread.GetOS().setup.gamecard.get()));
        auto archive_handle = context.next_archive_handle++;
        context.archives.emplace(std::make_pair(archive_handle, std::move(archive)));
        return std::make_tuple(RESULT_OK, archive_handle);
    }

    default:
        thread.GetLogger()->error("Unknown archive id {:#x}", archive_id);
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);
        throw nullptr;
    }
}

static std::tuple<Result> CloseArchive(FakeThread& thread, Context& context,
                                       uint64_t archive_handle) {
    thread.GetLogger()->info("{}received CloseArchive with archive_handle={:#x}",
                             ThreadPrinter{thread}, archive_handle);

    // TODO: Does anything happen to files from this archive that are still opened?
    context.archives.erase(archive_handle);

    return std::make_tuple(RESULT_OK);
}

static std::tuple<Result> Unknown0x4f(FakeThread& thread, Context& context, uint32_t param1, uint32_t param2) {
    thread.GetLogger()->info("{}received Unknown0x4f with param1={:#x}, param2={:#x}",
                             ThreadPrinter{thread}, param1, param2);
    return std::make_tuple(RESULT_OK);
}

static std::tuple<Result> SetPriority(FakeThread& thread, Context& context, uint32_t priority) {
    thread.GetLogger()->info("{}received SetPriority with priority={:#x}", ThreadPrinter{thread}, priority);
    return std::make_tuple(RESULT_OK);
}

static void CommandHandler(FakeThread& thread, Context& context, const IPC::CommandHeader& header) try {
    namespace FS = Platform::PXI::FS;

	thread.GetLogger()->info("\nPXIPXI cmd: {:08x}", header.command_id.Value());

    switch (header.command_id) {
    case FS::OpenFile::id:
        return IPC::HandleIPCCommand<FS::OpenFile>(OpenFile, thread, thread, context);

    case FS::DeleteFile::id:
       return IPC::HandleIPCCommand<FS::DeleteFile>(DeleteFile, thread, thread, context);

    case FS::ReadFile::id:
        return IPC::HandleIPCCommand<FS::ReadFile>(ReadFile, thread, thread, context);

    case FS::GetFileSHA256::id:
        return IPC::HandleIPCCommand<FS::GetFileSHA256>(GetFileSHA256, thread, thread, context);

    case FS::WriteFile::id:
        return IPC::HandleIPCCommand<FS::WriteFile>(WriteFile, thread, thread, context);

    case FS::CalcSavegameMAC::id:
        return IPC::HandleIPCCommand<FS::CalcSavegameMAC>(CalcSavegameMAC, thread, thread, context);

    case FS::GetFileSize::id:
        return IPC::HandleIPCCommand<FS::GetFileSize>(GetFileSize, thread, thread, context);

    case FS::SetFileSize::id:
        return IPC::HandleIPCCommand<FS::SetFileSize>(SetFileSize, thread, thread, context);

    case FS::CloseFile::id:
        return IPC::HandleIPCCommand<FS::CloseFile>(CloseFile, thread, thread, context);

    case FS::OpenArchive::id:
        return IPC::HandleIPCCommand<FS::OpenArchive>(OpenArchive, thread, thread, context);

    case FS::CloseArchive::id:
        return IPC::HandleIPCCommand<FS::CloseArchive>(CloseArchive, thread, thread, context);

    case FS::SetPriority::id:
        return IPC::HandleIPCCommand<FS::SetPriority>(SetPriority, thread, thread, context);

    case FS::Unknown0x4f::id:
        return IPC::HandleIPCCommand<FS::Unknown0x4f>(Unknown0x4f, thread, thread, context);

    default:
        throw std::runtime_error(fmt::format("Unknown PxiFSx service command with header {:#010x}", header.raw));
    }
} catch (const IPC::IPCError& err) {
    auto response_header = IPC::CommandHeader::Make(0, 1, 0);
    response_header.command_id = (err.header >> 16);
    thread.WriteTLS(0x80, response_header.raw);
    thread.WriteTLS(0x84, err.result);
}

}  // namespace FS

}  // namespace PXI

using namespace PXI::FS;

namespace PXI {

using OSImpl = OS::OS;

void FakePXI::FSThread(FakeThread& thread, Context& context, const char* service_name) {
    // NOTE: Actually, there should be four of these buffers!
    for (unsigned buffer_index = 0; buffer_index < 4; ++buffer_index) {
        const auto buffer_size = 0x1000;
        thread.WriteTLS(0x180 + 8 * buffer_index, IPC::TranslationDescriptor::MakeStaticBuffer(0, buffer_size).raw);
        Result result;
        uint32_t buffer_addr;
        std::tie(result, buffer_addr) = thread.CallSVC(&OSImpl::SVCControlMemory, 0, 0, pxi_static_buffer_size, 3 /* COMMIT */, 3 /* RW */);
//        std::tie(result, buffer_addr) = thread.CallSVC(&OSImpl::SVCControlMemory, 0, 0, 0x1000, 3 /* COMMIT */, 3 /* RW */);
        thread.WriteTLS(0x184 + 8 * buffer_index, buffer_addr);
    }

    OS::ServiceUtil service(thread, service_name, 1);

    OS::Handle last_signalled = OS::HANDLE_INVALID;

    for (;;) {
        Result result;
        int32_t index;
        std::tie(result,index) = service.ReplyAndReceive(thread, last_signalled);
        last_signalled = OS::HANDLE_INVALID;
        if (result != RESULT_OK)
            os.SVCBreak(thread, OSImpl::BreakReason::Panic);

        if (index == 0) {
            // ServerPort: Incoming client connection

            int32_t session_index;
            std::tie(result,session_index) = service.AcceptSession(thread, index);
            if (result != RESULT_OK) {
                auto session = service.GetObject<OS::ServerSession>(session_index);
                if (!session) {
                    logger.error("{}Failed to accept session.", ThreadPrinter{thread});
                    os.SVCBreak(thread, OSImpl::BreakReason::Panic);
                }

                auto session_handle = service.GetHandle(session_index);
                logger.warn("{}Failed to accept session. Maximal number of sessions exhausted? Closing session handle {}",
                            ThreadPrinter{thread}, OS::HandlePrinter{thread,session_handle});
                os.SVCCloseHandle(thread, session_handle);
            }
        } else {
            // server_session: Incoming IPC command from the indexed client
            logger.info("{}received IPC request", ThreadPrinter{thread});
            Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
            auto signalled_handle = service.GetHandle(index);
            CommandHandler(thread, context, header);
            last_signalled = signalled_handle;
        }
    }
}

}  // namespace PXI

}  // namespace HLE
