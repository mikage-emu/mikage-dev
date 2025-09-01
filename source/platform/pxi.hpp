#pragma once

#include "ipc.hpp"

#include <functional>

namespace Platform {

/**
 * PXI: Interprocessor communication.
 * This ARM11 system module implements the services used to interface the
 * ARM9 processor.
 */
namespace PXI {

/**
 * Low-level interface for filesystem access. In contrast to the
 * userland-facing FS module, archives and files are identified with
 * module-specific uint64_t handles here.
 */
namespace FS {

// TODO: Consider introducing a separate add_pxi_buffer tag!

/**
 * Inputs:
 * - transaction
 * - archive handle
 * - path type
 * - path size
 * - open flags
 * - attributes
 * - path buffer
 */
using OpenFile = IPC::IPCCommand<0x1>::add_uint32::add_uint64::add_uint32::add_uint32::add_uint32::add_uint32::add_pxi_buffer
                       ::response::add_uint64; // Response not verified

/**
 * Inputs:
 * - transaction
 * - archive handle
 * - path type
 * - path size
 * - path buffer
 */
using DeleteFile = IPC::IPCCommand<0x2>::add_uint32::add_uint64::add_uint32::add_uint32::add_pxi_buffer_r
                       ::response; // Response not verified

/**
 * Inputs:
 * - file handle
 * - file offset at which to start reading
 * - number of bytes to read
 * - destination buffer
 *
 * Outputs:
 * - number of bytes that were successfully read
 */
//using ReadFile = IPC::IPCCommand<0x9>::add_uint64::add_uint64::add_uint32::add_pxi_buffer
//                    ::response::add_uint32; // Response not verified
using ReadFile = IPC::IPCCommand<0x9>::add_uint64::add_uint64::add_uint32::add_pxi_buffer
                    ::response::add_uint32; // Response not verified

/**
 * Fills the given buffer with the SHA256 of the given file. The implementation
 * need not compute this from the actual file contents but may instead load
 * a precomputed hash from a location that is not normally accessible through
 * the given file object.
 *
 * For instance, the SHA256 hashes of each section of an application's ExeFS
 * are included in the header, so archive 0x2345678e need not compute the
 * hash manually but can instead just return the hash from that header.
 *
 * Inputs:
 * - file handle
 * - size of the given PXI buffer (usually 0x20)
 */
using GetFileSHA256 = IPC::IPCCommand<0xa>::add_uint64::add_uint32::add_pxi_buffer
                    ::response; // Response not verified; missing a "4" in the end

/**
 * Inputs:
 * - file handle
 * - file offset at which to start reading
 * - number of bytes to read
 * - flush flags
 * - destination buffer
 *
 * Outputs:
 * - number of bytes that were successfully read
 *
 * Notes:
 * - 3dbrew has the parameter order of "number of bytes to read" and "flush flags" mixed up, it seems.
 */
using WriteFile = IPC::IPCCommand<0xb>::add_uint64::add_uint64::add_uint32::add_uint32::add_pxi_buffer
                     ::response::add_uint32; // Response not verified

/**
 * Inputs:
 * - file handle
 * - output buffer size
 * - input buffer size
 * - input buffer
 * - output buffer
 *
 * Outputs:
 * - number of bytes that were successfully read
 *
 * @todo Why does this take a file handle? It seems the MAC is solely computed from the input buffer...
 */
using CalcSavegameMAC = IPC::IPCCommand<0xc>::add_uint64::add_uint32::add_uint32::add_pxi_buffer::add_pxi_buffer
                           ::response; // Response not verified

/**
 * Inputs:
 * - file handle
 */
using GetFileSize = IPC::IPCCommand<0xd>::add_uint64
                       ::response::add_uint64; // Response not verified

/**
 * Inputs:
 * - new size
 * - file handle
 *
 * @note At least for archive 0x1234567c, this leaves any appended data uninitialized
 */
using SetFileSize = IPC::IPCCommand<0xe>::add_uint64::add_uint64
                       ::response; // Response not verified

/**
 * Inputs:
 * - file handle
 */
using CloseFile = IPC::IPCCommand<0xf>::add_uint64
                     ::response; // Response not verified

//using OpenArchive = IPC::IPCCommand<0x12>::add_uint32::add_uint32::add_uint32::add_pxi_buffer
//                       ::response::add_uint64; // Response not verified
using OpenArchive = IPC::IPCCommand<0x12>::add_uint32::add_uint32::add_uint32::add_pxi_buffer_r
                       ::response::add_uint64; // Response not verified
using CloseArchive = IPC::IPCCommand<0x16>::add_uint64
                        ::response;
using Unknown0x4f = IPC::IPCCommand<0x4f>::add_uint32::add_uint32
                       ::response;
using SetPriority = IPC::IPCCommand<0x50>::add_uint32
                       ::response;

} // namespace FS


namespace PM {

struct ProgramInfo {
    uint64_t program_id;
    uint8_t media_type;

    static auto IPCDeserialize(uint64_t program_id, uint32_t media_type, uint32_t unknown) {
        return ProgramInfo { program_id, static_cast<uint8_t>(media_type) };
    }
    static auto IPCSerialize(const ProgramInfo& data) {
        return std::make_tuple(data.program_id, static_cast<uint32_t>(data.media_type), uint32_t{});
    }

    using ipc_data_size = std::integral_constant<size_t, 4>;
};

/**
 * Opaque handle used by PM to identify programs registered through RegisterProgram
 *
 * If the upper 32 bits of this are 0xffff0000, the raw value of this handle is
 * also used as the title id for Host IO (which is a feature available on dev-units).
 */
struct ProgramHandle {
    uint64_t value;

    static auto IPCDeserialize(uint64_t value) {
        return ProgramHandle { value };
    }
    static auto IPCSerialize(const ProgramHandle& data) {
        return std::make_tuple(data.value);
    }

    using ipc_data_size = std::integral_constant<size_t, 2>;

    bool operator==(const ProgramHandle& other) const {
        return value == other.value;
    }
};

/**
 * Retrieves the "public" part of the extended header, i.e. the SCI and the primary ACI
 *
 * Inputs:
 * - Program handle (returned from RegisterProgram) for the program of interest
 * - Target buffer for the SCI and ACI stored in the extended header
 */
using GetExtendedHeader = IPC::IPCCommand<0x1>::add_serialized<ProgramHandle>::add_pxi_buffer
                             ::response;

/**
 * Inputs:
 * - ProgramInfo for the title to be registered
 * - ProgramInfo for an update title to be registered
 *
 * Outputs:
 * - program handle
 */
using RegisterProgram = IPC::IPCCommand<0x2>::add_serialized<ProgramInfo>::add_serialized<ProgramInfo>
                           ::response::add_serialized<ProgramHandle>;

using UnregisterProgram = IPC::IPCCommand<0x3>::add_serialized<ProgramHandle>
                             ::response;

} // namespace PM


namespace PS {

/**
 * Inputs:
 * - SHA256 hash (?)
 * - Size of first buffer
 * - Size of second buffer
 * - Unknown PXI buffer
 * - Unknown PXI buffer
 *
 * Outputs:
 * - Result code (0 if signature verification successfull)
 * - Unknown if any other outputs follow
 */
using VerifyRsaSha256 = IPC::IPCCommand<0x3>::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32
                                            ::add_uint32::add_uint32::add_pxi_buffer::add_pxi_buffer::response;

/**
 * Inputs:
 * - Data size (in bytes)
 * - Initialization vector for AES (4 words)
 * - Operation (upper bytes ignored):
 *   0/1=CBC encrypt/decrypt, 2/3=CTR encrypt/decrypt, 4/5=CCM encrypt/decrypt (not supported?)
 * - Key id (PXI-specific, maps to hardware keyslots using an irregular pattern)
 * - input data
 * - output buffer
 */
using EncryptDecryptAES = IPC::IPCCommand<0x4>::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_pxi_buffer::add_pxi_buffer
                                              ::response;

using EncryptSignDecryptVerifyAesCcm = IPC::IPCCommand<0x5>::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_pxi_buffer_r::add_pxi_buffer::response;

/**
 * Inputs:
 * - buffer size (in bytes)
 * - Output buffer
 */
using GenerateRandomBytes = IPC::IPCCommand<0xd>::add_uint32::add_pxi_buffer
                                                ::response;

} // namespace PS

namespace MC {

/// TODO: Remove the commented out ones. They were actually AM commands!
// 3dbrew erratum: Takes one input word
// using Unknown0x1 = IPC::IPCCommand<0x1>::add_uint32
//                                        ::response;
//
// using Unknown0x2 = IPC::IPCCommand<0x2>::add_uint32::add_uint32::add_pxi_buffer_r
//                                        ::response;
//
// using Unknown0xa = IPC::IPCCommand<0xa>::add_uint32::add_uint32::add_uint32
//                                        ::response;

} // namespace MC

namespace AM {

/**
 * Returns the number of titles for the given media type
 *
 * Inputs:
 * - Media type
 *
 * Outputs:
 * - Title count
 */
using GetTitleCount = IPC::IPCCommand<0x1>::add_uint32
                                          ::response::add_uint32;

/**
 * Retrieves the list of all title IDs for the given media type
 *
 * Inputs:
 * - Number of titles to get information from (usually to be queried via
 *   GetTitleCount first)
 * - Media type
 * - Output buffer that is large enough to hold 8 * the requested number of titles
 *
 * Outputs:
 * - Number of titles for which information was stored in the output buffer
 */
using GetTitleList = IPC::IPCCommand<0x2>::add_uint32::add_uint32::add_pxi_buffer_r
                                          ::response::add_uint32;

/**
 * Retrieves the list of all title IDs for the given media type
 *
 * Inputs:
 * - Media type
 * - Number of titles to get information from (usually to be queried via
 *   GetTitleCount first)
 * - Input buffer that holds title IDs for the titles to get information of
 * - Output buffer that is large enough to hold 0x18 * the requested number of titles
 */
using GetTitleInfos = IPC::IPCCommand<0x3>::add_uint32::add_uint32::add_pxi_buffer_r::add_pxi_buffer
                                          ::response;

} // namespace AM

} // namespace PXI

} // namespace Platform

// Implement std::hash for use in unordered containers
namespace std {
template<>
struct hash<Platform::PXI::PM::ProgramHandle> {
    auto operator()(const Platform::PXI::PM::ProgramHandle& handle) const {
        return std::hash<decltype(handle.value)>{}(handle.value);
    }
};
}  // namespace std
