#pragma once

#include "ipc.hpp"

// Include definitions for ProgramInfo and ProgramHandle
#include "pxi.hpp"

#include <array>
#include <cstdint>
#include <stdexcept>

#include <boost/hana/define_struct.hpp>

namespace Platform {

namespace FS {

using ProgramInfo = PXI::PM::ProgramInfo;

struct StorageInfo {
    uint32_t unknown1;
    uint32_t unknown2;
    uint32_t unknown3;
    uint32_t unknown4;
    uint32_t unknown5;
    uint32_t unknown6;
    uint32_t unknown7;
    uint32_t unknown8;

    static auto IPCDeserialize(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g, uint32_t h) {
        return StorageInfo { a, b, c, d, e, f, g, h };
    }
    static auto IPCSerialize(const StorageInfo& data) {
        return std::make_tuple(data.unknown1, data.unknown2, data.unknown3, data.unknown4, data.unknown5, data.unknown6, data.unknown7, data.unknown8);
    }

    using ipc_data_size = std::integral_constant<size_t, 8>;
};

enum class MediaType : uint8_t {
    NAND     = 0,
    SD       = 1,
    GameCard = 2,
};

enum class SpecialContentType : uint8_t {
    UpdateData        = 1,
    Manual            = 2,
    DownloadPlayChild = 3,
    UpdateDataNew3DS  = 4,
};

struct ExtSaveDataInfo {
    MediaType media_type;
    uint8_t unknown[3];
    uint64_t save_id;
    uint32_t unknown2;

    static auto IPCDeserialize(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
        return ExtSaveDataInfo {
            static_cast<MediaType>(a & 0xff),
            { static_cast<uint8_t>(a >> 8), static_cast<uint8_t>(a >> 16), static_cast<uint8_t>(a >> 24) },
            (uint64_t { c } << 32) | b,
            d };
    }

    static auto IPCSerialize(const ExtSaveDataInfo& data) {
        return std::make_tuple(static_cast<uint32_t>(data.media_type) | (uint32_t { data.unknown[0] } << 8) | (uint32_t { data.unknown[1] } << 16) | (uint32_t { data.unknown[2] } << 24),
                               static_cast<uint32_t>(data.save_id), static_cast<uint32_t>(data.save_id >> 32), data.unknown2);
    }
};

/**
 * Parameters used when the archive was initially formatted
 */
struct ArchiveFormatInfo {
    uint32_t max_size;
    uint32_t max_directories;
    uint32_t max_files;
    bool duplicate_data;

    static auto IPCDeserialize(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
        // TODO: Some games (e.g. Cubic Ninja during startup) use values like
        //       0x0ffffe01 for this. Test if only the lowest byte is
        //       considered here, or if the entire word is compared against 0
        //       instead
        if ((d & 0xff) > 1) {
            throw std::runtime_error("Invalid input value for boolean field");
        }

        return ArchiveFormatInfo { a, b, c, static_cast<bool>(d & 0xff) };
    }

    static auto IPCSerialize(const ArchiveFormatInfo& data) noexcept {
        return std::make_tuple(data.max_size, data.max_directories, data.max_files, static_cast<uint32_t>(data.duplicate_data));
    }
};

// TODO: Turn these into strong typedefs
using ArchiveId = uint32_t;
using ArchiveHandle = uint64_t; // FS-internal handle for opened archives

namespace IPC = Platform::IPC;

/// fs:USER and fs:LDR service commands
namespace User {

/**
 * Observed error codes:
 * - 0xc8804465: Didn't register current process to fs:REG ?
 */
using Initialize =       IPC::IPCCommand<0x801>::add_process_id
                            ::response;

/**
 * Inputs:
 * - Transaction
 * - Archive handle
 * - File path type
 * - File path size
 * - File access mode (bit 0 = read, bit 1 = write, bit 2 = create)
 * - Attributes
 * - File path
 *
 * Error codes:
 * - 0xe0c046f8: Trying to open files with unsupported flags (e.g. 0, 4, and 5 on archive id 8)
 * - 0xc92044e6: Invalid combination of file access mode flags (e.g. 7)
 *               Trying to open a file that is already opened
 * - 0xe0e046be: Trying to open a file from an invalid path (e.g. empty, no leading "/", etc)
 * - 0xe0c04702: Trying to escape the root directory via .. (e.g. "/../test") <- TODO: Could indicate ArchiveSaveData just doesn't support ".." at all!
 */
using OpenFile =         IPC::IPCCommand<0x802>::add_uint32::add_uint64::add_uint32::add_uint32::add_uint32::add_uint32::add_static_buffer/*TODO: Id*/
                            ::response::add_and_close_handle<IPC::HandleType::ClientSession>;
struct OpenFileDirectly : IPC::IPCCommand<0x803>::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_static_buffer::add_static_buffer
                            ::response::add_and_close_handle<IPC::HandleType::ClientSession> {};

/**
 * Inputs:
 * - Transaction
 * - Archive handle
 * - File path type
 * - File path size
 * - File path
 *
 * Error codes:
 * - 0xc8804470: File does not exist
 * - 0xd9001830: Invalid arguments
 */
using DeleteFile = IPC::IPCCommand<0x804>::add_uint32::add_uint64::add_uint32::add_uint32::add_static_buffer
                      ::response;

/**
 * Inputs:
 * - Transaction
 * - Source archive handle
 * - Source file path type
 * - Source file path size
 * - Target archive handle
 * - Target file path type
 * - Target file path size
 * - Source file path
 * - Target file path
 */
using RenameFile = IPC::IPCCommand<0x805>::add_uint32::add_uint64::add_uint32::add_uint32::add_uint64::add_uint32::add_uint32::add_static_buffer::add_static_buffer
                      ::response;

/**
 * Inputs:
 * - Transaction
 * - Archive handle
 * - Directory path type
 * - Directory path size
 * - Directory path
 *
 * Error codes:
 * - 0xc8804471: Directory does not exist
 * - 0xc92044e6: Directory is still opened
 * - 0xc92044f0: Directory is not empty
 */
using DeleteDirectory = IPC::IPCCommand<0x806>::add_uint32::add_uint64::add_uint32::add_uint32::add_static_buffer
                      ::response;

/**
 * Inputs:
 * - Transaction
 * - Archive handle
 * - Directory path type
 * - Directory path size
 * - Directory path
 *
 * Error codes:
 * - 0xc8804471: Directory does not exist
 */
using DeleteDirectoryRecursively = IPC::IPCCommand<0x807>::add_uint32::add_uint64::add_uint32::add_uint32::add_static_buffer
                                      ::response;

/**
 * Inputs:
 * - Transaction
 * - Archive handle
 * - File path type
 * - File path size
 * - Attributes
 * - Initial file size (TODOTEST: will it be zero-filled?)
 * - File path buffer (id 0)
 *
 * Error codes:
 * - 0xc82044b4: No effect, e.g. because the file already existed
 * - 0xc8804471: Directory does not exist
 * - 0xe0c046f8: Unsupported operation (e.g. flag combination or empty file size)
 */
using CreateFile = IPC::IPCCommand<0x808>::add_uint32::add_uint64::add_uint32::add_uint32::add_uint32::add_uint64::add_static_buffer
                      ::response;

/**
 * Inputs:
 * - Transaction
 * - Archive handle
 * - File path type
 * - File path size
 * - Attributes
 * - File path buffer (id 0)
 *
 * Error codes:
 * - 0xc82044b9: Path already exists (whether it points to a directory or not)
 * - 0xe0e046be: Path too long (used instead of 0xe0e046bf by shared extdata archive 0x7)
 * - 0xe0e046bf: Path too long (used by most archives instead of 0xe0e046be)
 */
using CreateDirectory = IPC::IPCCommand<0x809>::add_uint32::add_uint64::add_uint32::add_uint32::add_uint32::add_static_buffer
                      ::response;

/**
 * Inputs:
 * - Archive handle
 * - Directory path type
 * - Directory path size
 * - Directory path
 *
 * Error codes:
 * - 0xc8804471: Directory does not exist
 */
using OpenDirectory = IPC::IPCCommand<0x80b>::add_uint64::add_uint32::add_uint32::add_static_buffer/*TODO: Id*/
                         ::response::add_and_close_handle<IPC::HandleType::ClientSession>;

/**
 * Inputs:
 * - Archive id
 * - Path type
 * - Path size (including null-terminator)
 *
 * Outputs:
 * - Archive handle
 *
 * Error codes:
 * - 0xc8804470: Trying to open an archive path that doesn't exist. Depending on the archive id, you may need to call e.g. CreateSystemSaveData first
 * - 0xc8804478: Observed while trying to open a savegame with size 0
 * - 0xc8a04555: Observed while trying to open a corrupted savegame via archive id 4 (needed to call FormatSaveData first)
 */
using OpenArchive      = IPC::IPCCommand<0x80c>::add_uint32::add_uint32::add_uint32::add_static_buffer
                            ::response::add_uint64;

/**
 * Contents of the input and output buffers depend on the given action.
 *
 * Inputs:
 * - Archive handle
 * - Action
 * - Input data size
 * - Output data size
 * - Input buffer
 * - Output buffer
 */
using ControlArchive   = IPC::IPCCommand<0x80d>::add_uint64::add_uint32::add_uint32::add_uint32::add_buffer_mapping_read::add_buffer_mapping_write
                            ::response::add_buffer_mapping_read::add_buffer_mapping_write;

using CloseArchive     = IPC::IPCCommand<0x80e>::add_uint64
                            ::response;

/**
 * Inputs:
 * - Save data block size
 * - Number of directories
 * - Number of files
 * - Number of directory buckets
 * - Number of file buckets
 * - Unknown
 */
using FormatOwnSaveData = IPC::IPCCommand<0x80f>::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32
                             ::response;

/**
 * Inputs:
 * - Save id
 * - Total size
 * - Block size (usually 0x1000)
 * - Number of directories
 * - Number of files
 * - Unknown
 * - Unknown
 * - Unknown
 */
using CreateSystemSaveDataLegacy = IPC::IPCCommand<0x810>::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32
                                      ::response;

/**
 * Inputs:
 * - Save id
 */
using DeleteSystemSaveDataLegacy = IPC::IPCCommand<0x811>::add_uint32
                                ::response;


/**
 * Outputs:
 * - 0 if CTR card, 1 if TWL card
 */
using GetCardType      = IPC::IPCCommand<0x813>
                            ::response::add_uint32;

using IsSdmcDetected   = IPC::IPCCommand<0x817>
                            ::response::add_uint32;

struct IsSdmcWritable  : IPC::IPCCommand<0x818>
                            ::response::add_uint32 {};
/*
 * Returns the ProgramInfo data that was given to fs:Reg::Register for the input process id
 */
using GetProgramLaunchInfo = IPC::IPCCommand<0x82f>::add_uint32
                                ::response::add_serialized<PXI::PM::ProgramInfo>;
/**
 * Wraps around CreateExtSaveData. Note that the parameter order is slightly
 * shuffled, and not all members of ExtSaveDataInfo are specified explicitly.
 *
 * Inputs:
 * - Media type
 * - Save id
 * - SMDH size
 * - Number of directories
 * - Number of files
 * - SMDH data
 */
using CreateExtSaveDataLegacy = IPC::IPCCommand<0x830>::add_uint32::add_uint64::add_uint32::add_uint32::add_uint32::add_buffer_mapping_read
                                ::response::add_buffer_mapping_read;

/**
 * Like DeleteExtSaveData, but only specified MediaType and lower 32 bits of save id as inputs
 */
using DeleteExtSaveDataLegacy = IPC::IPCCommand<0x835>::add_uint32::add_uint32
                                   ::response;
                                   

using Unknown0x839 = IPC::IPCCommand<0x839>
                        ::response;
                        
/**
 * Inputs:
 * - Media type
 * - Title ID
 * - Special content type
 *
 * Outputs:
 * - Special content index / partition index of special content
 */
using GetSpecialContentIndex = IPC::IPCCommand<0x83A>::add_uint32::add_uint64::add_uint32
                                ::response::add_uint32;

/**
 * Inputs:
 * - Archive ID
 * - Path type, size, and buffer
 *
 * Outputs:
 * - Total size
 * - Number of directories
 * - Number of files
 */
using GetFormatInfo = IPC::IPCCommand<0x845>::add_uint32::add_uint32::add_uint32::add_static_buffer
                         ::response::add_serialized<ArchiveFormatInfo>;

/**
 * Inputs:
 * - Archive ID
 * - Path type and size
 * - Number of save data blocks
 * - Number of directories
 * - Number of files
 * - Number of directory buckets
 * - Number of file buckets
 * - Unknown
 *
 * Error codes:
 * - 0xe0e046be: Trying to format archive with id different than 0x4 and 0x567890b2
 */
using FormatSaveData = IPC::IPCCommand<0x84c>::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_static_buffer
                          ::response;

/**
 * Inputs:
 * - 8 words of input hashes (unused?)
 * - Input data size in bytes
 * - 4 words for flags
 * - Input data buffer
 */
using UpdateSha256Context = IPC::IPCCommand<0x84e>::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_buffer_mapping_read
                               ::response::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_buffer_mapping_read;

/**
 * Inputs:
 * - Extdata info
 * - Number of directories
 * - Number of files
 * - Size limit (may be -1)
 * - SMDH size
 * - SMDH data
 */
using CreateExtSaveData = IPC::IPCCommand<0x851>::add_serialized<ExtSaveDataInfo>::add_uint32::add_uint32::add_uint64::add_uint32::add_buffer_mapping_read
                                ::response::add_buffer_mapping_read;

/**
 * Inputs:
 * - Extdata info
 *
 * Error codes:
 * - 0xc8804478: Not found
 * - 0xc92044fa: Attempted to delete archive while it was still opened
 */
using DeleteExtSaveData = IPC::IPCCommand<0x852>::add_serialized<ExtSaveDataInfo>
                             ::response;

/**
 * Inputs:
 * - Output Extdata ID buffer size
 * - Media Type (and other unknown flags)
 * - Extdata ID size (4 or 8)
 * - Is Shared
 * - Output Extdata ID buffer
 *
 * Error codes:
 * - 0xe0c046fa: Gamecard extdata is not supported
 * - 0xe0e046bc: Invalid buffer size or Extdata ID size
 */
using EnumerateExtSaveData = IPC::IPCCommand<0x855>::add_uint32::add_uint32::add_uint32::add_uint32::add_buffer_mapping_write
                                ::response::add_uint32::add_buffer_mapping_write;

/**
 * Inputs:
 * - Media type (and other things?)
 * - Save id
 * - Total size
 * - Block size (usually 0x1000)
 * - Number of directories
 * - Number of files
 * - Unknown
 * - Unknown
 * - Unknown
 *
 * Error codes:
 * - 0xc86044c8, observed with total_size=0x1000
 * - 0xc92044e7
 */
using CreateSystemSaveData = IPC::IPCCommand<0x856>::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32
                                ::response;
using DeleteSystemSaveData = IPC::IPCCommand<0x857>::add_uint32::add_uint32
                                ::response;

/**
 * Known SDK versions:
 * - 0xa0001c8 (4.5 cfg module)
 * - 0xb0502c8 (11.x cfg module)
 * - ...
 */
using InitializeWithSdkVersion = IPC::IPCCommand<0x861>::add_uint32::add_process_id
                                    ::response;
using GetPriority = IPC::IPCCommand<0x863>
                       ::response::add_uint32;

}  // namespace User

/// fs:REG service commands
namespace Reg {

/**
  * Authorizes the process with the given ProcessId to use the FS services.
  * The input ProgramHandle must previously have been registered through LoadProgram.
  *
  * Inputs:
  * - Process id
  * - PXIPM ProgramHandle
  * - ProgramInfo
  * - StorageInfo
  */
using Register = IPC::IPCCommand<0x401>
                    ::add_uint32::add_serialized<PXI::PM::ProgramHandle>
                    ::add_serialized<ProgramInfo>
                    ::add_serialized<StorageInfo>
                    ::response;

/**
  * Inputs:
  * - Process id
  */
using Unregister = IPC::IPCCommand<0x402>
                    ::add_uint32
                    ::response;

/**
 * Inputs:
 * - ProgramInfo
 *
 * Outputs:
 * - Program handle
 */
using LoadProgram = IPC::IPCCommand<0x404>
                       ::add_serialized<PXI::PM::ProgramInfo>
                       ::response::add_serialized<PXI::PM::ProgramHandle>;

/**
 * Inputs:
 * - PXI Program handle
 * TODO: This actually seems to be a title id!
 */
using CheckHostLoadId = IPC::IPCCommand<0x406>
                           ::add_serialized<PXI::PM::ProgramHandle>
                           ::response; // TODO: Response unverified

}  // namespace Reg

/// File session commands
namespace File {

using Control     = IPC::IPCCommand<0x401>::add_uint32::add_uint32::add_uint32
                        ::add_buffer_mapping_read
                        ::add_buffer_mapping_write
                        ::response;

using OpenSubFile = IPC::IPCCommand<0x801>::add_uint64::add_uint64
                        ::response::add_and_close_handle<IPC::HandleType::ClientSession>;

/**
 * Error codes:
 * - 0xc92044e6: Trying to read from a write-only file
 * - 0xc8a044dc: Trying to access a file that was closed
 */
struct Read        : IPC::IPCCommand<0x802>::add_uint64::add_uint32
                        ::add_buffer_mapping_write
                        ::response::add_uint32::add_buffer_mapping_write { };

/**
 * Error codes:
 * - 0xc92044e6: Trying to write to a read-only file
 * - 0xc8a044dc: Trying to access a file that was closed
 */
struct Write       : IPC::IPCCommand<0x803>::add_uint64::add_uint32::add_uint32
                        ::add_buffer_mapping_read
                        ::response::add_uint32::add_buffer_mapping_read { };

/**
 * Error codes:
 * - 0xc8a044dc: Trying to access a file that was closed
 */
using GetSize     = IPC::IPCCommand<0x804>
                        ::response::add_uint64;

/**
 * Error codes:
 * - 0xc8a044dc: Trying to access a file that was closed
 */
using SetSize     = IPC::IPCCommand<0x805>::add_uint64
                        ::response;

using Close       = IPC::IPCCommand<0x808>
                        ::response;

using Flush       = IPC::IPCCommand<0x809>
                        ::response;

using OpenLinkFile = IPC::IPCCommand<0x80c>
                        ::response::add_and_close_handle<IPC::HandleType::ClientSession>;

}  // namespace File

/// Directory session commands
namespace Dir {

struct Entry {
    BOOST_HANA_DEFINE_STRUCT(Entry,
        (std::array<char16_t, 0x106>, name), // UTF-16 entry name (TODO: null terminated?)
        (std::array<uint8_t, 0x14>, unknown),
        (uint64_t, size) // file size in bytes?
    );
};
static_assert(sizeof(Entry) == 0x228);

/**
 * Iteratively reads a number of directory entries. The internal directory
 * object will track a read offset and increase it accordingly when this
 * function is called.
 *
 * Inputs:
 * - Number of entries to read
 * - Directory path type
 * - Directory path size
 * - Directory path
 */
using Read = IPC::IPCCommand<0x801>::add_uint32::add_buffer_mapping_write
                ::response::add_uint32::add_buffer_mapping_write;

using Close = IPC::IPCCommand<0x802>
                ::response;

}

}  // namespace FS

}  // namespace Platform
