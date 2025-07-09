#pragma once

#include "fake_process.hpp"

#include "../platform/fs.hpp"

#include <memory>
#include <string>

namespace HLE {

using Platform::FS::ArchiveHandle;

class FakeFS;

using OS::FakeProcess;
using OS::FakeThread;
using OS::RESULT_OK;
using Result = OS::OS::Result;
using OS::HandleTable;
using OS::Handle;
using OS::Event;
using OS::ProcessId;

struct FileContext {
    spdlog::logger& logger;
};

/**
 * Interface for an internal buffer used as the data source/target for file
 * read/write operations.
 *
 * Usually, files operate on emulated memory, but it's beneficial for code
 * reuse in frontend code to enable file implementations to work with
 * host memory, too. This class enables this by abstracting away the notion
 * of emulated memory.
 */
class FileBuffer {
public:
    /// Read the specified number of bytes from the internal buffer to dest
//    virtual void Read(char* dest, uint32_t num_bytes) = 0;

    /// Write the specified number of bytes from the source to the internal buffer
    virtual void Write(const char* source, uint32_t num_bytes) = 0;
};

class File {
    friend class SubFile;

    void Fail();

    // True if this file is the reference file of a SubFile. While a sub file
    // is open, no operations may be requested on the parent file.
    bool has_subfile = false;

public:
    virtual ~File() = default;

    // Returns result code and number of bytes read (0 on error)
    virtual OS::OS::ResultAnd<uint32_t> Read(FileContext&, FakeFS&, uint64_t offset, uint32_t num_bytes, FileBuffer& target)/* = 0*/;

    // Returns result code and number of bytes written (0 on error)
    virtual OS::OS::ResultAnd<uint32_t> Write(FakeThread& thread, FakeFS&, uint64_t offset, uint32_t num_bytes, uint32_t options, uint32_t buffer_addr)/* = 0*/;

    // Returns result code and file size in bytes (0 on error)
    virtual OS::OS::ResultAnd<uint64_t> GetSize(FakeThread& thread, FakeFS&)/* = 0*/ { Fail(); return std::make_tuple(RESULT_OK, 0);}

    virtual OS::OS::ResultAnd<> SetSize(FakeThread& thread, FakeFS&, uint64_t size) { Fail(); return std::make_tuple(RESULT_OK);}

    virtual const char* GetFileName() {
        static std::string buffer;
        buffer = std::string("(unknown ") + typeid(*this).name() + ")";
        return buffer.c_str();
    }

    bool HasOpenSubFile() const noexcept;
};

class Directory;

class Archive {
public:
    virtual ~Archive() = default;

    virtual Platform::FS::ArchiveFormatInfo GetFormatInfo(FakeThread&, FakeFS&);

    virtual std::pair<Result,std::unique_ptr<File>> OpenFile(FakeThread&, FakeFS&, uint32_t transaction, uint32_t open_flags, uint32_t attributes, uint32_t path_type, IPC::StaticBuffer path) = 0;

    virtual Result CreateDirectory(FakeThread&, FakeFS&, uint32_t path_type, IPC::StaticBuffer path) = 0;

    virtual std::pair<Result,std::unique_ptr<Directory>> OpenDirectory(FakeThread&, FakeFS&, uint32_t path_type, IPC::StaticBuffer path) = 0;

    virtual Result CreateFile(FakeThread&, FakeFS&, uint32_t transaction, uint32_t attributes, uint64_t size, uint32_t path_type, IPC::StaticBuffer path);

    virtual Result DeleteFile(FakeThread&, FakeFS&, uint32_t transaction, uint32_t path_type, IPC::StaticBuffer path) = 0;

    virtual Result RenameFile(FakeThread&, FakeFS&, uint32_t transaction, uint32_t source_path_type, IPC::StaticBuffer source_path, uint32_t target_path_type, IPC::StaticBuffer target_path) = 0;

    virtual Result DeleteDirectory(FakeThread&, FakeFS&, uint32_t transaction, bool recursive, uint32_t path_type, IPC::StaticBuffer path) = 0;
};

struct FSServiceHelper : HLE::OS::ServiceHelper {
    // nullptr for ports; uint32_t (port handle index) for fs:USER/LDR sessions; others are self-explanatory
    using HandleData = std::variant<decltype(nullptr), uint32_t, std::shared_ptr<File>, std::shared_ptr<Directory>>;

    template<typename T>
    uint32_t Append(HandleTable::Entry<T> entry, FSServiceHelper::HandleData data = nullptr);
    void Erase(int32_t index) override;

    void OnNewSession(int32_t port_index, HandleTable::Entry<OS::ServerSession> session) override;

    /// Replaces the File object in the indexed HandleData with a new one. The previous object will be destroyed.
    void ReplaceFileServer(int32_t index, std::unique_ptr<File> new_file);

    std::vector<HandleData> handle_data;
};

class FakeFS {
    struct ProcessInfo {
        Platform::FS::ProgramInfo program;
        Platform::FS::StorageInfo storage;
    };

public: // TODO: Un-public-ize
    FSServiceHelper service;

    // Map from session handles to the ProcessId assigned via FSUser::Initialize
    std::unordered_map<Handle,ProcessId> fsuser_process_ids;

    std::unordered_map<ProcessId, ProcessInfo> process_infos;

    std::unordered_map<ArchiveHandle, std::unique_ptr<Archive>> archives;

    uint64_t next_archive_handle = 0;

    // TODO: Clarify what thread these belong to, and make sure they are *NOT* shared between threads!
    uint32_t static_buffer_size = 0x1000;
    uint32_t static_buffer_addr[3];

    Handle pxifs_session;

    // handle table indices
    uint32_t fsuser_handle_index;
    uint32_t fsldr_handle_index;

    void FSRegThread(FakeThread& thread);

    void FSUserThread(FakeThread& thread);

    decltype(HLE::OS::ServiceHelper::SendReply) RegCommandHandler(FakeThread& thread, IPC::CommandHeader header);
    decltype(HLE::OS::ServiceHelper::SendReply) UserCommandHandler(FakeThread& thread, Handle sender, const IPC::CommandHeader& header);


    OS::OS::ResultAnd<> OnReg_Register(FakeThread& thread, ProcessId pid, Platform::PXI::PM::ProgramHandle program_handle, Platform::PXI::PM::ProgramInfo program_info, Platform::FS::StorageInfo);
    OS::OS::ResultAnd<> OnReg_Unregister(FakeThread& thread, ProcessId pid);
    OS::OS::ResultAnd<> OnReg_CheckHostLoadId(FakeThread& thread, Platform::PXI::PM::ProgramHandle program_handle);

    std::tuple<OS::Result> HandleInitialize(FakeThread& thread, Handle session_handle, ProcessId id);
    std::tuple<OS::Result> HandleInitializeWithSdkVersion(FakeThread& thread, Handle session_handle, uint32_t version, ProcessId id);
    std::tuple<OS::Result, Handle> HandleOpenFile(FakeThread& thread, ProcessId session_id, uint32_t transaction, uint64_t archive_handle, uint32_t path_type, uint32_t path_size, uint32_t open_flags, uint32_t attributes, IPC::StaticBuffer path);
    std::tuple<OS::Result, Handle> HandleOpenFileDirectly(FakeThread& thread, ProcessId session_id, uint32_t transaction, uint32_t archive_id, uint32_t archive_path_type, uint32_t archive_path_size, uint32_t file_path_type, uint32_t file_path_size, uint32_t open_flags, uint32_t attributes, const IPC::StaticBuffer& archive_path, const IPC::StaticBuffer& file_path);
    std::tuple<OS::Result> HandleDeleteFile(FakeThread& thread, ProcessId session_id, uint32_t transaction, uint64_t archive_handle,
                                            uint32_t file_path_type, uint32_t file_path_size, IPC::StaticBuffer file_path);
    std::tuple<OS::Result> HandleRenameFile(FakeThread& thread, uint32_t transaction,
                                            uint64_t source_archive_handle, uint32_t source_file_path_type, uint32_t source_file_path_size,
                                            uint64_t target_archive_handle, uint32_t target_file_path_type, uint32_t target_file_path_size,
                                            IPC::StaticBuffer source_file_path, IPC::StaticBuffer target_file_path);
    std::tuple<OS::Result> HandleDeleteDirectory(FakeThread& thread, ProcessId session_id, bool recursive,
                                                 uint32_t transaction, ArchiveHandle archive_handle,
                                                 uint32_t dir_path_type, uint32_t dir_path_size,
                                                 IPC::StaticBuffer dir_path);
    std::tuple<OS::Result> HandleCreateFile(FakeThread& thread, ProcessId session_id, uint32_t transaction,
                                            uint64_t archive_handle, uint32_t file_path_type, uint32_t file_path_size,
                                            uint32_t attributes, uint64_t initial_file_size,
                                            IPC::StaticBuffer file_path);
    std::tuple<OS::Result> HandleCreateDirectory(FakeThread& thread, ProcessId session_id, uint32_t transaction,
                                                 uint64_t archive_handle, uint32_t dir_path_type, uint32_t dir_path_size,
                                                 uint32_t attributes, IPC::StaticBuffer dir_path);
    std::tuple<OS::Result, Handle> HandleOpenDirectory(FakeThread& thread, ProcessId session_id, uint64_t archive_handle, uint32_t path_type, uint32_t path_size, IPC::StaticBuffer path);
    std::tuple<OS::Result, uint64_t> HandleOpenArchive(FakeThread& thread, ProcessId session_id, uint32_t archive_id, uint32_t path_type, uint32_t path_size, IPC::StaticBuffer path);
    std::tuple<OS::Result, IPC::MappedBuffer, IPC::MappedBuffer> HandleControlArchive(FakeThread& thread, ProcessId session_id, uint64_t archive_handle, uint32_t action, uint32_t input_size, uint32_t output_size, IPC::MappedBuffer input, IPC::MappedBuffer output);
    std::tuple<OS::Result> HandleCloseArchive(FakeThread& thread, ProcessId session_id, uint64_t archive_handle);
    std::tuple<OS::Result> HandleFormatOwnSaveData(FakeThread& thread, ProcessId session_id, uint32_t block_size,
                                                   uint32_t num_dirs, uint32_t num_files, uint32_t num_dir_buckets,
                                                   uint32_t num_file_buckets, uint32_t unknown);
    std::tuple<OS::Result, uint32_t> HandleIsSdmcDetected(FakeThread& thread);
    std::tuple<OS::Result, uint32_t> HandleGetPriority(FakeThread& thread);
    std::tuple<OS::Result, Platform::PXI::PM::ProgramInfo> HandleGetProgramLaunchInfo(FakeThread& thread, ProcessId id);

    std::tuple<OS::Result, Platform::FS::ArchiveFormatInfo>
    HandleGetFormatInfo(FakeThread& thread, ProcessId session_id, Platform::FS::ArchiveId archive_id,
                        uint32_t archive_path_type, uint32_t archive_path_size, IPC::StaticBuffer archive_path);

    std::tuple<OS::Result> HandleFormatSaveData(FakeThread& thread, ProcessId session_id, Platform::FS::ArchiveId archive_id,
                                                uint32_t path_type, uint32_t path_size, uint32_t num_blocks,
                                                uint32_t num_dirs, uint32_t num_files, uint32_t num_dir_buckets,
                                                uint32_t num_file_buckets, uint32_t unknown, IPC::StaticBuffer archive_path);
    std::tuple<OS::Result, IPC::MappedBuffer> HandleCreateExtSaveData(FakeThread& thread, ProcessId session_id, const Platform::FS::ExtSaveDataInfo& info,
                                                   uint32_t num_directories, uint32_t num_files, uint64_t size_limit,
                                                   uint32_t smdh_size, IPC::MappedBuffer smdh);
    std::tuple<OS::Result, IPC::MappedBuffer> HandleCreateExtSaveDataLegacy(FakeThread& thread, ProcessId session_id, uint32_t media_type,
                                                   uint64_t save_id, uint32_t smdh_size, uint32_t num_directories, uint32_t num_files,
                                                   IPC::MappedBuffer smdh);
    std::tuple<OS::Result> HandleDeleteExtSaveData(FakeThread& thread, ProcessId session_id, const Platform::FS::ExtSaveDataInfo& info);
    std::tuple<OS::Result, uint32_t, IPC::MappedBuffer> HandleEnumerateExtSaveData(FakeThread&, ProcessId, uint32_t, uint32_t media_type,
                                                                                   uint32_t id_entry_size, uint32_t is_shared,
                                                                                   IPC::MappedBuffer output_ids);
    std::tuple<OS::Result> HandleCreateSystemSaveData(FakeThread& thread, ProcessId session_id, uint32_t media_type, uint32_t save_id,
                                                      uint32_t total_size, uint32_t block_size, uint32_t num_directories,
                                                      uint32_t num_files, uint32_t unk1, uint32_t unk2, uint32_t unk3);

    std::tuple<OS::Result, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, IPC::MappedBuffer>
    HandleUpdateSha256Context(  FakeThread& thread, ProcessId session_id, uint32_t, uint32_t, uint32_t, uint32_t,
                                uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                                uint32_t, IPC::MappedBuffer);

    FakeProcess& process;
    spdlog::logger& logger;
    FileContext file_context { logger };
    Settings::Settings& settings;

public:
    FakeFS(FakeThread& thread);
    ~FakeFS();
};

}  // namespace HLE
