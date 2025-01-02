#pragma once

#include "ipc.hpp"

#include <platform/pxi.hpp>

#include <fstream>
#include <filesystem>
#include <boost/optional.hpp>

namespace HLE {

namespace OS {
class Thread;
class FakeThread;
using Result = uint32_t;
template<typename... T>
using ResultAnd = std::tuple<Result, T...>;
extern const Result RESULT_OK;
}

struct CommonPath;
struct Utf8PathType;
struct BinaryPathType;

namespace PXI {

struct PXIBuffer;

namespace FS {

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
protected:
    virtual ~FileBuffer() = default;

public:
    /// Read the specified number of bytes from the internal buffer to dest
//    virtual void Read(char* dest, uint32_t num_bytes) = 0;

    /// Write the specified number of bytes from the source to the internal buffer
    virtual void Write(char* source, uint32_t num_bytes) = 0;
};

class FileBufferInHostMemory : public FileBuffer {
    char* memory;
    uint32_t size;

    template<typename T>
    char* CheckCast(T& t) {
        static_assert(!std::is_pointer_v<T>, "Pointers must use the sized constructor");
        return reinterpret_cast<char*>(&t);
    }

public:
    FileBufferInHostMemory(void* ptr, uint32_t size) : memory(reinterpret_cast<char*>(ptr)), size(size) {
    }

    template<typename T>
    FileBufferInHostMemory(T& t) : memory(CheckCast(t)), size(sizeof(T)) {
    }

    void Write(char* source, uint32_t num_bytes) override;
};

struct OpenFlags {
    bool read = true;
    bool write = true;
    bool create = false; // create or truncate
};

class File {
    [[noreturn]] void Fail();

public:
    virtual ~File() {
        Close();
    }

    /**
     * Open the given file on the disk.
     * Returns an error if the file does not exist unless the "create" flag is set.
     * If the file does already exist and the "create" flag is set, the file contents are discarded.
     */
    virtual OS::ResultAnd<> Open(FileContext&, OpenFlags);

    OS::ResultAnd<> OpenReadOnly(FileContext& context) {
        return Open(context, { .write = false });
    }

    /**
     * @return Result code and number of bytes read (0 on error)
     */
    virtual OS::ResultAnd<uint32_t> Read(FileContext&, uint64_t offset, uint32_t num_bytes, FileBuffer&& dest);

    /**
     * Overwrites file contents of the given size (num_bytes) at the given
     * offset with the data from the PXIBuffer argument.
     * @return Result code and number of bytes written (0 on error)
     */
    virtual OS::ResultAnd<uint32_t> Overwrite(OS::FakeThread& thread, uint64_t offset, uint32_t num_bytes, const PXIBuffer& data);

    // Returns result code and file size in bytes (0 on error)
    virtual OS::ResultAnd<uint64_t> GetSize(FileContext&)  {return std::make_tuple(OS::RESULT_OK, 0);}

    /**
     * Resize the file by inserting unspecified data or removing backmost data.
     * For the sake of deterministic emulation, all future read operations are
     * guaranteed to return 0 until the data is initialized by the application.
     */
    virtual OS::ResultAnd<> SetSize(OS::FakeThread& thread, uint64_t size) {return std::make_tuple(OS::RESULT_OK);}

    virtual void Close(/*OS::FakeThread& thread*/) {}
};

class HostFile final : public File {
public:
    enum Policy {
        Default = 0,
        PatchHash = 1,
    };

private:
    const std::filesystem::path path;
    std::fstream stream;

    Policy policy;

public:
    HostFile(std::string_view path, Policy policy);

    OS::ResultAnd<> Open(FileContext&, OpenFlags create) override;

    OS::ResultAnd<> SetSize(OS::FakeThread& thread, uint64_t size) override;
    OS::ResultAnd<uint64_t> GetSize(FileContext&) override;

    OS::ResultAnd<uint32_t> Read(FileContext&, uint64_t offset, uint32_t num_bytes, FileBuffer&& dest) override;
    OS::ResultAnd<uint32_t> Overwrite(OS::FakeThread& thread, uint64_t offset, uint32_t num_bytes, const PXIBuffer& input) override;

    // TODO: Delete functionality

    void Close(/*OS::FakeThread& thread*/) override;
};

class FileView final : public File {
    std::unique_ptr<File> file;
    uint64_t offset;
    uint32_t num_bytes;

    boost::optional<std::array<uint8_t, 0x20>> precomputed_hash;

public:
    FileView(std::unique_ptr<File> file, uint64_t offset, uint32_t num_bytes, boost::optional<std::array<uint8_t, 0x20>> precomputed_hash = boost::none);

    OS::ResultAnd<> Open(FileContext&, OpenFlags) override;

    // SetSize is not allowed on views
    // OS::ResultAnd<> SetSize(OS::FakeThread& thread, uint64_t size) override;

    OS::ResultAnd<uint64_t> GetSize(FileContext&) override;

    OS::ResultAnd<uint32_t> Read(FileContext&, uint64_t offset, uint32_t num_bytes, FileBuffer&& dest) override;
    OS::ResultAnd<uint32_t> Overwrite(OS::FakeThread& thread, uint64_t offset, uint32_t num_bytes, const PXIBuffer& input) override;

    std::array<uint8_t, 0x20> GetFileHash(OS::FakeThread& thread) const;

    // TODO: Should we use this for FS emulation too?
    std::unique_ptr<File> ReleaseParentAndClose();
};

class Archive {
    Archive(const Archive&) = delete;

protected:
    Archive() = default;

public:
    virtual ~Archive() = default;

    std::pair<OS::Result,std::unique_ptr<File>> OpenFile(OS::FakeThread&, const HLE::CommonPath&);

    virtual std::pair<OS::Result,std::unique_ptr<File>> OpenFile(OS::FakeThread&, const HLE::Utf8PathType&);
    virtual std::pair<OS::Result,std::unique_ptr<File>> OpenFile(OS::FakeThread&, const HLE::BinaryPathType&);
};

// TODO: Deprecate in favor of OpenNCCHSubFile
std::unique_ptr<File> NCCHOpenExeFSSection(spdlog::logger&, FileContext&, const KeyDatabase&, std::unique_ptr<File> ncch, uint8_t sub_file_type, std::basic_string_view<uint8_t> requested_exefs_section_name);

std::unique_ptr<File> OpenNCCHSubFile(OS::Thread& thread, Platform::PXI::PM::ProgramInfo, uint32_t content_id, uint32_t sub_file_type, std::basic_string_view<uint8_t> file_path, Loader::GameCard*);

} // namespace FS

} // namespace PXI

} // namespace HLE
