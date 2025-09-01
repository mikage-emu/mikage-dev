#include "fs.hpp"
#include "framework/meta_tools.hpp"
#include "fs_common.hpp"
#include "fs_paths.hpp"

#include <platform/file_formats/ncch.hpp>
#include "loader/gamecard.hpp"
#include "platform/fs.hpp"
#include "platform/ipc.hpp"
#include "platform/pxi.hpp"
#include "platform/sm.hpp"
#include "../os.hpp"
#include "../os_serialization.hpp"

#include <framework/exceptions.hpp>

#include <boost/algorithm/cxx11/all_of.hpp>

#include <boost/range/irange.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/range/adaptor/sliced.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/algorithm/copy.hpp>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/numeric.hpp>

#include <range/v3/numeric.hpp>
#include <range/v3/algorithm/copy.hpp>
#include <range/v3/algorithm/find.hpp>
#include <range/v3/algorithm/transform.hpp>
#include <range/v3/iterator/insert_iterators.hpp>
#include <range/v3/view/iota.hpp>
#include <range/v3/view/take.hpp>

#include <codecvt>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace Platform::FS;

namespace HLE {

// TODO: Factor out the state in FakeFS into a separate state for this
using FSContext = FakeFS;

using OS::HandlePrinter;
using OS::ThreadPrinter;
using OS::HANDLE_INVALID;
using OS::WrappedFakeThread;
using OS::ClientSession;
using OS::ServerSession;
using OS::Thread;

// TODO: Steel diver fails to boot if this directory doesn't exist - should make sure to create it automatically!
static std::filesystem::path HostSdmcDirectory(Settings::Settings& settings) {
    return GetRootDataDirectory(settings) / "sdmc/";
}

/**
 * FileBuffer that refers to emulated memory
 */
class FileBufferInEmulatedMemory : public FileBuffer {
public:
    FakeThread& thread;
    uint32_t address;

    void Write(const char* source, uint32_t num_bytes) override {
        auto WriteToAddr = [this](auto&& addr, auto&& value) { thread.WriteMemory(addr, value); return addr + 1; };
        ranges::v3::accumulate(source, source + num_bytes, address, WriteToAddr);
    }

    FileBufferInEmulatedMemory(FakeThread& thread, uint32_t address) : thread(thread), address(address) {
    }
};

void File::Fail() {
    throw std::runtime_error(std::string{"Unimplemented file operation for \""} + GetFileName() + "\"");
}

OS::OS::ResultAnd<uint32_t> File::Read(FileContext&, FSContext&, uint64_t offset, uint32_t num_bytes, FileBuffer&) {
    Fail();
    return std::make_tuple(RESULT_OK, 0);
}

OS::OS::ResultAnd<uint32_t> File::Write(FakeThread& thread, FSContext&, uint64_t offset, uint32_t num_bytes, uint32_t options, uint32_t buffer_addr) {
    Fail();
    return std::make_tuple(RESULT_OK, 0);
}

class RomfsFile : public File {
    ProgramInfo program_info;
    std::ifstream ncch;
    std::ifstream::pos_type romfs_start;
    uint32_t romfs_size;

    std::string filename;

public:
    RomfsFile(FSContext& context, ProgramInfo& program_info) : program_info(program_info) {
        if (program_info.media_type == 0) {
            // TODO: The content ID is hardcoded currently.
            uint32_t content_id = 0;
            filename = [&]() -> std::string {
                std::stringstream filename;
                filename << GetRootDataDirectory(context.settings).string() << "/";
                filename << std::hex << std::setw(8) << std::setfill('0') << (program_info.program_id >> 32);
                filename << "/";
                filename << std::hex << std::setw(8) << std::setfill('0') << (program_info.program_id & 0xFFFFFFFF);
                filename << "/content/";
                filename << std::hex << std::setw(8) << std::setfill('0') << content_id;
                filename << ".cxi";
                return filename.str();
            }();
            ncch.exceptions(std::ifstream::badbit | std::ifstream::failbit | std::ifstream::eofbit);
            ncch.open(filename);
            auto ncch_start = ncch.tellg();
            ncch.seekg(ncch_start + static_cast<std::ifstream::off_type>(offsetof(FileFormat::NCCHHeader,romfs_offset)));
            decltype(FileFormat::NCCHHeader::romfs_offset) offset;
            decltype(FileFormat::NCCHHeader::romfs_offset) size;
            ncch.read(reinterpret_cast<char*>(&offset), sizeof(offset));
            ncch.read(reinterpret_cast<char*>(&size), sizeof(size));

            auto ivfc_start = ncch_start + static_cast<std::ifstream::off_type>(offset.ToBytes());
/*            std::cerr << "ivfc offset: 0x" << std::hex << ivfc_start-ncch_start << std::endl;
            ncch.seekg(ivfc_start + static_cast<std::ifstream::off_type>(0x3c)); // offset in IVFC to level 3 entry offset
            boost::endian::little_uint32_t level3_offset;
            ncch.read(reinterpret_cast<char*>(&level3_offset), sizeof(level3_offset));
            std::cerr << "level3 offset: 0x" << std::hex << level3_offset << std::endl;*/

//            romfs_start = ivfc_start + static_cast<std::ifstream::off_type>(level3_offset);
            romfs_start = ivfc_start + static_cast<std::ifstream::off_type>(0x1000);
            romfs_size = size.ToBytes();
        } else if (program_info.media_type == 2) {
            throw std::runtime_error("TODO.");
        } else {
            throw std::runtime_error("Unknown media type");
        }
    }

    // Returns result code and number of bytes read (0 on error)
    OS::OS::ResultAnd<uint32_t> Read(FileContext&, FSContext&, uint64_t offset, uint32_t num_bytes, FileBuffer& buffer) override {
        ncch.seekg(romfs_start + static_cast<std::ifstream::off_type>(offset));
        if (offset + num_bytes > romfs_size) {
            throw std::runtime_error(fmt::format("Read end address {:#x} exceeds RomFS size {:#x}", offset + num_bytes, romfs_size));
        }

        std::vector<char> data(num_bytes);
        ncch.read(data.data(), num_bytes);

        buffer.Write(data.data(), num_bytes);

/*        std::stringstream ss;
        for (uint32_t off = 0; off < num_bytes; ++off)
            ss << std::setw(2) << std::hex << std::setfill('0') << static_cast<uint32_t>(static_cast<uint8_t>(thread.ReadMemory(buffer_addr + off)));
        std::cerr << ss.str() << std::endl;*/

        return std::make_tuple(RESULT_OK, num_bytes);
    }

    virtual OS::OS::ResultAnd<uint32_t> Write(FakeThread& thread, FSContext&, uint64_t offset, uint32_t num_bytes, uint32_t options, uint32_t buffer_addr) override {
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);
        return std::make_tuple(RESULT_OK, 0 /* TODO: Value of bytes written */);
    }

    virtual const char* GetFileName() override {
        static std::string buffer;
        buffer = filename + "(romfs)";
        return buffer.c_str();
    }
};

class FileSaveData : public File {
    std::fstream output_file;
    uint64_t size = 0;

    // If true, Write()ing past the file size will implicitly resize the file
    // If false, Write will discard any input data exceeding the file size
    bool implicit_resize = false;

public:
    /**
     * @param host_savegame_path Path to the savegame directory on the host
     * @param internal_path Path to the file within the savegame tree, starting with '/'
     */
    FileSaveData(FSContext& context, const ValidatedHostPath& path, bool create, bool implicit_resize)
        : implicit_resize(implicit_resize) {
        if (!std::filesystem::exists(path.path.parent_path())) {
            context.logger.info("Parent directory {} does not exist, returning error", path.path.parent_path().string());
            throw IPC::IPCError { 0, 0xc8804471 };
        }

        output_file.exceptions(std::ifstream::badbit | std::ifstream::failbit | std::ifstream::eofbit);

        if (!std::filesystem::exists(path)) {
            if (create) {
                context.logger.info("Implicitly creating file at {}", path.path.string());
                // Create the file by opening and then closing it. This is done in a separate step so that we don't "accidentally" end up in append mode
                output_file.open(path.path, std::ios::out);
                output_file.close();
            } else {
                throw IPC::IPCError { 0, 0xc8804470 };
            }
        }

        if (!std::filesystem::is_regular_file(path)) {
            test_mode ? throw IPC::IPCError { 0, 0xe0c04702 }
                      : throw std::runtime_error(fmt::format("Attempted to create FileSaveData from path {} that is not a file", path.path.string()));
        }

        output_file.open(path.path, std::ios::binary | std::ios::out | std::ios::in);

        // Get file size
        output_file.seekg(0, std::ios::beg);
        auto begin = output_file.tellg();
        output_file.seekg(0, std::ios::end);
        size = output_file.tellg() - begin;
    }

    // Returns result code and number of bytes read (0 on error)
    OS::OS::ResultAnd<uint32_t> Read(FileContext& context, FSContext&, uint64_t offset, uint32_t num_bytes, FileBuffer& buffer) override {
        if (offset > size) {
            throw std::runtime_error("Attempted to seek past end of file");
        }

        if (num_bytes == 0) {
            throw std::runtime_error("Tried to read 0 bytes. Not invalid, but indicates an emulator bug");
        }

        output_file.seekg(offset, std::ios_base::beg);

        std::vector<char> data(num_bytes);
        try {
            output_file.read(data.data(), num_bytes);
        } catch (std::ios_base::failure& err) {
            if (test_mode) {
                context.logger.warn("Failure during file read due to ios exception: {}", err.what());
                // Ignore error and return number of bytes we managed to read
                output_file.clear();
            } else {
                throw std::runtime_error(fmt::format("Failed to read data from file: {}", err.what()));
            }
        }
        auto bytes_read = output_file.gcount();

        buffer.Write(data.data(), bytes_read);

        // NOTE: When only parts of the requested data could be read, the result code will still indicate success
        return std::make_tuple(RESULT_OK, bytes_read);
    }

    OS::OS::ResultAnd<uint32_t> Write(FakeThread& thread, FSContext&, uint64_t offset, uint32_t num_bytes, uint32_t options, uint32_t buffer_addr) override {
        if (offset > size) {
            if (test_mode) {
                // The write cursor must always start within the bounds of the file (error 0xe0e046ca),
                // but for non-resizeable files error 0xe0e046c1 takes precedence
                return std::make_tuple<Result, uint32_t>(implicit_resize ? 0xe0e046ca : 0xe0e046c1, 0);
            } else {
                throw std::runtime_error("Attempted to seek past end of file");
            }
        }

        // TODO: Bravely Default has been found to use options 0x10001. Figure out what the actual set of supported options is
        if (!implicit_resize && (options != 0 && options != 0x10001)) {
            return test_mode ? std::make_tuple<Result, uint32_t>(0xe0e046c1, 0)
                             : throw std::runtime_error("May not use non-zero options for non-implicitly resizeable file");
        }

        if (num_bytes == 0) {
            // NOTE: mset performs a zero-length write to idb.dat during initial system setup after setting the time
            return std::make_tuple(RESULT_OK, uint32_t { 0 });
        }

        output_file.seekp(offset, std::ios_base::beg);

        if (!implicit_resize && offset + num_bytes > size) {
            if (!test_mode) {
                throw std::runtime_error("Writing past end of non-implicitly resizable file");
            } else {
                num_bytes = size - offset;
            }
        }

        auto DataAddressRange = boost::irange(buffer_addr, buffer_addr + num_bytes);
        auto ReadFromAddr = std::bind(&FakeThread::ReadMemory, &thread, std::placeholders::_1);
        std::vector<char> data(num_bytes);
        boost::copy(DataAddressRange | boost::adaptors::transformed(ReadFromAddr), data.begin());

        output_file.write(data.data(), data.size());
        output_file.flush();

        if (size < offset + num_bytes)
            size = offset + num_bytes;

        return std::make_tuple(RESULT_OK, num_bytes);
    }

    OS::OS::ResultAnd<uint64_t> GetSize(FakeThread& thread, FSContext&) override {
        return std::make_tuple(RESULT_OK, size);
    }

    OS::OS::ResultAnd<> SetSize(FakeThread& thread, FSContext&, uint64_t size) override {
        if (size < this->size) {
        // Home Menu workaround
//            throw std::runtime_error(fmt::format("Reducing file size not supported, yet (current size: {:#x}, requested {:#x})",
//                                                 this->size, size));
        } else if (size != this->size) {
            output_file.seekp(0, std::ios_base::end);
            std::vector<char> zeroes(64, 0);
            const uint64_t bytes_to_append = size - this->size;
            for (uint64_t bytes_left = bytes_to_append; bytes_left > 0;) {
                auto chunk_size = std::min<uint64_t>(64, bytes_left);
                output_file.write(zeroes.data(), chunk_size);
                bytes_left -= chunk_size;
            }
            this->size = size;
        }

        return std::make_tuple(RESULT_OK);
    }
};

class GenericHostFile : public File {
    std::fstream output_file;
    uint64_t size = 0;

public:
    static constexpr Result result_file_not_found = 0xc8804478;

    // Same as for files
    static constexpr Result result_directory_not_found = 0xc8804478;

    static constexpr Result result_file_already_exists = 0xc82044be;

    static constexpr Result result_directory_already_exists = 0xc82044be;

    /// @param sdmc_path Full path to the SDMC file on the host filesystem
    GenericHostFile(const ValidatedHostPath& path, bool create) {
        if (!std::filesystem::exists(path)) {
            if (create) {
                // Create the file by opening and then closing it. This is done in a separate step so that we don't "accidentally" end up in append mode
                output_file.open(path.path, std::ios::out);
                output_file.close();
            } else {
                throw IPC::IPCError { 0, result_file_not_found };
            }
        }

        output_file.exceptions(std::ifstream::badbit | std::ifstream::failbit | std::ifstream::eofbit);
        output_file.open(path.path, std::ios::binary | std::ios::out | std::ios::in);

        auto begin = output_file.tellg();
        output_file.seekg(0, std::fstream::end);
        size = output_file.tellg() - begin;
        output_file.seekg(0, std::fstream::beg);
    }

    // Returns result code and number of bytes read (0 on error)
    OS::OS::ResultAnd<uint32_t> Read(FileContext&, FSContext&, uint64_t offset, uint32_t num_bytes, FileBuffer& buffer) override {
        output_file.seekg(offset, std::ios_base::beg);

        std::vector<char> data(num_bytes);
        output_file.read(data.data(), num_bytes);
        buffer.Write(data.data(), num_bytes);

        return std::make_tuple(RESULT_OK, num_bytes);
    }

    OS::OS::ResultAnd<uint32_t> Write(FakeThread& thread, FSContext&, uint64_t offset, uint32_t num_bytes, uint32_t /*options*/, uint32_t buffer_addr) override {
        output_file.seekp(offset, std::ios_base::beg);

        auto DataAddressRange = boost::irange(buffer_addr, buffer_addr + num_bytes);
        auto ReadFromAddr = std::bind(&FakeThread::ReadMemory, &thread, std::placeholders::_1);
        std::vector<char> data(num_bytes);
        boost::copy(DataAddressRange | boost::adaptors::transformed(ReadFromAddr), data.begin());

        output_file.write(data.data(), data.size());
        output_file.flush();

        return std::make_tuple(RESULT_OK, num_bytes);
    }

    OS::OS::ResultAnd<uint64_t> GetSize(FakeThread&, FSContext&) override {
        return std::make_tuple(RESULT_OK, size);
    }

    OS::OS::ResultAnd<> SetSize(FakeThread&, FSContext&, uint64_t new_size) override {
        this->size = new_size;
        return std::make_tuple(RESULT_OK);
    }
};

class FilePXI : public File {
    uint64_t handle;

public:
    FilePXI(uint64_t file_handle) : handle(file_handle) {
    }

    OS::OS::ResultAnd<uint32_t> Read(FileContext&, FSContext& context, uint64_t offset, uint32_t num_bytes, FileBuffer& buffer) override {
        // TODO: Turn PXI indirection into an interface that can be mocked for frontend access. For now, this function will only work with FileBufferInEmulatedMemory
        auto& concrete_buffer = dynamic_cast<FileBufferInEmulatedMemory&>(buffer);

        // Expose the user-provided address through a PXI buffer descriptor and forward this call to PXIFS
        auto static_buffer_info = IPC::StaticBuffer{ concrete_buffer.address, num_bytes, 0 }; // TODO: Do we need to specify the data size here or the actual static buffer size?

        auto size = IPC::SendIPCRequest<Platform::PXI::FS::ReadFile>(concrete_buffer.thread, context.pxifs_session, handle, offset, num_bytes, static_buffer_info);
        return std::make_tuple(RESULT_OK, size);
    }



//     OS::OS::ResultAnd<uint32_t> Write(FakeThread& thread, uint64_t offset, uint32_t num_bytes, uint32_t options, uint32_t buffer_addr) override {
//         output_file.seekp(offset, std::ios_base::beg);
//
//         auto DataAddressRange = boost::irange(buffer_addr, buffer_addr + num_bytes);
//         auto ReadFromAddr = std::bind(&FakeThread::ReadMemory, &thread, std::placeholders::_1);
//         std::vector<char> data(num_bytes);
//         boost::copy(DataAddressRange | boost::adaptors::transformed(ReadFromAddr), data.begin());
//         std::cerr << "Writing " << std::dec << num_bytes << " bytes to offset " << std::dec << offset << ": ";
//         boost::copy(data, std::ostream_iterator<char>(std::cerr));
//         std::cerr << std::endl;
//
//         output_file.write(data.data(), data.size());
//         output_file.flush();
//
//         return std::make_tuple(RESULT_OK, num_bytes);
//     }
//

    OS::OS::ResultAnd<uint64_t> GetSize(FakeThread& thread, FSContext& context) override {
         auto size = IPC::SendIPCRequest<Platform::PXI::FS::GetFileSize>(thread, context.pxifs_session, handle);
         return std::make_tuple(RESULT_OK, size);
     }

    OS::OS::ResultAnd<> SetSize(FakeThread& thread, FSContext& context, uint64_t size) override {
         IPC::SendIPCRequest<Platform::PXI::FS::SetFileSize>(thread, context.pxifs_session, size, handle);
         return std::make_tuple(RESULT_OK);
     }
};

/**
 * Represents a file that has been closed but that's still accessible via a session.
 * FakeFS will replace File instances with instances of this class upon receiving a Close() IPC request
 */
class FileClosed : public File {
    OS::OS::ResultAnd<uint32_t> Read(FileContext&, FakeFS&, uint64_t, uint32_t, FileBuffer&) override {
        return test_mode ? std::make_pair<Result, uint32_t>(0xc8a044dc, 0)
                         : throw std::runtime_error("Attempting to Read from closed file");
    }

    OS::OS::ResultAnd<uint32_t> Write(FakeThread&, FakeFS&, uint64_t, uint32_t, uint32_t, uint32_t) override {
        return test_mode ? std::make_pair<Result, uint32_t>(0xc8a044dc, 0)
                         : throw std::runtime_error("Attempting to Write to closed file");
    }

    OS::OS::ResultAnd<uint64_t> GetSize(FakeThread&, FakeFS&) override {
        return test_mode ? std::make_pair<Result, uint64_t>(0xc8a044dc, 0)
                         : throw std::runtime_error("Attempting to GetSize of closed file");
    }

    OS::OS::ResultAnd<> SetSize(FakeThread&, FakeFS&, uint64_t) override {
        return test_mode ? std::make_tuple<Result>(0xc8a044dc)
                         : throw std::runtime_error("Attempting to SetSize of closed file");
    }
};

class SubFile : public File {
    std::shared_ptr<File> file;

    uint64_t offset;
    uint64_t num_bytes;

public:
    SubFile(std::shared_ptr<File> file, uint64_t offset, uint64_t num_bytes) : file(file), offset(offset), num_bytes(num_bytes) {
        ValidateContract(!file->has_subfile);
        file->has_subfile = true;
    }

    ~SubFile() {
        file->has_subfile = false;
    }

    OS::OS::ResultAnd<uint32_t> Read(FileContext& file_context, FakeFS& context, uint64_t subfile_offset, uint32_t subfile_num_bytes, FileBuffer& target) override {
        if (subfile_offset + subfile_num_bytes > num_bytes) {
            throw Mikage::Exceptions::Invalid("Attempted to read past sub file boundaries");
        }
        return file->Read(file_context, context, offset + subfile_offset, subfile_num_bytes, target);
    }
};

bool File::HasOpenSubFile() const noexcept {
    return has_subfile;
}

// TODO.
class Directory {
public:
    virtual ~Directory() = default;

    virtual OS::OS::ResultAnd<uint32_t> GetEntries(FakeThread&, FakeFS&, uint32_t requested_entries, FileBuffer& out_entries) = 0;
};

class HostDirectory : public Directory {
    std::filesystem::path path;
    std::filesystem::directory_iterator iter;

public:
    HostDirectory(const ValidatedHostPath& path) : path(path) {
        if (!std::filesystem::exists(path.path)) {
            // Required by Mario Kart 7 initial save file creation
            // TODOTEST: Is this the right error code?
            throw IPC::IPCError { 0, 0xc8804471 };
//            throw std::runtime_error("Called OpenDirectory on nonexisting directory");
        }

        if (!std::filesystem::is_directory(path.path)) {
            // TODOTEST: Is this the right error code?
            throw IPC::IPCError { 0, 0xe0c04702 };
//            throw std::runtime_error("Called OpenDirectory on path \"" + path.path.generic_string() + "\" that exists but is not a directory");
        }

        iter = std::filesystem::directory_iterator(path);
        // TODOTEST: What happens if the directory is modified after opening and before enumerating its contents?
    }

    OS::OS::ResultAnd<uint32_t> GetEntries(FakeThread&, FakeFS&, uint32_t requested_entries, FileBuffer& out_entries) override {
        // NOTE: This function is stateful: Subsequent calls skip previously retrieved entries

        if (requested_entries == 0) {
            // Return early to avoid advancing the directory iterator
            // TODO: Should probably assert to avoid this entirely for now
            return std::make_pair(RESULT_OK, uint32_t { 0 });
        }

//        auto it = iter;
        uint32_t actual_entries = 0;
        while (iter != std::filesystem::directory_iterator{}) {
            auto entry = *iter++;
            // TODO: Merge with Entry defined by platform
            struct Entry {
                uint16_t name_utf16[0x20c / 2];
                uint8_t short_name[0xa]; // short 8.3 filename without extension
                uint8_t short_name_ext[0x4];  // short filename extension
                uint8_t always_1;
                uint8_t unknown;
                uint8_t is_directory;
                uint8_t is_hidden;
                uint8_t is_archive;
                uint8_t is_read_only;
                uint64_t size;
            } out_entry {};
            static_assert(sizeof(out_entry) == 0x228);

            out_entry.always_1 = 1;
            out_entry.is_directory = entry.is_directory();
            out_entry.is_read_only = false; // TODO
            if (!entry.is_directory()) {
                out_entry.size = entry.file_size();
            }

            ranges::copy(entry.path().filename().string(), out_entry.name_utf16);
//            uint16_t
//            for (char c : entry.path().filename()) {
//                out_entry.name_utf8), entry.path().filename().c_str(), sizeof(out_entry.name_utf8));
//            }
//            strncpy(reinterpret_cast<char*>(out_entry.name_utf8), entry.path().filename().c_str(), sizeof(out_entry.name_utf8));
            // TODO: Properly encode as 8.3?
            strncpy(reinterpret_cast<char*>(out_entry.short_name), entry.path().filename().c_str(), sizeof(out_entry.short_name));
            strncpy(reinterpret_cast<char*>(out_entry.short_name_ext), entry.path().extension().c_str(), sizeof(out_entry.short_name_ext));
            // TODO: Short name + ext

            // Some 3DS homebrew applications expect this field to be set for
            // non-directory files. This does no harm as the bit would usually
            // be set for an SD card used on the 3DS anyway.
            out_entry.is_archive = !out_entry.is_directory;

            // TODO: Use proper serialization
            // TODOTEST: Does data after the null-terminated filename need to be zeroed out?
            out_entries.Write(reinterpret_cast<char*>(&out_entry), sizeof(out_entry));

            ++actual_entries;
            if (actual_entries >= requested_entries) {
                break;
            }
        }

        // TODO: If fewer than the total number of entries were requested, does the return value indicate how many entries there are in total?

        return std::make_pair(RESULT_OK, actual_entries);
    }
};

Result Archive::CreateFile(FakeThread& thread, FakeFS& context, uint32_t transaction, uint32_t attributes,
                           uint64_t initial_file_size, uint32_t file_path_type, IPC::StaticBuffer file_path) {
    throw std::runtime_error(std::string("CreateFile not implemented for archive ") + typeid(*this).name());
}

ArchiveFormatInfo Archive::GetFormatInfo(FakeThread&, FakeFS&) {
    throw std::runtime_error(std::string("GetFormatInfo not implemented for archive ") + typeid(*this).name());
}

class ArchivePXI : public Archive {
    uint64_t handle;
    uint32_t archive_id;

public:
    ArchivePXI(FakeThread& thread, FSContext& context, uint32_t archive_id, uint32_t path_type, IPC::StaticBuffer path)
        : handle(IPC::SendIPCRequest<Platform::PXI::FS::OpenArchive>(thread, context.pxifs_session, archive_id, path_type, path.size, path)),
          archive_id(archive_id) {
    }

    std::pair<Result,std::unique_ptr<File>> OpenFile(FakeThread& thread, FSContext& context, uint32_t transaction, uint32_t open_flags, uint32_t attributes, uint32_t path_type, IPC::StaticBuffer path) override {
        if (path_type != 2)
            throw std::runtime_error(fmt::format("Unknown file path {:#x} for PXI archive id {:#x}", path_type, archive_id));

        path = AdjustFilePath(thread, path);

        auto file = IPC::SendIPCRequest<Platform::PXI::FS::OpenFile>(thread, context.pxifs_session, transaction, handle, path_type, path.size, open_flags, attributes, path);
        auto file_ptr = std::unique_ptr<File>(new FilePXI(file));

        return std::make_pair(RESULT_OK, std::move(file_ptr));
    }

    std::pair<Result,std::unique_ptr<Directory>> OpenDirectory(FakeThread&, FakeFS&, uint32_t path_type, IPC::StaticBuffer path) override {
        throw std::runtime_error("OpenDirectory not implemented for ArchivePXI");
//        return std::pair<Result,std::unique_ptr<Directory>>(RESULT_OK, nullptr);
    }

    Result CreateDirectory(FakeThread&, FakeFS&, uint32_t path_type, IPC::StaticBuffer path) override {
        throw std::runtime_error("CreateDirectory not implemented for ArchivePXI");
    }

    virtual Result DeleteFile(FakeThread& thread, FSContext& context, uint32_t transaction, uint32_t path_type, IPC::StaticBuffer path) override final {
        throw std::runtime_error(fmt::format("DeleteFile not implemented for ArchivePXI"));
    }

    virtual Result RenameFile(FakeThread&, FSContext&, uint32_t, uint32_t, IPC::StaticBuffer, uint32_t, IPC::StaticBuffer) override final {
        throw std::runtime_error(fmt::format("RenameFile not implemented for ArchivePXI"));
    }

    virtual Result DeleteDirectory(FakeThread& thread, FSContext& context, uint32_t transaction, bool recursive, uint32_t path_type, IPC::StaticBuffer path) override final {
        throw std::runtime_error(fmt::format("DeleteDirectory not implemented for ArchivePXI"));
    }

    // Can be customized by child classes to reorder or generate fields on-the-fly
    virtual IPC::StaticBuffer AdjustFilePath(FakeThread& thread, IPC::StaticBuffer path) const {
        return path;
    }
};

class ArchiveDummy final : public Archive {
    uint32_t archive_id;

public:
    ArchiveDummy(FakeThread& thread, FSContext&, uint32_t path_type, IPC::StaticBuffer path, uint32_t archive_id) : archive_id(archive_id) {
        thread.GetLogger()->info("path size {}", path.size);

//         if (path_type != 1)
//             throw std::runtime_error(fmt::format("Invalid path type (expected 1, got {})", path_type));
//
//         if (path.size != 1)
//             throw std::runtime_error(fmt::format("Invalid path size (expected 1, got {})", path.size));

        // TODO: Implement. Stubbed for now to see what kind of files are opened for this
    }

    std::pair<Result,std::unique_ptr<File>> OpenFile(FakeThread&, FSContext&, uint32_t, uint32_t, uint32_t, uint32_t, IPC::StaticBuffer) override final {
        throw std::runtime_error(fmt::format("TODO: Implement OpenFile for archive {:#x}", archive_id));
    }

    std::pair<Result,std::unique_ptr<Directory>> OpenDirectory(FakeThread&, FakeFS&, uint32_t path_type, IPC::StaticBuffer path) override {
        throw std::runtime_error(fmt::format("OpenDirectory not implemented for {:#x}", archive_id));
    }

    Result CreateDirectory(FakeThread&, FakeFS&, uint32_t path_type, IPC::StaticBuffer path) override {
        throw std::runtime_error(fmt::format("CreateDirectory not implemented for archive {:#x}", archive_id));
    }

    Result DeleteFile(FakeThread&, FSContext&, uint32_t, uint32_t, IPC::StaticBuffer) override final {
        return RESULT_OK;
    }

    Result DeleteDirectory(FakeThread&, FSContext&, uint32_t, bool recursive, uint32_t, IPC::StaticBuffer) override final {
        throw std::runtime_error(fmt::format("TODO: Implement OpenDirectory for archive {:#x}", archive_id));
    }

    Result RenameFile(FakeThread&, FakeFS&, uint32_t transaction, uint32_t source_path_type, IPC::StaticBuffer source_path, uint32_t target_path_type, IPC::StaticBuffer target_path) override final {
        throw std::runtime_error(fmt::format("TODO: Implement RenameFile for archive {:#x}", archive_id));
    }
};

/// Base class for archives that do not directly map to a PXIFS archive
class ArchiveNonPXI : public Archive, PathValidator {
public:
    virtual ~ArchiveNonPXI() = default;

    struct invalid_path_tag {};
    struct empty_path_tag {};

    using ValidatedPath = ValidatedHostPath;

private:
    virtual Result ResultFileNotFound() const = 0; // 0xc8804470 for savegames, 0xc8804478 for sdmc
    virtual Result ResultDirectoryNotFound() const = 0; // 0xc8804471 for savegames, 0xc8804478 for sdmc
    virtual Result ResultFileAlreadyExists() const = 0; // 0xc82044b4 for savegames, 0xc82044be for sdmc
    virtual Result ResultDirectoryAlreadyExists() const = 0; // 0xc82044b9 for savegames, 0xc82044be for sdmc

    // Open from binary path
    virtual std::pair<Result,std::unique_ptr<File>> OpenFile(FakeThread&, FSContext&, uint32_t, uint32_t, uint32_t, uint8_t[], size_t);

    // Open from human readable UTF8 path
    virtual std::pair<Result, std::unique_ptr<File>>
    OpenFile(FakeThread&, FakeFS&, uint32_t transaction, uint32_t open_flags, uint32_t attributes, const ValidatedPath&);

    virtual Result DeleteFile(FakeThread&, FakeFS&, uint32_t /*transaction*/, const ValidatedPath&) {
        throw std::runtime_error(std::string("DeleteFile not implemented for archive ") + typeid(*this).name());
    }

    virtual Result RenameFile(FakeThread&, FakeFS&, uint32_t /*transaction*/, const ValidatedPath&, const ValidatedPath&) {
        throw std::runtime_error(std::string("RenameFile not implemented for archive ") + typeid(*this).name());
    }

    virtual Result CreateDirectory(FakeThread&, FakeFS&, const ValidatedPath&) {
        throw std::runtime_error(std::string("CreateDirectory not implemented for archive ") + typeid(*this).name());
    }

    virtual Result DeleteDirectory(FakeThread& thread, FSContext&, uint32_t /*transaction*/, bool /*recursive*/, const ValidatedPath&) {
        throw std::runtime_error(std::string("DeleteDirectory not implemented for archive ") + typeid(*this).name());
    }

    virtual std::pair<Result,std::unique_ptr<Directory>> OpenDirectory(FakeThread&, FSContext&, const ValidatedPath&) {
        throw std::runtime_error(std::string("OpenDirectory not implemented for archive ") + typeid(*this).name());
    }

private:
    std::pair<Result,std::unique_ptr<File>> OpenFile(FakeThread& thread, FSContext& context, uint32_t transaction, uint32_t open_flags, uint32_t attributes, uint32_t path_type, IPC::StaticBuffer path) override final {
        switch (path_type) {
        case 2:
        {
            // Binary path
            std::vector<uint8_t> data(path.size);
            auto DataAddressRange = ranges::view::ints(path.addr, path.addr + path.size);
            auto ReadFromAddr = [&thread](auto addr) { return thread.ReadMemory(addr); };
            ranges::transform(DataAddressRange, data.begin(), ReadFromAddr);

            return OpenFile(thread, context, transaction, open_flags, attributes, data.data(), data.size());
        }

        default:
        {
            auto common_path = CommonPath(thread, path_type, path.size, path);

            auto open_file_from_utf8 = [&](const Utf8PathType& utf8_path) {
                return OpenFile(thread, context, transaction, open_flags, attributes,
                                ValidateAndGetSandboxedTreePath(utf8_path));
            };

            return common_path.Visit(   open_file_from_utf8,
                                        [](const BinaryPathType&) -> std::pair<Result,std::unique_ptr<File>> { throw std::runtime_error("Binary path handling for ArchiveNonPXI not implemented"); });
        }
        }
    }

protected:
    virtual Result CreateFile(FakeThread& thread, FSContext& context, uint32_t transaction, uint32_t attributes,
                              uint64_t initial_file_size, const ValidatedPath& path) {
        auto attempt_open_file = [&](uint32_t open_flags) {
            return OpenFile(thread, context, transaction, open_flags, attributes, path);
        };

        Result result;
        {
            // Verify the file does not exist already
            std::unique_ptr<File> file;
            try {
                std::tie(result, file) = attempt_open_file(1);
                if (result == RESULT_OK) {
                    // File already exists
                    return test_mode ? ResultFileAlreadyExists()
                                     : throw std::runtime_error("Tried to CreateFile with a path that points to an existing file");
                }
            } catch (IPC::IPCError& err) {
                if (err.result != ResultFileNotFound()) {
                    // Re-throw unexpected error
                    throw;
                }
            }

            // Actually create the file now
            std::tie(result, file) = attempt_open_file(6 /* create and open writable */);
            if (result != RESULT_OK) {
                thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);
            }

            std::tie(result) = file->SetSize(thread, context, initial_file_size);
            if (result != RESULT_OK) {
                throw std::runtime_error("Failed to set initial size of newly created file");
            }

            // Fill a dummy buffer with zeroes to initialize the file contents
            auto buffer = thread.GetParentProcess().AllocateBuffer(64);
            memset(buffer.second, 0, 64);

            for (uint64_t offset = 0; offset < initial_file_size; offset += 64) {
                auto bytes_to_write = static_cast<uint32_t>(std::min(uint64_t{64}, initial_file_size - offset));
                uint32_t bytes_written;
                std::tie(result, bytes_written) = file->Write(thread, context, offset, bytes_to_write, 0, buffer.first);
                if (result != RESULT_OK || bytes_written != bytes_to_write) {
                    thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);
                }
            }

            thread.GetParentProcess().FreeBuffer(buffer.first);
        }

        return result;
    }

private:
    Result CreateFile(FakeThread& thread, FakeFS& context, uint32_t transaction, uint32_t attributes, uint64_t initial_file_size, uint32_t path_type, IPC::StaticBuffer path) override {
        auto common_path = CommonPath(thread, path_type, path.size, path);
        auto create_file_from_utf8 = [&](const Utf8PathType& utf8_path) {
            return CreateFile(  thread, context, transaction, attributes, initial_file_size,
                                ValidateAndGetSandboxedTreePath(utf8_path));
        };

        return common_path.Visit(   create_file_from_utf8,
                                    [](const BinaryPathType&) -> Result { throw std::runtime_error("Binary path handling for ArchiveNonPXI not implemented"); });
    }

    Result DeleteFile(FakeThread& thread, FSContext& context, uint32_t transaction, uint32_t path_type, IPC::StaticBuffer path) override final {
        auto delete_file_from_utf8 = [&](const Utf8PathType& utf8_path) {
            return DeleteFile(  thread, context, transaction,
                                ValidateAndGetSandboxedTreePath(utf8_path));
        };

        auto common_path = CommonPath(thread, path_type, path.size, path);
        return common_path.Visit(  delete_file_from_utf8,
                                   [](const BinaryPathType&) -> Result { throw std::runtime_error("Binary path handling for ArchiveNonPXI not implemented"); });
    }

    Result RenameFile(FakeThread& thread, FSContext& context, uint32_t transaction, uint32_t source_path_type, IPC::StaticBuffer source_path, uint32_t target_path_type, IPC::StaticBuffer target_path) override final {
        auto error_unsupported_binary_path = [](const BinaryPathType&) -> Result { throw std::runtime_error("Binary path handling for ArchiveNonPXI not implemented"); };

        auto source_common_path = CommonPath(thread, source_path_type, source_path.size, source_path);
        auto target_common_path = CommonPath(thread, target_path_type, target_path.size, target_path);

        return source_common_path.Visit(
            [&](const Utf8PathType& source_utf8_path) {
                return target_common_path.Visit(
                    [&](const Utf8PathType& target_utf8_path) {
                        return RenameFile(  thread, context, transaction,
                                            ValidateAndGetSandboxedTreePath(source_utf8_path),
                                            ValidateAndGetSandboxedTreePath(target_utf8_path));
                    }
                    , error_unsupported_binary_path);
            },
            error_unsupported_binary_path);
    }

    Result CreateDirectory(FakeThread& thread, FakeFS& context, uint32_t path_type, IPC::StaticBuffer path) override final {
        auto create_dir_from_utf8 = [&](const Utf8PathType& utf8_path) {
            return CreateDirectory( thread, context,
                                    ValidateAndGetSandboxedTreePath(utf8_path));
        };

        auto common_path = CommonPath(thread, path_type, path.size, path);
        return common_path.Visit(  create_dir_from_utf8,
                                   [](const BinaryPathType&) -> Result { throw std::runtime_error("Binary path handling for ArchiveNonPXI not implemented"); });
    }

    Result DeleteDirectory(FakeThread& thread, FSContext& context, uint32_t transaction, bool recursive, uint32_t path_type, IPC::StaticBuffer path) override final {
        auto delete_dir_from_utf8 = [&](const Utf8PathType& utf8_path) {
            return DeleteDirectory( thread, context, transaction, recursive,
                                    ValidateAndGetSandboxedTreePath(utf8_path));
        };

        auto common_path = CommonPath(thread, path_type, path.size, path);
        return common_path.Visit(  delete_dir_from_utf8,
                                   [](const BinaryPathType&) -> Result { throw std::runtime_error("Binary path handling for ArchiveNonPXI not implemented"); });
    }

    std::pair<Result,std::unique_ptr<Directory>> OpenDirectory(FakeThread& thread, FakeFS& context, uint32_t path_type, IPC::StaticBuffer path) override {
        auto open_dir_from_utf8 = [&](const Utf8PathType& utf8_path) {
            return OpenDirectory(   thread, context,
                                    ValidateAndGetSandboxedTreePath(utf8_path));
        };

        auto common_path = CommonPath(thread, path_type, path.size, path);
        return common_path.Visit(  open_dir_from_utf8,
                                   [](const BinaryPathType&) -> std::pair<Result,std::unique_ptr<Directory>> { throw std::runtime_error("Binary path handling for ArchiveNonPXI not implemented"); });
    }
};

std::pair<Result,std::unique_ptr<File>> ArchiveNonPXI::OpenFile(FakeThread&, FSContext&, uint32_t, uint32_t, uint32_t, uint8_t*, size_t) {
    throw std::runtime_error(std::string("OpenFile with binary path not implemented for archive ") + typeid(*this).name());
}

std::pair<Result, std::unique_ptr<File>>
ArchiveNonPXI::OpenFile(FakeThread&, FakeFS&, uint32_t, uint32_t, uint32_t, const ValidatedPath&) {
    throw std::runtime_error(std::string("OpenFile not implemented for archive ") + typeid(*this).name());
}

/**
 * Wrapper around ArchivePXI for NCCH access (archives 0x2345678a and 0x2345678e) to
 * deal with differences between FSPXI and FS.
 * When accessing the RomFS, FSPXI includes the full section whereas FS skips the
 * first 0x1000 bytes (up to the level 3 header).
 */
class ArchiveNCCHSection : public ArchivePXI {
public:
    ArchiveNCCHSection(FakeThread& thread, FSContext& context, uint32_t archive_id, uint32_t path_type, IPC::StaticBuffer path)
        : ArchivePXI(thread, context, archive_id, path_type, path) {
        ValidateContract(archive_id == 0x2345678a || archive_id == 0x2345678e);
    }

    std::pair<Result,std::unique_ptr<File>> OpenFile(FakeThread& thread, FSContext& context, uint32_t transaction, uint32_t open_flags, uint32_t attributes, uint32_t path_type, IPC::StaticBuffer path) override {
        auto ret = ArchivePXI::OpenFile(thread, context, transaction, open_flags, attributes, path_type, path);
        if (ret.first != RESULT_OK) {
            return ret;
        }

        if (thread.ReadMemory32(path.addr + 8) != 0) {
            // Non-RomFS sections are returned verbatimly
            return ret;
        }

        auto size = ret.second->GetSize(thread, context);
        if (std::get<0>(size) != RESULT_OK) {
            throw Mikage::Exceptions::NotImplemented("Opened file but could not determine size");
        }

        auto sub_file = std::make_unique<SubFile>(std::shared_ptr<File> { ret.second.release() }, 0x1000, std::get<1>(size) - 0x1000);
        return std::make_pair(RESULT_OK, std::move(sub_file));
    }
};

/**
 * Used to access sections (RomFS, ExeFS banner/icon/logo) of the
 * client application's own NCCH
 */
class ArchiveOwnNCCHSection : public ArchiveNCCHSection {
public:
    ArchiveOwnNCCHSection(FakeThread& thread, FSContext& context, uint32_t path_type, IPC::StaticBuffer path, ProgramInfo program_info)
        : ArchiveNCCHSection(thread, context, 0x2345678a, path_type, AdjustArchivePath(thread, path, program_info)) {
    }

    static IPC::StaticBuffer AdjustArchivePath(FakeThread& thread, IPC::StaticBuffer path, ProgramInfo program_info) {
        if (path.size != 1)
            throw std::runtime_error("Expected archive path with 1 byte of data");

        // TODO: Actually, archive 0x2345678a uses 16-byte archive paths!
        path.size = 12;

        thread.WriteMemory32(path.addr, program_info.program_id & 0xFFFFFFFF);
        thread.WriteMemory32(path.addr + 4, program_info.program_id >> 32);
        thread.WriteMemory32(path.addr + 8, program_info.media_type);

        return path;
    }

    IPC::StaticBuffer AdjustFilePath(FakeThread& thread, IPC::StaticBuffer path) const override {
        if (path.size != 12)
            throw std::runtime_error("Expected file path with 12 bytes of data");

        path.size = 20;

        // Move input path 8 bytes ahead for PXIFS
        thread.WriteMemory32(path.addr + 16, thread.ReadMemory32(path.addr + 8));
        thread.WriteMemory32(path.addr + 12, thread.ReadMemory32(path.addr + 4));
        thread.WriteMemory32(path.addr + 8, thread.ReadMemory32(path.addr + 0));

        thread.WriteMemory32(path.addr, 0); // Request NCCH data
        thread.WriteMemory32(path.addr + 4, 0); // Content index

        return path;
    }
};

/**
 * Proxy for PXI archive 0x1234567c, but tied to one particular saveid (which
 * is specified when opening the archive rather than when opening files).
 *
 * Files in this archive do not display the raw savegame; instead, the actual
 * partition contents are accessible via the given file path.
 *
 * TODO: What mediatype argument is used when opening 0x1234567c? Is it just always 0, i.e. NAND?
 * TODO: Is the first word of the path for this archive part of the saveid or actually the media type?
 */
class ArchiveSystemSaveDataForSaveId : public ArchiveNonPXI {
    FSContext& context;

    uint32_t mediatype;
    uint64_t saveid;

    void InitializeArchive(FakeThread& thread, FSContext& context) {
    mediatype &= 0xff; // TODO: cfg savegame?
        if (mediatype != 0) {
            // Not supported, yet
            thread.GetLogger()->warn("OpenArchive with mediatype {:#x} and saveid {:#x} failed due to unsupported mediatype",
                                     mediatype, saveid);
            throw std::runtime_error("Not implemented");
        }

        // TODO: This archive is supposed to be a proxy to a PXI archive,
        //       but we currently do not have any savegame parsing code
        //       to do this properly.
        const bool accurate_proxy = false;
        if (accurate_proxy) {
            // Reuse static buffer but replace its data with the media type for the PXI archive
//             const uint32_t media_type = 0;
//             thread.WriteMemory32(path.addr, media_type);
//             path.size = 4;
//             handle = IPC::SendIPCRequest<Platform::PXI::FS::OpenArchive>(thread, context.pxifs_session, 0x1234567c, 0x2 /* BINARY */, path.size, path);
        } else {
            // Return error if the save file hasn't been created yet
            if (!std::filesystem::exists(GetSandboxHostRoot())) {
                throw IPC::IPCError{0, 0xc8804470};
            }
        }
    }

    std::filesystem::path GetSandboxHostRoot() const override {
        return GetBaseFilePath(context, saveid);
    }

    // TODO: Verify
    Result ResultFileNotFound() const override {
        return 0xc8804470;
    }
    Result ResultDirectoryNotFound() const override {
        return 0xc8804471;
    }
    Result ResultFileAlreadyExists() const override {
        return 0xc82044b4;
    }
    Result ResultDirectoryAlreadyExists() const override {
        return 0xc82044b9;
    }

public:
    ArchiveSystemSaveDataForSaveId(FakeThread& thread, FSContext& context, uint32_t path_type, IPC::StaticBuffer path) : context(context) {
        if (path_type != 2)
            throw std::runtime_error(fmt::format("Invalid path type (expected 2, got {})", path_type));

        if (path.size != 8)
            throw std::runtime_error(fmt::format("Invalid path size (expected 8, got {})", path.size));

        // NOTE: The lower word of the saveid seems to be implied to be zero for this archive
        mediatype = thread.ReadMemory32(path.addr);
        saveid = thread.ReadMemory32(path.addr + 4);

        InitializeArchive(thread, context);
    }

    ArchiveSystemSaveDataForSaveId(FakeThread& thread, FSContext& context, uint32_t mediatype, uint64_t saveid) : context(context), mediatype(mediatype), saveid(saveid) {
        InitializeArchive(thread, context);
    }

    static std::string GetBaseFileParentPath(FSContext& context, uint64_t saveid) {
        return (GetRootDataDirectory(context.settings) / fmt::format("data/{:016x}/sysdata/{:08x}", GetId0(context), saveid & 0xFFFFFFFF)).string();
    }

    static std::string GetBaseFilePath(FSContext& context, uint64_t saveid) {
        return fmt::format("{}/{:08x}_extracted", GetBaseFileParentPath(context, saveid), saveid >> 32);
    }

    static void CreateSystemSaveData(FSContext& context, MediaType media_type, uint32_t saveid, uint32_t /*size*/) {
        if (media_type != MediaType::NAND) {
            throw Mikage::Exceptions::NotImplemented("Tried to CreateSystemSaveData for non-NAND mediatype");
        }

        if (std::filesystem::exists(GetBaseFilePath(context, saveid))) {
            throw Mikage::Exceptions::NotImplemented("Tried to CreateSystemSaveData for save_id {:#x} that already existed", saveid);
        }

        // TODO: Adopt interface similar to ArchiveSaveDataBase instead

        std::filesystem::create_directories(GetBaseFilePath(context, saveid));
    }

    std::pair<Result, std::unique_ptr<File>>
    OpenFile(FakeThread& thread, FakeFS& context, uint32_t transaction, uint32_t open_flags, uint32_t attributes, const ValidatedPath& path) override {
        const std::string savegame_path = GetBaseFilePath(context, saveid);

        thread.GetLogger()->info("{}ArchiveSystemSaveDataForSaveId opening file \"{}{}\"",
                                 ThreadPrinter{thread}, savegame_path, path.path.string());

        try {
            return { RESULT_OK, std::make_unique<FileSaveData>(context, path, ((open_flags & 0x4) != 0), true /* TODO: Implicit resize needed? */) };
        } catch (std::ios_base::failure& exc) {
            thread.GetLogger()->warn("Opening file failed: {}", exc.what());
            // TODOTEST: What error code to return?
            return { 0xc8804464, std::unique_ptr<FileSaveData>{} };
        }
    }

    virtual Result DeleteFile(FakeThread& thread, FSContext&, uint32_t /*transaction*/, const ValidatedPath& path) override {
        thread.GetLogger()->info("Deleting host file \"{}\"", path.path.string());

        if (!std::filesystem::remove(path.path)) {
            return ResultFileNotFound();
        }

        return RESULT_OK;
    }

    Result CreateDirectory(FakeThread&, FakeFS&, const ValidatedPath& validated_path) override {
        auto path = validated_path.path;

        // Drop redundant '/'s at the end, e.g "/edit/". std::filesystem turns
        // them into "/edit/.", which then breaks create_directory since it
        // expects all intermediate paths to exist (including /edit)
        while (path == ".") {
            path = path.parent_path();
        }

        if (std::filesystem::exists(path)) {
            if (std::filesystem::is_directory(path)) {
                // TODO: Requires testing!
                return ResultDirectoryAlreadyExists();
            }
            throw std::runtime_error("Called CreateDirectory on a non-directory path that already exists");
        }

        std::filesystem::create_directory(path);
        return RESULT_OK;
    }
};


class ArchiveSaveDataProvider {
    // Path to save data that is considered "created" but not "formatted"
    std::filesystem::path unformatted_path;

    // Path to save data (VirtualDirectory for extdata) that is considered both "created" and "formatted"
    std::filesystem::path formatted_path;

    // If true, writes past the end of file should implicitly resize the file
    bool implicit_resize;

    // If true, the save data is treated like extdata
    bool is_ext_data;

    std::filesystem::path FormatInfoPath() const {
        return std::filesystem::path { unformatted_path } / "metadata";
    }

public:
    ArchiveSaveDataProvider(std::string unformatted_path, std::string_view formatted_subpath, bool implicit_resize, bool is_ext_data)
        : unformatted_path(std::move(unformatted_path)), formatted_path({this->unformatted_path / std::move(formatted_subpath)}),
        implicit_resize(implicit_resize), is_ext_data(is_ext_data) {
    }

    bool IsCreated() const {
        return std::filesystem::exists(unformatted_path);
    }

    bool IsFormatted() const {
        return std::filesystem::exists(FormatInfoPath());
    }

    void Create() const {
        if (IsCreated()) {
            throw std::runtime_error(fmt::format("Create() called on save data file \"{}\" that already exists", unformatted_path.string()));
        }
        EnsureCreated();
    }

    /// Idempotent version of Create: Does not return an error when the save data is already created
    void EnsureCreated() const {
        std::filesystem::create_directories(unformatted_path);
    }

    void Format(const ArchiveFormatInfo& format_info) const {
        if (!IsCreated()) {
            throw std::runtime_error(fmt::format("Format() called on save data file \"{}\" that does not exist", unformatted_path.string()));
        }
        if (IsFormatted()) {
            // TODO: Mario Kart 7 seems to hit this
            // TODO: Super Street Fighter Demo seems to hit this
//            throw std::runtime_error(fmt::format("Format() called on save data file \"{}\" that is already formatted", unformatted_path.string()));
        }
        EnsureFormatted(format_info);
    }

    void EnsureFormatted(const ArchiveFormatInfo& format_info) const {
        if (is_ext_data) {
            std::filesystem::create_directory(unformatted_path / "boss");
            std::filesystem::create_directory(unformatted_path / "user");
        } else {
            std::filesystem::create_directory(formatted_path);
        }

        std::ofstream metadata(FormatInfoPath(), std::ios::binary);

        // TODO: Use serialization interface
        metadata.write(reinterpret_cast<const char*>(&format_info), 3 * sizeof(uint32_t));
        uint8_t duplicate_data = format_info.duplicate_data;
        metadata.write(reinterpret_cast<char*>(&duplicate_data), sizeof(duplicate_data));
    }

    ArchiveFormatInfo ReadFormatInfo() const {
        if (!IsFormatted()) {
            throw std::runtime_error(fmt::format("ReadFormatInfo() called on save data file \"{}\" that has not been formatted", formatted_path.string()));
        }

        std::ifstream metadata(FormatInfoPath());

        // TODO: Use serialization interface
        ArchiveFormatInfo format_info;
        metadata.read(reinterpret_cast<char*>(&format_info), 3 * sizeof(uint32_t));
        uint8_t duplicate_data;
        metadata.read(reinterpret_cast<char*>(&duplicate_data), sizeof(duplicate_data));
        format_info.duplicate_data = duplicate_data;
        return format_info;
    }

    std::filesystem::path GetAbsolutePath(const Utf8PathType& raw_path) const {
        return GetAbsolutePath(formatted_path, raw_path);
    }

    static std::filesystem::path GetAbsolutePath(const std::filesystem::path& base_path, const Utf8PathType& raw_path) {
        if (raw_path.empty() || raw_path[0] != '/') {
            throw std::runtime_error("Path must start with '/'");
        }

        std::filesystem::path path = base_path;
        path /= raw_path.to_std_path();
        path = path.lexically_relative(base_path);

        if (path.begin() != path.end() && *path.begin() == "..") {
            throw std::runtime_error("Path \"" + raw_path + "\" escapes sandbox root directory");
        }

        return std::filesystem::absolute(base_path / std::move(path));
    }

    const std::filesystem::path& GetFormattedRootPath() const {
        return formatted_path;
    }

    bool ShouldImplicitlyResize() const {
        return implicit_resize;
    }
};

class ArchiveSaveDataBase : public ArchiveNonPXI {
protected:
    Result ResultFileNotFound() const override {
        return 0xc8804470;
    }
    Result ResultDirectoryNotFound() const override {
        return 0xc8804471;
    }
    Result ResultFileAlreadyExists() const override {
        return 0xc82044b4;
    }
    Result ResultDirectoryAlreadyExists() const override {
        return 0xc82044b9;
    }

    ArchiveSaveDataProvider provider;

    ArchiveSaveDataBase(ArchiveSaveDataProvider provider_, Platform::FS::MediaType media_type)
        : provider(std::move(provider_)) {
        if (media_type == Platform::FS::MediaType::GameCard) {
            // Card saves always exist as part of the physical gamecard chip
            // TODO: The GameCard loader might be a better place to put this
            provider.EnsureCreated();
        }

        if (!provider.IsCreated()) {
            // Return "Not found"
            throw IPC::IPCError { 0, 0xc8804464 };
        }

        if (!provider.IsFormatted()) {
            // Archive has been created but not formatted: Return "Not formatted"
            throw IPC::IPCError { 0, 0xc8a04554 };
        }
    }

    ArchiveFormatInfo GetFormatInfo(FakeThread&, FakeFS&) override {
        return provider.ReadFormatInfo();
    }

    std::filesystem::path GetSandboxHostRoot() const override {
        return canonical(std::filesystem::path { std::string { provider.GetFormattedRootPath() } });
    }

    std::pair<Result, std::unique_ptr<File>>
    OpenFile(FakeThread&, FakeFS& context, uint32_t transaction, uint32_t open_flags, uint32_t attributes, const ValidatedPath& path) override {
        if (open_flags == 0) {
            test_mode ? throw IPC::IPCError { 0, 0xe0c046f8 }
                      : throw std::runtime_error("Tried to OpenFile with invalid open flags");
        }

        return { RESULT_OK, std::make_unique<FileSaveData>(context, path, ((open_flags & 4) != 0), provider.ShouldImplicitlyResize()) };
    }

    Result DeleteFile(FakeThread& thread, FSContext&, uint32_t, const ValidatedPath& path) override {
        if (!std::filesystem::exists(path)) {
            // Non-asserting failure required e.g. by Super Mario 3D Land during startup
            return ResultFileNotFound();
        }

        thread.GetLogger()->warn("Deleting file: {}", path.path.string());

        std::filesystem::remove(path);

        return RESULT_OK;
    }

    Result CreateDirectory(FakeThread&, FakeFS&, const ValidatedPath& validated_path) override {
        auto path = validated_path.path;

        // Drop redundant '/'s at the end, e.g "/edit/". std::filesystem turns
        // them into "/edit/.", which then breaks create_directory since it
        // expects all intermediate paths to exist (including /edit)
        while (path == ".") {
            path = path.parent_path();
        }

        if (std::filesystem::exists(path)) {
            if (std::filesystem::is_directory(path)) {
                // TODO: Requires testing!
                return ResultDirectoryAlreadyExists();
            }
            throw std::runtime_error("Called CreateDirectory on a non-directory path that already exists");
        }

        std::filesystem::create_directory(path);
        return RESULT_OK;
    }

    std::pair<Result,std::unique_ptr<Directory>> OpenDirectory(FakeThread&, FakeFS&, const ValidatedPath& path) override {
        return { RESULT_OK, std::make_unique<HostDirectory>(path) };
    }

    Result DeleteDirectory(FakeThread& thread, FSContext&, uint32_t, bool recursive, const ValidatedPath& path) override {
        thread.GetLogger()->warn("Deleting directory{}: {}", recursive ? " recursively" : "", path.path.string());

        if (!std::filesystem::exists(path.path)) {
            thread.GetLogger()->warn("Directory {} does not exist", path.path.string());

            return test_mode ? ResultDirectoryNotFound()
                             : throw std::runtime_error("Called DeleteDirectory on nonexisting directory");
        }

        if (!std::filesystem::is_directory(path.path)) {
            throw std::runtime_error("Called DeleteDirectory on something that's not a directory");
        }

        if (recursive) {
            throw std::runtime_error("Recursive deletion not supported yet");
        }

        [[maybe_unused]] bool result = std::filesystem::remove(path.path);
        assert(result); // "remove" should only return false if the directory didn't exist, which we checked for above
        return RESULT_OK;
    }
};

// TODO: This archive should be deferred to PXI archive 0x2345678a instead
class ArchiveSaveData : public ArchiveSaveDataBase {
public:
    ArchiveSaveData(FSContext& context, ProgramInfo& program_info) :
        ArchiveSaveDataBase(GetProvider(context, program_info), Platform::FS::MediaType { program_info.media_type }) {
    }

    static ArchiveSaveDataProvider GetProvider(FSContext& context, ProgramInfo& program_info) {
        const bool implicit_resize = true;
        return ArchiveSaveDataProvider(BuildBasePath(context, program_info), "00000001.sav.extracted", implicit_resize, false);
    }

    static std::string BuildBasePath(FSContext& context, const ProgramInfo& program_info) {
        // TODO: Check if save data is formatted, if not return error
        if (program_info.media_type == 0 /* NAND */) {
            // TODO: Figure out if NAND titles actually support this archive. Chances are NAND titles must always use SystemSaveData instead!
            throw std::runtime_error("NAND save data files are not supported, yet");
        }

        // TODO: For now, we automatically map files within save data to files on the host file system.
        //       For compatibility with FSPXI, we should instead map each title's entire save data to one host file.
        uint32_t program_id_high = (program_info.program_id >> 32);
        uint32_t program_id_low = (program_info.program_id & 0xFFFFFFFF);
        if (program_info.media_type == 1 /* SD */) {
            return HostSdmcDirectory(context.settings) / fmt::format("Nintendo 3DS/{:016x}/{:016x}/title/{:08x}/{:08x}/data", GetId0(context), GetId1(context), program_id_high, program_id_low);
        } else if (program_info.media_type == 2 /* Gamecard */) {
            return GetRootDataDirectory(context.settings) / fmt::format("card_savedata/{:08x}/{:08x}/data", program_id_high, program_id_low);
        } else {
            throw std::runtime_error("Unknown media type");
        }
    }
};

/**
 * "Extra Data", which is stored on the SD card even for NAND titles. An
 * exception to this is "shared extdata", which is stored on NAND. This archive
 * is mostly a simplified version ArchiveSaveData (file sizes cannot be changed
 * after creation, and there are no dedicated read-only or write-only file
 * opening modes).
 */
class ArchiveExtSaveData : public ArchiveSaveDataBase {
public:
    enum VirtualDirectory {
        Root     = 0,
        User     = 1,
        SpotPass = 2,
    };

    ArchiveExtSaveData(FakeThread& thread, FSContext& context, const ExtSaveDataInfo& info, bool is_spotpass) :
        ArchiveSaveDataBase(GetProvider(context, info, is_spotpass ? VirtualDirectory::SpotPass : VirtualDirectory::User), info.media_type) {
    }

    ArchiveExtSaveData(FakeThread& thread, FSContext& context, const ExtSaveDataInfo& info) :
        ArchiveSaveDataBase(GetProvider(context, info, VirtualDirectory::Root), info.media_type) {
    }

    static ArchiveSaveDataProvider GetProvider(FSContext& context, const ExtSaveDataInfo& info, VirtualDirectory directory) {
        const bool implicit_resize = false;
        const std::array<const std::string, 3> subpaths = { "", "user", "boss" };
        return ArchiveSaveDataProvider(BuildBasePath(context, info), subpaths.at(directory), implicit_resize, true);
    }

    static std::filesystem::path GetExtDataRootDirectory(FSContext& context, Platform::FS::MediaType media_type) {
        if (media_type == Platform::FS::MediaType::NAND) {
            return GetRootDataDirectory(context.settings) / fmt::format("data/{:016x}/extdata", GetId0(context));
        } else {
            return HostSdmcDirectory(context.settings) / fmt::format("Nintendo 3DS/{:016x}/{:016x}/extdata", GetId0(context), GetId1(context));
        }
    }

    // For FSUser::CreateExtSaveData
    static Result CreateSaveData(FakeThread& thread, FSContext& context, const ExtSaveDataInfo& info, uint32_t max_directories, uint32_t max_files, IPC::MappedBuffer smdh_icon) {
        // Note FSUser::CreateExtSaveData is idempotent: Calling it on an already created save data file is not an error
        auto provider = GetProvider(context, info, VirtualDirectory::Root);
        provider.EnsureCreated();

        // ExtSaveData is formatted automatically
        const uint32_t size = 0; // TODO: Which size should be reported? Citra seems to use 0, but FSUser::CreateExtSaveData does take a size limit parameter, too
        const bool duplicate_data = false; // TODO: Verify this is the returned value
        provider.EnsureFormatted(ArchiveFormatInfo { size, max_directories, max_files, duplicate_data });

        // Write SMDH icon
        std::filesystem::path base_path = BuildBasePath(context, info);
        std::ofstream icon(base_path / "icon", std::ios::binary);
        for (uint32_t i = 0; i < smdh_icon.size; ++i) {
            icon << thread.ReadMemory(smdh_icon.addr + i);
        }

        return RESULT_OK;
    }

    // For FSUser::DeleteExtSaveData
    // TODO: Move to ArchiveSaveDataProvider
    static Result DeleteSaveData(FakeThread& thread, FSContext& context, const ExtSaveDataInfo& info) {
        std::filesystem::path path = BuildBasePath(context, info);
        if (!std::filesystem::exists(path)) {
            return test_mode ? 0xc8804478 : throw std::runtime_error("Tried to delete extdata that doesn't exist");
        }
        if (!std::filesystem::is_directory(path)) {
            throw std::runtime_error("Tried to remove extdata file that somehow is not a directory");
        }
        thread.GetLogger()->warn("Deleting extdata directory {}", path.string());
        std::filesystem::remove_all(path);
        return RESULT_OK;
    }

private:
    static std::string BuildBasePath(FSContext& context, ExtSaveDataInfo info) {
        if (info.media_type == Platform::FS::MediaType::NAND && (info.save_id >> 32) != 0x48000) {
            throw Mikage::Exceptions::Invalid("NAND high extdata ID must be 0x48000");
        } else if (info.media_type == Platform::FS::MediaType::SD && (info.save_id >> 32) != 0) {
            // The FS module accepts any high extdata id here, but in practice only 0 is used
            throw Mikage::Exceptions::NotImplemented("Unexpected SD extdata ID {:#x}", info.save_id);
        } else if (info.media_type == Platform::FS::MediaType::GameCard) {
            throw Mikage::Exceptions::Invalid("Gamecards cannot store extdata");
        }

        // TODO: For now, we automatically map files within save data to files on the host file system.
        //       For compatibility with FSPXI, we should instead map each title's entire save data to one host file.

        uint32_t extdata_id_low = info.save_id & 0xffffffff;
        uint32_t extdata_id_high = info.save_id >> 32;
        return (GetExtDataRootDirectory(context, info.media_type) / fmt::format("{:08x}/{:08x}", extdata_id_high, extdata_id_low)).string();
    }

    Result CreateFile(FakeThread& thread, FSContext& context, uint32_t transaction, uint32_t attributes,
                      uint64_t initial_file_size, const ValidatedPath& path) override {
        // TODO: Use GetAbsolutePath!!
        if (initial_file_size == 0) {
            return test_mode ? 0xe0c046f8
                             : throw std::runtime_error("Tried to CreateFile an ExtData file with zero size");
        }

        auto attempt_open_file = [&](uint32_t open_flags) {
            // Using Base's OpenFile here since our OpenFile doesn't allow file creation
            return ArchiveSaveDataBase::OpenFile(thread, context, transaction, open_flags, attributes, path);
        };

        Result result;
        {
            // Verify the file does not exist already
            std::unique_ptr<File> file;
            try {
                std::tie(result, file) = attempt_open_file(1);
                if (result == RESULT_OK) {
                    // File already exists (non-asserting failure required by
                    // our internal creation logic for shared extra data in
                    // archive 0x00048000f000000b)
                    return ResultFileAlreadyExists();
                }
            } catch (IPC::IPCError& err) {
                if (err.result != ResultFileNotFound()) {
                    // Re-throw unexpected error
                    throw;
                }
            }

            // Actually create the file now
            std::tie(result, file) = attempt_open_file(6 /* create and open writable */);
            if (result != RESULT_OK) {
                thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);
            }
            uint64_t s;
            std::tie(result, s) = file->GetSize(thread, context);

            std::tie(result) = file->SetSize(thread, context, initial_file_size);
            if (result != RESULT_OK) {
                throw std::runtime_error("Failed to set initial size of newly created file");
            }

            // Fill a dummy buffer with zeroes to initialize the file contents
            auto buffer = thread.GetParentProcess().AllocateBuffer(64);
            memset(buffer.second, 0, 64);

            for (uint64_t offset = 0; offset < initial_file_size; offset += 64) {
                auto bytes_to_write = static_cast<uint32_t>(std::min(uint64_t{64}, initial_file_size - offset));
                uint32_t bytes_written;
                std::tie(result, bytes_written) = file->Write(thread, context, offset, bytes_to_write, 0, buffer.first);
                if (result != RESULT_OK || bytes_written != bytes_to_write) {
                    thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);
                }
            }

            thread.GetParentProcess().FreeBuffer(buffer.first);
        }

        return result;
    }

    std::pair<Result, std::unique_ptr<File>>
    OpenFile(FakeThread& thread, FakeFS& context, uint32_t transaction, uint32_t open_flags, uint32_t attributes, const ValidatedPath& path) override {
        // Prohibit implicit file creation
        if (open_flags & 0b100) {
            test_mode ? throw IPC::IPCError {0, 0xe0c046f8 }
                      : throw std::runtime_error("Extdata does not support creating files via OpenFile");
        }

        // If the open_flags are valid at all (either readable or writeable), the extdata archive automatically opens as read-write
        if (open_flags & 0b11) {
            open_flags |= 0b11;
        }

        try {
            return ArchiveSaveDataBase::OpenFile(thread, context, transaction, open_flags, attributes, path);
        } catch (IPC::IPCError& err) {
            return std::pair<Result, std::unique_ptr<File>>(err.result, nullptr);
        }
    }
};

class ArchiveHostDir : public ArchiveNonPXI {
    std::filesystem::path base_path;

    Result ResultFileNotFound() const override {
        return GenericHostFile::result_file_not_found;
    }

    Result ResultDirectoryNotFound() const override {
        // Same as for files
        return GenericHostFile::result_directory_not_found;
    }

    Result ResultFileAlreadyExists() const override {
        return GenericHostFile::result_file_already_exists;
    }

    Result ResultDirectoryAlreadyExists() const override {
        return GenericHostFile::result_directory_already_exists;
    }

public:
    ArchiveHostDir(std::filesystem::path base_path) : base_path(std::move(base_path)) {
    }

    std::filesystem::path GetSandboxHostRoot() const override {
        return std::filesystem::canonical(base_path);
    }

    std::pair<Result, std::unique_ptr<File>>
    OpenFile(FakeThread&, FakeFS&, uint32_t /*transaction*/, uint32_t open_flags, uint32_t /*attributes*/, const ValidatedPath& path) override {
        bool create = ((open_flags & 4) != 0);
        return { RESULT_OK, std::make_unique<GenericHostFile>(path, create) };
    }

    Result CreateDirectory(FakeThread&, FSContext&, const ValidatedPath& path) override {
        if (std::filesystem::exists(path)) {
            // NOTE: Steel Diver hits this case during startup for the SDMC archive
            return ResultDirectoryAlreadyExists();
        }

        std::filesystem::create_directory(path);
        return RESULT_OK;
    }

    Result DeleteFile(FakeThread& thread, FSContext&, uint32_t /*transaction*/, const ValidatedPath& path) override {
        thread.GetLogger()->warn("Deleting file: {}", path.path.string());

        if (!std::filesystem::exists(path)) {
            thread.GetLogger()->warn("File {} does not exist", path.path.string());

            return test_mode ? ResultFileNotFound()
                             : throw std::runtime_error("Called DeleteFile on nonexisting file");
        }

        if (!std::filesystem::is_regular_file(path)) {
            throw std::runtime_error("Called DeleteFile on something that's not a file");
        }

        [[maybe_unused]] bool result = std::filesystem::remove(path);
        assert(result); // "remove" should only return false if the directory didn't exist, which we checked for above
        return RESULT_OK;
    }

    Result RenameFile(FakeThread&, FakeFS&, uint32_t /*transaction*/, const ValidatedPath& source_path, const ValidatedPath& target_path) override {
        if (!std::filesystem::exists(source_path)) {
            throw Mikage::Exceptions::NotImplemented("Called RenameFile on a nonexisting source file");
        }

        if (!std::filesystem::is_regular_file(source_path)) {
            throw std::runtime_error("Called RenameFile on something that's not a file");
        }

        if (std::filesystem::exists(target_path)) {
            throw Mikage::Exceptions::NotImplemented("Called RenameFile with a target path that already exists");
        }

        std::filesystem::rename(source_path, target_path);

        return RESULT_OK;
    }

    Result DeleteDirectory(FakeThread& thread, FSContext&, uint32_t /*transaction*/, bool recursive, const ValidatedPath& path) override {
        thread.GetLogger()->warn("Deleting directory{}: {}", recursive ? " recursively" : "", path.path.string());

        if (!std::filesystem::exists(path)) {
            thread.GetLogger()->warn("Directory {} does not exist", path.path.string());

            // NOTE: Steel Diver hits this case during startup if the "sdmc:/Nintendo 3DS" folder does not exist
            return ResultDirectoryNotFound();
        }

        if (!std::filesystem::is_directory(path)) {
            throw std::runtime_error("Called DeleteDirectory on something that's not a directory");
        }

        if (recursive) {
            throw std::runtime_error("Recursive deletion not supported yet");
        }

        try {
            [[maybe_unused]] bool result = std::filesystem::remove(path);
            assert(result); // "remove" should only return false if the directory didn't exist, which we checked for above
        } catch (...) {
            // NOTE: Steel Diver hits this case during startup for the SDMC archive
            return 0xc92044fa;
        }
        return RESULT_OK;
    }

    std::pair<Result,std::unique_ptr<Directory>> OpenDirectory(FakeThread&, FSContext&, const ValidatedPath& path) override {
        return { RESULT_OK, std::make_unique<HostDirectory>(path) };
    }
};

static std::string IosExceptionInfo(std::ios_base::failure& err) {
    // On most systems (gcc included), err.code().message() doesn't return a
    // helpful message. On the other hand, reading errno isn't guaranteed to
    // work. So let's just print both, hoping that one of them will give us
    // some useful information...
    return fmt::format("{} / {}", err.code().message(), strerror(errno));
}

static OS::OS::ResultAnd<Handle>
OnIPCFileOpenSubFile(   FakeThread& thread, FSContext& context,
                        std::shared_ptr<File> file, uint64_t file_offset, uint64_t num_bytes) {
    auto sub_file = std::make_unique<SubFile>(file, file_offset, num_bytes);

    // Create file session object and append it to the file session handler thread
    OS::Result result;
    HandleTable::Entry<ServerSession> server_session;
    HandleTable::Entry<ClientSession> client_session;
    std::tie(result,server_session,client_session) = thread.CallSVC(&OS::OS::SVCCreateSession);
    if (result != RESULT_OK) {
        throw Mikage::Exceptions::NotImplemented("Failed to create sub file session");
    }
    server_session.second->name = "SubFile_ServerSession";
    client_session.second->name = "SubFile_ClientSession";

    context.service.Append(server_session, std::move(sub_file));

    return std::make_tuple(RESULT_OK, client_session.first);
}

static OS::OS::ResultAnd<uint32_t, IPC::MappedBuffer>
OnIPCFileRead(  FakeThread& thread, FSContext& context,
                File& file, uint64_t file_offset,
                uint32_t num_bytes, IPC::MappedBuffer buffer) {
    OS::Result result;
    uint32_t bytes_read;
    auto file_buffer = FileBufferInEmulatedMemory { thread, buffer.addr };
    std::tie(result, bytes_read) = file.Read(context.file_context, context, file_offset, num_bytes, file_buffer);
    return std::make_tuple(RESULT_OK, bytes_read, buffer);
}

static OS::OS::ResultAnd<uint32_t, IPC::MappedBuffer>
OnIPCFileWrite( FakeThread& thread, FSContext& context,
                File& file, uint64_t file_offset,
                uint32_t num_bytes, uint32_t options,
                IPC::MappedBuffer buffer) {
    // TODO: What do the "options" indicate? Observed values: 0x10001

    // TODO: Does this operation automatically update the file size?

    OS::Result result;
    uint32_t bytes_written;
    std::tie(result, bytes_written) = file.Write(thread, context, file_offset, num_bytes, options, buffer.addr);
    return std::make_tuple(RESULT_OK, bytes_written, buffer);
}

static decltype(HLE::OS::ServiceHelper::SendReply) OnFileIPCRequest(FakeThread& thread, FSContext& context, std::shared_ptr<File> file, int32_t session_index, const IPC::CommandHeader& header) try {
    using namespace Platform::FS::File;

    if (file->HasOpenSubFile() && header.command_id != Close::id) {
        throw Mikage::Exceptions::Invalid("Attempted to use file with open sub file");
    }

    switch (header.command_id) {
    case OpenSubFile::id:
        IPC::HandleIPCCommand<OpenSubFile>(OnIPCFileOpenSubFile, thread, thread, context, file);
        break;

    case Read::id:
        IPC::HandleIPCCommand<Read>(OnIPCFileRead, thread, thread, context, *file);
        break;

    case Write::id:
        IPC::HandleIPCCommand<Write>(OnIPCFileWrite, thread, thread, context, *file);
        break;

    case GetSize::id:
    {
        OS::Result result;
        uint64_t size;
        std::tie(result, size) = file->GetSize(thread, context);

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 3, 0).raw);
        thread.WriteTLS(0x84, result);
        thread.WriteTLS(0x88, size & 0xFFFFFFFF);
        thread.WriteTLS(0x8c, size >> 32);
        break;
    }

    case SetSize::id:
    {
        OS::Result result;
        uint64_t size = (static_cast<uint64_t>(thread.ReadTLS(0x88)) << 32) | thread.ReadTLS(0x84);

        std::tie(result) = file->SetSize(thread, context, size);
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, result);
        break;
    }

    case 0x80a: // SetPriority
    {
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    case OpenLinkFile::id:
    {
        OS::Result result;
        HandleTable::Entry<ServerSession> server_session;
        HandleTable::Entry<ClientSession> client_session;
        std::tie(result,server_session,client_session) = thread.CallSVC(&OS::OS::SVCCreateSession);
        if (result != RESULT_OK) {
            throw std::runtime_error("Failed to create session for link file");
        }

        context.service.Append(server_session, std::get<std::shared_ptr<File>>(context.service.handle_data[session_index]));

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 2).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, IPC::TranslationDescriptor::MakeHandles(1, true).raw);
        thread.WriteTLS(0x8c, client_session.first.value);
        break;
    }

    case Close::id:
    {
        // NOTE: Close() will keep the file session open; it just makes all
        //       file operations return an error. This is in line with the
        //       official implementation.
        context.service.ReplaceFileServer(session_index, std::make_unique<FileClosed>());

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    case Flush::id:
    {
        // Nothing to do
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    default:
        throw Mikage::Exceptions::NotImplemented("Unknown fs file IPC command with header {:#010x}", header.raw);
    }
    return HLE::OS::ServiceHelper::SendReply;
} catch (std::ios_base::failure& err) {
    thread.GetLogger()->error("Unexpected fstream exception in File IPC command {:#x} handled via object {}: {}",
                              header.command_id.Value(), boost::core::demangle(typeid(*file).name()),
                              IosExceptionInfo(err));
    throw;
}

static OS::OS::ResultAnd<uint32_t, IPC::MappedBuffer>
OnIPCDirRead( FakeThread& thread, FSContext& context,
                    Directory& dir, uint32_t requested_entries,
                    IPC::MappedBuffer buffer) {
    auto file_buffer = FileBufferInEmulatedMemory { thread, buffer.addr };
    auto [result, actual_entries] = dir.GetEntries(thread, context, requested_entries, file_buffer);
    return std::make_tuple(RESULT_OK, actual_entries, buffer);
}

static decltype(HLE::OS::ServiceHelper::SendReply) OnDirIPCRequest(FakeThread& thread, FSContext& context, Directory& dir, int32_t session_index, const IPC::CommandHeader& header) try {
    using namespace Platform::FS::Dir;

    switch (header.command_id) {
    case Read::id:
        IPC::HandleIPCCommand<Read>(OnIPCDirRead, thread, thread, context, dir);
        break;

    case Close::id:
    {
        // TODOTEST: Is this command similar to File::Close, in that it keeps
        //           the session itself open? That's what our implementation
        //           does for now

// TODO: REENABLE
//        context.service.ReplaceFileServer(session_index, std::make_unique<DirClosed>());

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    default:
        throw Mikage::Exceptions::NotImplemented("Unknown fs directory IPC command with header {:#010x}", header.raw);
    }
    return HLE::OS::ServiceHelper::SendReply;
} catch (std::ios_base::failure& err) {
    thread.GetLogger()->error("Unexpected fstream exception in Directory IPC command {:#x} handled via object {}: {}",
                              header.command_id.Value(), boost::core::demangle(typeid(dir).name()),
                              IosExceptionInfo(err));
    throw;
}

template<typename Class, typename Func>
static auto BindMemFn(Func f, Class* c) {
    return [f,c](auto&&... args) { return std::mem_fn(f)(c, args...); };
}

FakeFS::FakeFS(FakeThread& thread)
    : process(thread.GetParentProcess()),
      logger(*thread.GetLogger()),
      settings(process.GetOS().settings) {

    OS::Result result;

    // Get PxiFS0 service handle via srv:
    HandleTable::Entry<ClientSession> srv_session;
    std::tie(result,srv_session) = thread.CallSVC(&OS::OS::SVCConnectToPort, "srv:");
    if (result != RESULT_OK)
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);

    IPC::SendIPCRequest<Platform::SM::SRV::RegisterClient>(thread, srv_session.first, IPC::EmptyValue{});

    pxifs_session = IPC::SendIPCRequest<Platform::SM::SRV::GetServiceHandle>(thread, srv_session.first,
                                                                          Platform::SM::PortName("PxiFS0"), 0);

    thread.CallSVC(&OS::OS::SVCCloseHandle, srv_session.first);

    auto fsreg_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(), [this](FakeThread& thread) { return FSRegThread(thread); });
    fsreg_thread->name = "fs:REGThread";
    process.AttachThread(fsreg_thread);

    fsuser_handle_index = service.Append(OS::ServiceUtil::SetupService(thread, "fs:USER", 30));
    fsldr_handle_index = service.Append(OS::ServiceUtil::SetupService(thread, "fs:LDR", 2));

    FSUserThread(thread);
}

FakeFS::~FakeFS() = default;

template<typename T>
uint32_t FSServiceHelper::Append(HandleTable::Entry<T> entry, HandleData data) {
    auto ret = HLE::OS::ServiceHelper::Append(entry);
    handle_data.emplace_back(std::move(data));
    return ret;
}

void FSServiceHelper::Erase(int32_t index) {
    HLE::OS::ServiceHelper::Erase(index);
    handle_data.erase(handle_data.begin() + index);
}

void FSServiceHelper::OnNewSession(int32_t port_index, HandleTable::Entry<ServerSession> session) {
    ServiceHelper::OnNewSession(port_index, session);
    handle_data.emplace_back(static_cast<uint32_t>(port_index));
}

void FSServiceHelper::ReplaceFileServer(int32_t index, std::unique_ptr<File> new_file) {
    auto& data = handle_data[index];
    if (!std::holds_alternative<std::shared_ptr<File>>(data)) {
        throw std::runtime_error("Attempted to replace File object in non-File session");
    }
    data = std::move(new_file);
}

// Actually fs:USER *and* fs:LDR thread
void FakeFS::FSUserThread(FakeThread& thread) {
    // TODO: These must be backed by emulated physical memory, since otherwise PXI can't actually read from them
    auto path_buffer_addr = thread.GetParentProcess().AllocateStaticBuffer(0x30);
    auto archive_path_buffer_addr = thread.GetParentProcess().AllocateStaticBuffer(0x30);

    // Allocate static buffers and set up TLS descriptors for them
    // NOTE: Some IPC commands (e.g. OpenFileDirectly) will forward the data
    //       in these buffers to the PXI process as a PXI buffer (i.e. as a
    //       table of physical memory chunks). Hence, they must be backed by
    //       physical memory rather than fake memory.
    Result result;
    std::tie(result, static_buffer_addr[0]) = thread.CallSVC(&OS::OS::SVCControlMemory, 0, 0, static_buffer_size * 3, 3 /* COMMIT */, 3 /* RW */);
    thread.WriteTLS(0x180, IPC::TranslationDescriptor::MakeStaticBuffer(0, static_buffer_size).raw);
    thread.WriteTLS(0x184, static_buffer_addr[0]);

    static_buffer_addr[1] = static_buffer_addr[0] + static_buffer_size;
    thread.WriteTLS(0x188, IPC::TranslationDescriptor::MakeStaticBuffer(0, static_buffer_size).raw);
    thread.WriteTLS(0x18c, static_buffer_addr[1]);

    static_buffer_addr[2] = static_buffer_addr[1] + static_buffer_size;
    thread.WriteTLS(0x190, IPC::TranslationDescriptor::MakeStaticBuffer(0, static_buffer_size).raw);
    thread.WriteTLS(0x194, static_buffer_addr[2]);

    auto InvokeCommandHandler = [&](FakeThread& thread, uint32_t signalled_handle_index) {
        Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
        auto signalled_handle = service.handles.at(signalled_handle_index);
        auto& data = service.handle_data.at(signalled_handle_index);
        if (std::holds_alternative<uint32_t>(data)) {
            return UserCommandHandler(thread, signalled_handle, header);
        } else if (auto* file = std::get_if<std::shared_ptr<File>>(&data)) {
            return OnFileIPCRequest(thread, *this, *file, signalled_handle_index, header);
        } else if (auto* dir = std::get_if<std::shared_ptr<Directory>>(&data)) {
            return OnDirIPCRequest(thread, *this, **dir, signalled_handle_index, header);
        } else {
            return HLE::OS::ServiceHelper::DoNothing;
        }
    };

    service.Run(thread, std::move(InvokeCommandHandler));
}

static std::tuple<OS::Result, uint32_t> HandleIsSdmcWritable(FSContext& context, FakeThread& thread) {
    thread.GetLogger()->info("{}received IsSdmcWritable", ThreadPrinter{thread});
    return std::make_tuple(RESULT_OK, true /*false*/);
}

decltype(HLE::OS::ServiceHelper::SendReply) FakeFS::UserCommandHandler(FakeThread& thread, Handle sender, const IPC::CommandHeader& header) try {
    using namespace Platform::FS::User;

    // TODO: The registered handle should be removed from fsuser_process_ids when the session is closed!
    if (header.command_id == Initialize::id) {
        IPC::HandleIPCCommand<Initialize>(BindMemFn(&FakeFS::HandleInitialize, this), thread, thread, sender);
        return HLE::OS::ServiceHelper::SendReply;
    } else if (header.command_id == InitializeWithSdkVersion::id) {
        IPC::HandleIPCCommand<InitializeWithSdkVersion>(BindMemFn(&FakeFS::HandleInitializeWithSdkVersion, this), thread, thread, sender);
        return HLE::OS::ServiceHelper::SendReply;
    }

    // If this is not an Initialize command, we need to lookup the session context first.
    // TODO: What if the client calls svcDuplicateHandle on the "sender" handle
    //       and then tries to use this service? With our current
    //       implementation, this would fail, but does it work on the actual
    //       system?
    if (fsuser_process_ids.count(sender) == 0) {
        logger.error("Tried to use FS:User without calling Initialize on {}", HandlePrinter{thread,sender});
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);
    }
    auto session_pid = fsuser_process_ids[sender];

    switch (header.command_id) {
    case OpenFile::id:
        IPC::HandleIPCCommand<OpenFile>(BindMemFn(&FakeFS::HandleOpenFile, this), thread, thread, session_pid);
        break;

    case OpenFileDirectly::id:
        IPC::HandleIPCCommand<OpenFileDirectly>(BindMemFn(&FakeFS::HandleOpenFileDirectly, this), thread, thread, session_pid);
        break;

    case DeleteFile::id:
        IPC::HandleIPCCommand<DeleteFile>(BindMemFn(&FakeFS::HandleDeleteFile, this), thread, thread, session_pid);
        break;

    case RenameFile::id:
        IPC::HandleIPCCommand<RenameFile>(BindMemFn(&FakeFS::HandleRenameFile, this), thread, thread);
        break;

    case DeleteDirectory::id:
        IPC::HandleIPCCommand<DeleteDirectory>(std::mem_fn(&FakeFS::HandleDeleteDirectory), thread, this, thread, session_pid, false);
        break;

    case DeleteDirectoryRecursively::id:
        IPC::HandleIPCCommand<DeleteDirectoryRecursively>(std::mem_fn(&FakeFS::HandleDeleteDirectory), thread, this, thread, session_pid, true);
        break;

    case CreateFile::id:
        IPC::HandleIPCCommand<CreateFile>(BindMemFn(&FakeFS::HandleCreateFile, this), thread, thread, session_pid);
        break;

    case CreateDirectory::id:
        IPC::HandleIPCCommand<CreateDirectory>(BindMemFn(&FakeFS::HandleCreateDirectory, this), thread, thread, session_pid);
        break;

    case OpenDirectory::id:
        IPC::HandleIPCCommand<OpenDirectory>(BindMemFn(&FakeFS::HandleOpenDirectory, this), thread, thread, session_pid);
        break;

    case OpenArchive::id:
        IPC::HandleIPCCommand<OpenArchive>(BindMemFn(&FakeFS::HandleOpenArchive, this), thread, thread, session_pid);
        break;

    case ControlArchive::id:
        IPC::HandleIPCCommand<ControlArchive>(BindMemFn(&FakeFS::HandleControlArchive, this), thread, thread, session_pid);
        break;

    case CloseArchive::id:
        IPC::HandleIPCCommand<CloseArchive>(BindMemFn(&FakeFS::HandleCloseArchive, this), thread, thread, session_pid);
        break;

    case FormatOwnSaveData::id:
        IPC::HandleIPCCommand<FormatOwnSaveData>(BindMemFn(&FakeFS::HandleFormatOwnSaveData, this), thread, thread, session_pid);
        break;

    case CreateSystemSaveDataLegacy::id:
    {
        auto implied_mediatype = MediaType::NAND;
        IPC::HandleIPCCommand<CreateSystemSaveDataLegacy>(BindMemFn(&FakeFS::HandleCreateSystemSaveData, this), thread, thread, session_pid, static_cast<uint32_t>(implied_mediatype));
        break;
    }

    case 0x812: // GetFreeBytes (Super Smash Bros)
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0x10000000); // Lots of free bytes
        break;

    case IsSdmcDetected::id:
        IPC::HandleIPCCommand<IsSdmcDetected>(BindMemFn(&FakeFS::HandleIsSdmcDetected, this), thread, thread);
        break;

    case IsSdmcWritable::id:
        IPC::HandleIPCCommand<IsSdmcWritable>(HandleIsSdmcWritable, thread, *this, thread);
        break;

    case 0x821: // CardSlotIsInserted
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, (thread.GetOS().setup.gamecard != nullptr)); // True if game card inserted
        break;

    case 0x82E: // GetProductInfo
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 6, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0x31313131);
        thread.WriteTLS(0x8C, 0x31313131);
        thread.WriteTLS(0x90, 0x31313131);
        thread.WriteTLS(0x94, 0x31313131);
        thread.WriteTLS(0x98, 0x32323232);
        break;

    case CreateExtSaveDataLegacy::id:
    {
        IPC::HandleIPCCommand<CreateExtSaveDataLegacy>(BindMemFn(&FakeFS::HandleCreateExtSaveDataLegacy, this), thread, thread, session_pid);
        break;
    }

    case DeleteExtSaveDataLegacy::id:
    {
        // Forward to DeleteExtSaveData
        auto media_type = MediaType { static_cast<uint8_t>(thread.ReadTLS(0x84)) };
        uint64_t save_id = thread.ReadTLS(0x88); // Upper 32-bits are implied to be zero
        auto [result] = HandleDeleteExtSaveData(thread, session_pid, ExtSaveDataInfo { media_type, {}, save_id, {} });
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, result);
        break;
    }

    case GetSpecialContentIndex::id:
    {
        auto media_type = MediaType { static_cast<uint8_t>(thread.ReadTLS(0x84)) };
        auto content_type = static_cast<SpecialContentType>(thread.ReadTLS(0x90) & 0xff);
        if (media_type == MediaType::GameCard) {
            Loader::NCSDPartitionId target_ncsd_id;
            switch (content_type) {
                case Platform::FS::SpecialContentType::UpdateData:
                    target_ncsd_id = Loader::NCSDPartitionId::UpdateData;
                    break;
                case Platform::FS::SpecialContentType::Manual:
                    target_ncsd_id = Loader::NCSDPartitionId::Manual;
                    break;
                case Platform::FS::SpecialContentType::DownloadPlayChild:
                    target_ncsd_id = Loader::NCSDPartitionId::DownloadPlayChild;
                    break;
                case Platform::FS::SpecialContentType::UpdateDataNew3DS:
                    target_ncsd_id = Loader::NCSDPartitionId::UpdateDataNew3DS;
                    break;
                default:
                    throw Mikage::Exceptions::Invalid("GetSpecialContentType: Invalid special content type {:#x}", Meta::to_underlying(content_type));
            }

            auto gamecard = thread.GetOS().setup.gamecard.get();
            if (!gamecard) {
                throw Mikage::Exceptions::Invalid("Attempted GetSpecialContentType on gamecard without one inserted");
            }

            thread.WriteTLS(0x80, GetSpecialContentIndex::response_header);
            if (!gamecard->HasPartition(target_ncsd_id)) {
                thread.WriteTLS(0x84, 0xC8804636); // "Special content not found"
                // NOTE: this is required for the HOME Menu to properly show (or not show) the "Manual" button!
            } else {
                thread.WriteTLS(0x84, HLE::OS::RESULT_OK);
                thread.WriteTLS(0x88, Meta::to_underlying(target_ncsd_id));
            }
        } else {
            // NOTE: FSPXI retrieves special content indices for installed titles from the title database
            // TODO: properly reimplement this and check if the requested content actually exists
            thread.WriteTLS(0x80, GetSpecialContentIndex::response_header);
            uint32_t content_index{};
            switch (content_type) {
                case Platform::FS::SpecialContentType::UpdateData:
                case Platform::FS::SpecialContentType::UpdateDataNew3DS:
                    throw Mikage::Exceptions::Invalid("Attempted to get update partition index for non-gamecard title");
                case Platform::FS::SpecialContentType::Manual:
                    // NOTE: this may not always exist, but generally speaking, if it does, it will be content index 1
                    content_index = 1;
                    break;
                case Platform::FS::SpecialContentType::DownloadPlayChild:
                    // NOTE: this may not always exist, but generally speaking, if it does, it will be content index 2
                    content_index = 2;
                    break;
                default:
                    throw Mikage::Exceptions::Invalid("GetSpecialContentType: Invalid special content type {:#x}", Meta::to_underlying(content_type));
            }

            thread.WriteTLS(0x84, HLE::OS::RESULT_OK);
            thread.WriteTLS(0x88, content_index);
        }
        break;
    }

    case 0x83d: // CheckAuthorityToAccessExtSaveData
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x84, 1); // access allowed
        break;

    case GetPriority::id:
        IPC::HandleIPCCommand<GetPriority>(BindMemFn(&FakeFS::HandleGetPriority, this), thread, thread);
        break;

    case GetFormatInfo::id:
        IPC::HandleIPCCommand<GetFormatInfo>(BindMemFn(&FakeFS::HandleGetFormatInfo, this), thread, thread, session_pid);
        break;

    case 0x849:
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 5, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0x1000); // Sector size in bytes
        thread.WriteTLS(0x8c, 0x1000); // Cluster size in bytes
        thread.WriteTLS(0x90, 1024 * 100); // Partition capacity in clusters
        thread.WriteTLS(0x94, 1024 * 100); // Free space in clusters
        break;

    case FormatSaveData::id:
        IPC::HandleIPCCommand<FormatSaveData>(BindMemFn(&FakeFS::HandleFormatSaveData, this), thread, thread, session_pid);
        break;

    case UpdateSha256Context::id:
        IPC::HandleIPCCommand<UpdateSha256Context>(BindMemFn(&FakeFS::HandleUpdateSha256Context, this), thread, thread, session_pid);
        break;

    case CreateExtSaveData::id:
        IPC::HandleIPCCommand<CreateExtSaveData>(BindMemFn(&FakeFS::HandleCreateExtSaveData, this), thread, thread, session_pid);
        break;

    case DeleteExtSaveData::id:
        IPC::HandleIPCCommand<DeleteExtSaveData>(BindMemFn(&FakeFS::HandleDeleteExtSaveData, this), thread, thread, session_pid);
        break;

    case EnumerateExtSaveData::id:
        IPC::HandleIPCCommand<EnumerateExtSaveData>(BindMemFn(&FakeFS::HandleEnumerateExtSaveData, this), thread, thread, session_pid);
        break;

    case CreateSystemSaveData::id:
        IPC::HandleIPCCommand<CreateSystemSaveData>(BindMemFn(&FakeFS::HandleCreateSystemSaveData, this), thread, thread, session_pid);
        break;

    case DeleteSystemSaveData::id:
    {
        uint32_t save_data_info = thread.ReadTLS(0x84);
        uint32_t save_id = thread.ReadTLS(0x88);
        logger.info("{}received DeleteSystemSaveData with save_data_info={:#x}, save_id={:#x}",
                    ThreadPrinter{thread}, save_data_info, save_id);

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    case GetProgramLaunchInfo::id:
        IPC::HandleIPCCommand<GetProgramLaunchInfo>(BindMemFn(&FakeFS::HandleGetProgramLaunchInfo, this), thread, thread);
        break;

    // Used by menu during boot
    case GetCardType::id:
        logger.info("{}received stubbed IPC command GetCardType", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        // TODO: Consider returning error here if no card is inserted. This may help 4.5.0 display an appropriate message in that case
        thread.WriteTLS(0x84, RESULT_OK);
//        thread.WriteTLS(0x84, 0xc8804464);
        thread.WriteTLS(0x88, 0); // CTR card
        break;

    // Used by ptm during boot
    case Unknown0x839::id:
        logger.info("{}received stubbed IPC command 0x839", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case 0x85d: // SetFsCompatibilityInfo
        logger.info("{}received SetFsCompatibilityInfo", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case 0x85e: // ResetCardCompatibilityParameter
    {
        uint32_t parameter = thread.ReadTLS(0x84);
        logger.info("{}received ResetCardCompatibilityParameter with parameter={:#x}",
                          ThreadPrinter{thread}, parameter);

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    case 0x862: // SetPriority
    {
        uint32_t priority = thread.ReadTLS(0x84);
        logger.info("{}received SetPriority with priority={:#x}",
                          ThreadPrinter{thread}, priority);

//        LogStub(header);
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    case 0x86e: // SetThisSaveDataSecureValue (Super Smash Bros)
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case 0x86f: // GetThisSaveDataSecureValue (Super Smash Bros)
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0);
        break;

    case 0x87d: // GetNumSeeds (HOME Menu)
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0);
        break;

    case 0x883: // GetNumTitleTags (HOME Menu)
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0);
        break;

    default:
        throw Mikage::Exceptions::NotImplemented("Unknown FS service command with header {:#010x}", header.raw);
    }

    return HLE::OS::ServiceHelper::SendReply;
} catch (const IPC::IPCError& exc) {
    auto response_header = IPC::CommandHeader::Make(0, 1, 0);
    response_header.command_id = (exc.header >> 16);
    thread.WriteTLS(0x80, response_header.raw);
    thread.WriteTLS(0x84, exc.result);
    return HLE::OS::ServiceHelper::SendReply;
}

std::tuple<OS::Result> FakeFS::HandleInitialize(FakeThread& thread, Handle session_handle, ProcessId id) {
    fsuser_process_ids.emplace(std::make_pair(session_handle, id));

    return std::make_tuple(RESULT_OK);
}

std::tuple<OS::Result> FakeFS::HandleInitializeWithSdkVersion(FakeThread& thread, Handle session_handle, uint32_t version, ProcessId id) {
    fsuser_process_ids.emplace(std::make_pair(session_handle, id));

    return std::make_tuple(RESULT_OK);
}

// TODOTEST: What happens to files when their corresponding Archive is closed? (Presumably they stay alive)
// TODOTEST: What's the maximal path size? This is bound by the size of the static buffer given by path_addr!
std::tuple<OS::Result, Handle> FakeFS::HandleOpenFile(FakeThread& thread, ProcessId session_id, uint32_t transaction, uint64_t archive_handle, uint32_t path_type, uint32_t path_size, uint32_t open_flags, uint32_t attributes, IPC::StaticBuffer path) {
    if (archives.count(archive_handle) == 0) {
        throw std::runtime_error("Couldn't find the given archive handle");
    }

    auto& archive = archives[archive_handle];

    if (path.size < path_size)
        throw std::runtime_error("Given path length is larger than the static buffer size");

    path.size = path_size;

    auto file = Meta::invoke([&]() {
        try {
            auto result = archive->OpenFile(thread, *this, transaction, open_flags, attributes, path_type, path);
            if (result.first != RESULT_OK) {
                thread.GetLogger()->warn("Archive instance failed to open the given file");
                throw IPC::IPCError { 0x08020040, result.first };
            }
            return std::move(result.second);
        } catch (std::ios_base::failure& err) {
            thread.GetLogger()->error("Unexpected fstream exception in OpenFile via archive {}: {}", boost::core::demangle(typeid(*archive).name()), IosExceptionInfo(err));
            throw;
        }
    });

    // Create file session object and append it to the file session handler thread
    OS::Result result;
    HandleTable::Entry<ServerSession> server_session;
    HandleTable::Entry<ClientSession> client_session;
    std::tie(result,server_session,client_session) = thread.CallSVC(&OS::OS::SVCCreateSession);
    if (result != RESULT_OK) {
        thread.GetLogger()->error("Failed to create file session");
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);
    }
    server_session.second->name = "File_ServerSession";
    client_session.second->name = "File_ClientSession";

    service.Append(server_session, std::move(file));

    return std::make_tuple(RESULT_OK, client_session.first);
}

std::tuple<OS::Result, Handle> FakeFS::HandleOpenFileDirectly(FakeThread& thread, ProcessId session_id,
                                                              uint32_t transaction, uint32_t archive_id,
                                                              uint32_t archive_path_type, uint32_t archive_path_size,
                                                              uint32_t file_path_type, uint32_t file_path_size,
                                                              uint32_t open_flags, uint32_t attributes,
                                                              const IPC::StaticBuffer& archive_path,
                                                              const IPC::StaticBuffer& file_path) {
    OS::Result result;
    uint32_t archive_handle;
    std::tie(result, archive_handle) = HandleOpenArchive(thread, session_id, archive_id, archive_path_type, archive_path_size, archive_path);
    if (result != RESULT_OK) {
        logger.error("{}OpenArchive returned error code {:#x}", ThreadPrinter{thread}, result);
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);
    }

    Handle client_session;
    std::tie(result, client_session) = HandleOpenFile(thread, session_id, transaction, archive_handle, file_path_type, file_path_size, open_flags, attributes, file_path);
    if (result != RESULT_OK) {
        logger.error("{}OpenFile returned error code {:#x}", ThreadPrinter{thread}, result);
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);
    }

    std::tie(result) = HandleCloseArchive(thread, session_id, archive_handle);
    if (result != RESULT_OK) {
        logger.error("{}CloseArchive returned error code {:#x}", ThreadPrinter{thread}, result);
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);
    }

    return std::make_tuple(RESULT_OK, client_session);
}

std::tuple<OS::Result> FakeFS::HandleDeleteFile(FakeThread& thread, ProcessId session_id,
                                                uint32_t transaction, uint64_t archive_handle,
                                                uint32_t file_path_type, uint32_t file_path_size,
                                                IPC::StaticBuffer file_path) {
    if (archives.count(archive_handle) == 0) {
        throw Mikage::Exceptions::Invalid("Attempted to delete file from unknown archive handle");
    }

    auto& archive = archives[archive_handle];

    if (file_path.size < file_path_size)
        throw std::runtime_error("Given path length is larger than the static buffer size");

    // Restrict the path size to the given one
    file_path.size = file_path_size;

    // TODO: Assert that the file is not currently opened

    auto result = archive->DeleteFile(thread, *this, transaction, file_path_type, file_path);
    return std::make_tuple(result);
}

std::tuple<OS::Result> FakeFS::HandleRenameFile(
                FakeThread& thread, uint32_t transaction,
                uint64_t source_archive_handle, uint32_t source_file_path_type, uint32_t source_file_path_size,
                uint64_t target_archive_handle, uint32_t target_file_path_type, uint32_t target_file_path_size,
                IPC::StaticBuffer source_file_path, IPC::StaticBuffer target_file_path) {
    if (source_archive_handle != target_archive_handle) {
        throw Mikage::Exceptions::Invalid("May not rename files across archives");
    }

    if (archives.count(source_archive_handle) == 0) {
        throw Mikage::Exceptions::Invalid("Attempted to rename file from unknown archive handle");
    }

    auto& archive = archives[source_archive_handle];

    if (source_file_path.size < source_file_path_size) {
        throw std::runtime_error("Given source path length is larger than the static buffer size");
    }

    if (target_file_path.size < target_file_path_size) {
        throw std::runtime_error("Given target path length is larger than the static buffer size");
    }

    auto result = archive->RenameFile(thread, *this, transaction, source_file_path_type, source_file_path, target_file_path_type, target_file_path);
    return std::make_tuple(result);
}

std::tuple<OS::Result> FakeFS::HandleDeleteDirectory(FakeThread& thread, ProcessId session_id, bool recursive,
                                                     uint32_t transaction, ArchiveHandle archive_handle,
                                                     uint32_t dir_path_type, uint32_t dir_path_size,
                                                     IPC::StaticBuffer dir_path) {
    if (archives.count(archive_handle) == 0)
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);

    auto& archive = archives[archive_handle];

    if (dir_path.size < dir_path_size)
        throw std::runtime_error("Given path length is larger than the static buffer size");

    // Restrict the path size to the given one
    dir_path.size = dir_path_size;

    // TODO: Assert that the directory is not currently opened

    auto result = archive->DeleteDirectory(thread, *this, transaction, recursive, dir_path_type, dir_path);
    return std::make_tuple(result);
}

std::tuple<OS::Result> FakeFS::HandleCreateFile(FakeThread& thread, ProcessId session_id,
                                                uint32_t transaction, uint64_t archive_handle,
                                                uint32_t file_path_type, uint32_t file_path_size,
                                                uint32_t attributes, uint64_t initial_file_size,
                                                IPC::StaticBuffer file_path) {
    if (file_path.size < file_path_size)
        throw std::runtime_error("Given path length is larger than the static buffer size");

    if (archives.count(archive_handle) == 0)
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);

    auto& archive = archives[archive_handle];

    return archive->CreateFile(thread, *this, transaction, attributes, initial_file_size, file_path_type, file_path);
}

std::tuple<OS::Result> FakeFS::HandleCreateDirectory(FakeThread& thread, ProcessId /*session_id*/,
                                                     uint32_t transaction, uint64_t archive_handle,
                                                     uint32_t dir_path_type, uint32_t dir_path_size,
                                                     uint32_t /*attributes*/, IPC::StaticBuffer dir_path) {
    if (dir_path.size < dir_path_size)
        throw std::runtime_error("Given path length is larger than the static buffer size");

    if (archives.count(archive_handle) == 0)
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);

    auto& archive = archives[archive_handle];

    auto result = archive->CreateDirectory(thread, *this, dir_path_type, dir_path);
    return std::make_tuple(result);
}

std::tuple<OS::Result, Handle> FakeFS::HandleOpenDirectory(FakeThread &thread, ProcessId session_id, uint64_t archive_handle, uint32_t path_type, uint32_t path_size, IPC::StaticBuffer path) {
    if (archives.count(archive_handle) == 0) {
        thread.GetLogger()->error("Couldn't find the given archive id");
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);
    }

    auto& archive = archives[archive_handle];

    if (path.size < path_size)
        throw std::runtime_error("Given path length is larger than the static buffer size");

    path.size = path_size;

    auto dir = Meta::invoke([&]() {
        try {
            auto result = archive->OpenDirectory(thread, *this, path_type, path);
            if (result.first != RESULT_OK) {
                thread.GetLogger()->warn("Archive instance failed to open the given directory");
                 thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);
            }
            return std::move(result.second);
        } catch (std::ios_base::failure& err) {
            thread.GetLogger()->error("Unexpected fstream exception in OpenDirectory via archive {}: {}", boost::core::demangle(typeid(*archive).name()), IosExceptionInfo(err));
            throw;
        }
    });

    // Create file session object and append it to the file session handler thread
    OS::Result result;
    HandleTable::Entry<ServerSession> server_session;
    HandleTable::Entry<ClientSession> client_session;
    std::tie(result,server_session,client_session) = thread.CallSVC(&OS::OS::SVCCreateSession);
    if (result != RESULT_OK) {
        thread.GetLogger()->error("Failed to create directory session");
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);
    }
    server_session.second->name = "Dir_ServerSession";
    client_session.second->name = "Dir_ClientSession";

    service.Append(server_session, std::move(dir));

    return std::make_tuple(RESULT_OK, client_session.first);
}

/**
 * Open the given archive without publically registering it.
 * The archive is closed automatically on destruction.
 */
static std::tuple<OS::Result, std::unique_ptr<Archive>>
OpenArchive(FakeThread& thread, FSContext& context, ProcessId process_id, uint32_t archive_id, uint32_t path_type, uint32_t path_size, IPC::StaticBuffer path) try {
    // TODO: This is conditional on session_id to avoid rejecting loader from accessing FS. How should this be done properly, though?
    if (process_id > 5 && context.process_infos.count(process_id) == 0) {
        throw std::runtime_error(fmt::format("Process {} is not registered to FS", process_id));
    }

    if (path_size > path.size)
        throw std::runtime_error("Given path size is larger than the total static buffer size");

    // Pass on the bounded path size
    path.size = path_size;
    path.id = 0;

    switch (archive_id) {
    case 0x00000003:
    {
        // TODO: Remove this legacy code.
        auto program_info = context.process_infos.at(process_id).program;
        std::cerr << "Title id: " << std::hex << std::setw(8) << std::setfill('0') << (program_info.program_id & 0xFFFFFFFF) << std::setw(8) << (program_info.program_id >> 32) << std::endl;
        auto archive = std::unique_ptr<Archive>(new ArchiveOwnNCCHSection(thread, context, 0x2 /* path type = binary */, path, program_info));
        return std::make_tuple(RESULT_OK, std::move(archive));



//         auto program_info = process_infos[session_id].program;
//         std::cerr << "Title id: " << std::hex << std::setw(8) << std::setfill('0') << (program_info.program_id & 0xFFFFFFFF) << std::setw(8) << (program_info.program_id >> 32) << std::endl;
//
//         auto new_path = static_buffer_addr[0];
// TODOTOD: 12 bytes.        thread.WriteMemory32(new_path, program_info.program_id & 0xFFFFFFFF);
//         thread.WriteMemory32(new_path + 4, program_info.program_id >> 32);
//         thread.WriteMemory32(new_path + 8, program_info.media_type);
//         thread.WriteMemory32(new_path + 12, 0);
//         thread.WriteMemory32(new_path + 16, 0);
//         auto archive = std::make_unique<ArchivePXI>(thread, *this, 0x2345678a /* PXI archive */, 0x2 /* path type = binary */, IPC::StaticBuffer { new_path, 20, 0 });
//         thread.GetParentProcess().FreeStaticBuffer(new_path);
//         next_archive_handle++; // TODO: Move this into a MakeNewArchiveHandle function
//         archives.emplace(std::make_pair(next_archive_handle, std::move(archive)));
//
//         return std::make_tuple(RESULT_OK, next_archive_handle);
    }

    case 0x00000004:
    {
        // TODO: program info may not even be necessary...
        auto program_info = context.process_infos.at(process_id).program;
        std::cerr << "Title id: " << std::hex << std::setw(8) << std::setfill('0') << (program_info.program_id & 0xFFFFFFFF) << std::setw(8) << (program_info.program_id >> 32) << std::endl;
        auto archive = std::unique_ptr<Archive>(new ArchiveSaveData(context, program_info));
        return std::make_tuple(RESULT_OK, std::move(archive));
    }

    case 0x00000008:
    {
        auto archive = std::unique_ptr<Archive>(new ArchiveSystemSaveDataForSaveId(thread, context, path_type, path));
        return std::make_tuple(RESULT_OK, std::move(archive));
    }

    case 0x00000009:
    {
        auto archive = std::unique_ptr<Archive>(new ArchiveHostDir(HostSdmcDirectory(context.settings)));
        return std::make_tuple(RESULT_OK, std::move(archive));
    }

    case 0x00000006:
    case 0x00000007:
    case 0x12345678:
    {
        // NOTE: Home Menu uses this with mediatype 00000000 and extdata id 000000e000000000.
        //       Apparently, when we return success in this case, Home Menu boots into the System Transfer title (CARDBOAR)

        // TODO: Verify path size

        auto media_type = Serialization::LoadVia<uint32_t>(thread, path.addr);
        auto extdata_id = Serialization::LoadVia<uint64_t>(thread, path.addr + 4);
        auto extdata_info = ExtSaveDataInfo { static_cast<Platform::FS::MediaType>(media_type), {}, extdata_id, 0 };
        if (archive_id == 0x7) {
            // The FS module overrides the high extdata id with a hardcoded value for this archive id
            extdata_info.save_id = (extdata_info.save_id & 0xffff'ffff) | 0x48000'00000000;
        }

        bool is_spotpass = (archive_id == 0x12345678);

        auto archive = std::unique_ptr<Archive>(new ArchiveExtSaveData(thread, context, extdata_info, is_spotpass));
        return std::make_tuple(RESULT_OK, std::move(archive));
    }

    case 0x1234567d:
    {
        auto archive = std::unique_ptr<Archive>(new ArchiveHostDir(GetRootDataDirectory(context.settings) / "rw"));
        return std::make_tuple(RESULT_OK, std::move(archive));
    }

    case 0x1234567e:
    {
        auto archive = std::unique_ptr<Archive>(new ArchiveHostDir(GetRootDataDirectory(context.settings) / "ro"));
        return std::make_tuple(RESULT_OK, std::move(archive));
    }

    case 0x2345678a:
    case 0x2345678e:
    {
        auto archive = std::unique_ptr<Archive>(new ArchiveNCCHSection(thread, context, archive_id, path_type, path));
        return std::make_tuple(RESULT_OK, std::move(archive));
    }

    // TWL photo. Opened by mset during initial system setup
    case 0x567890ac:
    {
        auto archive = std::unique_ptr<Archive>(new ArchiveHostDir(GetRootDataDirectory(context.settings) / "twlp"));
        return std::make_tuple(RESULT_OK, std::move(archive));
    }

    // TODO: Implement other archives
    default:
        throw std::runtime_error(fmt::format("FS received OpenArchive on unknown archive ID {:#x}", archive_id));
    }
} catch (std::ios_base::failure& err) {
    thread.GetLogger()->error("Unexpected fstream exception in HandleOpenArchive: {}",
                              IosExceptionInfo(err));
    throw;
}

std::tuple<OS::Result, uint64_t> FakeFS::HandleOpenArchive(FakeThread& thread, ProcessId session_id, uint32_t archive_id, uint32_t path_type, uint32_t path_size, IPC::StaticBuffer path) {
    auto [result, archive] = OpenArchive(thread, *this, session_id, archive_id, path_type, path_size, path);

    // Move archive pointer into list and create an archive handle to refer to it
    next_archive_handle++;
    archives.emplace(std::make_pair(next_archive_handle, std::move(archive)));
    return std::make_tuple(RESULT_OK, next_archive_handle);
}

std::tuple<OS::Result, IPC::MappedBuffer, IPC::MappedBuffer> FakeFS::HandleControlArchive(FakeThread& thread, ProcessId session_id, uint64_t archive_handle, uint32_t action, uint32_t input_size, uint32_t output_size, IPC::MappedBuffer input, IPC::MappedBuffer output) {
    logger.info("{}received ControlArchive with archive_handle={:#x}, action={:#x}, input_size={:#x}, output_size={:#x}",
                ThreadPrinter{thread}, archive_handle, action, input_size, output_size);

    if (action == 0) {
        // Commit save data changes. We implement this as a nop for now (TODO).
    } else if (action == 1) {
        // Time stamp of last modification. We implement this as a nop for now (TODO).
    } else {
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);
    }

    return std::make_tuple(RESULT_OK, input, output);
}

std::tuple<OS::Result> FakeFS::HandleCloseArchive(FakeThread& thread, ProcessId session_id, uint64_t archive_handle) {
    logger.info("{}received CloseArchive with archive_handle={:#x}",
                ThreadPrinter{thread}, archive_handle);

    return std::make_tuple(RESULT_OK);
}

std::tuple<OS::Result> FakeFS::HandleFormatOwnSaveData(FakeThread& thread, ProcessId session_id, uint32_t block_size,
                                                       uint32_t num_dirs, uint32_t num_files, uint32_t num_dir_buckets,
                                                       uint32_t num_file_buckets, uint32_t unknown) {
    return HandleFormatSaveData(thread, session_id, 0x4, 1 /* PATH_EMPTY */, 1, block_size,
                                num_dirs, num_files, num_dir_buckets, num_file_buckets, unknown,
                                IPC::StaticBuffer { static_buffer_addr[0], static_buffer_size, 0 });
}

std::tuple<OS::Result, uint32_t> FakeFS::HandleIsSdmcDetected(FakeThread& thread) {
    logger.info("{}received IsSdmcDetected", ThreadPrinter{thread});
    // TODO: Make this configurable
    uint32_t detected = 1;
//    uint32_t detected = 0;
    return std::make_tuple(RESULT_OK, detected);
}

std::tuple<OS::Result, uint32_t> FakeFS::HandleGetPriority(FakeThread& thread) {
    logger.info("{}received GetPriority", ThreadPrinter{thread});
    uint32_t stub_priority = 0;
    return std::make_tuple(RESULT_OK, stub_priority);
}

std::tuple<OS::Result, Platform::PXI::PM::ProgramInfo> FakeFS::HandleGetProgramLaunchInfo(FakeThread& thread, ProcessId id) {
    logger.info("{}received GetProgramLaunchInfo for process id {}", ThreadPrinter{thread}, id);

    auto it = process_infos.find(id);
    if (it == process_infos.end())
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);

    return std::make_tuple(RESULT_OK, it->second.program);
}

std::tuple<OS::Result, ArchiveFormatInfo>
FakeFS::HandleGetFormatInfo(FakeThread& thread, ProcessId session_id, Platform::FS::ArchiveId archive_id,
                            uint32_t archive_path_type, uint32_t archive_path_size, IPC::StaticBuffer archive_path) {
    auto [result, archive] = OpenArchive(thread, *this, session_id, archive_id, archive_path_type, archive_path_size, archive_path);
    if (result != RESULT_OK) {
        throw std::runtime_error(fmt::format("Failed to open archive {:#x} for GetFormatInfo", archive_id));
    }

    auto info = archive->GetFormatInfo(thread, *this);
    return std::make_tuple(RESULT_OK, info);
}

std::tuple<OS::Result> FakeFS::HandleFormatSaveData(FakeThread&, ProcessId session_id, ArchiveId archive_id,
                                                    uint32_t path_type, uint32_t, uint32_t max_size,
                                                    uint32_t max_directories, uint32_t max_files,
                                                    uint32_t, uint32_t, uint32_t duplicate_data, IPC::StaticBuffer) {
    if (archive_id != 4) {
        throw std::runtime_error(fmt::format("Expected archive id 0x4 in FormatSaveData, got {:#x}", archive_id));
    }

    if (path_type != 1 /* EMPTY */) {
        throw std::runtime_error("Expected empty path in FormatSaveData");
    }

    auto it = process_infos.find(session_id);
    if (it == process_infos.end()) {
        throw std::runtime_error(fmt::format("Called FormatSaveData from unregistered process with id {}", session_id));
    }

    auto format_info = ArchiveFormatInfo::IPCDeserialize(max_size, max_directories, max_files, duplicate_data);
    ArchiveSaveData::GetProvider(*this, it->second.program).Format(format_info);

    return std::make_tuple(RESULT_OK);
}

std::tuple< OS::Result, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
            uint32_t, uint32_t, uint32_t, IPC::MappedBuffer>
FakeFS::HandleUpdateSha256Context(  FakeThread& thread, ProcessId, uint32_t, uint32_t,
                            uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                            uint32_t, uint32_t num_bytes, uint32_t, uint32_t,
                            uint32_t, uint32_t, IPC::MappedBuffer data) {
    if (data.size < num_bytes) {
        throw Mikage::Exceptions::Invalid("Input buffer too small");
    }

    if ((data.size % 0x40) != 0) {
//        throw Mikage::Exceptions::NotImplemented("Partial hashing not supported");
    }

    std::array<uint32_t, 8> result_sha {};

    // Reset SHA256 hardware context
    thread.WriteMemory32(0x1ec01000, 1);

    // Compute hash
    for (uint32_t i = 0; i < num_bytes; ++i) {
        auto val = thread.ReadMemory(data.addr + i);
        thread.WriteMemory(0x1ee01000 + i % 0x40, val);
    }

    // Finalize hash
    thread.WriteMemory32(0x1ec01000, 2);

    // Read result
    for (uint32_t i = 0; i < result_sha.size(); ++i) {
        // TODO: Have to use ReadPhysicalMemory32 here since ReadMemory32 expands to four individual 8-bit reads...
        result_sha[i] = thread.GetParentProcess().ReadPhysicalMemory32(Memory::IO_HASH::start + 0x40 + i * sizeof(uint32_t));
    }

    return std::make_tuple( RESULT_OK, result_sha[0], result_sha[1], result_sha[2], result_sha[3], result_sha[4], result_sha[5], result_sha[6], result_sha[7], data);
}

std::tuple<OS::Result, IPC::MappedBuffer>
FakeFS::HandleCreateExtSaveData(FakeThread& thread, ProcessId, const Platform::FS::ExtSaveDataInfo& info,
                                uint32_t max_directories, uint32_t max_files, uint64_t, uint32_t,
                                IPC::MappedBuffer input_smdh) {
    auto result = ArchiveExtSaveData::CreateSaveData(thread, *this, info, max_directories, max_files, input_smdh);
    return std::make_tuple(result, input_smdh);
}

std::tuple<OS::Result, uint32_t, IPC::MappedBuffer>
FakeFS::HandleEnumerateExtSaveData( FakeThread& thread, ProcessId, uint32_t, uint32_t media_type,
                                    uint32_t id_entry_size, uint32_t is_shared, IPC::MappedBuffer output_ids) {
    if (media_type == 0 && !is_shared) {
        throw Mikage::Exceptions::Invalid("NAND extdata must be shared");
    } else if (media_type == 1 && is_shared) {
        // The FS module accepts either type of extdata here, but in practice only non-shared is used
        throw Mikage::Exceptions::NotImplemented("SD extdata is expected to be non-shared");
    } else if (media_type == 2) {
        throw Mikage::Exceptions::Invalid("Gamecards cannot store extdata");
    }

    if ((id_entry_size != 4 && id_entry_size != 8) || output_ids.size % id_entry_size) {
        throw Mikage::Exceptions::Invalid("Invalid extdata ID size or misaligned ID buffer");
    }

    auto extdata_id_high = is_shared ? 0x00048000 : 0x00000000;
    auto extdata_high_dir = ArchiveExtSaveData::GetExtDataRootDirectory(*this, static_cast<MediaType>(media_type)) / (is_shared ? "00048000" : "00000000");

    uint32_t num_written = 0;
    const uint32_t max_entries = output_ids.size / id_entry_size;
    for (const auto& extdata_low_dir : std::filesystem::directory_iterator { extdata_high_dir }) {
        if (max_entries == num_written) {
            break;
        }

        std::string low_id_filename = extdata_low_dir.path().filename();
        uint32_t extdata_id_low = 0;
        auto result = std::from_chars(low_id_filename.data(), low_id_filename.data() + 8, extdata_id_low, 16);
        if (result.ptr != low_id_filename.data() + 8) {
            throw std::runtime_error(fmt::format("Could not parse extdata low ID from {}", extdata_low_dir.path().string()));
        }

        uint64_t extdata_id = (uint64_t)extdata_id_high << 32 | extdata_id_low;
        if (id_entry_size == 4) {
            thread.WriteMemory32(output_ids.addr + (num_written * 4), extdata_id);
        } else {
            thread.WriteMemory32(output_ids.addr + (num_written * 8), extdata_id);
            thread.WriteMemory32(output_ids.addr + (num_written * 8) + 4, extdata_id >> 32);
        }

        ++num_written;
    }

    return std::make_tuple(RESULT_OK, num_written, output_ids);
}

std::tuple<OS::Result, IPC::MappedBuffer>
FakeFS::HandleCreateExtSaveDataLegacy(  FakeThread& thread, ProcessId process_id, uint32_t media_type,
                                        uint64_t save_id, uint32_t smdh_size, uint32_t max_directories,
                                        uint32_t max_files, IPC::MappedBuffer smdh) {
    return HandleCreateExtSaveData( thread, process_id, ExtSaveDataInfo { static_cast<Platform::FS::MediaType>(media_type), {}, save_id, {} },
                                    max_directories, max_files, std::numeric_limits<uint64_t>::max(),
                                    smdh_size, smdh);
}

std::tuple<OS::Result> FakeFS::HandleDeleteExtSaveData(FakeThread& thread, ProcessId, const Platform::FS::ExtSaveDataInfo& info) {
    auto result = ArchiveExtSaveData::DeleteSaveData(thread, *this, info);
    return std::make_tuple(result);
}

std::tuple<OS::Result> FakeFS::HandleCreateSystemSaveData(FakeThread&, ProcessId, uint32_t media_type, uint32_t save_id,
                                                          uint32_t total_size, uint32_t /*block_size*/, uint32_t /*num_directories*/,
                                                          uint32_t /*num_files*/, uint32_t, uint32_t, uint32_t) {
    if (media_type > Meta::to_underlying(MediaType::SD)) {
        throw Mikage::Exceptions::Invalid("Invalid media type");
    }
    ArchiveSystemSaveDataForSaveId::CreateSystemSaveData(*this, static_cast<MediaType>(media_type), save_id, total_size);
    return std::make_tuple(RESULT_OK);
}

void FakeFS::FSRegThread(FakeThread& thread) {
    HLE::OS::ServiceHelper service;
    service.Append(OS::ServiceUtil::SetupService(thread, "fs:REG", 2));

    auto InvokeCommandHandler = [this](FakeThread& thread, uint32_t index) {
        Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
        return RegCommandHandler(thread, header);
    };

    service.Run(thread, std::move(InvokeCommandHandler));
}

decltype(HLE::OS::ServiceHelper::SendReply) FakeFS::RegCommandHandler(FakeThread& thread, IPC::CommandHeader header) {
    // server_session: Incoming IPC command from the indexed client
    thread.GetLogger()->info("{}received IPC request", ThreadPrinter{thread});

    namespace FSReg = Platform::FS::Reg;

    switch (header.command_id) {
    case FSReg::Register::id:
        IPC::HandleIPCCommand<FSReg::Register>(BindMemFn(&FakeFS::OnReg_Register, this), thread, thread);
        break;

    case FSReg::Unregister::id:
        IPC::HandleIPCCommand<FSReg::Unregister>(BindMemFn(&FakeFS::OnReg_Unregister, this), thread, thread);
        break;

    case FSReg::CheckHostLoadId::id:
        IPC::HandleIPCCommand<FSReg::CheckHostLoadId>(BindMemFn(&FakeFS::OnReg_CheckHostLoadId, this), thread, thread);
        break;

    default:
        throw Mikage::Exceptions::NotImplemented(   "{}received unknown command id {:#x} (full command: {:#010x})",
                                                    ThreadPrinter{thread}, header.command_id.Value(), header.raw);
    }

    return HLE::OS::ServiceHelper::SendReply;
}

OS::OS::ResultAnd<> FakeFS::OnReg_Register(FakeThread& thread, ProcessId pid, Platform::PXI::PM::ProgramHandle program_handle, Platform::PXI::PM::ProgramInfo program_info, Platform::FS::StorageInfo storage_info) {
    auto info = ProcessInfo { program_info, storage_info };
    process_infos.emplace(std::make_pair(pid, info));
    return std::make_tuple(RESULT_OK);
}

OS::OS::ResultAnd<> FakeFS::OnReg_Unregister(FakeThread&, ProcessId pid) {
    auto entry_it = process_infos.find(pid);
    if (entry_it == process_infos.end()) {
        throw Mikage::Exceptions::Invalid("Tried to unregister process that hadn't been registered before");
    }
    process_infos.erase(entry_it);

    return std::make_tuple(RESULT_OK);
}

OS::OS::ResultAnd<> FakeFS::OnReg_CheckHostLoadId(FakeThread& thread, Platform::PXI::PM::ProgramHandle program_handle) {
    // This is related to "Host IO", which is only available on dev kits

    logger.info("{}received CheckHostLoadId for program handle {:#018x}: Stub",
                ThreadPrinter{thread}, program_handle.value);

    // Return an error since we generally emulate a retail 3DS
    return std::make_tuple(0xd9004677);
}

}  // namespace HLE
