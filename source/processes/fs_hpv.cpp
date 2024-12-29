#include "fs_common.hpp"
#include "fs_hpv.hpp"
#include "os_hypervisor_private.hpp"
#include "os.hpp"
#include "ipc.hpp"

#include <platform/fs.hpp>
#include <platform/pxi.hpp>

#include <range/v3/algorithm/generate_n.hpp>
#include <range/v3/iterator/insert_iterators.hpp>
#include <range/v3/view/iota.hpp>

#include <boost/container/static_vector.hpp>
#include <boost/mp11/list.hpp>

#include <codecvt>
#include <variant>

#include <fmt/ranges.h>

namespace HLE {

namespace OS {

namespace HPV {

// TODO: Default actions:
// * Check return value
// * Check expected command signature
// * Dispatch command to lambda (=> TryDispatch)

Path::Path(Thread& thread, uint32_t type, uint32_t addr, uint32_t num_bytes)
    : Path(thread, type, num_bytes, [&thread,addr]() mutable { return thread.ReadMemory(addr++); }) {
}

Path::Path(Thread& thread, uint32_t type, uint32_t num_bytes, std::function<uint8_t()> read_next_byte) {
    switch (type) {
    case 1: // empty path
    {
        data = Utf8PathType { };
        break;
    }

    case 2: // binary path
    {
        data = BinaryPathType { };
        auto& path_data = std::get<BinaryPathType>(data);

        if (num_bytes > path_data.capacity()) {
            throw std::runtime_error(fmt::format("Path length {} exceeded maximum {}", num_bytes, path_data.capacity()));
        }

        ranges::generate_n(ranges::back_inserter(path_data), num_bytes, read_next_byte);
        break;
    }

    case 3: // ASCII path
    {
        // TODO: Strip trailing \0 characters (and do the same in FakeFS)
        data = Utf8PathType { };
        auto& path = std::get<Utf8PathType>(data);

        path.reserve(num_bytes);
        ranges::generate_n(ranges::back_inserter(path), num_bytes, read_next_byte);
        break;
    }

    case 4: // UTF-16 path
    {
        // TODO: Strip trailing \0 characters (and do the same in FakeFS)
        if (num_bytes % 2)
            throw std::runtime_error("Expected path size for UTF16 to be a multiple of 2");

        // Read in data as UTF-16 with host byte order
        std::u16string utf16_data;
        utf16_data.reserve(num_bytes / 2);
        auto ReadFromAddr = [&]() -> char16_t {
            uint16_t low = read_next_byte();
            uint16_t high = read_next_byte();
            return low | (high << uint16_t{8});
        };
        ranges::generate_n(ranges::back_inserter(utf16_data), num_bytes / 2, ReadFromAddr);

        // Strip trailing \0 characters
        // TODO: do the same in FakeFS
        while (!utf16_data.empty() && utf16_data.back() == 0) {
            utf16_data.pop_back();
        }

        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> conversion;
        data = Path::Utf8PathType { conversion.to_bytes(utf16_data) };
        break;
    }

default:
        throw std::runtime_error(fmt::format("Unknown path type {}", type));
    }
}

std::string Path::ToString() const {
    if (auto utf8_path = std::get_if<Path::Utf8PathType>(&data)) {
        return *utf8_path;
    } else {
        auto& binary_path = std::get<Path::BinaryPathType>(data);

        std::string ret;
        for (auto byte : binary_path) {
            ret += fmt::format("{:02x}", byte);
        }
        return ret;
    }
}

namespace {

std::string RawPathToString(Thread& thread, uint32_t type, uint32_t num_bytes, const IPC::StaticBuffer& path) {
    const char* type_strings[] = {
        "invalid",
        "empty",
        "binary",
        "ascii",
        "utf16",
    };
    if (type >= std::size(type_strings)) {
        throw std::runtime_error(fmt::format("Unknown path type {:#x}", type));
    }

    auto printed_path = CommonPath(thread, type, num_bytes, path).Visit(
                [](const Utf8PathType& utf8) { return static_cast<std::string>(utf8); },
                [](const BinaryPathType& bin) { return fmt::format("{:02x}", fmt::join(bin, "")); });

    return fmt::format("({},{}b,{})", type_strings[type], num_bytes, printed_path);
}

struct FileSession : NamedSession {
private:
    FileSession(std::string_view name, FSContext& context)
        : NamedSession(name, context) {
    }

public:
    FileSession(Archive& archive, const Path& file_path, FSContext& context)
        : NamedSession(BuildFileDescription(archive, file_path), context) {
    }

    FSContext& context() {
        return static_cast<FSContext&>(NamedSession::context);
    }

    static std::string BuildFileDescription(Archive& archive, const Path& file_path) {
        return fmt::format("File {}:/{}", archive.Describe(), file_path.ToString());
    }

    void OnRequest(Hypervisor& hypervisor, Thread& thread, Handle session) override {
        namespace FS = Platform::FS;
        namespace FSF = Platform::FS::File;

        auto dispatcher = RequestDispatcher<> { thread, *this, thread.ReadTLS(0x80) };

        dispatcher.DecodeRequest<FSF::OpenSubFile>([&](auto&, uint64_t offset, uint64_t num_bytes) {
            auto description = fmt::format("OpenSubFile, offset={:#x}, num_bytes={:#x}", offset, num_bytes);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSF::Read>([&](auto&, uint64_t offset, uint32_t num_bytes, const IPC::MappedBuffer& target) {
            auto description = fmt::format("Read, offset={:#x}, num_bytes={:#x}, target_addr={:#x}",
                                           offset, num_bytes, target.addr);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSF::Write>([&](auto&, uint64_t offset, uint32_t num_bytes, uint32_t options, const IPC::MappedBuffer& target) {
            auto description = fmt::format("Write, offset={:#x}, num_bytes={:#x}, options={:#x}, source_addr={:#x}",
                                           offset, num_bytes, options, target.addr);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSF::GetSize>([&](auto&) {
            auto description = fmt::format("GetSize");
            Session::OnRequest(hypervisor, thread, session, description);

            // TODO: Print returned size
        });

        dispatcher.DecodeRequest<FSF::SetSize>([&](auto&, uint64_t size) {
            auto description = fmt::format("SetSize, size={:#x}", size);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSF::Close>([&](auto&) {
            auto description = fmt::format("Close");
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSF::Flush>([&](auto&) {
            auto description = fmt::format("Flush");
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSF::OpenLinkFile>([&](auto& response) {
            Session::OnRequest(hypervisor, thread, session, "OpenLinkFile");

            response.OnResponse([=,this](Hypervisor& hv, Thread& thread, Result result, Handle file_session_handle) {
                if (result != RESULT_OK) {
                    return;
                }

                auto link_file = new FileSession(Describe() + " (link)", context());
                hv.SetSessionObject(thread.GetParentProcess().GetId(), file_session_handle, link_file);
            });
        });

        dispatcher.OnUnknown([&]() { Session::OnRequest(hypervisor, thread, session); });
    }
};

struct DirSession : NamedSession {
    DirSession(Archive& archive, const Path& dir_path, FSContext& context)
        : NamedSession(BuildDirectoryDescription(archive, dir_path), context) {
    }

    FSContext& context() {
        return static_cast<FSContext&>(NamedSession::context);
    }

    static std::string BuildDirectoryDescription(Archive& archive, const Path& dir_path) {
        return fmt::format("Directory {}:/{}", archive.Describe(), dir_path.ToString());
    }

    void OnRequest(Hypervisor& hypervisor, Thread& thread, Handle session) override {
        namespace FS = Platform::FS;
        namespace FSD = Platform::FS::Dir;

        auto dispatcher = RequestDispatcher<> { thread, *this, thread.ReadTLS(0x80) };

        dispatcher.DecodeRequest<FSD::Read>([&](auto& response, uint32_t requested_entries, const IPC::MappedBuffer& target) {
            auto description = fmt::format("Read, requested_entries={:#x}, target_addr={:#x}",
                                           requested_entries, target.addr);
            Session::OnRequest(hypervisor, thread, session, description);

            response.OnResponse([=](Hypervisor& hv, Thread& thread, Result result, uint32_t num_entries, const IPC::MappedBuffer& target) {
                if (result != RESULT_OK) {
                    return;
                }

                for (uint32_t entry = 0; entry < num_entries; ++entry) {
                    std::string filename;
                    uint32_t addr = target.addr + entry * 0x228;
                    for (;;) {
                        char c = thread.ReadMemory(addr++);
                        if (c == 0) {
                            break;
                        }
                        filename.push_back(c);
                    }

                    bool is_dir = thread.ReadMemory(target.addr + entry * 0x228 + 0x21C);
                    uint32_t size = thread.ReadMemory32(target.addr + entry * 0x228 + 0x220);

                    thread.GetLogger()->info("  Got directory entry: {} ({})", filename, is_dir ? "dir" : fmt::format("{:#x} bytes", size));
                }
            });
        });

        dispatcher.DecodeRequest<FSD::Close>([&](auto&) {
            Session::OnRequest(hypervisor, thread, session, "Close");
        });

        dispatcher.OnUnknown([&]() { Session::OnRequest(hypervisor, thread, session); });
    }
};

struct ArchiveImpl : Archive {
    // TODO: Archive path
    ArchiveImpl(uint32_t id, const Path& path) : id(id) {
        archive_path = path.ToString();
    }

    std::string Describe() const override {
        std::string archive_name;
        switch (id) {
        case 0x3:
            archive_name = "selfncch";
            break;

        case 0x4:
            archive_name = "savedata";
            break;

        case 0x7:
            archive_name = "shared_extdata";
            break;

        case 0x9:
            archive_name = "sdmc";
            break;

        case 0x1234567d:
            archive_name = "nandrw";
            break;

        case 0x1234567e:
            archive_name = "nandro";
            break;

        default:
            archive_name = fmt::format("{:#x}", id);
            break;
        }
        return fmt::format("{}:/{}", archive_name, archive_path);
    }

    FileSession* Open(FSContext& context, const Path& file_path) {
        return new FileSession(*this, file_path, context);
    }

    DirSession* OpenDirectory(FSContext& context, const Path& dir_path) {
        return new DirSession(*this, dir_path, context);
    }

    uint32_t id;
    std::string archive_path;
};

struct FSUserService : SessionToPort {
    FSUserService(RefCounted<Port> port, FSContext& context) : SessionToPort(port, context) {
    }

    FSContext& context() {
        return static_cast<FSContext&>(SessionToPort::context);
    }

    std::shared_ptr<ArchiveImpl> LookupArchive(Platform::FS::ArchiveHandle archive_handle) {
        auto archive_it = context().archives.find(archive_handle);
        if (archive_it == context().archives.end()) {
            throw std::runtime_error(fmt::format("Unknown archive handle {:#x} used in FS IPC command", archive_handle));
        }
        return std::static_pointer_cast<ArchiveImpl>(archive_it->second);
    }

    void OnRequest(Hypervisor& hypervisor, Thread& thread, Handle session) override {
        namespace FS = Platform::FS;
        namespace FSU = Platform::FS::User;

        auto dispatcher = RequestDispatcher<> { thread, *this, thread.ReadTLS(0x80) };
        dispatcher.DecodeRequest<FSU::Initialize>([&](auto&, ProcessId process_id) {
            context().process_ids.emplace(session, process_id);
            Session::OnRequest(hypervisor, thread, session, fmt::format("Initialize: process_id={}", process_id));
        });

        dispatcher.DecodeRequest<FSU::InitializeWithSdkVersion>([&](auto&, uint32_t, ProcessId process_id) {
            context().process_ids.emplace(session, process_id);
            Session::OnRequest(hypervisor, thread, session, fmt::format("InitializeWithSdkVersion: process_id={}", process_id));
        });

        dispatcher.DecodeRequest<FSU::OpenFile>([&](auto& response, uint32_t transaction, FS::ArchiveHandle archive_handle,
                                                    uint32_t file_path_type, uint32_t file_path_size,
                                                    uint32_t flags, uint32_t attributes,
                                                    const IPC::StaticBuffer& file_path) {
            auto archive = LookupArchive(archive_handle);

            auto description = fmt::format("OpenFile, transaction={:#x}, archive={}, file_path={}, flags={:#x}, attributes={:#x}",
                                           transaction, archive->Describe(),
                                           RawPathToString(thread, file_path_type, file_path_size, file_path),
                                           flags, attributes);
            Session::OnRequest(hypervisor, thread, session, description);

            response.OnResponse([=](Hypervisor& hv, Thread& thread, Result result, Handle file_session_handle) {
                if (result != RESULT_OK) {
                    return;
                }

                auto file_path_object = Path { thread, file_path_type, file_path.addr, file_path_size };
                auto file = archive->Open(context(), file_path_object);
                hv.SetSessionObject(thread.GetParentProcess().GetId(), file_session_handle, file);
            });
        });

        dispatcher.DecodeRequest<FSU::OpenFileDirectly>([&](auto& response, uint32_t transaction, FS::ArchiveId archive_id,
                                                            uint32_t archive_path_type, uint32_t archive_path_size,
                                                            uint32_t file_path_type, uint32_t file_path_size,
                                                            uint32_t flags, uint32_t attributes,
                                                            const IPC::StaticBuffer& archive_path,
                                                            const IPC::StaticBuffer& file_path) {
            auto description = fmt::format("OpenFileDirectly, transaction={:#x}, archive_id={:#x}, archive_path={}, file_path={}, flags={:#x}, attributes={:#x}",
                                           transaction, archive_id,
                                           RawPathToString(thread, archive_path_type, archive_path_size, archive_path),
                                           RawPathToString(thread, file_path_type, file_path_size, file_path),
                                           flags, attributes);
            Session::OnRequest(hypervisor, thread, session, description);

            response.OnResponse([=](Hypervisor& hv, Thread& thread, Result result, Handle file_session_handle) {
                if (result != RESULT_OK) {
                    return;
                }

                auto archive_path_object = Path { thread, archive_path_type, archive_path.addr, archive_path_size };
                auto file_path_object = Path { thread, file_path_type, file_path.addr, file_path_size };
                auto archive = new ArchiveImpl(archive_id, archive_path_object);
                auto file = archive->Open(context(), file_path_object);
                hv.SetSessionObject(thread.GetParentProcess().GetId(), file_session_handle, file);
            });
        });

        dispatcher.DecodeRequest<FSU::DeleteFile>([&](auto&, uint32_t transaction, FS::ArchiveHandle archive_handle, uint32_t file_path_type, uint32_t file_path_size, const IPC::StaticBuffer& dir_path) {
            auto archive = LookupArchive(archive_handle);

            auto description = fmt::format("DeleteFile, archive={}, file_path={}, transaction={:#x}",
                                           archive->Describe(),
                                           RawPathToString(thread, file_path_type, file_path_size, dir_path), transaction);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSU::RenameFile>([&](  auto&, uint32_t transaction,
                                                        FS::ArchiveHandle source_archive_handle, uint32_t source_path_type, uint32_t source_path_size,
                                                        FS::ArchiveHandle target_archive_handle, uint32_t target_path_type, uint32_t target_path_size,
                                                        const IPC::StaticBuffer& source_path, const IPC::StaticBuffer& target_path) {
            auto source_archive = LookupArchive(source_archive_handle);
            auto target_archive = LookupArchive(target_archive_handle);

            auto description = fmt::format("RenameFile, transaction={:#x}, archive={}->{}, {:#x}+{:#x}, file_path={}->{}",
                                           transaction, source_archive->Describe(), target_archive->Describe(),
                                           source_path.addr, source_path.size,
                                           RawPathToString(thread, source_path_type, source_path_size, source_path),
                                           RawPathToString(thread, target_path_type, target_path_size, target_path));
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSU::DeleteDirectory>([&](auto&, uint32_t transaction,
                                                           FS::ArchiveHandle archive_handle,
                                                           uint32_t dir_path_type, uint32_t dir_path_size,
                                                           const IPC::StaticBuffer& dir_path) {
            auto archive = LookupArchive(archive_handle);

            auto description = fmt::format("DeleteDirectory, transaction={:#x}, archive={}, dir_path={}",
                                           transaction, archive->Describe(),
                                           RawPathToString(thread, dir_path_type, dir_path_size, dir_path));
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSU::CreateFile>([&](auto&, uint32_t transaction, FS::ArchiveHandle archive_handle, uint32_t file_path_type, uint32_t file_path_size, uint32_t attributes, uint64_t initial_size, const IPC::StaticBuffer& dir_path) {
            auto archive = LookupArchive(archive_handle);

            auto description = fmt::format("CreateFile, archive={}, file_path={}, transaction={:#x}, attributes={:#x}, size={:#x}",
                                           archive->Describe(),
                                           RawPathToString(thread, file_path_type, file_path_size, dir_path), transaction, attributes, initial_size);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSU::CreateDirectory>([&](auto&, uint32_t transaction, FS::ArchiveHandle archive_handle, uint32_t dir_path_type, uint32_t dir_path_size, uint32_t attributes, const IPC::StaticBuffer& dir_path) {
            auto archive = LookupArchive(archive_handle);

            auto description = fmt::format("CreateDirectory, archive={}, dir_path={}, transaction={:#x}, attributes={:#x}",
                                           archive->Describe(),
                                           RawPathToString(thread, dir_path_type, dir_path_size, dir_path), transaction, attributes);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSU::OpenDirectory>([&](auto& response, FS::ArchiveHandle archive_handle, uint32_t dir_path_type, uint32_t dir_path_size, const IPC::StaticBuffer& dir_path) {
            auto archive = LookupArchive(archive_handle);

            auto description = fmt::format("OpenDirectory, archive={}, dir_path={}",
                                           archive->Describe(),
                                           RawPathToString(thread, dir_path_type, dir_path_size, dir_path));
            Session::OnRequest(hypervisor, thread, session, description);

            response.OnResponse([=](Hypervisor& hv, Thread& thread, Result result, Handle dir_session_handle) {
                if (result != RESULT_OK) {
                    return;
                }

                auto dir_path_object = Path { thread, dir_path_type, dir_path.addr, dir_path_size };
                auto dir = archive->OpenDirectory(context(), dir_path_object);
                hv.SetSessionObject(thread.GetParentProcess().GetId(), dir_session_handle, dir);
            });
        });

        dispatcher.DecodeRequest<FSU::OpenArchive>([&](auto& response, FS::ArchiveId archive_id, uint32_t archive_path_type, uint32_t archive_path_size, const IPC::StaticBuffer& archive_path) {
            auto description = fmt::format("OpenArchive, archive_id={:#x}, path={}", archive_id,
                                           RawPathToString(thread, archive_path_type, archive_path_size, archive_path));
            Session::OnRequest(hypervisor, thread, session, description);

            response.OnResponse([=](Hypervisor&, Thread& thread, Result result, FS::ArchiveHandle archive_handle) {
                if (result != RESULT_OK) {
                    return;
                    // TODO: Enable this once we stop using dummy archives!
//                    throw std::runtime_error("OpenArchive failed");
                }
                if (context().archives.count(archive_handle)) {
                    throw std::runtime_error("Archive with the given handle was already registered");
                }

                auto archive_path_object = Path { thread, archive_path_type, archive_path.addr, archive_path_size };
                auto archive = new ArchiveImpl(archive_id, archive_path_object);
                context().archives.emplace(archive_handle, archive);
            });
        });

        dispatcher.DecodeRequest<FSU::CreateSystemSaveDataLegacy>([&](  auto& response, uint32_t save_id,
                                                                        uint32_t total_size, uint32_t block_size, uint32_t num_directories,
                                                                        uint32_t num_files, uint32_t unk1, uint32_t unk2, uint32_t unk3) {
            auto description = fmt::format( "CreateSystemSaveDataLegacy, save_id={:#x}, total_size={:#x}, block_size={:#x}, num_directories={}, num_files={}, unk1={:#x}, unk2={:#x}, unk3={:#x}",
                                            save_id, total_size, block_size, num_directories, num_files, unk1, unk2, unk3);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSU::DeleteSystemSaveDataLegacy>([&](  auto& response, uint32_t save_id) {
            auto description = fmt::format( "DeleteSystemSaveDataLegacy, save_id={:#x}", save_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSU::CloseArchive>([&](auto&, FS::ArchiveHandle archive_handle) {
            auto archive = LookupArchive(archive_handle);
            auto description = fmt::format("CloseArchive, archive={}", archive->Describe());
            Session::OnRequest(hypervisor, thread, session, description);
            context().archives.erase(archive_handle);
        });

        dispatcher.DecodeRequest<FSU::GetFormatInfo>(   [&](auto&, FS::ArchiveId archive_id,
                                                            uint32_t archive_path_type, uint32_t archive_path_size,
                                                            IPC::StaticBuffer archive_path) {
            ArchiveImpl archive { archive_id, Path { thread, archive_path_type, archive_path.addr, archive_path_size } };
            auto description = fmt::format( "GetFormatInfo, archive={}", archive.Describe());
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSU::FormatSaveData>([&](auto&, FS::ArchiveId archive_id,
                                                      uint32_t archive_path_type, uint32_t archive_path_size, uint32_t num_blocks,
                                                      uint32_t num_dirs, uint32_t num_files, uint32_t num_dir_buckets,
                                                      uint32_t num_file_buckets, uint32_t unknown, IPC::StaticBuffer archive_path) {
            auto description = fmt::format( "FormatSaveData, archive_id={:#x}, path={}, num_blocks={:#x}, num_directories={:#x}, num_files={:#x}, num_dir_buckets={:#x}, num_file_buckets={:#x}, unknown={:#x}",
                                            archive_id, RawPathToString(thread, archive_path_type, archive_path_size, archive_path),
                                            num_blocks, num_dirs, num_files, num_dir_buckets, num_file_buckets, unknown);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSU::CreateExtSaveData>([&](auto&, const Platform::FS::ExtSaveDataInfo& info,
                                                         uint32_t num_dirs, uint32_t num_files, uint32_t size_limit,
                                                         uint32_t smdh_size, IPC::MappedBuffer) {
            auto description = fmt::format( "CreateExtSaveData, media_type={}, saveid={:#x}, num_directories={:#x}, num_files={:#x}, size_limit={:#x}, smdh_size={:#x}",
                                            static_cast<uint32_t>(info.media_type), info.save_id, num_dirs, num_files, size_limit, smdh_size);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSU::DeleteExtSaveData>([&](auto&, const Platform::FS::ExtSaveDataInfo& info) {
            auto description = fmt::format( "DeleteExtSaveData, media_type={}, saveid={:#x}",
                                            static_cast<uint32_t>(info.media_type), info.save_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSU::CreateSystemSaveData>([&](auto& response, uint32_t media_type, uint32_t save_id,
                                                                uint32_t total_size, uint32_t block_size, uint32_t num_directories,
                                                                uint32_t num_files, uint32_t unk1, uint32_t unk2, uint32_t unk3) {
            auto description = fmt::format( "CreateSystemSaveData, media_type={:#x}, save_id={:#x}, total_size={:#x}, block_size={:#x}, num_directories={}, num_files={}, unk1={:#x}, unk2={:#x}, unk3={:#x}",
                                            media_type, save_id, total_size, block_size, num_directories, num_files, unk1, unk2, unk3);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSU::DeleteSystemSaveData>([&](auto& response, uint32_t media_type, uint32_t save_id) {
            auto description = fmt::format( "DeleteSystemSaveData, media_type={:#x}, save_id={:#x}",
                                            media_type, save_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.OnUnknown([&]() { Session::OnRequest(hypervisor, thread, session); });
    }
};

struct FSRegService : SessionToPort {
    FSRegService(RefCounted<Port> port, FSContext& context) : SessionToPort(port, context) {
    }

    FSContext& context() {
        return static_cast<FSContext&>(SessionToPort::context);
    }

    std::shared_ptr<ArchiveImpl> LookupArchive(Platform::FS::ArchiveHandle archive_handle) {
        auto archive_it = context().archives.find(archive_handle);
        if (archive_it == context().archives.end()) {
            throw std::runtime_error(fmt::format("Unknown archive handle {:#x} used in FS IPC command", archive_handle));
        }
        return std::static_pointer_cast<ArchiveImpl>(archive_it->second);
    }

    void OnRequest(Hypervisor& hypervisor, Thread& thread, Handle session) override {
        namespace FS = Platform::FS;
        namespace FSR = Platform::FS::Reg;

        auto dispatcher = RequestDispatcher<> { thread, *this, thread.ReadTLS(0x80) };
        dispatcher.DecodeRequest<FSR::Register>([&](auto&, ProcessId pid, Platform::PXI::PM::ProgramHandle, const FS::ProgramInfo& program_info, const FS::StorageInfo& storage_info) {
            auto description = fmt::format( "Register, linking process_id {} to program_id {:#018x} (media type {:#x})", pid, program_info.program_id, program_info.media_type);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<FSR::Unregister>([&](auto&, ProcessId pid) {
            auto description = fmt::format( "Unregister, unlinking process_id {}", pid);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.OnUnknown([&]() { Session::OnRequest(hypervisor, thread, session); });
    }
};

} // anonymous namespace

HPV::RefCounted<Object> CreateFSUserService(RefCounted<Port> port, FSContext& context) {
    return HPV::RefCounted<Object>(new FSUserService(port, context));
}

HPV::RefCounted<Object> CreateFSLdrService(RefCounted<Port> port, FSContext& context) {
    // NOTE: fs:LDR has almost the same interface as fs:USER. Hence, until we need to distinguish between the two, we just return another FSUserService instance here
    return HPV::RefCounted<Object>(new FSUserService(port, context));
}

HPV::RefCounted<Object> CreateFSRegService(RefCounted<Port> port, FSContext& context) {
    return HPV::RefCounted<Object>(new FSRegService(port, context));
}

} // namespace HPV

} // namespace HOS

} // namespace HLE
