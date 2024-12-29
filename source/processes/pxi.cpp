#include "fs_common.hpp"
#include "pxi.hpp"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "os.hpp"

#include <framework/formats.hpp>
#include <framework/exceptions.hpp>

#include "platform/crypto.hpp"
#include "platform/file_formats/ncch.hpp"
#include "platform/pxi.hpp"
#include "pxi_fs.hpp"

#include "framework/meta_tools.hpp"

#include <range/v3/algorithm/copy.hpp>
#include <range/v3/algorithm/find.hpp>
#include <range/v3/algorithm/find_first_of.hpp>

#include <charconv>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <fmt/ostream.h>

std::vector<uint64_t>* nand_titles = nullptr;

namespace std {

static std::ostream& operator<<(std::ostream& os, const Platform::PXI::PM::ProgramInfo& info) {
    os << fmt::format("(title id {:#x}, media type {})",
                      info.program_id, info.media_type == 0 ? "NAND" : info.media_type == 1 ? "SD" : info.media_type == 2 ? "Game card" : "Unknown");
    return os;
}

} // namespace std

template <> struct fmt::formatter<Platform::PXI::PM::ProgramInfo> : ostream_formatter {};

namespace HLE {

// namespace OS {

namespace PXI {

using Result = OS::Result;
using Thread = OS::Thread;
using FakeThread = OS::FakeThread;
using WrappedFakeThread = OS::WrappedFakeThread;
using ThreadPrinter = OS::ThreadPrinter;

using OSImpl = OS::OS;
static const auto RESULT_OK = OS::RESULT_OK;

struct HLETitle {
    const char* name; // module name specified in the original NCCH
    std::vector<uint64_t> dependencies = {};
};

const std::unordered_map<uint64_t, HLETitle> hle_titles = {
    { 0x4003000008a02, { "ErrDisp" } },
    { 0x4013000001002, { "sm" } },
    { 0x4013000001102, { "fs" } },
    { 0x4013000001402, { "pxi" } },
    { 0x4013000001502, { "am" } },
    { 0x4013000001602, { "cam" } },
    { 0x4013000001702, { "cfg", { 0x4013000003102 } } },
    { 0x4013000001802, { "cdc", { 0x4013000001f02, 0x4013000002102 } } },
    { 0x4013000001a02, { "dsp" } },
    { 0x4013000001b02, { "gpio" } },
//    { 0x4013000001c02, { "gsp", { 0x4013000003502 } } }, // NEWS Hack
    { 0x4013000001d02, { "hid" } },
    { 0x4013000001e02, { "i2c" } },
    { 0x4013000001f02, { "mcu", { 0x4013000001e02 } } },
    { 0x4013000002002, { "mic" } },
    { 0x4013000002102, { "pdn" } },
    { 0x4013000002202, { "ptm", { 0x4013000001e02, 0x4013000001f02, 0x4013000002102 } } },
    { 0x4013000002402, { "ac", { 0x4013000002e02 } } },
    { 0x4013000002602, { "cecd", { 0x4013000003202 } } },
    { 0x4013000002702, { "csnd" } },
    { 0x4013000002802, { "dlp" } },
    { 0x4013000002902, { "http", { 0x4013000002e02 } } },
    { 0x4013000002a02, { "mp" } },
    { 0x4013000002b02, { "ndm", { 0x4013000002402, 0x4013000003202, 0x4013000003402 } } },
    { 0x4013000002c02, { "nim", { 0x4013000002402 } } },
    { 0x4013000002d02, { "nwm", { 0x4013000001f02 } } },
    { 0x4013000002e02, { "socket" } },
    { 0x4013000002f02, { "ssl", { 0x4013000002e02 } } },
    { 0x4013000003102, { "ps", { 0x4013000001f02 } } },
    { 0x4013000003202, { "friends", { 0x4013000002402, 0x4013000002e02 } } },
    { 0x4013000003302, { "ir", { 0x4013000001e02 } } },
    { 0x4013000003402, { "boss", { 0x4013000002402, 0x4013000003202 } } },
    { 0x4013000003502, { "news", { 0x4013000003202, 0x4013000003402 } } },
    { 0x4013000003702, { "ro" } },
    { 0x4013000003802, { "act" } },
    { 0x4013000004002, { "nfc" } },
    { 0x4013000008002, { "ns" } },
};

std::optional<const char*> GetHLEModuleName(uint64_t title_id) {
    auto it = hle_titles.find(title_id);
    if (it == hle_titles.end()) {
        return std::nullopt;
    }

    return it->second.name;
}

FakePXI::FakePXI(FakeThread& thread)
    : os(thread.GetOS()),
      logger(*thread.GetLogger()) {
    thread.name = "PxiFS0Thread";

    Context context;

    // Search for installed NAND titles
    // TODO: Move titles to ./data/title
    {
        std::filesystem::path base_path = GetRootDataDirectory(os.settings);

        auto parse_title_id_part = [](const std::string& filename) -> std::optional<uint32_t> {
            // Expect an 8-digit zero-padded hexadecimal number
            if (filename.size() != 8) {
                return std::nullopt;
            }

            uint32_t title_id_word = 0;
            auto result = std::from_chars(filename.data(), filename.data() + 8, title_id_word, 16);
            if (result.ptr != filename.data() + 8) {
                return std::nullopt;
            }
            return title_id_word;
        };

        for (const auto& dir : std::filesystem::directory_iterator(base_path)) {
            if (auto title_id_high = parse_title_id_part(dir.path().filename().string())) {
                for (const auto& subdir : std::filesystem::directory_iterator(dir)) {
                    if (auto title_id_low = parse_title_id_part(subdir.path().filename().string())) {
                        context.nand_titles.push_back((uint64_t { *title_id_high } << 32) | *title_id_low);
                    }
                }
            }
        }
        nand_titles = &context.nand_titles;
    }

    {
        auto pxifs1_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(), [this,&context](FakeThread& thread) { return FSThread(thread, context, "PxiFS1"); });
        pxifs1_thread->name = "PxiFS1Thread";
        thread.GetParentProcess().AttachThread(pxifs1_thread);
    }

    {
        auto pxifsb_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(), [this,&context](FakeThread& thread) { return FSThread(thread, context, "PxiFSB"); });
        pxifsb_thread->name = "PxiFSBThread";
        thread.GetParentProcess().AttachThread(pxifsb_thread);
    }

    {
        auto pxifsr_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(), [this,&context](FakeThread& thread) { return FSThread(thread, context, "PxiFSR"); });
        pxifsr_thread->name = "PxiFSRThread";
        thread.GetParentProcess().AttachThread(pxifsr_thread);
    }

    {
        auto pxipm_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(), [this,&context](FakeThread& thread) { return PMThread(thread, context); });
        pxipm_thread->name = "PxiPMThread";
        thread.GetParentProcess().AttachThread(pxipm_thread);
    }

    {
        auto pxips_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(), [this,&context](FakeThread& thread) { return PSThread(thread, context); });
        pxips_thread->name = "PxiPSThread";
        thread.GetParentProcess().AttachThread(pxips_thread);
    }

    {
        auto new_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(), [this,&context](FakeThread& thread) { return MCThread(thread, context); });
        new_thread->name = "PxiMCThread";
        thread.GetParentProcess().AttachThread(new_thread);
    }

    {
        auto new_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(), [this,&context](FakeThread& thread) { return AMThread(thread, context); });
        new_thread->name = "PxiAMThread";
        thread.GetParentProcess().AttachThread(new_thread);
    }

    FSThread(thread, context, "PxiFS0");
}

namespace PM = Platform::PXI::PM;

FileFormat::ExHeader GetExtendedHeader(FS::FileContext& file_context, const KeyDatabase& keydb, HLE::PXI::FS::File& ncch_file) {
    ncch_file.OpenReadOnly(file_context);

    std::array<uint8_t, FileFormat::NCCHHeader::Tags::expected_serialized_size> ncch_raw;
    auto [result, bytes_read] = ncch_file.Read(file_context, 0, sizeof(ncch_raw), FS::FileBufferInHostMemory(ncch_raw.data(), sizeof(ncch_raw)));
    assert(result == RESULT_OK && bytes_read == sizeof(ncch_raw));

    std::array<uint8_t, FileFormat::ExHeader::Tags::expected_serialized_size> exheader_raw;

    std::tie(result, bytes_read) = ncch_file.Read(file_context, FileFormat::NCCHHeader::Tags::expected_serialized_size, sizeof(exheader_raw), FS::FileBufferInHostMemory(exheader_raw.data(), sizeof(exheader_raw)));
    assert(result == RESULT_OK && bytes_read == sizeof(exheader_raw));

    auto ncch_data_stream = FileFormat::MakeStreamInFromContainer(ncch_raw.begin(), ncch_raw.end());
    auto ncch_header = FileFormat::Load<FileFormat::NCCHHeader>(ncch_data_stream);

    auto exheader_data_stream = FileFormat::MakeStreamInFromContainer(exheader_raw.begin(), exheader_raw.end());
    auto exheader = FileFormat::Load<FileFormat::ExHeader>(exheader_data_stream);

    bool is_encrypted = !(ncch_header.flags & 4);
    if (is_encrypted && exheader.aci.program_id == ncch_header.program_id) {
        // ExHeader is not actually encrypted => override encryption state
        is_encrypted = false;
    }

    if (is_encrypted) {
        fprintf(stderr, "DECRYPTING EXHEADER: %c%c%c%c\n", ncch_header.magic[0], ncch_header.magic[1], ncch_header.magic[2], ncch_header.magic[3]);
        std::array<uint8_t, 16> GenerateAESKey(const std::array<uint8_t, 16>& key_x, const std::array<uint8_t, 16>& key_y);

        // 0x2c key slot
        const std::array<uint8_t, 16>& key_x = keydb.aes_slots[0x2c].x.value();
        std::array<uint8_t, 16> key_y;
        memcpy(key_y.data(), &ncch_header, sizeof(key_y));
        auto key = GenerateAESKey(key_x, key_y);

        std::array<uint8_t, 16> iv {};
        // First 8 bytes are the partition id interpreted as big-endian
        memcpy(iv.data(), &ncch_header.partition_id, sizeof(ncch_header.partition_id));
        std::reverse(iv.begin(), iv.begin() + 8);
        iv[8] = 1;

        CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), sizeof(key), iv.data());
        dec.ProcessData(reinterpret_cast<CryptoPP::byte*>(&exheader), reinterpret_cast<const CryptoPP::byte*>(&exheader), sizeof(exheader));
    }

    return exheader;
}

FileFormat::ExHeader GetExtendedHeader(Thread& thread, const Platform::FS::ProgramInfo& title_info) {
    const auto& keydb = thread.GetParentProcess().interpreter_setup.keydb;

    if (title_info.media_type == 0) {
        for (auto& [title_id, module_info] : hle_titles) {
            // If this module is HLE-ed, return a dummy exheader
            if (title_id != title_info.program_id || !thread.GetOS().ShouldHLEProcess(module_info.name)) {
                continue;
            }

            // Return a dummy exheader with minimal code segments. A virtual ExeFS is provided along with this.
            FileFormat::ExHeader ret {};
            strcpy((char*)ret.application_title.data(), module_info.name);
            ret.section_text = { 0x100000, 1, 0x1000 };
            ret.section_ro   = { 0x101000, 1, 0x1000 };
            ret.section_data = { 0x102000, 1, 0x1000 };
            ret.aci.program_id = title_id;
            ret.aci.version = 2; // constant for all titles

            ranges::copy(module_info.dependencies, ret.dependencies.begin());

            using KernelFlags = FileFormat::ExHeader::ARM11KernelCapabilityDescriptor::KernelFlags;
            ret.aci.arm11_kernel_capabilities[0] = KernelFlags::Make().memory_type()(2);
            ret.flags = ret.flags.compress_exefs_code()(false);

            return ret;
        }

        // TODO: The following should perhaps be done in the PXIFS subsystem instead
        // TODO: The content ID is hardcoded currently.
        uint32_t content_id = 0;
        const std::string filename = Meta::invoke([&] {
            std::stringstream filename;
            filename << GetRootDataDirectory(thread.GetOS().settings).string();
            filename << std::hex << std::setw(8) << std::setfill('0') << (title_info.program_id >> 32);
            filename << "/";
            filename << std::hex << std::setw(8) << std::setfill('0') << (title_info.program_id & 0xFFFFFFFF);
            filename << "/content/";
            filename << std::hex << std::setw(8) << std::setfill('0') << content_id;
            filename << ".cxi";
            return filename.str();
        });

        thread.GetLogger()->info("{}Opening \"{}\" to get the extended header", ThreadPrinter{thread}, filename);
        std::ifstream input_file;
        input_file.exceptions(std::ifstream::badbit | std::ifstream::failbit | std::ifstream::eofbit);
        try {
            input_file.open(filename, std::ios::binary);
        } catch (const std::ios_base::failure&) {
            if ((title_info.program_id & 0xf0000000) == 0x20000000) {
//                // Trying to launch N3DS dependency on O3DS => non-critical error
//                // Some games (e.g. Retro City Rampage DX) run into this
                throw IPC::IPCError { 0, 0xc8804465 }; // TODO: Which error code to return?
            }
            throw std::runtime_error(fmt::format(   "Tried to launch non-existing title {:#x} from emulated NAND.\n\nPlease dump the title from your 3DS and install it manually to this path:\n{}",
                                                    title_info.program_id, filename));
        }

        auto ncch_begin = static_cast<uint64_t>(input_file.tellg());
        auto exheader_begin = ncch_begin + FileFormat::NCCHHeader::Tags::expected_serialized_size;
        input_file.seekg(exheader_begin);

        auto exheader = FileFormat::Load<FileFormat::ExHeader>(reinterpret_cast<std::istream&>(input_file));

input_file.seekg(ncch_begin + 0x188 + 7);
uint8_t encryption_flags;
input_file.read(reinterpret_cast<char*>(&encryption_flags), sizeof(encryption_flags));

bool is_encrypted = !(encryption_flags & 4);
// TODO: read full exheader
//if (is_encrypted && exheader.aci.program_id == ncch_header.program_id) {
//    // ExHeader is not actually encrypted => override encryption state
//    is_encrypted = false;
//}

if (is_encrypted) {
fprintf(stderr, "DECRYPTING EXHEADER\n");
    std::array<uint8_t, 16> GenerateAESKey(const std::array<uint8_t, 16>& key_x, const std::array<uint8_t, 16>& key_y);

    // 0x2c key slot
    const std::array<uint8_t, 16>& key_x = keydb.aes_slots[0x2c].x.value();
    std::array<uint8_t, 16> key_y;
    input_file.seekg(ncch_begin);
    input_file.read(reinterpret_cast<char*>(key_y.data()), sizeof(key_y));
    auto key = GenerateAESKey(key_x, key_y);

    std::array<uint8_t, 16> iv {};
    // First 8 bytes are the partition id interpreted as big-endian
    input_file.seekg(ncch_begin + 0x108);
    input_file.read(reinterpret_cast<char*>(iv.data()), 8);
    std::reverse(iv.begin(), iv.begin() + 8);
    iv[8] = 1;

    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), sizeof(key), iv.data());
    dec.ProcessData(reinterpret_cast<CryptoPP::byte*>(&exheader), reinterpret_cast<const CryptoPP::byte*>(&exheader), sizeof(exheader));
}

        return exheader;
    } else if (title_info.media_type == 2) {
        auto&& ncch = thread.GetOS().setup.gamecard->GetPartitionFromId(Loader::NCSDPartitionId::Executable);
        assert(ncch);

        FS::FileContext file_context { *thread.GetLogger() };
        return GetExtendedHeader(file_context, keydb, **ncch);
    } else {
        // TODO: Implement support for SD titles (mediatype 1)

        if (title_info.program_id >> 32 == 0x4000e) {
            // This is a patch title. NS::LaunchApplication will attempt to load these before loading the application itself.
            throw IPC::IPCError { 0, 0xc8804471 }; // TODO: Which error code to return?
        } else {
            throw Mikage::Exceptions::NotImplemented(   "{}Trying to load a title with media info {:#x}, which is currently not supported",
                                                        ThreadPrinter{thread}, title_info.media_type);
        }
    }
}

static std::tuple<Result> PMGetExtendedHeader(FakeThread& thread, Context& context, PMProgramHandle program_handle, const PXI::PXIBuffer& exheader_buffer) {
    thread.GetLogger()->info("{}received GetExtendedHeader with internal program handle {:#x}",
                             ThreadPrinter{thread}, program_handle.value);

    auto program_infos = context.programs.find(program_handle);
    if (program_infos == context.programs.end()) {
        thread.GetLogger()->error("{}Unknown program handle", ThreadPrinter{thread});
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);
    }

    PM::ProgramInfo title_info, update_info;
    std::tie(title_info, update_info) = program_infos->second;

    thread.GetLogger()->info("{}Getting extended header for title id {:#x} (media type {:#x})", ThreadPrinter{thread}, title_info.program_id, title_info.media_type);

    auto exheader = GetExtendedHeader(thread, title_info);

    // TODO: Serialize only the SCI and ACI, but for that we need to regroup the members in the ExHeader definition...
    uint32_t buffer_offset = 0;

    thread.GetLogger()->info("{}Writing ExHeader data...", ThreadPrinter{thread});
    auto write_buffer_data = [&](char* data, size_t size) {
        for (auto data_ptr = data; data_ptr - data < size; ++data_ptr) {
            // TODO: Don't hardcode this size... but either way, we shouldn't
            //       need to outright abort here, either, but we currently do
            //       this because our serialization code currently operates on
            //       the entire exheader rather than only on the sci and aci.
            if (buffer_offset >= 0x400)
                return;
            if (buffer_offset + size > 0x400) {
                throw std::runtime_error("Data corruption here :(");
            }

            exheader_buffer.Write<uint8_t>(thread, buffer_offset++, *data_ptr);
        }
    };
    FileFormat::SerializationInterface<decltype(exheader)>::Save(exheader, write_buffer_data);
    thread.GetLogger()->info("{}... done", ThreadPrinter{thread});

    return std::make_tuple(RESULT_OK);
}

static std::tuple<Result, PMProgramHandle> PMRegisterProgram(FakeThread& thread, Context& context, PM::ProgramInfo title_info, PM::ProgramInfo update_info) {
    thread.GetLogger()->info("{}received RegisterProgram with title_info={}, update_info={}; attempting to assign internal program handle {:#x}",
                             ThreadPrinter{thread}, title_info, update_info, context.next_program_handle.value);

    for (auto& entries : context.programs) {
        if (entries.second.first.program_id == title_info.program_id) {
            throw Mikage::Exceptions::Invalid("Tried to re-register title {:#x} with PxiPM", title_info.program_id);
        }
    }

    auto map_entry = context.programs.emplace(std::make_pair(context.next_program_handle, std::make_pair(title_info, update_info)));
    if (!map_entry.second)
        thread.CallSVC(&OSImpl::SVCBreak, OSImpl::BreakReason::Panic);

    context.next_program_handle.value++;

    return std::make_tuple(RESULT_OK, map_entry.first->first);
}

static std::tuple<Result> PMUnregisterProgram(FakeThread& thread, Context& context, PMProgramHandle program_handle) {
    thread.GetLogger()->info("{}received UnregisterProgram with program_handle={}",
                             ThreadPrinter{thread}, program_handle.value);

    auto program_it = context.programs.find(program_handle);
    if (program_it == context.programs.end()) {
        throw Mikage::Exceptions::Invalid("Attempted to unregister unknown program handle");
    }

    context.programs.erase(program_it);

    return std::make_tuple(RESULT_OK);
}

static void PXIPMCommandHandler(FakeThread& thread, Context& context, const IPC::CommandHeader& header) try {
    switch (header.command_id) {
    case PM::GetExtendedHeader::id:
        return IPC::HandleIPCCommand<PM::GetExtendedHeader>(PMGetExtendedHeader, thread, thread, context);

    case PM::RegisterProgram::id:
        return IPC::HandleIPCCommand<PM::RegisterProgram>(PMRegisterProgram, thread, thread, context);

    case PM::UnregisterProgram::id:
        return IPC::HandleIPCCommand<PM::UnregisterProgram>(PMUnregisterProgram, thread, thread, context);

    default:
        throw std::runtime_error(fmt::format("Unknown PxiPM service command with header {:#010x}", header.raw));
    }
} catch (const IPC::IPCError& exc) {
    thread.WriteTLS(0x80, IPC::CommandHeader::Make(header.command_id, 1, 0).raw);
    thread.WriteTLS(0x84, exc.result);
}

void FakePXI::PMThread(FakeThread& thread, Context& context) {
    // NOTE: Actually, there should be four of these buffers!
    for (unsigned buffer_index = 0; buffer_index < 1; ++buffer_index) {
        const auto buffer_size = 0x1000;
        thread.WriteTLS(0x180 + 8 * buffer_index, IPC::TranslationDescriptor::MakeStaticBuffer(0, buffer_size).raw);
        Result result;
        uint32_t buffer_addr;
        std::tie(result, buffer_addr) = thread.CallSVC(&OSImpl::SVCControlMemory, 0, 0, 0x1000, 3 /* COMMIT */, 3 /* RW */);
        thread.WriteTLS(0x184 + 8 * buffer_index, buffer_addr);
    }

    OS::ServiceUtil service(thread, "PxiPM", 1);

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
            logger.info("{}received IPC request, {:#08x}, {:#08x}, {:#08x}, {:#08x}", ThreadPrinter{thread}, thread.ReadTLS(0x80), thread.ReadTLS(0x84), thread.ReadTLS(0x88), thread.ReadTLS(0x8c));
            Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
            auto signalled_handle = service.GetHandle(index);
            PXIPMCommandHandler(thread, context, header);
            last_signalled = signalled_handle;
        }
    }
}

static std::tuple<Result> PSVerifyRsaSha256(FakeThread& thread, Context& context, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                                            uint32_t, uint32_t, const PXI::PXIBuffer&, const PXI::PXIBuffer&) {
    thread.GetLogger()->info("{}received VerifyRsaSha256 (stub)", ThreadPrinter{thread});

    return std::make_tuple(RESULT_OK);
}

static auto PXIPSCommandHandler(FakeThread& thread, Context& context, const IPC::CommandHeader& header) try {
    namespace PXIPS = Platform::PXI::PS;

    switch (header.command_id) {
    case PXIPS::VerifyRsaSha256::id:
        IPC::HandleIPCCommand<PXIPS::VerifyRsaSha256>(PSVerifyRsaSha256, thread, thread, context);
        break;

    default:
        throw IPC::IPCError{header.raw, 0xdeadbef1};
    }

    return OS::ServiceHelper::SendReply;
} catch (const IPC::IPCError& err) {
    throw std::runtime_error(fmt::format("Unknown pxi:ps9 service command with header {:#010x}", err.header));
}

void FakePXI::PSThread(FakeThread& thread, Context& context) {
    // NOTE: Actually, there should be four of these buffers!
    for (unsigned buffer_index = 0; buffer_index < 2; ++buffer_index) {
        const auto buffer_size = 0x1000;
        thread.WriteTLS(0x180 + 8 * buffer_index, IPC::TranslationDescriptor::MakeStaticBuffer(0, buffer_size).raw);
        Result result;
        uint32_t buffer_addr;
        std::tie(result, buffer_addr) = thread.CallSVC(&OSImpl::SVCControlMemory, 0, 0, 0x1000, 3 /* COMMIT */, 3 /* RW */);
        thread.WriteTLS(0x184 + 8 * buffer_index, buffer_addr);
    }

    OS::ServiceHelper service;
    service.Append(OS::ServiceUtil::SetupService(thread, "pxi:ps9", 1));

    auto InvokeCommandHandler = [&context](FakeThread& thread, uint32_t /* index of signalled handle */) {
        Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
        return PXIPSCommandHandler(thread, context, header);
    };

    service.Run(thread, std::move(InvokeCommandHandler));
}

static std::tuple<Result> MCHandleUnknown0x1(FakeThread& thread, Context& context, uint32_t arg1) {
    thread.GetLogger()->info("{}received stubbed command 0x1 with argument {:#x}",
                             ThreadPrinter{thread}, arg1);

    return std::make_tuple(RESULT_OK);
}

static std::tuple<Result> MCHandleUnknown0xa(FakeThread& thread, Context& context, uint32_t arg1, uint32_t arg2, uint32_t arg3) {
    thread.GetLogger()->info("{}received stubbed command 0xa with arguments {:#x}, {:#x}, and {:#x}",
                             ThreadPrinter{thread}, arg1, arg2, arg3);

    return std::make_tuple(RESULT_OK);
}

static void PXIMCCommandHandler(FakeThread& thread, Context& context, const IPC::CommandHeader& header) try {
    namespace PXIMC = Platform::PXI::MC;

    switch (header.command_id) {
//     case PXIMC::Unknown0x1::id:
//         return IPC::HandleIPCCommand<PXIMC::Unknown0x1>(MCHandleUnknown0x1, thread, thread, context);
//
//     case PXIMC::Unknown0x2::id:
//         return IPC::HandleIPCCommand<PXIMC::Unknown0x2>(MCHandleUnknown0x2, thread, thread, context);
//
//     case PXIMC::Unknown0xa::id:
//         return IPC::HandleIPCCommand<PXIMC::Unknown0xa>(MCHandleUnknown0xa, thread, thread, context);

    default:
        throw IPC::IPCError{header.raw, 0xdeadbef2};
    }
} catch (const IPC::IPCError& err) {
    throw std::runtime_error(fmt::format("Unknown pxi:mc service command with header {:#010x}", err.header));
}

void FakePXI::MCThread(FakeThread& thread, Context& context) {
    OS::ServiceUtil service(thread, "pxi:mc", 1);

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
            logger.info("{}received IPC request, {:#08x}, {:#08x}, {:#08x}, {:#08x}", ThreadPrinter{thread}, thread.ReadTLS(0x80), thread.ReadTLS(0x84), thread.ReadTLS(0x88), thread.ReadTLS(0x8c));
            Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
            auto signalled_handle = service.GetHandle(index);
            PXIMCCommandHandler(thread, context, header);
            last_signalled = signalled_handle;
        }
    }
}

static std::tuple<Result, uint32_t> AMHandleGetTitleCount(FakeThread& thread, Context& context, uint32_t media_type) {
    thread.GetLogger()->info("{}received stubbed GetTitleCount with media_type {:#x}",
                             ThreadPrinter{thread}, media_type);

    // Only the lowest byte of the media type is used
    media_type &= 0xff;

    if (media_type == 0) {
        return std::make_tuple(RESULT_OK, context.nand_titles.size());
    } else if (media_type == 2) {
        return std::make_tuple(RESULT_OK, uint32_t { thread.GetOS().setup.gamecard != nullptr });
    } else {
        return std::make_tuple(RESULT_OK, uint32_t{0});
//        throw Mikage::Exceptions::NotImplemented("Unsupported media type");
    }
}

static std::tuple<Result, uint32_t> AMHandleGetTitleList(FakeThread& thread, Context& context, uint32_t num_titles, uint32_t media_type, const PXI::PXIBuffer& output) {
    thread.GetLogger()->info("{}received stubbed GetTitleList for {:#x} titles with media_type {:#x}",
                             ThreadPrinter{thread}, num_titles, media_type);

    // Only the lowest byte of the media type and of the title count are used
    media_type &= 0xff;

    // TODO: Validate buffer size

    if (media_type == 0) {
        // NOTE: In recent system versions (>= 9.0.0), HOME Menu always uses num_titles = 0x1c00
        if (num_titles > context.nand_titles.size()) {
//            throw Mikage::Exceptions::Invalid("Invalid number of titles queried");
//            thread.GetOS().SVCBreak(thread, OSImpl::BreakReason::Panic);
            num_titles = context.nand_titles.size();
        }

        for (uint32_t title_index = 0; title_index < num_titles; ++title_index) {
            output.Write<uint64_t>(thread, title_index * sizeof(uint64_t), context.nand_titles[title_index]);
        }
        return std::make_tuple(RESULT_OK, num_titles);
    } else if (media_type == 2) {
        if (num_titles > (thread.GetOS().setup.gamecard ? 1 : 0))
            thread.GetOS().SVCBreak(thread, OSImpl::BreakReason::Panic);

        if (thread.GetOS().setup.gamecard) {
            // TODO: Do we need to return any actual data for this?
            output.Write<uint64_t>(thread, 0, 0);
        }
        return std::make_tuple(RESULT_OK, uint32_t { thread.GetOS().setup.gamecard != nullptr });
    } else if (media_type == 1) {
        // No titles installed to the SD card
        return std::make_tuple(RESULT_OK, uint32_t { 0 });
    } else {
        throw Mikage::Exceptions::NotImplemented("Unsupported media type");
    }
}

static std::tuple<Result> AMHandleGetTitleInfos(FakeThread& thread, Context& context, uint32_t media_type, uint32_t num_titles, const PXI::PXIBuffer& title_ids, const PXI::PXIBuffer& infos) {
    thread.GetLogger()->info("{}received stubbed GetTitleInfos for {:#x} titles with media_type {:#x}",
                             ThreadPrinter{thread}, num_titles, media_type);

    // Only the lowest byte of the media type is used
    media_type &= 0xff;

    // TODO: Validate buffer size

    if (media_type == 0) {
        if (num_titles > context.nand_titles.size())
            thread.GetOS().SVCBreak(thread, OSImpl::BreakReason::Panic);

        for (uint32_t title_index = 0; title_index < num_titles; ++title_index) {
            auto title_id = title_ids.Read<uint64_t>(thread, title_index * sizeof(uint64_t));
            auto title_it = ranges::find(context.nand_titles, title_id);
            if (title_it == context.nand_titles.end()) {
//                throw Mikage::Exceptions::Invalid("Queried title info for unknown NAND title id {:#x}", title_id);
                // Selecting the "Game Notes" icon in HOME Menu makes the menu query for possibly non-existing title IDs to check for New3DS-specific manuals
                infos.Write<uint64_t>(thread, title_index * 24, 0);
                // TODO: What data should be returned here?
                infos.Write<uint64_t>(thread, title_index * 24 + 0x8, 0);
                infos.Write<uint32_t>(thread, title_index * 24 + 0x10, 0);
                infos.Write<uint32_t>(thread, title_index * 24 + 0x14, 0);
                continue;
            }

            infos.Write<uint64_t>(thread, title_index * 24, *title_it);
            // TODO: What data should be returned here?
            infos.Write<uint64_t>(thread, title_index * 24 + 0x8, 0x447000);
            infos.Write<uint32_t>(thread, title_index * 24 + 0x10, 2055 );
            infos.Write<uint32_t>(thread, title_index * 24 + 0x14, 0x1);
        }
        return std::make_tuple(RESULT_OK);
    } else if (media_type == 2) {
        if (num_titles > (thread.GetOS().setup.gamecard ? 1 : 0))
            thread.GetOS().SVCBreak(thread, OSImpl::BreakReason::Panic);

        if (thread.GetOS().setup.gamecard) {
            // TODO: Do we need to return any actual data for this?
            infos.Write<uint64_t>(thread, 0x0, 0);
            infos.Write<uint64_t>(thread, 0x8, 0);
            infos.Write<uint64_t>(thread, 0x10, 0);
        }
        return std::make_tuple(RESULT_OK);
    } else {
        throw Mikage::Exceptions::NotImplemented("Unsupported media type");
    }

    return std::make_tuple(RESULT_OK);
}

static auto PXIAMCommandHandler(FakeThread& thread, Context& context, const IPC::CommandHeader& header) try {
    namespace PXIAM = Platform::PXI::AM;

    switch (header.command_id) {
    case PXIAM::GetTitleCount::id:
        IPC::HandleIPCCommand<PXIAM::GetTitleCount>(AMHandleGetTitleCount, thread, thread, context);
        break;

    case PXIAM::GetTitleList::id:
        IPC::HandleIPCCommand<PXIAM::GetTitleList>(AMHandleGetTitleList, thread, thread, context);
        break;

    case PXIAM::GetTitleInfos::id:
        IPC::HandleIPCCommand<PXIAM::GetTitleInfos>(AMHandleGetTitleInfos, thread, thread, context);
        break;

    // Takes a single input word (presumably a media_type)
    case 0x3f:
        // NOTE: This function is called by AM command 0x13 ("NeedsCleanup"),
        //       which returns a boolean, so my current guess is it just
        //       forwards that from this function. This needs to be verified,
        //       though!
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0); // Does not need cleanup
        break;

    default:
        throw IPC::IPCError{header.raw, 0xdeadbef3};
    }

    return OS::ServiceHelper::SendReply;
} catch (const IPC::IPCError& err) {
    throw std::runtime_error(fmt::format("Unknown pxi:am9 service command with header {:#010x}", err.header));
}

void FakePXI::AMThread(FakeThread& thread, Context& context) {
    // NOTE: Actually, there should be four of these buffers!
    for (unsigned buffer_index = 0; buffer_index < 2; ++buffer_index) {
        const auto buffer_size = 0x1000;
        thread.WriteTLS(0x180 + 8 * buffer_index, IPC::TranslationDescriptor::MakeStaticBuffer(0, buffer_size).raw);
        Result result;
        uint32_t buffer_addr;
        std::tie(result, buffer_addr) = thread.CallSVC(&OSImpl::SVCControlMemory, 0, 0, 0x1000, 3 /* COMMIT */, 3 /* RW */);
        thread.WriteTLS(0x184 + 8 * buffer_index, buffer_addr);
    }

    OS::ServiceHelper service;
    service.Append(OS::ServiceUtil::SetupService(thread, "pxi:am9", 1));

    auto InvokeCommandHandler = [&context](FakeThread& thread, uint32_t /* index of signalled handle */) {
        Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
        return PXIAMCommandHandler(thread, context, header);
    };

    service.Run(thread, std::move(InvokeCommandHandler));
}

}  // namespace PXI

// }  // namespace OS

}  // namespace HLE
