#include "os.hpp"
#include "ptm.hpp"

#include "platform/fs.hpp"
#include "platform/sm.hpp"

#include <framework/exceptions.hpp>

#include <boost/scope_exit.hpp>

namespace HLE {

namespace OS {

/**
 * Creates shared extra data archive 0x00048000f000000b and its file CFL_DB.dat
 */
static void CreatePTMSharedExtData(FakeThread& thread) {

    auto [result, srv_session] = thread.CallSVC(&OS::SVCConnectToPort, "srv:");
    if (result != RESULT_OK)
        throw std::runtime_error("CreatePTMSharedExtData failed to SVCConnectToPort");
    BOOST_SCOPE_EXIT(&srv_session, &thread) { thread.CallSVC(&OS::SVCCloseHandle, srv_session.first); } BOOST_SCOPE_EXIT_END;

    namespace SM = Platform::SM;
    IPC::SendIPCRequest<SM::SRV::RegisterClient>(thread, srv_session.first, IPC::EmptyValue{});
    auto fs_session = IPC::SendIPCRequest<SM::SRV::GetServiceHandle>(thread, srv_session.first, SM::PortName("fs:USER"), 0);
    BOOST_SCOPE_EXIT(&fs_session, &thread) { thread.CallSVC(&OS::SVCCloseHandle, fs_session); } BOOST_SCOPE_EXIT_END;

    namespace FS = Platform::FS;
    IPC::SendIPCRequest<FS::User::Initialize>(thread, fs_session, IPC::EmptyValue { });

    // Shared Extra Data
    FS::ExtSaveDataInfo extdata_info { FS::MediaType::NAND, {}, 0x00048000f000000b, 0 };
    std::array<uint8_t, 12> archive_path { };
    // TODO: Use serialization interface
    std::memcpy(archive_path.data() + 4, &extdata_info.save_id, sizeof(extdata_info.save_id));

    const uint32_t static_buffer_capacity = 32; // Large enough to hold the archive path and filename paths below
    auto static_buffer = IPC::StaticBuffer { thread.GetParentProcess().AllocateStaticBuffer(static_buffer_capacity), sizeof(archive_path), 0 };
    auto copy_to_static_buffer = [&](const auto& range) {
        uint32_t addr = static_buffer.addr;
        for (auto& elem : range) {
            assert(addr < static_buffer.addr + static_buffer_capacity);
            thread.WriteMemory(addr++, elem);
        }
        static_buffer.size = addr - static_buffer.addr;
    };
    copy_to_static_buffer(archive_path);

    FS::ArchiveHandle extdata_handle = std::invoke([&]() {
        while (true) {
            try {
                return IPC::SendIPCRequest<FS::User::OpenArchive>(thread, fs_session, 0x7, 2 /* binary path */, sizeof(archive_path), static_buffer);
            } catch (IPC::IPCError err) {
                // Create archive if it doesn't exist, yet
                if (err.result == 0xc8804464) {
                    // Create dummy buffer to pass to CreateExtSaveData
                    auto [result, buffer_addr] = thread.CallSVC(&OS::SVCControlMemory, 0, 0, 0x1000, 3/*ALLOC*/, 0x3/*RW*/);
                    IPC::SendIPCRequest<FS::User::CreateExtSaveData>(thread, fs_session, extdata_info, 100, 100, 0xffffffffffffffff, 0, IPC::MappedBuffer { buffer_addr, 0x1000 });
                    thread.CallSVC(&OS::SVCControlMemory, buffer_addr, 0, 0x1000, 1/*FREE*/, 0x3/*RW*/);
                } else {
                    // Unknown exception
                    throw;
                }
            }
        }
    });

    // NOTE: File sizes are picked according to what games expect
    const uint32_t transaction = 0;
    copy_to_static_buffer("/CFL_DB.dat");
    try {
        IPC::SendIPCRequest<FS::User::CreateFile>(thread, fs_session, transaction, extdata_handle, 3 /* ASCII */, static_buffer.size, 0, 0xe4c0 /* file size */, static_buffer);
    } catch (IPC::IPCError err) {
        if (err.result == 0xc82044b4) {
            // File already exists, which is all we need to ensure
        } else {
            throw;
        }
    }
}

FakePTM::FakePTM(FakeThread& thread)
    : os(thread.GetOS()),
      logger(*thread.GetLogger()) {

    thread.name = "ptm:sThread";

    // TODO: This function requires FakePTM to have FS access, but we don't
    //       actually register it to FS currently. This only works by accident
    //       because FakePTM gets assigned process id 4 currently (and hence is
    //       considered a FIRM module)
    // TODO: On the real system, this is done by Home Menu instead
    CreatePTMSharedExtData(thread);

    {
        auto new_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(), [this](FakeThread& thread) { return IPCThread(thread, "ptm:play"); });
        new_thread->name = "ptm:playThread";
        thread.GetParentProcess().AttachThread(new_thread);
    }

    {
        auto new_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(), [this](FakeThread& thread) { return IPCThread(thread, "ptm:sysm"); });
        new_thread->name = "ptm:sysmThread";
        thread.GetParentProcess().AttachThread(new_thread);
    }

    {
        auto new_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(), [this](FakeThread& thread) { return IPCThread(thread, "ptm:u"); });
        new_thread->name = "ptm:uThread";
        thread.GetParentProcess().AttachThread(new_thread);
    }

    {
        auto new_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(), [this](FakeThread& thread) { return IPCThread_gets(thread, "ptm:gets"); });
        new_thread->name = "ptm:getsThread";
        thread.GetParentProcess().AttachThread(new_thread);
    }

    // The CFG process goes into an infinite loop of svcSleepThread waiting for
    // the value at this address to become non-zero during boot. On the actual
    // system, PTM takes care of setting this to a non-zero value (TODO: CONFIRM!)
    thread.WriteMemory32(0x1ff81086, 1);

    IPCThread(thread, "ptm:s");
}

void FakePTM::IPCThread(FakeThread& thread, const char* service_name) {
    const uint32_t session_limit = 25; // Applies to all services other than ptm:sets (which only accepts a single connection)
    ServiceHelper service;
    service.Append(ServiceUtil::SetupService(thread, service_name, session_limit));

    Handle last_signalled = HANDLE_INVALID;

    for (;;) {
        OS::Result result;
        int32_t index;
        std::tie(result,index) = thread.CallSVC(&OS::SVCReplyAndReceive, service.handles.data(), service.handles.size(), last_signalled);
        last_signalled = HANDLE_INVALID;
        if (result == 0xc920181a) {
            if (index == -1) {
                // Reply target was closed... TODO: Implement
                os.SVCBreak(thread, OS::BreakReason::Panic);
            } else {
                // We woke up because a handle was closed; ServiceUtil has taken
                // care of closing the signalled handle already, so just continue
                service.Erase(index);
            }
        } else if (result != RESULT_OK) {
            os.SVCBreak(thread, OS::BreakReason::Panic);
        } else {
            if (index == 0) {
                // ServerPort: Incoming client connection

                HandleTable::Entry<ServerSession> session;
                std::tie(result,session) = thread.CallSVC(&OS::SVCAcceptSession, *service.GetObject<ServerPort>(index));
                if (result != RESULT_OK) {
                    os.SVCBreak(thread, OS::BreakReason::Panic);
                }

                service.Append(session);
            } else {
                // server_session: Incoming IPC command from the indexed client
                logger.info("{}received IPC request", ThreadPrinter{thread});
                Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
                auto signalled_handle = service.handles[index];
                CommandHandler(thread, header);
                last_signalled = signalled_handle;
            }
        }
    }
}

void FakePTM::IPCThread_gets(FakeThread& thread, const char* service_name) {
    const uint32_t session_limit = 25; // Applies to all services other than ptm:sets (which only accepts a single connection)
    ServiceHelper service;
    service.Append(ServiceUtil::SetupService(thread, service_name, session_limit));

    Handle last_signalled = HANDLE_INVALID;

    for (;;) {
        OS::Result result;
        int32_t index;
        std::tie(result,index) = thread.CallSVC(&OS::SVCReplyAndReceive, service.handles.data(), service.handles.size(), last_signalled);
        last_signalled = HANDLE_INVALID;
        if (result == 0xc920181a) {
            if (index == -1) {
                // Reply target was closed... TODO: Implement
                os.SVCBreak(thread, OS::BreakReason::Panic);
            } else {
                // We woke up because a handle was closed; ServiceUtil has taken
                // care of closing the signalled handle already, so just continue
                service.Erase(index);
            }
        } else if (result != RESULT_OK) {
            os.SVCBreak(thread, OS::BreakReason::Panic);
        } else {
            if (index == 0) {
                // ServerPort: Incoming client connection

                HandleTable::Entry<ServerSession> session;
                std::tie(result,session) = thread.CallSVC(&OS::SVCAcceptSession, *service.GetObject<ServerPort>(index));
                if (result != RESULT_OK) {
                    os.SVCBreak(thread, OS::BreakReason::Panic);
                }

                service.Append(session);
            } else {
                // server_session: Incoming IPC command from the indexed client
                logger.info("{}received IPC request", ThreadPrinter{thread});
                Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
                auto signalled_handle = service.handles[index];
                CommandHandler_gets(thread, header);
                last_signalled = signalled_handle;
            }
        }
    }
}

static OS::ResultAnd<IPC::MappedBuffer>
PTMGetStepHistory(FakeThread& thread, uint32_t num_hours, uint64_t start_time, IPC::MappedBuffer output) {
    if (num_hours * 2 != output.size) {
        throw Mikage::Exceptions::Invalid("PTMGetStepHistory: Buffer size does not match the size needed for the requested number of hours");
    }

    for (uint32_t hour = 0; hour < num_hours; ++hour) {
        thread.WriteMemory(output.addr + 2 * hour, 0);
        thread.WriteMemory(output.addr + 2 * hour + 1, 0);
    }

    return OS::ResultAnd<IPC::MappedBuffer> { RESULT_OK, output };
}

void FakePTM::CommandHandler(FakeThread& thread, const IPC::CommandHeader& header) try {
    using RegisterAlarmClient = IPC::IPCCommand<0x1>::add_handle<IPC::HandleType::Event>::response;

    using GetStepHistory = IPC::IPCCommand<0xb>::add_uint32::add_uint64::add_buffer_mapping_write::response::add_buffer_mapping_write;

    using GetTotalStepCount = IPC::IPCCommand<0xc>::response::add_uint32;

    switch (header.command_id) {
    case RegisterAlarmClient::id:
        // TODO
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case GetStepHistory::id:
        IPC::HandleIPCCommand<GetStepHistory>(PTMGetStepHistory, thread, thread);
        break;

    case GetTotalStepCount::id:
    {
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0); // No steps
        break;
    }

    case 0x409: // RebootAsync
    {
        logger.info("{}received RebootAsync: Stub", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    case 0x40a: // CheckNew3DS
    {
        logger.info("{}received CheckNew3DS: Stub", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0); // Old3DS
        break;
    }

    case 0x805:
        logger.info("{}received ClearStepHistory: Stub", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case 0x807: // GetPlayHistory
        logger.info("{}received GetPlayHistory: Stub", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 3, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case 0x808: // GetPlayHistoryStart
    {
        logger.info("{}received GetPlayHistoryStart: Stub", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 3, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0); // No steps
        thread.WriteTLS(0x8C, 0); // No steps
        break;
    }

    case 0x809: // GetPlayHistoryLength
    {
        logger.info("{}received GetPlayHistoryLength: Stub", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 3, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0); // No steps
        thread.WriteTLS(0x8C, 0); // No steps
        break;
    }

    case 0x80a:
        logger.info("{}received ClearPlayHistory: Stub", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case 0x80c:
    {
        logger.info("{}received SetUserTime: Stub", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    case 0x80e:
    {
        logger.info("{}received NotifyPlayEvent: Stub", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    // Used by menu
    case 0x80f:
    {
        logger.info("{}received GetSoftwareClosedFlag: Stub", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0); // Not closed
        break;
    }

    // Used by menu
    case 0x810:
    {
        logger.info("{}received ClearSoftwareClosedFlag: Stub", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    // Used by the MCU module
    case (0x08110000 >> 16): // GetShellStatus
        logger.info("{}received GetShellStatus: Stub", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 1); // Yes, the shell is open
        break;

    case 0x818: // ConfigureNew3DSCPU
    {
        logger.info("{}received ConfigureNew3DSCPU: Stub", ThreadPrinter{thread});

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    default:
        throw IPC::IPCError{header.raw, 0xdeadbeef};
    }
} catch (const IPC::IPCError& err) {
    throw std::runtime_error(fmt::format("Unknown PTM command request with header {:#010x}", err.header));
}

void FakePTM::CommandHandler_gets(FakeThread& thread, const IPC::CommandHeader& header) {
    using GetSystemTime = IPC::IPCCommand<0x401>::response::add_uint64;

    switch (header.command_id) {
    case GetSystemTime::id:
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 3, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0);
        thread.WriteTLS(0x8c, 0);
        break;

    default: // May be a ptm:u command
        FakePTM::CommandHandler(thread, header);
        break;
    }
}

}  // namespace OS

}  // namespace HLE
