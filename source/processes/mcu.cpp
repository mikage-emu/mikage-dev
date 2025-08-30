#include "mcu.hpp"
#include "os.hpp"

#include "../platform/mcu.hpp"

#include <memory>

namespace HLE {

namespace OS {

FakeMCU::FakeMCU(FakeThread& thread)
    : logger(*thread.GetLogger()) {

    thread.name = "MCUMainThread";

    OS::Result result;

    std::tie(result,gpu_event) = thread.CallSVC(&OS::SVCCreateEvent, ResetType::OneShot);
    if (result != RESULT_OK)
        thread.CallSVC(&OS::SVCBreak, OS::BreakReason::Panic);
    gpu_event.second->name = "mcu::GPUEvent";

    std::tie(result,hid_event) = thread.CallSVC(&OS::SVCCreateEvent, ResetType::OneShot);
    if (result != RESULT_OK)
        thread.CallSVC(&OS::SVCBreak, OS::BreakReason::Panic);
    hid_event.second->name = "mcu::HIDEvent";

    {
        auto hid_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(),
                                                              [this](FakeThread& thread) { return HIDThread(thread); });
        hid_thread->name = "MCUHIDThread";
        thread.GetParentProcess().AttachThread(hid_thread);
    }

    {
        auto pls_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(),
                                                              [this](FakeThread& thread) { return PLSThread(thread); });
        pls_thread->name = "MCUPLSThread";
        thread.GetParentProcess().AttachThread(pls_thread);
    }

    GPUThread(thread);
}

void FakeMCU::GPUThread(FakeThread& thread) {
    ServiceUtil service(thread, "mcu::GPU", 1);

    Handle last_signalled = HANDLE_INVALID;

    for (;;) {
        OS::Result result;
        int32_t index;
        std::tie(result,index) = service.ReplyAndReceive(thread, last_signalled);
        last_signalled = HANDLE_INVALID;
        if (result != RESULT_OK)
            thread.CallSVC(&OS::SVCBreak, OS::BreakReason::Panic);

        if (index == 0) {
            // ServerPort: Incoming client connection

            int32_t session_index;
            std::tie(result,session_index) = service.AcceptSession(thread, index);
            if (result != RESULT_OK) {
                auto session = service.GetObject<ServerSession>(session_index);
                if (!session) {
                    logger.error("{}Failed to accept session.", ThreadPrinter{thread});
                    thread.CallSVC(&OS::SVCBreak, OS::BreakReason::Panic);
                }

                auto session_handle = service.GetHandle(session_index);
                logger.warn("{}Failed to accept session. Maximal number of sessions exhausted? Closing session handle {}",
                            ThreadPrinter{thread}, HandlePrinter{thread,session_handle});
                thread.CallSVC(&OS::SVCCloseHandle, session_handle);
            }
        } else {
            // server_session: Incoming IPC command from the indexed client
            logger.info("{}received IPC request", ThreadPrinter{thread});
            Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
            auto signalled_handle = service.GetHandle(index);
            GPUCommandHandler(thread, signalled_handle, header);
            last_signalled = signalled_handle;
        }
    }
}

void FakeMCU::HIDThread(FakeThread& thread) {
    ServiceUtil service(thread, "mcu::HID", 1);

    Handle last_signalled = HANDLE_INVALID;

    for (;;) {
        OS::Result result;
        int32_t index;
        std::tie(result,index) = service.ReplyAndReceive(thread, last_signalled);
        last_signalled = HANDLE_INVALID;
        if (result != RESULT_OK)
            thread.CallSVC(&OS::SVCBreak, OS::BreakReason::Panic);

        if (index == 0) {
            // ServerPort: Incoming client connection

            int32_t session_index;
            std::tie(result,session_index) = service.AcceptSession(thread, index);
            if (result != RESULT_OK) {
                auto session = service.GetObject<ServerSession>(session_index);
                if (!session) {
                    logger.error("{}Failed to accept session.", ThreadPrinter{thread});
                    thread.CallSVC(&OS::SVCBreak, OS::BreakReason::Panic);
                }

                auto session_handle = service.GetHandle(session_index);
                logger.warn("{}Failed to accept session. Maximal number of sessions exhausted? Closing session handle {}",
                            ThreadPrinter{thread}, HandlePrinter{thread,session_handle});
                thread.CallSVC(&OS::SVCCloseHandle, session_handle);
            }
        } else {
            // server_session: Incoming IPC command from the indexed client
            logger.info("{}received IPC request", ThreadPrinter{thread});
            Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
            auto signalled_handle = service.GetHandle(index);
            HIDCommandHandler(thread, signalled_handle, header);
            last_signalled = signalled_handle;
        }
    }
}
static auto PLSCommandHandler(FakeThread& thread, const IPC::CommandHeader& header, Handle /*signalled_handle*/) try {
    switch (header.command_id) {
    case 1: // GetDatetime
        // Returns the I2C device 3 registers 0x30-0x36 converted to decimal
        // TODO: What's the correct byte order?
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 3, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0);
        thread.WriteTLS(0x8c, 0);
        break;

    case 9: // GetTickCounter (16 bit)
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0);
        break;

    default:
        throw IPC::IPCError { header.raw, 0xdeadbeef };
    }

    return ServiceHelper::SendReply;
} catch (const IPC::IPCError& err) {
    throw std::runtime_error(fmt::format("Unknown mcu::PLS service command with header {:#010x}", err.header));
}

void FakeMCU::PLSThread(FakeThread& thread) {
    ServiceHelper service;
    service.Append(ServiceUtil::SetupService(thread, "mcu::PLS", 1));

    auto InvokeCommandHandler = [&](FakeThread& thread, uint32_t signalled_handle_index) {
        Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
        return PLSCommandHandler(thread, header, service.handles[signalled_handle_index]);
    };

    service.Run(thread, std::move(InvokeCommandHandler));
}


template<typename Class, typename Func>
static auto BindMemFn(Func f, Class* c) {
    return [f,c](auto&&... args) { return std::mem_fn(f)(c, args...); };
}

void FakeMCU::GPUCommandHandler(FakeThread& thread, Handle sender, const IPC::CommandHeader& header) try {
    using namespace Platform::MCU::GPU;

    switch (header.command_id) {
    case GetLcdPowerState::id:
        return IPC::HandleIPCCommand<GetLcdPowerState>(BindMemFn(&FakeMCU::GPUGetLcdPowerState, this), thread, thread);

    case SetLcdPowerState::id:
        return IPC::HandleIPCCommand<SetLcdPowerState>(BindMemFn(&FakeMCU::GPUSetLcdPowerState, this), thread, thread);

    case GetGpuLcdInterfaceState::id:
        return IPC::HandleIPCCommand<GetGpuLcdInterfaceState>(BindMemFn(&FakeMCU::GPUGetGpuLcdInterfaceState, this), thread, thread);

    case SetGpuLcdInterfaceState::id:
        return IPC::HandleIPCCommand<SetGpuLcdInterfaceState>(BindMemFn(&FakeMCU::GPUSetGpuLcdInterfaceState, this), thread, thread);

    case GetMcuFwVerHigh::id:
        return IPC::HandleIPCCommand<GetMcuFwVerHigh>(BindMemFn(&FakeMCU::GPUGetMcuFwVerHigh, this), thread, thread);

    case GetMcuFwVerLow::id:
        return IPC::HandleIPCCommand<GetMcuFwVerLow>(BindMemFn(&FakeMCU::GPUGetMcuFwVerLow, this), thread, thread);

    case Set3dLedState::id:
        return IPC::HandleIPCCommand<Set3dLedState>(BindMemFn(&FakeMCU::GPUSet3dLedState, this), thread, thread);

    case GetMcuGpuEvent::id:
        return IPC::HandleIPCCommand<GetMcuGpuEvent>(BindMemFn(&FakeMCU::GPUGetMcuGpuEvent, this), thread, thread);

    case GetMcuGpuEventReason::id:
        return IPC::HandleIPCCommand<GetMcuGpuEventReason>(BindMemFn(&FakeMCU::GPUGetMcuGpuEventReason, this), thread, thread);

    default:
        throw IPC::IPCError{header.raw, 0xdeadbeef};
    }
} catch (IPC::IPCError& err) {
    throw std::runtime_error(fmt::format("Unknown mcu::GPU command request with header {:#010x}", err.header));
}

void FakeMCU::HIDCommandHandler(FakeThread& thread, Handle sender, const IPC::CommandHeader& header) try {
    using namespace Platform::MCU::HID;

    switch (header.command_id) {
    case Unknown0x1::id:
        return IPC::HandleIPCCommand<Unknown0x1>(BindMemFn(&FakeMCU::HIDUnknown0x1, this), thread, thread);

    case GetMcuHidEventHandle::id:
        return IPC::HandleIPCCommand<GetMcuHidEventHandle>(BindMemFn(&FakeMCU::HIDGetMcuHidEventHandle, this), thread, thread);

    case Get3dSliderState::id:
        return IPC::HandleIPCCommand<Get3dSliderState>(BindMemFn(&FakeMCU::HIDGet3dSliderState, this), thread, thread);

    case SetAccelerometerState::id:
        return IPC::HandleIPCCommand<SetAccelerometerState>(BindMemFn(&FakeMCU::HIDSetAccelerometerState, this), thread, thread);
    default:
        throw IPC::IPCError{header.raw, 0xdeadbeef};
    }
} catch (const IPC::IPCError& err) {
        throw std::runtime_error(fmt::format("Unknown mcu::HID command request with header {:#010x}", err.header));
}

OS::ResultAnd<uint32_t, uint32_t> FakeMCU::GPUGetLcdPowerState(FakeThread& thread) {
    logger.info("{}received GetLcdPowerState", ThreadPrinter{thread});
    return std::make_tuple(RESULT_OK, uint32_t{0}, uint32_t{0});
}

OS::ResultAnd<> FakeMCU::GPUSetLcdPowerState(FakeThread& thread, uint32_t param1, uint32_t param2) {
    logger.info("{}received SetLcdPowerState, param1={:#010x}, param2={:#010x}",
                ThreadPrinter{thread}, param1, param2);
    return std::make_tuple(RESULT_OK);
}

OS::ResultAnd<uint32_t> FakeMCU::GPUGetGpuLcdInterfaceState(FakeThread& thread) {
    logger.info("{}received GetGpuLcdInterfaceState", ThreadPrinter{thread});
    return std::make_tuple(RESULT_OK, uint32_t{0});
}

OS::ResultAnd<> FakeMCU::GPUSetGpuLcdInterfaceState(FakeThread& thread, uint32_t state) {
    logger.info("{}received SetGpuLcdInterfaceState, state={:#010x}", ThreadPrinter{thread}, state);
    return std::make_tuple(RESULT_OK);
}

OS::ResultAnd<uint32_t> FakeMCU::GPUGetMcuFwVerHigh(FakeThread& thread) {
    logger.info("{}received GetMcuFwVerHigh", ThreadPrinter{thread});
    return std::make_tuple(RESULT_OK, uint32_t{/*0x4000*/2});
}

OS::ResultAnd<uint32_t> FakeMCU::GPUGetMcuFwVerLow(FakeThread& thread) {
    logger.info("{}received GetMcuFwVerLow", ThreadPrinter{thread});
    return std::make_tuple(RESULT_OK, uint32_t{/*0x4000*/0x26});
}

OS::ResultAnd<> FakeMCU::GPUSet3dLedState(FakeThread& thread, uint32_t state) {
    logger.info("{}received Set3dLedState: state={:#x}", ThreadPrinter{thread}, state);
    return std::make_tuple(RESULT_OK);
}

OS::ResultAnd<Handle> FakeMCU::GPUGetMcuGpuEvent(FakeThread& thread) {
    logger.info("{}received GetMcuGpuEvent", ThreadPrinter{thread});

    // let's immediately signal the event. GSP seems to use it to detect whether the GPU is ready?
    // TODO: Race condition right here! We may be signalling this event too early
    gpu_event.second->SignalEvent();
    return std::make_tuple(RESULT_OK, gpu_event.first);
}

OS::ResultAnd<uint32_t> FakeMCU::GPUGetMcuGpuEventReason(FakeThread& thread) {
    logger.info("{}received GetMcuGpuEventReason", ThreadPrinter{thread});

    // TODO: This is just some stub code to make the GSP module work properly
    //       without an actual MCU implementation.
    uint32_t event_reason = 0;
    if (invocation == 0) {
        // LCD turned on
        event_reason = 0x02000000;
        gpu_event.second->SignalEvent();
    } else if (invocation == 1) {
        // LCD backlight turned on (both top and bottom screens).
        // GSP expects both of these to be signaled simultaneously
        event_reason = 0x28000000;
    } else {
        throw std::runtime_error("Cannot request more than two reasons");
        event_reason = 0;
    }
    ++invocation;

    return std::make_tuple(RESULT_OK, event_reason);
}

OS::ResultAnd<> FakeMCU::HIDUnknown0x1(FakeThread& thread, uint32_t param) {
    logger.info("{}received Unknown0x1, param={:#010x}", ThreadPrinter{thread}, param);
    return std::make_tuple(RESULT_OK);
}

OS::ResultAnd<Handle> FakeMCU::HIDGetMcuHidEventHandle(FakeThread& thread) {
    logger.info("{}received GetMcuHidEventHandle", ThreadPrinter{thread});

    // Let's immediately signal the event.
    // TODO: Remove this code and implement this module properly instead!
    // TODO: At least, we should call SVCSignalEvent here...
    hid_event.second->SignalEvent();

    return std::make_tuple(RESULT_OK, hid_event.first);
}

OS::ResultAnd<uint32_t> FakeMCU::HIDGet3dSliderState(FakeThread& thread) {
    logger.info("{}received Get3dSliderState", ThreadPrinter{thread});

    // Not sure what format this is in. HID exposes floats, but it seems unlikely that this is the actual hardware representation
    // TODO: Actually read this from I2C device 3
    return std::make_tuple(RESULT_OK, uint32_t{0});
}

OS::ResultAnd<> FakeMCU::HIDSetAccelerometerState(FakeThread& thread, uint32_t state) {
    logger.info("{}received SetAccelerometerState (state={:#x})",
                ThreadPrinter{thread}, state);

    return std::make_tuple(RESULT_OK);
}

}  // namespace OS

}  // namespace HLE
