#include "nwm.hpp"
#include "fake_process.hpp"

#include <framework/exceptions.hpp>

namespace HLE {

namespace OS {

static OS::ResultAnd<IPC::StaticBuffer> HandleGetMacAddress(FakeNWM& context, Thread& thread, uint32_t size) {
    if (size != 6) {
        throw Mikage::Exceptions::Invalid("Invalid MAC address size");
    }

    thread.WriteMemory(context.soc_static_buffer.addr, 0xb0);
    thread.WriteMemory(context.soc_static_buffer.addr + 1, 0xb1);
    thread.WriteMemory(context.soc_static_buffer.addr + 2, 0xb2);
    thread.WriteMemory(context.soc_static_buffer.addr + 3, 0xb3);
    thread.WriteMemory(context.soc_static_buffer.addr + 4, 0xb4);
    thread.WriteMemory(context.soc_static_buffer.addr + 5, 0xb5);

    return std::make_tuple( RESULT_OK, context.soc_static_buffer);
}

static OS::ResultAnd<uint32_t, std::array<Handle, 2>> HandleUnknown0x9(FakeNWM& context) {
    return std::make_tuple( RESULT_OK, context.shared_mem_size,
                            std::array<Handle, 2> { context.shared_memory.first, context.shared_memory_event.first });
}

static auto SOCCommandHandler(FakeNWM& context, FakeThread& thread, Platform::IPC::CommandHeader header) try {
    using GetMacAddress = IPC::IPCCommand<0x8>::add_uint32::response::add_static_buffer;
    using Unknown_0x9 = IPC::IPCCommand<0x9>::response::add_uint32::add_handles<IPC::HandleType::Object, 2>;

    switch (header.command_id) {
    case GetMacAddress::id:
        IPC::HandleIPCCommand<GetMacAddress>(HandleGetMacAddress, thread, context, thread);
        break;

    case 0x9: // Unknown, no parameters
        IPC::HandleIPCCommand<Unknown_0x9>(HandleUnknown0x9, thread, context);
        break;

    default:
        throw IPC::IPCError{header.raw, 0xdeadbeef};
    }

    return ServiceHelper::SendReply;
} catch (const IPC::IPCError& err) {
    throw std::runtime_error(fmt::format("Unknown nwm::SOC service command with header {:#010x}", err.header));
}

static auto EXTCommandHandler(FakeNWM& context, FakeThread& thread, Platform::IPC::CommandHeader header) try {
    switch (header.command_id) {
    default:
        throw IPC::IPCError{header.raw, 0xdeadbeef};
    }

    return ServiceHelper::SendReply;
} catch (const IPC::IPCError& err) {
    throw std::runtime_error(fmt::format("Unknown nwm::EXT service command with header {:#010x}", err.header));
}

static auto INFCommandHandler(FakeNWM& context, FakeThread& thread, Platform::IPC::CommandHeader header) try {
    switch (header.command_id) {
    case 0x3: // Unknown, no parameters
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case 0x4: // Unknown, no parameters
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case 0x5: // Unknown, no parameters
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case 0x6: // Unknown
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    default:
        throw IPC::IPCError{header.raw, 0xdeadbeef};
    }

    return ServiceHelper::SendReply;
} catch (const IPC::IPCError& err) {
    throw std::runtime_error(fmt::format("Unknown nwm::INF service command with header {:#010x}", err.header));
}

template<typename Handler>
static void IPCThread(FakeNWM& context, FakeThread& thread, const char* service_name, Handler&& handler) {
    // TODO: How many parallel sessions should we support?
    ServiceHelper service;
    service.Append(ServiceUtil::SetupService(thread, service_name, /*1*/3));

    auto InvokeCommandHandler = [&](FakeThread& thread, uint32_t index) {
        Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
        return handler(context, thread, header);
    };

    service.Run(thread, std::move(InvokeCommandHandler));
}

FakeNWM::FakeNWM(FakeThread& thread) {
    thread.name = "NWMThread";

    {
        soc_static_buffer = { thread.GetParentProcess().AllocateStaticBuffer(0x6), 0x6, 0 };

        Result result;

        std::tie(result, shared_mem_vaddr) = thread.CallSVC(&OS::SVCControlMemory, 0, 0, shared_mem_size, 3/*ALLOC*/, 0x3/*RW*/);
        if (result != RESULT_OK) {
            throw std::runtime_error("Failed to allocate NWM shared memory");
        }

        std::tie(result,shared_memory) = thread.CallSVC(&OS::SVCCreateMemoryBlock, shared_mem_vaddr, shared_mem_size, 0x3/*RW*/, 0x3/*RW*/);
        if (result != RESULT_OK) {
            throw std::runtime_error("Failed to create NWM shared memory block");
        }

        std::tie(result,shared_memory_event) = thread.CallSVC(&OS::SVCCreateEvent, ResetType::OneShot);
        if (result != RESULT_OK) {
            throw std::runtime_error("Failed to create NWM shared memory event");
        }

        auto new_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(), [this](FakeThread& thread) { return IPCThread(*this, thread, "nwm::SOC", SOCCommandHandler); });
        new_thread->name = "nwm::SOCThread";
        thread.GetParentProcess().AttachThread(new_thread);
    }

    {
        auto new_thread = std::make_shared<WrappedFakeThread>(thread.GetParentProcess(), [this](FakeThread& thread) { return IPCThread(*this, thread, "nwm::EXT", EXTCommandHandler); });
        new_thread->name = "nwm::EXTThread";
        thread.GetParentProcess().AttachThread(new_thread);
    }

    IPCThread(*this, thread, "nwm::INF", INFCommandHandler);
}

}  // namespace OS

}  // namespace HLE
