#include "ac.hpp"

#include <platform/ac.hpp>
#include <platform/sm.hpp>
#include <platform/config.hpp>

#include <framework/exceptions.hpp>

namespace HLE {

namespace OS {

struct FakeAC {
    FakeAC(FakeThread& thread);

    Handle cfg_session;

    IPC::StaticBuffer ipc_buffer;

    // // Last NetworkSetting loaded from config
    // std::vector<uint8_t> network_setting;
    VAddr network_setting_addr = 0;

    Handle status_change_event;
};

static OS::ResultAnd<IPC::StaticBuffer> ACCreateDefaultConfig(FakeThread& thread, FakeAC&, IPC::StaticBuffer output) {
    // Return default config as created by LLE ac
    for (uint32_t off = 0; off < output.size; ++off) {
        VAddr addr = output.addr + off;
        if (off == 0) {
            thread.WriteMemory(addr, 0xbf);
        } else if (off >= 8 && off < 14){
            thread.WriteMemory(addr, 0xff);
        } else {
            thread.WriteMemory(addr, 0);
        }
    }

    return std::make_tuple(RESULT_OK, output);
}

static OS::ResultAnd<IPC::StaticBuffer> ACUnknown_0x22(FakeThread& thread, FakeAC&, uint32_t value, IPC::StaticBuffer input) {
    thread.WriteMemory(input.addr, value & 0xff);
    return std::make_tuple(RESULT_OK, input);
}

static OS::ResultAnd<IPC::StaticBuffer> ACUnknown_Ignore(FakeThread&, FakeAC&, uint32_t value, IPC::StaticBuffer input) {
    // Placeholder for NetworkSetting setters that we ignore for now
    return std::make_tuple(RESULT_OK, input);
}

static OS::ResultAnd<IPC::StaticBuffer> ACUnknown_Ignore2(FakeThread&, FakeAC&, uint32_t value, uint32_t value2, IPC::StaticBuffer input) {
    // Placeholder for NetworkSetting setters that we ignore for now
    return std::make_tuple(RESULT_OK, input);
}

static OS::ResultAnd<Handle> ACGetStatusChangeEvent(FakeThread&, FakeAC& ac, ProcessId) {
    // Placeholder for NetworkSetting setters that we ignore for now
    return std::make_tuple(RESULT_OK, ac.status_change_event);
}

// TODO: Drop global state
static bool connected = false;

static auto ACUCommandHandler(FakeThread& thread, FakeAC& ac, std::string_view service_name, const IPC::CommandHeader& header) {
    using namespace Platform::AC;

    switch (header.command_id) {
    case CreateDefaultConfig::id:
        IPC::HandleIPCCommand<CreateDefaultConfig>(ACCreateDefaultConfig, thread, thread, ac, ac.ipc_buffer);
        break;

    case ConnectAsync::id:
    {
        Handle app_event = Handle {thread.ReadTLS(0x90)};

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);

        // TODO: Signal incoming event?
        connected = true;

        thread.CallSVC(&OS::SVCSignalEvent, ac.status_change_event);
        thread.CallSVC(&OS::SVCSignalEvent, app_event);

        break;
    }

    case 0x5: // GetConnectResult
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case CancelConnectAsync::id:
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case 0x8: // CloseAsync
    {
        Handle app_event = Handle {thread.ReadTLS(0x90)};

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);

        thread.CallSVC(&OS::SVCSignalEvent, app_event);
        break;
    }

    case 0x9: // GetCloseResult
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case 0xA: // GetLastErrorCode
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0);
        break;

    case GetConnectStatus::id:
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, 0);
        thread.WriteTLS(0x88, connected ? 3 : 1);
        break;

    case GetWifiStatus::id:
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, 0);
        thread.WriteTLS(0x88, 1); // wifi enabled (using the first configuration slot)
        // thread.WriteTLS(0x84, 0xe0a09d2e); // Indicate the hardware wifi switch is off
        // thread.WriteTLS(0x88, 0); // No wifi
        break;

    case 0xE: // GetCurrentAPInfo
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case 0xF: // GetConnectingInfraPriority
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0);
        break;

    case 0x13: // GetConnectingHotspotSubset
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    // Connect to access point test? Seems to prepare results for command 0x16?
    case Unknown_ViaConnectTest::id:
    {
        auto event_handle = Handle { thread.ReadTLS(0x90) };
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);

        thread.CallSVC(&OS::OS::SVCSignalEvent, event_handle);
        thread.CallSVC(&OS::OS::SVCCloseHandle, event_handle);
        break;
    }

    case Unknown_0x16::id: // GetExclusiveResult
    {
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    case Unknown_0x19::id: // CloseAllAsync
    {
        auto event_handle = Handle { thread.ReadTLS(0x90) };
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);

        thread.CallSVC(&OS::OS::SVCSignalEvent, event_handle);
        thread.CallSVC(&OS::OS::SVCCloseHandle, event_handle);
        break;
    }

    case Unknown_0x1a::id: // GetCloseAllResult
    {
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    case Unknown_0x22::id:
        IPC::HandleIPCCommand<Unknown_0x22>(ACUnknown_0x22, thread, thread, ac);
        break;

    case Unknown_0x25::id:
        IPC::HandleIPCCommand<Unknown_0x25>(ACUnknown_Ignore, thread, thread, ac);
        break;

    case SetInfraPriority::id:
        IPC::HandleIPCCommand<SetInfraPriority>(ACUnknown_Ignore, thread, thread, ac);
        break;

    case GetInfraPriority::id:
        // TODO: Should read from provided NetworkSettings instead
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0);
        break;

    case SetRequestEulaVersion::id:
        IPC::HandleIPCCommand<SetRequestEulaVersion>(ACUnknown_Ignore2, thread, thread, ac);
        break;

    case GetNZoneBeaconNotFoundEvent::id:
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case 0x30: // RegisterDisconnectEvent
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case GetStatusChangeEvent::id:
        IPC::HandleIPCCommand<GetStatusChangeEvent>(ACGetStatusChangeEvent, thread, thread, ac);
        break;

    case 0x3E: // IsConnected
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, connected);
        break;

    case SetClientVersion::id: // SetClientVersion
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    default:
        throw Mikage::Exceptions::NotImplemented("Unknown {} service command with header {:#010x}", service_name, header.raw);
    }

    return ServiceHelper::SendReply;
}

auto ACICommandHandler(FakeThread& thread, FakeAC& context, const IPC::CommandHeader& header) {
    // Signature confirmed
    // First parameter is connection slot? (0-2)
    using LoadNetworkSetting = IPC::IPCCommand<0x401>::add_uint32::response;

    using RemoveNetworkSetting = IPC::IPCCommand<0x403>::add_uint32::response;
    using FlushNetworkSetting = IPC::IPCCommand<0x404>::add_uint32::response;
    using InitializeNetworkSetting = IPC::IPCCommand<0x406>::add_uint32::response;

    // Signature confirmed
    using GetNetworkSettingVersion = IPC::IPCCommand<0x407>::response::add_uint32::add_uint32;

    /**
     * Returns the CRC field of the previously loaded NetworkSetting.
     *
     * NOTE: It's a 16-bit CRC, so the upper two bytes are zero.
     */
    using GetNetworkSettingCRC = IPC::IPCCommand<0x409>::response::add_uint32;

    switch (header.command_id) {
    case LoadNetworkSetting::id:
    {
        // NOTE: If no connection is registered in config data, an error should be returned here
        auto slot = thread.ReadTLS(0x84) & 0xff;

        auto [result, _] = IPC::SendIPCRequest<Platform::Config::GetConfigInfoBlk8>(
                thread, context.cfg_session, sizeof(Platform::AC::NetworkSetting), 0x80000 + slot,
                IPC::MappedBuffer { context.network_setting_addr, sizeof(Platform::AC::NetworkSetting) });

        if (result != RESULT_OK || thread.ReadMemory32(context.network_setting_addr) >> 16 == 0) {
            thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
            thread.WriteTLS(0x84, 0xc9609f25);
            break;
        }

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, 0);
        break;
    }

    case RemoveNetworkSetting::id:
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case FlushNetworkSetting::id:
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case InitializeNetworkSetting::id:
        // NOTE: Unknown parameter, maybe connection slot (1-3)? (upper bytes ignored)
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    case GetNetworkSettingVersion::id:
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 3, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0);
        thread.WriteTLS(0x8c, 1);
        break;

    case GetNetworkSettingCRC::id:
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, thread.ReadMemory32(context.network_setting_addr) >> 16 );
        break;

    case 0x40b: // WirelessEnable
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 1); // TODO: Read from config instead
        break;

    default:
        if (header.command_id > 0x406) {
            thread.WriteTLS(0x80, IPC::CommandHeader::Make(0, 3, 0).raw);
            thread.WriteTLS(0x84, RESULT_OK);
            thread.WriteTLS(0x88, 0);
            thread.WriteTLS(0x8c, 0);
            break;
        }
        return ACUCommandHandler(thread, context, "ac:i", header);
    }

    return ServiceHelper::SendReply;
}

static void MainThread(FakeAC& context, FakeThread& thread) {
    ServiceHelper service;
    service.Append(ServiceUtil::SetupService(thread, "ac:u", 10));
    auto aci_index = service.Append(ServiceUtil::SetupService(thread, "ac:i", 10));

    context.ipc_buffer = { thread.GetParentProcess().AllocateStaticBuffer(0x200), 0x200, 0 },
    thread.WriteTLS(0x180, IPC::TranslationDescriptor::MakeStaticBuffer(0, 0x200).raw);
    thread.WriteTLS(0x184, context.ipc_buffer.addr);

    thread.WriteTLS(0x188, IPC::TranslationDescriptor::MakeStaticBuffer(0, 0x200).raw);
    thread.WriteTLS(0x18c, thread.GetParentProcess().AllocateStaticBuffer(0x200));

    auto InvokeCommandHandler = [&](FakeThread& thread, uint32_t signalled_handle_index) {
        Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
        if (signalled_handle_index == aci_index) {
            return ACICommandHandler(thread, context, header);
        } else {
            return ACUCommandHandler(thread, context, "ac:u", header);
        }
    };

    service.Run(thread, std::move(InvokeCommandHandler));
}


FakeAC::FakeAC(FakeThread& thread) {
    thread.name = "ACUThread";

    Result result;
    {
        HandleTable::Entry<Event> status_change_event_entry;
        std::tie(result, status_change_event_entry) = thread.CallSVC(&OS::SVCCreateEvent, ResetType::OneShot);
        status_change_event = status_change_event_entry.first;
    }

    std::tie(result, network_setting_addr) = thread.CallSVC(&OS::SVCControlMemory, 0, 0, sizeof(Platform::AC::NetworkSetting), 3/*ALLOC*/, 0x3/*RW*/);
    {
        auto [result2, srv_session] = thread.CallSVC(&OS::OS::SVCConnectToPort, "srv:");
        if (result2 != RESULT_OK)
            thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);

        IPC::SendIPCRequest<Platform::SM::SRV::RegisterClient>(thread, srv_session.first, IPC::EmptyValue{});

        cfg_session = IPC::SendIPCRequest<Platform::SM::SRV::GetServiceHandle>(thread, srv_session.first,
                                                                              Platform::SM::PortName("cfg:s"), 0);

        thread.CallSVC(&OS::OS::SVCCloseHandle, srv_session.first);
    }

    MainThread(*this, thread);
}

template<> std::shared_ptr<WrappedFakeProcess> CreateFakeProcessViaContext<FakeAC>(OS& os, Interpreter::Setup& setup, uint32_t pid, const std::string& name) {
    return WrappedFakeProcess::CreateWithContext<FakeAC>(os, setup, pid, name);
}

} // namespace OS

} // namespace HLE
