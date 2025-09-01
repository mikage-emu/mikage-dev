#pragma once

#include "fake_process.hpp"

namespace HLE {

namespace OS {

struct Handle;

class FakeMCU {
    spdlog::logger& logger;

    HandleTable::Entry<Event> gpu_event;
    HandleTable::Entry<Event> hid_event;

    int invocation = 0;

public:
    FakeMCU(FakeThread& thread);
    virtual ~FakeMCU() = default;

    void GPUThread(FakeThread& thread);
    void HIDThread(FakeThread& thread);
    void PLSThread(FakeThread& thread);

    void GPUCommandHandler(FakeThread& thread, Handle sender, const IPC::CommandHeader& header);
    void HIDCommandHandler(FakeThread& thread, Handle sender, const IPC::CommandHeader& header);

    OS::ResultAnd<uint32_t, uint32_t> GPUGetLcdPowerState(FakeThread& thread);
    OS::ResultAnd<> GPUSetLcdPowerState(FakeThread& thread, uint32_t param1, uint32_t param2);
    OS::ResultAnd<uint32_t> GPUGetGpuLcdInterfaceState(FakeThread& thread);
    OS::ResultAnd<> GPUSetGpuLcdInterfaceState(FakeThread& thread, uint32_t state);
    OS::ResultAnd<uint32_t> GPUGetMcuFwVerHigh(FakeThread& thread);
    OS::ResultAnd<uint32_t> GPUGetMcuFwVerLow(FakeThread& thread);
    OS::ResultAnd<> GPUSet3dLedState(FakeThread& thread, uint32_t state);
    OS::ResultAnd<Handle> GPUGetMcuGpuEvent(FakeThread& thread);
    OS::ResultAnd<uint32_t> GPUGetMcuGpuEventReason(FakeThread& thread);

    OS::ResultAnd<> HIDUnknown0x1(FakeThread& thread, uint32_t param);
    OS::ResultAnd<Handle> HIDGetMcuHidEventHandle(FakeThread& thread);
    OS::ResultAnd<uint32_t> HIDGet3dSliderState(FakeThread& thread);
    OS::ResultAnd<> HIDSetAccelerometerState(FakeThread& thread, uint32_t state);
};

}  // namespace OS

}  // namespace HLE
