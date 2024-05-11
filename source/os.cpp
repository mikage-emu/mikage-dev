#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_OFF
#include "ipc.hpp"
#include "os.hpp"
#include "os_console.hpp"
#include "os_hypervisor.hpp"
#include "pica.hpp"
#include "video_core/src/video_core/vulkan/renderer.hpp" // TODO: Get rid of this


#include <framework/exceptions.hpp>
#include <framework/formats.hpp>
#include <framework/logging.hpp>
#include <framework/profiler.hpp>

#include "processes/am.hpp"
#include "processes/dsp.hpp"
#include "processes/hid.hpp"

#include "processes/errdisp.hpp"
#include "processes/fs.hpp"
#include "processes/gpio.hpp"
#include "processes/i2c.hpp"
#include "processes/mcu.hpp"
#include "processes/ns.hpp"
#include "processes/pdn.hpp"
#include "processes/ps.hpp"
#include "processes/ptm.hpp"
#include "processes/pxi.hpp"
#include "processes/pxi_fs.hpp"

#include "processes/act.hpp"
#include "processes/am.hpp"
#include "processes/cam.hpp"
#include "processes/cdc.hpp"
#include "processes/cecd.hpp"
#include "processes/csnd.hpp"
#include "processes/dlp.hpp"
#include "processes/dsp.hpp"
#include "processes/dummy.hpp"
#include "processes/friend.hpp"
#include "processes/hid.hpp"
#include "processes/http.hpp"
#include "processes/mic.hpp"
#include "processes/ndm.hpp"
#include "processes/nwm.hpp"
#include "processes/news.hpp"
#include "processes/pdn.hpp"
#include "processes/ssl.hpp"
#include "processes/soc.hpp"


#include "platform/ns.hpp"
#include "platform/sm.hpp"

#include "platform/file_formats/ncch.hpp"

#include "framework/meta_tools.hpp"
#include "framework/bit_field_new.hpp"

#include <iostream>

#include <tracy/Tracy.hpp>
#include <tracy/TracyC.h>

#include <spdlog/spdlog.h>

#include <boost/endian/arithmetic.hpp>

#include <boost/hana/functional/fix.hpp>
#include <boost/hana/fold.hpp>

#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/range/adaptor/sliced.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/algorithm/copy.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include <boost/range/algorithm/nth_element.hpp>
#include <boost/range/numeric.hpp>

#include <boost/scope_exit.hpp>

#include <range/v3/algorithm/all_of.hpp>
#include <range/v3/algorithm/copy.hpp>
#include <range/v3/algorithm/equal.hpp>
#include <range/v3/algorithm/find_if.hpp>
#include <range/v3/algorithm/lower_bound.hpp>
#include <range/v3/algorithm/search.hpp>
#include <range/v3/algorithm/transform.hpp>
#include <range/v3/iterator/insert_iterators.hpp>
#include <range/v3/numeric/accumulate.hpp>
#include <range/v3/range_for.hpp>
#include <range/v3/view/chunk.hpp>
#include <range/v3/view/filter.hpp>
#include <range/v3/view/iota.hpp>
#include <range/v3/view/map.hpp>
#include <range/v3/view/transform.hpp>
#include <range/v3/view/reverse.hpp>

#include <iomanip>
#include <memory>
#include <sstream>


#include <teakra/teakra.h>


extern Teakra::Teakra* g_teakra;
extern bool g_dsp_running; // TODO: Remove
extern bool g_dsp_just_reset; // TODO: Remove


namespace HLE {

namespace OS {

std::ostream& operator<<(std::ostream& os, const ProcessPrinter& printer) {
    os << printer.process.GetName();
    os << " (id " << std::dec << printer.process.GetId() << ")";
    return os;
}

std::ostream& operator<<(std::ostream& os, const ThreadPrinter& printer) {
    os << ProcessPrinter{printer.thread.GetParentProcess()};
    if (auto emuthread = dynamic_cast<EmuThread*>(&printer.thread)) {
        os << ", thread " << std::dec << printer.thread.GetId();
    } else {
        os << ", " << GetThreadObjectName(printer.thread);
    }
    os << ": ";
    return os;
}

std::ostream& operator<<(std::ostream& os, const ObjectRefPrinter& printer) {
    os << "(" << printer.object.GetName() << "," << &printer.object << ")";
    return os;
}

std::ostream& operator<<(std::ostream& os, const ObjectPrinter& printer) {
    if (!printer.object_ptr) {
        os << "(InvalidObject," << printer.object_ptr << ")";
        return os;
    }

    auto& object = *printer.object_ptr;
    os << ObjectRefPrinter{object};
    return os;
}

std::ostream& operator<<(std::ostream& os, const HandlePrinter& printer) {
    auto object_ptr = printer.thread.GetProcessHandleTable().FindObject<Object>(printer.handle, true);
    if (object_ptr) {
        os << /*ObjectPrinter{object_ptr}*/ printer.handle.value << "(" << object_ptr->GetName() << ")";
    } else {
        os << "(unknown handle " << std::dec << printer.handle.value << ")";
    }
    return os;
}

/*class IdleThread : FakeThread {
    // TODO! Although, not sure if we actually need this thread.
};*/

// TODO: Get rid of this global...
Interpreter::ProcessorController* gdbstub = nullptr;

[[noreturn]] static void HandleOSThreadException(const std::runtime_error& err, Thread& thread) {
    auto emu_thread = dynamic_cast<EmuThread*>(&thread);
    if (emu_thread) {
        auto cpu = emu_thread->context->ToGenericContext();

        thread.GetLogger()->error(" ({} code at PC = {:#010x}, r0={:x}, r1={:x}, r2={:x}, r3={:x}, r4={:x}, r5={:x}, r6={:x}, r7={:x}, r8={:x}):\n{}",
                                  cpu.cpsr.thumb ? "Thumb" : "ARM", cpu.PC(), cpu.reg[0], cpu.reg[1], cpu.reg[2],
                                  cpu.reg[3], cpu.reg[4], cpu.reg[5], cpu.reg[6], cpu.reg[7], cpu.reg[8], err.what());
#if 0
        for (auto& callsite : emu_thread->context.backtrace | ranges::view::reverse)
            thread.GetLogger()->info("{}{:#010x} (via {:#010x}): r0={:#x}, r1={:#x}, r2={:#x}, r3={:#x}, r4={:#x}, r5={:#x}, r6={:#x}, r7={:#x}, r8={:#x}, sp={:#x}",
                                     ThreadPrinter{thread}, callsite.target, callsite.source, callsite.state.reg[0],
                                     callsite.state.reg[1], callsite.state.reg[2], callsite.state.reg[3], callsite.state.reg[4],
                                     callsite.state.reg[5], callsite.state.reg[6], callsite.state.reg[7], callsite.state.reg[8],
                                     callsite.state.reg[13]);
#endif
// TODO: Re-enable exception printing if gdbstub is active
//    } else {
//        thread.GetLogger()->error(" {}", err.what());
    }
    gdbstub->NotifySegfault(thread.GetParentProcess().GetId(), thread.GetId());

    throw;

    // TODO: Exit more gracefully? Could e.g. have something like gdbstub::WaitForDetach()
    while (true) {
        if (gdbstub->request_pause)
            gdbstub->paused = true;
    }
}

class CoroutineThreadControl : public ThreadControl {
public:
    template<typename F>
    CoroutineThreadControl(F&& f) : coroutine {
        // Choose a stack size suitable to handle GSP (which is the biggest stack consumer due to use of the host GPU driver)
        boost::coroutines2::fixedsize_stack(1024*256),
        [this, f2=std::forward<F>(f)](boost::coroutines2::coroutine<void>::pull_type& scheduler) mutable {
            coroutine_yield = &scheduler;
            std::forward<F>(f2)();
        } } {
    }

    void YieldToScheduler() override {
        (*coroutine_yield)();
    }

    void ResumeFromScheduler() override {
        // TODO: This extra check shouldn't be needed, but is currently
        //       required for OS to shut down properly after a FakeThread threw
        //       an exception
        if (coroutine) {
            coroutine();
        }
    }

    boost::coroutines2::coroutine<void>::push_type coroutine;
    boost::coroutines2::coroutine<void>::pull_type* coroutine_yield;
};

class HostThreadBasedThreadControl : public ThreadControl {
public:
    template<typename F>
    HostThreadBasedThreadControl(F&& f);

    void YieldToScheduler() override;

    void ResumeFromScheduler() override;

private:
    struct ExitThreadToken{};

    void PrepareForExit() override {
        state = 2;
        resume.notify_one();
        if (thread.joinable()) {
            thread.join();
        }
    }

    void EnterTracingZone() {
        // The zone context must be copied to a non-stack variable for the zone to extend past function boundaries
#ifdef TRACY_ENABLE
        TracyCZoneN(ThreadActivity, "ThreadActivity", true);
        tracy_ctx = ThreadActivity;
#endif
    }

    void ExitTracingZone() {
        TracyCZoneEnd(*tracy_ctx);
        tracy_ctx = std::nullopt;
    }

    // 0 = run thread, 1 = pause thread, 2 = exit thread
    std::atomic<uint32_t> state = 0;

    // NOTE: Using global state here for simplicity because this code is only used outside of production
    static std::atomic<bool> scheduler_active_flag;

    std::optional<TracyCZoneCtx> tracy_ctx;

    std::mutex resume_mutex;
    std::condition_variable resume;

    // This member must be last, since the thread it spawns requires the other
    // members to be constructed before
    std::thread thread;
};

std::atomic<bool> HostThreadBasedThreadControl::scheduler_active_flag { true };

template<typename F>
HostThreadBasedThreadControl::HostThreadBasedThreadControl(F&& f)
    : thread([this, f2 = std::forward<F>(f)]() mutable {
        // Block until started
        {
            std::unique_lock lock(resume_mutex);
            resume.wait(lock, [this]() { return state != 0; } );
        }

        // TODO: Is this needed?
        if (state == 2) {
            return;
        }

        // Run main thread logic
        try {
            EnterTracingZone();
            std::forward<F>(f2)();
        } catch (const ExitThreadToken&) {
            // Exit normally
        } catch (...) {
            ExitTracingZone();
            throw;
        }

        // Ensure the Tracy zone was closed at some point
        ValidateContract(!tracy_ctx);
    }) {
}

void HostThreadBasedThreadControl::YieldToScheduler() {
    // Mark the end of the zone started at the end of this function
    ExitTracingZone();

    if (state == 2) {
        throw ExitThreadToken{};
    }

    // Hand control back to scheduler
    {
        std::unique_lock lock(resume_mutex);
        state = 0;
        scheduler_active_flag = true;
        resume.wait(lock, [this]() { return state != 0; } );
    }

    if (state == 2) {
        throw ExitThreadToken{};
    }

    // Start a Tracy zone that runs until this function is called again
    EnterTracingZone();
}

void HostThreadBasedThreadControl::ResumeFromScheduler() {
    {
        std::lock_guard lock(resume_mutex);
        scheduler_active_flag = false;
        uint32_t current_state = 0;
        state.compare_exchange_weak(current_state, 1);
        if (current_state != 0) {
            // We're actually stopping
            ValidateContract(current_state == 2);
        }
        resume.notify_one();
    }

    // TODO: Avoid spinlock
    while (!scheduler_active_flag ) {
        if (state == 2) {
            return;
        }

        std::this_thread::yield();
    }
}

using ActiveThreadControl = CoroutineThreadControl;

Thread::Thread(Process& owner, uint32_t id, uint32_t priority)
    : id(id), priority(priority),
      parent_process(owner),
      activity(owner.activity.GetSubActivity("tid_" + std::to_string(id))),
      control(std::make_unique<ActiveThreadControl>([this]() {
                    std::stringstream name_ss;
                    name_ss << ThreadPrinter{*this};
                    if (std::is_same_v<ActiveThreadControl, HostThreadBasedThreadControl>) {
                        tracy::SetThreadName(std::move(name_ss).str().c_str());
                    }

                    try {
                        auto scope_measure = MeasureScope(activity);

                        try {
                            Run();
                        } catch (const IPC::IPCError& err) {
                            throw std::runtime_error(fmt::format("Unexpected IPC error: {:#x} (header {:#x})", err.result, err.header));
                        }
                    } catch (const std::runtime_error& err) {
                        HandleOSThreadException(err, *this);
                    } catch (const EmuDisplay::EmuDisplay::ForceUnwind&) {
                        // Normal exit, ignore error
                    } catch (...) {
//                        fprintf(stderr, "UNKNOWN EXCEPTION IN %s\n", __PRETTY_FUNCTION__); // TODO: Display::ForceUnwind debugging
                        throw;
                    }
                }/*,  boost::coroutines2::attributes(0x1000000)*/)) {
}

std::shared_ptr<Thread> Thread::GetPointer() {
    return std::dynamic_pointer_cast<Thread>(shared_from_this());
}

HandleTable& Thread::GetProcessHandleTable() {
    return GetParentProcess().handle_table;
}

void Thread::SignalResourceReady() {
    status = Thread::Status::Ready;
}

OS& Thread::GetOS() {
    return GetParentProcess().GetOS();
}

void Thread::WriteMemory(VAddr addr, uint8_t value) {
    GetParentProcess().WriteMemory(addr, value);
}

uint8_t Thread::ReadMemory(VAddr addr) {
    return GetParentProcess().ReadMemory(addr);
}

uint32_t Thread::ReadMemory32(VAddr addr) {
    return (static_cast<uint32_t>(GetParentProcess().ReadMemory(addr)) << 0)
           | (static_cast<uint32_t>(GetParentProcess().ReadMemory(addr+1)) << 8)
           | (static_cast<uint32_t>(GetParentProcess().ReadMemory(addr+2)) << 16)
           | (static_cast<uint32_t>(GetParentProcess().ReadMemory(addr+3)) << 24);
}

void Thread::WriteMemory32(VAddr addr, uint32_t value) {
    GetParentProcess().WriteMemory32(addr, value);
}

uint32_t Thread::GetId() const {
    return id;
}

uint32_t Thread::GetPriority() const {
    return priority;
}

std::shared_ptr<spdlog::logger> Thread::GetLogger() {
    return GetOS().logger;
}

void Thread::OnResourceAcquired(ObserverSubject& resource) {
    assert(status == Thread::Status::Sleeping);

    GetLogger()->info("{}OnResourceAcquired called on {}", ThreadPrinter{*this}, ObjectRefPrinter{resource});

    auto it = boost::find_if(wait_list, [&](auto&& resource_ptr) { return resource_ptr.get() == &resource; });
    if (it == wait_list.end())
        throw std::runtime_error("Given resource was not being waited for");

    wake_index = std::distance(wait_list.begin(), it);
    woken_object = *it;
    (void)wait_list.erase(it);

    if (!wait_for_all) {
        GetLogger()->info("{}waking up", ThreadPrinter{*this});

        // we are already done, clear the remaining events
        for (auto sync_object : wait_list)
            sync_object->Unregister(GetPointer());

        wait_list.clear();
        status = Thread::Status::Ready;

        // TODO: Push in priority order.. ?
        // TODO: Currently, this will be followed by a reschedule, due to which this will be moved to the back anyway...
//         GetOS().priority_queue.push_back(GetPointer());
//         GetOS().ready_queue.push_back(GetPointer());
        GetOS().ready_queue.push_front(GetPointer());
//         GetOS().ready_queue.insert(std::next(GetOS().ready_queue.begin()), GetPointer());
    } else if (wait_list.empty()) {
        GetLogger()->info("{}waking up", ThreadPrinter{*this});
        status = Thread::Status::Ready;
        // TODO: For SVCWaitSynchronizationN, what index should we return in this case, though?
        // TODO: Push in priority order.. ?
        // TODO: Currently, this will be followed by a reschedule, due to which this will be moved to the back anyway...
//         GetOS().ready_queue.push_back(GetPointer());
        GetOS().ready_queue.push_front(GetPointer());
//         GetOS().priority_queue.push_back(GetPointer());
//         GetOS().ready_queue.push_front(GetPointer());
//         GetOS().ready_queue.insert(std::next(GetOS().ready_queue.begin()), GetPointer());
    }
}

void Thread::YieldForSVC(uint32_t svc) {
    decltype(callback_for_svc) store_result_in_context;

    // TODO: This need not be a lambda expression but rather can be a member function!!
    callback_for_svc = [svc,&store_result_in_context](std::shared_ptr<Thread> thread) {
        auto emu_thread = std::static_pointer_cast<EmuThread>(thread);
        auto callback_to_store_result = emu_thread->GetOS().SVCRaw(*emu_thread, svc, *emu_thread->context);

        // NOTE: If exiting the current process/thread, YieldForSVC returns
        //       before the callback reaches this line. Hence, avoid accessing
        //       the state of the outer function in that case.
        if (/*svc != 0x3 && svc != 0x9*/ emu_thread->status != Thread::Status::Stopped) {
            store_result_in_context = callback_to_store_result;
        }
    };

    // Bounce between the OS dispatcher and the OS thread to execute callbacks
    do {
//        HardwareScheduler::ScheduleSoftwareInterrupt(ctx.os->active_thread->shared_from_this(), instr.raw & 0xFFFFFF);
//        yield coroutine;
        // Switch to OS scheduler to process the callback
        // (NOTE: This may cause other threads to be dispatched if a reschedule
        // happens within the callback)
        GetOS().SwitchToSchedulerFromThread(*this); // TODO: Rename!

        if (status == Thread::Status::Stopped) {
            // TODO: Come up with a cleaner interface
            callback_for_svc = nullptr;
            throw this;
        }

        // Repeat iff the callback added another callback
    } while (callback_for_svc);

    store_result_in_context(GetPointer());
}

bool Thread::TryAcquireImpl(std::shared_ptr<Thread>) {
    // Fails until the thread has finished running
    return (status == Status::Stopped);
}


EmuThread::EmuThread(Process& owner, std::unique_ptr<Interpreter::ExecutionContext> context_, uint32_t id, uint32_t priority, VAddr entry, VAddr stack_top, TLSSlot tls_, uint32_t r0, uint32_t fpscr)
        : Thread(owner, id, priority), context(std::move(context_)), tls(std::move(tls_)) {
    ARM::State cpu { };
    cpu.cpsr.mode = ARM::InternalProcessorMode::User;

    cpu.cp15.Control().M = 1;

    // Set initial context registers
    cpu.reg[0] = r0;
    cpu.reg[13] = stack_top;
    cpu.PC() = entry & 0xfffffffe;

    if (entry & 1) {
        // Enable Thumb mode
        cpu.cpsr.thumb = 1;
    }


    cpu.fpscr.raw = fpscr; // TODO: Value?

    cpu.cp15.ThreadLocalStorage().virtual_addr = tls.addr;

    context->FromGenericContext(cpu);
}

// TODO: Deprecate
void EmuThread::SaveContext() {
    // Each thread has its own ExecutionContext, hence nothing to do
}

// TODO: Deprecate
void EmuThread::RestoreContext() {
    // Each thread has its own ExecutionContext, hence nothing to do
}

uint32_t EmuThread::GetCPURegisterValue(unsigned reg_index) {
    auto regs = context->ToGenericContext();

    if (reg_index < 16) {
        return regs.reg[reg_index];
    } else if (reg_index == 17) {
        return regs.cpsr.ToNativeRaw32();
    } else if (reg_index >= 18 && reg_index < 50) {
        uint32_t ret;
        std::memcpy(&ret, &regs.fpreg[reg_index - 18], sizeof(ret));
        return ret;
    } else if (reg_index == 50) {
        return regs.fpscr.raw;
    } else {
        return 0;
    }
    throw std::runtime_error("GetCPURegisterValue not implemented");
}

void EmuThread::SetCPURegisterValue(unsigned reg_index, uint32_t value) {
    auto regs = context->ToGenericContext();

    if (reg_index < 16)
        regs.reg[reg_index] = value;
    else if (reg_index == 17)
        regs.cpsr.FromNativeRaw32(value);
    else
        throw std::runtime_error("Invalid register index");

    context->FromGenericContext(regs);
}

void EmuThread::AddBreakpoint(VAddr addr) {
#if 0
    GetLogger()->info("{}added breakpoint at {:#x}", ThreadPrinter{*this}, addr);
    context.breakpoints.push_back({addr});
#endif
    throw std::runtime_error("AddBreakpoint not implemented");
}

void EmuThread::RemoveBreakpoint(VAddr addr) {
#if 0
    GetLogger()->info("{}removed breakpoint at {:#x}", ThreadPrinter{*this}, addr);
    context.breakpoints.remove({addr});
#endif
    throw std::runtime_error("RemoveBreakpoint not implemented");
}

void EmuThread::AddReadWatchpoint(VAddr addr) {
#if 0
    GetLogger()->info("{}added read watchpoint at {:#x}", ThreadPrinter{*this}, addr);
    context.read_watchpoints.push_back({addr});
#endif
    throw std::runtime_error("AddReadWatchpoint not implemented");
}

void EmuThread::RemoveReadWatchpoint(VAddr addr) {
#if 0
    GetLogger()->info("{}removed read watchpoint at {:#x}", ThreadPrinter{*this}, addr);
    context.read_watchpoints.remove({addr});
#endif
    throw std::runtime_error("RemoveReadWatchpoint not implemented");
}

void EmuThread::AddWriteWatchpoint(VAddr addr) {
#if 0
    GetLogger()->info("{}added write watchpoint at {:#x}", ThreadPrinter{*this}, addr);
    context.write_watchpoints.push_back({addr});
#endif
    throw std::runtime_error("AddWriteWatchpoint not implemented");
}

void EmuThread::RemoveWriteWatchpoint(VAddr addr) {
#if 0
    GetLogger()->info("{}removed write watchpoint at {:#x}", ThreadPrinter{*this}, addr);
    context.write_watchpoints.remove({addr});
#endif
    throw std::runtime_error("RemoveWriteWatchpoint not implemented");
}


uint32_t EmuThread::ReadTLS(uint32_t offset) {
    return static_cast<EmuProcess&>(GetParentProcess()).processor->ReadVirtualMemory32(tls.addr + offset);
}

void EmuThread::WriteTLS(uint32_t offset, uint32_t value) {
    static_cast<EmuProcess&>(GetParentProcess()).processor->WriteVirtualMemory32(tls.addr + offset, value);
}

void EmuThread::Run() {
    // TODO: Add an interface to EmuProcess to do this instead
    static_cast<EmuProcess&>(GetParentProcess()).processor->Run(*context, *gdbstub, GetParentProcess().GetId(), GetId());
}

FakeThread::FakeThread(FakeProcess& parent) : Thread(parent, 1 /* TODO: Consider using a different ID here, e.g. parent.MakeNewThreadId() */, Thread::PriorityDefault) {
}

FakeDebugThread::FakeDebugThread(Process& owner) : Thread(owner, 1, Thread::PriorityDefault) {
    // Do nothing
}

void FakeDebugThread::WaitForContinue(Interpreter::ProcessorController& controller) {
    while (!controller.request_continue) {
        // Do nothing
    }
    controller.paused = false;
    while (controller.request_continue) {
    }
}

void FakeDebugThread::ProcessLaunched(Process& process, Interpreter::ProcessorController& controller) {
    // TODO: Don't hardcode this check in here!
    if (GetOS().settings.get<Settings::ConnectToDebugger>()) {
        // Signal breakpoint
        // Breakpoint in debug process
        // TODO: Consider notifying the breakpoint for the launched process instead
        //       Some adjustments may need to be made to the GDB stub though, since
        //       the process reporting the breakpoint may not be the same as the
        //       process that is referred to.
        assert(!controller.paused);
        controller.NotifyProcessLaunched(GetParentProcess().GetId(), GetId(), process.GetId());

        // Wait for pause request due to breakpoint
        while (!controller.request_pause) {
        }
        controller.paused = true;

        // Wait until we are requested to continue, then unpause, then wait untilt he unpausing has been noticed
        WaitForContinue(controller);
    }
}

FakeProcess& FakeThread::GetParentProcess() {
    // TODO: This need not be a dynamic_cast, actually.
    return dynamic_cast<FakeProcess&>(parent_process);
}

bool FakeProcess::IsInternalAddress(VAddr addr) const {
    // Use the MSB to indicate internal memory
    return addr >> 31;
}

void FakeProcess::WriteMemory(VAddr addr, uint8_t value) {
    if (IsInternalAddress(addr)) {
        for (auto& static_buffer : static_buffers) {
            if (addr >= static_buffer.first &&
                    addr < static_buffer.first + static_buffer.second.data.size()) {
                static_buffer.second.data[addr - static_buffer.first] = value;
                return;
            }
        }
    } else {
        // Access emulated memory
        auto phys_addr_opt = ResolveVirtualAddr(addr);
        if (phys_addr_opt) {
            Memory::WriteLegacy<uint8_t>(interpreter_setup.mem, *phys_addr_opt, value);
            return;
        }
    }

    throw std::runtime_error(fmt::format("Tried to write to address {:#010x}, which is outside fake address range of {}",
                                         addr, ProcessPrinter{*this}));
}

void FakeProcess::WriteMemory32(VAddr addr, uint32_t value) {
    if (addr % 4) {
//        throw std::runtime_error("Unaligned target address for 32-bit write");
        Process::WriteMemory32(addr, value);
    }

    if (IsInternalAddress(addr)) {
        for (auto& static_buffer : static_buffers) {
            if (addr >= static_buffer.first &&
                    addr + sizeof(uint32_t) - 1 < static_buffer.first + static_buffer.second.data.size()) {
                static_buffer.second.data[addr - static_buffer.first    ] = value & 0xFF;
                static_buffer.second.data[addr - static_buffer.first + 1] = (value >> 8) & 0xFF;
                static_buffer.second.data[addr - static_buffer.first + 2] = (value >> 16) & 0xFF;
                static_buffer.second.data[addr - static_buffer.first + 3] = (value >> 24) & 0xFF;
                return;
            }
        }
    } else {
        // Access emulated memory
        auto phys_addr_opt = ResolveVirtualAddr(addr);
        if (phys_addr_opt) {
            Memory::WriteLegacy<uint32_t>(interpreter_setup.mem, *phys_addr_opt, value);
            return;
        }
    }

    throw std::runtime_error(fmt::format("Tried to write to address {:#010x}, which is outside fake address range of {}",
                                         addr, ProcessPrinter{*this}));
}

uint8_t FakeProcess::ReadMemory(VAddr addr) {
    if (IsInternalAddress(addr)) {
        for (auto& static_buffer : static_buffers) {
            if (addr >= static_buffer.first &&
                    addr < static_buffer.first + static_buffer.second.data.size()) {
                return static_buffer.second.data[addr - static_buffer.first];
            }
        }
    } else {
        // Access emulated memory
        auto phys_addr_opt = ResolveVirtualAddr(addr);
        if (phys_addr_opt) {
            return Memory::ReadLegacy<uint8_t>(interpreter_setup.mem, *phys_addr_opt);
        }
    }

    throw std::runtime_error(fmt::format("Tried to read from address {:#010x}, which is outside fake address range of {}",
                                         addr, ProcessPrinter{*this}));
}

// TODO: What's the actual difference between this and AllocateBuffer at this point?
uint32_t FakeProcess::AllocateStaticBuffer(uint32_t size) {
    size = (size + 0xfff) & ~0xfff;

    StaticBuffer buffer;
    buffer.data.resize(size);


    if (!static_buffers.empty())
        std::cout << "ALLOCATING STATIC BUFFER with size " << std::hex << size << " at " << static_buffers.rbegin()->first << " + " << static_buffers.rbegin()->second.data.size() << std::endl;
    else
        std::cout << "ALLOCATING STATIC BUFFER with size " << std::hex << size << std::endl;
    // Place the first buffer at address 0x80000000, and append new buffers at the end of the previous one
    // TODO: Change this to use FindAvailableVirtualMemory!
    uint32_t start_addr = static_buffers.empty() ? 0x80000000 :
                                (static_buffers.rbegin()->first + static_buffers.rbegin()->second.data.size());

    // Map it to some address to register it as allocated (otherwise, memory allocated via SVCControlMemory might unintentionally alias a static buffer!)
    if (!MapVirtualMemory(0xdeadbeef, size, start_addr, MemoryPermissions::ReadWrite)) {
        throw std::runtime_error("Failed to map internal memory");
    }

    // Let's hope we don't actually run into a situation were we allocate enough memory to unset the uppermost bit...
    if (!IsInternalAddress(start_addr))
        throw std::runtime_error("Integer overflow while allocating internal memory");

    static_buffers.insert({start_addr, buffer});
    return start_addr;
}

void FakeProcess::FreeStaticBuffer(uint32_t addr) {
    static_buffers.erase(addr);
}

std::pair<VAddr,uint8_t*> FakeProcess::AllocateBuffer(uint32_t size) {
    size = (size + 0xfff) & ~0xfff;

    // Find a place to "map" the buffer at
    VAddr start_addr = *FindAvailableVirtualMemory(size, 0x80000000, 0xFFFFFFFF - size + 1);

    std::cout << "ALLOCATING BUFFER with size " << std::hex << size << " at " << start_addr << std::endl;
    // Map it to some address to register it as allocated
    if (!MapVirtualMemory(0xdeadbeef, size, start_addr, MemoryPermissions::ReadWrite)) {
        throw std::runtime_error("Failed to map internal memory");
    }

    static_buffers[start_addr].data.resize(size);

    return { start_addr, static_buffers[start_addr].data.data() };
}

void FakeProcess::FreeBuffer(VAddr addr) {
    static_buffers.erase(addr);
    // TODO: Unmap virtual memory
}

template<typename T>
static const HandleTable::Entry<T> dummy_handle_table_entry{std::make_pair(DebugHandle{Handle{HANDLE_INVALID}}, std::shared_ptr<T>{})};

const int32_t OS::MAX_SESSIONS;

FakePort::FakePort(FakeProcess& parent, const std::string& name, uint32_t max_sessions) : FakeThread(parent), name(name), max_sessions(max_sessions), port(std::make_pair(DebugHandle{Handle{HANDLE_INVALID}}, std::shared_ptr<ServerPort>{})) {
    // Doesn't recognize error codes returned by ReplyAndReceive properly :/
//     throw std::runtime_error("Stop using me, I'm broken");
}



HandleTable::Entry<ServerPort> FakePort::Setup() {
    HandleTable::Entry<ServerPort> server_port = dummy_handle_table_entry<ServerPort>;
    HandleTable::Entry<ClientPort> client_port = dummy_handle_table_entry<ClientPort>;
    OS::Result result;
    std::tie(result,server_port,client_port) = CallSVC(&OS::SVCCreatePort, name, OS::MAX_SESSIONS);
    if (result != RESULT_OK)
        CallSVC(&OS::SVCBreak, OS::BreakReason::Panic);

    // Close the client port, since we don't need it
    std::tie(result) = CallSVC(&OS::SVCCloseHandle, client_port.first);
    if (result != RESULT_OK)
        CallSVC(&OS::SVCBreak, OS::BreakReason::Panic);

    return server_port;
}

std::string FakePort::GetInternalName() const {
    return "FAKEPORT \"" + name + "\"";
}

void FakePort::UnknownRequest(const IPC::CommandHeader& header) {
    throw Mikage::Exceptions::NotImplemented(   "{} received unknown command id {:#x} (full command: {:#010x})",
                                                GetInternalName(), header.command_id.Value(), header.raw);
}

void FakePort::LogStub(const IPC::CommandHeader& header) {
    GetLogger()->info("{}{} sending stub reply for command id {:#x}", ThreadPrinter{*this}, GetInternalName(), header.command_id.Value());
}

void FakePort::LogReturnedHandle(Handle handle) {
    GetLogger()->info("{}{} returning handle {}", ThreadPrinter{*this}, GetInternalName(), HandlePrinter{*this,handle});
}

void FakePort::Run() {
    port = Setup();

    GetLogger()->info("{}using server port handle {}", GetInternalName(), HandlePrinter{*this,port.first});

    // List of handles to synchronize against
    std::vector<Handle> handle_table = { port.first };
    Handle last_signalled = HANDLE_INVALID;

    for (;;) {
        OS::Result result;
        int32_t index;
        GetLogger()->info("{}{} ReplyAndReceive", ThreadPrinter{*this}, GetInternalName());
        std::tie(result,index) = CallSVC(&OS::SVCReplyAndReceive, handle_table.data(), handle_table.size(), last_signalled);
        last_signalled = HANDLE_INVALID;
        if (result != RESULT_OK) {
            continue;
//            throw Mikage::Exceptions::NotImplemented("{}{} Unknown error code returned by ReplyAndReceive", ThreadPrinter{*this}, GetInternalName());
        }

        if (index == 0) {
            // ServerPort: Incoming client connection

            std::shared_ptr<ServerSession> session;
            Handle session_handle;
            // TODO: Does forward_as_tuple work as we expect?
            GetLogger()->info("{}{} AcceptSession", ThreadPrinter{*this}, GetInternalName());
            std::forward_as_tuple(result,std::tie(session_handle,session)) = CallSVC(&OS::SVCAcceptSession, *port.second);
            if (result != RESULT_OK)
                CallSVC(&OS::SVCBreak, OS::BreakReason::Panic);

            // If maximum number of sessions is exhausted, close handle again.
            if (handle_table.size() < OS::MAX_SESSIONS+1) {
                handle_table.push_back(session_handle);
            } else {
                GetLogger()->warn("{} {} Maximal number of sessions exhausted; closing session handle {}",
                                  ThreadPrinter{*this}, GetInternalName(), HandlePrinter{*this,session_handle});
                CallSVC(&OS::SVCCloseHandle, session_handle);
            }
        } else {
            // server_session: Incoming IPC command from the indexed client
            GetLogger()->info("{}{} received IPC request", ThreadPrinter{*this}, GetInternalName());
            IPC::CommandHeader header = { ReadTLS(0x80) };
            OnIPCRequest(handle_table[index], header);
            last_signalled = handle_table[index];
        }
    }

    // Clean up
    for (auto handle : handle_table)
        CallSVC(&OS::SVCCloseHandle, handle);

    CallSVC(&OS::SVCExitThread);
}

FakeService::FakeService(FakeProcess& parent, const std::string& name, uint32_t max_sessions) : FakePort(parent, "", max_sessions), name(name), max_sessions(max_sessions) {
    Object::name = "Fake_" + name;
}

HandleTable::Entry<ServerPort> FakeService::Setup() {
    GetLogger()->info("{}{} Connecting to port \"srv:\" to register this fake service", ThreadPrinter{*this}, GetInternalName());

    OS::Result result;
    Handle srv_handle;
    std::shared_ptr<ClientSession> srv_session;
    std::forward_as_tuple(result,std::tie(srv_handle,srv_session)) = CallSVC(&OS::SVCConnectToPort, "srv:");
    if (result != RESULT_OK)
        CallSVC(&OS::SVCBreak, OS::BreakReason::Panic);

    // Send RegisterService request
    // TODO: Currently, we never request UnregisterService!
    WriteTLS(0x80, IPC::CommandHeader::Make(3, 4, 0).raw);

    // TODO: Clean this up by introducing WriteTLS<uint8_t> variants
    // TODO: This isn't even portable :(
    uint32_t value = 0;
    for (int i = 0; i < 8; ++i) {
        char c = (i < name.length()) ? name[i] : 0;
        value = (c << 24) | (value >> 8);
        if (i == 3 || i == 7) {
            WriteTLS(0x84 + (i / 4) * 4, value);
            value = 0;
        }
    }

    WriteTLS(0x8c, std::min<size_t>(8, name.length()));
    WriteTLS(0x90, max_sessions);

    GetLogger()->info("{}{} sending RegisterService request", ThreadPrinter{*this}, GetInternalName());
    std::tie(result) = CallSVC(&OS::SVCSendSyncRequest, srv_handle);
    if (result != RESULT_OK) {
        throw std::runtime_error("Unexpected error returned by SVCSendSyncRequest");
    }

    CallSVC(&OS::SVCCloseHandle, srv_handle);

    // Read RegisterService reply
    result = ReadTLS(0x84);
    if (result != RESULT_OK) {
        throw std::runtime_error("Unexpected error returned by srv:RegisterService");
    }

    Handle service_handle{ReadTLS(0x8c)};
    auto service_port = GetProcessHandleTable().FindObject<ServerPort>(service_handle);

    SetupService();

    GetLogger()->info("{}{} setup done", ThreadPrinter{*this}, GetInternalName());
    return { service_handle, service_port };
}

std::string FakeService::GetInternalName() const {
    return "FAKESERVICE \"" + name + "\"";
}

// First thread started by the OS: Takes care of setting up the system services
class BootThread : public FakeThread {
public:
    BootThread(FakeProcess& parent) : FakeThread(parent) {
    }

    virtual ~BootThread() = default;

    void Run() override try {
        // Open firm ExeFS
        uint8_t exefs_section[8] = { '.', 'f', 'i', 'r', 'm' };
        Platform::FS::ProgramInfo info { 0x4013800000002, Meta::to_underlying(Platform::FS::MediaType::NAND) };
        auto firm_file = HLE::PXI::FS::OpenNCCHSubFile(*this, info, 0, 1, std::basic_string_view<uint8_t>(exefs_section, sizeof(exefs_section)), nullptr);

        HLE::PXI::FS::FileContext file_context { *GetLogger() };
        std::vector<uint8_t> firm_data;
        {
            firm_file->OpenReadOnly(file_context);
            auto [result, num_bytes] = firm_file->GetSize(file_context);
            if (result != RESULT_OK) {
                throw std::runtime_error("Could not determine file size");
            }
            GetLogger()->info("Reading ExeFS from FIRM ({:#x} bytes)", num_bytes);
            firm_data.resize(num_bytes);
            uint64_t bytes_read = 0;
            std::tie(result, bytes_read) = firm_file->Read(file_context, 0, num_bytes, HLE::PXI::FS::FileBufferInHostMemory { firm_data.data(), static_cast<uint32_t>(num_bytes) });
        }

        const uint8_t marker[] = { 'N', 'C', 'C', 'H' };

        // Maps title id to offset + size in bytes
        std::map<uint64_t, std::pair<uint32_t, uint32_t>> firm_titles;

        // Find embedded NCCHs
        auto match_it = firm_data.begin() + 0x200;
        while (true) {
            auto [new_match_it, end_match_it] = ranges::search(match_it, firm_data.end(), std::begin(marker), std::end(marker));
            match_it = end_match_it;
            if (match_it == firm_data.end()) {
                break;
            }
            uint32_t offset = std::distance(firm_data.begin(), new_match_it) - offsetof(FileFormat::NCCHHeader, magic);
            auto title_id = FileFormat::LoadValue<uint64_t, boost::endian::order::little>(FileFormat::MakeStreamInFromContainer(new_match_it + 0x18, new_match_it + 0x20));
            auto num_bytes = 0x200 * FileFormat::LoadValue<uint32_t, boost::endian::order::little>(FileFormat::MakeStreamInFromContainer(new_match_it + 0x4, new_match_it + 0x8));
            if ((title_id >> 32) != 0x40130) {
                // This isn't an embedded NCCH, but just the string "NCCH" in the FIRM's NCCH loader
                continue;
            }
            GetLogger()->info("Found embedded FIRM title {:#x} at offset {:#x} ({:#x} bytes)", title_id, offset, num_bytes);
            firm_titles[title_id] = { offset, num_bytes };
        }
        firm_file.reset();

        const uint64_t title_id_sm     = 0x4013000001002;
        const uint64_t title_id_pxi    = 0x4013000001402;
        const uint64_t title_id_fs     = 0x4013000001102;
        const uint64_t title_id_loader = 0x4013000001302;
        const uint64_t title_id_pm     = 0x4013000001202;

        HandleTable::Entry<ClientSession> srv_session;
        for (auto title_id : { title_id_sm, title_id_pxi, title_id_fs, title_id_loader, title_id_pm }) {
            if (title_id == title_id_pxi || title_id == title_id_fs) {
                // Launch via dummy NCCH since these processes are HLEed
                LaunchTitleInternal(*this, true, title_id, 0);
                continue;
            }


            GetLogger()->info("Launching FIRM title {:#x}", title_id);
            auto firm_file = HLE::PXI::FS::OpenNCCHSubFile(*this, info, 0, 1, std::basic_string_view<uint8_t>(exefs_section, sizeof(exefs_section)), nullptr);
            auto [offset, num_bytes] = firm_titles.at(title_id);
            auto ncch_file = std::make_unique<PXI::FS::FileView>(std::move(firm_file), offset, num_bytes);
            auto exheader = HLE::PXI::GetExtendedHeader(file_context, GetParentProcess().interpreter_setup.keydb, *ncch_file);
            auto process = LoadProcessFromFile(*this, true, exheader, std::move(ncch_file));

            OS::StartupInfo startup{};
            startup.stack_size = exheader.stack_size;
            startup.priority = exheader.aci.flags.priority();
            auto [result] = CallSVC(&OS::SVCRun, process.first, startup);
            CallSVC(&OS::SVCCloseHandle, std::move(process).first);

            if (title_id == title_id_sm) {
                // Wait until SM has spawned its main port so HLE services can assume it's already set up
                while (true) {
                    std::tie(result, srv_session) = CallSVC(&OS::SVCConnectToPort, "srv:");
                    if (result == RESULT_OK) {
                        break;
                    }
                }
            }
        }


        GetLogger()->info("{}FakeThread \"BootThread\" exiting", ThreadPrinter{*this});
        CallSVC(&OS::SVCExitThread);
    } catch (HLE::OS::FakeThread* stopped_thread) {
        // Do nothing
    }
};

bool ObserverSubject::TryAcquire(std::shared_ptr<Thread> thread) {
    bool acquired = TryAcquireImpl(thread);
    if (acquired) {
        thread->GetLogger()->info("{}Successfully tried acquiring {}",
                                  ThreadPrinter{*thread}, ObjectRefPrinter{*this});
        Unregister(thread);
    }

    return acquired;
}

void ObserverSubject::Register(std::shared_ptr<Thread> thread) {
    observers.push_back(thread);
}

void ObserverSubject::Unregister(std::shared_ptr<Thread> thread) {
    // This should always find a match
    auto it = std::find_if(observers.begin(), observers.end(), [&thread](auto& observer) { return observer.lock() == thread; });
    assert(it != observers.end());
    observers.erase(it);
}

// TODOTEST: What happens if the application were doing something stupid like
// SVCWaitSynchronizationN'ing on multiple server port handles with the
// wait_for_all flag set to true?
bool ServerPort::TryAcquireImpl(std::shared_ptr<Thread> thread) {
    // NOTE: Some modules call SVCWaitSynchronization again after waking up
    //       on a ServerPort handle in SVCReplyAndReceive. Hence, acquisition
    //       must be idempotent.
    return !session_queue.empty();
}

void ServerPort::OfferSession(std::shared_ptr<Session> session) {
    session_queue.push(session);
}

bool ServerSession::TryAcquireImpl(std::shared_ptr<Thread>) {
    if (!session->client.lock()) {
        // Always succeed acquiring the session if the endpoint was closed.
        // ReplyAndReceive will check what caused the wakeup to happen.
        return true;
    }

    if (ipc_commands_pending) {
        return ipc_commands_pending--;
    } else {
        return false;
    }
}

void ServerSession::CommandReady() {
    ++ipc_commands_pending;

    // TODO: Reenable this and figure out what could break without any further special treatment. What was I concerned about here?
//     if (ipc_commands_pending > 1)
//         throw std::runtime_error("can't cope");
}

bool ClientPort::TryAcquireImpl(std::shared_ptr<Thread>) {
    if (!port->server.lock()) {
        throw std::runtime_error("Client port has no server endpoint");
    }

    return port->server.lock()->available_sessions != 0;
}

bool ClientSession::TryAcquireImpl(std::shared_ptr<Thread> acquiring_thread) {
    // Check whether our thread is still in the list of threads that need to wait.
    auto it = std::find_if(threads.begin(), threads.end(), [&](auto& thread) { return thread.lock() == acquiring_thread; });
    return (it == threads.end());
}

void ClientSession::SetReady(std::shared_ptr<Thread> waiting_thread) {
    auto it = std::find_if(threads.begin(), threads.end(), [&](auto& thread) { return thread.lock() == waiting_thread; });
    if (it == threads.end())
        throw std::runtime_error("Thread set ready despite not being in the wait list");

    threads.erase(it);
}

bool Mutex::TryAcquireImpl(std::shared_ptr<Thread> thread) {
    // Mutexes may be locked recursively, so we need to keep track of how
    // often the owning thread locked it. Only when all locks have been
    // released, another thread may acquire the mutex.
    if (lock_count) {
        auto owner_ptr = owner.lock();
        if (!owner_ptr) {
            throw std::runtime_error("Mutex still locked but owning thread was destroyed");
        }
        if (owner_ptr != thread) {
            return false;
        }
    }

    owner = thread;
    ++lock_count;
    return true;
}

void Mutex::Release() {
    assert(lock_count);

    // Unlock this mutex if and only if the owner has released all locks on it
    if (--lock_count == 0) {
        owner.reset();
    }
}

bool Mutex::IsOwner(std::shared_ptr<Thread> thread) const {
    return lock_count && thread == owner.lock();
}

bool Semaphore::TryAcquireImpl(std::shared_ptr<Thread> thread) {
    assert(available_count >= 0);

    if (available_count == 0)
        return false;

    --available_count;
    return true;
}

Result Semaphore::Release(int32_t times) {
    if (times < 0)
        return 0xe0e01bfd;

    // TODO: Will the semaphore indeed not be released at all in this case?
    if (available_count > max_available - times)
        return 0xd8e007fd;

    available_count += times;
    assert(available_count >= 0);

    return RESULT_OK;
}

bool Event::TryAcquireImpl(std::shared_ptr<Thread> thread) {
    if (!signalled)
        return false;

    if (type == ResetType::OneShot) {
        signalled = false;
    } else if (type == ResetType::Sticky) {
        // Don't reset the signal
    } else {
        // We shouldn't be able to create other events
        // TODO: According to https://github.com/citra-emu/citra/issues/1904, these do exist after all
        throw std::runtime_error("Event shouldn't have a type different than OneShot and Sticky");
    }

    return true;
}

void Event::SignalEvent() {
    signalled = true;
}

void Event::ResetEvent() {
    signalled = false;
}

bool Timer::TryAcquireImpl(std::shared_ptr<Thread> thread) {
    auto current_time = thread->GetOS().GetTimeInNanoSeconds();
    if (!active || current_time < timeout_time_ns)
        return false;

    if (type == ResetType::OneShot) {
        // This is the only thread we will wake up
        Reset();
    } else if (type == ResetType::Sticky) {
        // Don't reset the timer (keep waking up threads)
    } else if (type == ResetType::Pulse) {
        // Restart the timer so that it wakes up another thread later
        // TODO: According to https://github.com/citra-emu/citra/issues/1904, this should wake up all threads waiting rather than just a single one! (Also, if none wasn't waiting, it should just be silently reset!)
        Run(current_time + period_ns, period_ns);
    } else {
        // We shouldn't be able to create other timers
        throw std::runtime_error("Timer shouldn't have a type different than OneShot, Sticky, and Pulse");
    }

    return true;
}

void Timer::Run(uint64_t timeout_time, uint64_t period) {
    timeout_time_ns = timeout_time;
    period_ns = period;

    active = true;
}

void Timer::Reset() {
    active = false;
}

bool Timer::Expired(uint64_t current_time) const {
    return (active && current_time >= timeout_time_ns);
}

MemoryManager::MemoryManager(PAddr start_address, uint32_t size)
    : region_start_paddr(start_address), region_size_bytes(size) {
    free[region_start_paddr] = MemoryBlock { region_size_bytes, {} };
}

std::optional<uint32_t> MemoryManager::AllocateBlock(std::shared_ptr<MemoryBlockOwner> owner, uint32_t size_bytes) {
    for (auto block_it = free.begin(); block_it != free.end(); ++block_it) {
        ValidateContract(block_it->second.owner.expired());

        const uint32_t addr = block_it->first;
        const uint32_t free_size = block_it->second.size_bytes;

        if (free_size < size_bytes)
            continue;

        // Declare new "taken" memory block
        free.erase(block_it);
        taken[addr] = { size_bytes, owner };
        // TODO: Merge block with adjacent taken blocks

        // Add "free" entry for remaining space
        if (free_size != size_bytes)
            free[addr + size_bytes] = { free_size - size_bytes, {} };

        // TODO: Use a proper logger for this
        auto get_chunk_size = ranges::views::transform([](auto& chunk) -> uint32_t { return chunk.second.size_bytes; });
//        std::cout << "MemoryManager allocated new block at 0x" << std::hex << std::setw(8) << std::setfill('0') << addr << " with 0x" << size_bytes << " bytes; 0x" << ranges::accumulate(free | get_chunk_size, uint32_t{0}) << "/0x" << region_size_bytes << " bytes remaining" << std::endl;
        fmt::print( "MemoryManager allocated new block at {:#010x} with {:#x} bytes; {:#x}/{:#x} bytes remaining (owner {})\n",
                    addr, size_bytes, ranges::accumulate(free | get_chunk_size, uint32_t{0}), region_size_bytes, fmt::ptr(owner.get()));

            // TODO: Merge with adjacent free blocks in the else cases
            // Defragment the entire region as a stopgap solution
            for (auto it = free.begin(); it != free.end() && it != std::prev(free.end());) {
                auto next_it = std::next(it);
                if (it->first + it->second.size_bytes == next_it->first && it->second.owner.lock() == next_it->second.owner.lock()) {
                    it->second.size_bytes += next_it->second.size_bytes;
                    (void)free.erase(next_it);
                    // Repeat in case the next block can also be merged
                } else {
                    ++it;
                }
            }
            for (auto it = taken.begin(); it != taken.end() && it != std::prev(taken.end());) {
                auto next_it = std::next(it);
                if (it->first + it->second.size_bytes == next_it->first && it->second.owner.lock() == next_it->second.owner.lock()) {
                    it->second.size_bytes += next_it->second.size_bytes;
                    (void)taken.erase(next_it);
                    // Repeat in case the next block can also be merged
                } else {
                    ++it;
                }
            }

        return addr;
    }
    return {};
}

void MemoryManager::DeallocateBlock(std::shared_ptr<MemoryBlockOwner> owner, PAddr start_addr, uint32_t size_bytes) {
    fmt::print("Trying to free: {:#x}-{:#x}\n", start_addr, start_addr + size_bytes);
    for (auto block_it = taken.begin(); block_it != taken.end(); ++block_it) {
        const uint32_t chunk_addr = block_it->first;
        const uint32_t chunk_size = block_it->second.size_bytes;

        fmt::print("Chunk: {:#x}-{:#x}\n", chunk_addr, chunk_addr + chunk_size);

        ValidateContract(!block_it->second.owner.expired());

        if (chunk_addr <= start_addr && chunk_addr + chunk_size > start_addr) {
            ValidateContract(block_it->second.owner.lock() == owner);

            if (chunk_addr + chunk_size < start_addr + size_bytes) {
                throw Mikage::Exceptions::Invalid("Size to free is larger than allocated block");
            }

            // Declare new "taken" memory block
            taken.erase(block_it);

            free[start_addr] = MemoryBlock { size_bytes, {} };

            // Add "taken" entry for remaining space
            if (chunk_addr < start_addr) {
                taken[chunk_addr] = { start_addr - chunk_addr, owner};
            }
            if (chunk_addr + chunk_size > start_addr + size_bytes) {
                taken[start_addr + size_bytes] = { chunk_addr + chunk_size - start_addr - size_bytes, owner };
            }

            // TODO: Merge with adjacent free blocks in the else cases
            // Defragment the entire region as a stopgap solution
            for (auto it = free.begin(); it != free.end() && it != std::prev(free.end());) {
                auto next_it = std::next(it);
                if (it->first + it->second.size_bytes == next_it->first && it->second.owner.lock() == next_it->second.owner.lock()) {
                    it->second.size_bytes += next_it->second.size_bytes;
                    (void)free.erase(next_it);
                    // Repeat in case the next block can also be merged
                } else {
                    ++it;
                }
            }
            for (auto it = taken.begin(); it != taken.end() && it != std::prev(taken.end());) {
                auto next_it = std::next(it);
                if (it->first + it->second.size_bytes == next_it->first && it->second.owner.lock() == next_it->second.owner.lock()) {
                    it->second.size_bytes += next_it->second.size_bytes;
                    (void)taken.erase(next_it);
                    // Repeat in case the next block can also be merged
                } else {
                    ++it;
                }
            }

            // TODO: Use a proper logger for this
            std::cout << "MemoryManager freed up block at 0x" << std::hex << std::setw(8) << std::setfill('0') << start_addr << " with 0x" << size_bytes << " bytes\n";
            return;
        }
    }

    throw std::runtime_error("No suitable block found to free");
}

void MemoryManager::TransferOwnership(  std::shared_ptr<MemoryBlockOwner> old_owner, std::shared_ptr<MemoryBlockOwner> new_owner,
                                        PAddr start_addr, uint32_t size_bytes) {
    fmt::print("Trying to transfer memory ownership from {} to {}: {:#x}-{:#x}\n", fmt::ptr(old_owner.get()), fmt::ptr(new_owner.get()), start_addr, start_addr + size_bytes);
    for (auto block_it = taken.begin(); block_it != taken.end(); ++block_it) {
        const uint32_t chunk_addr = block_it->first;
        const uint32_t chunk_size = block_it->second.size_bytes;

        fmt::print("Chunk: {:#x}-{:#x} (owner {})\n", chunk_addr, chunk_addr + chunk_size, fmt::ptr(block_it->second.owner.lock().get()));

        ValidateContract(!block_it->second.owner.expired());

        if (chunk_addr <= start_addr && chunk_addr + chunk_size >= start_addr + size_bytes) {
            ValidateContract(block_it->second.owner.lock() == old_owner);

            if (chunk_addr + chunk_size < start_addr + size_bytes) {
                throw Mikage::Exceptions::Invalid("Size to transfer is larger than allocated block ({:#x}-{:#x}, next {:#x}-{:#x}",
                chunk_addr, chunk_addr + chunk_size, std::next(block_it)->first, std::next(block_it)->first + std::next(block_it)->second.size_bytes);
            }

            // Declare new "taken" memory block
            taken.erase(block_it);

            taken[start_addr] = MemoryBlock { size_bytes, new_owner };

            // Add "taken" entry for remaining space
            if (chunk_addr < start_addr) {
                taken[chunk_addr] = { start_addr - chunk_addr, old_owner };
            }
            if (chunk_addr + chunk_size > start_addr + size_bytes) {
                taken[start_addr + size_bytes] = { chunk_addr + chunk_size - start_addr - size_bytes, old_owner };
            }

            // TODO: Merge adjacent taken blocks
            // Defragment the entire region as a stopgap solution
            for (auto it = taken.begin(); it != taken.end() && it != std::prev(taken.end());) {
                auto next_it = std::next(it);
                if (it->first + it->second.size_bytes == next_it->first && it->second.owner.lock() == next_it->second.owner.lock()) {
                    it->second.size_bytes += next_it->second.size_bytes;
                    (void)taken.erase(next_it);
                    // Repeat in case the next block can also be merged
                } else {
                    ++it;
                }
            }

            // TODO: Use a proper logger for this
            std::cout << "MemoryManager transferred ownership of block at 0x" << std::hex << std::setw(8) << std::setfill('0') << start_addr << " with 0x" << size_bytes << " bytes\n";
            return;
        }
    }

    throw std::runtime_error("No suitable block found to transfer ownership of");
}

static uint32_t GetTotalSizeOfMemoryBlocks(const std::map<uint32_t, MemoryBlock>& list) {
    using boost::adaptors::map_values;
    using boost::adaptors::transformed;
    auto get_block_size = [](const MemoryBlock& block) { return block.size_bytes; };
    return boost::accumulate(list | map_values | transformed(get_block_size), uint32_t{});
}

uint32_t MemoryManager::UsedMemory() const {
    return GetTotalSizeOfMemoryBlocks(taken);
}

uint32_t MemoryManager::TotalSize() const {
    return UsedMemory() + GetTotalSizeOfMemoryBlocks(free);
}

void OS::Initialize() {
    // TODO: Create idle process
}

TLSSlot TLSManager::GetFreePage(Process& process) {
    auto it = std::find(slot_occupied.begin(), slot_occupied.end(), false);
    if (it == slot_occupied.end()) {
        // Append a new slot at the end, marked as "used"
        if (NextSlotNeedsNewPage()) {
            auto tls_paddr_opt = process.GetOS().memory_base().AllocateBlock(std::static_pointer_cast<Process>(process.shared_from_this()), page_size);
            auto tls_vaddr_opt = process.FindAvailableVirtualMemory(page_size, next_tls_addr, next_tls_addr + page_size);
            if (!tls_vaddr_opt || !process.MapVirtualMemory(*tls_paddr_opt, page_size, *tls_vaddr_opt, MemoryPermissions::ReadWrite)) {
                throw std::runtime_error("Failed to map TLS memory!");
            }
        }

        slot_occupied.emplace_back(true);
        it = std::prev(slot_occupied.end());

        // TODO: Limit how large this can become
        next_tls_addr += tls_size;
    }

    *it = true;
    auto slot_addr = first_tls_addr + static_cast<VAddr>(std::distance(slot_occupied.begin(), it) * tls_size);

    return TLSSlot { slot_addr, *this };
}

// lowest significant bit in entry_point indicates whether to start in thumb mode or not
std::shared_ptr<EmuThread> EmuProcess::SpawnThread(uint32_t priority, VAddr entry_point, VAddr stack_top, uint32_t r0, uint32_t fpscr) {
    // Allocate some memory for thread local storage
    // TODO: Change TLS to start being allocated at 0x1FF82000. Not sure how large it may become, though!
    // TODO: Error checking!
//    auto tls_paddr_opt = GetOS().memory.AllocateBlock(0x200);
//    auto tls_vaddr_opt = FindAvailableVirtualMemory(0x200, 0x03000000, 0x04000000);
//    if (!MapVirtualMemory(*tls_paddr_opt, 0x200, *tls_vaddr_opt, MemoryPermissions::ReadWrite))
    // TODO: Where is TLS usually allocated? We currently assume it's in the BASE memory region
//    auto tls_paddr_opt = GetOS().memory_base.AllocateBlock(0x1000);
//    auto tls_vaddr_opt = FindAvailableVirtualMemory(0x1000, 0x1FF82000, 0x1FF89000); // TODO: Instead, we should partition each page across 8 threads!
//    if (!MapVirtualMemory(*tls_paddr_opt, 0x1000, *tls_vaddr_opt, MemoryPermissions::ReadWrite))
//        throw std::runtime_error("Failed to map TLS memory!");

    // Create the actual thread object (mark it as attached to the debugger if our other threads are attached, too)
    auto thread = std::make_shared<EmuThread>(*this, processor->CreateExecutionContext(), MakeNewThreadId(), priority, entry_point, stack_top, tls_manager.GetFreePage(*this), r0, fpscr);
    if (!threads.empty())
        thread->context->SetDebuggingEnabled(std::static_pointer_cast<EmuThread>(threads.front())->context->IsDebuggingEnabled());
    threads.push_back(thread);
    GetOS().RegisterToScheduler(thread);
    return thread;
}

void EmuProcess::WriteMemory(VAddr addr, uint8_t value) {
    auto paddr_opt = ResolveVirtualAddr(addr);
    if (!paddr_opt) {
        throw std::runtime_error(fmt::format("EmuProcess trying to write to invalid virtual address {:#x}", addr));
    }
    Memory::WriteLegacy<uint8_t>(interpreter_setup.mem, *paddr_opt, value);
}

uint8_t EmuProcess::ReadMemory(VAddr addr) {
    auto paddr_opt = ResolveVirtualAddr(addr);
    if (!paddr_opt) {
        throw std::runtime_error(fmt::format("EmuProcess trying to read from invalid virtual address {:#x}", addr));
    }
    return Memory::ReadLegacy<uint8_t>(interpreter_setup.mem, *paddr_opt);
}

std::shared_ptr<FakeProcess> OS::MakeFakeProcess(Interpreter::Setup& setup, const std::string& name) {
    auto process = std::make_shared<FakeProcess>(*this, setup, MakeNewProcessId(), name);

    // The current Process handle is accessible through a fixed constant
    // TODO: Evaluate if there is any point in having this for FakeProcesses
    // TODO: Fill in debug information
    process->handle_table.CreateEntry(Handle{0xFFFF8001}, process);

    RegisterProcess(process);

    // TODO: Map shared pages

    return process;
}

bool OS::ShouldHLEProcess(std::string_view module_name) const {
    return hle_titles.find(module_name) != hle_titles.end();
}

void OS::RegisterToScheduler(std::shared_ptr<Thread> thread) {
    threads.push_back(thread);
    if (thread->status == Thread::Status::Ready)
        ready_queue.push_back(thread);
}

void OS::OnResourceReady(ObserverSubject& resource) {
    // TODO: Iterate threads in priority order!
    while (!resource.observers.empty()) {
        auto thread = resource.observers.front().lock();
        if (!thread) {
            resource.observers.pop_front();
            continue;
        }

        // A non-sleeping thread shouldn't be in our observer list
        assert(thread->status == Thread::Status::Sleeping);

        // Wake threads until resource acquisition fails (TryAcquire will
        // remove "thread" from resource.observers on success)
        bool acquired = resource.TryAcquire(thread);
        if (!acquired)
            break;

        thread->OnResourceAcquired(resource);
    }
}

void HandleTable::ErrorNotFound(Handle handle, const char* requested_type) {
    throw Mikage::Exceptions::Invalid("Could not find handle {} of type \"{}\" in handle table", handle.value, requested_type);
}

void HandleTable::ErrorWrongType(std::shared_ptr<Object> object, const char* requested_type) {
    auto& obj = *object;
    throw std::runtime_error(fmt::format("Requested type \"{}\", but found object has type \"{}\"\n", requested_type, obj.GetName()));
}

void HandleTable::CloseHandle(Handle handle) {
    auto it = table.find(handle);
    if (it == table.end()) {
        return; // TODO: 3dscraft workaround, only
        throw std::runtime_error("Tried to close handle " + std::to_string(handle.value) + " that is not in the handle table");
    }

    table.erase(table.find(handle));
}

Process::Process(OS& os, Profiler::Activity& activity, Interpreter::Setup& setup, uint32_t pid, MemoryManager& memory_allocator) : os(os), pid(pid), next_tid(1), interpreter_setup(setup), memory_allocator(memory_allocator),
    activity(activity) {
}

ThreadId Process::MakeNewThreadId() {
    return next_tid++;
}

std::shared_ptr<Thread> Process::GetThreadFromId(ThreadId thread_id) const {
    for (auto thread : threads) {
        if (thread_id == thread->GetId())
            return thread;
    }

    return nullptr;
}

bool Process::MapVirtualMemory(PAddr phys_addr, uint32_t size, VAddr vaddr, MemoryPermissions permissions) {
    if (size == 0) {
        throw std::runtime_error("Tried to map zero-sized memory block");
    }

    if (size % 0x1000) {
    fprintf(stderr, "MapVirtualMemory: Unaligned size\n");
//std::abort();
//        ValidateContract((size % 0x1000) == 0);
    }

    // First off, make sure the given range is actually valid:
    // - The first existing mapping starting at vaddr must be "far away" for "size" bytes to fit in
    // - The mapping before that one must end before or at "vaddr".
    auto it = virtual_memory.lower_bound(vaddr);
    if (it != virtual_memory.end() && it->first < vaddr + size)
        return false;

    if (it != virtual_memory.begin() && std::prev(it)->first + std::prev(it)->second.size > vaddr)
        return false;

    // Insert new mapping and invoke implementation-specific behavior
    virtual_memory.insert({vaddr, {phys_addr,size,permissions}});

    GetLogger()->info("{}Mapped VAddr [{:#010x};{:#010x}] to PAddr [{:#010x};{:#010x}]", ProcessPrinter{*this}, vaddr, vaddr + size, phys_addr, phys_addr + size);

    OnVirtualMemoryMapped(phys_addr, size, vaddr);
    return true;
}

bool Process::UnmapVirtualMemory(VAddr vaddr, uint32_t size) {
    if (size == 0) {
        throw std::runtime_error("Tried to unmap zero-sized memory block");
    }

    auto it = virtual_memory.upper_bound(vaddr);
    if (it != virtual_memory.begin() && std::prev(it)->first + std::prev(it)->second.size > vaddr && std::prev(it)->first < vaddr + size) {
        --it;
    }
    if (it == virtual_memory.end() /* || it->second.size != size)*/) {
        GetLogger()->warn("{}Couldn't find VAddr range [{:#010x};{:#010x}] in memory map", ProcessPrinter{*this}, vaddr, vaddr + size);
        return false;
    }

    auto unmapped_chunk_vstart = it->first;
    auto unmapped_chunk = it->second;
    if (unmapped_chunk_vstart > vaddr + size) {
        // Temporary workaround to counteract workaround in ControlMemory that force-unmaps existing memory...
        return false;
    }
    if (unmapped_chunk_vstart + unmapped_chunk.size < vaddr) {
        // Temporary workaround to counteract workaround in ControlMemory that force-unmaps existing memory...
        return false;
    }

    ValidateContract(unmapped_chunk_vstart < vaddr + size);
    ValidateContract(unmapped_chunk_vstart + unmapped_chunk.size > vaddr);

    (void)virtual_memory.erase(it);

    if (unmapped_chunk_vstart < vaddr) {
        // Reinsert the remaining memory into the map
        uint32_t remaining_size = vaddr - unmapped_chunk_vstart;
        auto remainder = VirtualMemoryBlock { unmapped_chunk.phys_start, remaining_size, unmapped_chunk.permissions };
        virtual_memory.insert({unmapped_chunk_vstart, remainder});

        auto delta = vaddr - unmapped_chunk_vstart;
        unmapped_chunk_vstart += delta;
        unmapped_chunk.phys_start += delta;
        unmapped_chunk.size -= delta;
    }

    if (unmapped_chunk.size > size) {
        // Reinsert the remaining memory into the map
        auto remainder = VirtualMemoryBlock { unmapped_chunk.phys_start + size, unmapped_chunk.size - size, unmapped_chunk.permissions };
        virtual_memory.insert({vaddr + size, remainder});
        unmapped_chunk.size = size;
    }

    GetLogger()->info("{}Unmapped VAddr [{:#010x};{:#010x}]", ProcessPrinter{*this}, unmapped_chunk_vstart, unmapped_chunk_vstart + unmapped_chunk.size);

    OnVirtualMemoryUnmapped(unmapped_chunk_vstart, unmapped_chunk.size);

    if (size > unmapped_chunk.size) {
        return UnmapVirtualMemory(vaddr + unmapped_chunk.size, size - unmapped_chunk.size);
    }

    return true;
}

std::optional<uint32_t> Process::ResolveVirtualAddr(VAddr addr) {
    // Find the first address mapping larger than addr, then move one step back to find the one containing addr
    // Possible corner cases:
    // * Empty ranges will return a begin iterator (=> abort)
    // * If the upper bound is an end iterator, moving one step back will be a valid iterator for non-empty maps
    auto it = virtual_memory.upper_bound(addr);
    if (it == virtual_memory.begin())
        return std::nullopt;

    // Finally, make sure the address is mapped at all
    --it;
    auto addr_range_vstart = it->first;
    auto addr_range_size = it->second.size;
    auto addr_range_pstart = it->second.phys_start;
    if (addr_range_vstart + addr_range_size <= addr)
        return std::nullopt;

    return addr_range_pstart + (addr - addr_range_vstart);
}

static std::optional<std::pair<VAddr, uint32_t>> ResolveVirtualAddrWithSize(Process& proc, VAddr addr) {
    // Find the first address mapping larger than addr, then move one step back to find the one containing addr
    // Possible corner cases:
    // * Empty ranges will return a begin iterator (=> abort)
    // * If the upper bound is an end iterator, moving one step back will be a valid iterator for non-empty maps
    auto it = proc.virtual_memory.upper_bound(addr);
    if (it == proc.virtual_memory.begin())
        return std::nullopt;

    // Finally, make sure the address is mapped at all
    --it;
    auto addr_range_vstart = it->first;
    auto addr_range_size = it->second.size;
    auto addr_range_pstart = it->second.phys_start;
    if (addr_range_vstart + addr_range_size <= addr)
        return std::nullopt;

    return std::make_pair<VAddr, uint32_t>(addr_range_pstart + (addr - addr_range_vstart), addr_range_size - (addr - addr_range_vstart));
}

std::optional<uint32_t> Process::FindAvailableVirtualMemory(uint32_t size, VAddr vaddr_start, VAddr vaddr_end) {

    // TODO: Guard against integer overflows throughout this function!

    VAddr candidate_range_start = vaddr_start;

    // Iterate existing mappings with increasing base address to find the
    // smallest address at which a memory chunk of \p size bytes is still
    // available for mapping.
    for (auto& addr_mapping : virtual_memory) {

        auto mapping_vaddr_start = addr_mapping.first;
        auto mapping_size = addr_mapping.second.size;

        // Ignore any mappings which don't even intersect with the candidate range
        if (mapping_vaddr_start + mapping_size < candidate_range_start)
            continue;

        // If the mapped range starts before our candidate range ends, move "start" behind and check the next mapping
        if (mapping_vaddr_start < candidate_range_start + size) {
            candidate_range_start = mapping_vaddr_start + mapping_size;
            continue;
        }

        // Otherwise, this may be the range we're looking for!
        break;
    }

    // Ensure the candidate range is within the specified bounds
    if (candidate_range_start + size > vaddr_end)
        return std::nullopt;

    return candidate_range_start;
}

uint8_t Process::ReadPhysicalMemory(PAddr addr) {
    return Memory::ReadLegacy<uint8_t>(interpreter_setup.mem, addr);
}

uint32_t Process::ReadPhysicalMemory32(PAddr addr) {
    return Memory::ReadLegacy<uint32_t>(interpreter_setup.mem, addr);
}

void Process::WritePhysicalMemory(PAddr addr, uint8_t value) {
    Memory::WriteLegacy<uint8_t>(interpreter_setup.mem, addr, value);
}

void Process::WritePhysicalMemory32(PAddr addr, uint32_t value) {
    Memory::WriteLegacy<uint32_t>(interpreter_setup.mem, addr, value);
}

uint32_t Process::ReadMemory32(VAddr addr) {
    return (static_cast<uint32_t>(ReadMemory(addr)) << 0)
           | (static_cast<uint32_t>(ReadMemory(addr+1)) << 8)
           | (static_cast<uint32_t>(ReadMemory(addr+2)) << 16)
           | (static_cast<uint32_t>(ReadMemory(addr+3)) << 24);
}

void Process::WriteMemory32(VAddr addr, uint32_t value) {
    WriteMemory(addr    ,  value        & 0xFF);
    WriteMemory(addr + 1, (value >>  8) & 0xFF);
    WriteMemory(addr + 2, (value >> 16) & 0xFF);
    WriteMemory(addr + 3,  value >> 24);
}

MemoryManager& Process::GetPhysicalMemoryManager() {
    return memory_allocator;
}

std::shared_ptr<spdlog::logger> Process::GetLogger() {
    return GetOS().logger;
}

EmuProcess::EmuProcess(OS& os, Interpreter::Setup& setup, uint32_t pid, std::shared_ptr<CodeSet> codeset, MemoryManager& memory_allocator)
    : Process(os, os.activity.GetSubActivity(codeset->app_name), setup, pid, memory_allocator), codeset(codeset) {

    switch (os.settings.get<Settings::CPUEngineTag>()) {
    case Settings::CPUEngine::NARMive:
        processor = Interpreter::CreateInterpreter(setup);
        break;

    }
}

EmuProcess::~EmuProcess() {
    // Delete TLS slots of EmuThreads to avoid dangling references to the earlier-cleared tls_manager
    for (auto& thread : threads) {
        dynamic_cast<EmuThread&>(*thread).tls.addr = 0;
    }
}

void EmuProcess::OnVirtualMemoryMapped(PAddr phys_addr, uint32_t size, VAddr vaddr) {
    processor->OnVirtualMemoryMapped(phys_addr, size, vaddr);
}

void EmuProcess::OnVirtualMemoryUnmapped(VAddr vaddr, uint32_t size) {
    processor->OnVirtualMemoryUnmapped(vaddr, size);
}

FakeProcess::FakeProcess(OS& os, Interpreter::Setup& setup, uint32_t pid, std::string_view name) : Process(os, os.activity.GetSubActivity(name), setup, pid, os.memory_system()) {
    this->name = name;
}

void FakeProcess::OnVirtualMemoryMapped(PAddr, uint32_t, VAddr) {
    // Do nothing
}

void FakeProcess::OnVirtualMemoryUnmapped(VAddr, uint32_t) {
    // Do nothing
}

void FakeProcess::AttachThread(std::shared_ptr<FakeThread> thread) {
    threads.push_back(thread);
    GetOS().RegisterToScheduler(thread);
}

FakeDebugProcess::FakeDebugProcess(OS& os, Interpreter::Setup& setup, ProcessId pid)
    : Process(os, os.activity.GetSubActivity("FakeDebugProcess"), setup, pid, os.memory_system()),
      thread(new FakeDebugThread(*this)) {
    // Do nothing
    threads.push_back(thread);
}

CodeSet::CodeSet(const CodeSetInfo& info)
    : app_name{}, text_vaddr(info.text_start), ro_vaddr(info.ro_start),
      data_vaddr(info.data_start), bss_size(info.data_size - info.data_pages) {
    ranges::copy(info.app_name, app_name);
}

CodeSet::~CodeSet() {
    // TODO: Deallocate memory regions!
}

static PAddr ApplicationMemoryStart(const Settings::Settings&) {
    return 0x20000000;
}

static PAddr ApplicationMemorySize(const Settings::Settings& settings) {
    switch (settings.get<Settings::AppMemType>()) {
    case 0: return 0x04000000;
    case 3: return 0x05000000;
    case 7: return 0x0b200000;
    }
    throw std::runtime_error("Unknown APPMEMTYPE");
}

static PAddr SysMemoryStart(const Settings::Settings& settings) {
    switch (settings.get<Settings::AppMemType>()) {
    case 0: return 0x24000000;
    case 3: return 0x25000000;
    case 7: return 0x2b200000;
    }
    throw std::runtime_error("Unknown APPMEMTYPE");
}

static PAddr SysMemorySize(const Settings::Settings& settings) {
    switch (settings.get<Settings::AppMemType>()) {
    case 0: return 0x02c00000;
    case 3: return 0x01c00000;
    case 7: return 0x02e00000;
    }
    throw std::runtime_error("Unknown APPMEMTYPE");
}

static PAddr BaseMemoryStart(const Settings::Settings& settings) {
    switch (settings.get<Settings::AppMemType>()) {
    case 0: return 0x26c00000;
    case 3: return 0x26c00000;
    case 7: return 0x2e000000;
    }
    throw std::runtime_error("Unknown APPMEMTYPE");
}

static PAddr BaseMemorySize(const Settings::Settings& settings) {
    switch (settings.get<Settings::AppMemType>()) {
    case 0: return 0x01400000;
    case 3: return 0x01400000;
    case 7: return 0x02000000;
    }
    throw std::runtime_error("Unknown APPMEMTYPE");
}

const uint32_t num_firm_modules = 5;

// TODO: The 3DS ABI guarantees that process IDs start at 0, since the PM
//       module sets the resource limits for the FIRM modules during boot by
//       referring to them via their PIDs (starting from zero). However,
//       process IDs reported to GDB must be non-zero. Two possible workarounds
//       come to mind for this: Either we offset all reported PIDs by one to
//       have reported PIDs start at 1, or we replace PID 0 with a magic number
//       when reporting it to the debugger.
// NOTE: Since FIRM module PIDs need to start at 0 but the first processes we
//       launch are FakeDebugProcess and BootThread, the first PIDs we assign
//       are the number of FIRM modules and the one after, after which next_pid
//       jumps back to zero.
//       See MakeNewProcessId for details.
//       TODO: Instead of this workaround, we should just not launch
//             FakeDebugProcess before the FIRM modules.
OS::OS( Profiler::Profiler& profiler, Settings::Settings& settings,
        Interpreter::Setup& setup_, LogManager& log_manager,
        AudioFrontend& audio, PicaContext& pica, EmuDisplay::EmuDisplay& display)
    : hypervisor(settings, audio),
      next_pid(num_firm_modules),
      internal_memory_owner(std::make_shared<MemoryBlockOwner>()),
      memory_regions {
        MemoryManager { ApplicationMemoryStart(settings), ApplicationMemorySize(settings) },
        MemoryManager { SysMemoryStart(settings), SysMemorySize(settings) },
        MemoryManager { BaseMemoryStart(settings), BaseMemorySize(settings) }
      },
      profiler(profiler),
      activity(profiler.GetActivity("OS")),
      pica_context(pica),
      display(display),
      settings(settings),
      setup(setup_),
      log_manager(log_manager),
      logger(log_manager.RegisterLogger("OS")) {
    logger->set_pattern("[%T.%e] [%n] [%l] %v");
}

OS::~OS() {
    // Threads/processes typically hold circular references to each other, so
    // we can't rely on reference counting for cleanup. Instead, terminate them
    // explicitly.
    logger->info("Cleaning up processes for OS shutdown");
    while (!process_handles.empty()) {
        // Find the first process with a non-empty thread list and close its threads
        auto proc_it = ranges::find_if(process_handles, [](auto& proc) { return !proc.second->threads.empty(); });
        if (proc_it == process_handles.end()) {
            // The only processes with empty thread lists still listed in the
            // process table are those that were just created before calling
            // SVCRun. Remove these explicitly and verify they were the last.
            proc_it = process_handles.begin();
            while (proc_it != process_handles.end() && proc_it->second->status == Process::Status::Created) {
                // This process was created but SVCRun hasn't been called yet.
                // Hence, just remove it from the process list
                proc_it = process_handles.erase(proc_it);
            }
            ValidateContract(process_handles.empty());
            continue;
        }

        auto& proc = *proc_it->second;
        while (!proc.threads.empty()) {
            auto threads_left = proc.threads.size();
            auto thread = proc.threads.front();
            ExitThread(*thread);
            TriggerThreadDestruction(std::move(thread));

            // NOTE: TriggerThreadDestruction already destroyed the process if
            //       this was the last thread, so we mustn't use its local
            //       reference to check the exit condition
            if (threads_left == 1) {
                break;
            }
        }

        // // Also drop any self-references
        // parent_process->handle_table.CloseHandle(Handle{0xFFFF8001});

    }

    ValidateContract(debug_process.use_count() == 1);
    while (!debug_process->threads.empty()) {
        auto threads_left = debug_process->threads.size();
        auto thread = debug_process->threads.front();
        ExitThread(*thread);
        TriggerThreadDestruction(std::move(thread));

        // NOTE: TriggerThreadDestruction already destroyed the process if
        //       this was the last thread, so we mustn't use its local
        //       reference to check the exit condition
        if (threads_left == 1) {
            break;
        }
    }
    debug_process.reset(); // TODO: Not needed
}

std::pair<std::unique_ptr<OS>, std::unique_ptr<::ConsoleModule>> OS::Create(Settings::Settings& settings, Interpreter::Setup& setup, LogManager& log_manager, Profiler::Profiler& profiler, AudioFrontend& audio, PicaContext& pica, EmuDisplay::EmuDisplay& display) {
    auto&& os = std::make_unique<OS>(profiler, settings, setup, log_manager, audio, pica, display);
    auto&& console_module = std::unique_ptr<::ConsoleModule>(new ConsoleModule(*os));
    return std::make_pair(std::move(os), std::move(console_module));
}

template<typename... Args>
SVCFuture<Args...> MakeFuture(Args... args) {
    return std::make_tuple(args...);
}

SVCFuture<OS::Result,uint32_t> OS::SVCControlProcessMemory(Thread& source, Process& process, uint32_t addr0, uint32_t addr1, uint32_t size, uint32_t operation, MemoryPermissions permissions) {
    if (&source.GetParentProcess() != &process && (operation < 4 || operation > 6)) {
        throw Mikage::Exceptions::Invalid("Invalid memory control operation attempted across processes");
    }

    if (Meta::to_underlying(permissions) & Meta::to_underlying(MemoryPermissions::Exec) && operation != 6) {
        throw Mikage::Exceptions::Invalid("Invalid MemoryOperation with executable permissions");
    }

    // NOTE: The memory region flags (mask 0x300) are only used for process id 1 (loader)

    switch (operation & 0xFF) {
    case 1: // Free memory block
    {
        source.GetLogger()->warn("{}SVCControlMemory: Stubbing FREE operation", ThreadPrinter{source});
//        TODOImplement();
//         GetParentProcess().UnmapVirtualMemory(
        return MakeFuture(RESULT_OK, uint32_t{0});
    }

    case 3: // Allocate new memory block
    {
        auto& memory_manager = Meta::invoke([&]() -> MemoryManager& {
            // TODO: Panic if the current PID is not 1 (i.e. not the loader process)
            switch (operation & 0xF00) {
            case 0x000:
                return process.GetPhysicalMemoryManager();

            case 0x100:
                return memory_app();

            case 0x200:
                return memory_system();

            case 0x300:
                return memory_base();

            default:
                throw Mikage::Exceptions::Invalid("ControlMemory: Invalid memory region");
            }
        });

        // TODO: CARDBOAR seems to assume whatever virtual address we return
        //       from this is larger than 0x1433200 (heap start + shared font
        //       size), since it expects the target vaddress of a
        //       MapMemoryBlock to always be 0x14000000. This may be because
        //       all the memory manager is expected to have allocated all
        //       "lower" memory at that point already, such that LINEAR
        //       addresses would always be at a high vaddress.
        auto block_address_opt = memory_manager.AllocateBlock(static_pointer_cast<Process>(process.shared_from_this()), size);
        if (!block_address_opt) {
            throw Mikage::Exceptions::Invalid(  "Failed to allocate physical memory: Requested {:#x} bytes, only {:#x}/{:#x} available",
                                                size, memory_manager.TotalSize() - memory_manager.UsedMemory(), memory_manager.TotalSize());
        }

        // Set virtual address region according to the LINEAR flag
        // TODO: For LINEAR memory, firmware 8.x titles and higher use the address range 0x30000000-0x38000000(-0x40000000 on New3DS)
        // NOTE: For LINEAR memory, we impose strict bounds, since the mapping between physical and virtual memory must be unique!
        VAddr vaddr_start, vaddr_end;
        // TODO: Not sure why this was dependent on memory type before. Seems wrong!
        #if 0
        switch (settings.get<Settings::AppMemType>()) {
        case 0:
        case 3:
        #endif
            vaddr_start = (operation & 0x10000) ? (process.linear_base_addr + (*block_address_opt - Memory::FCRAM::start)) : 0x08000000;
            vaddr_end = vaddr_start + ((operation & 0x10000) ? size : 0x08000000);
        #if 0
            break;

        case 6:
            vaddr_start = (operation & 0x10000) ? (0x30000000 + (*block_address_opt - Memory::FCRAM::start)) : 0x08000000;
            vaddr_end = vaddr_start + ((operation & 0x10000) ? size : 0x10000000);
            break;

        default:
            throw std::runtime_error("Unknown appmemtype");
        }
        #endif
        source.GetLogger()->info("{}Checking if VAddr range [{:#010x}:{:#010x}] is still available..",
                                 ThreadPrinter{source}, vaddr_start, vaddr_end);
        // TODO: It seems the loader process passes a non-zero address here,
        //       expecting memory to be allocated and mapped at the specified
        //       virtual address. I'm not sure to what extend this is the
        //       correct behavior, and whether or not it it somehow limited to
        //       the loader process
//         assert(addr0 != 0 || source.GetParentProcess().GetId() == 3); // TODO: Loader PID is supposed to be 1 as per ABI!
        auto vaddr_opt = (addr0 == 0) ? process.FindAvailableVirtualMemory(size, vaddr_start, vaddr_end)
                                    : process.FindAvailableVirtualMemory(size, addr0, addr0 + size);
        if (!vaddr_opt) {
            throw Mikage::Exceptions::Invalid("Failed to reserve virtual memory address space");
        }

        if (!process.MapVirtualMemory(*block_address_opt, size, *vaddr_opt, permissions)) {
            throw Mikage::Exceptions::Invalid("Failed to map virtual memory");
        }

        Reschedule(source.GetPointer());
        return MakeFuture(RESULT_OK, *vaddr_opt);
    }

    case 4: // Map memory from addr1 (in the given process) to addr0 (in the active process) TODO: Actually, it does map within the given process. It's used to constrain permissions by RO!
    {
        auto paddr_opt = process.ResolveVirtualAddr(addr1);
        if (!paddr_opt) {
            throw Mikage::Exceptions::Invalid("Input virtual address {:#x} not mapped", addr1);
        }

        auto& target_process = process;

        auto vaddr_opt = target_process.FindAvailableVirtualMemory(size, addr0, addr0 + size);
        if (/*addr0 == addr1 && */!vaddr_opt && &source.GetParentProcess() != &process) {
            // This is used by RO to restrict the permissions in CRO-loading client applications.
            // Unmap the given range and remap with the updated permissions hence.

            // TODO: Does this really just override whatever mapping was here previously?
            target_process.UnmapVirtualMemory(addr0, size);

            // Retry
            vaddr_opt = target_process.FindAvailableVirtualMemory(size, addr0, addr0 + size);
        }
        if (!vaddr_opt) {
            throw Mikage::Exceptions::Invalid("Target virtual memory range [{:#x},{:#x}] for mapping not available", addr0, addr0 + size);
        }

        if (!target_process.MapVirtualMemory(*paddr_opt, size, *vaddr_opt, permissions)) {
            throw Mikage::Exceptions::Invalid("Mapping memory failed");
        }

        Reschedule(source.GetPointer());
        // TODO: What should we return in this case?
        return MakeFuture(RESULT_OK, uint32_t{0});
    }

    case 5: // Unmap memory
    {
        if (!process.UnmapVirtualMemory(addr0, size)) {
            throw Mikage::Exceptions::Invalid("Failed to unmap memory");
        }
        return MakeFuture(RESULT_OK, uint32_t{0});
    }

    case 6: // Protect memory based on addr0
    {
        source.GetLogger()->info("Reprotecting virtual memory region [{:#x},{:#x}]", addr0, addr0 + size);
        auto paddr_opt = process.ResolveVirtualAddr(addr0);
        if (!paddr_opt) {
            throw Mikage::Exceptions::Invalid("Input virtual address {:#x} not mapped", addr0);
        }
        if (!process.UnmapVirtualMemory(addr0, size)) {
            throw Mikage::Exceptions::Invalid("Failed to unmap memory");
        }
        auto vaddr_opt = process.FindAvailableVirtualMemory(size, addr0, addr0 + size);
        ValidateContract(vaddr_opt);
        auto success = process.MapVirtualMemory(*paddr_opt, size, *vaddr_opt, permissions);
        ValidateContract(success);


        Reschedule(source.GetPointer());
        return MakeFuture(RESULT_OK, addr0);
    }

    default:
        throw Mikage::Exceptions::NotImplemented("MemoryOperation {:#x} not implemented", operation);
    }
}

SVCFuture<OS::Result,uint32_t> OS::SVCControlMemory(Thread& source, uint32_t addr0, uint32_t addr1, uint32_t size, uint32_t operation, uint32_t permissions) {
    source.GetLogger()->info("{}SVCControlMemory: addr0={:#010x}, addr1={:#010x}, size={:#x}, op={:#x}, perm={:#x}",
                             ThreadPrinter{source}, addr0, addr1, size, operation, permissions);
    return SVCControlProcessMemory(source, source.GetParentProcess(), addr0, addr1, size, operation, MemoryPermissions { permissions });
}

SVCFuture<OS::Result,HandleTable::Entry<Thread>> OS::SVCCreateThread(Thread& source, uint32_t entry, uint32_t arg, uint32_t stack_top, uint32_t priority, uint32_t processor_id) {
    source.GetLogger()->info("{}SVCCreateThread, entry={:#010x}, arg={:#x}, stack={:#x}, prio={:#x}, proc_id={:#x}",
                             ThreadPrinter{source}, entry, arg, stack_top, priority, processor_id);

    auto& owner = dynamic_cast<EmuProcess&>(source.GetParentProcess());

    // TODO: Which FPSCR value should we use?
    auto thread_ptr = owner.SpawnThread(priority, entry, stack_top, arg, 0x03c00000);
    thread_ptr->name = thread_ptr->GetName() + std::to_string(thread_ptr->GetId());

    auto thread = source.GetProcessHandleTable().CreateHandle<Thread>(thread_ptr, MakeHandleDebugInfo());
    threads.push_back(thread_ptr);

    // TODO: XDS seems to just keep going without a reschedule, so we'll do the same for now. We should consider re-enabling this, though!
    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK, thread);
}

void OS::ExitThread(Thread& thread) {
    if (thread.status == Thread::Status::Stopped) {
        return;
    }

    // Find all owned mutexes and release them
    // TODO: Should we also release any semaphore counts?
    for (auto& entry : thread.GetProcessHandleTable().table) {
        auto mutex = std::dynamic_pointer_cast<Mutex>(entry.second);

        if (mutex && mutex->IsOwner(thread.GetPointer())) {
            mutex->Release(); // TODO: Should release until ready!!!
            if (!mutex->IsReady()) {
                throw std::runtime_error("Need recursive mutex release on thread exit");
            }

            OnResourceReady(*mutex);
        }
    }

    // TODO: Deallocate Thread Local Storage

    // Unregister from all wait objects to make sure we don't run into cyclic dependencies
    for (auto& notifier : thread.wait_list)
        notifier->Unregister(thread.GetPointer());

    thread.GetProcessHandleTable().SetCurrentThread(nullptr); // release internal reference

    thread.control->PrepareForExit();

    thread.wait_list.clear();

    thread.status = Thread::Status::Stopped;

    // Resume the thread one final time so that it can cleanly unwind
    // TODO: Integrate this into PrepareForExit?
    // TODO CRITICAL: processor dynamic assumes that the running thread is given by setup.os->active_thread !!!
    auto prev_active_thread = std::exchange(active_thread, &thread);
    thread.control->ResumeFromScheduler();
    active_thread = prev_active_thread;

    ready_queue.remove_if([ptr=thread.GetPointer()](auto elem) { return elem.lock() == ptr; });
//     priority_queue.remove_if([ptr=source.GetPointer()](auto elem) { return elem.lock() == ptr; });

    OnResourceReady(thread);
}

SVCEmptyFuture OS::SVCExitThread(Thread& source) {
    source.GetLogger()->info("{}SVCExitThread", ThreadPrinter{source});

    ExitThread(source);

    Reschedule(source.GetPointer());

    return MakeFuture(nullptr);
}

SVCEmptyFuture OS::SVCSleepThread(Thread& source, int64_t duration) {
    // TODO: In Citra, OoT3D calls this with 0 nanoseconds, but we call it with 10000....
    source.GetLogger()->info("{}SVCSleepThread for {} nanoseconds", ThreadPrinter{source}, duration);

    source.timeout_at = OS::GetTimeInNanoSeconds() + duration;
    source.status = Thread::Status::WaitingForTimeout;
    ready_queue.remove_if([ptr=source.GetPointer()](auto elem) { return elem.lock() == ptr; });
//     priority_queue.remove_if([ptr=source.GetPointer()](auto elem) { return elem.lock() == ptr; });
    waiting_queue.push_back(source.GetPointer());

    return MakeFuture(nullptr);
}


SVCFuture<OS::Result> OS::SVCRun(Thread& source, Handle process_handle, const OS::StartupInfo& startup) {
    source.GetLogger()->info("{}SVCRun: Running process {}, stack size {:#x}", ThreadPrinter{source}, HandlePrinter{source,process_handle}, startup.stack_size);

    // FakeProcesses automatically run on creation
    auto fake_process = source.GetProcessHandleTable().FindObject<FakeProcess>(process_handle, true);
    if (fake_process) {
        if (auto wrapped_fake_process = std::dynamic_pointer_cast<WrappedFakeProcess>(fake_process)) {
            wrapped_fake_process->SpawnMainThread();
        }
        fake_process->status = Process::Status::Running;
        return MakeFuture(RESULT_OK);
    }

    // Explicitly requesting EmuProcess here because spawning FakeProcesses like this can only cause problems down the road.
    auto process = source.GetProcessHandleTable().FindObject<EmuProcess>(process_handle);
    if (process->status != Process::Status::Created) {
        throw Mikage::Exceptions::Invalid("Called SVCRun on a process that was already active");
    }

    // In its own handle table, the new Process is accessible through a fixed constant
    // NOTE: This was moved from SVCCreateProcess, since it's easier to unwind
    //       processes in Created status if they don't have self-references.
    process->handle_table.CreateEntry<Process>(Handle{0xFFFF8001}, process);

    // Allocate stack memory for the main thread
    // NOTE: Retail applications expect the stack to end at 0x10000000
    auto stack_paddr_opt = source.GetParentProcess().GetPhysicalMemoryManager().AllocateBlock(process, startup.stack_size);
    auto stack_vaddr_opt = process->FindAvailableVirtualMemory(startup.stack_size, 0x10000000 - startup.stack_size, 0x10000000);
    process->MapVirtualMemory(*stack_paddr_opt, startup.stack_size, *stack_vaddr_opt, MemoryPermissions::ReadWrite);

    // TODO: argc and argv not supported yet!
    if (startup.argc != 0)
        SVCBreak(source, BreakReason::Panic);

    // Spawn main thread (in SVCRun, the thread entry point is always the beginning of the .text segment!)
    // TODO: Which FPSCR value should we use?
    /*threads.push_back*/(process->SpawnThread(startup.priority, process->codeset->text_vaddr, *stack_vaddr_opt + startup.stack_size, 0, 0x03c00010));
    process->status = Process::Status::Running;

    // Wait for debugger to attach...
    if (settings.get<Settings::ConnectToDebugger>() &&
        process->GetId() == settings.get<Settings::AttachToProcessOnStartup>()) {

        // Notify launched process to the debugger
        source.GetLogger()->info("{}SVCRun: Signalling debugger.. about process/thread with id {:#x}/{:#x}",
                                 ThreadPrinter{source}, process->GetId(), threads.back().lock()->GetId());
//        debug_process->thread->ProcessLaunched(*process, *gdbstub);


        // It's often useful to be able to attach to a process immediately when
        // it's being started. Unfortunately, GDB doesn't provide any support
        // for this and instead requires explicit attaching to a process once
        // it's already running. To workaround this, we wait for a debugger to
        // attach for each created process.

        auto attach_info = std::make_shared<Interpreter::WrappedAttachInfo>();
        attach_info->data = std::make_unique<Interpreter::AttachInfo>(Interpreter::AttachInfo{process->GetId()});
//        std::unique_lock<std::mutex> lock(attach_info->condvar_mutex);
        // os_console->WaitingForAttach(attach_info); // TODO> Implement this so that we can skip the debugger attaching
        gdbstub->OfferAttach(attach_info);
        attach_info->AwaitProcessing();
        source.GetLogger()->info("{}Done waiting for debugger to attach", ThreadPrinter{source});
    }

    Reschedule(source.GetPointer());

    return MakeFuture(RESULT_OK);
}

SVCFuture<OS::Result,HandleTable::Entry<Mutex>> OS::SVCCreateMutex(Thread& source, bool lock) {
    source.GetLogger()->info("{}SVCCreateMutex, lock={}", ThreadPrinter{source}, lock);
    auto mutex = source.GetProcessHandleTable().CreateHandle<Mutex>(std::make_shared<Mutex>(lock, source.GetPointer()), MakeHandleDebugInfo());
    source.GetLogger()->info("{}SVCCreateMutex output handle={}", ThreadPrinter{source}, HandlePrinter{source,mutex.first});
    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK, mutex);
}

SVCFuture<OS::Result> OS::SVCReleaseMutex(Thread& source, Handle mutex_handle) {
    source.GetLogger()->info("{}SVCReleaseMutex, handle={}", ThreadPrinter{source}, HandlePrinter{source,mutex_handle});
    auto mutex = source.GetProcessHandleTable().FindObject<Mutex>(mutex_handle);
    if (!mutex || !mutex->IsOwner(source.GetPointer())) {
        throw std::runtime_error("Mutex not owned by the current thread");
    }

    mutex->Release();
    if (mutex->IsReady()) {
        OnResourceReady(*mutex);
    }

    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK);
}

SVCFuture<OS::Result,HandleTable::Entry<Semaphore>> OS::SVCCreateSemaphore(Thread& source, int32_t initial_count, int32_t max_count) {
    auto semaphore = source.GetProcessHandleTable().CreateHandle(std::make_shared<Semaphore>(initial_count, max_count), MakeHandleDebugInfo());
    source.GetLogger()->info("{}SVCCreateSemaphore, initial={:#x}, max={:#x} -> {}", ThreadPrinter{source}, initial_count, max_count, HandlePrinter{source,semaphore.first});
    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK, semaphore);
}

SVCFuture<OS::Result,int32_t> OS::SVCReleaseSemaphore(Thread& source, Semaphore& sema, int32_t release_count) {
    source.GetLogger()->info("{}SVCReleaseSemaphore, sema={}, release_count={:#x} (available={:#x})",
                             ThreadPrinter{source}, ObjectRefPrinter{sema}, release_count, sema.available_count);

    auto old_count = sema.available_count;
    auto result = sema.Release(release_count);
    OnResourceReady(sema);

    Reschedule(source.GetPointer());
    return MakeFuture(result, old_count);
}

SVCFuture<OS::Result,HandleTable::Entry<Event>> OS::SVCCreateEvent(Thread& source, ResetType type) {
    source.GetLogger()->info("{}SVCCreateEvent, type={}", ThreadPrinter{source}, static_cast<uint32_t>(type));

    if (type != ResetType::OneShot && type != ResetType::Sticky) {
        // Unsupported reset type. TODO: Not sure if Pulse makes any sense for events!
        SVCBreak(source, BreakReason::Panic);
    }

    auto event = source.GetProcessHandleTable().CreateHandle<Event>(std::make_shared<Event>(type), MakeHandleDebugInfo());
    source.GetLogger()->info("{}SVCCreateEvent output handle={}", ThreadPrinter{source}, HandlePrinter{source,event.first});
    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK, event);
}

SVCFuture<OS::Result> OS::SVCSignalEvent(Thread& source, Handle event_handle) {
    source.GetLogger()->info("{}SVCSignalEvent, handle={}", ThreadPrinter{source}, HandlePrinter{source,event_handle});
    auto event = source.GetProcessHandleTable().FindObject<Event>(event_handle, true);
    if (!event) {
        throw Mikage::Exceptions::Invalid("Attempted to signal invalid event");
    }

    hypervisor.OnEventSignaled(source, source.GetParentProcess().GetId(), event_handle);

    event->SignalEvent();
    OnResourceReady(*event);
    // TODO: For OneShot events, should event acquisition succeed when a thread
    //       started to wait for an event *after* is has been signalled but not
    //       immediately been acquired? This should be tested by signalling an
    //       event and then waiting for it on the same thread.
    // TODO: XDS seems to just keep going without a reschedule, so we'll do the same for now. We should consider re-enabling this, though!
//     Reschedule(source.GetPointer());
    Reschedule(source.GetPointer()); // Required by Rhythm Thief
    return MakeFuture(RESULT_OK);
}

SVCFuture<OS::Result> OS::SVCClearEvent(Thread& source, Handle event_handle) {
    source.GetLogger()->info("{}SVCClearEvent, handle={}", ThreadPrinter{source}, HandlePrinter{source,event_handle});
    auto event = source.GetProcessHandleTable().FindObject<Event>(event_handle, true);
    if (!event) {
        throw Mikage::Exceptions::Invalid("Passed invalid event handle to SVCClearEvent");
    }

    // TODO: Consider adding an assert (or at least a warning) against clearing a OneShot event!
    if (event->type == ResetType::OneShot) {
        source.GetLogger()->warn("{}Clearring a OneShot event. Not uncommon for system modules, but seems unorthodox", ThreadPrinter{source});
    }

    event->ResetEvent();
    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK);
}

SVCFuture<OS::Result,HandleTable::Entry<Timer>> OS::SVCCreateTimer(Thread& source, ResetType type) {
    source.GetLogger()->info("{}SVCCreateTimer, type={}", ThreadPrinter{source}, static_cast<uint32_t>(type));

    if (type != ResetType::OneShot && type != ResetType::Sticky && type != ResetType::Pulse) {
        // Unsupported reset type.
        SVCBreak(source, BreakReason::Panic);
    }

    auto timer = source.GetProcessHandleTable().CreateHandle(std::make_shared<Timer>(type), MakeHandleDebugInfo());
    source.GetLogger()->info("{}SVCCreateTimer output handle={}", ThreadPrinter{source}, HandlePrinter{source,timer.first});
    active_timers.push_back(timer.second);
    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK, timer);
}

SVCFuture<OS::Result> OS::SVCSetTimer(Thread& source, Timer& timer, int64_t initial, int64_t period) {
    source.GetLogger()->info("{}SVCSetTimer: timer={}, initial={:#x}, period={:#x}",
                             ThreadPrinter{source}, ObjectRefPrinter{timer}, initial, period);

    if (initial < 0 || period < 0)
        SVCBreak(source, BreakReason::Panic);

    timer.Run(GetTimeInNanoSeconds() + initial, period);
    if (timer.Expired(GetTimeInNanoSeconds()))
        OnResourceReady(timer);

    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK);
}

SVCFuture<OS::Result,HandleTable::Entry<SharedMemoryBlock>> OS::SVCCreateMemoryBlock(Thread& source, VAddr addr, uint32_t size, uint32_t owner_perms, uint32_t other_perms) {
    source.GetLogger()->info("{}SVCCreateMemoryBlock: addr={:#010x}, size={:#x}, owner_perms={:#x}, other_perms={:#x}",
                             ThreadPrinter{source}, addr, size, owner_perms, other_perms);

    // TODO: Implement permissions

    // If the given address is zero, allocate new memory for this process
    auto& process = source.GetParentProcess();
    PAddr block_addr = Meta::invoke([&] {
        if (addr == 0) {
            // Allocate physical memory
            // TODO: This must be LINEAR memory!
            auto block_address_opt = process.GetPhysicalMemoryManager().AllocateBlock(std::static_pointer_cast<Process>(process.shared_from_this()), size);
            if (!block_address_opt)
                SVCBreak(source, BreakReason::Panic);
            return *block_address_opt;
        } else {
            // Share memory that is already allocated
            // TODO: Make sure there is enough contiguous memory available at the specified address
            // TODO: Really do this now!

            auto phys_addr_opt = source.GetParentProcess().ResolveVirtualAddr(addr);
            if (!phys_addr_opt)
                SVCBreak(source, BreakReason::Panic);

            return *phys_addr_opt;
        }
    });

    auto block = source.GetProcessHandleTable().CreateHandle<SharedMemoryBlock>(std::make_shared<SharedMemoryBlock>(block_addr, size, (addr == 0)), MakeHandleDebugInfo());
    if (addr == 0) {
        // TODO: Should this indeed only be done for addr == 0?
        process.GetPhysicalMemoryManager().TransferOwnership(std::static_pointer_cast<Process>(process.shared_from_this()), block.second, block_addr, size);
    }

    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK, block);
}

SVCFuture<OS::Result> OS::SVCMapMemoryBlock(Thread& source, Handle block_handle, VAddr addr, MemoryPermissions caller_perms, MemoryPermissions other_perms) {
    source.GetLogger()->info("{}SVCMapMemoryBlock: handle={:#x}, addr={:#010x}, caller_perms={:#x}, other_perms={:#x}",
                             ThreadPrinter{source}, block_handle.value /* TODO: HandlePrinter! */, addr,
                             Meta::to_underlying(caller_perms), Meta::to_underlying(other_perms));

    auto block = source.GetProcessHandleTable().FindObject<SharedMemoryBlock>(block_handle);
    if (!block) {
        throw std::runtime_error(fmt::format("Invalid block handle {} for SharedMemoryBlock", HandlePrinter{source,block_handle}));
    }

    if (addr == 0) {
        // Map LINEAR memory block (TODOTEST)

        if (block->phys_address < Memory::FCRAM::start || block->phys_address + block->size >= Memory::FCRAM::end) {
            throw std::runtime_error("Invariant violated: Shared memory block is located outside FCRAM");
        }

        // TODO: Should map to 0x10000000 - 0x14000000 instead, maybe?
        VAddr linear_region_start = 0x14000000;
        VAddr target_addr = block->phys_address - Memory::FCRAM::start + linear_region_start;

        auto addr_opt = source.GetParentProcess().FindAvailableVirtualMemory(block->size, target_addr, target_addr + block->size);
        if (!addr_opt) {
            throw std::runtime_error("Failed to map shared memory block in LINEAR virtual memory");
        }
        source.GetLogger()->info("{}Address was zero, so I looked up virtual address {:#x} for physical address {:#x}; {:#x} bytes",
                                ThreadPrinter{source}, *addr_opt, block->phys_address, block->size);
        addr = *addr_opt;
    }

    // TODO: Implement permissions

    if (!source.GetParentProcess().MapVirtualMemory(block->phys_address, block->size, addr, caller_perms)) {
        throw Mikage::Exceptions::Invalid(  "Failed to map physical memory range [{:#x};{:#x}] to virtual memory [{:#x};{:#x}]",
                                            block->phys_address, block->phys_address + block->size, addr, addr + block->size);
    }

    // TODO: When directly launching Mii Maker with LLE ns, the shared font doesn't finish loading in time (as indicated by its first two bytes). It works when launched from the Home Menu, though

    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK);
}

SVCFuture<OS::Result> OS::SVCUnmapMemoryBlock(Thread& source, SharedMemoryBlock& block, VAddr addr) {
    source.GetLogger()->info("{}SVCUnmapMemoryBlock: addr={:#010x}", ThreadPrinter{source}, addr);

    if (!source.GetParentProcess().UnmapVirtualMemory(addr, block.size)) {
        throw Mikage::Exceptions::Invalid(  "Failed to unmap shared block virtual memory range [{:#x};{:#x}]",
                                            addr, addr + block.size);
    }

    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK);
}

SVCFuture<OS::Result,HandleTable::Entry<AddressArbiter>> OS::SVCCreateAddressArbiter(Thread& source) {
    source.GetLogger()->info("{}SVCCreateAddressArbiter", ThreadPrinter{source});

    auto arbiter = source.GetProcessHandleTable().CreateHandle(std::make_shared<AddressArbiter>(), MakeHandleDebugInfo());

    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK, arbiter);
}

SVCFuture<PromisedResult> OS::SVCArbitrateAddress(Thread& source, Handle arbiter_handle, uint32_t address, ArbitrationType type, uint32_t value, int64_t timeout) {
    source.GetLogger()->info("{}SVCArbitrateAddress: handle={}, type={:#x}, addr={:#010x}, value={:#x}, timeout={:#x}",
                             ThreadPrinter{source}, HandlePrinter{source,arbiter_handle}, static_cast<uint32_t>(type),
                             address, value, timeout);

    // Report success unless we encounter an error later on
    source.promised_result = RESULT_OK;

    switch (type) {
        case OS::ArbitrationType::Signal:
        {
            // Resume up to "value" threads that were waiting on an arbiter signal;
            // start with the highest prioritized ones.

            // Reject pathological cases
//            if (value == 0)
//                break;
//             do {

            // Declare some helper functions
            auto lock_weak_thread_ptr = [](std::weak_ptr<Thread> weak_thread) {
                return weak_thread.lock();
            };
            // TODO: Should probably only wake those threads that wait on the given arbiter!!!
            auto waiting_for_arbitration = [address](std::shared_ptr<Thread> thread) {
                return thread
                    && thread->status == Thread::Status::WaitingForArbitration
                    && thread->arbitration_address == address;
            };
            auto compare_by_priority = [](std::shared_ptr<Thread> t1, std::shared_ptr<Thread> t2) {
                return t1->GetPriority() > t2->GetPriority();
            };

            // Gather list of threads waiting for an arbiter signal
            std::vector<std::shared_ptr<Thread>> threads_waiting;
            boost::copy(threads | boost::adaptors::transformed(lock_weak_thread_ptr)
                                | boost::adaptors::filtered(waiting_for_arbitration),
                        std::back_inserter(threads_waiting));

            // Wake up to "value" threads (in particular: if "value" is negative, wake all of them)
            //value = std::min<size_t>(value, threads_waiting.size());
            auto threads_to_wake = std::min<size_t>(value, threads_waiting.size());

            // Get the "value" threads with highest priority (=lowest priority value)
            boost::nth_element(threads_waiting, threads_waiting.begin() + threads_to_wake, compare_by_priority);
            for (auto& thread : threads_waiting | boost::adaptors::sliced(0, threads_to_wake)) {
                thread->status = Thread::Status::Ready;
                ready_queue.push_back(thread);
//                 priority_queue.push_back(thread);
                // TODO: Push in priority order!
                // TODO: Currently, this will be followed by a reschedule, due to which this will be moved to the back anyway...
                source.GetLogger()->info("{}Woke {}", ThreadPrinter{source}, ThreadPrinter{*thread});
            }

            source.GetLogger()->info("{}Woke {} threads in total", ThreadPrinter{source}, threads_to_wake);
            value -= threads_to_wake;

            /**
             * Unschedule the current thread if and only if we actually woke up
             * any threads. This restriction seems to be necessary because in
             * Brunswick Pro Bowling, otherwise a worker thread will be
             * unscheduled and the main thread will subsequently enter a
             * stationary loop that never calls any system calls (and as such
             * never gets unscheduled and hence never gives the worker thread a
             * chance to complete).
             */
            // TODO: XDS seems to just keep going without a reschedule, so we'll do the same for now. We should consider re-enabling this, though!
//             if (threads_to_wake > 0)
//                 Reschedule(source.GetPointer());
//             else
//                 RescheduleImmediately(source.GetPointer());
break;
/*            // If the requested number of threads hasn't been waken up yet, reschedule
            if (value != 0 && !(value & 0x80000000))
                Reschedule(source.GetPointer());*/

//             } while (value != 0 && !(value & 0x80000000));

            // TODO: Is an error returned if less threads were woken than requested?
            break;
        }

        default:
        {
            // TODO: Thread-safety!

            auto memory_value = static_cast<uint32_t>(source.ReadMemory(address))
                                | (static_cast<uint32_t>(source.ReadMemory(address+1)) << 8)
                                | (static_cast<uint32_t>(source.ReadMemory(address+2)) << 16)
                                | (static_cast<uint32_t>(source.ReadMemory(address+3)) << 24);

            // TODO: Do we want signed comparison here?
            if (static_cast<int32_t>(memory_value) >= static_cast<int32_t>(value)) {
                source.GetLogger()->info("{}Comparison succeeded ({:#x} vs {:#x}), no need to go to sleep",
                                         ThreadPrinter{source}, memory_value, value);
                break;
            }
            source.GetLogger()->info("{}Comparison failed ({:#x} vs {:#x}), putting thread to sleep",
                                     ThreadPrinter{source}, memory_value, value);

            // Override this later for arbitration types with timeout
            source.timeout_at = -1;

            switch (type) {
                case OS::ArbitrationType::Signal:
                    // Silence compiler warning (this code will never get executed)
                    break;

                case OS::ArbitrationType::Acquire:
                    // Do nothing besides putting the thread to sleep (see below)
                    break;

                case OS::ArbitrationType::DecrementAndAcquire:
                    --memory_value;
                    source.WriteMemory(address    ,  memory_value        & 0xFF);
                    source.WriteMemory(address + 1, (memory_value >>  8) & 0xFF);
                    source.WriteMemory(address + 2, (memory_value >> 16) & 0xFF);
                    source.WriteMemory(address + 3,  memory_value >> 24);
                    break;

                case OS::ArbitrationType::AcquireWithTimeout:
                    source.timeout_at = /*CurrentTime + */ timeout;
                    // TODO: Implement timeout!
                    SVCBreak(source, BreakReason::Panic);
                    break;

                case OS::ArbitrationType::DecrementAndAcquireWithTimeout:
                    --memory_value;
                    source.WriteMemory(address    ,  memory_value        & 0xFF);
                    source.WriteMemory(address + 1, (memory_value >>  8) & 0xFF);
                    source.WriteMemory(address + 2, (memory_value >> 16) & 0xFF);
                    source.WriteMemory(address + 3,  memory_value >> 24);

                    // TODO: Implement timeout!
                    source.timeout_at = /*CurrentTime + */ timeout;
                    SVCBreak(source, BreakReason::Panic);
                    break;
            }

            // Put thread to sleep
            source.arbitration_address = address;
            source.arbitration_handle = arbiter_handle;
            source.status = Thread::Status::WaitingForArbitration;
            ready_queue.remove_if([ptr=source.GetPointer()](auto elem) { return elem.lock() == ptr; });
//             priority_queue.remove_if([ptr=source.GetPointer()](auto elem) { return elem.lock() == ptr; });
            if (source.timeout_at != -1) {
                waiting_queue.push_back(source.GetPointer());
            }

            Reschedule(source.GetPointer());
        }
    }

    // the Signal case handles this on its own
    // TODO: XDS seems to just keep going without a reschedule, so we'll do the same for now. We should consider re-enabling this, though!
//     if (type != OS::ArbitrationType::Signal)
         Reschedule(source.GetPointer()); // NOTE: Possibly required by SenranKaguraShoujotachiNoShinei, which gets stuck on an ArbitrateAddress thread that never yields to a ready thread
    return MakeFuture(PromisedResult{});
}

OS::Result OS::CloseHandle(Thread& source, Handle handle) {
    hypervisor.OnHandleClosed(source.GetParentProcess().GetId(), handle);

    auto use_count = [&]() {
        auto ptr = source.GetProcessHandleTable().FindObject<Object>(handle, true);
        return (ptr ? (ptr.use_count() - 1) : 0);
    }();
    source.GetLogger()->info("{}CloseHandle: handle={} (object use count: {})",
                             ThreadPrinter{source}, HandlePrinter{source,handle}, use_count);
    {
        auto object = source.GetProcessHandleTable().FindObject<Object>(handle, true);

        // TODO: If this handle was a ClientSession, notify the ServerSession about this (it must wake up for the server to close it) TODOTEST
        // TODO: If a Session is closed because both its ClientSession and ServerSession have been closed, wake the ServerPort since a session has become free (TODOTEST: I guess it's sufficient for the ServerSession to become closed!)
        // TODO: ReplyAndReceive must return 0xC920181A for handles that have been waited for but are closed now

        // First off, release any remaining locks on ObserverSubjects
        // TODO: No idea whether we are actually supposed to do this here, since there are explicit release SVCs for this.

        if (auto client_session = std::dynamic_pointer_cast<ClientSession>(object)) {
            if (use_count == 1) {
                source.GetLogger()->info("{}Closed last instance of a ClientSession => waking up server", ThreadPrinter{source});
                // Wake up any threads waiting on the corresponding server session.
                // Remove the client session from the Session object so the server sees we closed this session.
                // (The server will usually close the ServerSession, which will then free up a session slot in the ServerPort.)
                client_session->session->client.reset();
                auto server_session = client_session->session->server.lock();
                if (server_session) {
                    OnResourceReady(*server_session);
                }
            }
        } else if (auto server_session = std::dynamic_pointer_cast<ServerSession>(object)) {
            if (use_count == 1) {
                auto port = server_session->port;
                if (port) {
                    ++port->available_sessions;
                    source.GetLogger()->info("{}Closed last instance of {} => freeing up a session slot in {} (now have {} open sessions)",
                                             ThreadPrinter{source}, ObjectPrinter{server_session}, ObjectPrinter{port}, port->available_sessions);
                    OnResourceReady(*port);

                    // TODO: LLE sm expects this to be signaled: If GetServiceHandle is called on a full port, the reply is withheld until the client port is signaled
                    // TODO: Shouldn't this be done when the clientsession was closed?
                    if (auto client_port = port->port->client.lock()) {
                        OnResourceReady(*client_port);
                    }
                }
            }
        } else if (auto mutex = std::dynamic_pointer_cast<Mutex>(object)) {
            // TODOTEST: Should something like this indeed be done? Perhaps only if this was the last handle in the current process, however?
            if (mutex->IsOwner(source.GetPointer())) {
                mutex->Release();
                OnResourceReady(*mutex);
            }
        } else if (auto process = std::dynamic_pointer_cast<Process>(object)) {
            // TODO: ?
        } else if (auto block = std::dynamic_pointer_cast<SharedMemoryBlock>(object)) {
            if (use_count == 1 && block->owns_memory) {
                FindMemoryRegionContaining(block->phys_address, block->size).DeallocateBlock(block, block->phys_address, block->size);
            }
        } else if (auto codeset = std::dynamic_pointer_cast<CodeSet>(object)) {
            if (use_count == 1) {
                try {
                    const uint32_t page_size = 0x1000;
                    for (auto& mapping : codeset->text_phys) {
                        FindMemoryRegionContaining(mapping.phys_start, mapping.num_pages * page_size).DeallocateBlock(codeset, mapping.phys_start, mapping.num_pages * page_size);
                    }
                    for (auto& mapping : codeset->ro_phys) {
                        FindMemoryRegionContaining(mapping.phys_start, mapping.num_pages * page_size).DeallocateBlock(codeset, mapping.phys_start, mapping.num_pages * page_size);
                    }
                    for (auto& mapping : codeset->data_phys) {
                        FindMemoryRegionContaining(mapping.phys_start, mapping.num_pages * page_size).DeallocateBlock(codeset, mapping.phys_start, mapping.num_pages * page_size);
                    }
                    if (codeset->bss_size) {
                        FindMemoryRegionContaining(codeset->bss_paddr, codeset->bss_size * page_size).DeallocateBlock(codeset, codeset->bss_paddr, codeset->bss_size * page_size);
                    }
                } catch (...) {
                    // TODO: Handle the common case that the CodeSet has transferred its memory to an EmuProcess more cleanly
                }
            }
        }
    }

    // Delete the handle from the table
    source.GetProcessHandleTable().CloseHandle(handle);
    return RESULT_OK;
}

SVCFuture<OS::Result> OS::SVCCloseHandle(Thread& source, Handle handle) {
    source.GetLogger()->info("{}SVCCloseHandle", ThreadPrinter{source});

    CloseHandle(source, handle);

    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK);
}

// TODO: Move this elsewhere
template<typename... T>
auto Unwrap(SVCFuture<T...>&& future) {
    return *future.data;
}

SVCFuture<PromisedResult> OS::SVCWaitSynchronization(Thread& source, Handle handle, int64_t timeout) {
    source.GetLogger()->info("{}SVCWaitSynchronization: handle={}, timeout={:#x}",
                             ThreadPrinter{source}, HandlePrinter{source,handle}, timeout);
    (void)OS::SVCWaitSynchronizationN(source, &handle, 1, false, timeout);
    return MakeFuture(PromisedResult{});
}

// TODO: What should this return for the "index" when wait_for_all is true?
// TODO: When a ServerPort is passed to this function, will it wake up and return an error when the corresponding client session is closed?
SVCFuture<PromisedResult,PromisedWakeIndex> OS::SVCWaitSynchronizationN(Thread& source, Handle* handles, uint32_t handle_count, bool wait_for_all, int64_t timeout) {
    auto& svc_activity = activity.GetSubActivity("SVC").GetSubActivity("WaitSyncN");
    auto scope_measure = MeasureScope(svc_activity);

    // AC workaround
    if (handle_count == 3 && handles[2] == HANDLE_INVALID) {
        --handle_count;
    }

    std::stringstream ss;
    ss << fmt::format("{}SVCWaitSynchronizationN: handle_count={:#x}, wait_for_all={}, timeout={:#x}, wait_handles=[",
                      ThreadPrinter{source}, handle_count, wait_for_all, timeout);
    for (unsigned i = 0; i < handle_count; ++i)
        ss << (i != 0 ? ", " : "") << HandlePrinter{source,handles[i]};
    ss << "]";
    source.GetLogger()->info(ss.str());


    // TODO: What are the semantics of negative timeout values?

    // TODO: Actually respect the timeout. Currently, we just store this for debugging purposes
    if (timeout != -1) {
        source.timeout_at = GetTimeInNanoSeconds() + timeout;
    } else {
        source.timeout_at = -1;
    }

    // Report success by default. We will override this when we encounter an error later
    source.promised_result = RESULT_OK;

    if (!source.wait_list.empty()) {
        throw std::runtime_error(fmt::format("Internal precondition violated: Expected wait list to be empty"));
    }

    for (Handle* handle = handles; handle != handles + handle_count; ++handle) {
        auto subject = source.GetProcessHandleTable().FindObject<ObserverSubject>(*handle);
        if (!subject) {
            throw std::runtime_error(fmt::format("Given handle {:#x} not found in process handle table", handle->value));
        }

        subject->Register(source.GetPointer());
        source.wait_list.push_back(subject);
    }

    // Check once whether any of the resources we're waiting on are already
    // ready (e.g. sticky events). Then (if need be), put the thread to sleep
    // until one of the resources becomes ready.
    for (auto it = source.wait_list.begin(); it != source.wait_list.end();) {
        auto object = *it;
        if (!object->TryAcquire(source.GetPointer())) {
            ++it;
            continue;
        }

        // Resource acquired successfully - remove it from the wait_list.
        // NOTE: TryAcquire already Unregister'ed us.
        source.wake_index = std::distance(source.wait_list.begin(), it);
        source.woken_object = *it;
        it = source.wait_list.erase(it);

        source.GetLogger()->info("{}WaitSynchronizationN signalled on {}", ThreadPrinter{source}, ObjectPrinter{object});

        if (!wait_for_all) {
            source.GetLogger()->info("{}WaitSynchronizationN waking up", ThreadPrinter{source});

            // we are already done, clear the remaining events
            for (auto sync_object : source.wait_list)
                sync_object->Unregister(source.GetPointer());

            source.wait_list.clear();
            break;
        } else if (source.wait_list.empty()) {
            source.GetLogger()->info("{}WaitSynchronizationN waking up", ThreadPrinter{source});
            // TODO: What index would we return in this case, though?
            break;
        }
    }

    // If this didn't already empty the list, suspend this thread until we are set back to Status::Ready again
    // TODO: Is it acceptable that we don't schedule at all if this condition evaluates to false?
    // TODO: When we timeout after we tried to acquire multiple resources, is it acceptable to leave some of the requested resources in an acquired state?
    if (!source.wait_list.empty()) {
        source.wait_for_all = wait_for_all;
        source.status = Thread::Status::Sleeping;
        ready_queue.remove_if([ptr=source.GetPointer()](auto elem) { return elem.lock() == ptr; });
//         priority_queue.remove_if([ptr=source.GetPointer()](auto elem) { return elem.lock() == ptr; });
        if (source.timeout_at != -1) {
            waiting_queue.push_back(source.GetPointer());
        }
        source.GetLogger()->info("{}Putting thread into sleep state...", ThreadPrinter{source});
        Reschedule(source.GetPointer());
    } else {
        RescheduleImmediately(source.GetPointer());
    }

    return MakeFuture(PromisedResult{}, PromisedWakeIndex{});
}

SVCFuture<OS::Result,Handle> OS::SVCDuplicateHandle(Thread& source, Handle handle) {
    source.GetLogger()->info("{}SVCDuplicateHandle: handle={}", ThreadPrinter{source}, HandlePrinter{source,handle});

    auto object = source.GetProcessHandleTable().FindObject<Object>(handle);
    if (!object) {
        throw std::runtime_error(fmt::format("{}Called SVCDuplicateHandle on invalid handle {}",
                                  ThreadPrinter{source}, HandlePrinter{source,handle}));
    }

    auto new_handle = source.GetProcessHandleTable().CreateHandle(object, MakeHandleDebugInfo(DebugHandle::Duplicated)).first;
    auto process_id = source.GetParentProcess().GetId();
    hypervisor.OnHandleDuplicated(process_id, handle, process_id, new_handle);

    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK, static_cast<Handle>(new_handle));
}

SVCFuture<uint64_t> OS::SVCGetSystemTick(Thread& source) {
    source.GetLogger()->info("{}SVCGetSystemTick", ThreadPrinter{source});

    // NOTE: On New3DS, this seems to return the number of system ticks
    //       with respect to the Old3DS CPU clock rate.
    auto old_tick = system_tick.count();

    // NOTE: Some applications use GetSystemTick in a busy loop. Since
    //       GetSystemTick is one of the few system calls that do not
    //       invoke the scheduler, we need to make sure to advance the
    //       system tick manually here.
    //       Cubic Ninja uses this in the first screen, for instance
    //       TODO: Considering this note, why do we still reschedule here?
    system_tick += ticks{1000};

    RescheduleImmediately(source.GetPointer());
    return MakeFuture(old_tick);
}

SVCFuture<OS::Result,HandleTable::Entry<ClientSession>> OS::SVCConnectToPort(Thread& source, const std::string& name) {
    auto& svc_activity = activity.GetSubActivity("SVC").GetSubActivity("ConnectToPort");
    auto scope_measure = MeasureScope(svc_activity);

    source.GetLogger()->info("{}SVCConnectToPort: name={}", ThreadPrinter{source}, name);

    auto port_it = ports.find(name);
    if (port_it == ports.end()) {
        source.GetLogger()->warn("{}Port does not exist (yet?), returning error", ThreadPrinter{source});
        Reschedule(source.GetPointer());
        return std::make_tuple(0xd88007fa, HandleTable::Entry<ClientSession>{});
    }

    auto server_port = port_it->second->server.lock();
    if (!server_port)
        SVCBreak(source, BreakReason::Panic);

    if (server_port->available_sessions == 0) {
        source.GetLogger()->info("{}No more sessions available on this port (number of open sessions: {})",
                                 ThreadPrinter{source}, server_port->available_sessions);
        return std::make_tuple(0xd0401834, HandleTable::Entry<ClientSession>{});
    }
    --server_port->available_sessions;

    auto session = std::make_shared<Session>();
    auto client_session = std::make_shared<ClientSession>(session); // handle created below
    session->client = client_session;
    client_session->name = "CSession_" + server_port->port->GetName();

    source.GetLogger()->info("{}SVCConnectToPort: output session=({}, {}), {} more sessions available",
                             ThreadPrinter{source}, ObjectPrinter{session}, ObjectPrinter{client_session},
                             server_port->available_sessions);

    auto client_session_entry = source.GetProcessHandleTable().CreateHandle(client_session, MakeHandleDebugInfo());
    hypervisor.OnConnectToPort(source.GetParentProcess().GetId(), name, client_session_entry.first);

    server_port->OfferSession(session);
    OnResourceReady(*server_port);

    // TODO: XDS seems to just keep going without a reschedule, so we'll do the same for now. We should consider re-enabling this, though!
//     Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK, client_session_entry);
}

// TODO: Consider refactoring this function to take a callback that receives an SVCFuture
template<typename Func, typename... T>
static void RunWhenReady(Thread& thread, Func f, T... args) {

    // Make sure there is no callback scheduled, yet
    assert(!thread.callback_for_svc);

    // Set up function to call from within the OS context the next time the
    // thread gets dispatched
    thread.callback_for_svc = [f, args...](std::shared_ptr<Thread> thread) { f(thread, args...); };
}

namespace detail {
template<typename Callable>
class ScopeExit final {
    static_assert(std::is_constructible<std::function<void()>, Callable>::value,
                  "Scope exit callbacks may not take any arguments and must return void");

    Callable callback;

public:
    ScopeExit(Callable callback) noexcept(std::is_nothrow_move_constructible<Callable>::value)
        : callback(std::move(callback)) {
        static_assert(noexcept(callback()), "Scope exit callbacks may not throw exceptions");
    }

    ScopeExit(const ScopeExit&) = delete;
    ScopeExit& operator=(const ScopeExit&) = delete;

    ~ScopeExit() noexcept(std::declval<Callable>()()) {
        callback();
    }
};
} // namespace detail

template<typename Callable>
detail::ScopeExit<Callable> OnScopeExit(Callable callback) {
    return detail::ScopeExit<Callable>(callback);
}


SVCFuture<PromisedResult> OS::SVCSendSyncRequest(Thread& source, Handle session_handle) {
    ZoneScoped;
    auto& svc_activity = activity.GetSubActivity("SVC").GetSubActivity("SendSyncRequest");
    auto scope_measure = MeasureScope(svc_activity);

    // TODO: appletEd workaround. Upon exit, it tries to close an invalid client session
//    auto session = source.GetProcessHandleTable().FindObject<ClientSession>(session_handle);
    auto session = source.GetProcessHandleTable().FindObject<ClientSession>(session_handle, true);
    if (!session) {
// TODO: HOME Menu tries to send requests to news:s before actually GetServiceHandle'ing its handle.
//throw std::runtime_error(fmt::format("Invalid session handle {}", HandlePrinter{source, session_handle}));
        source.promised_result = 0xdeadbef4;
        return MakeFuture(PromisedResult{});
    }
    source.GetLogger()->info("{}SVCSendSyncRequest: session={}, cmdheader={:#010x}",
                             ThreadPrinter{source}, HandlePrinter{source,session_handle},
                             source.ReadTLS(0x80));

    if (!session) {
        throw std::runtime_error(fmt::format("{}Unknown client session handle passed to SendSyncRequest", ThreadPrinter{source}));
        // TODO: DSP seems to just pass in a null handle upon boot...

        source.promised_result = 0xdeadbef5;
        return MakeFuture(PromisedResult{});
    }

    session->threads.push_back(source.GetPointer());

    // Report success by default. If an error occurs later on, we will override
    // this with the proper error code.
    source.promised_result = RESULT_OK;

    // NOTE: boost::hana::fix does not support functions returning void, so we are returning a dummy value from within our thing and wrap it in a void lambda
    auto continuation = boost::hana::fix([&svc_activity, session, session_handle](auto self, std::shared_ptr<Thread> thread) -> std::nullptr_t {
        svc_activity.Resume();

        // Wait until the server accepts the session
        std::shared_ptr<ServerSession> server_session = session->session->server.lock();
        if (!server_session) {
            thread->GetLogger()->info("{}ServerSession for ({},{}) not yet accepted, scheduling out...",
                                    ThreadPrinter{*thread}, ObjectPrinter{session->session}, ObjectPrinter{session});
            thread->GetOS().Reschedule(thread);
            RunWhenReady(*thread, self);
            // TODO: Put to sleep and set this thread waiting on a
            // server_session to arrive! Currently, we are
            // quasi-"spinlocking" instead by allowing scheduling this
            // thread back in early.

            // Switch back to Thread context
            svc_activity.Interrupt();
            return {};
        }

//         thread->GetLogger()->info("{}CLIENT SendSyncRequest CommandReady", ThreadPrinter{*thread});

        server_session->CommandReady();
        thread->GetOS().OnResourceReady(*server_session);

        // Wait for command to be processed (and the session_handle to be signaled)
//         thread->GetLogger()->info("{}CLIENT SendSyncRequest WaitSync", ThreadPrinter{*thread});
        thread->GetOS().SVCWaitSynchronization(*thread, session_handle, -1); // TODO: Big change!
        RunWhenReady(*thread, [session_handle](std::shared_ptr<Thread> thread) {
//             thread->GetLogger()->info("{}CLIENT SendSyncRequest WaitSync over", ThreadPrinter{*thread});
            thread->GetOS().RescheduleImmediately(thread);
        });
        thread->GetOS().RescheduleImmediately(thread);
        svc_activity.Interrupt();
        return {};
    });

    svc_activity.Interrupt();
    continuation(source.GetPointer());
    svc_activity.Resume();

    // TODO: Check threads waiting for an IPC reply to make sure they aren't left dangling indefinitely

    return MakeFuture(PromisedResult{});
}

SVCFuture<Result,HandleTable::Entry<Process>> OS::SVCOpenProcess(Thread& source, ProcessId pid) {
    source.GetLogger()->info("{}SVCOpenProcess: pid={:#x}", ThreadPrinter{source}, pid);

    auto process_ptr = GetProcessFromId(pid);
    if (!process_ptr) {
        throw std::runtime_error(fmt::format("Couldn't find any process with pid {:#x}", pid));
    }
    auto process_handle = source.GetProcessHandleTable().CreateHandle(process_ptr, MakeHandleDebugInfo());

    RescheduleImmediately(source.GetPointer());
    return MakeFuture(RESULT_OK, process_handle);
}


SVCFuture<OS::Result,ProcessId> OS::SVCGetProcessId(Thread& source, Process& process) {
    source.GetLogger()->info("{}SVCGetProcessId", ThreadPrinter{source});
    // TODO: According to 3dmoo, if the active process is passed to this SVC, an ID of "1" will always be returned
    RescheduleImmediately(source.GetPointer());
    return MakeFuture(RESULT_OK, process.GetId());
}

SVCFuture<OS::Result,ThreadId> OS::SVCGetThreadId(Thread& source, Thread& thread) {
    source.GetLogger()->info("{}SVCGetThreadId", ThreadPrinter{source});
    RescheduleImmediately(source.GetPointer());
    return MakeFuture(RESULT_OK, thread.GetId());
}

SVCEmptyFuture OS::SVCBreak(Thread& source, OS::BreakReason reason) {
    source.GetLogger()->info("{}KERNEL PANIC - CANNOT CONTINUE!", ThreadPrinter{source});
    throw Mikage::Exceptions::Invalid("Kernel panic:");
}

SVCFuture<OS::Result,HandleTable::Entry<ServerPort>,HandleTable::Entry<ClientPort>>
OS::SVCCreatePort(Thread& source, const std::string& name, int32_t max_sessions) {
    source.GetLogger()->info("{}SVCCreatePort: name={}, max_sessions={}", ThreadPrinter{source}, name, max_sessions);

    auto port = std::make_shared<Port>();
    auto server = std::make_shared<ServerPort>(port, max_sessions);
    auto client = std::make_shared<ClientPort>(port);
    port->server = server;
    port->client = client;

    if (max_sessions < 0) {
        // Not sure how to handle this case
        SVCBreak(source, BreakReason::Panic);
    }

    if (!name.empty()) {
        port->name = "Port_" + name;
        server->name = "SPort_" + name;
        client->name = "CPort_" + name;
    }

    // TODO: Need verification on "name": Make sure it's null-terminated, make sure there is not already a port with the given name!

    // TODO: When both the client and server handles are released, this entry should be removed again!
    if (!name.empty())
        ports.insert({name, port});

    auto process_id = source.GetParentProcess().GetId();
    auto server_handle = source.GetProcessHandleTable().CreateHandle(server, MakeHandleDebugInfo());
    auto client_handle = source.GetProcessHandleTable().CreateHandle(client, MakeHandleDebugInfo());

    hypervisor.OnPortCreated(process_id, name, server_handle.first);
    hypervisor.OnHandleDuplicated(process_id, server_handle.first, process_id, client_handle.first);

    Reschedule(source.GetPointer());

    // TODO: a client port should only be returned for anonymous ports!
    return MakeFuture(RESULT_OK, server_handle, client_handle);
}

SVCFuture<OS::Result,HandleTable::Entry<ClientSession>> OS::SVCCreateSessionToPort(Thread& source, Handle client_port_handle) {
    auto log_message = fmt::format("{}SVCCreateSessionToPort: handle={}", ThreadPrinter{source}, HandlePrinter{source,client_port_handle});
    auto client_port = source.GetProcessHandleTable().FindObject<ClientPort>(client_port_handle);
    if (!client_port)
        SVCBreak(source, BreakReason::Panic);

    auto server_port = client_port->port->server.lock();
    if (server_port->available_sessions == 0) {
        source.GetLogger()->error("{}No more sessions available on this port (number of open sessions: {})",
                                  ThreadPrinter{source}, server_port->available_sessions);
        // TODO: What's the correct error code to return?
        return std::make_tuple(0xd0401834, HandleTable::Entry<ClientSession>{});
    }
    --server_port->available_sessions;

    // Create session
    auto session = std::make_shared<Session>();
    auto client_session = std::make_shared<ClientSession>(session); // handle created below
    session->client = client_session;
    // TODO: Make compatible with sm changes in version 7.x
//    fprintf(stderr, "PORT NAME: ...\n");
//    fprintf(stderr, "PORT NAME: %s\n", client_port->name.c_str());
//    ValidateContract(client_port->name.size() > 6); // Get service/port name by stripping away "CPort_" prefix
//    session->name = "Session_" + client_port->name.substr(6);
//    client_session->name = "CSession_" + client_port->name.substr(6);

    log_message += fmt::format(", output session=({}, {}), {} more sessions available",
                               ObjectPrinter{session}, ObjectPrinter{client_session}, server_port->available_sessions);
    source.GetLogger()->info(log_message);

    auto client_session_handle_entry = source.GetProcessHandleTable().CreateHandle(client_session, MakeHandleDebugInfo());
    hypervisor.OnNewSession(source.GetParentProcess().GetId(), client_port_handle, client_session_handle_entry.first);

    // Push to server's connection queue and return to the caller
    server_port->OfferSession(session);
    OnResourceReady(*server_port);

    // Keep running; the earliest we need the session to be accepted is once the caller actually tries to call SendSyncRequest on the returned session
    RescheduleImmediately(source.GetPointer());
    return MakeFuture(RESULT_OK, client_session_handle_entry);
}

SVCFuture<OS::Result,HandleTable::Entry<ServerSession>,HandleTable::Entry<ClientSession>> OS::SVCCreateSession(Thread& source) {
    auto log_message = fmt::format("{}SVCCreateSession", ThreadPrinter{source});

    // Create session
    auto session = std::make_shared<Session>();
    auto server_session = std::make_shared<ServerSession>(session, nullptr); // handle created below
    auto client_session = std::make_shared<ClientSession>(session); // handle created below
    session->server = server_session;
    session->client = client_session;

    log_message += fmt::format(", output session=({}, {}, {})", ObjectPrinter{session},
                               ObjectPrinter{server_session}, ObjectPrinter{client_session});
    source.GetLogger()->info(log_message);

    auto server_session_handle_entry = source.GetProcessHandleTable().CreateHandle(server_session, MakeHandleDebugInfo());
    auto client_session_handle_entry = source.GetProcessHandleTable().CreateHandle(client_session, MakeHandleDebugInfo());

    auto process_id = source.GetParentProcess().GetId();
    hypervisor.OnSessionCreated(process_id, server_session_handle_entry.first);
    hypervisor.OnHandleDuplicated(process_id, server_session_handle_entry.first, process_id, client_session_handle_entry.first);

    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK, server_session_handle_entry, client_session_handle_entry);
}

SVCFuture<OS::Result,HandleTable::Entry<ServerSession>> OS::SVCAcceptSession(Thread& source, ServerPort& server_port) {
    source.GetLogger()->info("{}SVCAcceptSession: server_port={}", ThreadPrinter{source}, ObjectRefPrinter{server_port});

    if (server_port.session_queue.empty()) {
        throw Mikage::Exceptions::Invalid("Attempted to accept nonexisting session");
    }
    auto session = server_port.session_queue.front();
    server_port.session_queue.pop();

    source.GetLogger()->info("{}SVCAcceptSession: accepting session {} / {}", ThreadPrinter{source},
                             ObjectPrinter{session}, ObjectPrinter{session->client.lock()});

    auto server_session = std::make_shared<ServerSession>(session, std::static_pointer_cast<ServerPort>(server_port.shared_from_this()));

    auto client_session = session->client.lock();
//    assert(client_session);
    // NOTE: During initial system setup, LLE ac requests a cfg:s handle and immediately closes it before cfg accepts the session.
    //       Should the scheduler prevent this from happening or is this a valid scenario? In the latter case, should we return an error or immediately signal the server session?
    if (client_session) {
        auto client_session_name = client_session->GetName();
        if (std::string_view { client_session_name }.substr(0, 9) == "CSession_") {
            // This name was set up by sm_hpv and reliably provides the service name
            server_session->name = "SSession_" + client_session_name.substr(9);
        } else {
            // This is either a session to a global (i.e. non-service) port or
            // a session without any port at all (e.g. FS files)
            server_session->name = "SSession_" + server_port.name;
        }
    } else {
        // Preliminary implementation: If the client session was already closed, signal the ServerSession.
        // To the server, this will effectively look like the ClientSession was closed after accepting the Session
        OnResourceReady(*server_session);
    }

    session->server = server_session;
    auto session_handle_entry = source.GetProcessHandleTable().CreateHandle(server_session, MakeHandleDebugInfo());

    hypervisor.OnNewSession(source.GetParentProcess().GetId(), source.GetProcessHandleTable().FindHandle(&server_port), session_handle_entry.first);
    source.GetLogger()->info("{}SVCAcceptSession returning session handle {} ({} more available)",
                             ThreadPrinter{source}, HandlePrinter{source,session_handle_entry.first}, server_port.available_sessions);

    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK, session_handle_entry);
}

void OS::TranslateIPCMessage(Thread& source, Thread& dest, bool is_reply) {
    IPC::CommandHeader header = { source.ReadTLS(0x80) };
    // Copy header code and normal parameters
    unsigned tls_offset = 0x80;

    // TODO: Move the IPC block output logic to hypervisor

    auto log_message = fmt::format("{}", ThreadPrinter{source});
    log_message += (is_reply ? fmt::format("IPC reply from {} to {}:", ProcessPrinter{source.GetParentProcess()}, ProcessPrinter{dest.GetParentProcess()})
                             : fmt::format("IPC message from {} to {}:", ProcessPrinter{source.GetParentProcess()}, ProcessPrinter{dest.GetParentProcess()}));
    const uint32_t command_end = 0x84 + 4 * (header.num_normal_params + header.size_translate_params);
    {
        uint32_t tls_addr = 0x80;
        log_message += fmt::format(" {:#010x} (header)", source.ReadTLS(tls_addr));
        tls_addr += 4;
        for (; tls_addr < 0x84 + 4 * header.num_normal_params; tls_addr += 4) {
            log_message += fmt::format("\n{:#010x} (normal parameter)", source.ReadTLS(tls_addr));
        }
        for (; tls_addr < command_end; tls_addr += 4) {
            log_message += fmt::format("\n{:#010x} (translate parameter)", source.ReadTLS(tls_addr));
        }

    }
    source.GetLogger()->info(log_message);

    if (is_reply && source.ReadTLS(0x84) != 0)
        source.GetLogger()->warn("NOTE: This IPC reply seems to indicate failure");

    // Fill TLS with poison values to detect uninitialized data
    // NOTE: Some applications (notably cfg) only overwrite the lowest byte
    //       in reply words, leaving the rest unchanged from the input data.
    //       Other software even leaves entire words untouched and expects the
    //       original data to be returned to the caller. We hence cannot poison
    //       all command buffer data to check for uninitialized data accesses.
    //       It seems safe to poison all data after normal parameters, though.
    for (unsigned i = header.num_normal_params + 1; i < 0x40; ++i) {
//         dest.WriteTLS(0x80 + 4 * i, 0xdeadbeef + (0x100 * i));
         dest.WriteTLS(0x80 + 4 * i, 0);
    }
    while (tls_offset < 0x84 + 4 * header.num_normal_params) {
        dest.WriteTLS(tls_offset, source.ReadTLS(tls_offset));
        tls_offset += 4;
    }

    uint32_t dest_static_buffers_used_mask = 0;

    // Copy translate parameters
    while (tls_offset < command_end) {
        // Copy translation descriptor
        IPC::TranslationDescriptor descriptor = { source.ReadTLS(tls_offset) };
        dest.WriteTLS(tls_offset, descriptor.raw);
        tls_offset += 4;

        // Write translated parameters
        switch (descriptor.type) {
        case IPC::TranslationDescriptor::Type::Handles:
            if (descriptor.handles.close_handle && descriptor.handles.fill_process_id) {
                // TODO: No idea whether this is supported at all or what it
                //       would be doing. Since process IDs are global, this
                //       wouldn't make a lot of sense. On the other hand, maybe
                //       it's just implemented as a NOP. This needs a test!
                throw std::runtime_error("Attempting to close handle on process id");
            }

            for (uint32_t i = 0; i < descriptor.handles.NumHandles(); ++i) {
                if (descriptor.handles.fill_process_id) {
                    // NOTE: This indeed fills the process ID rather than creating a process handle in the target process.
                    //       Process IDs are global, hence no translation is necessary.
                    auto pid = source.GetParentProcess().GetId();
                    dest.WriteTLS(tls_offset, pid);
                } else {
                    Handle source_handle{source.ReadTLS(tls_offset)};

                    // Translate handles
                    if (source_handle == HANDLE_INVALID) {
                        // This is apparently a valid thing to do. E.g. APT:U::ReceiveParameter relies on it, because its handle is merely optional
                        // Similarly, passing a null handle to dsp::DSP::RegisterInterruptEvents has special behavior
                        dest.WriteTLS(tls_offset, 0);
                    } else {
                        auto object = source.GetProcessHandleTable().FindObject<Object>(source_handle);
                        if (!object) {
                            throw std::runtime_error(fmt::format("Unknown handle {} input for translation", source_handle.value));
                        }

                        // Fail if this is an address arbiter: They are not
                        // currently usable for interprocess communication, so
                        // rejecting them is a good measure to prevent effects that
                        // would otherwise be hard to debug.
                        // TODO: How does hardware handle address arbitration across processes?
                        if (nullptr != std::dynamic_pointer_cast<AddressArbiter>(object)) {
                            throw std::runtime_error("Attempting to transfer address arbiter via IPC");
                        }

                        auto handle_table_entry = dest.GetProcessHandleTable().CreateHandle(object, MakeHandleDebugInfoFromIPC(dest.ReadTLS(0x80)));
                        auto handle = handle_table_entry.first;
                        hypervisor.OnHandleDuplicated(source.GetParentProcess().GetId(), source_handle,
                                                      dest.GetParentProcess().GetId(), handle);

                        // TODOTEST: If the object is already mapped in the target process, should the existing handle be used or a new one be created?
                        source.GetLogger()->info("Translated {} handle {:#x} to the {} handle {:#x} (object: {})",
                                                ProcessPrinter { source.GetParentProcess() }, source_handle.value,
                                                ProcessPrinter { dest.GetParentProcess() }, handle.value, ObjectPrinter{object});

                        if (descriptor.handles.close_handle) {
                            auto result = std::get<0>(Unwrap(SVCCloseHandle(source, source_handle)));
                            if (result != RESULT_OK) {
                                source.GetLogger()->error("Unexpected error on closing handle");
                                SVCBreak(source, BreakReason::Panic);
                            }
                        }

                        dest.WriteTLS(tls_offset, handle.value);
                     }
                }
                tls_offset += 4;
            }
            break;

        case IPC::TranslationDescriptor::Type::StaticBuffer:
        {
            // Transfer data from the source thread to a static buffer of the destination thread

            uint32_t source_data_addr = source.ReadTLS(tls_offset);
            IPC::TranslationDescriptor dest_descriptor = { dest.ReadTLS(0x180 + 8 * descriptor.static_buffer.id) };
            uint32_t dest_buffer_size = dest_descriptor.static_buffer.size;
            uint32_t dest_buffer_addr = dest.ReadTLS(0x184 + 8 * descriptor.static_buffer.id);

            if (dest_static_buffers_used_mask & (1 << descriptor.static_buffer.id)) {
                throw Mikage::Exceptions::Invalid("Attempted to use target static buffer {} twice", descriptor.static_buffer.id.Value());
            }
            dest_static_buffers_used_mask |= (1 << descriptor.static_buffer.id);

            // Check that the destination process provides a valid static buffer for the input data
            if (dest_descriptor.type != IPC::TranslationDescriptor::Type::StaticBuffer ||
                    dest_buffer_size < descriptor.static_buffer.size) {

                // 3ds-examples/libapplet_launch hits this
                throw std::runtime_error(fmt::format("{}Expected target thread {} to have a static buffer descriptor of id {:#x} and of size {:#x}. Got TLS@{:#x}={:#x}",
                                                     ThreadPrinter{source}, ThreadPrinter{dest}, descriptor.static_buffer.id.Value(), descriptor.static_buffer.size.Value(),
                                                     0x180 + 8 * descriptor.static_buffer.id, dest.ReadTLS(0x180 + 8 * descriptor.static_buffer.id)));
            }

            source.GetLogger()->info("{}Copying {}/{} bytes of static buffer data from {:#010x} to {:#010x} in thread {}:",
                                     ThreadPrinter{source}, descriptor.static_buffer.size.Value(), dest_buffer_size, source_data_addr,
                                     dest_buffer_addr, ThreadPrinter{dest});
            std::string data;
            auto max_size = std::min<uint32_t>(64, descriptor.static_buffer.size);
            data.reserve(2 * max_size);
            data = ranges::accumulate(ranges::view::ints(source_data_addr, source_data_addr + max_size), std::move(data),
                                      [&](auto& accum, uint32_t addr) { return std::move(accum) + fmt::format("{:02x}", source.ReadMemory(addr)); });
            source.GetLogger()->info("{}{}", data, (descriptor.static_buffer.size > max_size) ? "..." : "");

            // TODO: Remove libapplet_launch workaround std::min
            for (uint32_t offset = 0; offset < std::min<uint32_t>(dest_buffer_size, descriptor.static_buffer.size); ++offset)
                dest.WriteMemory(dest_buffer_addr + offset, source.ReadMemory(source_data_addr + offset));

            // Read the static buffer address from TLS and copy it into the IPC message
            dest.WriteTLS(tls_offset, dest_buffer_addr);
            tls_offset += 4;

            break;
        }

        case IPC::TranslationDescriptor::Type::PXIBuffer:
        case IPC::TranslationDescriptor::Type::PXIConstBuffer:
        {
            // This descriptor instructs the kernel to build a list of memory
            // chunks which is written to a static buffer in the target process
            IPC::TranslationDescriptor static_buffer_descriptor = { dest.ReadTLS(0x180 + 8 * descriptor.pxi_buffer.id) };
            VAddr dest_buffer_addr = dest.ReadTLS(0x184 + 8 * descriptor.pxi_buffer.id);

            if (dest_static_buffers_used_mask & (1 << descriptor.pxi_buffer.id)) {
                throw Mikage::Exceptions::Invalid("Attempted to use target PXI buffer {} twice", descriptor.pxi_buffer.id.Value());
            }
            dest_static_buffers_used_mask |= (1 << descriptor.pxi_buffer.id);

            // Check that the destination process provides a valid static buffer for the input data
            // TODO: Verify the size of the buffer!
            if (static_buffer_descriptor.type != IPC::TranslationDescriptor::Type::StaticBuffer) {
                throw std::runtime_error(fmt::format("{}Expected target thread {} to have a static buffer descriptor of id {:#x}. Got TLS@{:#x}={:#x}",
                                                     ThreadPrinter{source}, ThreadPrinter{dest}, descriptor.pxi_buffer.id.Value(),
                                                     0x180 + 8 * descriptor.pxi_buffer.id, static_buffer_descriptor.raw));
                SVCBreak(source, BreakReason::Panic);
            }

            uint32_t buffer_size = descriptor.pxi_buffer.size;

            VAddr buffer_address = source.ReadTLS(tls_offset);

            // TODO: Respect read-only-ness

            uint32_t static_buffer_offset = 0;
            source.GetLogger()->info("{}Setting up PXI buffer table {:#x} at address {:#x} in target process",
                                     ThreadPrinter{source}, descriptor.pxi_buffer.id.Value(), dest_buffer_addr);

            auto base_physical_chunk = ResolveVirtualAddrWithSize(source.GetParentProcess(), buffer_address);
            if (!base_physical_chunk) {
                if (buffer_size == 0) {
                    // NOTE: Some games use zero-length buffers. Naively we
                    //       could just not map any buffer in the target
                    //       process in that case, but services may expect to
                    //       be able to forward the buffers to other services.
                    //       A notable example of this is Super Mario 3D Land,
                    //       which sends zero-byte file read requests to FS,
                    //       which in turn forwards those requests to PXI.
                    //       Usually, games provide valid buffer addresses
                    //       despite the zero buffer size. However for am:net's
                    //       ImportCertificates, a typical usage pattern is
                    //       zero-size with a nullptr.
                    // TODO: Review if LLE FS avoids PXI calls for null buffers.
                    //       If it does, HLE FS should copy this behavior so
                    //       that an error can be raised here instead.
                    base_physical_chunk.emplace(0, 0);
                } else {
                    throw Mikage::Exceptions::NotImplemented(
                            "{}Failed to resolve virtual address {:#x}",
                            ThreadPrinter{source}, buffer_address);
                }
            }
            if (base_physical_chunk->second >= buffer_size) {
                // Create one single PXI entry covering the entire buffer
                if (static_buffer_descriptor.static_buffer.size < 8) {
                    throw std::runtime_error(fmt::format("{}Exceeded capacity of static buffer",
                                                         ThreadPrinter{source}));
                }

                dest.WriteMemory32(dest_buffer_addr + static_buffer_offset, base_physical_chunk->first);
                dest.WriteMemory32(dest_buffer_addr + static_buffer_offset + 4, buffer_size);

                source.GetLogger()->info("Added PXI physical memory chunk {:#x} of size {:#x} in static buffer {} at {:#x}",
                                        base_physical_chunk->first, buffer_size, descriptor.pxi_buffer.id.Value(), dest_buffer_addr + static_buffer_offset);

                static_buffer_offset += 8;

                buffer_address += buffer_size;
                buffer_size -= buffer_size;
            } else {
                // We'll need to split the memory across multiple PXI buffer entries.
                // To make sure our PXI implementation can look up addresses reasonably quick,
                // we split it into equally sized entries (each sized as large as possible while
                // guaranteeing the specified memory ranges are contiguous).
                while (buffer_size) {
                    if (static_buffer_descriptor.static_buffer.size < 8) {
                        throw std::runtime_error("Exceeded capacity of static buffer");
                    }

                    // TODO: We should presumably merge adjacent entries
                    auto physical_chunk = ResolveVirtualAddrWithSize(source.GetParentProcess(), buffer_address);
                    if (!physical_chunk) {
                        throw std::runtime_error(fmt::format(   "Failed to resolve virtual address {:#x}",
                                                                buffer_address));
                    }
                    auto physical_chunk_address = physical_chunk->first;
                    if (physical_chunk->second >= buffer_size)
                        source.GetLogger()->error("COULD DO THE FANCY STUFF");
                    dest.WriteMemory32(dest_buffer_addr + static_buffer_offset, physical_chunk_address);
                    const uint32_t page_size = 0x1000;
                    const auto next_buffer_page_addr = (buffer_address + page_size) & ~(page_size - 1);
                    const uint32_t chunk_size = std::min(buffer_size, next_buffer_page_addr - buffer_address);
                    dest.WriteMemory32(dest_buffer_addr + static_buffer_offset + 4, chunk_size);

                    source.GetLogger()->info("Added PXI physical memory chunk {:#x} of size {:#x} in static buffer {} at {:#x}",
                                            physical_chunk_address, chunk_size, descriptor.pxi_buffer.id.Value(), dest_buffer_addr + static_buffer_offset);

                    static_buffer_offset += 8;

                    buffer_address += chunk_size;
                    buffer_size -= chunk_size;
                }
            }

            // TODO: The official kernel probably does not modify the
            //       translation descriptor at all. We purely do this for
            //       convenience, currently!
            dest.WriteTLS(tls_offset - 4, IPC::TranslationDescriptor::MakeStaticBuffer(descriptor.pxi_buffer.id, static_buffer_offset).raw);
            dest.WriteTLS(tls_offset, *dest.GetParentProcess().ResolveVirtualAddr(dest_buffer_addr));
            tls_offset += 4;
            break;
        }

        case IPC::TranslationDescriptor::Type::MapReadOnly:
        case IPC::TranslationDescriptor::Type::MapWriteOnly:
        case IPC::TranslationDescriptor::Type::MapReadWrite:
        {
            // NOTE: Mapped buffers may be of size zero, in which case we
            //       don't actually map any memory.
            // TODO: Test if the kernel should still map at least one page in
            //       the target process in this case.
            const VAddr buffer_source_addr = source.ReadTLS(tls_offset);

            if (!descriptor.map_buffer.size) {
                tls_offset += 4;
                break;
            }

            // Extend buffer size to partially covered pages
            // NOTE: Two alignment considerations are made here:
            //       1. The offset of the dest pointer into the first page must match the source pointer
            //       2. The mapped data must end on a page boundary.
            //          This is particularly important for the sub-page
            //          allocations done in HLE modules, due to which e.g.
            //          APT::Wrap fails to properly forward its buffers to PS
            //          if they're allocated within the same virtual memory page
            //          Side TODO: Stop sub-page allocating in HLE modules
            uint32_t mapped_buffer_size = ((buffer_source_addr + descriptor.map_buffer.size + 0xfff) & ~0xfff) - (buffer_source_addr & ~0xfff);

            if (is_reply) {
                // Unmap buffer from the source process. It seems that the
                // server process is responsible for specifying the appropriate
                // size and address of the unmapped buffer itself, otherwise it
                // will remain mapped.
                // TODO: It's unconfirmed whether this is how it works!
                // TODO: Not sure if this translate descriptor is passed through to the target process at all
                // TODO: The first and last pages are copied to internal buffers in BASE memory to make sure unaligned buffers don't leak data into the target process

                if (descriptor.type != IPC::TranslationDescriptor::Type::MapReadOnly) {
                    source.GetLogger()->info(   "{}Unmapping buffer for output data at {:#010x} from thread {}:",
                                                ThreadPrinter{source}, buffer_source_addr, ThreadPrinter{dest});
                    std::string data;
                    auto max_size = std::min<uint32_t>(0x100, descriptor.map_buffer.size);
                    data.reserve(2 * max_size);
                    data = ranges::accumulate(ranges::view::ints(buffer_source_addr, buffer_source_addr + max_size), std::move(data),
                                              [&](auto& accum, uint32_t addr) { return std::move(accum) + fmt::format("{:02x}", source.ReadMemory(addr)); });
                    source.GetLogger()->info("{}{}", data, (descriptor.map_buffer.size > max_size) ? "..." : "");
                }

                bool success = source.GetParentProcess().UnmapVirtualMemory(buffer_source_addr & ~0xfff, mapped_buffer_size);
                if (!success) {
                    throw std::runtime_error("Couldn't unmap IPC buffer memory");
                }

                // TODO: Should we write this or not?
                dest.WriteTLS(tls_offset, 0);
            } else {
                // Map buffer in the target process
                // TODO: Setup proper permissions
                // TODO: Page-align the mappings??

                auto buffer_dest_vaddr_opt = dest.GetParentProcess().FindAvailableVirtualMemory(mapped_buffer_size, 0x10000000, 0x20000000);
                if (!buffer_dest_vaddr_opt) {
                    throw std::runtime_error("Couldn't find any free virtual memory to map IPC buffer");
                }

                MemoryPermissions permissions = (descriptor.type == IPC::TranslationDescriptor::Type::MapReadOnly)
                                                ? MemoryPermissions::Read
                                                : (descriptor.type == IPC::TranslationDescriptor::Type::MapWriteOnly)
                                                    ? MemoryPermissions::Write
                                                    : MemoryPermissions::ReadWrite;

                for (uint32_t bytes_mapped = 0; bytes_mapped < mapped_buffer_size;) {
                    auto buffer_paddr_pair_opt = ResolveVirtualAddrWithSize(source.GetParentProcess(), ((buffer_source_addr + bytes_mapped) & ~0xfff));
                    if (!buffer_paddr_pair_opt) {
                        throw std::runtime_error(fmt::format("Failed to resolve IPC buffer address {:#x}", buffer_source_addr));
                    }
                    uint32_t bytes_to_map = std::min<uint32_t>(buffer_paddr_pair_opt->second, mapped_buffer_size - bytes_mapped);

                    // TODO: Currently, we can have mappings like "VAddr [0x10000000;0x100036c0] to PAddr [0x245cc9a0;0x245d0060]", but we really shouldn't change alignment of data like this...
                    bool success = dest.GetParentProcess().MapVirtualMemory(buffer_paddr_pair_opt->first, bytes_to_map, *buffer_dest_vaddr_opt + bytes_mapped, permissions);
                    if (!success) {
                        throw std::runtime_error("Couldn't map virtual memory for IPC buffer");
                    }

                    bytes_mapped += bytes_to_map;
                }

                // Write target address. Care must be taken to preserve the page offset into the source data
                dest.WriteTLS(tls_offset, *buffer_dest_vaddr_opt + (buffer_source_addr & 0xfff));

                source.GetLogger()->info(   "{}Mapping buffer for input data at {:#010x} in thread {}:",
                                            ThreadPrinter{source}, buffer_source_addr, ThreadPrinter{dest});
                if (descriptor.type != IPC::TranslationDescriptor::Type::MapWriteOnly) {
                    std::string data;
                    auto max_size = std::min<uint32_t>(0x1000, descriptor.map_buffer.size);
                    data.reserve(2 * max_size);
                    data = ranges::accumulate(ranges::view::ints(buffer_source_addr, buffer_source_addr + max_size), std::move(data),
                                              [&](auto& accum, uint32_t addr) { return std::move(accum) + fmt::format("{:02x}", source.ReadMemory(addr)); });
                    source.GetLogger()->info("{}{}", data, (descriptor.map_buffer.size > max_size) ? "..." : "");
                }
            }
            tls_offset += 4;
            break;
        }

        default:
            throw std::runtime_error("Unknown IPC descriptor type");
        }
    }
}

// Postcondition: On success or on error 0xc920181a, -1 <= wake_index < handle_count. On success, wake_index will not be -1.
SVCFuture<PromisedResult,PromisedWakeIndex> OS::SVCReplyAndReceive(Thread& source, Handle* handles, uint32_t handle_count, Handle reply_target) {
    auto& svc_activity = activity.GetSubActivity("SVC").GetSubActivity("ReplyAndReceive");
    auto scope_measure = MeasureScope(svc_activity);

    // Return success by default, override later on failure
    source.promised_result = RESULT_OK;
    source.timeout_at = -1; // Timeout is ignored in ReplyAndReceive, but it's printed in the debug output, so let's make it clear that we'll be waiting indefinitely

    auto log_message = fmt::format("{}SVCReplyAndReceive: ", ThreadPrinter{source});
    log_message += reply_target != HANDLE_INVALID ? fmt::format("reply_handle={}", HandlePrinter{source,reply_target})
                                                  : "reply omitted";
    log_message += ", receive_handles=[";
    for (unsigned i = 0; i < handle_count; ++i)
        log_message += fmt::format("{}{}", (i != 0 ? ", " : ""), HandlePrinter{source,handles[i]});
    log_message += "]";
    source.GetLogger()->info(log_message);

    // TODO: The HANDLE_INVALID check is only necessary to get the fake services running. Actually, the kernel (likely) only provides the former check!
    if ((source.ReadTLS(0x80) >> 16) != 0xFFFF && reply_target != HANDLE_INVALID) {
        auto server_session = source.GetProcessHandleTable().FindObject<ServerSession>(reply_target);
        if (!server_session) {
            source.GetLogger()->error("{}Server session for reply target has been closed!", ThreadPrinter{source});
            SVCBreak(source, OS::BreakReason::Panic);
        }

        // Copy over server response to client's TLS
        assert(server_session->session);
        auto client_session = server_session->session->client.lock();
        assert(client_session && !client_session->threads.empty());
//         if (!client_session) {
            // TODO: Should return 0xc920181a and set wake_index to -1 in this case
//         }
        auto client_thread = client_session->threads.front().lock();
        assert(client_thread);
        source.GetLogger()->info("{}Sending IPC reply on {} with result {:#x}", ThreadPrinter{source}, ObjectPrinter{client_session}, source.ReadTLS(0x84));
        hypervisor.OnIPCReplyFromTo(source, *client_thread, reply_target);
        TranslateIPCMessage(source, *client_thread, true);

        source.GetLogger()->info("{}SERVER ReplyAndReceive notifying client session {} about IPC reply",
                                 ThreadPrinter{source}, ObjectPrinter{client_session});
        client_session->SetReady(client_thread);
        OnResourceReady(*client_session);
    }

    // If the wait object list is empty, return immediately reporting success (and an unchanged wake index)
    // TODO: Make sure returning the unchanged wake index cannot violate deterministic emulation
    if (handle_count == 0) {
//         Reschedule(source.GetPointer());
        return MakeFuture(PromisedResult{}, PromisedWakeIndex{});
    }

    // TODO: On the actual hardware, how does SVCWaitsynchronization behave
    //       with regards to server sessions?
    //       Multiple options sound viable:
    //       * It outright errors out when a ServerSession handle is given
    //       * Having other threads send sync requests simply will not wake up
    //         a thread waiting via WaitSynchronization
    //       * Having other threads send sync requests will wake up a thread
    //         waiting via WaitSynchronization, but no IPC data will be
    //         transferred
    //       * Having other threads send sync requests will have the exact
    //         same effect regardless of whether the server thread is waiting
    //         using SVCWaitSynchronization or SVCReplyAndReceive.
    // TODO: Should this wake up when any of the given handles are closed? loader.c suggests 0xC920181A should be returned in that case. TODOTEST!
    source.GetLogger()->info("{}SVCReplyAndReceive waiting", ThreadPrinter{source});
    svc_activity.Interrupt();
    auto future = SVCWaitSynchronizationN(source, handles, handle_count, 0, -1); // TODO: Changing a 0 to -1 is actually a BIG CHANGE here! (immediate timeout -> no timeout)
    svc_activity.Resume();

    // NOTE: handles will have ran out of scope when this callback is executed,
    // hence we read woken_object instead of looking up the handle ourselves.
    RunWhenReady(source, [this, future](std::shared_ptr<Thread> thread) {
        auto& svc_activity = activity.GetSubActivity("SVC").GetSubActivity("ReplyAndReceive"); // TODO: Use scope exit for interrupting this!
        svc_activity.Resume();

        auto result = thread->GetPromise(std::get<0>(*future.data));
        if (result != RESULT_OK) {
            // Forward the promise to the caller
            // TODO: Uhm... does this access a copied value of *this??
            RescheduleImmediately(thread);
            svc_activity.Interrupt();
            return;
        }

        thread->GetLogger()->info("{}SVCReplyAndReceive woken up on {} (wake index {})",
                                  ThreadPrinter{*thread}, ObjectPrinter{thread->woken_object.lock()},
                                  thread->GetPromise(std::get<1>(*future.data)));

        // If the acquired object is a ServerSession (i.e. a client request has
        // been sent), copy over request to the server TLS and perform any
        // requested argument translation.
        auto server_session = std::dynamic_pointer_cast<ServerSession>(thread->woken_object.lock());
        if (server_session) {
            assert(server_session->session);
            auto client_session = server_session->session->client.lock();
            if (client_session) {
                assert(!client_session->threads.empty());
                // TODO: There's a possible race condition here if two threads send a sync request at the same time, in which case we'll process the second one twice and the first one not at all
                //       We could easily (?) resolve this by checking for ipc_commands_pending
//                TODOTODO: Must take the appropriate session instead, here and in the other function that uses threads.front();
                auto client_thread = client_session->threads.front().lock();
                assert(client_thread);

                thread->GetLogger()->info("{}Incoming IPC request on {}", ThreadPrinter{*thread}, ObjectPrinter{client_session});
                TranslateIPCMessage(*client_thread, *thread, false);

                hypervisor.OnIPCRequestFromTo(*client_thread, *thread, thread->GetProcessHandleTable().FindHandle(server_session));
            } else {
                // The thread was woken up because the client session was closed, so report this to the caller
                thread->promised_result = 0xc920181a;
                // Forward promised wake index set by WaitSynchronization
                RescheduleImmediately(thread);
                svc_activity.Interrupt();
                return;
            }
        }
        RescheduleImmediately(thread);
        svc_activity.Interrupt();
    });

    return future;
}

SVCFuture<OS::Result> OS::SVCBindInterrupt(Thread& source, uint32_t interrupt_index, std::shared_ptr<Event> signal_event, int32_t priority, uint32_t is_manual_clear) {
    source.GetLogger()->info("{}SVCBindInterrupt: Binding interrupt {:#x} to {} (priority={:#x}, is_manual_clear={:#x})",
                             ThreadPrinter{source}, interrupt_index, ObjectPrinter{signal_event}, priority, is_manual_clear);

    // TODO: Check that the given interrupt_index is listed in the kernel capabilities!

    bound_interrupts[interrupt_index].push_back(signal_event);
    std::string interrupt_name = std::invoke([=]() -> std::string {
        switch (interrupt_index) {
        case 0x28:
            return "PSC0";

        case 0x29:
            return "PSC1";

        case 0x2a:
            return "VBlankTop";

        case 0x2b:
            return "VBlankBottom";

        case 0x2c:
            return "PPF";

        case 0x2d:
            return "P3D";

        default:
            return fmt::format("{:#x}", interrupt_index);
        }
    });
    signal_event->name = signal_event->GetName() + "_Interrupt" + interrupt_name;
    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK);
}

auto OS::SVCInvalidateProcessDataCache(Thread& source, Handle process_handle, uint32_t start, uint32_t num_bytes)
    -> SVCFuture<Result> {
    source.GetLogger()->info("{}SVCInvalidateProcessDataCache: VAddr range [{:#010x}:{:#010x}] in process {}",
                             ThreadPrinter{source}, start, start + num_bytes, HandlePrinter { source, process_handle });

    // Assert the address is valid, ignore otherwise as we don't emulate caches
    auto process = source.GetProcessHandleTable().FindObject<Process>(process_handle);
    auto src_paddr_opt = process->ResolveVirtualAddr(start);
    if (!src_paddr_opt) {
        throw std::runtime_error("Failed to look up source address");
    }

    RescheduleImmediately(source.GetPointer());
    return MakeFuture(RESULT_OK);
}

auto OS::SVCFlushProcessDataCache(Thread& source, Handle process_handle, uint32_t start, uint32_t num_bytes)
    -> SVCFuture<Result> {
    source.GetLogger()->info("{}SVCFlushProcessDataCache: VAddr range [{:#010x}:{:#010x}] in process {}",
                             ThreadPrinter{source}, start, start + num_bytes, HandlePrinter { source, process_handle });

    // Assert the address is valid, ignore otherwise as we don't emulate caches
    auto process = source.GetProcessHandleTable().FindObject<Process>(process_handle);
    auto src_paddr_opt = process->ResolveVirtualAddr(start);
    if (!src_paddr_opt) {
        throw std::runtime_error("Failed to look up source address");
    }

    RescheduleImmediately(source.GetPointer());
    return MakeFuture(RESULT_OK);
}

SVCFuture<OS::Result,HandleTable::Entry<DMAObject>> OS::SVCStartInterprocessDMA(Thread& source, Process& src_process, Process& dst_process, const VAddr src_address, const VAddr dst_address, uint32_t size, DMAConfig& dma_config) {
    source.GetLogger()->info("{}SVCStartInterprocessDMA: {:#x} bytes from address {:#010x} in {} to address {:#010x} in {}",
                                ThreadPrinter{source}, size,
                                src_address, ObjectRefPrinter{src_process},
                                dst_address, ObjectRefPrinter{dst_process});

    std::string message;
    message += fmt::format("Channel: {:#x}\n", dma_config.channel);
    message += fmt::format("Value size: {:#x}\n", dma_config.value_size);
    message += fmt::format("Unknown 1: {:#x}\n", dma_config.flags.storage);
    message += fmt::format("Unknown 2: {:#x}\n", dma_config.unknown2);
    for (auto& sub_config : {dma_config.dest, dma_config.source}) {
        message += fmt::format("Unknown1: {:#x}\n", sub_config.unknown);
        message += fmt::format("Flags: {:#x}\n", sub_config.type);
        message += fmt::format("Unknown2: {:#x}\n", sub_config.unknown2);
        message += fmt::format("Transfer size: {:#x}\n", sub_config.transfer_size);
        message += fmt::format("Unknown3: {:#x}\n", sub_config.unknown3);
        message += fmt::format("Stride: {:#x}\n", sub_config.stride);
    }
    source.GetLogger()->info("{}", message);

//     if (dma_config.source.stride == 0) {
//         source.GetLogger()->error("{}Given DMA stride is zero", ThreadPrinter{source});
//         SVCBreak(source, BreakReason::Panic);
//     }

    // NOTE: Correct implementation of this function is critical: The
    //       loader process DMAs an entire ExeFS over the HASH IO registers
    //       to compute SHA256 hashes for verification
    auto paddr_opt = dst_process.ResolveVirtualAddr(dst_address);
    if (!paddr_opt) {
        throw std::runtime_error(fmt::format("Failed to look up target address {:#x} for DMA", dst_address));
    }
    auto paddr = *paddr_opt;

    auto src_paddr_opt = src_process.ResolveVirtualAddr(src_address);
    if (!src_paddr_opt) {
        throw std::runtime_error(fmt::format("Failed to look up source address {:#x} for DMA", src_address));
    }
    auto src_paddr = *src_paddr_opt;

    // 0 means "transfer in one chunk". Otherwise it seems to repeatedly copy over the same chunk of memory address space?
    if (!dma_config.source.transfer_size) {
        dma_config.source.transfer_size = size;
    }

    // TODO: Flush source region
    pica_context.renderer->InvalidateRange(paddr, size);

    // If the transfer crosses a page boundary, make sure the virtual memory range is contiguous.
    // TODO: Ideally this should just work; the real kernel likely splits the DMAs at non-contiguous page boundaries
    auto check_contiguity = [](Process& process, uint32_t vstart, uint32_t pstart, uint32_t num_bytes) {
        const uint32_t page_mask = 0xfffff000;
        const uint32_t page_size = 0x1000;
        uint32_t first_vpage = vstart & page_mask;
        uint32_t first_ppage = pstart & page_mask;
        for (uint32_t offset = 0; first_vpage + offset < vstart + num_bytes; offset += page_size) {
            auto resolved_paddr = process.ResolveVirtualAddr(first_vpage + offset);
            if (!resolved_paddr || *resolved_paddr != first_ppage + offset) {
                throw std::runtime_error("DMAs involving non-contiguous memory ranges are not supported, yet");
            }
        }
    };
    try {
        check_contiguity(src_process, src_address, src_paddr, size);
        check_contiguity(dst_process, dst_address, paddr, size);
    } catch(...) {
        // TODO: Digimon World workaround for Y2R
        size = 0;
    }

    for (uint32_t offset = 0; offset < size; ) {
        const auto bytes_remaining = size - offset;

        // dma_config.source.type is a bit mask specifying transfer granularities that may be involved.
        // E.g. if bit 2 is set, 4-byte transfers may be used, and if not other granularities are used.
        // TODO: Re-enable the mod! A "wrapping" mode exists that writes to a repeated version of the same target range, e.g. used for the HASH registers
        // TODO: Implement the (dma_config.source.type & 2) case for 16-bit transfer granularity
        if ((dma_config.source.type & 4) && bytes_remaining >= 4) {
            auto value = src_process.ReadPhysicalMemory32(src_paddr + offset);
            dst_process.WritePhysicalMemory32(paddr + (offset /*% dma_config.source.transfer_size*/), value);
            offset += 4;
        } else if (dma_config.source.type & 1) {
            auto value = src_process.ReadPhysicalMemory(src_paddr + offset);
            dst_process.WritePhysicalMemory(paddr + (offset /*% dma_config.source.transfer_size*/), value);
            ++offset;
        } else {
            throw std::runtime_error(fmt::format("Given transfer of size {:#x} not supported with the given parameters (:#x)", size, dma_config.source.type));
        }
    }

    auto dma_object = source.GetProcessHandleTable().CreateHandle(std::make_shared<DMAObject>(), MakeHandleDebugInfo());
    RescheduleImmediately(source.GetPointer());
    return MakeFuture(RESULT_OK, dma_object);
}

MemoryManager& OS::FindMemoryRegionContaining(uint32_t paddr, uint32_t size) {
    auto memory_manager = ranges::find_if(  memory_regions,
                                            [paddr, size](const MemoryManager& region) {
                                                return (paddr >= region.RegionStart() && paddr + size <= region.RegionEnd());
                                            });
    if (memory_manager == memory_regions.end()) {
        throw std::runtime_error("Could not determine memory region");
    }
    return *memory_manager;
}

SVCFuture<OS::Result,HandleTable::Entry<CodeSet>> OS::SVCCreateCodeSet(Thread& source, const CodeSetInfo& info, VAddr text_data_addr, VAddr ro_data_addr, VAddr data_data_addr) {
    source.GetLogger()->info("{}SVCCreateCodeSet with given data for text@{:#x}, ro@{:#x}, data@{:#x}",
                             ThreadPrinter{source}, text_data_addr, ro_data_addr, data_data_addr);

    // These pairs should match (other than data_size, which includes bss whereas info.data_pages does not)
    if (info.text_pages != info.text_size || info.ro_pages != info.ro_size || info.data_pages > info.data_size) {
        throw Mikage::Exceptions::Invalid("Invalid arguments for CodeSet creation");
    }

    char app_name[1 + std::tuple_size_v<decltype(info.app_name)>] { };
    ranges::copy(info.app_name, std::begin(app_name));

    // TODO: Move firm-specific functionality to an internal API
    const uint32_t page_size = 0x1000;
    const char* firm_module_names[] = { "sm", "fs", "pm", "loader", "pxi" };
    const bool is_firm_module = (std::end(firm_module_names) != ranges::find_if(firm_module_names, [app_name](const char* module_name) { return strcmp(app_name, module_name) == 0; }));
    if (!is_firm_module && ((text_data_addr % page_size) || (ro_data_addr % page_size) || (data_data_addr % page_size))) {
        throw Mikage::Exceptions::Invalid("Unaligned source addresses for SVCCreateCodeSet");
    }

    source.GetLogger()->info("Process name: \"{}\"", app_name);
    source.GetLogger()->info("text section: Starts at {:#x}, page counts are {:#x} and {:#x}", info.text_start, info.text_pages, info.text_size);
    source.GetLogger()->info("ro   section: Starts at {:#x}, page counts are {:#x} and {:#x}", info.ro_start, info.ro_pages, info.ro_size);
    source.GetLogger()->info("data section: Starts at {:#x}, page counts are {:#x} and {:#x}", info.data_start, info.data_pages, info.data_size);

    std::shared_ptr<CodeSet> codeset;
    auto& mem = source.GetParentProcess().interpreter_setup.mem;
    if (is_firm_module) {
        // For FIRM modules, allocate a contiguous chunk of memory for the program data according to the given section sizes. This is needed since the input addresses may be unaligned and it's expected that each segment is moved to a page-aligned starting address.

        codeset = std::make_shared<CodeSet>(info);
    //    auto text_paddr_opt = source.GetParentProcess().GetPhysicalMemoryManager().AllocateBlock(std::static_pointer_cast<Process>(source.GetParentProcess().shared_from_this()), (info.text_size + info.ro_size + info.data_size) * page_size);
        auto text_paddr_opt = memory_base().AllocateBlock(codeset, (info.text_size + info.ro_size + info.data_size) * page_size);
        if (!text_paddr_opt) {
            throw std::runtime_error(fmt::format(   "{}Failed to allocate {:#x} pages of memory",
                                                    ThreadPrinter{source}, info.text_size + info.ro_size + info.data_size));
        }

        codeset->text_phys.push_back({ *text_paddr_opt, info.text_size });
        codeset->ro_phys.push_back({ codeset->text_phys[0].phys_start + info.text_size * page_size, info.ro_size });
        codeset->data_phys.push_back({ codeset->text_phys[0].phys_start + (info.text_size + info.ro_size) * page_size, info.data_pages });
        codeset->bss_paddr = codeset->text_phys[0].phys_start + (info.text_size + info.ro_size + info.data_pages) * page_size;

        // Copy data to the allocated memory
    //     // TODO: Introduce a generic CopyFromTo function to do this more efficiently
        for (uint32_t offset = 0; offset < info.text_size * page_size; ++offset) {
            Memory::WriteLegacy<uint8_t>(mem, codeset->text_phys[0].phys_start + offset, source.ReadMemory(text_data_addr + offset));
        }
        for (uint32_t offset = 0; offset < info.ro_size * page_size; ++offset) {
            Memory::WriteLegacy<uint8_t>(mem, codeset->ro_phys[0].phys_start + offset, source.ReadMemory(ro_data_addr + offset));
        }

        // Data without BSS
        for (uint32_t offset = 0; offset < info.data_pages * page_size; ++offset) {
            Memory::WriteLegacy<uint8_t>(mem, codeset->data_phys[0].phys_start + offset, source.ReadMemory(data_data_addr + offset));
        }
    } else {
        // NOTE: The underlying memory may be split across different physical
        //       memory regions! System versions 10.4+ do this to randomize
        //       physical address layout.
        codeset = std::make_shared<CodeSet>(info);

        auto source_process = std::static_pointer_cast<Process>(source.GetParentProcess().shared_from_this());
        struct {
            const char* name;
            uint32_t virt_start;
            uint32_t num_pages_total;
            std::vector<CodeSet::Mapping>& phys;
        } sections[] = {
            { "text", text_data_addr, info.text_pages, codeset->text_phys },
            { "ro", ro_data_addr, info.ro_pages, codeset->ro_phys },
            // NOTE: The source process does not reserve space for bss
            { "data", data_data_addr, info.data_pages, codeset->data_phys },
        };
        for (auto& section : sections) {
            source.GetLogger()->info("Reparenting {} section", section.name);
            for (VAddr vaddr = section.virt_start; vaddr < section.virt_start + section.num_pages_total * page_size;) {
                auto [paddr, size] = ResolveVirtualAddrWithSize(source.GetParentProcess(), vaddr).value_or(std::pair { VAddr { }, uint32_t { } });
                if (!paddr || !size) {
                    throw Mikage::Exceptions::Invalid("CodeSet source addresses not mapped");
                }
                ValidateContract((size % page_size) == 0);
                size = std::min<uint32_t>(size, section.num_pages_total * page_size - (vaddr - section.virt_start));
                FindMemoryRegionContaining(paddr, size).TransferOwnership(source_process, codeset, paddr, size);
                section.phys.push_back({ paddr, size / page_size });
                vaddr += size;
            }
        }

        auto& data_region = FindMemoryRegionContaining(source.GetParentProcess().ResolveVirtualAddr(data_data_addr).value(), 1);

        // Allocate extra memory for BSS
        if (info.data_size > info.data_pages) {
            auto bss_paddr = data_region.AllocateBlock(codeset, (info.data_size - info.data_pages) * page_size);
            if (!bss_paddr) {
                throw std::runtime_error("Failed to allocate bss memory");
            }
            codeset->bss_paddr = *bss_paddr;
        } else {
            codeset->bss_paddr = 0;
        }
    }

    // Initialize BSS
    for (uint32_t offset = 0; offset < (info.data_size - info.data_pages) * page_size; ++offset) {
        Memory::WriteLegacy<uint8_t>(mem, codeset->bss_paddr + offset, 0);
    }

#if 1 // TODO: Re-enable for FIRM modules
    // Unmap the given data from the virtual address space of the calling
    // process, since ownership is now transferred to the CodeSet object
    if (source.GetParentProcess().GetId() != 6) { // Omit this logic when we are FakeBootThread... TODO: Do this in a cleaner way!
#if 0 // TODO: Re-enable for FIRM modules TODO: Should REALLY re-enable this for FIRM modules!
        // TODO: Should not need to restrict this to EmuProcess
        if (auto* emu_process = dynamic_cast<EmuProcess*>(&source.GetParentProcess())) {
            auto deallocate = [&](VAddr vaddr, uint32_t size) {
                auto paddr = *source.GetParentProcess().ResolveVirtualAddr(vaddr);
                auto memory_manager = ranges::find_if(  memory_regions,
                                                        [paddr, size](const MemoryManager& region) {
                                                            return (paddr >= region.RegionStart() && paddr + size <= region.RegionEnd());
                                                        });
                if (memory_manager == memory_regions.end()) {
                    throw std::runtime_error("Could not determine memory region");
                }
//                auto memory_manager = (paddr >= ApplicationMemoryStart(settings) && paddr < ApplicationMemoryStart(settings) + ApplicationMemorySize(settings)) ? memory_regions[0]
//                                    : (paddr >= SysMemoryStart(settings) && paddr < SysMemoryStart(settings) + SysMemorySize(settings)) ? memory_system
//                                    : (paddr >= BaseMemoryStart(settings) && paddr < BaseMemoryStart(settings) + BaseMemorySize(settings)) ? memory_base
//                                    : throw std::runtime_error("Could not determine memory region");
                memory_manager->DeallocateBlock(paddr, size);
            };
            deallocate(text_data_addr, info.text_pages * page_size);
            deallocate(ro_data_addr, info.ro_pages * page_size);
            deallocate(data_data_addr, info.data_pages * page_size);
        }
#endif

        bool success = true;
        success &= source.GetParentProcess().UnmapVirtualMemory(text_data_addr, info.text_pages * page_size);
        assert(success);
        success &= source.GetParentProcess().UnmapVirtualMemory(ro_data_addr, info.ro_pages * page_size);
        assert(success);
        success &= source.GetParentProcess().UnmapVirtualMemory(data_data_addr, info.data_pages * page_size);
        assert(success);
    }
#endif

    auto codeset_entry = source.GetProcessHandleTable().CreateHandle<CodeSet>(codeset, MakeHandleDebugInfo());

    Reschedule(source.GetPointer());

    return MakeFuture(RESULT_OK, codeset_entry);
}

static unsigned CountLeadingOnes(uint32_t value) {
    unsigned ret = 0;
    while (value & 0x80000000) {
        ++ret;
        value <<= 1;
    }
    return ret;
}

/**
 * Resolve the given virtual address with respect to the default userland
 * mapping defined by the kernel.
 */
static PAddr ResolveStandardVirtualAddress(VAddr vaddr) {
    // TODO: The particular limits of these regions are untested.
    if (vaddr >= 0x1EC00000 && vaddr < 0x1F000000) {
        // IO registers
        return vaddr - 0x0EB00000;
    } else if (vaddr >= 0x1F000000 && vaddr < 0x1F600000) {
        // VRAM
        return vaddr - 0x07000000;
    } else if (vaddr >= 0x1FF00000 && vaddr < 0x1FF80000) {
        // DSP memory (identity mapped)
        return vaddr;
    } else {
        throw std::runtime_error(fmt::format("Virtual address {:#010x} not covered by the known standard mappings", vaddr));
    }
}

SVCFuture<OS::Result,HandleTable::Entry<Process>> OS::SVCCreateProcess(Thread& source, Handle codeset_handle, KernelCapability* kernel_caps, uint32_t num_kernel_caps) {
    source.GetLogger()->info("{}SVCCreateProcess: num_kernel_caps={:#x}",
                             ThreadPrinter{source}, num_kernel_caps);
    auto codeset = source.GetProcessHandleTable().FindObject<CodeSet>(codeset_handle);

    const uint32_t page_size = 0x1000;

    // Check if this process can be HLEed. This is done by matching a list of
    // known module names against the CodeSet::app_name.
    // NOTE: For titles that can be HLEed but for which no CXI is available
    //       on emulated NAND, the CodeSet is created from dummy data generated
    //       on-the-fly by FakePXI. This tricks LLE loader/pm into accepting
    //       our fake processes.
    for (auto& [process_name, fake_process_info] : hle_titles) {
        if (!ranges::equal(std::string_view { codeset->app_name }, process_name)) {
            continue;
        }

        if (fake_process_info.fake_process.lock()) {
            throw Mikage::Exceptions::Invalid("Attempted to restart HLEed process \"{}\"", process_name);
        }

        auto process = fake_process_info.create(*this, std::string { process_name } + "_hle");
        RegisterProcess(process);
        // Create an entry in our handle table for the new process
        auto process_entry = source.GetProcessHandleTable().CreateHandle<Process>(process, MakeHandleDebugInfo());
        fake_process_info.fake_process = process;

        // Map kernel configuration memory
        process->MapVirtualMemory(configuration_memory, page_size, 0x1FF80000, MemoryPermissions::Read);

        // Map shared memory page
        // TODO: Should only be writable by processes with appropriate exheader information
        process->MapVirtualMemory(shared_memory_page, page_size, 0x1FF81000, MemoryPermissions::ReadWrite);

        Reschedule(source.GetPointer());
        return MakeFuture(RESULT_OK, process_entry);
    }

    // No HLE possible/enabled, proceed to load the actual process

    auto memory_region = [&]() {
        for (unsigned cap_index = 0; cap_index < num_kernel_caps; ++cap_index) {
            KernelCapability cap = kernel_caps[cap_index];
            source.GetLogger()->info("{}Kernel cap identifier {}: {:#010x} ({} leading zeroes)", ThreadPrinter{source},
                                     cap_index, cap.storage, CountLeadingOnes(cap.storage));
            if (CountLeadingOnes(cap.storage) == 8) {
                auto memory_region = BitField::v1::ViewBitField<8, 4, uint32_t>(cap.storage).Value();
                if (memory_region < 1 || memory_region > 3)
                    throw std::runtime_error("Invalid memory region type set in kernel capabilities");
                return static_cast<MemoryRegion>(memory_region);
            }
        }

        throw Mikage::Exceptions::Invalid("No memory type specified in exheader");
    }();
    MemoryManager& memory_allocator = (memory_region == MemoryRegion::App) ? memory_app()
                                    : (memory_region == MemoryRegion::Sys) ? memory_system()
                                    : memory_base();

    // Invalidate all memory cached by the renderer in this region
    // The started application overwrites this memory anyway, so this avoids costly overlap detection
    // TODO: Go further and *destroy* all resources in the overlapping range
    // TODO: This masks a bug in the ResourceManager: The sequence "HOME Menu -> SM3DL -> HOME Menu -> Mii Maker -> Create new Mii -> Start from scratch" will produce a glitchy button texture without this line
    pica_context.renderer->InvalidateRange(memory_allocator.RegionStart(), memory_allocator.RegionEnd() - memory_allocator.RegionStart());

    // Create process
    auto process = std::make_shared<EmuProcess>(*this, source.GetParentProcess().interpreter_setup, MakeNewProcessId(), codeset, memory_allocator);

    // Map program segments into process
    for (auto vaddr = codeset->text_vaddr; auto& mapping : codeset->text_phys) {
        process->MapVirtualMemory(mapping.phys_start, mapping.num_pages * page_size, vaddr, MemoryPermissions::ReadExec);
        memory_allocator.TransferOwnership(codeset, process, mapping.phys_start, mapping.num_pages * page_size);
        vaddr += mapping.num_pages * page_size;
    }
    for (auto vaddr = codeset->ro_vaddr; auto& mapping : codeset->ro_phys) {
        process->MapVirtualMemory(mapping.phys_start, mapping.num_pages * page_size, vaddr, MemoryPermissions::Read);
        memory_allocator.TransferOwnership(codeset, process, mapping.phys_start, mapping.num_pages * page_size);
        vaddr += mapping.num_pages * page_size;
    }
    auto data_vaddr = codeset->data_vaddr;
    for (auto& mapping : codeset->data_phys) {
        process->MapVirtualMemory(mapping.phys_start, mapping.num_pages * page_size, data_vaddr, MemoryPermissions::ReadWrite);
        memory_allocator.TransferOwnership(codeset, process, mapping.phys_start, mapping.num_pages * page_size);
        data_vaddr += mapping.num_pages * page_size;
    }
    if (codeset->bss_paddr) {
        process->MapVirtualMemory(codeset->bss_paddr, codeset->bss_size * page_size, data_vaddr, MemoryPermissions::ReadWrite);
        memory_allocator.TransferOwnership(codeset, process, codeset->bss_paddr, codeset->bss_size * page_size);
    }

    // Map kernel configuration memory
    process->MapVirtualMemory(configuration_memory, page_size, 0x1FF80000, MemoryPermissions::Read);

    // Map shared memory page
    // TODO: Should only be writable for processes with appropriate exheader flags
    process->MapVirtualMemory(shared_memory_page, page_size, 0x1FF81000, MemoryPermissions::ReadWrite);

    for (unsigned cap_index = 0; cap_index < num_kernel_caps; ++cap_index) {
        KernelCapability cap = kernel_caps[cap_index];
        source.GetLogger()->info("{}Kernel cap identifier {}: {:#010x} ({} leading ones)", ThreadPrinter{source},
                                 cap_index, cap.storage, CountLeadingOnes(cap.storage));
        switch (CountLeadingOnes(cap.storage)) {
        case 6:
        {
            // Kernel version
            if (cap.kernel_version().major() != 2) {
                throw Mikage::Exceptions::Invalid("Invalid kernel major version");
            }

            if (cap.kernel_version().minor() > process->ReadMemory(0x1ff80002)) {
                throw Mikage::Exceptions::Invalid("System requires an update to run this title");
            }

            // System version 8.0.0 moves the region for LINEAR memory to 0x30000000
            if (cap.kernel_version().minor() >= 44) {
                process->linear_base_addr = 0x30000000;
            }
            break;
        }

        case 8:
            // Memory region: Already handled above
            break;

        case 9:
        case 11:
        {
            // Map memory page(s). For "11", only a single page is mapped,
            // while "9" maps an entire range of pages.
            const VAddr base_vaddr = cap.map_io_page().page_index()() << 12;
            uint32_t size = page_size;

            if (CountLeadingOnes(cap.storage) == 9) {
                // Map the address range starting from base_vaddr up to the page given by the following descriptor
                if (++cap_index >= num_kernel_caps)
                    throw std::runtime_error("Expected caps descriptor for address range end");

                KernelCapability next_cap = kernel_caps[cap_index];
                if (CountLeadingOnes(next_cap.storage) != 9)
                    throw std::runtime_error("Expected caps descriptor for address range end");

                uint32_t end_vaddr = next_cap.map_io_page().page_index()() << 12;
                if (base_vaddr >= end_vaddr)
                    throw std::runtime_error("Invalid address range");

                // TODO: Does the "read_only" field in the second descriptor have any relevance?

                size = end_vaddr - base_vaddr;
            }

            source.GetLogger()->info("{}SVCCreateProcess mapping VAddr range [{:#010x};{:#010x}] to PAddr {:#010x}",
                                     ThreadPrinter{source}, base_vaddr, base_vaddr + size,
                                     ResolveStandardVirtualAddress(base_vaddr));

            // TODO: Should we actually support mapping memory that spans multiple noncontiguous physical regions?
            for (VAddr vaddr = base_vaddr; vaddr < base_vaddr + size; vaddr += page_size) {
                PAddr paddr = ResolveStandardVirtualAddress(vaddr);

                // TODO: Which permissions should be used here?
                if (!process->MapVirtualMemory(paddr, page_size, vaddr, MemoryPermissions::ReadWrite))
                    SVCBreak(source, BreakReason::Panic);
            }
            break;
        }

        case 32:
            // Unused descriptor
            break;

        default:
            source.GetLogger()->info("{}SVCCreateProcess encountered unknown kernel capability descriptor {:#010x}",
                                     ThreadPrinter{source}, cap.storage);
//            SVCBreak(source, BreakReason::Panic);
        }
    }

    process->name = codeset->app_name;


    // Finally, add the new process to the global process list
    RegisterProcess(process);

    // Create an entry in our handle table for the new process
    auto process_entry = source.GetProcessHandleTable().CreateHandle<Process>(process, MakeHandleDebugInfo());

    Reschedule(source.GetPointer());

    return MakeFuture(RESULT_OK, process_entry);
}

class ResourceLimit : public Object {
public:
    virtual ~ResourceLimit() = default;

    static constexpr size_t num_resources = 10;

    uint64_t limits[num_resources] = {};
};

SVCFuture<Result,HandleTable::Entry<ResourceLimit>> OS::SVCCreateResourceLimit(Thread& source) {
    source.GetLogger()->info("{}SVCCreateResourceLimit", ThreadPrinter{source});

    auto resource_limit = source.GetProcessHandleTable().CreateHandle(std::make_shared<ResourceLimit>(), MakeHandleDebugInfo());

    RescheduleImmediately(source.GetPointer());
    return MakeFuture(RESULT_OK, resource_limit);
}

SVCFuture<Result> OS::SVCSetResourceLimitValues(Thread& source, ResourceLimit& resource_limit, const std::vector<std::pair<uint32_t, uint64_t>>& limits) {
    auto limit_to_string = [](auto&& limit) {
        return fmt::format("\t{:#x}: {:#x}\n", limit.first, limit.second);
    };
    auto log_message = fmt::format("{}SVCSetResourceLimitValues, limits = {{\n", ThreadPrinter{source});
    log_message += ranges::accumulate(limits | ranges::view::transform(limit_to_string), std::string(""));
    log_message += "}}";
    source.GetLogger()->info(log_message);

    for (const auto& limit : limits) {
        auto type = limit.first;
        auto value = limit.second;

        if (type >= resource_limit.num_resources) {
            source.GetLogger()->error("Invalid resource limit type 0x{:#x}", type);
            SVCBreak(source, BreakReason::Panic);
        }

        resource_limit.limits[type] = value;
    }

    RescheduleImmediately(source.GetPointer());
    return MakeFuture(RESULT_OK);
}

SVCEmptyFuture OS::SVCDoNothing(Thread& source) {
    Reschedule(source.GetPointer());
    return MakeFuture(nullptr);
}

SVCFuture<OS::Result,HandleTable::Entry<Object>> OS::SVCCreateDummyObject(FakeThread& source, const std::string& name) {
    source.GetLogger()->info("{}SVCCreateDummyObject, name={}", ThreadPrinter{source}, name);

    auto object = source.GetProcessHandleTable().CreateHandle(std::make_shared<Object>(), MakeHandleDebugInfo());
    object.second->name = name;
    source.GetLogger()->info("{}SVCCreateDummyObject output handle={}",
                             ThreadPrinter{source}, HandlePrinter{source,object.first});
    Reschedule(source.GetPointer());
    return MakeFuture(RESULT_OK, object);
}

SVCCallbackType OS::SVCRaw(Thread& source, unsigned svc_id, Interpreter::ExecutionContext& ctx) try {
    ZoneScopedN("SVCRaw");

    source.GetLogger()->info("{}SVCRaw entering: {:#x}", ThreadPrinter{source}, svc_id);
//    for (auto& callsite : dynamic_cast<EmuThread&>(source).context.backtrace | ranges::view::reverse) {
//        source.GetLogger()->info("{}{:#010x} (via {:#010x}): r0={:#x}, r1={:#x}, r2={:#x}, r3={:#x}, r4={:#x}, r5={:#x}, r6={:#x}, r7={:#x}, r8={:#x}, sp={:#x}",
//                                 ThreadPrinter{source}, callsite.target, callsite.source, callsite.state.reg[0],
//                                 callsite.state.reg[1], callsite.state.reg[2], callsite.state.reg[3], callsite.state.reg[4],
//                                 callsite.state.reg[5], callsite.state.reg[6], callsite.state.reg[7], callsite.state.reg[8],
//                                 callsite.state.reg[13]);
//    }

    struct AtExit {
        ~AtExit() {
            if (!std::uncaught_exception())
                source.GetLogger()->info("{}SVCRaw TODOMOVEME leaving: {:#x}", ThreadPrinter{source}, svc_id);
        }

        Thread& source;
        unsigned svc_id;
    } at_exit{source,svc_id};

    static auto Lookup = [](std::shared_ptr<Thread> thread, auto arg) {
        return boost::hana::overload(
            [=](uint32_t val) {
                return val;
            },
            [=](PromisedWakeIndex) {
                if (thread->promised_result == 0x09401bfe) {
                    // On timeout, leave the wake index at -1.
                    // ErrDisp relies on this to detect timeouts properly
                    return 0xffffffff;
                } else {
                    return thread->wake_index;
                }
            },
            [=](PromisedResult) {
                return thread->promised_result;
            },
            [=](Handle handle) {
                return handle.value;
            },
            // Decode handle table entries of any kind to their handle values
            [=](auto arg) -> typename std::enable_if<Meta::is_same_v<decltype(arg), HandleTable::Entry<typename decltype(arg)::second_type::element_type>>, uint32_t>::type {
                return arg.first.value;
            })(arg);
    };

    auto Encode = [&ctx](auto... args) {
        return [=, &ctx](std::shared_ptr<Thread> thread) {
            std::array<uint32_t, sizeof...(args)> arg_array = {{ static_cast<uint32_t>(Lookup(thread, args))... }};

            // TODO: Use a less wasteful way of encoding the registers
            auto emu_thread = std::static_pointer_cast<EmuThread>(thread);
            auto input_regs = ctx.ToGenericContext();
            ranges::copy(arg_array, std::begin(input_regs.reg));
            ctx.FromGenericContext(input_regs);
        };
    };

    auto EncodeTuple = [&ctx](auto tuple) {
        return [tuple=std::move(tuple), &ctx](std::shared_ptr<Thread> thread) {
            auto emu_thread = std::static_pointer_cast<EmuThread>(thread);
            auto input_regs = ctx.ToGenericContext();
            boost::hana::fold(tuple, std::begin(input_regs.reg), [=](auto register_iterator, auto elem) {
                // TODO: Resolve the return value for each type! E.g. PromisedResult should fetch it from the member rather than the given value
                *register_iterator = Lookup(thread, elem);
                return ++register_iterator;
            });
            ctx.FromGenericContext(input_regs);
        };
    };

    auto EncodeFuture = boost::hana::overload(
                            [=](SVCEmptyFuture&&) {
                                return Encode();
                            },
                            [=](SVCFuture<uint64_t>&& future) {
                                auto&& [value] = Unwrap(std::move(future));
                                return EncodeTuple(std::make_tuple(value & 0xFFFFFFFF, value >> 32));
                            },
                            [=](auto&& future) {
                                return EncodeTuple(Unwrap(std::move(future)));
                            }
                        );

    // TODO: Use a less wasteful way of reading the registers
    auto input_regs = ctx.ToGenericContext();

    auto& svc_activity = activity.GetSubActivity("SVC");

    switch (svc_id) {
    case 0x1: // ControlMemory
        return EncodeFuture(SVCControlMemory(source, input_regs.reg[1], input_regs.reg[2], input_regs.reg[3], input_regs.reg[0], input_regs.reg[4]));

    case 0x2: // QueryMemory
    case 0x7d: // QueryProcessMemory
    {
        auto& query_memory_activity = svc_activity.GetSubActivity("QueryMemory");
        auto scope_measure = MeasureScope(query_memory_activity);

        bool for_calling_process = (svc_id == 0x2);

        VAddr address = for_calling_process ? input_regs.reg[2] : input_regs.reg[3];
        auto& process = *source.GetProcessHandleTable().FindObject<Process>(for_calling_process ? Handle{0xffff8001} : Handle{input_regs.reg[2]});

        source.GetLogger()->warn("{}SVCQuery{}Memory: process {}, address {:#x})",
                                 ThreadPrinter{source}, for_calling_process ? "" : "Process", ProcessPrinter { process }, address);

        if (address & 0xc0000000) {
            // TODO: Return error code
            source.GetLogger()->error("{}SVCQuery{}Memory: Invalid memory address",
                                      ThreadPrinter{source}, for_calling_process ? "" : "Process");
            SVCBreak(source, BreakReason::Panic);
        }

        auto& vm = process.virtual_memory;

        // NOTE: ns uses this to find the virtual memory address that MapMemoryBlock mapped a shared memory buffer to


        // Find first mapping (starting from the end) that starts at an adress smaller or equal equal to the given one.
        auto it = std::find_if(vm.rbegin(), vm.rend(), [address](auto& entry) { return entry.first <= address; });
        if (it == vm.rend() || it->first + it->second.size <= address) {
            // No mapping found. Return range from previous mapping (if any) and next one
            source.GetLogger()->error("{}SVCQuery{}Memory: Unknown memory region",
                                      ThreadPrinter{source}, for_calling_process ? "" : "Process");
            auto previous_end = (it == vm.rend() ? 0 : it->first + it->second.size);
            if (it == vm.rbegin()) {
                // TODO: return range up until 0x40000000?
                throw Mikage::Exceptions::NotImplemented("");
            }
            auto next_begin = std::prev(it)->first;
            return Encode(RESULT_OK, previous_end, next_begin - previous_end, 0, 0, 0);
        } else {
            uint32_t base_vaddr = it->first;
            uint32_t size = it->second.size;

            const MemoryPermissions permissions = it->second.permissions;
            uint32_t state;
            uint32_t page_flags = 0; // TODO: When is this supposed to be non-zero?

            if (base_vaddr >= process.linear_base_addr && base_vaddr + size <= process.linear_base_addr + 0x8000000) {
                // Linear heap
//                 state = 7;
                state = 6; // TODOTEST: Value returned for memory regions allocated using SVCCreateMemoryBlock?
            } else if (base_vaddr >= 0x08000000 && base_vaddr + size < 0x10000000) {
                // Non-linear heap
                // NOTE: The base_vaddr + size == 0x10000000 case is the stack (handled below)
                state = 5; // "Private". Expected by ro::Initialize
            } else  if (base_vaddr >= 0x100000 && base_vaddr + size < 0x10000000) {
                state = 10;
                // TODO: Make (Un)MapMemory defragment memory ranges instead
                while (it != vm.rbegin() && std::prev(it)->first == base_vaddr + size && std::prev(it)->second.permissions == permissions) {
                    --it;
                    size += it->second.size;
                }
            } else if (base_vaddr + size <= 0x10000000) { // TODO: Check the lower stack size bound, too! .. Actually, just turn this into a "=="
                // Stack
                state = 11; // "Locked". TODOTEST
            } else {
                // TODO: Support other memory regions than linear heap and stack
                throw Mikage::Exceptions::NotImplemented(   "{}SVCQuery{}Memory: Unknown memory region {:#x}-{:#x}",
                                                            ThreadPrinter{source}, for_calling_process ? "" : "Process", base_vaddr, base_vaddr + size);
            }
            source.GetLogger()->info("{}SVCQuery{}Memory: returning address {:#x}, size {:#x}",
                                     ThreadPrinter{source}, for_calling_process ? "" : "Process", base_vaddr, size);

            return Encode(RESULT_OK, base_vaddr, size, Meta::to_underlying(permissions), state, page_flags);
        }
    }

    case 0x3: // ExitProcess
    {
        source.GetLogger()->info("{}SVCExitProcess", ThreadPrinter{source});

        auto& process = source.GetParentProcess();

        while (process.threads.size() != 1) {
            for (auto thread : process.threads) {
                if (thread.get() == &source) {
                    // Must be destroyed after reschedule
                    continue;
                }

                ExitThread(*thread);
                TriggerThreadDestruction(std::move(thread));

                // thread list was modified, so break to the outer loop
                break;
            }
        }

        ExitThread(source);
        Reschedule(source.GetPointer());

        // Return an empty callback - it won't be used after all anyway
        // TODO: We can probably even return "{}" here
        return [=](std::shared_ptr<Thread> thread) {};
    }

    case 0x5: // SetProcessAffinityMask
    {
        auto process = source.GetProcessHandleTable().FindObject<Process>(Handle{input_regs.reg[0]});
        if (!process)
            SVCBreak(source, BreakReason::Panic);

        source.GetLogger()->warn("{}SVCSetProcessAffinityMask: Stub (Process {}, processor count {:#x})",
                                 ThreadPrinter{source}, ProcessPrinter{*process}, input_regs.reg[2]);
        RescheduleImmediately(source.GetPointer());
        return Encode(RESULT_OK);
    }

    case 0x7: // SetProcessIdealProcessor
    {
        auto process = source.GetProcessHandleTable().FindObject<Process>(Handle{input_regs.reg[0]});
        if (!process)
            SVCBreak(source, BreakReason::Panic);

        source.GetLogger()->warn("{}SetProcessIdealProcessor: Stub (Process {}, processor {:#x})",
                                 ThreadPrinter{source}, ProcessPrinter{*process}, input_regs.reg[1]);
        RescheduleImmediately(source.GetPointer());
        return Encode(RESULT_OK);
    }

    case 0x8: // CreateThread
        return EncodeFuture(SVCCreateThread(source, input_regs.reg[1], input_regs.reg[2], input_regs.reg[3], input_regs.reg[0], input_regs.reg[4]));

    case 0x9: // ExitThread
        SVCExitThread(source);
        // Return an empty callback - it won't be used after all anyway
        // TODO: We can probably even return "{}" here
        return [=](std::shared_ptr<Thread> thread) {};

    case 0xa: // SleepThread
    {
        int64_t duration = static_cast<int64_t>((static_cast<uint64_t>(input_regs.reg[1]) << 32) | static_cast<uint64_t>(input_regs.reg[0]));

        // NOTE: This function has no return value
        return EncodeFuture(SVCSleepThread(source, duration));

    }

    case 0xb: // GetThreadPriority
    {
        source.GetLogger()->info("SVCGetThreadPriority for {}", HandlePrinter{source,Handle{input_regs.reg[1]}});
        auto thread = source.GetProcessHandleTable().FindObject<Thread>(Handle{input_regs.reg[1]});
        if (!thread)
            SVCBreak(source, BreakReason::Panic);

        RescheduleImmediately(source.GetPointer());
        return Encode(RESULT_OK, thread->priority);
    }

    case 0xc: // SetThreadPriority
    {
        // TODO: Implement. Reporting success for now.
        // NOTE: r0 is thread handle, r1 is priority
        RescheduleImmediately(source.GetPointer());
        return Encode(RESULT_OK);
    }

    case 0x11: // GetCurrentProcessorNumber
    {
        return Encode(RESULT_OK, uint32_t { 1 });
    }

    case 0x12: // Run
    {
        // 3dbrew erratum: This SVC doesn't actually take a pointer to the struct, but instead specifies the arguments through registers
        StartupInfo startup_info = {
            static_cast<int32_t>(input_regs.reg[1]), // priority
            static_cast<uint32_t>(input_regs.reg[2]), // stack size
            static_cast<int32_t>(input_regs.reg[3]), // argc
            static_cast<VAddr>(input_regs.reg[4]), // argv address
            static_cast<VAddr>(input_regs.reg[5]) // envp address
        };
        return EncodeFuture(SVCRun(source, Handle{input_regs.reg[0]}, startup_info));
    }

    case 0x13: // CreateMutex
        return EncodeFuture(SVCCreateMutex(source, input_regs.reg[1]));

    case 0x14: // ReleaseMutex
    {
        Handle handle{input_regs.reg[0]};
        return EncodeFuture(SVCReleaseMutex(source, handle));
    }

    case 0x15: // CreateSemaphore
    {
        int32_t init_count = input_regs.reg[1];
        if (init_count < 0)
            return Encode(0xe0e01bfd);

        int32_t max_count = input_regs.reg[2];
        if (init_count > max_count)
            return Encode(0xd90007ee);

        return EncodeFuture(SVCCreateSemaphore(source, init_count, max_count));
    }

    case 0x16: // ReleaseSemaphore
    {
        Handle handle{input_regs.reg[1]};
        int32_t times = input_regs.reg[2];
        auto semaphore = source.GetProcessHandleTable().FindObject<Semaphore>(handle);
        if (semaphore == nullptr)
            SVCBreak(source, BreakReason::Panic);

        return EncodeFuture(SVCReleaseSemaphore(source, *semaphore, times));
    }

    case 0x17: // CreateEvent
    {
        auto type = static_cast<ResetType>(input_regs.reg[1]);
        return EncodeFuture(SVCCreateEvent(source, type));
    }

    case 0x18: // SignalEvent
    {
        Handle handle{input_regs.reg[0]};
        return EncodeFuture(SVCSignalEvent(source, handle));
    }

    case 0x19: // ClearEvent
    {
        Handle handle{input_regs.reg[0]};
        return EncodeFuture(SVCClearEvent(source, handle));
    }

    case 0x1a: // CreateTimer
    {
        auto type = static_cast<ResetType>(input_regs.reg[1]);
        return EncodeFuture(SVCCreateTimer(source, type));
    }

    case 0x1b: // SetTimer
    {
        auto timer = source.GetProcessHandleTable().FindObject<Timer>(Handle{input_regs.reg[0]});
        int64_t initial = (static_cast<int64_t>(input_regs.reg[3]) << 32) | input_regs.reg[2];
        int64_t interval = (static_cast<int64_t>(input_regs.reg[4]) << 32) | input_regs.reg[1];
        if (!timer) {
            SVCBreak(source, BreakReason::Panic);
        }

        return EncodeFuture(SVCSetTimer(source, *timer, initial, interval));
    }

    case 0x1e: // CreateMemoryBlock
        return EncodeFuture(OS::SVCCreateMemoryBlock(source, input_regs.reg[1], input_regs.reg[2], input_regs.reg[3], input_regs.reg[0]));

    case 0x1f: // MapMemoryBlock
        return EncodeFuture(OS::SVCMapMemoryBlock(  source, Handle{input_regs.reg[0]}, input_regs.reg[1],
                                                    MemoryPermissions { input_regs.reg[2] },
                                                    MemoryPermissions { input_regs.reg[3] }));

    case 0x20: // UnmapMemoryBlock
    {
        auto mem_block = source.GetProcessHandleTable().FindObject<SharedMemoryBlock>(Handle{input_regs.reg[0]});
        if (!mem_block)
            SVCBreak(source,BreakReason::Panic);
        return EncodeFuture(OS::SVCUnmapMemoryBlock(source, *mem_block, input_regs.reg[1]));
    }

    case 0x21: // CreateAddressArbiter
        return EncodeFuture(SVCCreateAddressArbiter(source));

    case 0x22: // ArbitrateAddress
    {
        Handle arbiter_handle{input_regs.reg[0]};
        uint32_t address = input_regs.reg[1];
        auto type = static_cast<ArbitrationType>(input_regs.reg[2]);
        uint32_t value = input_regs.reg[3];

        if (input_regs.reg[2] > 4)
            SVCBreak(source, BreakReason::Panic);

        // TODO: Word order?
        auto timeout = (static_cast<int64_t>(input_regs.reg[5]) << 32) | input_regs.reg[4];

        return EncodeFuture(SVCArbitrateAddress(source, arbiter_handle, address, type, value, timeout));
    }

    case 0x23: // CloseHandle
    {
        Handle handle{input_regs.reg[0]};
        return EncodeFuture(SVCCloseHandle(source, handle));
    }

    case 0x24: // WaitSynchronization
    {
        // NOTE: 64-bit values are encoded in two registers, and the starting register is padded to an even-numbered one. Hence, r1 is actually unused in this system call.
        Handle handle{input_regs.reg[0]};
        int64_t timeout = (static_cast<uint64_t>(input_regs.reg[3]) << 32) | input_regs.reg[2];
        return EncodeFuture(SVCWaitSynchronization(source, handle, timeout));
    }

    case 0x25: // WaitSynchronizationN
    {
        // NOTE: 3dmoo disagrees, but also has the timeout marked as "todo". Citra says the high part is in R4 and the low part in r0
//         auto timeout = static_cast<int64_t>((uint64_t{input_regs.reg[5]} << 32) | input_regs.reg[4]);
        auto timeout = static_cast<int64_t>((uint64_t{input_regs.reg[4]} << 32) | input_regs.reg[0]);

        std::vector<Handle> handles(input_regs.reg[2]);
        for (uint32_t index = 0; index < handles.size(); ++index)
            handles[index] = Handle{source.ReadMemory32(input_regs.reg[1] + 4 * index)};

        return EncodeFuture(SVCWaitSynchronizationN(source, handles.data(), handles.size(), input_regs.reg[3], timeout));
    }

    case 0x27: // DuplicateHandle
    {
        Handle handle{input_regs.reg[1]};
        return EncodeFuture(SVCDuplicateHandle(source, handle));
    }

    case 0x28: // GetSystemTick
        return EncodeFuture(SVCGetSystemTick(source));

    case 0x2a: // GetSystemInfo
    {
        source.GetLogger()->info("{}GetSystemInfo: r1={:#x}, r2={:#x}", ThreadPrinter{source}, input_regs.reg[1], input_regs.reg[2]);

        uint32_t info_type = input_regs.reg[1];
        uint32_t param = input_regs.reg[2];

        if (info_type == 0x1a) {
            // Total number of processes which were launched by the kernel
            // Used for access control by the ServerManager process, and also
            // by PM to set the number of resource limits for processes 0 up to
            // this number minus one (corresponding to the FIRM modules)
            RescheduleImmediately(source.GetPointer());
            // Return one more for the SM process so that BootThread is exempted from service access checks
            // TODO: Currently returning much more than that so that we just don't have to bother...
            return Encode(RESULT_OK, num_firm_modules + 100 * (source.GetParentProcess().GetId() == 0), 0 /* Ignored (?) */);
        } else if (info_type != 0 || param != 1) {
            throw Mikage::Exceptions::NotImplemented("Unknown SVCGetSystemInfo arguments {:#x} and {:#x}", info_type, param);
        } else {
            RescheduleImmediately(source.GetPointer());
            return Encode(RESULT_OK, memory_app().UsedMemory(), 0 /* Ignored (?) */);
        }
    }

    case 0x2b: // GetProcessInfo
    {
        auto& process = *source.GetProcessHandleTable().FindObject<Process>(Handle{input_regs.reg[1]});

        // r2 specifies the kind of information to retrieve. Currently, we only
        // support a limited set of inputs
        if (input_regs.reg[2] == 1) {
            source.GetLogger()->warn("{}: GetProcessInfo with info type 1 stubbed", ThreadPrinter{source});
            // Welp...
            return Encode(RESULT_OK, 0, 0);
        } else if (input_regs.reg[2] == 2) {
            // Amount of memory used this process
            // TODO: This may be overcounting memory, since the actual system sums up a very specific set of metrics instead
            uint32_t used_memory = 0;
            for (const auto& [addr, block] : process.memory_allocator.taken) {
                if (block.owner.lock() == std::static_pointer_cast<Process>(process.shared_from_this())) {
                    used_memory += block.size_bytes;
                }
            }

            source.GetLogger()->warn("{}: GetProcessInfo with info type 2. Returning {:#x}", ThreadPrinter{source}, used_memory);
            return Encode(RESULT_OK, used_memory, 0);
        } else if (input_regs.reg[2] == 19) {
            // TODO: Used in system version 11.x
            source.GetLogger()->warn("{}: GetProcessInfo with info type 19 stubbed", ThreadPrinter{source});
            return Encode(RESULT_OK, 0, 0);
        } else if (input_regs.reg[2] == 20) {
            source.GetLogger()->warn("{}: GetProcessInfo with info type 20 NOT SURE IF WE GOT THIS RIGHT POST-8.0.0", ThreadPrinter{source});
            // denotes the value to add to virtual
            // addresses in the LINEAR region to obtain physical addresses.
            auto value = Memory::FCRAM::start - process.linear_base_addr; // FCRAM physical address minus LINEAR virtual base address;
            RescheduleImmediately(source.GetPointer());
            return Encode(RESULT_OK, value, 0 /* Ignored (?) */);
        } else {
            throw std::runtime_error(fmt::format("Unsupported GetProcessInfo query {:#x}", input_regs.reg[2]));
        }

    }

    case 0x2d: // ConnectToPort
    {
        uint32_t name_addr = input_regs.reg[1];
        std::string port_name;
        while (uint8_t c = source.ReadMemory(name_addr++)) {
            port_name.push_back(c);
            if (port_name.size() > 8)
                SVCBreak(source, BreakReason::Panic);
        }

        return EncodeFuture(SVCConnectToPort(source, port_name));
    }

    case 0x32: // SendSyncRequest
    {
        Handle session_handle{input_regs.reg[0]};
        return EncodeFuture(SVCSendSyncRequest(source, session_handle));
    }

    case 0x33: // OpenProcess
    {
        return EncodeFuture(SVCOpenProcess(source, input_regs.reg[1]));
    }

    case 0x35: // GetProcessId
    {
        auto process = source.GetProcessHandleTable().FindObject<Process>(Handle{input_regs.reg[1]});
        return EncodeFuture(SVCGetProcessId(source, *process));
    }

    case 0x37: // GetThreadId
    {
        auto thread = source.GetProcessHandleTable().FindObject<Thread>(Handle{input_regs.reg[1]});
        return EncodeFuture(SVCGetThreadId(source, *thread));
    }

    case 0x38: // GetResourceLimit
    {
        auto process = source.GetProcessHandleTable().FindObject<Process>(Handle{input_regs.reg[1]});

        std::cerr << "SVCGetResourceLimit" << std::endl;

        if (!process->limit) {
            throw Mikage::Exceptions::Invalid("Called GetResourceLimit but the process had none set");
        }

        auto handle = source.GetProcessHandleTable().CreateHandle(process->limit, MakeHandleDebugInfo());
        RescheduleImmediately(source.GetPointer());
        return Encode(RESULT_OK, handle.first);
    }

    case 0x39: // GetResourceLimitLimitValues
    case 0x3a: // GetResourceLimitCurrentValues
    {
        uint32_t out_addr = input_regs.reg[0];
        auto resource_limit = source.GetProcessHandleTable().FindObject<ResourceLimit>({input_regs.reg[1]});
        uint32_t names_addr = input_regs.reg[2];
        uint32_t num_names = input_regs.reg[3];

        const bool is_limits = (svc_id == 0x39);

        std::cerr << (is_limits ? "SVCGetResourceLimitLimitValues" : "SVCGetResourceLimitCurrentValues") << " to addr 0x"
                  << std::hex << out_addr
                  << ", 0x" << num_names
                  << " names at addr 0x" << names_addr << std::endl;
        for (unsigned name = 0; name < num_names; ++name) {
            uint32_t addr = names_addr + name * 4;
            uint32_t limit_type = source.ReadMemory32(addr);
            std::cerr << "Name " << std::dec << name << ": 0x" << std::hex << limit_type << std::endl;

            if (limit_type > std::size(resource_limit->limits)) {
                throw Mikage::Exceptions::Invalid("Out-of-bounds limit type");
            }
            if (is_limits) {
                source.WriteMemory32(out_addr + 8 * name    , resource_limit->limits[limit_type] & 0xffffffff);
                source.WriteMemory32(out_addr + 8 * name + 4, resource_limit->limits[limit_type] >> 32);
            } else {
                if (limit_type == 0x1) {
                    // Current commit: Apparently, Citra always returns 0 here.
                    // TODO: Properly respect the application's exheader flags here.
                    // TODO NOW: We just changed this to write 8 bytes instead of 4, and I'm not sure whether I got the word order right.
                    source.WriteMemory32(out_addr + 8 * name    , memory_app().UsedMemory());
                    source.WriteMemory32(out_addr + 8 * name + 4, 0);
                    std::cerr << "Returning value 0x" << std::hex << memory_app().UsedMemory() << std::endl;
                } else {
                    throw 5;
                }
            }
        }

        RescheduleImmediately(source.GetPointer());
        return Encode(RESULT_OK);
    }

    case 0x3c: // Break
    {
        return EncodeFuture(SVCBreak(source, static_cast<OS::BreakReason>(input_regs.reg[0])));
    }

    case 0x3d: // OutputDebugString
    {
        auto string_addr = input_regs.reg[0];
        auto string_len = input_regs.reg[1];
        auto log_message = fmt::format("{}Debug output: ", ThreadPrinter{source});
        for (uint32_t addr = string_addr; addr < string_addr + string_len; ++addr) {
            char data = source.ReadMemory(addr);
            if (data == 0)
                break;
            log_message += data;
        }
        source.GetLogger()->info(log_message);
        RescheduleImmediately(source.GetPointer());
        return Encode();
    }

    case 0x47: // CreatePort
    {
        uint32_t name_addr = input_regs.reg[2];
        std::string port_name;

        uint8_t c;
        while (name_addr && (c = source.ReadMemory(name_addr++))) {
            port_name.push_back(c);
            if (port_name.size() > 8)
                SVCBreak(source, BreakReason::Panic);
        }

        uint32_t max_sessions = input_regs.reg[3];
        return EncodeFuture(SVCCreatePort(source, port_name, max_sessions));
    }

    case 0x48: // CreateSessionToPort
        return EncodeFuture(SVCCreateSessionToPort(source, Handle{input_regs.reg[1]}));

    case 0x49: // CreateSession
        return EncodeFuture(SVCCreateSession(source));

    case 0x4a: // AcceptSession
    {
        auto server_port = source.GetProcessHandleTable().FindObject<ServerPort>(Handle{input_regs.reg[1]});
        return EncodeFuture(SVCAcceptSession(source, *server_port));
    }

    case 0x4f: // ReplyAndReceive
    {
        VAddr handles_addr = input_regs.reg[1];
        uint32_t num_handles = input_regs.reg[2];
        Handle reply_target{input_regs.reg[3]};
        std::vector<Handle> handles(num_handles);
        for (unsigned i = 0; i < num_handles; ++i)
            handles[i] = Handle{source.ReadMemory32(handles_addr + 4 * i)};

        return EncodeFuture(SVCReplyAndReceive(source, handles.data(), num_handles, reply_target));
    }

    case 0x50: // BindInterrupt
    {
        uint32_t interrupt_index = input_regs.reg[0];
        Handle observer_handle{input_regs.reg[1]};
        int32_t priority = input_regs.reg[2];
        uint32_t is_manual_clear = input_regs.reg[3];

        auto observer = source.GetProcessHandleTable().FindObject<Event>(observer_handle);
        return EncodeFuture(SVCBindInterrupt(source, interrupt_index, observer, priority, is_manual_clear));
    }

    case 0x52: // InvalidateProcessDataCache
    {
        Handle process { input_regs.reg[0] };
        uint32_t addr = input_regs.reg[1];
        uint32_t size = input_regs.reg[2];
        return EncodeFuture(SVCInvalidateProcessDataCache(source, process, addr, size));
    }

    case 0x53: // StoreProcessDataCache
    {
        uint32_t addr = input_regs.reg[1];
        uint32_t size = input_regs.reg[2];
        source.GetLogger()->warn("{}Omitting StoreProcessDataCache for VAddr range [{:#010x}:{:#010x}]",
                                 ThreadPrinter{source}, addr, addr + size);

        // We don't implement caches, hence we can just omit this system call.
        RescheduleImmediately(source.GetPointer());
        return Encode(RESULT_OK);
    }

    case 0x54: // FlushProcessDataCache
    {
        Handle process { input_regs.reg[0] };
        uint32_t addr = input_regs.reg[1];
        uint32_t size = input_regs.reg[2];
        return EncodeFuture(SVCFlushProcessDataCache(source, process, addr, size));
    }

    case 0x55: // StartInterprocessDMA
    {
        auto dst_process = source.GetProcessHandleTable().FindObject<Process>({input_regs.reg[1]});
        auto src_process = source.GetProcessHandleTable().FindObject<Process>({input_regs.reg[3]});
        const uint32_t dst_address = input_regs.reg[2];
        const uint32_t src_address = input_regs.reg[0];
        uint32_t size = input_regs.reg[4];
        uint32_t dma_config_address = input_regs.reg[5];

        source.GetLogger()->info("{}SVCStartInterprocessDMA: {:#x} bytes from address {:#010x} in {} to address {:#010x} in {}",
                                 ThreadPrinter{source}, size,
                                 src_address, ObjectPrinter{src_process},
                                 dst_address, ObjectPrinter{dst_process});

        // TODO: Most of the contents of this struct need to be verified!
        DMAConfig dma_config = {
            source.ReadMemory(dma_config_address),
            source.ReadMemory(dma_config_address + 1),
            { source.ReadMemory(dma_config_address + 2) },
            source.ReadMemory(dma_config_address + 3),
            DMAConfig::SubConfig::Default(),
            DMAConfig::SubConfig::Default()
        };

        if (dma_config.flags.LoadTargetConfig()() || dma_config.flags.LoadTargetAltConfig()()) {
            const auto peripheral_id = dma_config.flags.LoadTargetAltConfig()() ? uint8_t{0xff} : source.ReadMemory(dma_config_address + 4);

            // TODO: Optimize reads...
            dma_config.dest = {
                peripheral_id,
                source.ReadMemory(dma_config_address + 5),
                static_cast<uint16_t>(source.ReadMemory(dma_config_address + 6) | (uint16_t{source.ReadMemory(dma_config_address + 7)} << 8)),
                static_cast<uint16_t>(source.ReadMemory(dma_config_address + 8) | (uint16_t{source.ReadMemory(dma_config_address + 9)} << 8)),
                static_cast<uint16_t>(source.ReadMemory(dma_config_address + 10) | (uint16_t{source.ReadMemory(dma_config_address + 11)} << 8)),
                static_cast<uint16_t>(source.ReadMemory(dma_config_address + 12) | (uint16_t{source.ReadMemory(dma_config_address + 13)} << 8))
            };
        }

        if (dma_config.flags.LoadSourceConfig()() || dma_config.flags.LoadSourceAltConfig()()) {
            const auto peripheral_id = dma_config.flags.LoadSourceAltConfig()() ? uint8_t{0xff} : source.ReadMemory(dma_config_address + 14);

            dma_config.source = {
                peripheral_id,
                source.ReadMemory(dma_config_address + 15),
                static_cast<uint16_t>(source.ReadMemory(dma_config_address + 16) | (uint16_t{source.ReadMemory(dma_config_address + 17)} << 8)),
                static_cast<uint16_t>(source.ReadMemory(dma_config_address + 18) | (uint16_t{source.ReadMemory(dma_config_address + 19)} << 8)),
                static_cast<uint16_t>(source.ReadMemory(dma_config_address + 20) | (uint16_t{source.ReadMemory(dma_config_address + 21)} << 8)),
                static_cast<uint16_t>(source.ReadMemory(dma_config_address + 22) | (uint16_t{source.ReadMemory(dma_config_address + 22)} << 8))
            };
        }

        if (!dst_process | !src_process) {
            source.GetLogger()->error("{}Invalid process handles given", ThreadPrinter{source});
            SVCBreak(source, BreakReason::Panic);
        }

        return EncodeFuture(SVCStartInterprocessDMA(source, *src_process, *dst_process, src_address, dst_address, size, dma_config));
    }

    case 0x56: // StopDMA
    {
        // NOTE: One might think this system call is intended to cancel a
        //       running DMA, but it (also?) seems to be used to be called
        //       after a DMA initiated by StartInterProcessDMA has finished.
//////        //       TODONOWEDONTDOTHISATMHence, all we do here is free the given DMA handle. TODO: SHOULD WE DO THIS OR NOT?
        RescheduleImmediately(source.GetPointer());
        return Encode(RESULT_OK);
    }

    case 0x57: // GetDMAState
    {
        uint32_t state_addr = input_regs.reg[0];
        source.WriteMemory32(state_addr, 2); // "2" seems to signal that the DMA has completed
        source.GetLogger()->info("{}SVCGetDMAState: Stub; returning dummy value to signal instant DMA completion", ThreadPrinter{source});
        RescheduleImmediately(source.GetPointer());
        return Encode(RESULT_OK);
    }

    // Sets up FCRAM cutoff for the GPU
    case 0x59:
        return Encode(RESULT_OK);

    case 0x70: // ControlProcessMemory
    {
        auto& process = *source.GetProcessHandleTable().FindObject<Process>(Handle{input_regs.reg[0]});
        uint32_t addr0 = input_regs.reg[1];
        uint32_t addr1 = input_regs.reg[2];
        uint32_t size = input_regs.reg[3];
        uint32_t operation = input_regs.reg[4];
        MemoryPermissions permissions { input_regs.reg[5] };
        source.GetLogger()->info("{}SVCControlProcessMemory: process={}, addr0={:#010x}, addr1={:#010x}, size={:#x}, op={:#x}, perm={:#x}",
                                 ThreadPrinter{source}, ProcessPrinter{process}, addr0, addr1, size, operation, Meta::to_underlying(permissions));

        return EncodeFuture(SVCControlProcessMemory(source, process, addr0, addr1, size, operation, permissions));
    }


    case 0x73: // CreateCodeSet
    {
        uint32_t code_set_info_addr = input_regs.reg[1];
        uint32_t code_data_addr = input_regs.reg[2];
        uint32_t ro_data_addr = input_regs.reg[3];
        uint32_t data_data_addr = input_regs.reg[0];

        // TODO: Factor this function out into a standalone EmulatedMemoryReader functor
        auto load_buffer_data = [&](char* dest, size_t size) {
            for (auto data_ptr = dest; data_ptr - dest < size; ++data_ptr) {
                *data_ptr = source.ReadMemory(code_set_info_addr++);
            }
        };
        auto info = FileFormat::SerializationInterface<CodeSetInfo>::Load(load_buffer_data);

        return EncodeFuture(SVCCreateCodeSet(source, info, code_data_addr, ro_data_addr, data_data_addr));
    }

    case 0x75: // CreateProcess
    {
        Handle codeset{input_regs.reg[1]};
        std::array<KernelCapability, 28> caps;
        uint32_t num_caps = input_regs.reg[3];
        if (num_caps > caps.size()) {
            throw Mikage::Exceptions::Invalid("Attempted to create process with too many KernelCapabilities");
        }
        for (uint32_t cap_index = 0; cap_index < num_caps; ++cap_index) {
            caps[cap_index] = { source.ReadMemory32(input_regs.reg[2] + 4 * cap_index) };
        }

        return EncodeFuture(SVCCreateProcess(source, codeset, caps.data(), num_caps));
    }

    case 0x76: // TerminateProcess
    {
        auto process = source.GetProcessHandleTable().FindObject<Process>({input_regs.reg[0]});
        source.GetLogger()->info("{}SVCTerminateProcess: {}", ThreadPrinter{source}, ProcessPrinter{*process});

        if (process.get() == &source.GetParentProcess()) {
            throw Mikage::Exceptions::Invalid("Attempted to terminate a process from itself");
        }

        if (process->status == Process::Status::Stopping) {
            throw Mikage::Exceptions::Invalid("Attempted to terminate process that was already stopping");
        }

        for (auto& thread : process->threads) {
            ExitThread(*thread);
            // Actual destruction handled below
        }

        while (true) {
            bool last = process->threads.size() == 1;
            auto thread = process->threads.front();
            if (last) {
                // Release reference
                process.reset();
            }
            TriggerThreadDestruction(std::move(thread));
            if (last) {
                break;
            }
        }

        return Encode(RESULT_OK);
    }

    case 0x77: // SetProcessResourceLimits
    {
        auto process = source.GetProcessHandleTable().FindObject<Process>({input_regs.reg[0]});
        auto limit = source.GetProcessHandleTable().FindObject<ResourceLimit>({input_regs.reg[1]});
        source.GetLogger()->info("{}SetProcessResourceLimits: {} for process {}", ThreadPrinter{source}, ObjectPrinter { limit }, ObjectPrinter { process });
        process->limit = limit;
        RescheduleImmediately(source.GetPointer());
        return Encode(RESULT_OK);
    }

    case 0x78: // CreateResourceLimit
    {
        return EncodeFuture(SVCCreateResourceLimit(source));
    }

    case 0x79: // SetResourceLimitValues
    {
        auto resource_limit = source.GetProcessHandleTable().FindObject<ResourceLimit>({input_regs.reg[0]});
        uint32_t limit_type_addr{input_regs.reg[1]};
        uint32_t limit_value_addr{input_regs.reg[2]};
        uint32_t limit_count{input_regs.reg[3]};
        std::vector<std::pair<uint32_t, uint64_t>> limits;
        for (uint32_t limit = 0; limit < limit_count; ++limit) {
            uint32_t type = source.ReadMemory32(limit_type_addr);
            uint32_t value = uint64_t{source.ReadMemory32(limit_value_addr)} | (uint64_t{source.ReadMemory32(limit_value_addr + 4)} << 32);
            limit_type_addr += 4;
            limit_value_addr += 8;
            limits.emplace_back(std::make_pair(type, value));
        }
        return EncodeFuture(SVCSetResourceLimitValues(source, *resource_limit, limits));
    }

    case 0x7c: // KernelSetState
    {
        source.GetLogger()->info("{}KernelSetState: r0={:#x}, r1={:#x}, r2={:#x}",
                                 ThreadPrinter{source}, input_regs.reg[0], input_regs.reg[1], input_regs.reg[2]);

        if (input_regs.reg[0] == 3 && input_regs.reg[1] == 0) {
            // Map FIRM launch parameters to the virtual address given in r2
            // TODO: Actually implement this. PM requests this early in the
            //       boot process, but doesn't actually read from the page
            //       until far later (it's exposed through the IPC command
            //       GetFIRMLaunchParameters, which is used by NS on boot).
            source.GetLogger()->info("Mapping FIRM launch parameter page to virtual address {:#x}", input_regs.reg[2]);
            if (!source.GetParentProcess().MapVirtualMemory(firm_launch_parameters, 0x1000, input_regs.reg[2], MemoryPermissions::Read))
                SVCBreak(source, BreakReason::Panic);
        } else {
            // TODO: Re-enable. Currently "needed" to allow ns to launch the devunit title
//             source.GetLogger()->error("Unknown operation");
//             SVCBreak(source, BreakReason::Panic);
        }

        RescheduleImmediately(source.GetPointer());
        return Encode(RESULT_OK);
    }

    default:
        throw std::runtime_error(fmt::format("Unknown SVC index {:#x} (arguments: r0={:#x}, r1={:#x}, r2={:#x}, r3={:#x}, r4={:#x})",
                                             svc_id, input_regs.reg[0], input_regs.reg[1], input_regs.reg[2], input_regs.reg[3], input_regs.reg[4]));
    }

} catch(const std::runtime_error& err) {
    HandleOSThreadException(err, source);
}

void OS::NotifyInterrupt(uint32_t index) {
    std::cout << "Firing interrupt 0x" << std::hex << index << "" << std::endl;
    if (bound_interrupts[index].empty()) {
        std::cout << "Firing interrupt 0x" << std::hex << index << ", but nobody is listening" << std::endl;
        return;
    }

    for (auto observer : bound_interrupts[index]) {
        auto locked_observer = observer.lock();
        locked_observer->SignalEvent();
        OnResourceReady(*locked_observer);
    }
}

ProcessId OS::MakeNewProcessId() {
    // On the actual 3DS, the FIRM modules are the first processes to be
    // launched during boot, and as such they are assigned process IDs zero
    // through "num_firm_modules-1". In our boot process, FakeDebugProcess and
    // BootThread are the first processes to be launched, but for ABI
    // compatibility reasons we need to ensure the FIRM modules get their
    // appropriate process IDs. This is currently achieved by assigning the
    // PIDs "num_firm_modules" and the one after to FakeDebugProcess and
    // BootThread, respectively, then jumping back to PID 0 for the FIRM modules, and
    // finally skipping the initial two PIDs once all FIRM processes have been
    // loaded.
    if (next_pid == num_firm_modules + 1) {
        // Jump back to FIRM module PIDs for the next process
        next_pid = 0;
        return num_firm_modules + 1;
    } else if (next_pid + 1 == num_firm_modules) {
        // Skip PIDs for FakeDebugProcess and BootThread for the next process
        next_pid = num_firm_modules + 2;
        return num_firm_modules - 1;
    } else {
        // Default case: Just move to the next PID
        return next_pid++;
    }
}

DebugHandle::DebugInfo OS::MakeHandleDebugInfo(DebugHandle::Source source) const {
    return { system_tick.count(), source, 0 };
}

DebugHandle::DebugInfo OS::MakeHandleDebugInfoFromIPC(uint32_t ipc_command) const {
    return { system_tick.count(), DebugHandle::FromIPC, ipc_command };
}

void OS::RegisterProcess(std::shared_ptr<Process> process) {
    process_handles[process->GetId()] = process;
}

std::vector<std::shared_ptr<Thread>> OS::GetThreadList() const {
    // NOTE: It's important that the debug_process is at the front,
    //       since it will be stopped by gdb upon initial connection!
    std::vector<std::shared_ptr<Thread>> ret = { debug_process->thread };

    auto lock_weak_ptr = [](auto& weak_ptr) { return weak_ptr.lock(); };
    auto not_nullptr = [](const auto& ptr) { return ptr != nullptr; };
    auto is_emuthread = [](const auto& ptr) { return (nullptr != std::dynamic_pointer_cast<EmuThread>(ptr)); };
    ranges::copy(threads | ranges::view::transform(lock_weak_ptr) | ranges::view::filter(not_nullptr) | ranges::view::filter(is_emuthread), ranges::back_inserter(ret));
    return ret;
}

std::shared_ptr<Process> OS::GetProcessFromId(ProcessId proc_id) /* const */{
    if (proc_id == debug_process->GetId())
        return debug_process;

    auto process_it = process_handles.find(proc_id);
    if (process_it == process_handles.end())
        return nullptr;
    return process_it->second;
}

// TODO: Rename to Reschedule
void OS::SwitchToSchedulerFromThread(Thread& thread) {
    // Interrupt the profile for this process, but keep the OS profile running.
    thread.GetParentProcess().activity.Interrupt();

    thread.control->YieldToScheduler();

    // Resume profile in this thread
    thread.activity.Resume();
}

uint64_t OS::GetTimeInNanoSeconds() const {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(system_tick).count();
}

static ticks dsp_tick;
OS* g_os = nullptr;

static ticks GetDspTick(OS& os) {
    if (os.settings.get<Settings::EnableAudioEmulation>()) {
        // DSP clock rate is half the CPU clock rate
        return os.system_tick / 2;
    } else {
        // Disabling DSP emulation entirely would break games.
        // However we can safely underclock the DSP to save work.
        return os.system_tick / 64;
    }
}

void SetupOSDSPCallbacks(OS& os) {
    static auto dsp_interrupt_handlera = [&os]() {
        fprintf(stderr, "DSP INTERRUPT0\n");
        os.NotifyInterrupt(0x4a);
    };
    static auto dsp_interrupt_handlerb = [&os]() {
        fprintf(stderr, "DSP INTERRUPT1\n");
        os.NotifyInterrupt(0x4a);
    };
    static auto dsp_interrupt_handlerc  = [&os]() {
        fprintf(stderr, "DSP INTERRUPT2\n");
        os.NotifyInterrupt(0x4a);
    };
    static auto dsp_interrupt_handler2 = [&os]() {
        fprintf(stderr, "DSP SEMA INTERRUPT\n");
        os.NotifyInterrupt(0x4a);
    };

    // TODO: Enable these handlers with HLE DSP, too
    if (!os.hle_titles.count("dsp")) {
        g_teakra->SetRecvDataHandler(0, dsp_interrupt_handlera);
        g_teakra->SetRecvDataHandler(1, dsp_interrupt_handlerb);
        g_teakra->SetRecvDataHandler(2, dsp_interrupt_handlerc);
        g_teakra->SetSemaphoreHandler(dsp_interrupt_handler2);
    }
    dsp_tick = GetDspTick(os);
}

void OS::EnterExecutionLoop() {
    g_os = this;
//    auto dsp_interrupt_handlera = [this]() {
//        fprintf(stderr, "DSP INTERRUPT0\n");
//        NotifyInterrupt(0x4a);
//    };
//    auto dsp_interrupt_handlerb = [this]() {
//        fprintf(stderr, "DSP INTERRUPT1\n");
//        NotifyInterrupt(0x4a);
//    };
//    auto dsp_interrupt_handlerc  = [this]() {
//        fprintf(stderr, "DSP INTERRUPT2\n");
//        NotifyInterrupt(0x4a);
//    };
//    auto dsp_interrupt_handler2 = [this]() {
//        fprintf(stderr, "DSP SEMA INTERRUPT\n");
//        NotifyInterrupt(0x4a);
//    };

    /*auto */dsp_tick = GetDspTick(*this);

    while (!stop_requested) {
        // TODO: Gather these from the "caller" (i.e. the coroutine)
        auto max_cycles = 100;

        if (g_dsp_running) {
//            if (g_dsp_just_reset) {
//                g_dsp_just_reset = false;
//                g_teakra->SetRecvDataHandler(0, dsp_interrupt_handlera);
//                g_teakra->SetRecvDataHandler(1, dsp_interrupt_handlerb);
//                g_teakra->SetRecvDataHandler(2, dsp_interrupt_handlerc);
//                g_teakra->SetSemaphoreHandler(dsp_interrupt_handler2);
//                dsp_tick = GetDspTick(*this);
//            }

            // Run DSP time slices of at least 100 ticks.
            // This number was carefully chosen, since too large minimum bounds
            // trigger hangs.
            auto dsp_tick_diff = GetDspTick(*this) - dsp_tick;
            if (dsp_tick_diff.count() > 100) {
                // For profiling, present DSP emulation as one logical fiber
                TracyFiberEnter("DSP");
                TracyCZoneN(DSPSliceZone, "DSPSlice", true);
//                fprintf(stderr, "Running %d teakra cycles\n", (int)dsp_tick_diff.count());
                g_teakra->Run(dsp_tick_diff.count());
                dsp_tick = GetDspTick(*this);
                TracyCZoneEnd(DSPSliceZone);
                TracyFiberLeave;
            }
        }

        // NOTE: Tracy does not support interrupting a zone, which we would
        //       like to do in this loop when passing control flow to the
        //       CPU engine coroutine. As a workaround we use two Tracy zones:
        //       One for execution up to the CPU coroutine, and one for
        //       execution after.
        TracyCZoneN(SchedulerZonePre, "OS", true);

        // TODO: If all threads are waiting, the GDB stub still should be able
        //       to interrupt execution! (currently, this is not possible
        //       because an EmuThread needs to invoke the interpreter so that
        //       the "request_pause" flag will be checked)

//         if (priority_queue.empty() && ready_queue.empty()) {
        if (ready_queue.empty()) {
            // TODO: Find next event instead (i.e. interrupt or timer)
//            const auto duration_per_tick = std::chrono::nanoseconds(10000000);
            const auto duration_per_tick = std::chrono::nanoseconds(100000);
            ElapseTime(duration_per_tick);
            TracyCZoneEnd(SchedulerZonePre)
            continue;
        }

        // "Schedule" and dispatch next thread
//         auto next_thread = priority_queue.empty() ? ready_queue.front().lock() : priority_queue.front().lock();
        auto next_thread = ready_queue.front().lock();

        if (!next_thread->wait_list.empty()) {
            TracyCZoneEnd(SchedulerZonePre)
            throw std::runtime_error("Threads in the ready queue shouldn't be waiting on anything");
        }

        if (!next_thread || next_thread->status != Thread::Status::Ready) {
            // thread was closed or was unscheduled => move to next thread
            // TODO: We should probably do this when closing/unscheduling the thread instead...
            ready_queue.pop_front();

            TracyCZoneEnd(SchedulerZonePre)
            continue;
        }

        // Resume thread until it invokes a system call

        active_thread = next_thread.get();
        decltype(ARM::State::cycle_count) ticks_elapsed = 0;
        {
            auto emuthread = std::dynamic_pointer_cast<EmuThread>(next_thread);

            if (emuthread) {
                auto cpu = emuthread->context->ToGenericContext();
                next_thread->GetLogger()->info("{}Dispatcher entering (PC at {:#x}), r0={:x}, r1={:x}, r2={:x}, r3={:x}, r4={:x}, r5={:x}, r6={:x}, r7={:x}, r8={:x}",
                                               ThreadPrinter{*next_thread}, cpu.reg[15], cpu.reg[0], cpu.reg[1],
                                               cpu.reg[2], cpu.reg[3], cpu.reg[4], cpu.reg[5], cpu.reg[6],
                                               cpu.reg[7], cpu.reg[8]);


                ticks_elapsed = cpu.cycle_count;
            } else {
                next_thread->GetLogger()->info("{}Dispatcher entering", ThreadPrinter{*next_thread});
            }
        }
        next_thread->GetProcessHandleTable().SetCurrentThread(next_thread);
        next_thread->RestoreContext();

        TracyCZoneEnd(SchedulerZonePre);
        {
#ifdef TRACY_ENABLE
            // TODO: Also add a name for FakeProcesses
            if (auto* emuproc = dynamic_cast<EmuProcess*>(&next_thread->GetParentProcess())) {
                static std::unordered_map<ProcessId, std::unordered_map<ThreadId, std::string>> thread_names;
                auto [thread_name_it, new_thread] = thread_names[emuproc->GetId()].emplace(next_thread->GetId(), "");
                if (new_thread) {
                    thread_name_it->second = fmt::format("{} thread {}", emuproc->codeset->app_name, next_thread->GetId());
                }
                TracyFiberEnter( thread_name_it->second.c_str() );
                bool is_gsp = emuproc->codeset->app_name == std::string_view { "gsp" };
                if (is_gsp) {
                    // GSP does little actual CPU emulation work; most of it is spent emulating the GPU
                    ZoneNamedN(Activity, "GPU emulation", true);
                    next_thread->control->ResumeFromScheduler();
                } else {
                    ZoneNamedN(Activity, "CPU emulation", true);
                    next_thread->control->ResumeFromScheduler();
                }
                TracyFiberLeave;
#else
            if (false) {
#endif
            } else {
                next_thread->control->ResumeFromScheduler();
            }
        }
        ZoneNamedN(SchedulerZonePost, "OS", true);

        next_thread->SaveContext();
        {
            auto emuthread = std::dynamic_pointer_cast<EmuThread>(next_thread);
            next_thread->GetLogger()->info("{}Dispatcher leaving {}", ThreadPrinter{*active_thread},
                                             emuthread ? fmt::format(" (PC at {:#x}, LR at {:#x})", emuthread->context->ToGenericContext().reg[15], emuthread->context->ToGenericContext().reg[14]) : "");

            if (emuthread) {
                auto cpu = emuthread->context->ToGenericContext();
                next_thread->GetLogger()->info("{}Dispatcher LEAVING (PC at {:#x}), r0={:x}, r1={:x}, r2={:x}, r3={:x}, r4={:x}, r5={:x}, r6={:x}, r7={:x}, r8={:x}",
                                               ThreadPrinter{*next_thread}, cpu.reg[15], cpu.reg[0], cpu.reg[1],
                                               cpu.reg[2], cpu.reg[3], cpu.reg[4], cpu.reg[5], cpu.reg[6],
                                               cpu.reg[7], cpu.reg[8]);

                ticks_elapsed = cpu.cycle_count - ticks_elapsed;
            }
        }
        active_thread = debug_process->thread.get();

        ElapseTime(std::chrono::duration_cast<std::chrono::nanoseconds>(ticks{ticks_elapsed}));

        activity.GetSubActivity("SVC").Resume();

        {
            ZoneNamedN(SchedulerSVC, "SVC", true);

            // Process system call if necessary. Note that the callback may replace
            // callback_for_svc with a followup callback, so it's important that we
            // reset callback_for_svc before invoking the callback.
            auto callback = std::exchange(next_thread->callback_for_svc, nullptr);
            if (callback)
                callback(/*std::move*/(next_thread));

// PRE VVVVVV WORKAROUND
            if (next_thread->status == Thread::Status::Stopped/* && thread.use_count() == 2*/) {
                TriggerThreadDestruction(std::move(next_thread));
// POST VVVVVV WORKAROUND (for Narmive only)
//            if (next_thread->status == Thread::Status::Stopped && next_thread.use_count() <= 2) {
//                TriggerThreadDestruction(std::move(next_thread));
            }
        }

        activity.GetSubActivity("SVC").Interrupt();
    }
}

static void DisplayFramesToHost(Memory::PhysicalMemory& mem, spdlog::logger& logger, EmuDisplay::EmuDisplay& display, Pica::Renderer& renderer) {
    // NOTE: On hardware, the vblank interrupt is fired shortly after all pixel data has been sent to the display.
    //       The interrupt indicates to software that configuration for the next frame must be set up quickly.
    //       The start of processing the next frame is not signaled to software.
    //
    //       There are two points in emulated time we can consider sending the frames on the host display:
    //       - When hardware would have finished processing frame data (i.e. when signaling the next vblank; easy but adds latency)
    //       - When hardware would have started processing frame data the frame data (i.e. a short emulated time span after the previous vblank determined by the other framebuffer registers)

    // TODO: Consider skipping frame submission if configuration hasn't changed

static uint64_t timestamp = 0; // TODO
    auto gpu_base = 0x10400000;

    if (Memory::ReadLegacy<uint32_t>(mem, gpu_base + 0x474) & 1) {
        auto fb_format = Memory::ReadLegacy<uint32_t>(mem, gpu_base + 0x470);
        auto format = FromRawValue<EmuDisplay::Format>(fb_format & 0x7);
        bool fb_select = (Memory::ReadLegacy<uint32_t>(mem, gpu_base + 0x478) & 1);
        auto fb_stride = Memory::ReadLegacy<uint32_t>(mem, gpu_base + 0x490);

        {
            // TODO: Is the fb_select_top selection logic correct, or should it be inverted?
            auto data_addr = Memory::ReadLegacy<uint32_t>(mem, gpu_base + 0x468 + fb_select * 4);
            logger.info("Submitting new top screen frame from data at {:#x}", data_addr);
            auto& frame = display.PrepareImage(EmuDisplay::DataStreamId::TopScreenLeftEye, ++timestamp);
            renderer.ProduceFrame(display, frame, mem, EmuDisplay::DataStreamId::TopScreenLeftEye, data_addr, fb_stride, format);
            display.PushImage(EmuDisplay::DataStreamId::TopScreenLeftEye, frame, timestamp);
        }

    // If 3D is enabled, push a frame for the right-eye image, too
        if (fb_format & (1 << 5)) {
            auto data_addr = Memory::ReadLegacy<uint32_t>(mem, gpu_base + 0x494 + fb_select * 4);
            auto& frame = display.PrepareImage(EmuDisplay::DataStreamId::TopScreenRightEye, ++timestamp);
            renderer.ProduceFrame(display, frame, mem, EmuDisplay::DataStreamId::TopScreenRightEye, data_addr, fb_stride, format);
            display.PushImage(EmuDisplay::DataStreamId::TopScreenRightEye, frame, timestamp);
        }
    }

    if (Memory::ReadLegacy<uint32_t>(mem, gpu_base + 0x574) & 1) {
        auto fb_format = Memory::ReadLegacy<uint32_t>(mem, gpu_base + 0x570);
        auto format = FromRawValue<EmuDisplay::Format>(fb_format & 0x7);
        bool fb_select = (Memory::ReadLegacy<uint32_t>(mem, gpu_base + 0x578) & 1);
        auto fb_stride = Memory::ReadLegacy<uint32_t>(mem, gpu_base + 0x590);

        {
            // TODO: Is the fb_select_top selection logic correct, or should it be inverted?
            auto data_addr = Memory::ReadLegacy<uint32_t>(mem, gpu_base + 0x568 + fb_select * 4);
            logger.info("Submitting new bottom screen frame from data at {:#x}", data_addr);
            auto& frame = display.PrepareImage(EmuDisplay::DataStreamId::BottomScreen, ++timestamp);
            renderer.ProduceFrame(display, frame, mem, EmuDisplay::DataStreamId::BottomScreen, data_addr, fb_stride, format);
            display.PushImage(EmuDisplay::DataStreamId::BottomScreen, frame, timestamp);
        }
    }
}

void OS::ElapseTime(std::chrono::nanoseconds time) {
    const auto system_tick_old = system_tick;
    system_tick += std::chrono::duration_cast<ticks>(time);

    {
        auto ms_now = std::chrono::duration_cast<std::chrono::milliseconds>(system_tick);
        auto ms_old = std::chrono::duration_cast<std::chrono::milliseconds>(system_tick_old);
        if (ms_now / 10 != ms_old / 10) {
            logger->info("{} emulated milliseconds have passed!", ms_now.count());
            fmt::print("{} emulated milliseconds have passed!\n", ms_now.count());
        }
    }

    auto nanoseconds = GetTimeInNanoSeconds();
    for (auto timer_weak : active_timers) {
        auto timer = timer_weak.lock();
        if (!timer) {
            // TODO: Remove timer from active_timers!
            continue;
        }

        if (timer->Expired(nanoseconds))
            OnResourceReady(*timer);
    }

    if (std::chrono::duration_cast<vblanks_per_sec>(system_tick).count() !=
        std::chrono::duration_cast<vblanks_per_sec>(system_tick_old).count()) {
        std::cerr << "OS scheduler signalling interrupts: " << std::chrono::duration_cast<vblanks_per_sec>(system_tick).count() << " vs " <<
                  std::chrono::duration_cast<vblanks_per_sec>(system_tick_old).count() << " vblanks" << std::endl;
        std::cerr << "OS scheduler signalling interrupts" << std::endl;
        // 0x28 and 0x2a together trigger PSC0
        // 0x29 and 0x2a together trigger PSC1
        // 0x2b and 0x2a together trigger VBlank1
        // 0x2c and 0x2a together trigger PPF
        //NotifyInterrupt(0x28); // does not wake VBlank1, nor PPF, nor PSC0
        //NotifyInterrupt(0x29); // does not wake VBlank1, nor PPF, nor PSC0
        static bool signal_2ba = true; // TODO: Remove this. Trying out stuff since maybe vblank0 and vblank1 are signaled too closely together, although really that shouldnt matter.

        // TODO: Display previous frame now
        DisplayFramesToHost(setup.mem, *logger, display, *pica_context.renderer);

//         if (signal_2ba)
            NotifyInterrupt(0x2a); // does wake VBlank0, but not VBlank1, nor PPF, nor PSC0
//         else
            NotifyInterrupt(0x2b); // does NOT wake VBlank0, nor VBlank1, nor PPF
        signal_2ba = !signal_2ba;
        //NotifyInterrupt(0x2c); // does not wake VBlank1, nor PPF
        //NotifyInterrupt(0x2d);

        // TODO: Schedule event in the close future (<0.2 * vblank interval) to display the next frame

        NotifyInterrupt(0x64); // HID. config never returns from IPC request 0x00010000 to cdc:HID without this. TODO remove?

        }

    // HID interrupts
/*        if ((iteration % 1000) == 0) {
        std::cerr << "OS scheduler signalling HID interrupts" << std::endl;
        NotifyInterrupt(0x6a);
    }*/

    // TODO NOW: This should also be checked for threads waiting for arbitration or events with timeout!!!
    for (auto thread_it = waiting_queue.begin(); thread_it != waiting_queue.end();) {
        auto thread = thread_it->lock();
        if (!thread) {
            thread_it = waiting_queue.erase(thread_it);
        } else if (thread->timeout_at <= GetTimeInNanoSeconds()) {
            thread->GetLogger()->info("{}Waking up thread after timeout", ThreadPrinter{*thread});

            // status==Sleeping corresponds to WaitSynchronizationN timing out... TODO: This is extremely ugly, clean this up instead :/
            // NOTE: The returned value indeed does not have the topmost bit set (as any regular error code would)
            if (thread->status == Thread::Status::Sleeping) {
                thread->promised_result = 0x09401BFE;

                // Clear wait_list
                for (auto sync_object : thread->wait_list)
                    sync_object->Unregister(thread);
                thread->wait_list.clear();
            }

            thread->status = Thread::Status::Ready;
            ready_queue.push_back(thread);
//             priority_queue.push_back(thread);
            thread_it = waiting_queue.erase(thread_it);
        } else {
            ++thread_it;
        }
    }
}

void OS::TriggerThreadDestruction(std::shared_ptr<Thread> thread) {
    // Clean up thread

    // Get a shared_ptr in case we are about to destroy the only
    // process thread (and as such possibly the only process reference)
    auto parent_process = std::dynamic_pointer_cast<Process>(thread->GetParentProcess().shared_from_this());

    auto& process_threads = parent_process->threads;

try{
    // Delete the stopped thread from the process list
    // TODO: Where should we do this? Here? SVCExitThread? ~Thread?
    auto it = std::find(process_threads.begin(), process_threads.end(), thread);
    if (it == process_threads.end()) { // TODO: Use contract instead
        // TODO: throw exception instead
        // TODO: Needed for debug_thread
        // SVCBreak(*thread, OS::BreakReason::Panic);
        throw std::runtime_error("TODO: Contract it == process_threads.end()");
    }
    process_threads.erase(it);
}catch(...) {
}

try{
    // Delete the stopped thread from the scheduler queue
    auto it2 = std::find_if(threads.begin(), threads.end(), [&thread](auto& cur) { return cur.lock() == thread; });
    if (it2 == threads.end()) {
        throw std::runtime_error("TODO: Contract it2 == threads.end()");
    }
    threads.erase(it2);
}catch(...) {
}

    // Finally, release what's hopefully the last reference to the thread, and make sure that indeed no dangling references are present - otherwise, we *will* be leaking memory
    // TODO: Actually, other processes might still be holding handle table entries for this.
/*        if (thread.use_count() != 1)
        SVCBreak(*thread, BreakReason::Panic);*/
    thread->GetLogger()->info("{}About to be destroyed ({} remaining)", ThreadPrinter{*thread}, process_threads.size());

    // If this was the last thread, exit the whole process
    if (process_threads.empty()) {
        thread->GetLogger()->info("{}Last thread destroyed, winding down process", ThreadPrinter{*thread});

        // If this is the last process thread, delete the whole process

        parent_process->status = Process::Status::Stopping;

        // Remove process from global handle table
        // TODO: This affects behavior of SVCGetProcessFromId.
        //       We need to test whether references to a process may
        //       still be retrieved after the process has been closed
        //       (while other processes still may hold a reference,
        //       preventing process destruction)
        process_handles.erase(parent_process->GetId());

        // Close all pending handles
        while (!parent_process->handle_table.table.empty()) {
            CloseHandle(*thread, parent_process->handle_table.table.begin()->first);
        }

        for (auto& memory_region : memory_regions) {
            // TODO: Add an interface to MemoryManager to do this more cleanly
            for (auto taken_it = memory_region.taken.begin(); taken_it != memory_region.taken.end();) {
                if (taken_it->second.owner.lock() == parent_process) {
                    memory_region.DeallocateBlock(parent_process, taken_it->first, taken_it->second.size_bytes);
                    taken_it = memory_region.taken.begin();
                } else {
                    ++taken_it;
                }
            }
        }

        // If this was the last non-stopped thread, terminate the process itself
        const bool terminate_process = ranges::all_of(  parent_process->threads,
                                                        [](auto& child_thread) { return child_thread->status == Thread::Status::Stopped; });
        auto keep_process_alive = parent_process->shared_from_this();
        if (terminate_process) {
            for (auto& other_process : process_handles) {
                for (auto& handle : other_process.second->handle_table.table) {
                    // The pm module holds references to every other process.
                    // If any other modules still reference the process, then
                    // that indicates a handle leak.
                    if (handle.second == parent_process && handle.first != Handle { 0xFFFF8001 } && other_process.second->GetName() != "pm") {
                        fmt::print( "Process {} still holds a reference to {} through its handle {}\n",
                                    other_process.second->GetName(), parent_process->GetName(), HandlePrinter { *thread, handle.first });
                    }
                }
            }
        }

        // TODO: Print dangling references and make sure they add up to the process use count

        // Signal termination
        OnResourceReady(*parent_process);

        thread = nullptr; // Destroy thread first to drop any dangling references to the process

        // Finally, release what's hopefully the last reference to the process, and make sure that indeed no dangling references are present - otherwise, we *will* be leaking memory
        // TODO: Actually, other processes might still be holding handle table entries for this (SVCOpenProcess!).
        // TODO: LLE pm may call SVCTerminateProcess on swkbd during Initial Setup; this seems to cause it to hold a dangling reference?
//        if (parent_process.use_count() != 1)
//            throw std::runtime_error("Dangling references to process: " + std::to_string(parent_process.use_count()));
        parent_process->GetLogger()->info("{}About to be destroyed", ProcessPrinter{*parent_process});
        parent_process = nullptr;
    }
    thread = nullptr;
}

void OS::Reschedule(std::shared_ptr<Thread> thread) {
    // Applications hopefully don't rely on accurate system tick emulation (how would they know how much time the OS spends in system processes, after all?), hence we just increment the system tick counter by a fixed constant on each reschedule.
    // NOTE: In particular, this will increment the system tick when svcGetSystemTick is called!
    const auto duration_per_tick = std::chrono::nanoseconds(500);
    ElapseTime(duration_per_tick);

    // Use-count 2: Only referenced by the function parameter and the parent thread
    // TODO: Verify this actually gets hit!
    if (thread->status == Thread::Status::Stopped/* && thread.use_count() == 2*/) {
//        TriggerThreadDestruction(std::move(thread));
    } else if (thread->status == Thread::Status::Ready) {
        // Reinsert thread to the end of the (non-priority) queue
//         ready_queue.push_back(thread);
    }

    // Move thread to the end of the queue
    std::rotate(ready_queue.begin(), std::next(ready_queue.begin()), ready_queue.end());
}

void OS::RescheduleImmediately(std::shared_ptr<Thread> thread) {
    // Do nothing; thread will just keep running by default
//     priority_queue.push_front(thread);
}

#if 0
void OS::StartScheduler(boost::coroutines::symmetric_coroutine<void>::yield_type& yield) {
    while (!threads.empty()) {
        // "Schedule" and dispatch next thread
        auto next_thread = threads.front().lock();
        if (!next_thread) {
            // thread was closed => remove from list and continue
            threads.pop_front();
            continue;
        }

        // Applications hopefully don't rely on accurate system tick emulation (how would they know how much time the OS spends in system processes, after all?), hence we just increment the system tick counter by a fixed constant on each reschedule.
        // NOTE: In particular, this will increment the system tick when svcGetSystemTick is called!
        const auto duration_per_tick = std::chrono::nanoseconds(1000);
        const auto system_tick_old = system_tick;
        system_tick += std::chrono::duration_cast<ticks>(duration_per_tick);

        {
            auto ms_now = std::chrono::duration_cast<std::chrono::milliseconds>(system_tick);
            auto ms_old = std::chrono::duration_cast<std::chrono::milliseconds>(system_tick_old);
            if (ms_now != ms_old)
                logger->info("{} emulated milliseconds have passed!", ms_now.count());
        }

        auto nanoseconds = GetTimeInNanoSeconds();
        for (auto timer_weak : active_timers) {
            auto timer = timer_weak.lock();
            if (!timer) {
                // TODO: Remove timer from active_timers!
                continue;
            }

            if (timer->Expired(nanoseconds))
                OnResourceReady(*timer);
        }



        if (std::chrono::duration_cast<vblanks_per_sec>(system_tick).count() !=
            std::chrono::duration_cast<vblanks_per_sec>(system_tick_old).count()) {
            std::cerr << "OS scheduler signalling interrupts" << std::endl;
            // 0x28 and 0x2a together trigger PSC0
            // 0x29 and 0x2a together trigger PSC1
            // 0x2b and 0x2a together trigger VBlank1
            // 0x2c and 0x2a together trigger PPF
            //NotifyInterrupt(0x28); // does not wake VBlank1, nor PPF, nor PSC0
            //NotifyInterrupt(0x29); // does not wake VBlank1, nor PPF, nor PSC0
            NotifyInterrupt(0x2a); // does wake VBlank0, but not VBlank1, nor PPF, nor PSC0
            NotifyInterrupt(0x2b); // does NOT wake VBlank0, nor VBlank1, nor PPF
            //NotifyInterrupt(0x2c); // does not wake VBlank1, nor PPF
            //NotifyInterrupt(0x2d);
        }

        // HID interrupts
/*        if ((iteration % 1000) == 0) {
            std::cerr << "OS scheduler signalling HID interrupts" << std::endl;
            NotifyInterrupt(0x6a);
        }*/

        // TODO: If all threads are waiting, the GDB stub still should be able
        //       to interrupt execution! (currently, this is not possible
        //       because an EmuThread needs to invoke the interpreter so that
        //       the "request_pause" flag will be checked)

        // TODO NOW: This should also be checked for threads waiting for arbitration or events with timeout!!!
        if (next_thread->status == Thread::Status::WaitingForTimeout &&
            next_thread->timeout_at <= GetTimeInNanoSeconds()) {
            next_thread->status = Thread::Status::Ready;
            waiting_queue.erase(std::remove_if(waiting_queue.begin(), waiting_queue.end(), [&next_thread](auto& elem) { return elem.lock() == next_thread; }));
        }

        if (next_thread->status == Thread::Status::Ready) {
            // Resume thread
            active_thread = next_thread.get();
            {
                auto emuthread = std::dynamic_pointer_cast<EmuThread>(next_thread);
                next_thread->GetLogger()->info("{}Scheduling in{}", ThreadPrinter{*next_thread},
                                                emuthread ? fmt::format(" (PC at {:#x})", emuthread->context.cpu.reg[15]) : "");
            }
            next_thread->GetProcessHandleTable().SetCurrentThread(next_thread);
            next_thread->RestoreContext();
            next_thread->coroutine_2();
            next_thread->SaveContext();
            next_thread->GetProcessHandleTable().SetCurrentThread(nullptr); // release internal reference
            auto emuthread = std::dynamic_pointer_cast<EmuThread>(next_thread);
            next_thread->GetLogger()->info("{}Scheduling out{}", ThreadPrinter{*active_thread},
                                             emuthread ? fmt::format(" (PC at {:#x})", emuthread->context.cpu.reg[15]) : "");
            active_thread = debug_process->thread.get();
        } else if (next_thread->status == Thread::Status::Stopped) {
            // Clean up thread

            // Get a shared_ptr in case we are about to destroy the only
            // process thread (and as such possibly the only process reference)
            auto parent_process = std::dynamic_pointer_cast<Process>(next_thread->GetParentProcess().shared_from_this());

            auto& process_threads = parent_process->threads;

            // Delete the stopped thread from the process list
            // TODO: Where should we do this? Here? SVCExitThread? ~Thread?
            auto it = std::find(process_threads.begin(), process_threads.end(), next_thread);
            if (it == process_threads.end())
                SVCBreak(*next_thread, BreakReason::Panic);
            process_threads.erase(it);

            // Delete the stopped thread from the scheduler queue
            auto it2 = std::find_if(threads.begin(), threads.end(), [&next_thread](auto& cur) { return cur.lock() == next_thread; });
            if (it2 == threads.end())
                SVCBreak(*next_thread, BreakReason::Panic);
            threads.erase(it2);

            // Finally, release what's hopefully the last reference to the thread, and make sure that indeed no dangling references are present - otherwise, we *will* be leaking memory
            // TODO: Actually, other processes might still be holding handle table entries for this.
            if (next_thread.use_count() != 1)
                SVCBreak(*next_thread, BreakReason::Panic);
            next_thread->GetLogger()->info("{}About to be destroyed", ThreadPrinter{*next_thread});
            next_thread = nullptr;

            // If this was the last thread, exit the whole process
            if (process_threads.empty()) {
                // If this is the last process thread, delete the whole process

                // Remove process from global handle table
                // TODO: This affects behavior of SVCGetProcessFromId.
                //       We need to test whether references to a process may
                //       still be retrieved after the process has been closed
                //       (while other processes still may hold a reference,
                //       preventing process destruction)
                process_handles.erase(parent_process->GetId());

                // Explicitly remove the current process from its own handle table to make sure the reference is dropped.
                // TODO: Actually, we should clear the whole handle table in order to resolve circular process dependencies!
                parent_process->handle_table.CloseHandle(Handle{0xFFFF8001});

                // Finally, release what's hopefully the last reference to the process, and make sure that indeed no dangling references are present - otherwise, we *will* be leaking memory
                // TODO: Actually, other processes might still be holding handle table entries for this (SVCOpenProcess!).
                if (parent_process.use_count() != 1)
                    throw std::runtime_error("Dangling references to process: " + std::to_string(parent_process.use_count()));
                parent_process->GetLogger()->info("{}About to be destroyed", ProcessPrinter{*parent_process});
                parent_process = nullptr;
            }
        }

        // Move thread to the end of the queue
        std::rotate(threads.begin(), std::next(threads.begin()), threads.end());
    }
}
#endif

template<typename FakeProcess>
const inline auto FakeProcessFactoryFor =
    +[](OS& os, const std::string& name) {
        return CreateFakeProcessViaContext<FakeProcess>(os, os.setup, os.MakeNewProcessId(), name);
    };

void OS::Run(std::shared_ptr<Interpreter::Setup> setup) {
    std::unique_ptr<Interpreter::DummyController> dummy_controller;

    // Create FakeDebugProcess for the debugger to attach to
    // TODO: Figure out whether we can omit this when debugging is disabled.
    //       Currently, the debug_process is still used in the scheduler, though.
    debug_process = std::make_shared<FakeDebugProcess>(*this, *setup, MakeNewProcessId());
    active_thread = debug_process->thread.get();

    if (settings.get<Settings::ConnectToDebugger>()) {
        auto gdbstub1 = std::make_unique<Interpreter::GDBStub>(*this, log_manager, 12345);
        gdbstub = gdbstub1.get();

        // Loop indefinitely in the GDB stub thread. TODO: This should be quittable!
        gdbthread = std::make_unique<std::thread>([stub=std::move(gdbstub1)](){ while (true) stub->ProcessQueue(); });
//        debug_process->thread->WaitForContinue(*gdbstub);
    } else {
        // Create a dummy interface instead of the debugger
        dummy_controller = std::make_unique<Interpreter::DummyController>();
        gdbstub = dummy_controller.get();
    }

    // Allocate and initialize kernel configuration memory (mapped to 0x1FF80000 in all processes)
    // TODO: Where is this allocated on the actual system?
    configuration_memory = *memory_base().AllocateBlock(internal_memory_owner, 0x1000);

    // NSTID: Title ID to launch by PM after the FIRM modules are loaded (i.e. typically the title ID of NS)
    // NOTE/TODO: The high word of the title ID must be 0x00040130, and the
    //            uppermost byte of the lower word must be 2
    Memory::WriteLegacy<uint32_t>(setup->mem, configuration_memory + 0x8, 0x00008002);
    Memory::WriteLegacy<uint32_t>(setup->mem, configuration_memory + 0xc, 0x00040130);

    // SYSCOREVER & FIRM_SYSCOREVER
    Memory::WriteLegacy<uint32_t>(setup->mem, configuration_memory + 0x10, 2);
    Memory::WriteLegacy<uint32_t>(setup->mem, configuration_memory + 0x64, 2);

    // Set kernel version to 11.8.0.. TODO: Select from CVer title instead!
     Memory::WriteLegacy<uint8_t>(setup->mem, configuration_memory + 2, 0x37);
     Memory::WriteLegacy<uint8_t>(setup->mem, configuration_memory + 3, 0x2);
     Memory::WriteLegacy<uint8_t>(setup->mem, configuration_memory + 0x62, 0x37);
     Memory::WriteLegacy<uint8_t>(setup->mem, configuration_memory + 0x63, 0x2);

    // CTRSDKVERSION: TODO: Reconsider whether we need to intialize this
    Memory::WriteLegacy<uint32_t>(setup->mem, configuration_memory + 0x68, 0x0000F297);

        // UNITINFO: bit0 is 1 for retail units (OR IS IT??)
    // TODO 0x13 WAS THE WRONG OFFSET :<
    // NOTE: If you wanted to emulate a dev unit, the config savegame needs to contain the appropriate home menu tid!
//     Memory::Write<uint32_t>(setup->mem, configuration_memory + 0x13, 0x01); // TODO WTF WHY A UINT32 WRITE
//     const bool emulate_dev_unit = true; // TODO: Set to false
    const bool emulate_dev_unit = false; // TODO: Set to false
    if (emulate_dev_unit) {
        Memory::WriteLegacy<uint8_t>(setup->mem, configuration_memory + 0x14, 0x00); // ENVINFO
        Memory::WriteLegacy<uint8_t>(setup->mem, configuration_memory + 0x15, 0x01); // UNITINFO
    } else {
        Memory::WriteLegacy<uint8_t>(setup->mem, configuration_memory + 0x14, 0x01); // ENVINFO
        Memory::WriteLegacy<uint8_t>(setup->mem, configuration_memory + 0x15, 0x00); // UNITINFO
    }

    // If Home Menu is disabled, set up auto-booting in the FIRM launch parameters (see offset 0x440).
    // This is only used with LLE ns.
    const bool autoboot = !settings.get<Settings::BootToHomeMenu>();
    Memory::WriteLegacy<uint8_t>(setup->mem, configuration_memory + 0x16, autoboot);

    // APPMEMTYPE, APPMEMALLOC, SYSMEMALLOC, BASEMEMALLOC
    // NOTE: APPMEMTYPE is supposed to be initialized from firm launch parameters
    Memory::WriteLegacy<uint32_t>(setup->mem, configuration_memory + 0x30, settings.get<Settings::AppMemType>());
    Memory::WriteLegacy<uint32_t>(setup->mem, configuration_memory + 0x40, memory_app().TotalSize());
    Memory::WriteLegacy<uint32_t>(setup->mem, configuration_memory + 0x44, memory_system().TotalSize());
    Memory::WriteLegacy<uint32_t>(setup->mem, configuration_memory + 0x48, memory_base().TotalSize());

    // Allocate and initialize shared memory page (mapped to 0x1FF81000 in all processes)
    // TODO: Where is this allocated on the actual system?
    shared_memory_page = *memory_base().AllocateBlock(internal_memory_owner, 0x1000);

    // RUNNING_HW: 1 = product
    Memory::WriteLegacy<uint32_t>(setup->mem, shared_memory_page + 0x4, 1);

    // Time/Date. First 8 bytes at 0x20 are the number of milliseconds since the start of 1900, second 8 bytes is the system tick at which this data was written
    // TODO: Refresh these values every emulated hour (see Citra PR 1963)
    //       The value at offset 0 is an index selecting between different date/time structures, but since it's always 0 currently we only initialize the first one
    Memory::WriteLegacy<uint32_t>(setup->mem, shared_memory_page + 0x0, 0);
    // Use a fixed date in January 2023
    uint64_t fixed_time = (uint64_t { 2023 - 1900 } * 365 + 30 /* leap days */ + 8) * 24 * 60 * 60 * 1000 + uint64_t(15.75 * 60 * 60 * 1000);
    Memory::WriteLegacy<uint32_t>(setup->mem, shared_memory_page + 0x20, fixed_time & 0xffffffff);
    Memory::WriteLegacy<uint32_t>(setup->mem, shared_memory_page + 0x24, fixed_time >> 32);
    Memory::WriteLegacy<uint32_t>(setup->mem, shared_memory_page + 0x28, system_tick.count() & 0xffffffff); // Update tick
    Memory::WriteLegacy<uint32_t>(setup->mem, shared_memory_page + 0x2c, system_tick.count() >> 32); // Update tick

    // Wi-Fi MAC address
    Memory::WriteLegacy<uint8_t>(setup->mem, shared_memory_page + 0x60, 0xb0);
    Memory::WriteLegacy<uint8_t>(setup->mem, shared_memory_page + 0x60 + 1, 0xb1);
    Memory::WriteLegacy<uint8_t>(setup->mem, shared_memory_page + 0x60 + 2, 0xb2);
    Memory::WriteLegacy<uint8_t>(setup->mem, shared_memory_page + 0x60 + 3, 0xb3);
    Memory::WriteLegacy<uint8_t>(setup->mem, shared_memory_page + 0x60 + 4, 0xb4);
    Memory::WriteLegacy<uint8_t>(setup->mem, shared_memory_page + 0x60 + 5, 0xb5);

    // Wi-Fi signal quality (0-3)
    Memory::WriteLegacy<uint8_t>(setup->mem, shared_memory_page + 0x66, 3);
    // Network status: 7 == deactivated (prevents HOME Menu from calling unimplemented networking interfaces)
    // 2: Internet available
    // TODO: Should likely also set mac address (see https://github.com/citra-emu/citra/pull/3444)
    Memory::WriteLegacy<uint8_t>(setup->mem, shared_memory_page + 0x67, 2);

    // 3D_SLIDERSTATE, 3D_LEDSTATE - NOTE: These are probably initialized by HID anyway.
//    float stuff = /*0.0*/1.0; // From 0.0 (no 3D) to 1.0 (strongest 3D)
//    float stuff = /*0.0*/1.0; // From 0.0 (no 3D) to 1.0 (strongest 3D)
    float stuff = 0.0; // From 0.0 (no 3D) to 1.0 (strongest 3D)
    uint32_t stuff2;
    memcpy(&stuff2, &stuff, sizeof(stuff));
    Memory::WriteLegacy<uint32_t>(setup->mem, shared_memory_page + 0x80, stuff2);
    Memory::WriteLegacy<uint8_t>(setup->mem, shared_memory_page + 0x84, 1);

    // Battery state:
    // * Bit 0 indicates that a charger is connected
    // * Bit 1 indicates that the battery is charging (and not already fully charged)
    // * Bits 2-4 indicate the battery level (value 5 being fully charged)
    Memory::WriteLegacy<uint8_t>(setup->mem, shared_memory_page + 0x85, 5 << 2);


    // Home menu title ID (used by NS during boot)
    // TODO: This doesn't seem to have any actual effect :(
    // TODO: Apparently, on dev units, NS reads the title ID from the CONFIG savegame instead
    Memory::WriteLegacy<uint32_t>(setup->mem, shared_memory_page + 0xa0, 0x00009802);
    Memory::WriteLegacy<uint32_t>(setup->mem, shared_memory_page + 0xa4, 0x00040030);
    Memory::WriteLegacy<uint32_t>(setup->mem, shared_memory_page + 0xa8, 0x00009802);
    Memory::WriteLegacy<uint32_t>(setup->mem, shared_memory_page + 0xac, 0x00040030);

    // Allocate and initialize FIRM launch parameters (mappable via KernelSetState)
    // TODO: Fill this in properly. For now, we just zero-fill it
    firm_launch_parameters = *memory_base().AllocateBlock(internal_memory_owner, 0x1000);
    for (unsigned i = 0; i < 0x1000; i += 4) {
        Memory::WriteLegacy<uint32_t>(setup->mem, firm_launch_parameters + i, 0);
    }
    // If enabled, autoboot from GameCard (title id is autodetected)
    Memory::WriteLegacy<uint32_t>(setup->mem, firm_launch_parameters + 0x440, 0);
    Memory::WriteLegacy<uint32_t>(setup->mem, firm_launch_parameters + 0x444, 0);
    Memory::WriteLegacy<uint32_t>(setup->mem, firm_launch_parameters + 0x448, Meta::to_underlying(Platform::FS::MediaType::GameCard));
    Memory::WriteLegacy<uint32_t>(setup->mem, firm_launch_parameters + 0x44c, 0);
    Memory::WriteLegacy<uint32_t>(setup->mem, firm_launch_parameters + 0x460, autoboot);

    {
        if (!settings.get<Settings::UseNativeHID>()) {
            hle_titles["hid"].create = FakeProcessFactoryFor<FakeHID>;
        }


        if (!settings.get<Settings::UseNativeFS>()) {
            hle_titles["fs"].create = FakeProcessFactoryFor<FakeFS>;
        }


        hle_titles["act"].create = FakeProcessFactoryFor<FakeACT>;
        hle_titles["am"].create = FakeProcessFactoryFor<FakeAM>;
        hle_titles["cam"].create = FakeProcessFactoryFor<FakeCAM>;
        hle_titles["cdc"].create = FakeProcessFactoryFor<FakeCDC>;
        hle_titles["cecd"].create = FakeProcessFactoryFor<FakeCECD>;
        hle_titles["csnd"].create = FakeProcessFactoryFor<FakeCSND>;
        hle_titles["dlp"].create = FakeProcessFactoryFor<FakeDLP>;
        hle_titles["dsp"].create = FakeProcessFactoryFor<FakeDSP>;
        hle_titles["ErrDisp"].create = FakeProcessFactoryFor<FakeErrorDisp>;
        hle_titles["friends"].create = FakeProcessFactoryFor<FakeFRIEND>;
        hle_titles["gpio"].create = FakeProcessFactoryFor<FakeGPIO>;
        // hle_titles["http"].create = FakeProcessFactoryFor<FakeHTTP>; // TODO: HLE is a silent cause of hangs here. The event given to Initialize will be signaled to sent requests...
        hle_titles["i2c"].create = FakeProcessFactoryFor<FakeI2C>;
        hle_titles["mcu"].create = FakeProcessFactoryFor<FakeMCU>;
        hle_titles["mic"].create = FakeProcessFactoryFor<FakeMIC>;
        hle_titles["mp"].create = FakeProcessFactoryFor<DummyProcess>;
        hle_titles["ndm"].create = FakeProcessFactoryFor<FakeNDM>;
        hle_titles["news"].create = FakeProcessFactoryFor<FakeNEWS>;
        hle_titles["nfc"].create = FakeProcessFactoryFor<DummyProcess>;
        hle_titles["nwm"].create = FakeProcessFactoryFor<FakeNWM>;
        hle_titles["pdn"].create = FakeProcessFactoryFor<FakePDN>;
        hle_titles["ps"].create = FakeProcessFactoryFor<FakePS>;
        hle_titles["ptm"].create = FakeProcessFactoryFor<FakePTM>;
        hle_titles["pxi"].create = FakeProcessFactoryFor<PXI::FakePXI>;
        hle_titles["ro"].create = FakeProcessFactoryFor<DummyProcess>;
        hle_titles["socket"].create = FakeProcessFactoryFor<FakeSOC>;
        hle_titles["ssl"].create = FakeProcessFactoryFor<FakeSSL>;

        auto process = MakeFakeProcess(*setup, "FakeBootThread");
        process->AttachThread(std::make_shared<BootThread>(*process));
    }

    EnterExecutionLoop();
}

void OS::RequestStop() {
    stop_requested = true;
}

}  // namespace OS

}  // namespace HLE
