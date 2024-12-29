#pragma once

#include "interpreter.h"

#include "os_hypervisor.hpp"
#include "os_types.hpp"

#include "framework/bit_field_new.hpp"
#include "framework/console.hpp"
#include "framework/settings.hpp"

//#include <spdlog/logger.h>
#include <spdlog/spdlog.h>
#include <fmt/ostream.h>

#include <boost/coroutine2/coroutine.hpp>

#include <boost/hana/define_struct.hpp>
#include <boost/hana/ext/std/tuple.hpp>
#include <boost/hana/functional/overload.hpp>

#include <list>
#include <map>
#include <unordered_map>
#include <memory>
#include <queue>
#include <thread>

#include "video_core/src/interrupt_listener.hpp"

class LogManager;
class PicaContext;

namespace Interpreter {
struct CPUContext;
struct Setup;
class GDBStub;
}

namespace Profiler {
class Profiler;
class Activity;
}

namespace HLE {

namespace OS {

// Abstract object with some unique ID.
class Object : public std::enable_shared_from_this<Object> {
public:
    Object() = default;
    Object(const Object&) = delete;

    virtual ~Object() = default;

    std::string name{};

    std::string GetName() const {
        if (!name.empty())
            return name;

       return typeid(*this).name();
    }
};

// TODO: Add a reference counting base class?

class Thread;

// Called "KSynchronizationObject" on 3dbrew.
class ObserverSubject : public Object {
    friend class OS;
public:
    // List of observers. May include the same Thread multiple times.
    std::list<std::weak_ptr<Thread>> observers;

    // TODO: This should be made purely virtual once all ObserverSubject
    //       instances have this function implemented
    virtual bool TryAcquireImpl(std::shared_ptr<Thread>) {
        throw std::runtime_error("This should never be called!");
    }

public:
    virtual ~ObserverSubject() = default;

    /**
     * Tries to acquire the maintained resource in the given thread.
     * If successful, thread will be unregistered from observers.
     */
    bool TryAcquire(std::shared_ptr<Thread> thread);

    /**
     * Registers the given thread for notifications. This will make sure that
     * threads waiting for this subject to become ready will be woken up when
     * it does.
     * The thread will be unregistered once the event has been acquired using
     * TryAcquire.
     */
    void Register(std::shared_ptr<Thread> thread);

    /**
     * Manually unregister the given thread from notifications.
     */
    void Unregister(std::shared_ptr<Thread> thread);
};

/**
 * A handle table is a collection of handles owned by a particular process.
 * Handles are process-unique, but handles of different threads may refer to
 * the same object. The objects are "owned" in the sense that deleting all
 * handles that refer to a particular object will trigger destruction of the
 * object.
 */
class HandleTable {
public: // TODO: Un-publicize. We currently need to do this to be able to find mutexes held by an exited thread :/
    friend class ConsoleModule;

    std::unordered_map<DebugHandle, std::shared_ptr<Object>> table;

    Handle cur_handle = { 0 };

    // Prints an internal logging message about a type mismatch.
    void ErrorNotFound(Handle, const char* requested_type);

    // Prints an internal logging message about a type mismatch.
    void ErrorWrongType(std::shared_ptr<Object> object, const char* requested_type);

public:
    template<typename Type>
    using Entry = std::pair<DebugHandle, std::shared_ptr<Type>>;

    /**
     * Inserts the given Object into the handle table and returns a Handle to the object.
     * @return Immutable pair of Handle and pointer the object.
     */
    template<typename Type>
    Entry<Type> CreateHandle(std::shared_ptr<Type> object, const DebugHandle::DebugInfo& debug_info) {
        static_assert(std::is_base_of<Object,Type>::value, "object must be a shared_ptr to a derivative class of Object!");
        ++cur_handle.value; // TODO: Make sure this never becomes one of the reserved handles
        DebugHandle debug_handle{cur_handle.value, debug_info};
        table[debug_handle] = object;
        return { debug_handle, object };
    }

    /**
     * Inserts the given Object into the handle table with the specified Handle.
     * Use this to set up reserved handles (e.g. 0xFFFF8001 for the handle of the current process)
     */
    template<typename Type>
    void CreateEntry(const DebugHandle& handle, std::shared_ptr<Type> object) {
        static_assert(std::is_base_of<Object,Type>::value, "object must be a shared_ptr to a derivative class of Object!");
        if (table.count(handle))
            throw std::runtime_error("Handle already in table!");

        table[handle] = object;
    }

    /**
     * Returns a shared pointer to the kernel Object referenced by handle if
     * it is in the table and if the object can be downcast to Type.
     * @param fail_expected If true, we won't log an error when an object of different type is found with the given handle
     * @return shared_ptr of the given Type. nullptr if the handle can't be used to obtain a pointer to Type.
     */
    template<typename Type>
    std::shared_ptr<Type> FindObject(Handle handle, bool fail_expected = false) {
        static_assert(std::is_base_of<Object,Type>::value, "object must be a shared_ptr to a derivative class of Object!");

        if (table.count(handle) == 0) {
            if (!fail_expected) {
                ErrorNotFound(handle, typeid(Type).name());
            }
            return nullptr;
        }

        auto object_ptr = std::dynamic_pointer_cast<Type>(table[handle]);
        if (!fail_expected && !object_ptr)
            ErrorWrongType(table[handle], typeid(Type).name());
        return object_ptr;
    }

    DebugHandle FindHandle(void* object) {
        for (auto& entry : table) {
            if (entry.second.get() == object) {
                return entry.first;
            }
        }
        return Handle{HANDLE_INVALID};
    }

    template<typename Type>
    Handle FindHandle(std::shared_ptr<Type> object) {
        static_assert(std::is_base_of<Object,Type>::value, "object must be a shared_ptr to a derivative class of Object!");
        return FindHandle(object.get());
    }

    /**
     * Sets the currently running thread (to be exposed as handle 0xFFFF8000)
     * TODO: What does this return when multiple threads of the same process run on different CPUs?
     */
    void SetCurrentThread(std::shared_ptr<Thread> thread) {
        if (!thread) {
            table.erase(Handle{0xFFFF8000});
        } else {
            table[Handle{0xFFFF8000}] = std::static_pointer_cast<Object>(thread);
        }
    }

    /**
     * Closes the given handle. Does not release any locks still hold on ObserverSubjects.
     * @todo Implement error case?
     */
    void CloseHandle(Handle handle);
};

class Process;
class OS;
class Session;

/// Returned as part of an SVCFuture to signalize that a Thread's wake_index should be returned upon next dispatch
struct PromisedWakeIndex {};

/// Returned as part of an SVCFuture to signalize that a Thread's pending_result should be returned upon next dispatch
struct PromisedResult {};

namespace detail {
template<typename T>
struct SVCFutureResultType {
    using type = T;
};

template<>
struct SVCFutureResultType<PromisedWakeIndex> {
    using type = uint32_t;
};

template<>
struct SVCFutureResultType<PromisedResult> {
    using type = uint32_t;
};

} // namespace detail

// TODO: Move elsewhere
template<typename... T>
struct SVCFuture {
    using DataType = std::tuple<T...>;
    using ResultType = std::tuple<typename detail::SVCFutureResultType<T>::type...>;

    SVCFuture() = default;
    SVCFuture(DataType&& data) : data(data) {};
    SVCFuture& operator =(const SVCFuture&) = default;

    // TODO: This shouldn't be provided outside of the two functions that really need it
    std::optional<DataType> data;
};

/**
 * Utility type for returning the equivalent of "void" from a system call
 * implementation
 */
using SVCEmptyFuture = SVCFuture<std::nullptr_t>;

using SVCCallbackType = std::function<void(std::shared_ptr<Thread>)>;


/**
 * Mechanism that switches control flow between emulated OS threads and the emulated OS scheduler.
 *
 * Usually this is implemented using coroutines, but for Tracy-based profiling there exists a
 * thread-based implementation.
 */
class ThreadControl {
public:
    virtual ~ThreadControl() = default;

    /**
     * Move active control flow from this thread to the scheduler.
     * Must only be called from the running thread
     */
    virtual void YieldToScheduler() = 0;

    /**
     * Move active control flow from the scheduler to the thread.
     * Must only be called from the scheduler
     */
    virtual void ResumeFromScheduler() = 0;

    /**
     * Tear down any resources that may not be active when removing this thread
     * from the scheduler
     */
    virtual void PrepareForExit() {}
};

/// A single thread of execution (child classes may either be actual emulation threads or high-level emulated ones).
class Thread : public ObserverSubject {
    uint32_t id;

public:
    // TODO: Figure out how this actually affects behavior on the 3DS!
    uint32_t priority;

    bool pending_svc = false;

    static const uint32_t PriorityDefault = 0x30;

    /*
     * When status is either WaitingForTimeout or WaitingForArbitration, this
     * number denotes the system time (in nanoseconds) at which to wake up.
     */
    int64_t timeout_at;

    // Address that this thread is currently watching via an AddressArbiter
    VAddr arbitration_address;

    // Arbitration handle (stored for debugging)
    Handle arbitration_handle;

    Process& parent_process;

    Profiler::Activity& activity;
    /// Result to return from a pending system call
    uint32_t promised_result;

    /**
     * Function to be called when a thread is interrupted due to a system call.
     * All variables captured in this function are guaranteed to be valid until
     * the thread execution is resumed or the thread exits.
     */
    SVCCallbackType callback_for_svc;

    // TODO: Make this private!
/*    struct Context {
        uint32_t regs[16];
        uint32_t cpsr;
    } context;*/

    enum class Status {
        Ready,                 // running or ready to run
        Sleeping,              // waiting until SignalResourceReady is called (TODO: SignalResourceReady is unused now!!!)
        WaitingForTimeout,     // waiting for a fixed amount of time
        WaitingForArbitration, // waiting for another thread to signalize a particular address using ArbitrateAddress
        Stopped,               // thread exited and is waiting for its destruction
    } status = Status::Ready;

    /// List of resources that are being waited on as part of SVCWaitSynchronizationN.
    std::list<std::shared_ptr<ObserverSubject>> wait_list;

    /// If true, will not wake up the thread before wait_list is empty.
    bool wait_for_all;

    /**
     * Index of the particular ObserverSubject in wait_list which has been
     * acquired most recently. Note that the value of this variable is only
     * intended to be read by emulated applications when wait_for_all is false.
     */
    uint32_t wake_index;

    /**
     * weak_ptr to the most recently acquired ObserverSubject. This is only
     * valid when wait_for_all is false.
     */
    std::weak_ptr<Object> woken_object;

    // Notify thread of a resource being ready for being TryAcquire'ed
    // TODO: This function is unused now!
    void SignalResourceReady();

    std::unique_ptr<ThreadControl> control;

    Thread(Process& owner, uint32_t id, uint32_t priority);

    virtual ~Thread() = default;

    // Guaranteed to be valid, since every thread must have a process.
    Process& GetParentProcess() {
        return parent_process;
    }

    std::shared_ptr<Thread> GetPointer();

    HandleTable& GetProcessHandleTable();

    uint32_t GetId() const;

    uint32_t GetPriority() const;

    OS& GetOS();

    // Save the current CPU context into "context"
    virtual void SaveContext() = 0;

    // Restore the saved CPU context
    virtual void RestoreContext() = 0;

    /**
     * Run the thread. Execution may yield back to the OS and consecutively other threads through the OS's internal scheduling coroutine.
     * @note In order for execution to yield back to the OS, some system call must be invoked.
     */
    virtual void Run() = 0;

    /**
     * Read a word from the TLS at the given byte offset (must be a multiple of 4)
     * @todo Obsolete. Replace usage of this with ReadMemory
     */
    virtual uint32_t ReadTLS(uint32_t byte_offset) = 0;

    /**
     * Write a word to the TLS at the given byte offset (must be a multiple of 4)
     * @todo Obsolete. Replace usage of this with WriteMemory
     */
    virtual void WriteTLS(uint32_t byte_offset, uint32_t value) = 0;

    /**
     * Write a byte to a location in this thread's parent process virtual memory
     */
    void WriteMemory(VAddr addr, uint8_t value);

    /**
     * Write a word to a location in this thread's parent process virtual memory
     */
    void WriteMemory32(VAddr addr, uint32_t value);

    /**
     * Read a byte from a location in this thread's parent process virtual memory
     */
    uint8_t ReadMemory(VAddr addr);

    /**
     * Read a word from a location in this thread's parent process virtual memory
     */
    uint32_t ReadMemory32(VAddr addr);

    /**
     * Get the value of the given CPU register in this thread's context.
     * @param reg_index Index of the CPU register. r0-r15 are mapped to the first 16 values; CPSR is value 16.
     */
    virtual uint32_t GetCPURegisterValue(unsigned reg_index) {
        return 0;
    }

    /**
     * Set the value of the given CPU register in this thread's context.
     * @param reg_index Index of the CPU register. r0-r15 are mapped to the first 16 values; CPSR is value 16.
     * @param value New value for the specified register
     */
    virtual void SetCPURegisterValue(unsigned reg_index, uint32_t value) {
        // Do nothing by default
    }

    /**
     * Add a breakpoint at the given address. The Thread implementation must
     * ensure that whenever execution reaches the address, execution is paused
     * and the GDB stub is notified about the event.
     */
    virtual void AddBreakpoint(VAddr addr) {
        // Do nothing by default
    }

    /**
     * Removes any breakpoints from the given address.
     */
    virtual void RemoveBreakpoint(VAddr addr) {
        // Do nothing by default
    }

    /**
     * Add a watchpoint at the given address. The Thread implementation must
     * ensure that whenever execution reaches the address, execution is paused
     * and the GDB stub is notified about the event.
     */
    virtual void AddReadWatchpoint(VAddr addr) {
        // Do nothing by default
    }

    /**
     * Removes any read watchpoints from the given address.
     */
    virtual void RemoveReadWatchpoint(VAddr addr) {
        // Do nothing by default
    }

    /**
     * Add a watchpoint at the given address. The Thread implementation must
     * ensure that whenever execution reaches the address, execution is paused
     * and the GDB stub is notified about the event.
     */
    virtual void AddWriteWatchpoint(VAddr addr) {
        // Do nothing by default
    }

    /**
     * Removes any read watchpoints from the given address.
     */
    virtual void RemoveWriteWatchpoint(VAddr addr) {
        // Do nothing by default
    }

    std::shared_ptr<spdlog::logger> GetLogger();

    /**
     * Notifies this Thread about the resource being acquired for it. The
     * resource will be removed from wait_list and the thread will be
     * woken up if appropriate.
     * @pre Thread state must be waiting for resources
     * @pre The given resource must have been in wait_list
     */
    void OnResourceAcquired(ObserverSubject& resource);

    /**
     * Signals a software interrupt to the HardwareScheduler and yields the
     * Thread coroutine. The thread will not be dispatched back in until the
     * OS has processed the system call. In particular, this means the current
     * thread may be unscheduled and other threads may be dispatched before
     * control returns to this thread.
     */
    void YieldForSVC(uint32_t svc);

    uint32_t GetPromise(PromisedResult) const {
        return promised_result;
    }

    uint32_t GetPromise(PromisedWakeIndex) const {
        return wake_index;
    }

    virtual bool TryAcquireImpl(std::shared_ptr<Thread>) override;
};

class TLSManager {
    friend struct TLSSlot;

    void Release(VAddr addr) {
        slot_occupied[(addr - first_tls_addr) / tls_size] = false;
    }

    static constexpr uint32_t page_size = 0x1000;
    static constexpr uint32_t tls_size = 0x200;
    static constexpr uint32_t slots_per_page = page_size / tls_size;

    static constexpr VAddr first_tls_addr = 0x1ff82000;
    VAddr next_tls_addr = first_tls_addr;
    std::vector<bool> slot_occupied;

    bool NextSlotNeedsNewPage() const {
        return (0 == (slot_occupied.size() % slots_per_page));
    }

public:
    struct TLSSlot GetFreePage(Process& process);
};

struct TLSSlot {
    VAddr addr;
    TLSManager& manager;

    TLSSlot(VAddr addr, TLSManager& manager) : addr(addr), manager(manager) {
    }

    TLSSlot(TLSSlot&& slot) : manager(slot.manager) {
        addr = std::exchange(slot.addr, 0);
    }

    ~TLSSlot() {
        if (addr) {
            manager.Release(addr);
        }
    }
};

// A thread performing CPU emulation. This is as close as to a "true" emulated userland thread as it gets.
class EmuThread : public Thread {
public: // TODO: Required by SVCRaw for now. Should have a DumpRegister interface...
    std::unique_ptr<Interpreter::ExecutionContext> context;

public: // TODO: Un-public-ize this!
    TLSSlot tls;

public:
    EmuThread(Process& owner, std::unique_ptr<Interpreter::ExecutionContext>, uint32_t id, uint32_t priority, VAddr entry, VAddr stack_top, TLSSlot tls, uint32_t r0, uint32_t fpscr);

    virtual ~EmuThread() = default;

    void SaveContext() override;

    void RestoreContext() override;

    virtual void Run() override;

    virtual uint32_t ReadTLS(uint32_t offset) override;

    virtual void WriteTLS(uint32_t offset, uint32_t value) override;

    uint32_t GetCPURegisterValue(unsigned reg_index) override;

    void SetCPURegisterValue(unsigned reg_index, uint32_t value) override;

    void AddBreakpoint(VAddr addr) override;

    void RemoveBreakpoint(VAddr addr) override;

    void AddReadWatchpoint(VAddr addr) override;

    void RemoveReadWatchpoint(VAddr addr) override;

    void AddWriteWatchpoint(VAddr addr) override;

    void RemoveWriteWatchpoint(VAddr addr) override;
};

class FakeProcess;

// A high-level emulated thread that omits any CPU emulation and instead executes a given C++ function
// Implementations must provide the Thread::Run() member function.
class FakeThread : public Thread {
    // Fake thread local storage - initialized to zero to make sure all static buffer parameters are reset, etc.
    // NOTE: This should actually be 0x200 bytes large.
    std::array<uint32_t,0x200> tls{};

public:
    FakeThread(FakeProcess& parent);

    virtual ~FakeThread() = default;

    void SaveContext() override {
        // No context to save
        // TODO: Actually, we might want to restore MMU configuration (e.g. to access IO registers)!
    }

    void RestoreContext() override {
        // No context to restore
    }

    uint32_t ReadTLS(uint32_t offset) override {
        return tls[offset / 4];
    }

    void WriteTLS(uint32_t offset, uint32_t value) override {
        tls[offset / 4] = value;
    }

    // Overloaded from Thread for convenience to retrieve a FakeProcess directly rather than a Process
    FakeProcess& GetParentProcess();

    /**
     * Yield back to the OS thread dispatcher and invoke the given system call
     * implementation in its context. This function returns once the OS has
     * dispatched this thread back in.
     */
    template<typename... Results, typename... Args, typename... Args2>
    auto CallSVC(SVCFuture<Results...> (OS::*svc_func)(Args2...), Args&&... args);
};

/**
 * Wraps the given function in a FakeThread, enabling convenient implementation
 * of threads using C++ functions.
 */
class WrappedFakeThread final : public FakeThread {
    std::function<void(FakeThread&)> func;

    void Run() override {
        try {
            func(*this);
        } catch (HLE::OS::FakeThread*) { // TODO: Cleanup interface
            // Do nothing
        }
    }

public:
    WrappedFakeThread(FakeProcess& parent, std::function<void(FakeThread&)> func)
        : FakeThread(parent), func(std::move(func)) {
    }
};

/// See FakeDebugProcess.
class FakeDebugThread : public Thread {
public:
    FakeDebugThread(Process& owner);

    void SaveContext() override {
        // No context to save
    }

    void RestoreContext() override {
        // No context to restore
    }

    uint32_t ReadTLS(uint32_t offset) override {
        // We don't maintain any TLS, so just return 0
        return 0;
    }

    void WriteTLS(uint32_t offset, uint32_t value) override {
        // We don't maintain any TLS, so just do nothing
    }

    void Run() override {
        // Do nothing
    }

    /**
     * Block until the given ProcessorControl requests execution to continue
     */
    void WaitForContinue(Interpreter::ProcessorController& controller);

    /**
     * Reports that a new process was just created, and signals this to the
     * given controller as a breakpoint. In return, the debugger will request
     * execution to be paused and eventually to continue. This function blocks
     * until the latter has happened.
     * @param process Process that just launched
     * @pre process must have its main thread created when calling this function.
     */
    void ProcessLaunched(Process& process, Interpreter::ProcessorController& controller);
};

class MemoryManager;
class ResourceLimit;

/**
 * Owner of a physical memory allocation: Either a Process, a SharedMemoryBlock, or a CodeSet
 */
class MemoryBlockOwner {
public:
    virtual ~MemoryBlockOwner() = default;
};

enum class MemoryPermissions : uint32_t {
    None      = 0,
    Read      = 1,
    Write     = 2,
    ReadWrite = 3,
    Exec      = 4,
    ReadExec  = 5,
};

/// A process (for a very broad definition of "process").
class Process : public ObserverSubject, public MemoryBlockOwner {
    struct VirtualMemoryBlock {
        uint32_t phys_start;
        uint32_t size;
        MemoryPermissions permissions;
    };

    virtual bool TryAcquireImpl(std::shared_ptr<Thread>) {
        for (auto& thread : threads) {
            if (thread->status != Thread::Status::Stopped) {
                return false;
            }
        }
        // Report that the process is terminated, since all of its threads stopped
        return (status != Status::Created);
    }

public: // TODO: Make this private again!
    // Map from starting address to the virtual memory block
    std::map<uint32_t, VirtualMemoryBlock> virtual_memory;
private:

    OS& os;
public:
    MemoryManager& memory_allocator;

public:
    VAddr linear_base_addr = 0x14000000;

private:
    // Process ID
    ProcessId pid;

    ThreadId next_tid;

protected:
public: // TODO: Un-public-ize this!
    Profiler::Activity& activity;

    /**
     * Every Process needs a CPU interpreter Setup, even if the Process is
     * high-level emulated: In particular, FakeProcesses might want to share
     * memory with low-level emulated ones.
     */
    Interpreter::Setup& interpreter_setup;

protected:
    ThreadId MakeNewThreadId();

    /**
     * Called from MapVirtualMemory when a mapping took place.
     * @param phys_addr Base physical address to map data from
     * @param size Number of bytes to map.
     * @param vaddr Virtual address at which to map the given physical memory
     * @todo We might not actually need this!
     */
    virtual void OnVirtualMemoryMapped(PAddr phys_addr, uint32_t size, VAddr vaddr) = 0;

    /**
     * Called from MapVirtualMemory when an unmapping took place.
     * @param size Number of bytes to unmap
     * @param vaddr Virtual address to start unmapping at
     */
    virtual void OnVirtualMemoryUnmapped(VAddr vaddr, uint32_t size) = 0;

public:
    // TODO: Consider making this private!
    std::list<std::shared_ptr<Thread>> threads;

public:
    HandleTable handle_table;

    std::shared_ptr<ResourceLimit> limit;

    enum class Status {
        Created,  // Just created (doesn't have any threads yet)
        Running,  // Process running with at least one thread (i.e. SVCRun has been called)
        Stopping, // Stopping or stopped (if all threads are Stopped)
    } status = Status::Created;

    Process(OS& os, Profiler::Activity&, Interpreter::Setup& setup, ProcessId pid, MemoryManager& memory_allocator);

    virtual ~Process() = default;

    OS& GetOS() { return os; }

    ProcessId GetId() const {
        return pid;
    }

    std::shared_ptr<Thread> GetThreadFromId(ThreadId thread_id) const;

    /**
     * Set up a mapping from virtual memory to physical memory.
     * @param phys_addr Base physical address to map data from
     * @param size Number of bytes to map.
     * @param vaddr Virtual address at which to map the given physical memory
     * @return true on success, false otherwise
     * @todo This may currently only be called on active processes (since it may modify the underlying's CPUContext MMU configuration)
     */
    bool MapVirtualMemory(PAddr phys_addr, uint32_t size, VAddr vaddr, MemoryPermissions);

    /**
     * Unmaps the given virtual memory range from this process.
     * @return true if the given range was successfully unmapped; false if parts of the range weren't unmapped
     */
    bool UnmapVirtualMemory(VAddr vaddr, uint32_t size);

    /**
     * Translate the given virtual address to a physical one.
     */
    std::optional<uint32_t> ResolveVirtualAddr(VAddr addr);

    /**
     * Finds the first unmapped virtual address range of the given size in bytes within the given bounds.
     * @param size Minimum number of bytes in the given range
     * @param vaddr_start Minimal virtual address at which to look for available locations
     * @param vaddr_end Virtual address at which to stop looking for available locations
     * @return On success, returns the base virtual address for the found range
     * @todo This should actually be a Process matter!
     */
    std::optional<uint32_t> FindAvailableVirtualMemory(uint32_t size, VAddr vaddr_start, VAddr vaddr_end);

    MemoryManager& GetPhysicalMemoryManager();

    /**
     * Write a byte to a location in this process's virtual memory
     * @todo Move to Process!
     */
    virtual void WriteMemory(VAddr addr, uint8_t value) = 0;

    virtual void WriteMemory32(VAddr addr, uint32_t value);

    /**
     * Read a byte from a location in this process's virtual memory
     */
    virtual uint8_t ReadMemory(VAddr addr) = 0;

    virtual uint32_t ReadMemory32(VAddr addr);

    /**
     * Read a byte from a location in physical memory. Only intended to be used
     * by the PXI process
     */
    uint8_t ReadPhysicalMemory(PAddr addr);
    uint32_t ReadPhysicalMemory32(PAddr addr);
    void WritePhysicalMemory(PAddr addr, uint8_t value);
    void WritePhysicalMemory32(PAddr addr, uint32_t value);

    std::shared_ptr<spdlog::logger> GetLogger();
};

class CodeSet;

class ResourceLimit;

// A low-level emulated process that is constituted of one or more EmuThreads
class EmuProcess : public Process {
public:
    // TODO: Un-publish
    std::unique_ptr<Interpreter::Processor> processor;

private:
    TLSManager tls_manager;

    void OnVirtualMemoryMapped(PAddr phys_addr, uint32_t size, VAddr vaddr) override;

    void OnVirtualMemoryUnmapped(VAddr vaddr, uint32_t size) override;

public:
    // The given CPUContext is used to initialize the virtual address mapping for this process
    EmuProcess(OS& os, Interpreter::Setup& setup, uint32_t pid, std::shared_ptr<CodeSet> codeset, MemoryManager& memory_allocator);
    ~EmuProcess();

    /**
     * Creates a new EmuThread in this process (allocating memory for thread local storage along the way).
     * The caller is responsible for registering the thread to the OS scheduler.
     * @param entry_point Entry point of the thread.
     */
    std::shared_ptr<EmuThread> SpawnThread(uint32_t priority, VAddr entry_point, VAddr stack_top, uint32_t r0, uint32_t fpscr);

    std::shared_ptr<CodeSet> codeset;

    void WriteMemory(VAddr addr, uint8_t value) override;

    uint8_t ReadMemory(VAddr addr) override;
};

// A high-level emulated process that is constituted of one or more FakeThreads
class FakeProcess : public Process {
    void OnVirtualMemoryMapped(PAddr phys_addr, uint32_t size, VAddr vaddr) override;
    void OnVirtualMemoryUnmapped(VAddr vaddr, uint32_t size) override;

    struct StaticBuffer {
        std::vector<uint8_t> data;
    };

    /**
     * Fake static buffers (maps from the fake start address to the data).
     * Contained buffers are guaranteed to be non-overlapping.
     * TODO: This can be turned into a generic buffer container
     */
    std::map<uint32_t, StaticBuffer> static_buffers;

    // Returns true if the given address points to process-internal storage.
    // Returns false if the given address points to emulated memory.
    bool IsInternalAddress(VAddr addr) const;

public:
    FakeProcess(OS& os, Interpreter::Setup& setup, uint32_t pid, std::string_view name);

    virtual ~FakeProcess() = default;

    /**
     * Attaches the given thread to the internal thread list and registers it to the OS scheduler.
     */
    void AttachThread(std::shared_ptr<FakeThread> thread);

    /**
     * Allocate a static buffer for use in IPC requests.
     * @return A fake address used to identify the static buffer data.
     * @todo Actually, we can make this act as a generic "allocate buffer data" function
     */
    uint32_t AllocateStaticBuffer(uint32_t size);

    /**
     * Allocate a static buffer for use in IPC requests
     * @param address Address previously obtained by AllocateStaticBuffer, which is used to identify the buffer data.
     */
    void FreeStaticBuffer(uint32_t address);

    /**
     * Allocate an internal buffer that is accessible from kernel functions
     * @return a pair of an address where the buffer pretends to be mapped and a pointer to the buffer data
     */
    std::pair<VAddr,uint8_t*> AllocateBuffer(uint32_t size);

    void FreeBuffer(VAddr addr);

    void WriteMemory(VAddr addr, uint8_t value) override;

    void WriteMemory32(VAddr addr, uint32_t value) override;

    uint8_t ReadMemory(VAddr addr) override;
};

/**
 * A fake process similar in spirit to FakeProcess, but even more reduced to the bare minimum.
 * FakeDebugProcess is not intended to actively participate in the OS operation; instead, it's
 * mere purpose is to act as a dummy process that host debuggers can attach to such that they
 * can listen for newly created EmuProcesses (which will report a SIGTRAP to debuggers).
 * Other than that, FakeDebugProcess implements the memory reading interface to return always
 * the same value (representing a "branch to self" ARM instruction), such that it appears to the
 * debugger as if we were stuck in an infinite loop (since the alternative of returning garbage
 * data would probably make the debugger go crazy).
 */
class FakeDebugProcess : public Process {
    void OnVirtualMemoryMapped(PAddr, uint32_t, VAddr) override {
        // Do nothing
    }

    void OnVirtualMemoryUnmapped(VAddr, uint32_t) override {
        // Do nothing
    }

public:
    FakeDebugProcess(OS& os, Interpreter::Setup& setup, ProcessId pid);

    void WriteMemory(VAddr, uint8_t) override {
        // Do nothing
    }

    uint8_t ReadMemory(VAddr addr) override {
        // Always return the ARM instruction 0xeafffffe, which is a branch to
        // the current offset. To the debugger it will hence look as if we were
        // stuck in an infinite loop (which is better than returning garbage
        // instruction data).
        switch (addr % 4) {
        case 0: return 0xfe;
        case 1: return 0xff;
        case 2: return 0xff;
        case 3: return 0xea;
        default: return 0; // Silence compiler warning
        }
    }

    std::shared_ptr<FakeDebugThread> thread;
};

// Tags for WrappedFakeProcess
struct TagMapGPUMMIO {};
struct TagMapHIDMMIO {};
struct TagMapVRAM {};
struct TagMapDSPMemory {};

/**
 * Wraps a FakeProcess around the C++ code providing for the process main
 * thread logic. This logic is intended to be implemented in the State
 * constructor. Effectively, a State object is created that represents the main
 * process thread while it furthermore carries the entire process state (which
 * may be used to spawn additional threads). This allows for high-level
 * emulating stateful, multi-threaded Processes in a very natural manner.
 * @note The State object creation is delayed until the FakeProcess's main
 *       thread is scheduled in, which allows the use of system calls in the
 *       State constructor, hence making for cleaner resource management.
 * @todo Consider whether this should just be promoted to be our Thread class:
 *       Both EmuThread and FakeThread could possibly be implemented using
 *       an appropriate lambda expression.
 */
class WrappedFakeProcess : public FakeProcess {
    std::function<void(FakeThread&)> functor;

    WrappedFakeProcess(OS& os, Interpreter::Setup& setup, uint32_t pid, std::string_view name, std::function<void(FakeThread&)> functor)
        : FakeProcess(os, setup, pid, name), functor(std::move(functor)) {
    }

public:
    void SpawnMainThread() {
        // TODO: Should we call SVCExitThread after State{...} is done?
        //       If we do, we should assert that no more than one thread is left running!
        auto thread = std::make_shared<WrappedFakeThread>(*this, std::move(functor));
        AttachThread(thread);
    }

    static std::shared_ptr<WrappedFakeProcess> Create(OS& os, Interpreter::Setup& setup, uint32_t pid, const std::string& name, std::function<void(FakeThread&)> functor) {
        auto process = std::shared_ptr<WrappedFakeProcess>(new WrappedFakeProcess(os, setup, pid, name, std::move(functor)));
        // TODO: Attach debug information!
        process->handle_table.CreateEntry(Handle{0xFFFF8001}, process);
        return process;
    }

    template<typename Context, typename... Args>
    static std::shared_ptr<WrappedFakeProcess> CreateWithContext(OS& os, Interpreter::Setup& setup, uint32_t pid, const std::string& name, Args&&... args) {
        auto process = Create(os, setup, pid, name, [args...](FakeThread& thread) { Context{thread, args...}; });
        // Map IO memory for HLE processes
        if (std::is_base_of<TagMapGPUMMIO, Context>::value) {
            process->MapVirtualMemory(Memory::IO_GPU::start, Memory::IO_GPU::size, 0x1EF00000, MemoryPermissions::ReadWrite);
        }
        // TODO: Add TagMapHashMMIO tag
//        if (std::is_base_of<TagMapGPUMMIO, Context>::value) {
            process->MapVirtualMemory(Memory::IO_HASH::start, Memory::IO_HASH::size, 0x1EC01000, MemoryPermissions::ReadWrite);
            process->MapVirtualMemory(Memory::IO_HASH2::start, Memory::IO_HASH2::size, 0x1EE01000, MemoryPermissions::ReadWrite);
//        }
        if (std::is_base_of<TagMapHIDMMIO, Context>::value) {
            process->MapVirtualMemory(Memory::IO_HID::start, Memory::IO_HID::size, 0x1EC46000, MemoryPermissions::ReadWrite);
        }
        if (std::is_base_of<TagMapVRAM, Context>::value) {
            process->MapVirtualMemory(Memory::VRAM::start, Memory::VRAM::size, 0x1F000000, MemoryPermissions::ReadWrite);
        }
        // TODO: Migrate DSP to new service framework and apply this tag
        /*if (std::is_base_of<TagMapDSPMemory, Context>::value)*/ {
            process->MapVirtualMemory(Memory::DSP::start, Memory::DSP::size, 0x1FF00000, MemoryPermissions::ReadWrite);
        }
        return process;
    }
};

template<typename Context, typename... Args>
std::shared_ptr<WrappedFakeProcess> CreateFakeProcessViaContext(OS& os, Interpreter::Setup& setup, uint32_t pid, const std::string& name, Args&&... args) {
    return WrappedFakeProcess::CreateWithContext<Context>(os, setup, pid, name, std::forward<Args>(args)...);
}

struct CodeSetInfo {
    BOOST_HANA_DEFINE_STRUCT(CodeSetInfo,
        (std::array<uint8_t, 8>, app_name),
        (std::array<uint8_t, 8>, unknown),

        (VAddr, text_start),
        (uint32_t, text_pages),
        (VAddr, ro_start),
        (uint32_t, ro_pages),
        (VAddr, data_start),
        (uint32_t, data_pages), // bss exclusive

        // These fields seem to be the same as text_pages/ro_pages/data/pages
        (uint32_t, text_size), // in 0x1000-pages
        (uint32_t, ro_size),   // in 0x1000-pages
        (uint32_t, data_size), // in 0x1000-pages (bss inclusive)

        (std::array<uint8_t, 12>, unknown2)
    );
};

// TODO: Most of the contents of this struct need to be verified!
struct DMAConfig {
    // There are 8 channels the application may chose from (values 0 through 7)
    // 0xff means "any channel"
    uint8_t channel;

    // Value size (used for endian-swapping): 0=uint8, 2=uint16, 4=uint32, 8=uint64
    uint8_t value_size;

    struct {
        uint8_t storage;

        using Fields = v2::BitField::Fields<uint32_t>;

        /// Load target configuration following this structure
        auto LoadTargetConfig() const { return Fields::MakeOn<0, 1>(this); }

        /// Load source configuration following this structure and the target configuration
        auto LoadSourceConfig() const { return Fields::MakeOn<1, 1>(this); }

        auto BlockUntilCompletion() const { return Fields::MakeOn<2, 1>(this); }

        /// Load target configuration, but force its peripheral_id to be 0xff
        auto LoadTargetAltConfig() const { return Fields::MakeOn<6, 1>(this); }

        /// Load source configuration, but force its peripheral_id to be 0xff
        auto LoadSourceAltConfig() const { return Fields::MakeOn<7, 1>(this); }
    } flags;

    uint8_t unknown2;

    struct SubConfig {
        uint8_t unknown;

        // Seems to indicate the value size? TODO: how is this compatible with the member value_size above?
        uint8_t type;

        uint16_t unknown2;

        uint16_t transfer_size;

        uint16_t unknown3;

        uint16_t stride;

        static SubConfig Default() {
            return { 0xff, 0xf, 0x80, 0x0, 0x80, 0x0 };
        }
    };

    // NOTE: Possible 3dbrew erratum: Which SubConfig actually comes first?
    SubConfig dest;
    SubConfig source;
};

class CodeSet : public Object, public MemoryBlockOwner {
public:
    char app_name[9]; // 8 characters + null-terminator

    // NOTE: System version 10.x added pseudo address layout randomization,
    //       so the mapped physical memory provided by the caller may not be
    //       contiguous. We hence have to keep a list of mappings.
    //       The virtual address space is still contiguous, so a single start address is sufficient.

    struct Mapping {
        PAddr phys_start;
        uint32_t num_pages;
    };

    std::vector<Mapping> text_phys;
    VAddr text_vaddr;

    std::vector<Mapping> ro_phys;
    VAddr ro_vaddr;

    // data excluding bss
    std::vector<Mapping> data_phys;
    VAddr data_vaddr;

    PAddr bss_paddr;
    uint32_t bss_size; // in pages

    CodeSet(const CodeSetInfo& info);

    // Cleans up the allocated data
    virtual ~CodeSet() override;
};

class Port;

class ServerPort : public ObserverSubject {
    friend class OS;
    friend class ClientPort;

    // Number of sessions that can be created in addition to the ones that are already open
    uint32_t available_sessions;

public:
    ServerPort(std::shared_ptr<Port> port, uint32_t max_sessions) : port(port), available_sessions(max_sessions) {
    }

    virtual ~ServerPort() = default;

    bool TryAcquireImpl(std::shared_ptr<Thread> thread) override;

    void OfferSession(std::shared_ptr<Session> session);

    std::shared_ptr<Port> port;

    // Queue of incoming sessions
    std::queue<std::shared_ptr<Session>> session_queue;
};

class ClientPort : public ObserverSubject {
public:
    ClientPort(std::shared_ptr<Port> port) : port(port) {
    }

    virtual ~ClientPort() = default;

    std::shared_ptr<Port> port;

    bool TryAcquireImpl(std::shared_ptr<Thread> thread) override;
};

class ServerSession : public ObserverSubject {
public: // TODO: Un-public-ize
    uint32_t ipc_commands_pending = 0;

public:
    ServerSession(std::shared_ptr<Session> session, std::shared_ptr<ServerPort> port) : session(session), port(port) {
    }

    virtual ~ServerSession() = default;

    bool TryAcquireImpl(std::shared_ptr<Thread> thread) override;

    void CommandReady();

    std::shared_ptr<Session> session;

    // May be nullptr for sessions that aren't bound to any port
    std::shared_ptr<ServerPort> port;
};

class ClientSession : public ObserverSubject {
public:
    ClientSession(std::shared_ptr<Session> session) : session(session) {
    }

    virtual ~ClientSession() = default;

    // Returns bool if the session has been signalled for the thread pushed as the argument
    // (thread = SVCSendSyncRequest sender)
    bool TryAcquireImpl(std::shared_ptr<Thread> thread) override;

    // Releases the first of the remaining waiting threads
    void SetReady(std::shared_ptr<Thread> waiting_thread);

    std::shared_ptr<Session> session;

    // location of the thread that last sent an IPC request using this session (for the server to read IPC requests from its TLS)
    std::list<std::weak_ptr<Thread>> threads;
};

class Port : public Object {
public:
    virtual ~Port() = default;

    // NOTE: Port is owned by its children, since one child is enough for a Port to exist, but if both children are released, the parent Port dies to.
    std::weak_ptr<ServerPort> server;
    std::weak_ptr<ClientPort> client;
};

class Session : public Object {
public:
    virtual ~Session() = default;

    // NOTE: Session is owned by its children, since one child is enough for a Session to exist, but if both children are released, the parent Session dies to.
    std::weak_ptr<ClientSession> client;
    std::weak_ptr<ServerSession> server;
};

class Mutex : public ObserverSubject {
    uint32_t lock_count = 0;

    // Thread currently holding a lock in this mutex
    std::weak_ptr<Thread> owner;

public:
    Mutex(bool locked, std::shared_ptr<Thread> initial_owner) : lock_count(locked ? 1 : 0), owner(initial_owner) {};

    virtual ~Mutex() = default;

    bool TryAcquireImpl(std::shared_ptr<Thread> thread) override;

    void Release();

    bool IsOwner(std::shared_ptr<Thread> thread) const;

    bool IsReady() const {
        return (lock_count == 0);
    }
};

class Semaphore : public ObserverSubject {
public:
    int32_t available_count;

private:
    int32_t max_available;

public:

    /// @pre 0 <= count <= max_count
    Semaphore(int32_t count, int32_t max_count) : available_count(count), max_available(max_count) {
    }

    bool TryAcquireImpl(std::shared_ptr<Thread> thread) override;

    /**
     * Release this semaphore "times" times. This will allow "times" additional
     * threads to acquire the thread. "times" needs to be larger than zero. The
     * implied final count may not exceed the maximal count.
     * @result RESULT_OK on success
     */
    uint32_t Release(int32_t times);
};

enum class ResetType : uint32_t {
    OneShot = 0, // Be acquirable once, then reset
    Sticky  = 1, // Be acquirable until explicitly reset
    Pulse   = 2, // Timer-only: Be acquirable once, then reset and restart the timer.
};

class Event : public ObserverSubject {
    // TODO: Make this class thread-safe!
public: // TODO: Remove this ugly hack
    bool signalled = false;

    ResetType type;

public:
    Event(ResetType type) : type(type) {
    }

    virtual ~Event() = default;

    bool TryAcquireImpl(std::shared_ptr<Thread> thread) override;

    void SignalEvent();

    void ResetEvent();
};

class DMAObject : public ObserverSubject {
public:
    DMAObject() = default;
    virtual ~DMAObject() = default;

    bool TryAcquireImpl(std::shared_ptr<Thread>) override {
        // Our current DMA SVC implementation has DMAs complete instantly,
        // so we always allow successful acquisition of this object
        return true;
    }
};

constexpr uint64_t cpu_clockrate = 268111856; // Clock rate as per constants used in 3DS kernel
using secs_per_tick = std::ratio<1,cpu_clockrate>;
using ticks = std::chrono::duration<uint64_t, secs_per_tick>;
// This is determined by LCD hardware configuration: cpu_clockrate / 24 / ((HTotal+1) * (VTotal+1))
using vblanks_per_sec = std::chrono::duration<uint64_t, std::ratio<24 * 451 * 414, cpu_clockrate>>; // approximately 59.83 Hz

class Timer : public ObserverSubject {
    // TODO: Make this class thread-safe!
public: // TODO: remove this
    bool active = false;

    ResetType type;

    // timeout when current_time >= timeout_time_ns
    uint64_t timeout_time_ns = 0;

    uint64_t period_ns = 0;

public:
    Timer(ResetType type) : type(type) {
    }

    virtual ~Timer() = default;

    bool TryAcquireImpl(std::shared_ptr<Thread> thread) override;

    void Run(uint64_t timeout_time, uint64_t period);

    void Reset();

    bool Expired(uint64_t current_time) const;
};

/**
 * These are used e.g. to implement light events (of which there may be
 * arbitrarily many, but multiple light events need no more than a single
 * kernel handle).
 */
class AddressArbiter : public Object {
public:
    AddressArbiter() = default;

    virtual ~AddressArbiter() = default;
};

struct MemoryBlock {
    uint32_t size_bytes;

    std::weak_ptr<MemoryBlockOwner> owner;
};

class MemoryManager {
    // physical starting address of region
    uint32_t region_start_paddr;

    uint32_t region_size_bytes;

public:
// TODO: Needs an interface to check for ownership
    // Maps describing the free/taken memory blocks (mapped by their starting physical address)
    std::map<uint32_t, MemoryBlock> free;
    std::map<uint32_t, MemoryBlock> taken;

public:
    MemoryManager(PAddr start_address, uint32_t size);

    /**
     * Allocate a memory block of the given size.
     * @return Starting address of the allocated buffer. boost::none on failure.
     * @todo Provide means to deallocate the block again!
     */
    std::optional<uint32_t> AllocateBlock(std::shared_ptr<MemoryBlockOwner>, uint32_t size_bytes);

    void DeallocateBlock(std::shared_ptr<MemoryBlockOwner>, PAddr start_addr, uint32_t size_bytes);

    void TransferOwnership(std::shared_ptr<MemoryBlockOwner> old_owner, std::shared_ptr<MemoryBlockOwner> new_owner, PAddr start_addr, uint32_t size_bytes);

    void DeallocateBlock(PAddr start_addr, uint32_t size_bytes);

    uint32_t UsedMemory() const;

    uint32_t TotalSize() const;

    PAddr RegionStart() const { return region_start_paddr; }
    PAddr RegionEnd() const { return region_start_paddr + region_size_bytes; }
};

class SharedMemoryBlock : public Object, public MemoryBlockOwner {
public:
    // Address to data stored in emulated memory
    uint32_t phys_address;

    uint32_t size;

    bool owns_memory;

    SharedMemoryBlock(uint32_t physical_address, uint32_t size, bool owns_memory)
        : phys_address(physical_address), size(size), owns_memory(owns_memory) {
    }

    // TODO: On destruction, this must deallocate any pending memory!
    virtual ~SharedMemoryBlock() = default;
};

// A service is an anonymous port that is queryable through the port srv, which needs service processes to provide the GetPrivateName method.
class Service : Port {
public:
    virtual const char* GetPrivateName() = 0;
};

class OS final : public InterruptListener {
    friend class ConsoleModule;

    // Thread list for the scheduler (threads are owned by processes).
    std::list<std::weak_ptr<Thread>> threads;

/*    // GDB stub for Core 1
    std::unique_ptr<Interpreter::GDBStub> gdbstub;
*/
    // Thread for running the GDB stub
    std::unique_ptr<std::thread> gdbthread;

    // TODO: Currently, we never release any of the references hold here before shutdown!
    // TODO: Consider storing ClientPorts here instead.
    std::map<std::string, std::shared_ptr<Port>> ports;


    Hypervisor hypervisor;

public: // TODO: Ugh.
    PAddr configuration_memory = 0;

    PAddr shared_memory_page = 0;

    PAddr firm_launch_parameters = 0;

    std::array<std::list<std::weak_ptr<Event>>, 0x76> bound_interrupts;

    // Id of the next process that is going to be created
    ProcessId next_pid;

    // Number of CPU ticks since power-on
    ticks system_tick = ticks::zero();

    std::list<std::weak_ptr<Timer>> active_timers;

    // Process handle table - all processes are owned exclusively by this table.
    std::unordered_map<ProcessId, std::shared_ptr<Process>> process_handles;

    struct FakeProcessInfo {
        std::shared_ptr<WrappedFakeProcess> (*create)(OS&, const std::string&);
        std::weak_ptr<Process> fake_process {};
    };
    std::unordered_map<std::string_view, FakeProcessInfo> hle_titles;

    // TODO: Get rid of the parameter
    DebugHandle::DebugInfo MakeHandleDebugInfo(DebugHandle::Source source = DebugHandle::Original) const;
    DebugHandle::DebugInfo MakeHandleDebugInfoFromIPC(uint32_t ipc_command) const;

public: // TODO: privatize this again!
    std::list<std::weak_ptr<Thread>> ready_queue; // Queue of threads that are ready to run
//     std::list<std::weak_ptr<Thread>> priority_queue; // Queue of threads that are ready to run and should be prioritized over those in ready_queue (e.g. because they had been waiting on an event that was just signalled)
    std::vector<std::weak_ptr<Thread>> waiting_queue; // List of threads waiting on a timeout

    std::shared_ptr<MemoryBlockOwner> internal_memory_owner;

    // APP, SYSTEM, and BASE
    // For each application, all data (code + stack(?) + heap) is allocated
    // in the region indicated by the memory type in the application's exheader
    // kernel flags. The only known exception to this is Thread Local Storage,
    // which is always allocated in the BASE region.
    std::array<MemoryManager, 3> memory_regions;
    [[deprecated]] MemoryManager& memory_app() { return memory_regions[0]; }
    [[deprecated]] MemoryManager& memory_system() { return memory_regions[1]; }
    [[deprecated]] MemoryManager& memory_base() { return memory_regions[2]; }
    MemoryManager& FindMemoryRegionContaining(uint32_t paddr, uint32_t size);

    OS( Profiler::Profiler&, Settings::Settings&, Interpreter::Setup&,
        LogManager&, AudioFrontend&, PicaContext&, EmuDisplay::EmuDisplay&);
    ~OS();

    Profiler::Profiler& profiler;
    Profiler::Activity& activity;

    PicaContext& pica_context;
    EmuDisplay::EmuDisplay& display;

public:
    Settings::Settings& settings;

    Interpreter::Setup& setup;

    ProcessId MakeNewProcessId();

    /// Appends the given process to the global process list
    void RegisterProcess(std::shared_ptr<Process> process);

    // Process for debuggers to attach to initially
    std::shared_ptr<FakeDebugProcess> debug_process;

    static const int32_t MAX_SESSIONS = 0x1000; // Arbitrary choice

    // NOTE: Required for SVCRaw (for some reason) and GDBStub
    // TODO: Create an interface around this instead.
    Thread* active_thread;

    LogManager& log_manager;
    std::shared_ptr<spdlog::logger> logger;

private:
    std::atomic<bool> stop_requested { false };

public:

    using Result = uint32_t;

    template<typename... T>
    using ResultAnd = std::tuple<Result, T...>;

    enum class BreakReason : uint32_t {
        Panic  = 0,
        Assert = 1,
        User   = 2
    };

    enum class ArbitrationType : uint32_t {
        Signal = 0,
        Acquire = 1,
        DecrementAndAcquire = 2,
        AcquireWithTimeout = 3,
        DecrementAndAcquireWithTimeout = 4,
    };

    enum class MemoryRegion {
        App = 1,
        Sys = 2,
        Base = 3
    };

    struct StartupInfo {
        int32_t priority;
        uint32_t stack_size;
        int32_t argc;
        VAddr argv_addr;
        VAddr envp_addr;
    };

    struct KernelCapability {
        uint32_t storage;

        // The number of leading 1s in this field distinguishes each type of capability
        auto identifier() const { return BitField::v3::MakeFieldOn<20, 12>(this); }

        auto kernel_version() const {
            struct {
                uint32_t storage;

                auto minor() const { return BitField::v3::MakeFieldOn<0, 8>(this); }
                auto major() const { return BitField::v3::MakeFieldOn<8, 8>(this); }
            } ret { storage };
            return ret;
        }

        // TODO: Possible bugfix here... this used to be a struct of two BitFields, hence being uint64_t in total size???
        auto map_io_page() const {
            struct {
                uint32_t storage;

                auto page_index() const { return BitField::v3::MakeFieldOn<0, 20>(this); }
                auto read_only() const { return BitField::v3::MakeFlagOn<20>(this); }
            } ret { storage };
            return ret;
        }
    };

    // System calls begin here
    /**
     * TODOTEST: This has a PID==1 check on actual hardware, see https://www.3dbrew.org/w/index.php?title=3DS_System_Flaws&curid=95&diff=18930&oldid=18655
     * TODO: Change permission parameter to MemoryPermissions type
     */
    SVCFuture<OS::Result,uint32_t> SVCControlMemory(Thread& source, uint32_t addr0, uint32_t addr1, uint32_t size, uint32_t operation, uint32_t permissions);

    SVCFuture<OS::Result,uint32_t> SVCControlProcessMemory(Thread& source, Process& process, uint32_t addr0, uint32_t addr1, uint32_t size, uint32_t operation, MemoryPermissions);

    SVCFuture<OS::Result,HandleTable::Entry<Thread>> SVCCreateThread(Thread& source, uint32_t entry, uint32_t arg, uint32_t stack_top, uint32_t priority, uint32_t processor_id);

    void ExitThread(Thread& thread);
    SVCEmptyFuture SVCExitThread(Thread& source);

    SVCEmptyFuture SVCSleepThread(Thread& source, int64_t duration);

    // Allocate stack memory, set up the process main thread, and append the thread to the scheduler queue
    SVCFuture<Result> SVCRun(Thread& source, Handle process, const StartupInfo& startup);

    SVCFuture<Result,HandleTable::Entry<Mutex>> SVCCreateMutex(Thread& source, bool lock);
    SVCFuture<Result> SVCReleaseMutex(Thread& source, Handle mutex);

    /// @pre 0 <= initial_count <= max_count
    SVCFuture<Result,HandleTable::Entry<Semaphore>> SVCCreateSemaphore(Thread& source, int32_t initial_count, int32_t max_count);
    SVCFuture<OS::Result,int32_t> SVCReleaseSemaphore(Thread& source, Semaphore& sema, int32_t release_count);

    SVCFuture<Result,HandleTable::Entry<Event>> SVCCreateEvent(Thread& source, ResetType type);
    SVCFuture<Result> SVCSignalEvent(Thread& source, Handle event);
    SVCFuture<Result> SVCClearEvent(Thread& source, Handle event);

    SVCFuture<Result,HandleTable::Entry<Timer>> SVCCreateTimer(Thread& source, ResetType type);
    /**
     * Functional properties:
     * - Timer starts waking up threads after the given initial time duration (in nanoseconds) has passed
     * - ONESHOT timers will wake exactly one thread
     * - STICKY timers will wake any number of threads until they are reset
     * - PULSE timers will wake exactly one thread, and restart themselves to fire "interval" nanoseconds after the wakeup
     *     - In particular, this means that threads in general get woken later than "initial + interval * n", because the time of firing the timer will be after waking the thread.
     */
    SVCFuture<Result> SVCSetTimer(Thread& source, Timer& timer, int64_t initial, int64_t period);

    // TODO: This should transfer ownership of the shared pages to the memory block!
    SVCFuture<Result,HandleTable::Entry<SharedMemoryBlock>> SVCCreateMemoryBlock(Thread& source, VAddr addr, uint32_t size, uint32_t owner_perms, uint32_t other_perms);
    /**
     * @todo Figure out what closing the block handle achieves: Does it unmap the memory?
     */
    SVCFuture<Result> SVCMapMemoryBlock(Thread& source, Handle block_handle, VAddr addr, MemoryPermissions caller_perms, MemoryPermissions other_perms);

    /**
     * @todo Why does this take both a block and an address, when either would suffice?
     */
    SVCFuture<Result> SVCUnmapMemoryBlock(Thread& source, SharedMemoryBlock& block, VAddr addr);

    SVCFuture<Result,HandleTable::Entry<AddressArbiter>> SVCCreateAddressArbiter(Thread& source);

    /**
     * Functional properties:
     * - Acquiring type: If the word at the given address is smaller than the
     *                   given value, the thread is put to sleep until woken
     *                   up by a call to this system call.
     * - Signalling type: Wakes up "value"" threads waiting due to a call to
     *                    this system call with the same address.
     *                    (A negative "value" resumes all threads waiting on
     *                    this arbiter.)
     * @todo value should actually be of type int32_t, because value=-1 means to signalize all waiting threads
     */
    SVCFuture<PromisedResult> SVCArbitrateAddress(Thread& source, Handle arbiter_handle, uint32_t address, ArbitrationType type, uint32_t value, int64_t timeout);

    /**
     * Things to test:
     * - Does closing a mutex unlock it?
     */
    SVCFuture<Result> SVCCloseHandle(Thread& source, Handle object);

    Result CloseHandle(Thread& source, Handle object);

    /**
     * Things to test:
     * - timeout = -1 implies indefinite sleep until resource is ready
     * - timeout = 0 implies instant wakeup if resource is not ready
     * - What about timeout < -2?
     */
    SVCFuture<PromisedResult> SVCWaitSynchronization(Thread& source, Handle handle, int64_t timeout);

    /**
     * Things to test:
     * - What happens if one of the given objects is being destroyed while waiting on it?
     * - timeout = -1 implies indefinite sleep until resources are ready
     * - timeout = 0 implies instant wakeup if resources are not ready
     * - What about timeout < -2?
     */
    SVCFuture<PromisedResult,PromisedWakeIndex> SVCWaitSynchronizationN(Thread& source, Handle* handles, uint32_t handle_count, bool wait_for_all, int64_t timeout);

    // Create a new handle referencing the same object as the given handle.
    SVCFuture<Result,Handle> SVCDuplicateHandle(Thread& source, Handle handle);

    // Gets the time passed since turning on the system (measured in CPU ticks)
    SVCFuture<uint64_t> SVCGetSystemTick(Thread& source);

    /**
     * Functional properties:
     * - Returns success instantly as long as the port exists (the server need not have called ReplyAndReceive yet)
     * - Returns 0xd88007fa if no port with the given name exists
     */
    SVCFuture<Result,HandleTable::Entry<ClientSession>> SVCConnectToPort(Thread& source, const std::string& name);

    /**
     * Functional properties:
     * - Behavior when two threads use this system call on the same handle:
     *   - The two requests get processed independently
     *   - It's unclear whether causal order is preserved when processing the two requests
     * - SendSyncRequest can be called before the server has accepted the session in the first place (and SendSyncRequest will then block)
     * - Blocks until a response arrives.
     */
    SVCFuture<PromisedResult> SVCSendSyncRequest(Thread& source, Handle session);

    /**
     * Things to test:
     * - May a process open itself?
     * - Will circular dependencies between two processes that have opened each other be resolved when both of the processes have exited?
     */
    SVCFuture<Result,HandleTable::Entry<Process>> SVCOpenProcess(Thread& source, ProcessId proc_id);

    SVCFuture<Result,ProcessId> SVCGetProcessId(Thread& source, Process& process);

    SVCFuture<Result,ThreadId> SVCGetThreadId(Thread& source, Thread& thread);

    [[noreturn]] SVCEmptyFuture SVCBreak(Thread& source, BreakReason reason);
    /**
     * Functional properties:
     * - A client port is only created when \p name is the empty string
     * - Multiple ports with the same name may be created
     * - No more than 7 ports may be created across the entire system
     * - There seems to be no way to unregister a port (TODO: Verify)
     */
    SVCFuture<Result,HandleTable::Entry<ServerPort>,HandleTable::Entry<ClientPort>> SVCCreatePort(Thread& source, const std::string& name, int32_t max_sessions);
    /**
     * Functional properties:
     * - Returns before the server calls SVCReplyAndReceive
     */
    SVCFuture<Result,HandleTable::Entry<ClientSession>> SVCCreateSessionToPort(Thread& source, Handle client_port);
    SVCFuture<Result,HandleTable::Entry<ServerSession>,HandleTable::Entry<ClientSession>> SVCCreateSession(Thread& source);
    SVCFuture<Result,HandleTable::Entry<ServerSession>> SVCAcceptSession(Thread& source, ServerPort& server_port); // returns server session
    /**
     * Functional properties:
     * - When TLS@0x80 is 0xffff0000 and reply_target==0, the reply is omitted
     * - handle_count==0 logically omits the "receive" part
     * - handles==nullptr => ??
     * - this function returns when a ServerPort handle that it's waiting on is being connected to. Does it also return when a session handle is closed?
     */
    SVCFuture<PromisedResult,PromisedWakeIndex> SVCReplyAndReceive(Thread& source, Handle* handle_values, uint32_t handle_count, Handle reply_target); // returns index into @p handles

    SVCFuture<Result> SVCBindInterrupt(Thread& source, uint32_t interrupt_index, std::shared_ptr<Event> signal_event, int32_t priority, uint32_t is_manual_clear);

    /**
     * @param start Range start adress (must be mapped in the source process)
     */
    SVCFuture<Result> SVCInvalidateProcessDataCache(Thread& source, Handle process, uint32_t start, uint32_t num_bytes);

    /**
     * @param start Range start adress (must be mapped in the source process)
     */
    SVCFuture<Result> SVCFlushProcessDataCache(Thread& source, Handle process, uint32_t start, uint32_t num_bytes);

    SVCFuture<OS::Result,HandleTable::Entry<DMAObject>> SVCStartInterprocessDMA(Thread& source, Process& src_process, Process& dst_process, const VAddr src_address, const VAddr dst_address, uint32_t size, DMAConfig& dma_config);

    /**
     * Functional properties:
     * - Unmaps the given memory from the virtual address space of the calling process (TODO: Verify)
     */
    SVCFuture<Result,HandleTable::Entry<CodeSet>> SVCCreateCodeSet(Thread& source, const CodeSetInfo& info, VAddr text_data_addr, VAddr ro_data_addr, VAddr data_data_addr);

    /**
     * Functional properties:
     * - Returns 0xe0a01bf5 when the code set contains a ro and rw address that are equal
     */
    SVCFuture<Result,HandleTable::Entry<Process>> SVCCreateProcess(Thread& source, Handle codeset_handle, KernelCapability* kernel_caps, uint32_t num_kernel_caps);

    /**
     *
     */
    SVCFuture<Result,HandleTable::Entry<ResourceLimit>> SVCCreateResourceLimit(Thread& source);

    /**
     *
     */
    SVCFuture<Result> SVCSetResourceLimitValues(Thread& source, ResourceLimit& resource_limit, const std::vector<std::pair<uint32_t, uint64_t>>& limits);

    // Fake SVCs begin here - these don't map to native SVCs but provide useful functionality

    /**
     * Invokes the system call handler for the given svc_id and decodes
     * arguments appropriately from the given CPUContext.
     * @return Function to call in the Thread context to encode the return
     *         values back into the CPUContext
     */
    SVCCallbackType SVCRaw(Thread& source, unsigned svc_id, Interpreter::ExecutionContext&);

    SVCEmptyFuture SVCDoNothing(Thread& source); // TODO: We don't really need this one, it was just for testing!

    SVCFuture<Result,HandleTable::Entry<Object>> SVCCreateDummyObject(FakeThread& source, const std::string& name);

    /**
     * Add the given Thread to the internal thread list recognized by the scheduler.
     * Intended to be used for FakeThreads, only. Native threads are added automatically when calling SVCCreateThread.
     * TODO: This doesn't seem to be used anymore.
     */
    SVCEmptyFuture SVCAddThread(std::shared_ptr<Thread> thread);

    static std::pair<std::unique_ptr<OS>, std::unique_ptr<ConsoleModule>> Create(Settings::Settings& settings, Interpreter::Setup& setup, LogManager& log_manager, Profiler::Profiler&, AudioFrontend&, PicaContext&, EmuDisplay::EmuDisplay&);

    /**
     * Initialized the OS, spawning all service processes along the way.
     */
    void Initialize();

    /**
     * Creates a FakeProcess with no running threads.
     */
    std::shared_ptr<FakeProcess> MakeFakeProcess(Interpreter::Setup& setup, const std::string& name);

    /**
     * Returns true if the given module should be high-level emulated, i.e. replaced with a FakeProcess
     */
    bool ShouldHLEProcess(std::string_view module_name) const;

    /**
     * Registers a thread to the OS scheduler
     */
    void RegisterToScheduler(std::shared_ptr<Thread> thread);

    /**
     * Runs the OS dispatcher.
     * This function won't return unless the emulator encounters an exception
     * or RequestStop is called.
     *
     * @note This must be called after Initialize()
     * @note You have to add any user process explicitly before calling this if it should be ran, too.
     */
    void Run(std::shared_ptr<Interpreter::Setup> setup);

    /**
     * Requests OS execution to stop.
     *
     * Resources will be cleaned up gracefully as far as C++ goes, but
     * no guarantees are made with regards to emulated entities. Effectively,
     * the state of emulated entities is considered undefined behavior upon
     * calling this function.
     *
     * @note Thread-safe
     */
    void RequestStop();

    /**
     * Runs the OS dispatcher. Does not return until all threads have exited.
     * @todo This currently seems to overlap with Run in terms of functionality, but ultimately we want to move the whole OS scheduler/dispatcher to this function.
     */
//    void StartScheduler(boost::coroutines::symmetric_coroutine<void>::yield_type& yield);

    void EnterExecutionLoop();
    void ElapseTime(std::chrono::nanoseconds time);
    void Reschedule(std::shared_ptr<Thread> thread);
    void RescheduleImmediately(std::shared_ptr<Thread> thread);
    void TriggerThreadDestruction(std::shared_ptr<Thread>);

    /**
     * @pre The given thread must be the one currently running.
     */
    void SwitchToSchedulerFromThread(Thread& thread);

    std::vector<std::shared_ptr<Thread>> GetThreadList() const;

    // TODO: This should eventually become SVCOpenProcess
    std::shared_ptr<Process> GetProcessFromId(ProcessId proc_id) /*const*/;

    /**
     * Translate an IPC message (i.e. a request or a reply) from the source
     * thread to the destination thread.
     */
    void TranslateIPCMessage(Thread& source, Thread& dest, bool is_reply);

    uint64_t GetTimeInNanoSeconds() const;

    /**
     * Signalize all events that are bound to the given interrupt
     */
    void NotifyInterrupt(uint32_t index) override;

    void OnResourceReady(ObserverSubject& resource);
};

const OS::Result RESULT_OK = 0;

template<typename... Results, typename... Args, typename... Args2>
auto FakeThread::CallSVC(SVCFuture<Results...> (OS::*svc_func)(Args2...), Args&&... args) {
    if constexpr (std::is_same_v<decltype(svc_func), decltype(&OS::SVCBreak)>) {
        if (svc_func == &OS::SVCBreak) {
            // Throw immediately rather than switching to the OS coroutine and throwing from there.
            // This makes error location much easier, since a debugger cannot print a relevant backtrace elsewhere.
            throw std::runtime_error("Called SVCBreak");
        }
    }

    SVCFuture<Results...> future;
    callback_for_svc = [&future, svc_func, &args...](std::shared_ptr<Thread> thread) {
        // Care must be taken when writing the result here. If we processed SVCExitThread (or similar), the outer context won't be valid anymore. Hence the result is stored externally in result_storage_for_svc
        auto new_future = (thread->GetOS().*svc_func)(*std::static_pointer_cast<FakeThread>(thread), args...);
        if (thread->status != Thread::Status::Stopped) {
            future = std::move(new_future);
        }
    };

    // Bounce between the OS dispatcher and the OS thread to execute callbacks
    do {
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

    auto TransformTuple = [this](auto&&... args) {
        auto Lookup = [this](auto arg) {
            if constexpr (std::is_same_v<PromisedWakeIndex, decltype(arg)>) {
                return wake_index;
            } else if constexpr (std::is_same_v<PromisedResult, decltype(arg)>) {
                return promised_result;
            } else {
                return arg;
            }
        };
        return std::make_tuple(Lookup(args)...);
    };
    return std::apply(TransformTuple, *future.data);
}

inline std::string GetThreadObjectName(Thread& thread) {
    return thread.GetName();
}

/// Utility structure to wrap a Process in a printable object
struct ProcessPrinter {
    Process& process;
};

/// Utility structure to wrap a Thread in a printable object
struct ThreadPrinter {
    Thread& thread;
};

/// Utility structure to wrap an Object reference in a printable object
struct ObjectRefPrinter {
    Object& object;
};

/// Utility structure to wrap an std::shared_ptr<Object> in a printable object
struct ObjectPrinter {
    const std::shared_ptr<Object>& object_ptr;
};

/// Utility structure to wrap a kernel handle in a printable object
struct HandlePrinter {
    Thread& thread;
    Handle handle;
};

std::ostream& operator<<(std::ostream& os, const ProcessPrinter& printer);
std::ostream& operator<<(std::ostream& os, const ThreadPrinter& printer);
std::ostream& operator<<(std::ostream& os, const ObjectRefPrinter& printer);
std::ostream& operator<<(std::ostream& os, const ObjectPrinter& printer);
std::ostream& operator<<(std::ostream& os, const HandlePrinter& printer);

}  // namespace OS

}  // namespace HLE

template <> struct fmt::formatter<HLE::OS::ProcessPrinter> : ostream_formatter {};
template <> struct fmt::formatter<HLE::OS::ThreadPrinter> : ostream_formatter {};
template <> struct fmt::formatter<HLE::OS::ObjectRefPrinter> : ostream_formatter {};
template <> struct fmt::formatter<HLE::OS::ObjectPrinter> : ostream_formatter {};
template <> struct fmt::formatter<HLE::OS::HandlePrinter> : ostream_formatter {};

// Now that we're done with the definitions, include some definitions that are required to instantiate the above structs (e.g. due to unique_ptr being used on incomplete types)
#include "gdb_stub.h"
