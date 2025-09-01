#include "os.hpp"
#include "os_hypervisor.hpp"
#include "os_hypervisor_private.hpp"

#include "processes/ac_hpv.hpp"
#include "processes/am_hpv.hpp"
#include "processes/cfg_hpv.hpp"
#include "processes/dsp_hpv.hpp"
#include "processes/fs_hpv.hpp"
#include "processes/ns_hpv.hpp"
#include "processes/sm_hpv.hpp"
#include "processes/ro_hpv.hpp"
#include "processes/soc_hpv.hpp"

#include <memory>

namespace HLE {

namespace OS {

namespace HPV {

void Session::OnRequest(Hypervisor& hv, Thread& from_thread, Thread& to_thread, Handle session) {
    client_thread = &from_thread;
    OnRequest(hv, to_thread, session);
    client_thread = nullptr;
}

void Session::OnRequest(Hypervisor& hv, Thread& to_thread, Handle session) {
    OnRequest(hv, to_thread, session, fmt::format("{:08x}", to_thread.ReadTLS(0x80)));
}

void Session::OnRequest(Hypervisor&, Thread& thread, Handle, std::string_view command_description) {
    thread.GetLogger()->info("IPC message from {} to {}: {}", client_thread->GetParentProcess().GetName(), Describe(), command_description);
}

// Empty context for unrecognized sessions
struct NullContext : SessionContext {
};

struct State {
    using HandleTable = std::unordered_map<Handle, HPV::RefCounted<HPV::Object>>;

    std::unordered_map<ProcessId, HandleTable> handle_tables;

    // TODO: Not actually needed anymore.
    std::vector<HPV::RefCounted<HPV::Port>> ports;

    HPV::NullContext null_context;
    HPV::ACContext ac_context;
    HPV::AMContext am_context;
    HPV::CFGContext cfg_context;
    HPV::DSPContext dsp_context;
    HPV::FSContext fs_context;
    HPV::SMContext sm_context;
    HPV::NSContext ns_context;
    HPV::ROContext ro_context;
    HPV::SOCContext soc_context;

    template<typename T>
    HPV::RefCounted<T> FindObject(ProcessId process, Handle handle) const {
        static_assert(std::is_base_of_v<HPV::Object, T>, "Given object type is not derived from HPV::Object");

        auto handle_table_it = handle_tables.find(process);
        if (handle_table_it == handle_tables.end()) {
            throw std::runtime_error("Precondition violated: No handles are registered for this process");
        }
        auto& handle_table = handle_table_it->second;

        auto object_it = handle_table.find(handle);
        if (object_it == handle_table.end()) {
            throw std::runtime_error(fmt::format("Precondition violated: Handle {:#x} is not registered", handle.value));
        }

        auto typed_object = HPV::dynamic_refcounted_cast<T>(object_it->second);
        if (!typed_object) {
            throw std::runtime_error("Precondition violated: Given handle is registered to an object that does not represent the given type");
        }

        return typed_object;
    }
};

}

Hypervisor::Hypervisor(Settings::Settings& settings, AudioFrontend& audio_frontend) : state(new HPV::State) {
    state->dsp_context.settings = &settings;
    state->dsp_context.frontend = &audio_frontend;
}

Hypervisor::~Hypervisor() = default;

void Hypervisor::OnPortCreated(ProcessId process, std::string_view port_name, Handle port_handle) {
    auto& handle_table = state->handle_tables[process];
    if (handle_table.count(port_handle)) {
        throw std::runtime_error("Precondition violated: A Port for this handle is already registered");
    }

    auto port = HPV::RefCounted(new HPV::NamedPort(port_name));
    state->ports.push_back(HPV::static_refcounted_cast<HPV::Port>(port));
    handle_table.emplace(port_handle, HPV::static_refcounted_cast<HPV::Object>(port));
}

namespace {

/**
 * Adapts service factories like CreateSMSrvService (taking SessionContext& as
 * second parameter) to a function taking an HPV::State instead. The required
 * SessionContext is looked up using the template parameter "Context"
 */
template<auto F, auto Context>
HPV::RefCounted<HPV::Object> WrapSessionFactory(HPV::RefCounted<HPV::Port> port, HPV::State& state) {
    return F(port, state.*Context);
}

using SessionFactoryType = std::add_pointer_t<HPV::RefCounted<HPV::Object>(HPV::RefCounted<HPV::Port>, HPV::State&)>;
using namespace std::string_view_literals;
std::unordered_map<std::string_view, SessionFactoryType> service_factory_map = {{
    { "ac:i"sv,     WrapSessionFactory<HPV::CreateAcService,      &HPV::State::ac_context> },
    { "ac:u"sv,     WrapSessionFactory<HPV::CreateAcService,      &HPV::State::ac_context> },

    { "am:app"sv,   WrapSessionFactory<HPV::CreateAmService,      &HPV::State::am_context> },
    { "am:net"sv,   WrapSessionFactory<HPV::CreateAmService,      &HPV::State::am_context> },
    { "am:sys"sv,   WrapSessionFactory<HPV::CreateAmService,      &HPV::State::am_context> },
    { "am:u"sv,     WrapSessionFactory<HPV::CreateAmService,      &HPV::State::am_context> },

    { "cfg:i"sv,    WrapSessionFactory<HPV::CreateCfgService,     &HPV::State::cfg_context> },
    { "cfg:s"sv,    WrapSessionFactory<HPV::CreateCfgService,     &HPV::State::cfg_context> },
    { "cfg:u"sv,    WrapSessionFactory<HPV::CreateCfgService,     &HPV::State::cfg_context> },

    { "dsp::DSP"sv, WrapSessionFactory<HPV::CreateDspService,     &HPV::State::dsp_context> },

    { "fs:USER"sv,  WrapSessionFactory<HPV::CreateFSUserService,  &HPV::State::fs_context> },
    { "fs:LDR"sv,   WrapSessionFactory<HPV::CreateFSLdrService,   &HPV::State::fs_context> },
    { "fs:REG"sv,   WrapSessionFactory<HPV::CreateFSRegService,   &HPV::State::fs_context> },
    { "srv:"sv,     WrapSessionFactory<HPV::CreateSMSrvService,   &HPV::State::sm_context> },
    { "srv:pm"sv,   WrapSessionFactory<HPV::CreateSMSrvPmService, &HPV::State::sm_context> },
    { "ns:s"sv,     WrapSessionFactory<HPV::CreateNSService,      &HPV::State::ns_context> },
    { "APT:S"sv,    WrapSessionFactory<HPV::CreateAPTService,     &HPV::State::ns_context> },

    { "ldr:ro"sv,   WrapSessionFactory<HPV::CreateRoService,      &HPV::State::ro_context> },

    { "soc:U"sv,    WrapSessionFactory<HPV::CreateSocService,     &HPV::State::soc_context> },
}};

HPV::RefCounted<HPV::Object> SessionFactory(HPV::State& state, HPV::RefCounted<HPV::Port> port) {
    auto name = port->Name();

    auto factory = service_factory_map.find(name);
    if (factory == service_factory_map.end()) {
        // Unrecognized service. Return default Session
        return HPV::RefCounted<HPV::Object>(new HPV::SessionToPort(port, state.null_context));
    }
    return (factory->second)(port, state);
}

} // anonymous namespace

void Hypervisor::OnConnectToPort(ProcessId process, std::string_view port_name, Handle session_handle) {
    auto& handle_table = state->handle_tables[process];
    if (handle_table.count(session_handle)) {
        throw std::runtime_error("Precondition violated: A Session for this handle is already registered");
    }

    auto port_it = std::find_if(state->ports.begin(), state->ports.end(), [=](auto& port) { return (port->Name() == port_name); });
    if (port_it == state->ports.end()) {
        throw std::runtime_error("No port with the name \"" + std::string { port_name } + "\" exists");
    }

    handle_table.emplace(session_handle, SessionFactory(*state, *port_it));
}

void Hypervisor::OnNewSession(ProcessId process, Handle port_handle, Handle session_handle) {
    auto& handle_table = state->handle_tables[process];
    if (handle_table.count(session_handle)) {
        throw std::runtime_error("Precondition violated: A Session for this handle is already registered");
    }

    auto port = state->FindObject<HPV::Port>(process, port_handle);

    handle_table.emplace(session_handle, SessionFactory(*state, port));
}

void Hypervisor::OnSessionCreated(ProcessId process, Handle session_handle) {
    auto& handle_table = state->handle_tables[process];
    if (handle_table.count(session_handle)) {
        throw std::runtime_error("Precondition violated: A Session for this handle is already registered");
    }

    // This is a placeholder Session: If there is other HPV that names it
    // (usually the response handler for the IPC command that caused this
    // session to be created, e.g. SM::SRV::RegisterService), we'll replace
    // it with a more specific type
    auto session = HPV::RefCounted(new HPV::UnnamedSession);
    handle_table.emplace(session_handle, HPV::static_refcounted_cast<HPV::Object>(session));
}

void Hypervisor::SetSessionObject(ProcessId process, Handle session_handle, HPV::Session* object) {
    auto session = state->FindObject<HPV::Session>(process, session_handle);
    session.ReplaceManagedObject(object);
}

void Hypervisor::SetPortName(ProcessId process, Handle port_handle, std::string_view port_name) {
    auto port = state->FindObject<HPV::Port>(process, port_handle);
    port.ReplaceManagedObject(new HPV::ServicePort(port_name));
}

void Hypervisor::OnHandleDuplicated(ProcessId source_process, Handle source_handle, ProcessId dest_process, Handle dest_handle) {
    auto& source_handle_table = state->handle_tables[source_process];
    auto session_it = source_handle_table.find(source_handle);
    if (session_it == source_handle_table.end()) {
        // We don't track all kinds of handles yet, so the given handle may not
        // have made it into our handle table in the first place.
        // Hence, this is not an error.
        return;
    }

    auto& dest_handle_table = state->handle_tables[dest_process];
    if (dest_handle_table.count(dest_handle)) {
        throw std::runtime_error("Precondition violated: A Session for this handle is already registered");
    }
    dest_handle_table.emplace(dest_handle, session_it->second);
}

void Hypervisor::OnHandleClosed(ProcessId process, Handle handle) {
    state->handle_tables[process].erase(handle);
}

void Hypervisor::OnIPCRequestFromTo(Thread& from_thread, Thread& to_thread, Handle session_handle) {
    auto session = state->FindObject<HPV::Session>(to_thread.GetParentProcess().GetId(), session_handle);

    // TODO: Verify command header against expectation

    session->OnRequest(*this, from_thread, to_thread, session_handle);
}

// TODO: Need to have the reply target argument back
void Hypervisor::OnIPCReplyFromTo(Thread& from_thread, Thread& to_thread, Handle session_handle) {
    auto session = state->FindObject<HPV::Session>(from_thread.GetParentProcess().GetId(), session_handle);

    if (session->hpv_ipc_callback) // TODO: Instead, put the callback into a well-defined state all the time!
        session->hpv_ipc_callback(*this, from_thread);
    session->hpv_ipc_callback = [](Hypervisor&, Thread&) {};

    // TODO: Verify response header against expectation
}

// TODO: Drop Thread parameter. Instead, add memory access interface for hypervisor
void Hypervisor::OnEventSignaled(Thread& thread, ProcessId process, Handle event_handle) {
//    // TODO: Should keep a list of shadow events that shadow services subscribe to

//    // For now, we just hardcode some DSP code
//    if (process != 17 || thread.GetProcessHandleTable().FindObject<Event>(event_handle)->GetName() != "DSPSemaphoreEvent") {
//        return;
//    }

//    // Look for DSP-side handle...
//    process = 25;
//    event_handle.value = 8;

//    for (auto& entry : state->handle_tables.at(process)) {
//        auto obj = dynamic_refcounted_cast<HPV::SessionToPort>(entry.second);
//        if (obj && obj->Describe() == "dsp::DSP") {
//            [[deprecated]] void OnDSPSemaphoreEventSignaled(Thread&, HPV::RefCounted<HPV::SessionToPort>&);
//            OnDSPSemaphoreEventSignaled(thread, obj);
//            return;
//        }
//    }

//    throw std::runtime_error("Could not find DSP port");
}


void Hypervisor::SetObjectTag(Thread& thread, Handle handle, std::string name) {
    auto object = thread.GetProcessHandleTable().FindObject<Object>(handle);
    assert(object);
    object->name = std::move(name);
}

#if 0
/**
 * todo.
 *
 * Gets the thread that sent the message. Note this function gets called before the IPC message is marshalled, so mixing up the threads will get us the wrong arguments!
 */
template<typename CommandParameterList, typename Func, typename Thread, typename... ExtraArgs>
static auto HandleIntrospection(Func handler, Thread& thread, ExtraArgs&&... args) {
    using TypeList = boost::mp11::mp_rename<CommandParameterList, std::tuple>;

//     if (thread.ReadTLS(0x80) != Command::request_header)
//         throw IPCError{thread.ReadTLS(0x80), 0xdeadbeef};
//
    // Read request data from TLS
    // TODO: Actually, we would prefer some sort of generate() algorithm instead of having to instantiate the TypeList for transformation.
    auto input_data = TransformTupleSequentially(IPC::TLSReader(thread), TypeList{});

    // Invoke request handler
    // TODO: Can we statically_assert the number of input parameters here?
    //       Note that the input function may be a lambda expression, which may
    //       be harder to introspect!
    // TODO: The following may perform implicit conversion of uint64_t
    //       parameters to uint32_t (or vice versa), hence it actually provides
    //       less compile-time safety that we would like it to, currently.
    // NOTE: bound_handler was initialized using hana::partial before, but
    //       that unfortunately captures variables by value (i.e. imperfectly),
    //       hence making it useless when trying to forward reference
    //       parameters.
    auto bound_handler = [&handler,&args...](auto&&... inputs) { return handler(std::forward<ExtraArgs>(args)..., inputs...); };
    return std::apply(bound_handler, input_data);
}

static std::unique_ptr<IPCMessage> APTInitialize(Thread& server, uint32_t app_id, uint32_t applet_attr) {
    server.GetLogger()->info("{}received Initialize with AppID={:#x}, AppletAttr={:#x}",
                             ThreadPrinter{server}, app_id, applet_attr);
    return nullptr;
}

std::unique_ptr<IPCMessage> Hypervisor::IntrospectIPCRequest(Thread& source, Thread& dest) {
    switch (dest.GetParentProcess().GetId()) {
    default:
        if (ProcessHasName(dest, "ns")) {
            namespace APT = Platform::NS::APT;
            if (source.ReadTLS(0x80) == APT::Initialize::request_header) {
                return HandleIntrospection<APT::Initialize::request_list>(APTInitialize, source, dest);
            } else {
                dest.GetLogger()->info("{}unrecognized IPC command with header {:#010x}",
                                        ThreadPrinter{dest}, source.ReadTLS(0x80));
                return nullptr;
            }
        } else if (ProcessHasName(dest, "gsp") || ProcessHasName(dest, "FakeGSP")) {
            namespace GSPGPU = Platform::GSP::GPU;
            if (source.ReadTLS(0x80) == GSPGPU::RegisterInterruptRelayQueue::request_header) {
                dest.GetLogger()->info("{}RegisterInterruptRelayQueue",
                                        ThreadPrinter{dest});
                auto interrupt_event = source.GetProcessHandleTable().FindObject<Event>({source.ReadTLS(0x8c)});
                assert(interrupt_event);
                interrupt_event->name = "GSPInterruptQueueEvent";
                return nullptr;
            } else {
                dest.GetLogger()->info("{}unrecognized IPC command with header {:#010x}",
                                        ThreadPrinter{dest}, source.ReadTLS(0x80));
                return nullptr;
            }
        } else {
            dest.GetLogger()->info("{}OSHPV: unrecognized IPC command with header {:#010x}, {}",
                                    ThreadPrinter{dest}, source.ReadTLS(0x80), dest.GetParentProcess().GetName());
            return nullptr;
        }
    };
}

void Hypervisor::IntrospectIPCReply(Thread& server, Thread& client, std::unique_ptr<HVIPCMessageTracker> request_data) {
    if (ProcessHasName(server, "ns")) {
        server.GetLogger()->info("bllaaaa {:#x}", client.ReadTLS(0x80));
        if (client.ReadTLS(0x80) == Platform::NS::APT::Initialize::request_header) {
            assert(server.ReadTLS(0x80) == Platform::NS::APT::Initialize::response_header);

            auto notification_event = server.GetProcessHandleTable().FindObject<Event>({server.ReadTLS(0x8c)});
            assert(notification_event);
            notification_event->name = "APTNotificationEvent";

            auto resume_event = server.GetProcessHandleTable().FindObject<Event>({server.ReadTLS(0x90)});
            assert(resume_event);
            resume_event->name = "APTResumeEvent";
        /*} else if (server.ReadTLS(0x80) == 0x00020043 && ProcessHasName(client, "menu")) {
            auto notification_event = server.GetProcessHandleTable().FindObject<Event>({server.ReadTLS(0x8c)});
            assert(notification_event);
            notification_event->name = "APTNotificationEvent";

            auto resume_event = server.GetProcessHandleTable().FindObject<Event>({server.ReadTLS(0x90)});
            assert(resume_event);
            resume_event->name = "APTResumeEvent"; */
        } else if (server.ReadTLS(0x80) == 0x000100c2 && ProcessHasName(client, "menu")) {
            auto apt_lock = server.GetProcessHandleTable().FindObject<Mutex>({server.ReadTLS(0x94)});
            assert(apt_lock);
            apt_lock->name = "APTLock";
        }
    } else if (ProcessHasName(server, "mcu")) {
        if (server.ReadTLS(0x80) == 0x000d0042 && ProcessHasName(client, "gsp")) {
            auto event = server.GetProcessHandleTable().FindObject<Event>({server.ReadTLS(0x8c)});
            assert(event);
            event->name = "MCU_GPUEvent";
        }
    }
}
#endif

} // namespace OS

} // namespace HLE
