#include "ns_hpv.hpp"
#include "loader/gamecard.hpp"
#include "os_hypervisor_private.hpp"
#include "os.hpp"

#include <platform/ns.hpp>

namespace HLE {

namespace OS {

namespace HPV {

namespace {

const char* ToString(Platform::NS::AppletPos pos) {
    using namespace Platform::NS;

    switch (pos) {
    case AppletPos::App:      return "App";
    case AppletPos::AppLib:   return "AppLib";
    case AppletPos::Sys:      return "Sys";
    case AppletPos::SysLib:   return "SysLib";
    case AppletPos::Resident: return "Resident";
    case AppletPos::AppLib2:  return "AppLib2";
    case static_cast<AppletPos>(0xff): return "None?"; // Observed by swkbd during initialization
    case static_cast<AppletPos>(0xffffffff): return "None?"; // Observed by ctrulib when switching to home menu
    default:                  throw std::runtime_error("Unknown AppletPos");
    }
}

struct AptService : SessionToPort {
    AptService(RefCounted<Port> port_, NSContext& context_) : SessionToPort(port_, context_) {
    }

    void OnRequest(Hypervisor& hypervisor, Thread& thread, Handle session) override {
        using namespace Platform::NS;

        const uint32_t command_header = thread.ReadTLS(0x80);
        auto dispatcher = RequestDispatcher<> { thread, *this, command_header };

        dispatcher.DecodeRequest<APT::GetLockHandle>([&](auto& response, uint32_t flags) {
            auto description = fmt::format( "GetLockHandle, flags={:#x}", flags);
            Session::OnRequest(hypervisor, thread, session, description);

            response.OnResponse([=](Hypervisor& hv, Thread& thread, Result result, AppletAttr attr, uint32_t /* power_button_state */, Handle lock_handle) {
                if (result != RESULT_OK) {
                    throw std::runtime_error("GetLockHandle failed");
                }

                hv.SetObjectTag(thread, lock_handle, fmt::format("APTLock_{:#x}", Meta::to_underlying(attr.pos()())));
            });
        });

        dispatcher.DecodeRequest<APT::Initialize>([&](auto& response, AppId app_id, AppletAttr attr) {
            auto description = fmt::format( "Initialize, app_id={:#x}, attr={:#x}",
                                            Meta::to_underlying(app_id), attr.value);
            Session::OnRequest(hypervisor, thread, session, description);

            response.OnResponse([=](Hypervisor& hv, Thread& thread, Result result, std::array<Handle, 2> event_handles) {
                if (result != RESULT_OK) {
                    throw std::runtime_error("Initialize failed");
                }

                hv.SetObjectTag(thread, event_handles[0], fmt::format("APTNotificationEvent_{:#x}", Meta::to_underlying(app_id)));
                hv.SetObjectTag(thread, event_handles[1], fmt::format("APTParameterReadyEvent_{:#x}", Meta::to_underlying(app_id)));
            });
        });

        dispatcher.DecodeRequest<APT::Enable>([&](auto&, AppletAttr attr) {
            auto description = fmt::format( "Enable, attr={:#x}", attr.value);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::GetAppletManInfo>([&](auto&, AppletPos pos) {
            auto description = fmt::format( "GetAppletManInfo, pos={}", ToString(pos));
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::GetAppletInfo>([&](auto&, AppId app_id) {
            auto description = fmt::format( "GetAppletInfo, app_id={:#x}", Meta::to_underlying(app_id));
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::IsRegistered>([&](auto&, AppId app_id) {
            auto description = fmt::format( "IsRegistered, app_id={:#x}", Meta::to_underlying(app_id));
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::SendParameter>([&](   auto&, AppId source, AppId target,
                                                            AppletCommand command, uint32_t data_size,
                                                            Handle /*handle*/, IPC::StaticBuffer /*data*/) {
            auto description = fmt::format( "SendParameter, source_app_id={:#x}, dest_app_id={:#x}, command={:#x}, data_size={:#x}",
                                            Meta::to_underlying(source), Meta::to_underlying(target), Meta::to_underlying(command), data_size);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::ReceiveParameter>([&](auto&, AppId target, uint32_t bytes_to_receive) {
            auto description = fmt::format( "ReceiveParameter, target_app_id={:#x}, buffer_size={:#x}",
                                            Meta::to_underlying(target), bytes_to_receive);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::GlanceParameter>([&](auto&, AppId target, uint32_t bytes_to_receive) {
            auto description = fmt::format( "GlanceParameter, target_app_id={:#x}, buffer_size={:#x}",
                                            Meta::to_underlying(target), bytes_to_receive);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::CancelParameter>([&](auto&, bool check_source, AppId source_app_id, uint32_t check_target, AppId target_app_id) {
            auto description = fmt::format( "CancelParameter, check_source={:#x}, source_app_id={:#x}, check_target={:#x}, target_app_id={:#x}",
                                            check_source, Meta::to_underlying(source_app_id),
                                            check_target, Meta::to_underlying(target_app_id));
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::PrepareToStartApplication>([&](auto&, const Platform::PXI::PM::ProgramInfo& program_info, uint32_t flags) {
            auto description = fmt::format( "PrepareToStartApplication, program_id={:#x} (media type {}), flags {:#x}",
                                            program_info.program_id, program_info.media_type, flags);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::FinishPreloadingLibraryApplet>([&](auto&, AppId app_id) {
            auto description = fmt::format( "FinishPreloadingLibraryApplet, app_id={:#x}",
                                            Meta::to_underlying(app_id));
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::PrepareToStartLibraryApplet>([&](auto&, AppId app_id) {
            auto description = fmt::format( "PrepareToStartLibraryApplet, app_id={:#x}",
                                            Meta::to_underlying(app_id));
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::StartLibraryApplet>([&](auto&, AppId app_id, uint32_t data_size, Handle /*handle*/, IPC::StaticBuffer /*data*/) {
            auto description = fmt::format( "StartLibraryApplet, app_id={:#x}, data_size={:#x}",
                                            Meta::to_underlying(app_id), data_size);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::PrepareToCloseApplication>([&](auto&, uint32_t cancel_preload) {
            auto description = fmt::format( "PrepareToCloseApplication, cancel_preload={:#x}", cancel_preload);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::PrepareToCloseLibraryApplet>([&](auto&, uint32_t unknown_flag, uint32_t caller_exiting, uint32_t jump_to_home) {
            auto description = fmt::format( "PrepareToCloseLibraryApplet, unknown_flag={:#x}, caller_exiting={:#x}, jump_to_home={:#x}",
                                            unknown_flag, caller_exiting, jump_to_home);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::CloseLibraryApplet>([&](auto&, uint32_t param_size, Handle /*handle*/, IPC::StaticBuffer /*data*/) {
            auto description = fmt::format( "CloseLibraryApplet, param_size={:#x}", param_size);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::PrepareToJumpToHomeMenu>([&](auto&) {
            auto description = fmt::format( "PrepareToJumpToHomeMenu");
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::JumpToHomeMenu>([&](auto&, uint32_t param_size, Handle /*handle*/, IPC::StaticBuffer /*data*/) {
            auto description = fmt::format( "JumpToHomeMenu, param_size={:#x}", param_size);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::StartApplication>([&](auto&, uint32_t param_size, uint32_t hmac_size,
                                                            uint32_t launch_paused, IPC::StaticBuffer /*param_buffer*/,
                                                            IPC::StaticBuffer /*hmac_buffer*/) {
            auto description = fmt::format( "StartApplication, param_size={:#x}, hmac_size={:#x}, paused={:#x}",
                                            param_size, hmac_size, launch_paused);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::SendCaptureBufferInfo>([&](auto&, uint32_t size, IPC::StaticBuffer /*buffer*/) {
            auto description = fmt::format( "SendCaptureBufferInfo, info_size={:#x}", size);
            // TODO: Print out the actual buffer
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::ReceiveCaptureBufferInfo>([&](auto&, uint32_t size) {
            auto description = fmt::format( "ReceiveCaptureBufferInfo, info_size={:#x}", size);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::NotifyToWait>([&](auto&, AppId app_id) {
            auto description = fmt::format( "NotifyToWait, app_id={:#x}", Meta::to_underlying(app_id));
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<APT::GetSharedFont>([&](auto&) {
            Session::OnRequest(hypervisor, thread, session, "GetSharedFont");
            // TODO: On response, check that the font has actually finished loading. Otherwise, recommend booting through Home Menu
        });
    }
};

struct NsService : SessionToPort {
    NsService(RefCounted<Port> port_, NSContext& context_) : SessionToPort(port_, context_) {
    }

    void OnRequest(Hypervisor& hypervisor, Thread& thread, Handle session) override {
        using namespace Platform::NS;

        const uint32_t command_header = thread.ReadTLS(0x80);
        auto dispatcher = RequestDispatcher<> { thread, *this, command_header };

        dispatcher.DecodeRequest<NS::LaunchTitle>([&](auto&, uint64_t title_id, uint32_t flags) {
            auto description = fmt::format( "LaunchTitle, title_id={:#x}, flags={:#x}", title_id, flags);
            Session::OnRequest(hypervisor, thread, session, description);
        });
        
        dispatcher.DecodeRequest<NS::CardUpdateInitialize>([&](auto& response, uint32_t shared_mem_size, Handle /* shared_mem */) {
            auto description = fmt::format( "CardUpdateInitialize, shared_mem_size={:#x}", shared_mem_size);
            Session::OnRequest(hypervisor, thread, session, description);
            
            // Disable card update process for 3DSX/CXI -> Gamecard adaptors
            auto gamecard = thread.GetOS().setup.gamecard.get();
            if (gamecard && (dynamic_cast<Loader::GameCardFrom3DSX*>(gamecard) != nullptr || dynamic_cast<Loader::GameCardFromCXI*>(gamecard) != nullptr)) {
                thread.WriteTLS(0x80, 0xFFFE0000); // make NS think a bogus command is sent
                
                response.OnResponse([=](Hypervisor& hv, Thread& thread, Result result) {
                    thread.WriteTLS(0x80, NS::CardUpdateInitialize::response_header);
                    thread.WriteTLS(0x84, 0xc821180b); // "No card update required"
                });
            }
        });
    }
};

} // anonymous namespace

HPV::RefCounted<Object> CreateAPTService(RefCounted<Port> port, NSContext& context) {
    return HPV::RefCounted<Object>(new AptService(port, context));
}

HPV::RefCounted<Object> CreateNSService(RefCounted<Port> port, NSContext& context) {
    return HPV::RefCounted<Object>(new NsService(port, context));
}

} // namespace HPV

} // namespace HOS

} // namespace HLE
