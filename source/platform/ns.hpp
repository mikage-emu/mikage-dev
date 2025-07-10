#pragma once

#include "ipc.hpp"
#include "pxi.hpp"

#include "framework/bit_field_new.hpp"

namespace Platform {

/**
 * Nintendo Shell: Responsible for managing programs currently running on
 * the system, as well as transition between active applications, and other
 * things.
 */
namespace NS {

enum class AppletPos : uint32_t {
    App      = 0, // Games and other applications launched from the Home Menu
    AppLib   = 1, // Applets (swkbd, appletEd, ...)
    Sys      = 2, // Home Menu
    SysLib   = 3,
    Resident = 4,
    AppLib2  = 5, // swkbd uses this during initialization, seems to act like AppLib and SysLib?

    None     = 0xffffffff,
};

struct AppletAttr {
    uint32_t value;

    auto pos() const { return v3::BitField::MakeFieldOn<0, 3, AppletPos>(this); }

    // If true, the applet must request GSP rights itself (via AcquireRights)
    auto no_automatic_gsp_handover() const { return v3::BitField::MakeFlagOn<3>(this); }

    // TODO: Bit 4 is similar to bit 3 but for DSP (?)

    auto is_menu() const { return v3::BitField::MakeFlagOn<29>(this); }

    static auto IPCDeserialize(uint32_t data) {
        return AppletAttr { data };
    }
    static auto IPCSerialize(AppletAttr data) {
        return std::make_tuple(static_cast<uint32_t>(data.value));
    }
};

enum class AppId : uint32_t {
    // Used by applications as a placeholder, e.g. when calling FinishPreloadingLibraryApplet
    Any              = 0x000,

    Menu             = 0x101,

    Application      = 0x300,

    SoftwareKeyboard = 0x401,
    MiiSelector      = 0x402,
    Error            = 0x406, // NOTE: This is a separate process from ErrDisp (the latter only hosts a thin service without any applets or user interface)
};

enum class AppletCommand : uint32_t {
    Wakeup         = 0x1,
    WakeupByExit   = 0xa,
    WakeupToJumpHome   = 0xf,
};

namespace NS {

namespace IPC = Platform::IPC;

using LaunchTitle = IPC::IPCCommand<0x2>::add_uint64::add_uint32
                       ::response::add_uint32;
                       
using CardUpdateInitialize = IPC::IPCCommand<0x7>::add_uint32::add_handle<IPC::HandleType::SharedMemoryBlock>
                                ::response;

} // namespace NS

namespace APT {

namespace IPC = Platform::IPC;

/**
 * Retrieves a mutex used to guard access to the given applet position.
 *
 * It's not fully understood what this mutex guards specifically.
 *
 * TODOTEST: Is there only one mutex or does each position get its own?
 *
 * Inputs:
 * - flags: Stores the applet position in the lower bits. Has unknown functionality in the other bits.
 *
 * Outputs:
 * - Attributes (not sure of what?)
 * - Power button state
 * - Mutex
 */
using GetLockHandle = IPC::IPCCommand<0x1>::add_uint32
                         ::response::add_serialized<AppletAttr>::add_uint32::add_handle<IPC::HandleType::Mutex>;

/**
 * Registers the given AppId for the specified position indicated by AppletAttr.
 *
 * Only one AppId may be registered for each applet position at a time.
 *
 * Outputs:
 * - Event handles: Signal for new notification (see InquireNotification), signal for new parameter (see ReceiveParameter)
 */
using Initialize = IPC::IPCCommand<0x2>::add_serialized<AppId>::add_serialized<AppletAttr>
                      ::response::add_handles<IPC::HandleType::Event, 2>;

/**
 * Notifies NS that the applet at the given position is now ready to be started
 */
using Enable = IPC::IPCCommand<0x3>::add_serialized<AppletAttr>
                  ::response;

using Finalize = IPC::IPCCommand<0x4>::add_serialized<AppId>
                    ::response;

/**
 * TODO: Does this indeed return the AppletPos or is it AppletAttr?
 */
using GetAppletManInfo = IPC::IPCCommand<0x5>::add_serialized<AppletPos>
                            ::response::add_serialized<AppletPos>::add_serialized<AppId>::add_serialized<AppId>::add_serialized<AppId>;

/**
 * Outputs:
 * - Program id corresponding to this app id
 * - Media type corresponding to this app id
 * - Is the app registered?
 * - Is the app loaded?
 * - Applet attributes
 *
 * Error codes:
 * - 0xc880cffa: Applet isn't registered (TODOTEST)
 */
using GetAppletInfo = IPC::IPCCommand<0x6>::add_serialized<AppId>
                    ::response::add_uint64::add_uint32::add_uint32::add_uint32::add_serialized<AppletAttr>;

/**
 * Queries whether an applet with the given id has been registered or not
 */
using IsRegistered = IPC::IPCCommand<0x9>::add_serialized<AppId>
                        ::response::add_uint32;

/**
 * Queries recently sent APT notifications
 */
using InquireNotification = IPC::IPCCommand<0xb>::add_serialized<AppId>
                               ::response::add_uint32;

/**
 * Inputs:
 * - Source app id (sender)
 * - Target app id (receiver)
 * - Command
 * - Size of user-provided data
 * - User-provided handle (may be 0 if not needed)
 * - User-provided data buffer (up to 0x1000 bytes)
 *
 * TODO: Does the handle indeed get copied or does it get moved?
 */
using SendParameter = IPC::IPCCommand<0xc>::add_serialized<AppId>::add_serialized<AppId>::add_serialized<AppletCommand>::add_uint32::add_handle<IPC::HandleType::Object>::add_static_buffer
                         ::response;

/**
 * Inputs:
 * - App id of the receiving app
 * - Maximum number of bytes to receive in the parameter data buffer
 *
 * Outputs:
 * - App id of the sending app
 * - Command
 * - Number of bytes received in the parameter data buffer
 * - Parameter data
 * - Parameter object handle (may be null)
 */
using ReceiveParameter = IPC::IPCCommand<0xd>::add_serialized<AppId>::add_uint32
                            ::response::add_serialized<AppId>::add_serialized<AppletCommand>::add_uint32::add_and_close_handle<IPC::HandleType::Object>::add_static_buffer;

/**
 * Like ReceiveParameter, but leaves the parameter in the queue so that
 * successive calls to Receive/GlanceParameter can still read it
 */
using GlanceParameter = IPC::IPCCommand<0xe>::add_serialized<AppId>::add_uint32
                            ::response::add_serialized<AppId>::add_serialized<AppletCommand>::add_uint32::add_handle<IPC::HandleType::Object>::add_static_buffer;

using CancelParameter = IPC::IPCCommand<0xf>::add_uint32::add_serialized<AppId>::add_uint32::add_serialized<AppId>
                        ::response::add_uint32;

/**
 * Inputs:
 * - ProgramInfo of the application to launch. Program ID may be 0, in which case behavior is unknown
 * - Unknown flags
 */
using PrepareToStartApplication = IPC::IPCCommand<0x15>::add_serialized<PXI::PM::ProgramInfo>::add_uint32
                                         ::response;

/**
 * Launches the title corresponding to this AppId if necessary
 *
 * TODO: Not sure what the difference between this and PrepareToStartLibraryApplet is
 */
using PreloadLibraryApplet = IPC::IPCCommand<0x16>::add_serialized<AppId>
                                ::response;

using FinishPreloadingLibraryApplet = IPC::IPCCommand<0x17>::add_serialized<AppId>
                                         ::response;

/**
 * Launches the title corresponding to this AppId if necessary
 */
using PrepareToStartLibraryApplet = IPC::IPCCommand<0x18>::add_serialized<AppId>
                                       ::response;

/**
 * Inputs:
 * - Size of parameter to send to the started application
 * - HMAC size
 * - 1 to launch paused, 0 to run immediately
 * - Parameter to send to the started application
 * - HMAC
 */
using StartApplication = IPC::IPCCommand<0x1b>::add_uint32::add_uint32::add_uint32::add_static_buffer::add_static_buffer
                            ::response;

/**
 * Inputs:
 * - AppId to start
 * - Size of startup parameter data
 * - Startup parameter handle
 * - Startup parameter data
 */
using StartLibraryApplet = IPC::IPCCommand<0x1e>::add_serialized<AppId>::add_uint32::add_handle<IPC::HandleType::Object>::add_static_buffer
                              ::response;

using PrepareToCloseApplication = IPC::IPCCommand<0x22>::add_uint32
                                     ::response;

/**
 * Inputs:
 * - Whether to stop (1) or pause (0) the applet
 * - If 1, indicates to the applet that the calling application is closing
 * - If 1, indicates to the applet that a switch to the Home Menu is requested
 */
using PrepareToCloseLibraryApplet = IPC::IPCCommand<0x25>::add_uint32::add_uint32::add_uint32
                                       ::response;

/**
 * Inputs:
 * - Size of user-provided data
 * - User-provided handle (may be 0 if not needed)
 * - User-provided data buffer (up to 0x1000 bytes)
 *
 * TODO: Does the handle indeed get copied or does it get moved?
 */
using CloseLibraryApplet = IPC::IPCCommand<0x28>::add_uint32::add_handle<IPC::HandleType::Object>::add_static_buffer
                              ::response;

using PrepareToJumpToHomeMenu = IPC::IPCCommand<0x2b>
                                   ::response;

/**
 * Inputs:
 * - Size of startup parameter data
 * - Parameter handle
 * - Parameter data
 */
using JumpToHomeMenu = IPC::IPCCommand<0x2c>::add_uint32::add_handle<IPC::HandleType::Object>::add_static_buffer
                          ::response;

/**
 * Inputs:
 * - Buffer size
 * - Buffer data
 */
using SendCaptureBufferInfo = IPC::IPCCommand<0x40>::add_uint32::add_static_buffer
                                 ::response;

using ReceiveCaptureBufferInfo = IPC::IPCCommand<0x41>::add_uint32
                                 ::response::add_uint32::add_static_buffer;

using NotifyToWait = IPC::IPCCommand<0x43>::add_serialized<AppId>
                        ::response;

/**
 * Outputs:
 * - Virtual address in the LINEAR range to which the shared font is mapped
 * - Shared memory block containing font data in BCFNT format
 */
using GetSharedFont = IPC::IPCCommand<0x44>
                         ::response::add_uint32::add_handle<IPC::HandleType::SharedMemoryBlock>;

using AppletUtility = IPC::IPCCommand<0x4b>::add_uint32::add_uint32::add_uint32::add_static_buffer
                         ::response::add_uint32;

using SetScreencapPostPermission = IPC::IPCCommand<0x55>::add_uint32
                                      ::response;
using CheckNew3DS = IPC::IPCCommand<0x102>
                       ::response::add_uint32;

} // namespace APT

} // namespace NS

} // namespace Platform
