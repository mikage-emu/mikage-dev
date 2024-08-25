#include "ac_hpv.hpp"
#include "ipc.hpp"
#include "os_hypervisor_private.hpp"
#include "os.hpp"

#include <platform/ac.hpp>

#include <framework/exceptions.hpp>

namespace HLE::OS::HPV {

namespace {

struct AcService : SessionToPort {
    AcService(RefCounted<Port> port_, ACContext& context_) : SessionToPort(port_, context_) {
    }

    void OnRequest(Hypervisor& hypervisor, Thread& thread, Handle session) override {
        const uint32_t command_header = thread.ReadTLS(0x80);
        auto dispatcher = RequestDispatcher<> { thread, *this, command_header };

        namespace Cmd = Platform::AC;

        dispatcher.DecodeRequest<Cmd::SetClientVersion>([&](auto&, uint32_t version, ProcessId pid) {
            auto description = fmt::format( "SetClientVersion, version={:#x}, pid={}",
                                            version, pid);
            Session::OnRequest(hypervisor, thread, session, description);
        });
    }
};

} // anonymous namespace

HPV::RefCounted<Object> CreateAcService(RefCounted<Port> port, ACContext& context) {
    return HPV::RefCounted<Object>(new AcService(port, context));
}

} // namespace HLE::OS::HPV
