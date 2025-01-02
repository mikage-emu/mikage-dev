#include "am_hpv.hpp"
#include "os_hypervisor_private.hpp"
#include "os.hpp"

#include <platform/am.hpp>
#include <fmt/ranges.h>

namespace HLE {

namespace OS {

namespace HPV {

namespace {

// Covers all am:* services
struct AmService : SessionToPort {
    AmService(RefCounted<Port> port_, AMContext& context_) : SessionToPort(port_, context_) {
    }

    void OnRequest(Hypervisor& hypervisor, Thread& thread, Handle session) override {
        using namespace Platform::AM;

        const uint32_t command_header = thread.ReadTLS(0x80);
        auto dispatcher = RequestDispatcher<> { thread, *this, command_header };

        dispatcher.DecodeRequest<GetNumPrograms>([&](auto&, uint32_t media_type) {
            auto description = fmt::format( "GetProgramList, media_type={}", media_type);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<GetProgramList>([&](auto&, uint32_t max_count, uint32_t media_type, IPC::MappedBuffer) {
            auto description = fmt::format( "GetProgramList, max_count={:#x}, media_type={}", max_count, media_type);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<GetProgramInfos>([&](auto&, uint32_t media_type, uint32_t max_count, IPC::MappedBuffer title_ids_buffer, IPC::MappedBuffer) {
            std::vector<uint64_t> title_ids;
            for (unsigned idx = 0; idx < max_count; ++idx) {
                uint64_t title_id = thread.ReadMemory32(title_ids_buffer.addr + idx * sizeof(uint64_t)) |
                                    (uint64_t { thread.ReadMemory32(title_ids_buffer.addr + idx * sizeof(uint64_t) + 4) } << 32u);
                title_ids.push_back(title_id);
            }
            auto description = fmt::format( "GetProgramInfos, media_type={}, max_count={:#x}, title_ids={{{:#x}}}",
                                            media_type, max_count, fmt::join(title_ids, ", "));
            Session::OnRequest(hypervisor, thread, session, description);
        });
    }
};

} // anonymous namespace

HPV::RefCounted<Object> CreateAmService(RefCounted<Port> port, AMContext& context) {
    return HPV::RefCounted<Object>(new AmService(port, context));
}

} // namespace HPV

} // namespace HOS

} // namespace HLE
