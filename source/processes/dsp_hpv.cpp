#include "dsp_hpv.hpp"
#include "os_hypervisor_private.hpp"
#include "os.hpp"
#include <ui/audio_frontend.hpp>

#include <platform/dsp.hpp>

#include <framework/exceptions.hpp>

#include <fmt/ranges.h>

namespace HLE {

namespace OS {

namespace HPV {

namespace {

struct DspService : SessionToPort {
    // Offsets to the typical
    std::vector<uint16_t> struct_offsets;

    // The DSP pipe is typically read exactly twice: Once to get the number of struct offsets, and once to read them
    enum class PipeReadState {
        Reset,
        Incomplete,
        Finished
    } pipe_read_state;

    DspService(RefCounted<Port> port_, DSPContext& context_) : SessionToPort(port_, context_) {
    }

    DSPContext& GetContext() {
        return static_cast<DSPContext&>(context);
    }

    void OnRequest(Hypervisor& hypervisor, Thread& thread, Handle session) override {
        using namespace Platform::CTR::DSP;

        const uint32_t command_header = thread.ReadTLS(0x80);
        auto dispatcher = RequestDispatcher<> { thread, *this, command_header };

        using ReadPipe = IPC::IPCCommand<0xe>::add_uint32::add_uint32::add_uint32::response::add_uint32::add_static_buffer;

        dispatcher.DecodeRequest<WriteProcessPipe>([&](auto&, uint32_t channel, uint32_t num_bytes, IPC::StaticBuffer) {
            auto description = fmt::format( "WriteProcessPipe, channel={}, num_bytes={:#x}",
                                            channel, num_bytes);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<ReadPipe>([&](auto& response, uint32_t channel, uint32_t peer, uint32_t num_bytes) {
            auto description = fmt::format( "ReadPipe, channel={}, num_bytes={:#x} from {}",
                                            channel, num_bytes, peer == 0 ? "DSP" : peer == 1 ? "ARM" : "unknown peer");
            Session::OnRequest(hypervisor, thread, session, description);

            response.OnResponse([this](Hypervisor&, Thread& thread, Result result, uint32_t num_bytes_read, IPC::StaticBuffer data) {
                if (result != RESULT_OK || !num_bytes_read) {
                    throw std::runtime_error("Unexpected error in ReadPipe");
                }

                OnPipeRead(thread, num_bytes_read, data);
            });
        });

        dispatcher.DecodeRequest<ReadPipeIfPossible>([&](auto& response, uint32_t channel, uint32_t peer, uint32_t num_bytes) {
            auto description = fmt::format( "ReadPipeIfPossible, channel={}, num_bytes={:#x} from {}",
                                            channel, num_bytes, peer == 0 ? "DSP" : peer == 1 ? "ARM" : "unknown peer");
            Session::OnRequest(hypervisor, thread, session, description);


            response.OnResponse([this](Hypervisor&, Thread& thread, Result result, uint32_t num_bytes_read, IPC::StaticBuffer data) {
                if (result != RESULT_OK || !num_bytes_read) {
                    throw std::runtime_error("Unexpected error in ReadPipeIfPossible");
                }

                OnPipeRead(thread, num_bytes_read, data);
            });
        });

        dispatcher.DecodeRequest<LoadComponent>([&](auto&, uint32_t size, uint32_t program_mask, uint32_t data_mask, IPC::MappedBuffer data) {
            auto description = fmt::format( "LoadComponent, size={:#x}, program_mask={:#x}, data_mask={:#x}",
                                            size, program_mask, data_mask);
            Session::OnRequest(hypervisor, thread, session, description);

            std::array<uint8_t, 0x100> signature;
            for (unsigned i = 0; i < signature.size(); ++i) {
                signature[i] = thread.ReadMemory(data.addr + i);
            }

            pipe_read_state = PipeReadState::Reset;
        });

        dispatcher.DecodeRequest<RegisterInterruptEvents>([&](auto&, uint32_t interrupt, uint32_t pipe, Handle event_handle) {
            auto description = fmt::format("RegisterInterruptEvents: interrupt={}, pipe={}", interrupt, pipe);
            Session::OnRequest(hypervisor, thread, session, description);

            if (interrupt != 2 || pipe != 2) {
//                throw Mikage::Exceptions::NotImplemented("Unknown DSP interrupt/pipe");
return;
            }

            // Handle may be null to unregister the event on shutdown
            if (event_handle != HANDLE_INVALID) {
                hypervisor.SetObjectTag(thread, event_handle, "DSPInterruptEvent");
            }
        });

        dispatcher.DecodeRequest<GetSemaphoreEventHandle>([&](auto& response) {
            Session::OnRequest(hypervisor, thread, session, "GetSemaphoreEventHandle");

            response.OnResponse([](Hypervisor& hv, Thread& thread, Result result, Handle event_handle) {
                hv.SetObjectTag(thread, event_handle, "DSPSemaphoreEvent");
            });
        });
    }

    void OnPipeRead(Thread& thread, uint32_t num_bytes_read, IPC::StaticBuffer data) {
        switch (pipe_read_state) {
        case PipeReadState::Reset:
            // First 16 bits read are the number of structure offsets read after
            if (num_bytes_read != 2) {
                throw Mikage::Exceptions::Invalid("Unexpected number of DSP pipe bytes read");
            }

            struct_offsets.resize(thread.ReadMemory(data.addr) | (uint16_t { thread.ReadMemory(data.addr + 1) } << 8));
            pipe_read_state = PipeReadState::Incomplete;

            break;

        case PipeReadState::Incomplete:
            // Read structure offset (typically 15 of them)
            if (num_bytes_read != struct_offsets.size() * sizeof(uint16_t)) {
                throw Mikage::Exceptions::Invalid("Unexpected number of DSP pipe bytes read");
            }

            for (uint32_t offset = 0; offset < num_bytes_read; offset += 2) {
                struct_offsets[offset / 2] = thread.ReadMemory(data.addr + offset) | (uint16_t { thread.ReadMemory(data.addr + offset + 1) } << 8);
            }
            pipe_read_state = PipeReadState::Finished;

            break;

        default:
            throw Mikage::Exceptions::Invalid("Unexpected read of DSP pipe after finished initialization");
        }
    }

    void OnDSPSemaphoreEventSignaled(Thread& thread) {
        if (pipe_read_state != PipeReadState::Finished) {
            throw Mikage::Exceptions::Invalid("Signaled DSP semaphore event before finishing initialization");
        }
        fprintf(stderr, "DSP DSP DSP:::::::::: SEMAPHORE\n");

        auto read_u8s = [&thread](VAddr addr) -> std::pair<uint8_t, uint8_t> {
            addr = addr * 2 + 0x1ff40000;
            return std::make_pair(thread.ReadMemory(addr), thread.ReadMemory(addr + 1));
        };
        auto read_u16 = [&thread](VAddr addr) -> uint16_t {
            addr = addr * 2 + 0x1ff40000;
            return thread.ReadMemory(addr) | (uint16_t { thread.ReadMemory(addr + 1) } << 8);
        };
        auto read_u32 = [&thread](VAddr addr) -> uint32_t {
            addr = addr * 2 + 0x1ff40000;
            return thread.ReadMemory(addr) | (uint32_t { thread.ReadMemory(addr + 1) } << 8) | (uint32_t { thread.ReadMemory(addr + 2) } << 16) | (uint32_t { thread.ReadMemory(addr + 3) } << 24);
        };

        fprintf(stderr, "  Frame count: %d\n", read_u16(struct_offsets[0]));
        {
            auto offset = struct_offsets[2];
            auto [enabled, dirty] = read_u8s(offset);
            fprintf(stderr, "  Input status: %s%s\n", enabled ? "enabled" : "disabled", dirty ? ", dirty" : "");
            fprintf(stderr, "    Sync count: %d\n", read_u16(offset + 1));
            fprintf(stderr, "    Position:   %d\n", read_u32(offset + 2));
            fprintf(stderr, "    Buffer id:  %d\n", read_u16(offset + 4));
        }
    }
};

} // anonymous namespace

HPV::RefCounted<Object> CreateDspService(RefCounted<Port> port, DSPContext& context) {
    return HPV::RefCounted<Object>(new DspService(port, context));
}

} // namespace HPV

// TODO: Implement Hypervisor interfaces to hook into this properly
[[deprecated]] void OnDSPSemaphoreEventSignaled(Thread& thread, HPV::RefCounted<HPV::SessionToPort>& obj) {
    static_refcounted_cast<HPV::DspService>(obj)->OnDSPSemaphoreEventSignaled(thread);
}

} // namespace OS

} // namespace HLE
