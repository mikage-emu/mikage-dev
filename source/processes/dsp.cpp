#include "dsp.hpp"
#include "os.hpp"

#include "../platform/dsp.hpp"
#include <platform/file_formats/dsp1.hpp>

#include <framework/exceptions.hpp>


#include <teakra/teakra.h>
extern Teakra::Teakra* g_teakra; // TODO: Remove



using namespace Platform::CTR::DSP;

namespace HLE {

namespace OS {

// TODO: Use virtual addresses instead
// const VAddr dsp_mmio = 0x1ed03000;
const PAddr dsp_mmio = 0x10103000;

// "Pipes" are data areas in DSP memory shared between this module and the client application.
// There are 4 pipes in total, each of which have two SubPipeInfo headers for the two sides of communication (DSP->ARM11 and ARM11->DSP).
// The read/write cursors range from 0 to num_bytes and wrap around. The 16th bit can be considered an iteration count.
struct SubPipeInfo {
    struct Cursor {
        BOOST_HANA_DEFINE_STRUCT(Cursor,
            (uint16_t, storage)
        );

        auto value() const { return BitField::v3::MakeFieldOn<0, 15>(this); }

        auto iteration() const { return BitField::v3::MakeFieldOn<15, 1>(this); }
    };

    BOOST_HANA_DEFINE_STRUCT(SubPipeInfo,
        (uint16_t, pipe_offset_words), // offset to pipe data in 16-bit words
        (uint16_t, num_bytes),         // size of pipe data in bytes
        (Cursor, read_cursor),         // read offset within pipe data
        (Cursor, write_cursor),        // write offset within pipe data
        (uint8_t, subpipe_index),      // 0: Pipe 0 to ARM11, 1: Pipe 0 to DSP, 0: Pipe 1 to ARM11, ...
        (uint8_t, unknownflags)
    );

    uint16_t GetWritableBytesUntilWrap() const {
        return num_bytes - write_cursor.value();
    }

    uint16_t GetReadableBytesUntilWrap() const {
        return std::min<uint16_t>(CursorDistance(), num_bytes - read_cursor.value());
    }

    uint16_t CursorDistance() const {
        auto ret = write_cursor.value() - read_cursor.value();
        if (write_cursor.iteration() == read_cursor.iteration()) {
            if (write_cursor.value() < read_cursor.value()) {
                throw Mikage::Exceptions::Invalid("Read cursor for DSP pipe overlaps write cursor");
            }
        } else {
            if (write_cursor.value() > read_cursor.value() || read_cursor.value() - write_cursor.value() > num_bytes) {
                throw Mikage::Exceptions::Invalid("Write cursor for DSP pipe overlaps read cursor");
            }

            ret += num_bytes;
        }
        return ret;
    }

    uint16_t GetWritableBytes() const {
        return num_bytes - CursorDistance();
    }

    // TODO: Use this somewhere
    void ValidateInvariants() const {
        (void)CursorDistance(); // Should pass fine

        if (read_cursor.value() > num_bytes) {
            throw Mikage::Exceptions::Invalid("Read cursor out of bounds");
        }
        if (write_cursor.value() > num_bytes) {
            throw Mikage::Exceptions::Invalid("Write cursor out of bounds");
        }
    }

    void MoveCursor(Cursor& cursor, uint16_t offset) const {
        uint32_t new_value = uint32_t { cursor.value() } + offset;
        bool new_iteration = cursor.iteration();
        if (uint32_t { cursor.value() } + offset >= num_bytes) {
            new_value -= num_bytes;
            new_iteration = !new_iteration;
        }
        cursor = cursor.iteration()(new_iteration).value()(new_value);
    }

    bool IsEmpty() const {
        return read_cursor.storage == write_cursor.storage;
    }

    bool IsFull() const {
        return CursorDistance() == num_bytes;
    }

    // Index for data written by the DSP for read-out by ARM11
    static uint8_t IndexToARM11(uint8_t pipe_index) {
        return pipe_index * 2;
    }

    // Index for data written by ARM11 for read-out by the DSP
    static uint8_t IndexToDSP(uint8_t pipe_index) {
        return pipe_index * 2 + 1;
    }
};

FakeDSP::FakeDSP(FakeThread& thread)
    : os(thread.GetOS()),
      logger(*thread.GetLogger()) {

    static_buffer_addr = thread.GetParentProcess().AllocateStaticBuffer(0x20);
    thread.WriteTLS(0x188, IPC::TranslationDescriptor::MakeStaticBuffer(0, 0x20).raw);
    thread.WriteTLS(0x18c, static_buffer_addr);

    pipe_address = thread.GetParentProcess().AllocateStaticBuffer(0x20);
    thread.WriteTLS(0x180, IPC::TranslationDescriptor::MakeStaticBuffer(0, 0x20).raw);
    thread.WriteTLS(0x184, pipe_address);

    // TODO: These should actually both be sticky events
    Result result;
    HandleTable::Entry<Event> semaphore_event_entry;
    std::tie(result, semaphore_event_entry) = thread.CallSVC(&OS::SVCCreateEvent, ResetType::OneShot);
    ValidateContract(result == RESULT_OK);
    semaphore_event = semaphore_event_entry.first;
    semaphore_event_entry.second->name = "DSPSemaphoreEvent";

    HandleTable::Entry<Event> interrupt_event_entry;
    std::tie(result, interrupt_event_entry) = thread.CallSVC(&OS::SVCCreateEvent, ResetType::OneShot);
    ValidateContract(result == RESULT_OK);
    interrupt_event_new = interrupt_event_entry.first;
    interrupt_event_entry.second->name = "DSPInterruptEvent";

// // TODO: Re-enable
    std::tie(result) = thread.CallSVC(&OS::SVCBindInterrupt, 0x4a, interrupt_event_entry.second, 4, 1);
    ValidateContract(result == RESULT_OK);

    ServiceHelper service;
    service.Append(ServiceUtil::SetupService(thread, "dsp::DSP", 4));
    service.Append(interrupt_event_entry);
    service.Append(semaphore_event_entry);

    auto InvokeCommandHandler = [&](FakeThread& thread, uint32_t index) {
        Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
        auto signalled_handle = service.handles[index];
        if (signalled_handle == interrupt_event_new) {
            // TODO: Probably needs to be more sophisticated...
            fprintf(stderr, "DSP INTERRUPT 0x4a handler\n");

            const auto dsp_status_reg = Memory::ReadLegacy<uint16_t>(os.setup.mem, dsp_mmio + 0xc);
            /*const */bool channel2_has_data = (dsp_status_reg & (1 << 12));

            if (!channel2_has_data) {
                fprintf(stderr, "WARNING: DSP interrupt signaled, but channel 2 has no data\n");
//                throw Mikage::Exceptions::Invalid("DSP interrupt signaled, but channel 2 has no data");
                channel2_has_data = true;
            }

            if (channel2_has_data && channel_event != HANDLE_INVALID) {
                logger.info("{} signalling DSP reply received event {} for channel 2", ThreadPrinter{thread}, HandlePrinter{thread, channel_event});
                thread.CallSVC(&OS::SVCSignalEvent, channel_event);
            }

            return ServiceHelper::DoNothing;
        } else if (signalled_handle == semaphore_event) {
            Memory::WriteLegacy<uint16_t>(os.setup.mem, dsp_mmio + 0x10, semaphore_mask);
            return ServiceHelper::DoNothing;
        } else {
            OnIPCRequest(thread, signalled_handle, header);
            return ServiceHelper::SendReply;
        }
    };

    service.Run(thread, std::move(InvokeCommandHandler));
}

std::tuple<OS::Result>
FakeDSP::HandleWriteProcessPipe(FakeThread& thread, uint32_t pipe_index, uint32_t num_bytes, IPC::StaticBuffer buffer) {
    auto buffer_addr = buffer.addr;

    // TODO: Assert num_bytes is non-zero and smaller/equal than the buffer size

    // TODO: Move to common code
    struct {
        Thread& thread;
        VAddr addr;

        void operator()(char* dest, size_t size) {
            for (auto data_ptr = dest; data_ptr != dest + size; ++data_ptr) {
                *data_ptr = thread.ReadMemory(addr++);
            }
        }
    } reader { thread, static_cast<VAddr>(pipe_info_base + SubPipeInfo::IndexToDSP(pipe_index) * sizeof(SubPipeInfo)) };

    SubPipeInfo pipe = FileFormat::SerializationInterface<SubPipeInfo>::Load(reader);

    logger.info("Pipe {} to DSP with cursors [{:#x}, {:#x}] from {:#x}-{:#x}",
                pipe_index, pipe.read_cursor.value()(), pipe.write_cursor.value()(),
                pipe_info_base + 2 * pipe.pipe_offset_words,
                pipe_info_base + 2 * pipe.pipe_offset_words + pipe.num_bytes);

    if (pipe.subpipe_index != SubPipeInfo::IndexToDSP(pipe_index)) {
        throw Mikage::Exceptions::Invalid("Invalid DSP pipe header {}<->{}", pipe.subpipe_index, SubPipeInfo::IndexToDSP(pipe_index));
    }

    while (num_bytes > 0) {
        if (pipe.IsFull() || num_bytes > pipe.GetWritableBytes()) {
            throw Mikage::Exceptions::NotImplemented("Cannot flush partial pipe writes");
        }

        uint16_t chunk_size = std::min<uint16_t>(num_bytes, pipe.GetWritableBytesUntilWrap());
        logger.info("  Writing {:#x} bytes of data at write cursor {:#x} (iteration {})", chunk_size, pipe.write_cursor.value()(), pipe.write_cursor.iteration()());
        for (uint32_t offset = 0; offset < chunk_size; ++offset) {
//                fprintf(stderr, "Wrong target address! Should refer to teakra's DSP memory instead\n");
//                throw std::runtime_error("Wrong target address! Should refer to teakra's DSP memory instead");
//                thread.WriteMemory( pipe_info_base + 2 * pipe.pipe_offset_words + pipe.write_cursor.value() + offset,
//                                    thread.ReadMemory(buffer_addr + offset));

            auto val = thread.ReadMemory(buffer_addr + offset);
            if (num_bytes == 4 && offset >= 2) {
                // NOTE: Apparently actual DSP does this? Without it, launching titles from HOME Menu fails
                // TODO: This is not the full workaround, see Citra.
                val = 0;
            }
            // TODO: Write via virtual memory instead
            g_teakra->GetDspMemory()[/*pipe_info_base*/0x40000 + 2 * pipe.pipe_offset_words + pipe.write_cursor.value() + offset] = val;
        }
        num_bytes -= chunk_size;
        buffer_addr += chunk_size;
        pipe.MoveCursor(pipe.write_cursor, chunk_size);
    }

    // Write back SubPipeInfo to memory
    // TODO: Only need to write back the read/write cursors...
    struct Writer {
        Thread& thread;
        VAddr addr;

        void operator()(char* data, size_t size) {
            for (auto data_ptr = data; data_ptr != data + size; ++data_ptr) {
                thread.WriteMemory(addr++, *data_ptr);
            }
        }
    } writer { thread, static_cast<VAddr>(pipe_info_base + SubPipeInfo::IndexToDSP(pipe_index) * sizeof(SubPipeInfo)) };
    FileFormat::SerializationInterface<SubPipeInfo>::Save(pipe, writer);

    // Notify DSP to process data
    const auto dsp_status_reg = Memory::ReadLegacy<uint16_t>(os.setup.mem, dsp_mmio + 0xc);
    if ((dsp_status_reg & (1 << 15)) == 1) {
        throw Mikage::Exceptions::NotImplemented("WriteProcessPipe: Must wait for pending DSP writes");
    }
    // Send subpipe index to DSP channel 2
    Memory::WriteLegacy<uint16_t>(os.setup.mem, dsp_mmio + 0x30, pipe.subpipe_index);

    return std::make_tuple(RESULT_OK);
}

std::tuple<OS::Result,uint32_t,IPC::StaticBuffer>
FakeDSP::HandleReadPipeIfPossible(FakeThread& thread, uint32_t pipe_index, uint32_t direction, uint32_t num_bytes) {
// TODO: wait for dsp status?

    if (direction != 0) {
        fprintf(stderr, "ERROR: %d\n", __LINE__);
        throw Mikage::Exceptions::Invalid("Can't read ARM-side DSP pipe yet");
    }

    // TODO: Move to common code
    struct {
        Thread& thread;
        VAddr addr;

        void operator()(char* dest, size_t size) {
            for (auto data_ptr = dest; data_ptr != dest + size; ++data_ptr) {
                *data_ptr = thread.ReadMemory(addr++);
            }
        }
    } reader { thread, static_cast<VAddr>(pipe_info_base + SubPipeInfo::IndexToARM11(pipe_index) * sizeof(SubPipeInfo)) };
    const auto reader2 = reader;

    SubPipeInfo pipe = FileFormat::SerializationInterface<SubPipeInfo>::Load(reader);

    logger.info("Pipe {} to DSP with cursors [{:#x}, {:#x}] from {:#x}-{:#x}",
                pipe_index, pipe.read_cursor.value()(), pipe.write_cursor.value()(),
                pipe_info_base + 2 * pipe.pipe_offset_words,
                pipe_info_base + 2 * pipe.pipe_offset_words + pipe.num_bytes);

    if (pipe.subpipe_index != SubPipeInfo::IndexToARM11(pipe_index)) {
        fprintf(stderr, "ERROR: %d\n", __LINE__);
        throw Mikage::Exceptions::Invalid("Invalid DSP pipe header {}<->{}", pipe.subpipe_index, SubPipeInfo::IndexToARM11(pipe_index));
    }

    // TODO: Return immediately instead if no data is available?
    while (pipe.IsEmpty() || pipe.CursorDistance() < num_bytes) {
        fprintf(stderr, "Only %d bytes available to read, running DSP cycles...\n", pipe.CursorDistance());
//            g_teakra->Run(100);
        g_teakra->Run(0x4000);
        reader.addr = reader2.addr;
        pipe = FileFormat::SerializationInterface<SubPipeInfo>::Load(reader);
    }

    fprintf(stderr, "Available bytes to read: %d\n", pipe.CursorDistance());

//        if (pipe.IsEmpty()) {
//            num_bytes = 0;
//        }

    VAddr target_addr = pipe_address;

    for (uint32_t bytes_left = num_bytes; bytes_left > 0;) {
        if (bytes_left > pipe.CursorDistance()) {
            fprintf(stderr, "Partial pipe reads not supported\n");
            throw Mikage::Exceptions::NotImplemented("Partial pipe reads not supported");
        }

        uint16_t chunk_size = std::min<uint16_t>(bytes_left, pipe.GetReadableBytesUntilWrap());
        logger.info("  Reading {:#x} bytes of data at read cursor {:#x} (iteration {})", chunk_size, pipe.read_cursor.value()(), pipe.read_cursor.iteration()());
//            logger.info("  Reading {:#x} bytes of data from address {:#x} indicated by read cursor {:#x} (iteration {})", chunk_size, pipe.read_cursor.value()(), pipe.read_cursor.iteration()());
        for (uint32_t offset = 0; offset < chunk_size; ++offset) {
            // TODO: Access this through virtual memory instead...
//                auto value = thread.ReadMemory(/*pipe_info_base*/0x40000 + 2 * pipe.pipe_offset_words + pipe.read_cursor.value() + offset);
            auto value = g_teakra->GetDspMemory()[/*pipe_info_base*/0x40000 + 2 * pipe.pipe_offset_words + pipe.read_cursor.value() + offset];
            thread.WriteMemory(target_addr + offset, value);
        }
        bytes_left -= chunk_size;
        target_addr += chunk_size;
        pipe.MoveCursor(pipe.read_cursor, chunk_size);
    }

    if (num_bytes > 0) {
        // Write back SubPipeInfo to memory
        // TODO: Only need to write back the read/write cursors...
        struct Writer {
            Thread& thread;
            VAddr addr;

            void operator()(char* data, size_t size) {
                for (auto data_ptr = data; data_ptr != data + size; ++data_ptr) {
                    thread.WriteMemory(addr++, *data_ptr);
                }
            }
        } writer { thread, static_cast<VAddr>(pipe_info_base + SubPipeInfo::IndexToARM11(pipe_index) * sizeof(SubPipeInfo)) };
        FileFormat::SerializationInterface<SubPipeInfo>::Save(pipe, writer);

        // Notify DSP to process data
        const auto dsp_status_reg = Memory::ReadLegacy<uint16_t>(os.setup.mem, dsp_mmio + 0xc);
        if ((dsp_status_reg & (1 << 15)) == 1) {
            throw Mikage::Exceptions::NotImplemented("ReadPipeIfPossible: Must wait for pending DSP writes");
        }
        // Send subpipe index to DSP channel 2
        Memory::WriteLegacy<uint16_t>(os.setup.mem, dsp_mmio + 0x30, pipe.subpipe_index);
    }

    return std::make_tuple(RESULT_OK, num_bytes, IPC::StaticBuffer { pipe_address, num_bytes, 0 });
}

std::tuple<OS::Result,uint32_t,IPC::MappedBuffer> FakeDSP::HandleLoadComponent(FakeThread& thread, uint32_t size, uint32_t program_mask, uint32_t data_mask, const IPC::MappedBuffer component_buffer) {
    using Header = FileFormat::DSPFirmwareHeader;

    // NOTE: The upper 16 bits of these may be filled with noise (e.g. Kirby Battle Royale Demo)
    if ((program_mask & 0xffff) != 0xff || (data_mask & 0xffff) != 0xff) {
        throw Mikage::Exceptions::Invalid("Unsupported program mask {:#x} and data mask {:#x} for DSP firmware loading", program_mask, data_mask);
    }

    if (size < Header::Tags::expected_serialized_size) {
        throw Mikage::Exceptions::Invalid("Invalid buffer size for DSP firmware header");
    }

    // TODO: Move to common code
    struct {
        Thread& thread;
        VAddr addr;

        void operator()(char* dest, size_t size) {
            for (auto data_ptr = dest; data_ptr != dest + size; ++data_ptr) {
                *data_ptr = thread.ReadMemory(addr++);
            }
        }
    } reader { thread, component_buffer.addr };

    auto header = FileFormat::SerializationInterface<FileFormat::DSPFirmwareHeader>::Load(reader);
    if (header.magic[0] != 'D' || header.magic[1] != 'S' || header.magic[2] != 'P' || header.magic[3] != '1') {
        throw Mikage::Exceptions::Invalid("Invalid DSP firmware identifier");
    }
    if (size < header.size_bytes) {
        throw Mikage::Exceptions::Invalid("Invalid buffer size for DSP firmware");
    }

memset(g_teakra->GetDspMemory().data(), 0, g_teakra->GetDspMemory().size());

    logger.info("DSP firmware segments:");
    for (int index = 0; index < header.num_segments; ++index) {
        auto& segment = header.segments[index];
        bool is_data_memory = (segment.memory_type == 2);
        auto target_paddr = Memory::DSP::start + (is_data_memory ? Memory::DSP::size / 2 : 0) + segment.target_offset * sizeof(uint16_t);
        logger.info("  {} at {:#x} -> {:#x}-{:#x}",
                    is_data_memory ? "Data" : segment.memory_type < 2 ? "Program data" : "Unknown data",
                    segment.data_offset, target_paddr, target_paddr + segment.size_bytes);

        for (uint32_t offset = 0; offset < segment.size_bytes; ++offset) {
            // NOTE: DSP memory is identity-mapped in virtual memory
            thread.WriteMemory(target_paddr + offset, thread.ReadMemory(component_buffer.addr + segment.data_offset + offset));
        }
    }

    // TODO: Should this be done before or after waiting for the DSP replies?
    if (header.init_flags.load_3d_filters()) {
        // TODO: At least just write zeroes instead...
        fprintf(stderr, "TODO DSP: Implement 3d filters\n");
//        throw Mikage::Exceptions::NotImplemented("TODO: Implement loading of 3D filters");
    }

    auto& mem = thread.GetOS().setup.mem;

// TODO: Re-enable?
//    // Reset semaphore
//    Memory::WriteLegacy<uint16_t>(mem, dsp_mmio + 0x10, 0);
//    Memory::WriteLegacy<uint16_t>(mem, dsp_mmio + 0x18, 0xffff);
    Memory::WriteLegacy<uint16_t>(mem, dsp_mmio + 0x10, 0);
    Memory::WriteLegacy<uint16_t>(mem, dsp_mmio + 0x18, 0xffff);

    // Trigger DSP reset
    const auto dsp_config = Memory::ReadLegacy<uint16_t>(mem, dsp_mmio + 0x8);
    Memory::WriteLegacy<uint16_t>(mem, dsp_mmio + 0x8, dsp_config | 1);
    // TODO: Wait for bit 2 in DSP status to be cleared

    // Release reset trigger
    Memory::WriteLegacy<uint16_t>(mem, dsp_mmio + 0x8, dsp_config & 0xfe);

//    Memory::WriteLegacy<uint16_t>(mem, dsp_mmio + 0x14, 0xffff);

    // Wait for channels to be ready
    if (header.init_flags.wait_for_dsp_reply()) {
        for (int channel = 0; channel < 3; ++channel) {
            fprintf(stderr, "Waiting for channel %d to be ready\n", channel);
            while (true) {
                g_teakra->Run(100);

                auto dsp_status = Memory::ReadLegacy<uint16_t>(mem, dsp_mmio + 0xc);
                if (dsp_status & (1 << (10 + channel))) {
                    auto reply = Memory::ReadLegacy<uint16_t>(mem, dsp_mmio + 0x24 + 8 * channel);
                    if (reply == 1) {
                        break;
                    } else {
                        throw Mikage::Exceptions::Invalid("Post-init DSP reply has invalid value");
                    }
                }
            }
        }
    } else {
        // Not sure if any other logic in LoadComponent must be skipped in this case
        throw Mikage::Exceptions::NotImplemented("LoadComponent: Unclear semantics for firmware loading");
    }

    // First reply on channel 2 after initialization is the start offset (in 16-bit words) of the DSP SubPipeInfo array
    while ((Memory::ReadLegacy<uint16_t>(mem, dsp_mmio + 0xc) & (1 << 12)) == 0) {
//        g_teakra->Run(100);
        g_teakra->Run(0x4000);
    }
    pipe_info_base = Memory::DSP::start + Memory::DSP::size / 2 + sizeof(uint16_t) * Memory::ReadLegacy<uint16_t>(mem, dsp_mmio + 0x34);
    logger.info("DSP pipe headers located at {:#x}", pipe_info_base);
    if (pipe_info_base >= Memory::DSP::end) {
        throw Mikage::Exceptions::Invalid("Invalid DSP pipe location");
    }

    // TODO: Don't override OS handlers... instead, subscribe to DSP interrupt!
    struct ProcessPipeEventHandler {
        FakeDSP& context;

        OS& os;

        bool event_from_data;

        void operator()() const {
            // TODO: Assert this is only called from the OS scheduler

            if (event_from_data) {
                context.data_signaled = true;
            } else {
                if ((g_teakra->GetSemaphore() & 0x8000) == 0) {
                    return;
                }
                context.semaphore_signaled = true;
            }

            if (context.data_signaled && context.semaphore_signaled) {
                context.data_signaled = context.semaphore_signaled = false;
                uint16_t slot = g_teakra->RecvData(2);
                if ((slot % 2) != 0) {
                    return;
                }
                if ((slot / 2) == 0) {
                    fprintf(stderr, "ERROR: PIPE 0\n");
                    throw std::runtime_error("NOT IMPLEMENTED");
                }

                os.NotifyInterrupt(0x4a);
                // TODO: Preempt DSP execution
            }
        }
    };

#if 0
    /*static */auto process_pipe_event = [os=&thread.GetOS(), this](bool event_from_data) {
        // TODO: Assert this is only called from the OS scheduler

        if (event_from_data) {
            data_signaled = true;
        } else {
            if ((g_teakra->GetSemaphore() & 0x8000) == 0) {
                return;
            }
            semaphore_signaled = true;
        }

        if (data_signaled && semaphore_signaled) {
            data_signaled = semaphore_signaled = false;
            uint16_t slot = g_teakra->RecvData(2);
            if ((slot % 2) != 0) {
                return;
            }
            if ((slot / 2) == 0) {
                fprintf(stderr, "ERROR: PIPE 0\n");
                throw std::runtime_error("NOT IMPLEMENTED");
            }

            os->NotifyInterrupt(0x4a);
            // TODO: Preempt DSP execution
        }
    };
#endif

    g_teakra->SetSemaphoreHandler(/*[]() { process_pipe_event(false); }*/ ProcessPipeEventHandler { *this, thread.GetOS(), false });
    g_teakra->SetRecvDataHandler(2, /*[]() { process_pipe_event(true); }*/ ProcessPipeEventHandler { *this, thread.GetOS(), true });

    return std::make_tuple(RESULT_OK, 1 /* component loaded */, component_buffer);
}

std::tuple<OS::Result> FakeDSP::HandleFlushDataCache(FakeThread& thread, uint32_t start, uint32_t num_bytes, Handle process) {
    thread.CallSVC(&OS::SVCFlushProcessDataCache, process, start, num_bytes);

    // Close incoming thread handle
    thread.CallSVC(&OS::SVCCloseHandle, process);

    return std::make_tuple(RESULT_OK);

}

std::tuple<OS::Result> FakeDSP::HandleInvalidateDataCache(FakeThread& thread, uint32_t start, uint32_t num_bytes, Handle process) {
    thread.CallSVC(&OS::SVCInvalidateProcessDataCache, process, start, num_bytes);

    // Close incoming thread handle
    thread.CallSVC(&OS::SVCCloseHandle, process);

    return std::make_tuple(RESULT_OK);

}

std::tuple<OS::Result,Handle> FakeDSP::HandleGetSemaphoreEventHandle(FakeThread& thread) {
    logger.info("{}received GetSemaphoreEventHandle", ThreadPrinter{thread});
    return std::make_tuple(RESULT_OK, semaphore_event);
}


template<typename Class, typename Func>
static auto BindMemFn(Func f, Class* c) {
    return boost::hana::partial(std::mem_fn(f), c);
}

static int lol = 0; // TODO: Un-global-ize
void FakeDSP::OnIPCRequest(FakeThread& thread, Handle sender, const IPC::CommandHeader& header) {
    switch (header.command_id) {
    case 0x1: // RecvData
//        throw Mikage::Exceptions::NotImplemented("Not implemented: RecvData");
    {
        auto index = thread.ReadTLS(0x84);

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(1, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        // TODO: Applications use RecvData shortly after putting the DSP to
        //       sleep via WriteProcessPipe. However, if we indicate Sleep
        //       status too quickly, a race condition will prevent the
        //       application's main DSP client thread from properly pausing.
        //       Hence, we wait for a bit before reporting the new status,
        //       however this should be done in a cleaner way.
//        lol++;
//        thread.WriteTLS(0x88, lol > 10 && state != State::Running);
        if (!g_teakra->RecvDataIsReady(index)) {
            fprintf(stderr, "ERROR: DSP data is not ready\n");
            throw Mikage::Exceptions::Invalid("DSP data is not ready");
        }

        auto data = g_teakra->RecvData(index);
        thread.WriteTLS(0x88, data);

        thread.GetLogger()->info("{}received RecvData with state={}, returning {}",
                                 ThreadPrinter{thread}, Meta::to_underlying(state), data);
        break;
    }

    case 0x2: // RecvDataIsReady
    {
        auto index = thread.ReadTLS(0x84);
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(2, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, g_teakra->RecvDataIsReady(index));
        break;
    }

    case SetSemaphore::id:
    {
        auto value = thread.ReadTLS(0x84);
        if (value > 0xffff) {
            throw Mikage::Exceptions::Invalid("Invalid DSP semaphore value");
        }
        Memory::WriteLegacy<uint16_t>(os.setup.mem, dsp_mmio + 0x10, value);

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(SetSemaphore::id, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    case 0xc:
    {
        // TODO: This is not actually an address but rather an offset (in 16-bit values)
        VAddr addr = thread.ReadTLS(0x84);

        thread.GetLogger()->info("{}received ConvertProcessAddressFromDSPRam with address={:#x}",
                                 ThreadPrinter{thread}, addr);

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0xc, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        // TODO: Replace hardcoded constant with symbol for the mid of the physical DSP memory region
        auto out_addr = 2 * addr + 0x1ff40000;
        if (out_addr >= 0x1ff80000 || out_addr < 0x1ff40000) {
            throw Mikage::Exceptions::Invalid("ConvertProcessAddressFromDSPRam tried to query invalid DSP memory address {:#x}", out_addr);
        }
        thread.WriteTLS(0x88, out_addr);
        break;
    }

    case 0xd: // WriteProcessPipe
        IPC::HandleIPCCommand<WriteProcessPipe>(BindMemFn(&FakeDSP::HandleWriteProcessPipe, this), thread, thread);
        break;
//        // Detect DSP state changes, but stub-implement everything else
//        if (pipe == 2) {
//            auto value = thread.ReadMemory(buffer_addr);
//            switch (value) {
//            case 0: state = State::Running; thread.GetLogger()->info("{}received WriteProcessPipe -> State::Running", ThreadPrinter{thread}); break;
//            case 1: state = State::Stopped; lol = 0; thread.GetLogger()->info("{}received WriteProcessPipe -> State::Stopped", ThreadPrinter{thread}); break;
//            case 2: state = State::Running; thread.GetLogger()->info("{}received WriteProcessPipe -> State::Running", ThreadPrinter{thread}); break;
//            case 3: state = State::Sleeping; lol = 0; thread.GetLogger()->info("{}received WriteProcessPipe -> State::Sleeping", ThreadPrinter{thread}); break;
//            default: throw Mikage::Exceptions::Invalid("Invalid DSP state");
//            }

//            if (state == State::Stopped || state == State::Sleeping || true) {
//                read_pipe_if_possible_counter = -1;
//            }
//        }

//        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0xd, 1, 0).raw);
//        thread.WriteTLS(0x84, RESULT_OK);
//        break;

    // ReadPipeIfPossible
    case 0x10:
    {
        IPC::HandleIPCCommand<ReadPipeIfPossible>(BindMemFn(&FakeDSP::HandleReadPipeIfPossible, this), thread, thread);
        break;
//        uint32_t a = thread.ReadTLS(0x84);
//        uint32_t b = thread.ReadTLS(0x88);
//        uint32_t size = std::min<uint32_t>(thread.ReadTLS(0x8c) & 0xFFFF, 0x20); // Only considers the lower 16 bits for the size
//        thread.GetLogger()->info("ReadPipeIfPossible: channel {:#x}, {:#x} bytes", a, size);

//        if (a != 2)
//            thread.CallSVC(&OS::SVCBreak, OS::BreakReason::Panic);

//        for (unsigned i = 0; i < 0x20; ++i)
//            thread.WriteTLS(0x80 + 4*i, 0xdeadbeef);
//        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0x10, 2, 2).raw);
//        thread.WriteTLS(0x84, RESULT_OK);
//        thread.WriteTLS(0x88, size);
//        thread.WriteTLS(0x8c, IPC::TranslationDescriptor::MakeStaticBuffer(0, size).raw);
//        thread.WriteTLS(0x90, pipe_address); // TODO: Return offset to pipe data instead?
   }

    case LoadComponent::id:
        IPC::HandleIPCCommand<LoadComponent>(BindMemFn(&FakeDSP::HandleLoadComponent, this), thread, thread);
        break;

    case 0x12: // UnloadComponent
    {
        auto& mem = thread.GetOS().setup.mem;

        const auto channel = 2; // NOTE: Channel 2 seems to be implicit for this call

        const auto dsp_config = Memory::ReadLegacy<uint16_t>(mem, dsp_mmio + 0x8);
        Memory::WriteLegacy<uint16_t>(mem, dsp_mmio + 0x8, dsp_config & ~0x800);

        semaphore_mask = Memory::ReadLegacy<uint16_t>(mem, dsp_mmio + 0x14);
        semaphore_mask |= 0x8000;
        Memory::WriteLegacy<uint16_t>(mem, dsp_mmio + 0x14, semaphore_mask);

        if ((Memory::ReadLegacy<uint16_t>(mem, dsp_mmio + 0xc) & (1 << (13 + channel))) != 0) {
            throw Mikage::Exceptions::NotImplemented("Waiting on pending DSP write not implemented");
        }

        Memory::WriteLegacy<uint16_t>(os.setup.mem, dsp_mmio + 0x20 + channel * 8, 0x8000);
        // Wait until DSP has processed the request
        while ((Memory::ReadLegacy<uint16_t>(mem, dsp_mmio + 0xc) & (1 << 12)) == 0) {
            g_teakra->Run(0x4000);
        }

        auto reply = Memory::ReadLegacy<uint16_t>(mem, dsp_mmio + 0x24 + 8 * channel);
        fprintf(stderr, "DSP SHUTDOWN REPLY: %#x\n", reply);

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0x12, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    case FlushDataCache::id:
        IPC::HandleIPCCommand<FlushDataCache>(BindMemFn(&FakeDSP::HandleFlushDataCache, this), thread, thread);
        break;

    case 0x14:
        IPC::HandleIPCCommand<InvalidateDataCache>(BindMemFn(&FakeDSP::HandleInvalidateDataCache, this), thread, thread);
        break;

    case RegisterInterruptEvents::id:
    {
        auto interrupt = thread.ReadTLS(0x84);
        auto pipe = thread.ReadTLS(0x88);

        if (interrupt != 2 || pipe != 2) {
            throw Mikage::Exceptions::Invalid("Invalid DSP interrupt/pipe");
        }

        auto new_channel_event = Handle{thread.ReadTLS(0x90)};
        if (channel_event != HANDLE_INVALID && new_channel_event != HANDLE_INVALID) {
            throw Mikage::Exceptions::Invalid("Cannot register more than one DSP client");
        }

        if (new_channel_event != HANDLE_INVALID) {
            std::shared_ptr<Event> object;
            object = thread.GetProcessHandleTable().FindObject<Event>(new_channel_event);
            object->name = "DSPInterruptEvent";
        } else {
            // TODO: Unregister previously registered event
//            throw Mikage::Exceptions::NotImplemented("Cannot unregister DSP interrupt event yet");
            thread.CallSVC(&OS::SVCCloseHandle, channel_event);
        }
        channel_event = new_channel_event;

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(RegisterInterruptEvents::id, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;
    }

    case GetSemaphoreEventHandle::id:
        IPC::HandleIPCCommand<GetSemaphoreEventHandle>(BindMemFn(&FakeDSP::HandleGetSemaphoreEventHandle, this), thread, thread);
        break;

    case SetSemaphoreMask::id:
        semaphore_mask = thread.ReadTLS(0x84);

        thread.WriteTLS(0x80, IPC::CommandHeader::Make(SetSemaphoreMask::id, 1, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        break;

    // GetHeadPhoneStatus
    case 0x1f:
        thread.WriteTLS(0x80, IPC::CommandHeader::Make(0x1f, 2, 0).raw);
        thread.WriteTLS(0x84, RESULT_OK);
        thread.WriteTLS(0x88, 0); // not inserted
        break;

    default:
        // TODO: Throw and catch IPCError instead
        throw std::runtime_error(fmt::format("Unknown DSP IPC request {:#x}", header.command_id.Value()));
    }
}

}  // namespace OS

}  // namespace HLE

#define FORMATS_IMPL_EXPLICIT_FORMAT_INSTANTIATIONS_INTENDED
#include <framework/formats_impl.hpp>

namespace FileFormat {

template struct SerializationInterface<HLE::OS::SubPipeInfo>;

}
