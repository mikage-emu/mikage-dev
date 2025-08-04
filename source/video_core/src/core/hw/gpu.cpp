#include "common/common_types.h"
#include "common/log.h"

//#include "core/core.h"
#include "gpu.h"

#include "video_core/command_processor.h"
//#include "video_core/video_core.h"
#include <video_core/context.h>
#include <video_core/renderer.hpp>
#include <video_core/debug_utils/debug_utils.h>

#include <framework/color.hpp>
#include <framework/exceptions.hpp>

#include "../../interrupt_listener.hpp"

#include "spdlog/fmt/fmt.h"
#include "spdlog/logger.h"

namespace GPU {

Regs g_regs;

template <typename T>
inline void Read(Pica::Context& context, T &var, const u32 raw_addr) {
    u32 addr = raw_addr - 0x1EF00000;
    u32 index = addr / 4;

    // Reads other than u32 are untested, so I'd rather have them abort than silently fail
    if (index >= Regs::NumIds() || !std::is_same<T,u32>::value) {
        LOG_ERROR(HW_GPU, "unknown Read%lu @ 0x%08X", sizeof(var) * 8, addr);
        return;
    }

    var = g_regs[addr / 4];
}

template <typename T>
inline void Write(Pica::Context& context, u32 addr, const T data) {
//    addr -= 0x1EF00000;
    u32 index = addr / 4;

    // Writes other than u32 are untested, so I'd rather have them abort than silently fail
    if (index >= Regs::NumIds() || !std::is_same<T,u32>::value) {
        ERROR_LOG(GPU, "unknown Write%lu 0x%08X @ 0x%08X", sizeof(data) * 8, data, addr);
        return;
    }

    g_regs[index] = static_cast<u32>(data);

    switch (index) {

    // Memory fills are triggered once the fill value is written.
    case GPU_REG_INDEX_WORKAROUND(memory_fill_config[0].trigger, 0x00004 + 0x3):
    case GPU_REG_INDEX_WORKAROUND(memory_fill_config[1].trigger, 0x00008 + 0x3):
    {
        const bool is_second_filler = (index != GPU_REG_INDEX(memory_fill_config[0].trigger));
        auto& config = g_regs.memory_fill_config[is_second_filler];

        if (config.address_start && config.trigger) {
            PAddr current_offset = 0;
            PAddr num_bytes = config.GetEndAddress() - config.GetStartAddress();

            // Invalidate renderer memory so that overwritten memory pages will be backed by host memory again
            context.renderer->InvalidateRange(config.GetStartAddress(), num_bytes);

            auto output_memory = Memory::LookupContiguousMemoryBackedPage<Memory::HookKind::Write>(
                                                                            *context.mem, config.GetStartAddress(),
                                                                            config.GetEndAddress() - config.GetStartAddress());
            if (!output_memory) {
                throw std::runtime_error("Attempted to fill memory that is not backed by host memory");
            }

            if (config.fill_24bit) {
                // fill with 24-bit values
                while (current_offset < num_bytes) {
                    Memory::Write<uint8_t>(output_memory, current_offset++, config.value_24bit_r);
                    Memory::Write<uint8_t>(output_memory, current_offset++, config.value_24bit_g);
                    Memory::Write<uint8_t>(output_memory, current_offset++, config.value_24bit_b);
                }
            } else if (config.fill_32bit) {
                // fill with 32-bit values
                if (num_bytes > current_offset) {
                u32 value = config.value_32bit;
                    size_t len = (num_bytes - current_offset) / sizeof(u32);
                    for (size_t i = 0; i < len; ++i) {
                        Memory::Write<uint32_t>(output_memory, current_offset + i * sizeof(uint32_t), value);
                    }
                }
            } else {
                // fill with 16-bit values
                u16 value_16bit = config.value_16bit.Value();
                for (uint32_t addr = current_offset; addr < num_bytes; addr += sizeof(u16)) {
                    Memory::Write<uint16_t>(output_memory, addr, value_16bit);
                }
            }

//            LOG_TRACE(HW_GPU, "MemoryFill from 0x%08x to 0x%08x", config.GetStartAddress(), config.GetEndAddress());
            printf( "MemoryFill from 0x%08x to 0x%08x with %d-byte value %#x\n",
                    config.GetStartAddress(), config.GetEndAddress(),
                    config.fill_24bit ? 3 : config.fill_32bit ? 4 : 2,
                    config.fill_24bit ? config.value_32bit & 0xffffff : config.fill_32bit ? config.value_32bit : config.value_16bit.Value());

            config.trigger = 0;
            config.finished = 1;

            context.os->NotifyInterrupt(0x28 + is_second_filler);
        }
        break;
    }

    case GPU_REG_INDEX(display_transfer_config.trigger):
    {
        const auto& config = g_regs.display_transfer_config;
        if (config.trigger & 1) {
            if (config.is_raw_copy) {
                // TODO: Review changes from https://github.com/citra-emu/citra/pull/2809
                auto& copy = config.texture_copy;

                // Compute line count from the number of *copied* bytes (which excludes padding)
                const auto num_lines = copy.total_bytes_to_copy / copy.InputBytesPerLine();
                if (num_lines * copy.InputBytesPerLine() != copy.total_bytes_to_copy) {
                    throw std::runtime_error("Attempted to perform unaligned texture copy");
                }
                if (copy.total_bytes_to_copy & 0xf) {
                    // NOTE: Supposedly the lower 4 bits are just ignored
                    throw std::runtime_error("Number of bytes to copy for TextureCopy was not aligned");
                }

                if (copy.total_bytes_to_copy == 0) {
                    throw std::runtime_error("Attempted to perform zero-sized texture copy");
                }

                if (copy.InputBytesPerLine() == 0 || copy.OutputBytesPerLine() == 0) {
                    throw std::runtime_error("Attempted to perform texture copy with zero line size");
                }

                if (config.convert_to_tiled || config.disable_untiling) {
                    throw std::runtime_error("Attempted to set tiling flags in a texture copy");
                }

                if (config.output_tiled) {
                    throw std::runtime_error("Attempted to use 32x32 tiling mode in a texture copy");
                }

                if (config.scaling_mode != 0) {
                    throw std::runtime_error("Attempted to use scaling in a texture copy");
                }

                const auto input_memory_size = num_lines * copy.InputTotalBytesPerLine() - copy.InputPaddingBytesPerLine();
                const auto output_memory_size = num_lines * copy.OutputTotalBytesPerLine() - copy.OutputPaddingBytesPerLine();

                fmt::print("TextureCopy: {} lines of size {}+{} to {}+{}, addr {:#x} -> {:#x}\n",
                          num_lines, copy.InputBytesPerLine(), copy.InputPaddingBytesPerLine(),
                          copy.OutputBytesPerLine(), copy.OutputPaddingBytesPerLine(),
                          config.GetPhysicalInputAddress(), config.GetPhysicalOutputAddress());

                // TODO: Consider flushing/invalidating per line rather than for the whole area
                context.renderer->FlushRange(config.GetPhysicalInputAddress(), input_memory_size);
                if (copy.OutputPaddingBytesPerLine()) {
                    // Texture copy doesn't modify padding bytes, so resources at this location must be flushed back to memory
                    context.renderer->FlushRange(config.GetPhysicalInputAddress() + copy.OutputBytesPerLine(), num_lines * copy.OutputTotalBytesPerLine() - copy.OutputBytesPerLine());
                }
                context.renderer->InvalidateRange(config.GetPhysicalOutputAddress(), output_memory_size);

                auto source_memory = LookupContiguousMemoryBackedPage<Memory::HookKind::Read>(*context.mem, config.GetPhysicalInputAddress(), input_memory_size);
                auto dest_memory = LookupContiguousMemoryBackedPage<Memory::HookKind::Write>(*context.mem, config.GetPhysicalOutputAddress(), output_memory_size);
                if (!source_memory || !dest_memory) {
                    throw std::runtime_error(fmt::format("Attempted to run display transfer between memory that is not backed by host memory"));
                }

                if (copy.InputBytesPerLine() != copy.OutputBytesPerLine()) {
                    throw Mikage::Exceptions::NotImplemented("TextureCopy with differing line sizes not implemented");
                }

                // TODO: Provide GPU-accelerated code path
                for (u32 y = 0; y < num_lines; ++y) {
                    // TODO: If bit 2 is set, use OutputBytesPerLine instead?
                    memcpy( dest_memory.data + y * copy.OutputTotalBytesPerLine(),
                            source_memory.data + y * copy.InputTotalBytesPerLine(),
                            copy.InputBytesPerLine());
                }
            } else {
                // Encountered in Retro City Rampage while rendering the first frame
                if (config.display_transfer.output_height == 0) {
                    printf("Output dimensions are zero, skipping\n");
                    break;
                }

                // Encountered in Zelda: Ocarina of Time 3D while rendering the first frame
                if (config.display_transfer.output_width == 0) {
                    printf("Output dimensions are zero, skipping\n");
                    break;
                }

                if (config.output_tiled) {
//                    throw Mikage::Exceptions::NotImplemented("32x32 block tiling mode not implemented");
                }

                if (config.convert_to_tiled) {
//                    throw Mikage::Exceptions::NotImplemented("Converting images from linear to tiled is not implemented");
                }

                if (config.disable_untiling) {
                    // NOTE: We don't actually handle tiling here currently, yet this behavior is equivalent to a tiled->linear conversion.
                    //       This is because host render targets aren't tiling-encoded when flushing to emulated memory.
//                    throw Mikage::Exceptions::NotImplemented("Converting images from linear to linear is not implemented");
                }

                if (config.scaling_mode == 3) {
                    throw Mikage::Exceptions::Invalid("Invalid scaling mode 3");
                }

                if (config.disable_untiling ^ config.convert_to_tiled) {
                    // Allegedly not valid, but Luigi's Mansion 2 uses this configuration
//                    throw Mikage::Exceptions::Invalid("Attempted to disable tiling conversion while also reversing tiling direction");
                }

                // NOTE: Various titles use input height = 0x190 and output height = 0x140.
                //       The smaller of the two (i.e. the output height) must be used in that case.
                //       Notably, this affects Super Mario 3D Land and Retro City Rampage.
                //       The inverse scenario has not been observed, so we still assert on it.
                if (config.display_transfer.output_height > config.display_transfer.input_height) {
                    throw std::runtime_error(fmt::format(   "Input height {:#x} doesn't match output height {:#x}",
                                                            config.display_transfer.input_height.Value(),
                                                            config.display_transfer.output_height.Value()));
                }

                const PAddr src_addr = config.GetPhysicalInputAddress();
                const PAddr dst_addr = config.GetPhysicalOutputAddress();

                // Cheap emulation of horizontal scaling: Just skip each second pixel of the
                // input framebuffer. We keep track of this in the pixel_skip variable.
                // TODO: At least implement a simple box filter instead. Also, test against hardware what filter is used in practice
                unsigned pixel_skip = (config.scaling_mode != 0) ? 2 : 1;
                unsigned pixel_skip_y = (config.scaling_mode == 2) ? 2 : 1;
                uint32_t scaled_output_width = config.display_transfer.output_width / pixel_skip;
                uint32_t scaled_output_height = config.display_transfer.output_height / pixel_skip_y;

                const auto input_format = ToGenericFormat(config.GetInputFormat());
                const auto input_total_size = TextureSize(input_format, config.display_transfer.input_width, config.display_transfer.input_height);
                const auto input_stride = input_total_size / config.display_transfer.input_height;
                const auto output_format = ToGenericFormat(config.GetOutputFormat());
                const auto output_total_size = TextureSize(output_format, scaled_output_width, scaled_output_height);
                const auto output_stride = output_total_size / scaled_output_height;

                fmt::print("DisplayTriggerTransfer: {}x{} -> {}x{}, {} -> {}, addr {:#x} -> {:#x}\n",
                          config.display_transfer.input_width.Value(), config.display_transfer.input_height.Value(),
                          scaled_output_width, scaled_output_height,
                          ToGenericFormat(config.GetInputFormat()), ToGenericFormat(config.GetOutputFormat()),
                          config.GetPhysicalInputAddress(), config.GetPhysicalOutputAddress());

                // NOTE: There are a couple of non-trivial configurations to consider here:
                // * Steel Diver uses a 256x400 -> 240x400 copy when rendering the title screen
                // * TLoZ: Majora's Mask uses a 512x400 -> 240x400 copy (downscaling horizontally) when rendering the title screen
                // It seems that input_width is actually an input row stride (in pixels),
                // and output_width determines the image size on both input and output.
                const bool software_fallback = !context.renderer->BlitImage(context, config.GetPhysicalInputAddress(),
                                                                            config.display_transfer.output_width,
                                                                            std::min(config.display_transfer.input_height, config.display_transfer.output_height),
                                                                            input_stride,
                                                                            config.GetInputFormat().raw,
                                                                            config.GetPhysicalOutputAddress(),
                                                                            scaled_output_width, scaled_output_height, output_stride,
                                                                            config.GetOutputFormat().raw,
                                                                            config.flip_data);
                if (software_fallback) {
                    // Flush host GPU objects in the source memory range to
                    // emulated memory, and invalidate host GPU objects in
                    // the target range

                    fmt::print("Running software fallback for display transfer => Flushing input resources and invalidating outputs\n");
                    context.renderer->FlushRange(src_addr, input_total_size);
                    context.renderer->InvalidateRange(dst_addr, output_total_size);

                    auto source_memory = LookupContiguousMemoryBackedPage<Memory::HookKind::Read>(*context.mem, src_addr, input_total_size);
                    auto dest_memory = LookupContiguousMemoryBackedPage<Memory::HookKind::Write>(*context.mem, dst_addr, output_total_size);
                    if (!source_memory || !dest_memory) {
                        throw std::runtime_error(fmt::format("Attempted to run display transfer between memory that is not backed by host memory"));
                    }

                    for (u32 y = 0; y < scaled_output_height; ++y) {
			u32 flipped_y = config.flip_data ? ((config.display_transfer.input_height - 1) - y) : y;
                        
                        for (u32 x = 0; x < scaled_output_width; ++x) {
                            struct {
                                int r, g, b, a;
                            } source_color = { 0, 0, 0, 0 };

                            switch (ToGenericFormat(config.GetInputFormat())) {
                            case GenericImageFormat::RGBA8:
                            {
                                PAddr pixel_addr = x * 4 * pixel_skip + flipped_y * pixel_skip_y * config.display_transfer.input_width * 4;
                                source_color.r = Memory::Read<uint8_t>(source_memory, pixel_addr + 3); // red
                                source_color.g = Memory::Read<uint8_t>(source_memory, pixel_addr + 2); // green
                                source_color.b = Memory::Read<uint8_t>(source_memory, pixel_addr + 1); // blue
                                source_color.a = Memory::Read<uint8_t>(source_memory, pixel_addr + 0); // alpha
                                break;
                            }

// NOTE: Allegedly, most of these formats aren't actually supported by hardware. Supposedly working are RGBA5551->RGB565, RGB565->RGBA5551, RGBA8->RGB8
// I verified that RGBA8->RGBA8, RGBA8->RGB8, and RGB8->RGB8 work.

                            case GenericImageFormat::RGB565:
                            {
                                u16 srcval = Memory::Read<uint16_t>(source_memory, x * 2 * pixel_skip + flipped_y * pixel_skip_y * config.display_transfer.input_width * 2);
                                source_color.r = Color::Convert5To8((srcval >> 11) & 0x1F); // red
                                source_color.g = Color::Convert6To8((srcval >>  5) & 0x3F); // green
                                source_color.b = Color::Convert5To8( srcval        & 0x1F); // blue
                                source_color.a = 255;
                                break;
                            }

                            case GenericImageFormat::RGBA5551:
                            {
                                u16 srcval = Memory::Read<uint16_t>(source_memory, x * 2 * pixel_skip + flipped_y * pixel_skip_y * config.display_transfer.input_width * 2);
                                source_color.r = Color::Convert5To8((srcval >> 11) & 0x1F); // red
                                source_color.g = Color::Convert5To8((srcval >>  6) & 0x1F); // green
                                source_color.b = Color::Convert5To8((srcval >>  1) & 0x1F); // blue
                                source_color.a = Color::Convert1To8(srcval & 0x1);          // alpha
                                break;
                            }

                            case GenericImageFormat::RGBA4:
                            {
                                u16 srcval = Memory::Read<uint16_t>(source_memory, x * 2 * pixel_skip + flipped_y * pixel_skip_y * config.display_transfer.input_width * 2);
                                source_color.r = Color::Convert4To8((srcval >> 12) & 0xF); // red
                                source_color.g = Color::Convert4To8((srcval >>  8) & 0xF); // green
                                source_color.b = Color::Convert4To8((srcval >>  4) & 0xF); // blue
                                source_color.a = Color::Convert4To8( srcval        & 0xF); // alpha
                                break;
                            }

                            default:
                                throw std::runtime_error(fmt::format("Unknown source framebuffer format {:#x}", config.GetInputFormat().raw));
                                break;
                            }

                            switch (ToGenericFormat(config.GetOutputFormat())) {
                            case GenericImageFormat::RGBA8:
                            {
                                PAddr pixel_addr = x * 4 + y * scaled_output_width * 4;
                                Memory::Write<uint8_t>(dest_memory, pixel_addr + 3, source_color.r);
                                Memory::Write<uint8_t>(dest_memory, pixel_addr + 2, source_color.g);
                                Memory::Write<uint8_t>(dest_memory, pixel_addr + 1, source_color.b);
                                Memory::Write<uint8_t>(dest_memory, pixel_addr + 0, source_color.a);
                                break;
                            }

                            case GenericImageFormat::RGB8:
                            {
                                PAddr pixel_addr = x * 3 + y * scaled_output_width * 3;
                                Memory::Write<uint8_t>(dest_memory, pixel_addr + 2, source_color.r); // red
                                Memory::Write<uint8_t>(dest_memory, pixel_addr + 1, source_color.g); // green
                                Memory::Write<uint8_t>(dest_memory, pixel_addr + 0, source_color.b); // blue
                                break;
                            }

                            case GenericImageFormat::RGB565:
                            {
                                PAddr pixel_addr = x * 2 + y * scaled_output_width * 2;
                                Memory::Write<uint16_t>(dest_memory, pixel_addr, ((source_color.r >> 3) << 11) | ((source_color.g >> 2) << 5)
                                        | ((source_color.b >> 3)));
                                break;
                            }

                            case GenericImageFormat::RGBA5551:
                            {
                                PAddr pixel_addr = x * 2 + y * scaled_output_width * 2;
                                Memory::Write<uint16_t>(dest_memory, pixel_addr, ((source_color.r >> 3) << 11) | ((source_color.g >> 3) << 6)
                                        | ((source_color.b >> 3) <<  1) | ( source_color.a >> 7));
                                break;
                            }

                            case GenericImageFormat::RGBA4:
                            {
                                PAddr pixel_addr = x * 2 + y * scaled_output_width * 2;
                                Memory::Write<uint16_t>(dest_memory, pixel_addr, ((source_color.r >> 4) << 12) | ((source_color.g >> 4) << 8)
                                        | ((source_color.b >> 4) <<  4) | ( source_color.a >> 4));
                                break;
                            }

                            default:
                                throw std::runtime_error(fmt::format("Unknown destination framebuffer format {:#x}", config.GetOutputFormat().raw));
                                break;
                            }
                        }
                    }
                }
            }

            context.os->NotifyInterrupt(0x2c);
        }
        break;
    }

    // Seems like writing to this register triggers processing
    case GPU_REG_INDEX(command_processor_config.trigger):
    {
        auto& config = g_regs.command_processor_config;
        if (config.trigger & 1)
        {
            u32 size = config.size << 3;
            Pica::CommandProcessor::ProcessCommandList(context, config.GetPhysicalAddress(), size);
            config.trigger = 0;
        }
        break;
    }

    case GPU_REG_INDEX(command_processor_config.trigger) - 3:
    case GPU_REG_INDEX(command_processor_config.trigger) - 1:
    case GPU_REG_INDEX(command_processor_config.trigger) + 1:
        throw std::runtime_error("Accessing the secondary command submission engine through MMIO is not currently supported");

    default:
        break;
    }
}

template void Read<u64>(Pica::Context&, u64 &var, const u32 addr);
template void Read<u32>(Pica::Context&, u32 &var, const u32 addr);
template void Read<u16>(Pica::Context&, u16 &var, const u32 addr);
template void Read<u8>(Pica::Context&, u8 &var, const u32 addr);

template void Write<u64>(Pica::Context&, u32 addr, const u64 data);
template void Write<u32>(Pica::Context&, u32 addr, const u32 data);
template void Write<u16>(Pica::Context&, u32 addr, const u16 data);
template void Write<u8>(Pica::Context&, u32 addr, const u8 data);

} // namespace
