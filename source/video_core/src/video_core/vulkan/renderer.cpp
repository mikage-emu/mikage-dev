#define VULKAN_HPP_DISPATCH_LOADER_DYNAMIC 1

#include "pipeline_cache.hpp"
#include "renderer.hpp"
#include "resource_manager.hpp"
#include "shader_gen.hpp"
#include "state_mapping.hpp"
#include "../context.h"
#include "../vertex_loader.hpp"
#include "../debug_utils/debug_utils.h"

#include "layout_transitions.hpp"

#include "../../core/hw/gpu.h"

#include "../../../framework/exceptions.hpp"
#include "../../../framework/meta_tools.hpp"
#include "../../../framework/profiler.hpp"
#include "framework/image_format.hpp"
#include "../../../framework/settings.hpp"

#include <vulkan_utils/debug_markers.hpp>
#include <vulkan_utils/glsl_helper.hpp>

#include <boost/container/static_vector.hpp>
#include <boost/endian/buffers.hpp>
#include <boost/scope_exit.hpp>

#include <range/v3/algorithm/any_of.hpp>
#include <range/v3/algorithm/copy_if.hpp>
#include <range/v3/algorithm/for_each.hpp>
#include <range/v3/algorithm/fill.hpp>
#include <range/v3/algorithm/generate_n.hpp>
#include <range/v3/algorithm/move.hpp>
#include <range/v3/algorithm/transform.hpp>
#include <range/v3/iterator/insert_iterators.hpp>
#include <range/v3/view/indices.hpp>
#include <range/v3/view/indirect.hpp>
#include <range/v3/view/transform.hpp>
#include <range/v3/view/zip.hpp>

#include <functional>
#include <iostream> // TODO: Remove
#include <bitset>

#include <spdlog/logger.h>

#include <tracy/Tracy.hpp>
#include <tracy/TracyC.h>

#define USE_SHADER_UBO

extern std::mutex g_vulkan_queue_mutex; // TODO: Turn into a proper interface

namespace Pica {

namespace Vulkan {

// static constexpr uint32_t vertex_buffer_size = 10000000;
//
// static constexpr uint32_t descriptor_pool_size = 99; // maximum number of descriptors

// static constexpr uint32_t vertex_buffer_size = 1'000'000;
static constexpr uint32_t vertex_buffer_size = 1024 * 1024 * 100;

// TODO: Don't rely on exceptions to catch the maximum size of these!!!
//static constexpr uint32_t descriptor_pool_size = 99; // maximum number of descriptors
static constexpr uint32_t descriptor_pool_size = 1000; // maximum number of descriptors
static uint32_t occupied_descriptor_pool_slots = 0;

constexpr uint32_t ubo_binding = 0;
constexpr uint32_t base_texture_binding = ubo_binding + 1;
constexpr uint32_t base_light_lut_binding = base_texture_binding + 3;

/*
 * Fragment shader uniforms:
 * - Combiner buffer init value
 * - global ambient light rgb
 * - NUM_LIGHTS * (ambient rgb + diffuse rgb + diffuse dir rgb + 2 * specular rgb + specular dir)
 * - NUM_TEV_STAGES * tev const
 * - NUM_TEXTURES * border color rgba
 *
 * TODO: Store the light vectors as triplets rather than packing them in 4D vectors
 */
constexpr uint32_t fs_uniform_data_size = 4 * sizeof(float) * (1 + 1 + 8 * 6 + 6 * 1 + 3);

// Float uniforms and integer uniforms (4 * uvec4)
constexpr uint32_t vs_uniform_data_size = sizeof(Context::shader_uniforms.f) + sizeof(uint32_t) * 4 * 4;

constexpr uint32_t total_uniform_data_size = vs_uniform_data_size + fs_uniform_data_size;

Renderer::Renderer(Memory::PhysicalMemory& mem, std::shared_ptr<spdlog::logger> logger, Profiler::Profiler& profiler, vk::PhysicalDevice physical_device, vk::Device device, uint32_t graphics_queue_family_index, vk::Queue graphics_queue)
        : logger(logger), profiler(profiler), activity(reinterpret_cast<Profiler::TaggedActivity<Profiler::Activities::GPU>&>(profiler.GetActivity("GPU"))), device(device),
          graphics_queue_index(graphics_queue_family_index),
          graphics_queue(graphics_queue),
          memory_types(*logger, physical_device) {

    vk::CommandPoolCreateInfo command_pool_info { vk::CommandPoolCreateFlagBits::eTransient | vk::CommandPoolCreateFlagBits::eResetCommandBuffer, graphics_queue_index };
    command_pool = device.createCommandPoolUnique(command_pool_info);

    resource_manager = std::make_unique<ResourceManager>(mem, device, graphics_queue, *command_pool, memory_types);

    pipeline_cache = std::make_unique<PipelineCache>(device);

    {
        constexpr uint32_t num_tex_stages = 3;
        constexpr uint32_t num_light_luts = 24;

        std::array<vk::DescriptorPoolSize, 3> pool_sizes;
        pool_sizes[0] = vk::DescriptorPoolSize {
            vk::DescriptorType::eCombinedImageSampler,
            num_tex_stages * 10 // descriptor count (up to 3 texture stages)
        };
        pool_sizes[1] = vk::DescriptorPoolSize {
            vk::DescriptorType::eUniformBuffer,
            10
        };
        pool_sizes[2] = vk::DescriptorPoolSize {
            vk::DescriptorType::eUniformTexelBuffer,
            num_light_luts * 10
        };

        vk::DescriptorPoolCreateInfo pool_info {
            vk::DescriptorPoolCreateFlagBits::eFreeDescriptorSet, // NOTE: Technically, we could do without this, but it's easier to manage descriptor sets by freeing and reallocating them instead
            99, // number of sets // TODO: Use driver-provided limit?
            pool_sizes.size(), // number of pool sizes
            pool_sizes.data()
        };
        desc_pool = device.createDescriptorPoolUnique(pool_info);
    }

    // Create vertex buffer
    {
        vk::BufferCreateInfo vertex_buffer_info {
            vk::BufferCreateFlagBits { },
            vertex_buffer_size,
            vk::BufferUsageFlagBits::eVertexBuffer | vk::BufferUsageFlagBits::eIndexBuffer, // TODO: Use a dedicated index buffer instead?
            vk::SharingMode::eExclusive, // For now, only the CPU thread and the present queue ever use this buffer
        };
        vertex_buffer = device.createBufferUnique(vertex_buffer_info);

        auto requirements = device.getBufferMemoryRequirements(*vertex_buffer);

        // TODO: Review which flags are needed
        auto vertex_buffer_memory_info = memory_types.GetMemoryAllocateInfo<vk::MemoryPropertyFlagBits::eHostVisible, vk::MemoryPropertyFlagBits::eHostCoherent>(requirements);
        vertex_buffer_memory = device.allocateMemoryUnique(vertex_buffer_memory_info);

        device.bindBufferMemory(*vertex_buffer, *vertex_buffer_memory, 0);
    }

    // Create vertex shader uniform buffer
    {
        pica_uniform_buffer_info = vk::BufferCreateInfo {
            vk::BufferCreateFlagBits { },
            total_uniform_data_size * 100,
            vk::BufferUsageFlagBits::eUniformBuffer,
            vk::SharingMode::eExclusive
        };
        pica_uniform_buffer = device.createBufferUnique(pica_uniform_buffer_info);

        auto requirements = device.getBufferMemoryRequirements(*pica_uniform_buffer);

        // TODO: Review which flags are needed
        auto buffer_memory_info = memory_types.GetMemoryAllocateInfo<vk::MemoryPropertyFlagBits::eHostVisible, vk::MemoryPropertyFlagBits::eHostCoherent>(requirements);
        pica_uniform_memory = device.allocateMemoryUnique(buffer_memory_info);
        device.bindBufferMemory(*pica_uniform_buffer, *pica_uniform_memory, 0);
    }

    // Create light LUT uniform texel buffer
    {
        auto pica_light_lut_buffer_info = vk::BufferCreateInfo {
            vk::BufferCreateFlagBits { },
            pica_light_lut_buffer_views.size() * pica_lut_data_slot_size,
            vk::BufferUsageFlagBits::eUniformTexelBuffer,
            vk::SharingMode::eExclusive
        };
        pica_light_lut_buffer = device.createBufferUnique(pica_light_lut_buffer_info);

        auto requirements = device.getBufferMemoryRequirements(*pica_light_lut_buffer);

        // TODO: Review which flags are needed
        auto buffer_memory_info = memory_types.GetMemoryAllocateInfo<vk::MemoryPropertyFlagBits::eHostVisible, vk::MemoryPropertyFlagBits::eHostCoherent>(requirements);
        pica_light_lut_memory = device.allocateMemoryUnique(buffer_memory_info);
        device.bindBufferMemory(*pica_light_lut_buffer, *pica_light_lut_memory, 0);

        fmt::print(stderr, "Total size {}\n", pica_light_lut_buffer_views.size() * pica_lut_data_slot_size);
        for (unsigned i = 0; i < pica_light_lut_buffer_views.size(); ++i) {
            fmt::print(stderr, "Creating view {} at offset {}\n", i, i * pica_lut_data_slot_size);
            vk::BufferViewCreateInfo view_info = {
                vk::BufferViewCreateFlags {},
                *pica_light_lut_buffer,
                vk::Format::eR16G16Sint,
                i * pica_lut_data_slot_size,
                pica_lut_data_slot_size
            };
            pica_light_lut_buffer_views[i] = device.createBufferViewUnique(view_info);
        }
    }

    {
        // Setup descriptor set layout for:
        // * vertex shader uniforms
        // * up to 3 texture stages
        // * up to 24 lighting LUTs
        std::array<vk::DescriptorSetLayoutBinding, 28> bindings {{
            {
                ubo_binding,
                vk::DescriptorType::eUniformBuffer, // TODO: Consider using eUniformBufferDynamic?
                1,
                vk::ShaderStageFlagBits::eVertex | vk::ShaderStageFlagBits::eFragment,
                nullptr
            },
            {
                base_texture_binding,
                vk::DescriptorType::eCombinedImageSampler,
                1,
                vk::ShaderStageFlagBits::eFragment,
                nullptr
            },
            {},
            {},
            {
                base_light_lut_binding,
                vk::DescriptorType::eUniformTexelBuffer,
                1,
                vk::ShaderStageFlagBits::eFragment,
                nullptr
            }
        }};
        for (int i = 1; i < 3; ++i) {
            bindings[base_texture_binding + i] = bindings[base_texture_binding];
            bindings[base_texture_binding + i].binding = base_texture_binding + i;
        }
        for (int i = 1; i < 24; ++i) {
            bindings[base_light_lut_binding + i] = bindings[base_light_lut_binding];
            bindings[base_light_lut_binding + i].binding = base_light_lut_binding + i;
        }

        vk::DescriptorSetLayoutCreateInfo info {
            vk::DescriptorSetLayoutCreateFlags { },
            static_cast<uint32_t>(bindings.size()),
            bindings.data()
        };
        pica_render_desc_set_layout = device.createDescriptorSetLayoutUnique(info);

        vk::PipelineLayoutCreateInfo layout_info {
            vk::PipelineLayoutCreateFlags { },
            1, &*pica_render_desc_set_layout, // descriptor set layouts
            0, nullptr, // push constant ranges
        };
        layout = device.createPipelineLayoutUnique(layout_info);
    }

    ranges::generate_n(blit_resources.begin(), 5, [this]() {
        BlitResources ret;
        vk::CommandBufferAllocateInfo command_buffer_info { *command_pool, vk::CommandBufferLevel::ePrimary,
                                                            static_cast<uint32_t>(ret.command_buffers.size()) };
        ranges::move(this->device.allocateCommandBuffersUnique(command_buffer_info), ret.command_buffers.begin());
        ret.completion_fence = this->device.createFenceUnique({ vk::FenceCreateFlagBits::eSignaled });
        return ret;
    });
}

Renderer::~Renderer() = default;

//bool Renderer::ScreenPart::TryAcquire(vk::Device device, size_t index) {
//    if (in_use_by_cpu[index]) {
//        return false;
//    }

//    if (in_use_by_gpu[index].IsReady(device)) {
//        return true;
//    }

//    return false;
//}

void Renderer::ProduceFrame(EmuDisplay::EmuDisplay& display, EmuDisplay::Frame& frame, Memory::PhysicalMemory& mem, EmuDisplay::DataStreamId stream_id, uint32_t addr, uint32_t stride, EmuDisplay::Format format) {
    ZoneScoped;
    auto scope_measure = MeasureScope(*activity, "FrameProduction");

            auto& image = frame.image;
            auto& memory = frame.buffer_memory;

//                part.in_use_by_cpu[buffer_index] = true;
//                part.in_use_by_gpu[buffer_index] = { }; // Initialized by frontend before toggling in_use_by_cpu back to false

                uint32_t width = (stream_id == EmuDisplay::DataStreamId::BottomScreen) ? 320 : 400;
                uint32_t height = 240;

                // Frames are rotated by 90 degree in emulated memory, hence width and height are swapped here
                MemoryRange memory_range { addr, TextureSize(ToGenericFormat(format), width, height) };
                // TODO: Use PrepareToCopyRenderTargetArea instead
                auto& input = resource_manager->PrepareRenderTarget(memory_range, height, width, ToGenericFormat(format), stride);

                auto& command_buffer = frame.command_buffer;
                command_buffer = vk::UniqueCommandBuffer { };

                {
                    vk::DescriptorImageInfo tex_desc_image_info {
                        // TODO: Have PrepareRenderTarget create samplers instead!
                        *frame.image_sampler, *input.image_view, vk::ImageLayout::eShaderReadOnlyOptimal
                    };

                    vk::WriteDescriptorSet desc_write = {
                        frame.desc_set,
                        0,
                        0,
                        1,
                        vk::DescriptorType::eCombinedImageSampler,
                        &tex_desc_image_info,
                        nullptr,
                        nullptr
                    };

                    device.updateDescriptorSets({ desc_write }, {});
                }

                // TODO: Instead of recreating command buffers all the time, just keep them pooled and reset them instead
                vk::CommandBufferAllocateInfo command_buffer_info { *display.command_pool, vk::CommandBufferLevel::ePrimary, 1 };
                command_buffer = std::move(device.allocateCommandBuffersUnique(command_buffer_info)[0]);

                vk::CommandBufferBeginInfo begin_info { /*vk::CommandBufferUsageFlagBits::eSimultaneousUse | */vk::CommandBufferUsageFlagBits::eOneTimeSubmit };
                command_buffer->begin(begin_info);

                {
                const char* screen_name = (stream_id == EmuDisplay::DataStreamId::TopScreenLeftEye)
                                          ? "Top left" : (stream_id == EmuDisplay::DataStreamId::TopScreenRightEye)
                                                       ? "Top right" : "Bottom";
                GuardedDebugMarker debug_guard(*command_buffer, fmt::format("ProduceFrame: {}", screen_name).c_str());
                // TODO: Restrict this to "input"
                resource_manager->UploadStagedDataToHost(*command_buffer);

                auto& image_blitter = display.image_blitter[Meta::to_underlying(stream_id)];
#if 0
                auto full_image = vk::ImageSubresourceLayers { vk::ImageAspectFlagBits::eColor, 0, 0, 1 };
                auto offset = vk::Offset3D { 0, 0, 0 };
                auto end_offset = vk::Offset3D { static_cast<int32_t>(width), static_cast<int32_t>(height), 1 };
                vk::ImageBlit copy_region {
                    full_image, { offset, end_offset }, full_image, { offset, end_offset }
                };
                command_buffer->blitImage(*input.image, vk::ImageLayout::eGeneral, *image, vk::ImageLayout::eGeneral, { copy_region }, vk::Filter::eNearest);
#else
                vk::RenderPassBeginInfo renderpass_info {   *image_blitter.renderpass,
                                                            *frame.framebuffer,
                                                            vk::Rect2D { vk::Offset2D { 0, 0 }, vk::Extent2D { width, height } },
                                                            0, nullptr // clear values
                                                        };

                vk::ImageSubresourceRange full_image = { vk::ImageAspectFlagBits::eColor, 0, 1, 0, 1 };
                TransitionImageLayout(*command_buffer, *input.image, full_image, ImageLayoutTransitionPoint::FromColorAttachmentOutput(), ImageLayoutTransitionPoint::ToShaderRead());

                command_buffer->beginRenderPass(renderpass_info, vk::SubpassContents::eInline);

                command_buffer->bindPipeline(vk::PipelineBindPoint::eGraphics, *image_blitter.pipeline);

                command_buffer->bindDescriptorSets(vk::PipelineBindPoint::eGraphics, *image_blitter.pipeline_layout, 0, 1, &frame.desc_set, 0, nullptr);

                command_buffer->draw(4, 1 /* instance count */, 0 /* first vertex */, 0 /* first instance */);

                command_buffer->endRenderPass();

                TransitionImageLayout(*command_buffer, *input.image, full_image, { vk::ImageLayout::eShaderReadOnlyOptimal, vk::PipelineStageFlagBits::eFragmentShader, vk::AccessFlagBits::eShaderRead },
                                      ImageLayoutTransitionPoint::ToColorAttachmentOutput());
#endif
                }
                command_buffer->end();

                vk::PipelineStageFlags submit_wait_flags = vk::PipelineStageFlagBits::eTransfer | vk::PipelineStageFlagBits::eAllGraphics;
                vk::SubmitInfo submit_info { 0, nullptr, &submit_wait_flags, 1, &*command_buffer, 0, nullptr };
                {
                    std::unique_lock lock(g_vulkan_queue_mutex);
                    (void)graphics_queue.submit(1, &submit_info, vk::Fence { });
                }

                FrameMark;
}

static uint64_t global_data_size;

/**
 * This function is a template so that we can keep the vertex attribute
 * descriptors easily consistent with the data that we actually write.
 *
 * If GenerateOffsets is true, no triangle will actually be emitted, and
 * dummy OutputVertexes may be passed to this function.
 */
// TODO: Bring back to sync with the InputVertex variant of this function?
template<bool GenerateOffsets>
void DoAddTriangle(Renderer& renderer, Context& context, VertexShader::OutputVertex& v0, VertexShader::OutputVertex& v1, VertexShader::OutputVertex& v2) {
    static constexpr uint32_t vertex_size = /*14*/16 * sizeof(float);
    // TODO: Do vertices need to be aligned? Technically, 14 is enough, but 16 seems "safer" due to alignment
    std::array<float, vertex_size / sizeof(float)> data;

    for (auto& vtx : { v0, v1, v2 }) {
        size_t index = 0;
        size_t attribute_index = 0;

        if (GenerateOffsets) {
            renderer.vertex_attribute_descs.emplace_back(attribute_index++, 0, vk::Format::eR32G32B32A32Sfloat, index * sizeof(float));
        }
        data[index++] = vtx.pos[0].ToFloat32();
        data[index++] = vtx.pos[1].ToFloat32();
        data[index++] = vtx.pos[2].ToFloat32();
        data[index++] = vtx.pos[3].ToFloat32();

        if (GenerateOffsets) {
            renderer.vertex_attribute_descs.emplace_back(attribute_index++, 0, vk::Format::eR32G32B32A32Sfloat, index * sizeof(float));
        }
        data[index++] = vtx.color[0].ToFloat32();
        data[index++] = vtx.color[1].ToFloat32();
        data[index++] = vtx.color[2].ToFloat32();
        data[index++] = vtx.color[3].ToFloat32();

        if (GenerateOffsets) {
            renderer.vertex_attribute_descs.emplace_back(attribute_index++, 0, vk::Format::eR32G32Sfloat, index * sizeof(float));
        }
        data[index++] = vtx.tc0[0].ToFloat32();
        data[index++] = vtx.tc0[1].ToFloat32();

        if (GenerateOffsets) {
            renderer.vertex_attribute_descs.emplace_back(attribute_index++, 0, vk::Format::eR32G32Sfloat, index * sizeof(float));
        }
        data[index++] = vtx.tc1[0].ToFloat32();
        data[index++] = vtx.tc1[1].ToFloat32();

        if (GenerateOffsets) {
            renderer.vertex_attribute_descs.emplace_back(attribute_index++, 0, vk::Format::eR32G32Sfloat, index * sizeof(float));
        }
        data[index++] = vtx.tc2[0].ToFloat32();
        data[index++] = vtx.tc2[1].ToFloat32();

        // TODO: Add quaternion and view vector

//         uint32_t vertex_stride = index * sizeof(data[0]); // in bytes
//         memcpy(next_vertex_ptr, data.data(), vertex_stride);
        uint32_t vertex_stride = vertex_size; // in bytes
        if (GenerateOffsets) {
            renderer.vertex_binding_descs.emplace_back(0, vertex_stride, vk::VertexInputRate::eVertex);
            break;
        } else {
            memcpy(renderer.next_vertex_ptr, data.data(), index * sizeof(data[0]));
            renderer.next_vertex_ptr += vertex_stride;

            if (vertex_stride != vertex_size) {
                throw std::runtime_error("BLA");
            }
        }
    }

    if constexpr (!GenerateOffsets) {
        renderer.num_vertices += 3;
    }
}

constexpr uint32_t max_vertex_size = sizeof(VertexShader::InputVertex);

// TODO: Drop global
bool hardware_vertex_loading = true;
bool preassembled_triangles = false;

void Renderer::AddPreassembledTriangle(Context& context, VertexShader::OutputVertex& v0, VertexShader::OutputVertex& v1, VertexShader::OutputVertex& v2) {
    hardware_vertex_loading = false;
    preassembled_triangles = true;
    return DoAddTriangle<false>(*this, context, v0, v1, v2);
}

void Renderer::AddVertex(Context& context, uint32_t num_attributes, VertexShader::InputVertex& vtx) {
    if (num_vertices == 0) {
        // TODO: Come up with a better design
        hardware_vertex_loading = false;
        next_vertex_buffer_offset = vertex_buffer_offset;
        vertex_binding_offset[0] = next_vertex_buffer_offset;

        // Initialize pipeline state on first triangle
        // TODO: Move to PrepareTriangleBatch
        for (auto attribute_index : ranges::views::iota(uint32_t { 0 }, num_attributes)) {
            uint32_t register_index = context.registers.vs_input_register_map.GetRegisterForAttribute(attribute_index);

            // Check that no two attributes are bound to the same input register
            if (ranges::any_of(vertex_attribute_descs, [register_index](auto& desc) { return desc.location == register_index; })) {
                throw Mikage::Exceptions::NotImplemented("Multiple attributes bound to the same shader input register");
            }

            vertex_attribute_descs.emplace_back(register_index, 0, vk::Format::eR32G32B32A32Sfloat, attribute_index * 4 * sizeof(float));
        }

        uint32_t vertex_stride = num_attributes * 4 * sizeof(float); // in bytes. TODO: Do we need to care about alignment?
        vertex_binding_descs.emplace_back(0, vertex_stride, vk::VertexInputRate::eVertex);
    }

    std::array<float, max_vertex_size / sizeof(float)> data {};

    for (auto attribute_index : ranges::views::iota(uint32_t { 0 }, num_attributes)) {
        auto& input_attribute = vtx.attr[static_cast<std::size_t>(attribute_index)];
        for (auto comp : ranges::views::iota(0, 4)) {
            data[attribute_index * 4 + comp] = input_attribute[comp].ToFloat32();
        }
    }

    uint32_t vertex_stride = num_attributes * 4 * sizeof(float); // in bytes. TODO: Do we need to care about alignment?
    memcpy(next_vertex_ptr, data.data(), vertex_stride);
    next_vertex_ptr += vertex_stride;
    ++num_vertices;

    // TODO: Eh.
    next_vertex_buffer_offset += max_vertex_size * 2;
}

static uint32_t min_vertex_index = 0; // TODO: Un-global-ize

void Renderer::AwaitTriangleBatches(Context& context) {
    const bool wait_all = true; // TODO: Add path for partial waiting

    std::vector<vk::Fence> pending_renders;
    auto get_fence = [](TriangleBatchInFlight& batch) { return *batch.fence; };
    ranges::copy_if(triangle_batches | ranges::views::transform(get_fence),
                    ranges::back_inserter(pending_renders),
                    [](auto fence) -> bool {
                        return fence;
                    });
    if (!pending_renders.empty()) {
        printf("TRACE: Waiting for vertex buffer memory to be free again\n");
        auto result = device.waitForFences(pending_renders, wait_all, std::numeric_limits<uint64_t>::max());
        if (result != vk::Result::eSuccess) {
            throw std::runtime_error(fmt::format("waitForFences failed in PrepareTriangleBatch! {}", vk::to_string(result)));
        }
    }

    occupied_descriptor_pool_slots -= triangle_batches.size();
    for (auto& batch : triangle_batches) {
        batch.fence_awaitable.Wait(device);
    }
    triangle_batches.clear();
}

void Renderer::PrepareTriangleBatch(Context& context, const VertexShader::ShaderEngine& shader_engine, uint32_t max_triangles, bool is_indexed) {
    ZoneNamedN(PrepareTriangleBatch, "PrepareTriangleBatch", true);
    auto& submit_batch_activity = activity.GetSubActivity<Profiler::Activities::SubmitBatch>();
    submit_batch_activity->Resume();

    // TODO: Use actual vertex size
    // TODO: This should be easy to do now...!
    auto data_size = 3 * max_triangles * max_vertex_size;
    data_size = (data_size + 0xff) & ~0xff; // TODO: nonCoherentAtomSize
    if (data_size > vertex_buffer_size) {
        throw std::runtime_error(fmt::format("Triangle batch with {} triangles (requiring {:#x} bytes of memory) is too large for vertex buffer allocation ({:#x} bytes)",
                                             max_triangles, data_size, vertex_buffer_size));
    }

    submit_batch_activity.GetSubActivity("WaitVertexBuffer").Resume();
    context.logger->info("Triangle batch at offset {:#x} with size {:#x}\n", vertex_buffer_offset, data_size);
    if (vertex_buffer_offset + data_size > vertex_buffer_size) {
        // Wait until vertex buffer memory is free again.. TODO: Only wait for renders that affect the memory in the beginning!
        AwaitTriangleBatches(context);
        vertex_buffer_offset = 0;
    }
    // NOTE: Interrupt the last sub-activity, only, and keep submit_batch_activity itself running until the end of FinalizeTriangleBatch
    submit_batch_activity.GetSubActivity("WaitVertexBuffer").Interrupt();

    // TODO: Should consider nonCoherentAtomSize in here, too... the range needs to be rounded towards a multiple of that, and then the range might overlap
    next_vertex_ptr = reinterpret_cast<char*>(device.mapMemory(*vertex_buffer_memory, vertex_buffer_offset, data_size));
    num_vertices = 0;
    global_data_size = data_size;

//    // TODO: Clean this up. This builds the vertex_binding_descs and vertex_attribute_descs
    vertex_binding_descs.clear();
    vertex_attribute_descs.clear();
    if (shader_engine.ProcessesInputVertexesOnGPU()) {
        hardware_vertex_loading = true;
        preassembled_triangles = false;
    } else {
        VertexShader::OutputVertex vtx;
        DoAddTriangle<true>(*this, context, vtx, vtx, vtx);
    }
}

void Renderer::BeginTriangleBatch(Context& context) {
    ValidateContract(!pending_batch);

    pending_batch.emplace();

    TriangleBatchInFlight& batch = pending_batch.value();

    // TODO: If allocation fails, wait for a previous batch to complete
    vk::CommandBufferAllocateInfo command_buffer_info { *command_pool, vk::CommandBufferLevel::ePrimary, 1 };
    batch.command_buffer = std::move(device.allocateCommandBuffersUnique(command_buffer_info)[0]);

    vk::CommandBufferBeginInfo command_buffer_begin_info { vk::CommandBufferUsageFlagBits::eOneTimeSubmit };
    batch.command_buffer->begin(command_buffer_begin_info);

    batch.fence = device.createFenceUnique(vk::FenceCreateInfo { });
    batch.fence_awaitable = CPUAwaitable { *batch.fence };
}

void Renderer::FinalizeTriangleBatchInternal(Context& context, const VertexShader::ShaderEngine& shader_engine, bool is_indexed) try {
        if (hardware_vertex_loading) {
            next_vertex_buffer_offset = vertex_buffer_offset;
            vertex_binding_offset = {};

            const Regs::VertexAttributes& attribute_config = context.registers.vertex_attributes;
            uint32_t max_vertex_index = 0;
            min_vertex_index = std::numeric_limits<uint32_t>::max();

            if (is_indexed) {
                // Determine vertex index bounds and load index data
                const auto& index_info = context.registers.index_array;
                const uint32_t index_address = attribute_config.GetPhysicalBaseAddress() + index_info.offset;
                const bool index_u16 = index_info.format != 0;

                uint32_t size_index_data = context.registers.num_vertices * (index_u16 ? 2 : 1);
                auto index_memory = Memory::LookupContiguousMemoryBackedPage(*context.mem, index_address, size_index_data);

                for (unsigned int index = 0; index < context.registers.num_vertices; ++index)
                {
                    // TODO: Should vertex_offset indeed only be applied for non-indexed rendering?
                    uint32_t vertex = (index_u16 ? Memory::Read<uint16_t>(index_memory, 2 * index) : Memory::Read<uint8_t>(index_memory, index));
                    min_vertex_index = std::min(min_vertex_index, vertex);
                    max_vertex_index = std::max(max_vertex_index, vertex);
                }
                min_vertex_index = std::min(min_vertex_index, max_vertex_index); // Corner case for num_vertices == 0

                // TODO: Ensure alignment...
                if (index_u16) {
                    memcpy(next_vertex_ptr, index_memory.data, size_index_data);
                } else {
                    // TODO: Look into native 8-bit index support
                    size_index_data *= 2;
                    for (uint16_t index_index = 0; index_index < context.registers.num_vertices; ++index_index) {
                        uint16_t index16 = Memory::Read<uint8_t>(index_memory, index_index);
                        memcpy(next_vertex_ptr + 2 * index_index, &index16, sizeof(index16));
                    }
                }
                next_vertex_ptr += size_index_data;
                next_vertex_buffer_offset += size_index_data;
            } else {
                min_vertex_index = context.registers.vertex_offset;
                max_vertex_index = context.registers.vertex_offset + context.registers.num_vertices - 1;
            }

            // TODO: Align properly
            next_vertex_ptr += ((next_vertex_buffer_offset + 0xf) & ~0xf) - next_vertex_buffer_offset;
            next_vertex_buffer_offset += ((next_vertex_buffer_offset + 0xf) & ~0xf) - next_vertex_buffer_offset;

            std::bitset<16> register_initialized;

            VertexLoader loader { context, attribute_config };
            for (int i = 0; i < 12; ++i) {
                const auto& loader_config = attribute_config.attribute_loaders[i];
                if (!loader.vertex_attribute_sources[i]) { // TODO: Check component count / byte count instead
                    // TODO: Required by lego batman during bootup?
                    continue;
                }

                if (loader_config.component_count == 0 || loader_config.byte_count == 0) {
                    continue;
                }

                // TODO: Do we need to factor in vertex_attribute_element_size[idx], too?

                uint32_t vertex_stride = loader.vertex_attribute_strides[i]; // in bytes. TODO: Do we need to care about alignment?
                const uint32_t binding_index = i;
                const uint32_t binding_stride = loader_config.byte_count;
                // TODO: Use device requirements instead
                const uint32_t host_binding_stride = (binding_stride + 0x1f) & ~0x1f;
                vertex_binding_descs.emplace_back(binding_index, host_binding_stride, vk::VertexInputRate::eVertex);

                uint32_t offset = 0;
                for (unsigned component = 0; component < loader_config.component_count; ++component) {
                    const uint32_t attribute_index = loader_config.GetComponent(component);
                    if (attribute_index >= 12) {
                        // Explicit alignment by 4/8/12/16 bytes.
                        // TODO: Should offset be additionally aligned to the alignment size itself?
                        offset = (offset + 3) & ~3;
                        offset += 4 * (attribute_index - 11);
                        continue;
//                        throw Mikage::Exceptions::NotImplemented("TODO: Implement vertex attribute padding");
                    }

                    uint32_t num_elements = attribute_config.GetNumElements(attribute_index);
                    if (num_elements == 0) {
                        continue;
                    }
                    const auto format = attribute_config.GetFormat(attribute_index);

                    // Implicit alignment to element size
                    const auto element_size = attribute_config.GetElementSizeInBytes(attribute_index);
                    offset = (offset + element_size - 1) & ~(element_size - 1);

                    const uint32_t register_index = context.registers.vs_input_register_map.GetRegisterForAttribute(attribute_index);

                    // Check that no two attributes are bound to the same input register
                    // TODO: Use register_initialized instead
                    if (ranges::any_of(vertex_attribute_descs, [register_index](auto& desc) { return desc.location == register_index; })) {
                        throw Mikage::Exceptions::NotImplemented("Multiple attributes bound to the same shader input register");
                    }

                    // TODO: Check that the current offset matches the VkFormat alignment requirements

                    // TODO: Assert this does not partially overlap with any default/fixed arguments... if it does, how do we handle it?
                    // TODO: Do individual attributes have host alignment requirements?
                    // TODO: Align guest offset to attribute_config.GetElementSizeInBytes(attribute_index), or at least assert it is already aligned!
                    register_initialized.set(register_index);
                    vertex_attribute_descs.emplace_back(register_index, binding_index, FromPicaState(format, num_elements), offset);

                    offset += attribute_config.GetStride(attribute_index); // element size * number of elements
                }

                if (loader_config.byte_count < offset) {
                    throw Mikage::Exceptions::Invalid("Vertex attribute offset is smaller than the binding stride");
                }
                const uint32_t load_address = attribute_config.GetPhysicalBaseAddress() + loader_config.data_offset + min_vertex_index * binding_stride;
                const uint32_t num_indexed_vertices = max_vertex_index - min_vertex_index + 1;
                const uint32_t size_vertex_data = num_indexed_vertices * host_binding_stride;

                // TODO: Should be safe to use the size_vertex_data bound here
                auto load_ptr = Memory::LookupContiguousMemoryBackedPage/*<Memory::HookKind::Read>*/(*context.mem, load_address, num_indexed_vertices * binding_stride);

                if (binding_stride == host_binding_stride) {
                    memcpy(next_vertex_ptr, load_ptr.data, size_vertex_data);
                } else {
                    for (std::size_t vertex = 0; vertex < size_vertex_data / host_binding_stride; ++vertex) {
                        memcpy(next_vertex_ptr + vertex * host_binding_stride, load_ptr.data + vertex * binding_stride, binding_stride);
                    }
                }
                next_vertex_ptr += size_vertex_data;
                vertex_binding_offset[binding_index] = next_vertex_buffer_offset;
                next_vertex_buffer_offset += size_vertex_data;

                // TODO: Align properly
                next_vertex_ptr += ((next_vertex_buffer_offset + 0xf) & ~0xf) - next_vertex_buffer_offset;
                next_vertex_buffer_offset += ((next_vertex_buffer_offset + 0xf) & ~0xf) - next_vertex_buffer_offset;
            }

            // And finally, set up default attributes...
            // NOTE: These use vk::VertexInputRate::eInstance since they are the same for each vertex
            {
                const auto binding_index = vertex_binding_offset.size() - 1;

                // Default values used when the attribute loader is active but doesn't initialize all attribute elements
                // NOTE: For components loaded by one of the other methods but with fewer than 4 components, Vulkan guarantees the remaining components get filled appropriately
                float default_data[4] = { 0.f, 0.f, 0.f, 1.f };

                for (std::size_t attribute_index = 0; attribute_index < attribute_config.GetNumTotalAttributes(); ++attribute_index) {
                    // TODO: Do we need to handle partial overlaps?
                    auto register_index = context.registers.vs_input_register_map.GetRegisterForAttribute(attribute_index);
                    if (register_initialized[register_index]) {
                        // TODO: If possible, assert that the corresponding fixed attribute is disabled?
                        continue;
                    }

                    if (attribute_config.fixed_attribute_mask & (1 << attribute_index)) {
                        vertex_attribute_descs.emplace_back(register_index, binding_index, vk::Format::eR32G32B32A32Sfloat, sizeof(default_data) + attribute_index * sizeof(float) * 4);
                        register_initialized.set(register_index);
                    }
                }

                // TODO: Do we strictly need a separate loop afterwards?
                for (std::size_t attribute_index = 0; attribute_index < attribute_config.GetNumTotalAttributes(); ++attribute_index) {
                    auto register_index = context.registers.vs_input_register_map.GetRegisterForAttribute(attribute_index);
                    if (register_initialized[register_index]) {
                        continue;
                    }

                    // Use default data
                    vertex_attribute_descs.emplace_back(register_index, binding_index, vk::Format::eR32G32B32A32Sfloat, 0);
                    register_initialized.set(register_index);
                }

                // Add dummy attributes for anything not specified by the application. Avoids validation layer warnings about uninitialized attributes
                // TODO: Is this needed? Shouldn't we emit smarter vertex shaders instead?
                for (std::size_t register_index = 0; register_index < 16; ++register_index) {
                    if (register_initialized[register_index]) {
                        continue;
                    }

                    // Use default data
                    vertex_attribute_descs.emplace_back(register_index, binding_index, vk::Format::eR32G32B32A32Sfloat, 0);
                }

                // Fixed vertex attributes set by the application
                constexpr auto num_default_attributes = std::tuple_size_v<decltype(context.vertex_attribute_defaults)>;
                float fixed_data[num_default_attributes * 4];
                for (std::size_t i = 0; i < std::size(fixed_data); ++i) {
                    std::array<float24, 4>& attr = context.vertex_attribute_defaults[i / 4];
                    fixed_data[i] = attr[i % 4].ToFloat32();
                }

                uint32_t vertex_stride = sizeof(default_data) + sizeof(fixed_data);

                memcpy(next_vertex_ptr, &default_data, sizeof(default_data));
                memcpy(next_vertex_ptr + sizeof(default_data), &fixed_data, sizeof(fixed_data));
                next_vertex_ptr += vertex_stride;
                vertex_binding_offset[binding_index] = next_vertex_buffer_offset;
                next_vertex_buffer_offset += vertex_stride;

                // TODO: Consider going back to eInstance due to VK_KHR_portability_subset (may impose minimal vertex stride)
                vertex_binding_descs.emplace_back(binding_index, /*vertex_stride*/ 0, vk::VertexInputRate::eVertex/*eInstance*/);
            }

            // TODO: Check proper device limits
            if (vertex_attribute_descs.size() > 32) {
                throw Mikage::Exceptions::Invalid("Exceeded device limit for vertex attribute descs");
            }

            num_vertices = max_vertex_index - min_vertex_index + 1;
        } else {
            // TODO: Instead assert this is the case. AddVertex should've been called the appropriate number of times
//            num_vertices = context.registers.num_vertices;
        }

        // TODO: Check minimum stride alignment of host





    ZoneNamedN(FinalizeTriangleBatch, "FinalizeTriangleBatch", true);
    auto& submit_activity = activity.GetSubActivity<Profiler::Activities::SubmitBatch>();

    submit_activity.GetSubActivity("UnmapVertexBuffer").Resume();
    // Unmap vertex buffer
    {
        // TODO: Use actual vertex size
        if (num_vertices > global_data_size / max_vertex_size) {

//            throw std::runtime_error("Too many vertices 2");
        }
        device.unmapMemory(*vertex_buffer_memory);
        next_vertex_ptr = nullptr;
    }
    submit_activity.GetSubActivity("UnmapVertexBuffer").Interrupt();

    if (!num_vertices) {
        // This may happen if clipping (which is done CPU-side) discarded all submitted triangles
        return;
    }

#if 1
    TriangleBatchInFlight& batch = pending_batch.value();
    auto& command_buffer = batch.command_buffer;

    boost::container::static_vector<TextureResource*, 3> texcache_entries;
    {
    GuardedDebugMarker debug_marker(*command_buffer, fmt::format("Render {} vertices", num_vertices).c_str());

    // Refresh texture cache
    submit_activity.GetSubActivity("TexCache").Resume();
    TracyCZoneN(TexCache, "Texture Cache", true);

    for (int i = 0; i < 3; ++i) {
        auto texture = context.registers.GetTextures()[i];
        if (!texture.enabled)
            continue;

        if (texture.config.GetPhysicalAddress() == 0) {
            // TODO: It seems appletEd hits this case when trying out the mii_selector.3dsx example with custom settings (i.e. pressing B on startup)
//            throw std::runtime_error("Texture set up with invalid data address"); // TODO: Some applications actually do this, though :/
            continue;
        }

        // NOTE: These fields are 11 bits wide according to 3dbrew, but
        //       presumably the actual texture size limit is 1024 (after all,
        //       only sizes up to 2047 are representable with 11 bits, and that
        //       seems like a weird limit to have)
        if (texture.config.width > 1024 || texture.config.height > 1024) {
            throw std::runtime_error("Unexpectedly large texture dimensions");
        }

        auto& texture_resource = resource_manager->LookupTextureResource(texture);

//        printf("TRACE: Refreshing texcache image\n");

        texcache_entries.emplace_back(&texture_resource);

        resource_manager->RefreshTextureMemory(*command_buffer, texture_resource, *context.mem, texture);
    }
    TracyCZoneEnd(TexCache);
    submit_activity.GetSubActivity("TexCache").Interrupt();

    submit_activity.GetSubActivity("FB reload").Resume();
    TracyCZoneN(FBReload, "FB Reload", true);
//    std::cerr << fmt::format("Rendering to {:#x}, {:#x}\n", context.registers.framebuffer.GetColorBufferPhysicalAddress(), context.registers.framebuffer.GetDepthBufferPhysicalAddress());
    auto [color_fb, depth_fb] = [&]() -> std::pair<RenderTargetResource*, RenderTargetResource*> {
        auto& fb_registers = context.registers.framebuffer;
        MemoryRange color_range = {
            fb_registers.GetColorBufferPhysicalAddress(),
            TextureSize(ToGenericFormat(fb_registers.GetColorFormat()), fb_registers.GetWidth(), fb_registers.GetHeight())
        };
        MemoryRange depth_stencil_range = {
            // NOTE: This address may be 0 if depth buffer access is disabled (see below)
            fb_registers.GetDepthBufferPhysicalAddress(),
            // Size calculation is done below
            0,
        };

        // Make sure framebuffer read access is enabled when needed.
        // NOTE: Read operations have well-defined results on hardware even if
        //       access is disabled. This has been observed e.g. in Captain Toad: Treasure Tracker
        const auto& output_merger = context.registers.output_merger;
        if (!fb_registers.color_read_enabled() && fb_registers.color_write_enabled()) {
            bool needs_read_access;
            if (output_merger.alphablend_enable) {
                needs_read_access = (output_merger.alpha_blending.factor_dest_rgb != AlphaBlendFactor::Zero ||
                                    output_merger.alpha_blending.factor_dest_a != AlphaBlendFactor::Zero);
            } else {
                needs_read_access = (output_merger.logic_op.op != LogicOp::Set);
            }
            if (needs_read_access) {
                throw Mikage::Exceptions::NotImplemented("Cannot render to a write-only color buffer");
            }
        }
        if (!fb_registers.depth_stencil_read_enabled() && fb_registers.depth_stencil_write_enabled()) {
            throw Mikage::Exceptions::NotImplemented("Cannot render to a write-only depth buffer");
        }
        if (!fb_registers.depth_stencil_read_enabled() && output_merger.depth_test_enable && output_merger.depth_test_func != DepthFunc::Always) {
            if (output_merger.depth_test_func == DepthFunc::LessThanOrEqual) {
                // NOTE: Luigi's Mansion 2 hits this path on the title screen
                // TODO: Depth testing should be enabled in this case, but always compare against 0
                logger->warn("Application enabled depth testing with depth access disabled (test function {})\n",
                            Meta::to_underlying(output_merger.depth_test_func.Value()));
            } else {
                // Captain Toad: Treasure Tracker (Demo) hits the DepthFunc::LessThan path when entering any level. Such draws are skipped during command processing.
                ValidateContract(output_merger.depth_test_func != DepthFunc::LessThan);

                throw Mikage::Exceptions::NotImplemented("Cannot perform depth test without depth buffer read access");
            }

            // TODO: We *must* set num_bytes to 0 here, otherwise we risk corrupting memory hook state
        }
        if (!fb_registers.depth_stencil_read_enabled() && output_merger.stencil_test.enabled()) {
            throw Mikage::Exceptions::NotImplemented("Cannot perform stencil test without stencil buffer read access");
        }
        if (!fb_registers.depth_stencil_write_enabled() && output_merger.stencil_test.enabled() &&
            (output_merger.stencil_test.op_fail_stencil() != StencilTest::Op::Keep ||
            output_merger.stencil_test.op_pass_stencil_fail_depth() != StencilTest::Op::Keep ||
            output_merger.stencil_test.op_pass_both() != StencilTest::Op::Keep)) {
            // TODO: Poochy & Yoshi's Woolly World hit this quickly within the first level
            // throw Mikage::Exceptions::NotImplemented("Cannot perform stencil test without stencil buffer write access");
        }
        if ((output_merger.depth_test_enable && output_merger.depth_test_func != DepthFunc::Always) ||
            output_merger.stencil_test.enabled() ||
            (fb_registers.depth_stencil_write_enabled() && output_merger.depth_write_enable)) {
            auto ds_format = ToGenericFormat(fb_registers.GetDepthStencilFormat());
            depth_stencil_range.num_bytes = TextureSize(ds_format, fb_registers.GetWidth(), fb_registers.GetHeight());
        }
        // TODO: If rendering to a memory area that covers existing render targets, make sure to invalidate those!
        //       This blocks GPU-accelerated display transfers in SM3DL
//        fmt::print(stderr, "Rendering to color memory range {:#x}-{:#x} ({}x{})", color_range.start, color_range.start + color_range.num_bytes, fb_registers.GetWidth(), fb_registers.GetHeight());
//        if (depth_stencil_range.num_bytes) {
//            fmt::print(stderr, " (DS {:#x}-{:#x})", depth_stencil_range.start, depth_stencil_range.start + depth_stencil_range.num_bytes);
//        }
//        fmt::print(stderr, "\n");
        // TODO: If color read/write access are disabled (or if write access and alpha test are disabled), we can skip preparing the color render target
        // TODO: Factor in scissor rect / viewport for the relevant memory range
        auto& color_resource = resource_manager->PrepareRenderTarget(
                                                            color_range,
                                                            fb_registers.GetWidth(), fb_registers.GetHeight(),
                                                            ToGenericFormat(fb_registers.GetColorFormat()));
        RenderTargetResource* depth_resource = nullptr;
        if (depth_stencil_range.num_bytes) {
            depth_resource = &resource_manager->PrepareRenderTarget(
                                                            depth_stencil_range,
                                                            fb_registers.GetWidth(), fb_registers.GetHeight(),
                                                            ToGenericFormat(fb_registers.GetDepthStencilFormat()));
        }

        return { &color_resource, depth_resource };
    }();
    // NOTE: LinkRenderTargets may return a cached resource that has a
    //       depth buffer. To check if the depth buffer should be used,
    //       depth_fb must be checked instead hence.
    auto& linked_render_targets = resource_manager->LinkRenderTargets(*color_fb, depth_fb);
    TracyCZoneEnd(FBReload);
    submit_activity.GetSubActivity("FB reload").Interrupt();

    submit_activity.GetSubActivity("DescriptorSets").Resume();
    TracyCZoneN(DescriptorSets, "DescriptorSets", true)
    {
        vk::DescriptorSetAllocateInfo desc_set_info {
            *desc_pool,
            1,
            &*pica_render_desc_set_layout
        };
        // TODO: If this fails, wait until a previous batch completes
        std::vector<vk::UniqueDescriptorSet> desc_sets;
        while (desc_sets.empty()) {
//            if (occupied_descriptor_pool_slots + 1 > descriptor_pool_size) {
//                // Wait for any of the pending renders to complete, then try again.
            // TODO: With proper accounting in occupied_descriptor_pool_slots, the following line should just work!
            // TODO: With the AwaitTriangleBatches refactor, the accounting should hopefully be good!
//                AwaitTriangleBatches(context);
//                desc_sets = device.allocateDescriptorSetsUnique(desc_set_info);
            try {
                desc_sets = device.allocateDescriptorSetsUnique(desc_set_info);
//            } catch (vk::OutOfPoolMemoryError&) {
            } catch (...) { // NOTE: This one will catch both vk::OutOfPoolMemoryError vk::FragmentedPoolError
                // Wait for any of the pending renders to complete, then try again.
                AwaitTriangleBatches(context);
            }
        }
        batch.desc_set = std::move(desc_sets[0]);
    }

    // Update descriptor sets. NOTE: Must be done before creating the pipeline!
    {
        auto next_pica_uniform_buffer_offset = (pica_uniform_buffer_offset + total_uniform_data_size + 63) & ~63; // TODO: Use minUniformBufferOffsetAlignment instead
        if (next_pica_uniform_buffer_offset >= pica_uniform_buffer_info.size) {
            // TODO: Wait for previous renders to complete
            pica_uniform_buffer_offset = 0;
            next_pica_uniform_buffer_offset = (pica_uniform_buffer_offset + total_uniform_data_size + 63) & ~63; // TODO: Use minUniformBufferOffsetAlignment instead
        }

        std::array<vk::DescriptorImageInfo, 3> tex_desc_image_info;

        std::array<vk::WriteDescriptorSet, 3> desc_writes;
        ranges::transform(  ranges::views::indices(static_cast<uint32_t>(desc_writes.size())),
                            desc_writes.begin(),
                            [&](auto index) {
                                return  vk::WriteDescriptorSet {
                                            *batch.desc_set,
                                            base_texture_binding + index,
                                            0,
                                            1,
                                            vk::DescriptorType::eCombinedImageSampler,
                                            &tex_desc_image_info[index],
                                            nullptr,
                                            nullptr
                                        };
                            });

        // 1 uniform buffer, 3 texture slots, 24 light LUT slots
        boost::container::static_vector<vk::WriteDescriptorSet, 28> active_desc_writes;
        vk::DescriptorBufferInfo ubo_info {
            *pica_uniform_buffer,
            pica_uniform_buffer_offset,
            total_uniform_data_size
        };
        active_desc_writes.push_back(vk::WriteDescriptorSet {
            *batch.desc_set,
            ubo_binding,
            0,
            1,
            vk::DescriptorType::eUniformBuffer,
            nullptr,
            &ubo_info,
            nullptr
        });
        for (auto* entry : texcache_entries) {
            // TODO: Skip textures that aren't actually active
            for (auto i = 0; i < 3; ++i) {
                auto& texture = (i == 0) ? context.registers.texture0
                              : (i == 1) ? context.registers.texture1
                                         : context.registers.texture2;
                // TODO: Do this more cleanly...

                if (entry->range.start == texture.GetPhysicalAddress()) {
                    vk::SamplerCreateInfo sampler_info {
                        vk::SamplerCreateFlags { },
                        FromPicaState(texture.mag_filter),
                        FromPicaState(texture.min_filter),
                        vk::SamplerMipmapMode::eNearest, // TODO: Use mip_filter!
                        FromPicaState(texture.wrap_s),
                        FromPicaState(texture.wrap_t), // TODO: Does this produce correct semantics, considering Pica t coordinates are flipped?
                        vk::SamplerAddressMode::eRepeat,
                        0.f, // LOD bias
                        false, // anisotropic filter
                        0.f, // anisotropic filter
                        false, // compare enable
                        vk::CompareOp::eNever,
                        0.f, // min LOD
                        0.f, // max LOD
                        vk::BorderColor::eFloatTransparentBlack,
                        false // unnormalized coordinates
                    };
                    uint32_t sampler_params =
                            (Meta::to_underlying(texture.wrap_s.Value())) |
                            (Meta::to_underlying(texture.wrap_t.Value()) << 4) |
                            (Meta::to_underlying(texture.mag_filter.Value()) << 8) |
                            (Meta::to_underlying(texture.min_filter.Value()) << 12);
                    memcpy(&sampler_params, &texture.wrap_s, sizeof(sampler_params));
                    auto sampler_it = texture_samplers.find(sampler_params);
                    if (sampler_it == texture_samplers.end()) {
                        auto sampler = device.createSamplerUnique(sampler_info);
                        sampler_it = texture_samplers.emplace(sampler_params, std::move(sampler)).first;
                    }

                    tex_desc_image_info[i] = { *sampler_it->second, *entry->image_view, vk::ImageLayout::eShaderReadOnlyOptimal };
                    active_desc_writes.push_back(desc_writes[i]);
                }
            }
        }

        // Set up uniform texel buffers for light LUTs
        if (!context.registers.lighting.config.LUTConfigConsistent()) {
            // Hit in steel diver on startup!
            // throw Mikage::Exceptions::Invalid("Inconsistent lighting configuration: Attempted to read disabled LUTs");
        }
        const uint32_t used_luts = context.registers.lighting.disabled() ? 0 : context.registers.lighting.config.GetEnabledLUTMask();

        for (unsigned lut_index = 0; lut_index < 24; ++lut_index) {
            if (!(used_luts & (1 << lut_index))) {
                continue;
            }
            if (lut_index == 2 || lut_index == 7) {
                // These LUTs don't seem to exist on hardware
                continue;
            }

            active_desc_writes.push_back(
                vk::WriteDescriptorSet {
                    *batch.desc_set,
                    base_light_lut_binding + lut_index,
                    0,
                    1,
                    vk::DescriptorType::eUniformTexelBuffer,
                    nullptr,
                    nullptr,
                    &*pica_light_lut_buffer_views[pica_light_lut_slot_next]
                });

            // Update data in memory
            // TODO: Actually only upload it if it changed!
            auto* lut_data_ptr = reinterpret_cast<char*>(device.mapMemory(*pica_light_lut_memory, pica_light_lut_slot_next * pica_lut_data_slot_size, pica_lut_data_slot_size));
            for (unsigned entry = 0; entry < 256; ++entry) {
                int16_t data[2];
                data[0] = context.light_lut_data[lut_index].data()[entry] & 0xfff;
                data[1] = (context.light_lut_data[lut_index].data()[entry] >> 12) & 0xfff;
                if (data[1] & 0x800) {
                    data[1] = -static_cast<int>(data[1] & 0x7ff);
                }
                memcpy(lut_data_ptr, data, sizeof(data));
                lut_data_ptr += sizeof(data);
            }
            device.unmapMemory(*pica_light_lut_memory);

            ++pica_light_lut_slot_next;

            if (pica_light_lut_slot_next >= pica_light_lut_buffer_views.size()) {
                // Wait for previous renders to complete
                AwaitTriangleBatches(context);
                pica_light_lut_slot_next = 0;
            }
        }

        if (active_desc_writes.size()) {
            device.updateDescriptorSets(active_desc_writes, {});
        }

        // Upload new uniform data
        // TODO: Actually only upload it if it changed!
        auto* const ubo_data = reinterpret_cast<char*>(device.mapMemory(*pica_uniform_memory, pica_uniform_buffer_offset, total_uniform_data_size));
        auto* ubo_data_ptr = ubo_data;
        memcpy(ubo_data_ptr, context.shader_uniforms.f.data(), sizeof(context.shader_uniforms.f));
        ubo_data_ptr += sizeof(context.shader_uniforms.f);
        for (auto& uniform : context.shader_uniforms.i) {
            // Expand components from 8 bit to 32 bit
            for (uint32_t comp : { uniform.x, uniform.y, uniform.z, uniform.w }) {
                memcpy(ubo_data_ptr, &comp, sizeof(comp));
                ubo_data_ptr += sizeof(comp);
            }
        }

        // Make sure we did not forget any vertex shader data
        ValidateContract(ubo_data_ptr == ubo_data + vs_uniform_data_size);

        {
            auto& cb_init = context.registers.combiner_buffer_init;
            for (uint32_t val : { cb_init.r()(), cb_init.g()(), cb_init.b()(), cb_init.a()() }) {
                memcpy(ubo_data_ptr, &val, sizeof(val));
                ubo_data_ptr += sizeof(val);
            }

            const auto tev_stages = context.registers.GetTevStages();
            for (auto& tev_stage : tev_stages) {
                for (uint32_t val : { tev_stage.const_r()(), tev_stage.const_g()(), tev_stage.const_b()(), tev_stage.const_a()() }) {
                    memcpy(ubo_data_ptr, &val, sizeof(val));
                    ubo_data_ptr += sizeof(val);
                }
            }

            auto& global_ambient = context.registers.lighting.global_ambient;
            for (uint32_t val : { global_ambient.red()(), global_ambient.green()(), global_ambient.blue()(), uint32_t { 0 } }) {
                float float_val = val / 255.f;
                memcpy(ubo_data_ptr, &float_val, sizeof(float_val));
                ubo_data_ptr += sizeof(float_val);
            }

            for (auto& light : context.registers.lighting.lights) {
                for (uint32_t val : { light.ambient.red()(), light.ambient.green()(), light.ambient.blue()(), uint32_t { 0 } }) {
                    float float_val = val / 255.f;
                    memcpy(ubo_data_ptr, &float_val, sizeof(float_val));
                    ubo_data_ptr += sizeof(float_val);
                }

                for (uint32_t val : { light.diffuse.red()(), light.diffuse.green()(), light.diffuse.blue()(), uint32_t { 0 } }) {
                    float float_val = val / 255.f;
                    memcpy(ubo_data_ptr, &float_val, sizeof(float_val));
                    ubo_data_ptr += sizeof(float_val);
                }

                for (float val : { light.get_light_dir_x().ToFloat32(), light.get_light_dir_y().ToFloat32(), light.get_light_dir_z().ToFloat32(), 0.f }) {
                    memcpy(ubo_data_ptr, &val, sizeof(val));
                    ubo_data_ptr += sizeof(val);
                }

                for (auto& specular_rgb : light.specular) {
                    for (uint32_t val : { specular_rgb.red()(), specular_rgb.green()(), specular_rgb.blue()(), uint32_t { 0 } }) {
                        memcpy(ubo_data_ptr, &val, sizeof(val));
                        ubo_data_ptr += sizeof(val);
                    }
                }

                for (uint32_t val : { light.spot_dir_x()(), light.spot_dir_y()(), light.spot_dir_z()(), 0 }) {
                    memcpy(ubo_data_ptr, &val, sizeof(val));
                    ubo_data_ptr += sizeof(val);
                }
            }

            for (auto& texture : context.registers.GetTextures()) {
                auto& border_color = texture.config.border_color;
                for (float val : { border_color.r()(), border_color.g()(), border_color.b()(), border_color.a()() }) {
                    memcpy(ubo_data_ptr, &val, sizeof(val));
                    ubo_data_ptr += sizeof(val);
                }
            }

            // Make sure we did not forget any data
            ValidateContract(ubo_data_ptr == ubo_data + total_uniform_data_size);
        }
        device.unmapMemory(*pica_uniform_memory);

        pica_uniform_buffer_offset = next_pica_uniform_buffer_offset;
    }

    TracyCZoneEnd(DescriptorSets);
    submit_activity.GetSubActivity("DescriptorSets").Interrupt();

    auto& pipeline_activity = submit_activity.GetSubActivity("PipelineCreation");
    TracyCZoneN(PipelineCreate, "Pipeline Create", true)
    pipeline_activity.Resume();
    auto pipeline = std::invoke([&](Context& context) -> vk::Pipeline {
        TracyCZoneN(ShaderCompile, "Shader Compile", true)
        pipeline_activity.GetSubActivity("ShaderCompile").Resume();
        auto vertex_shader_code = GenerateVertexShader(context, shader_engine);
        auto fragment_shader_code = GenerateFragmentShader(context);

        auto vertex_shader = std::invoke([&] {
            auto& shader = shader_cache[0][vertex_shader_code];
            if (!shader) {
                auto shader_spv = CompileShader(EShLangVertex, vertex_shader_code.c_str(), "main");

                vk::ShaderModuleCreateInfo shader_module_info {
                    vk::ShaderModuleCreateFlags { }, shader_spv.size() * sizeof(shader_spv.data()[0]), shader_spv.data()
                };
                shader = device.createShaderModuleUnique(shader_module_info);
            }
            return *shader;
        });
        auto pixel_shader = std::invoke([&] {
            auto& shader = shader_cache[1][fragment_shader_code];
            if (!shader) {
                auto shader_spv = CompileShader(EShLangFragment, fragment_shader_code.c_str(), "main");

                vk::ShaderModuleCreateInfo shader_module_info {
                    vk::ShaderModuleCreateFlags { }, shader_spv.size() * sizeof(shader_spv.data()[1]), shader_spv.data()
                };
                shader = device.createShaderModuleUnique(shader_module_info);
            }
            return *shader;
        });
        TracyCZoneEnd(ShaderCompile)
        pipeline_activity.GetSubActivity("ShaderCompile").Interrupt();

        vk::PipelineVertexInputStateCreateInfo vertex_input_info {
            vk::PipelineVertexInputStateCreateFlags { },
            static_cast<uint32_t>(vertex_binding_descs.size()), vertex_binding_descs.data(),
            static_cast<uint32_t>(vertex_attribute_descs.size()), vertex_attribute_descs.data()
        };

        return pipeline_cache->Lookup(pipeline_activity, linked_render_targets, *layout, vertex_shader, pixel_shader, vertex_input_info, context.registers);
    }, context);

    TracyCZoneEnd(PipelineCreate)
    pipeline_activity.Interrupt();

    submit_activity.GetSubActivity("CommandBuffer").Resume();
    TracyCZoneN(CommandBuffer, "Record Command Buffer", true);

    {
        resource_manager->UploadStagedDataToHost(*command_buffer);

        vk::RenderPassBeginInfo renderpass_info {   *linked_render_targets.renderpass,
                                                    *linked_render_targets.fb,
                                                    vk::Rect2D { vk::Offset2D { 0, 0 }, vk::Extent2D { color_fb->info.extent.width, color_fb->info.extent.height }},
                                                    0, nullptr // clear values
                                                };
        command_buffer->beginRenderPass(renderpass_info, vk::SubpassContents::eInline);

        command_buffer->bindPipeline(vk::PipelineBindPoint::eGraphics, pipeline);

        command_buffer->bindDescriptorSets(vk::PipelineBindPoint::eGraphics, *layout, 0, 1, &*batch.desc_set, 0, nullptr);

        if (is_indexed) {
            // TODO: Look into native 8-bit index support
            command_buffer->bindIndexBuffer(*vertex_buffer, vertex_buffer_offset, vk::IndexType::eUint16);
        }

        for (auto& vertex_binding : vertex_binding_descs) {
            command_buffer->bindVertexBuffers(vertex_binding.binding, { *vertex_buffer }, { vertex_binding_offset[vertex_binding.binding] });
        }
        uint32_t first_vertex = 0;
        if (is_indexed) {
            command_buffer->drawIndexed(context.registers.num_vertices, 1 /* instance count */, first_vertex, -min_vertex_index /* vertex offset */, 0 /* first instance */);
        } else {
            command_buffer->draw(num_vertices, 1 /* instance count */, first_vertex, 0 /* first instance */);
        }
        // TODO: Use actual vertex size
        vertex_buffer_offset = next_vertex_buffer_offset;
        vertex_buffer_offset = (vertex_buffer_offset + 0xff) >> 8 << 8; // TODO: Use nonCoherentAtomSize instead

        command_buffer->endRenderPass();

        resource_manager->InvalidateOverlappingResources(*color_fb);
        // Invalidate data overlapping with the depth buffer only if we expect depth/stencil to be modified
        if (depth_fb && context.registers.framebuffer.depth_stencil_write_enabled() &&
            (context.registers.output_merger.stencil_test.enabled() || context.registers.output_merger.depth_write_enable)) {
            resource_manager->InvalidateOverlappingResources(*depth_fb);
        }

        color_fb->ProtectBackingEmulatedMemory(*context.mem, *resource_manager);
        if (depth_fb) {
            depth_fb->ProtectBackingEmulatedMemory(*context.mem, *resource_manager);
        }
    }

    TracyCZoneEnd(CommandBuffer);
    } // GuardedDebugMarker
    submit_activity.GetSubActivity("CommandBuffer").Interrupt();

    submit_activity.GetSubActivity("Submit").Resume();
    TracyCZoneN(Submit, "Submit", true);

    for (auto* entry : texcache_entries) {
        entry->access_guard = batch.fence_awaitable;
    }

    TracyCZoneEnd(Submit);
    submit_activity.GetSubActivity("Submit").Interrupt();
#endif

//    printf("TRACE: QUEUE SUBMIT\n");
    activity->Interrupt();
} catch (std::exception& exc) {
    printf("EXCEPTION: %s\n", exc.what());
    throw;
}

void Renderer::FlushTriangleBatches(Context& context) try {
    triangle_batches.push_back(*std::exchange(pending_batch, std::nullopt));
    auto& batch = triangle_batches.back();

    batch.command_buffer->end();

    {
        vk::PipelineStageFlags submit_wait_flags = vk::PipelineStageFlagBits::eAllGraphics;
        vk::SubmitInfo submit_info { 0, nullptr, &submit_wait_flags, 1, &*batch.command_buffer, 0, nullptr };

        std::unique_lock lock(g_vulkan_queue_mutex);
        (void)graphics_queue.submit(1, &submit_info, *batch.fence);
    }
} catch (std::exception& exc) {
    printf("EXCEPTION: %s\n", exc.what());
    throw;
}

void Renderer::FinalizeTriangleBatch(Context& context, const VertexShader::ShaderEngine& shader_engine, bool is_indexed) try {
    BeginTriangleBatch(context);
    FinalizeTriangleBatchInternal(context, shader_engine, is_indexed);
    FlushTriangleBatches(context);
} catch (std::exception& exc) {
    printf("EXCEPTION: %s\n", exc.what());
    throw;
}

void Renderer::InvalidateRange(PAddr start, uint32_t num_bytes) {
//    std::cerr << fmt::format("Renderer::InvalidateRange: {:#x}-{:#x}\n", start, start + num_bytes);
    resource_manager->InvalidateRange(start, num_bytes);
}

void Renderer::FlushRange(PAddr start, uint32_t num_bytes) {
//    activity.GetSubActivity("FB flush").Resume();
//    BOOST_SCOPE_EXIT(&activity) { activity.Interrupt(); } BOOST_SCOPE_EXIT_END;

    resource_manager->FlushRange(start, num_bytes);
}

bool Renderer::BlitImage(Context& context, uint32_t /* TODO: PAddr */ input_addr, uint32_t input_width, uint32_t input_height, uint32_t input_stride, uint32_t input_format_raw,
                         uint32_t output_addr, uint32_t output_width, uint32_t output_height, uint32_t output_stride, uint32_t output_format_raw, bool flip_y) {
    if (output_addr == 0) {
        // TODO: Super Street Fighter 4 hits this, but it's likely a bug elsewhere
        return true;
    }
    // TODO: When copying from a depth buffer, adapt the parameters for this!
    auto input_format = ToGenericFormat(GPU::Regs::FramebufferFormat { input_format_raw });
    auto output_format = ToGenericFormat(GPU::Regs::FramebufferFormat { output_format_raw });

    MemoryRange input_range { input_addr, input_stride * input_height };
    MemoryRange output_range { output_addr, output_stride * output_height };

    fmt::print("BlitImage: {}x{} -> {}x{}, {} -> {}, addr {:#x} -> {:#x}\n",
              input_width, input_height, output_width, output_height,
              input_format, output_format,
              input_addr, output_addr);

    const auto host_input_width = input_stride * 2 / NibblesPerPixel(input_format);
    auto [input, input_start_y, input_end_y] = resource_manager->PrepareToCopyRenderTargetArea(input_range, host_input_width, input_height, input_format, input_stride);
    ValidateContract(input_end_y - input_start_y == input_height);
    auto& output = resource_manager->PrepareRenderTarget(output_range, output_width, output_height, output_format);

    // Wait for blit resources to become available again
    auto& completion_fence = blit_resources[next_blit_resource].completion_fence;
    (void)device.waitForFences({ *completion_fence }, true, std::numeric_limits<uint64_t>::max());
    device.resetFences({ *completion_fence });
    auto& [command_buffer, command_buffer2] = blit_resources[next_blit_resource].command_buffers;
    ++next_blit_resource %= blit_resources.size();

    {
        vk::CommandBufferBeginInfo begin_info { /*vk::CommandBufferUsageFlagBits::eSimultaneousUse | */vk::CommandBufferUsageFlagBits::eOneTimeSubmit };
        command_buffer2->reset({});
        command_buffer2->begin(begin_info);
        {
        GuardedDebugMarker debug_guard(*command_buffer2, "Upload staged data for BlitImage");
        resource_manager->UploadStagedDataToHost(*command_buffer2);
        }
        command_buffer2->end();
    }

    {
        vk::CommandBufferBeginInfo begin_info { /*vk::CommandBufferUsageFlagBits::eSimultaneousUse | */vk::CommandBufferUsageFlagBits::eOneTimeSubmit };
        command_buffer->reset({});
        command_buffer->begin(begin_info);
        {
        GuardedDebugMarker debug_guard(*command_buffer, fmt::format("BlitImage: {:#x} -> {:#x}, {}x{} -> {}x{}", input_addr, output_addr, input_width, input_height, output_width, output_height).c_str());

        TransitionImageLayout(*command_buffer, *input.image, GetVkImageSubresourceRange(input),
                                { input.image_layout, vk::PipelineStageFlagBits::eColorAttachmentOutput, vk::AccessFlagBits::eColorAttachmentWrite | vk::AccessFlagBits::eColorAttachmentRead },
                              ImageLayoutTransitionPoint::ToTransferSrcGeneral());

        TransitionImageLayout(*command_buffer, *output.image, GetVkImageSubresourceRange(output),
                              { output.image_layout, vk::PipelineStageFlagBits::eColorAttachmentOutput, vk::AccessFlagBits::eColorAttachmentWrite | vk::AccessFlagBits::eColorAttachmentRead },
                              ImageLayoutTransitionPoint::ToTransferDstGeneral());

        auto full_image = vk::ImageSubresourceLayers { vk::ImageAspectFlagBits::eColor, 0, 0, 1 };
        const auto input_start_offset = vk::Offset3D { 0, static_cast<int32_t>(flip_y ? input_end_y : input_start_y), 0 };
        const auto output_start_offset = vk::Offset3D { 0, 0, 0 };
        const auto input_end_offset = vk::Offset3D { static_cast<int32_t>(input_width), static_cast<int32_t>(flip_y ? input_start_y : input_end_y), 1 };
        const auto output_end_offset = vk::Offset3D { static_cast<int32_t>(output_width), static_cast<int32_t>(output_height), 1 };
        {
            // Validate that in each dimension, we're either copying 1:1 or scaling 2:1
            const auto copied_input_width = input_end_offset.x - input_start_offset.x;
            const auto copied_input_height = std::abs(input_start_offset.y - input_end_offset.y);
            const auto copied_output_width = output_end_offset.x - output_start_offset.x;
            const auto copied_output_height = output_end_offset.y - output_start_offset.y;
            if ((copied_input_width != copied_output_width && copied_input_width != copied_output_width * 2) ||
                (copied_input_height != copied_output_height && copied_input_height != copied_output_height * 2)) {
                throw Mikage::Exceptions::NotImplemented(   "Tried to BlitImage from {}x{} to {}x{}, but only copies and 1:2 downscales are supported",
                                                            input_end_offset.x, input_end_offset.y,
                                                            output_end_offset.x, output_end_offset.y);
            }
        }
        vk::ImageBlit copy_region {
            full_image, { input_start_offset, input_end_offset }, full_image, { output_start_offset, output_end_offset }
        };
        // TODO: Emulate loss of precision
        command_buffer->blitImage(*input.image, vk::ImageLayout::eGeneral, *output.image, vk::ImageLayout::eGeneral, { copy_region }, vk::Filter::eLinear);

        TransitionImageLayout(*command_buffer, *input.image, GetVkImageSubresourceRange(input),
                              ImageLayoutTransitionPoint::FromTransferSrcGeneral(),
                              ImageLayoutTransitionPoint::ToColorAttachmentOutput());

        TransitionImageLayout(*command_buffer, *output.image, GetVkImageSubresourceRange(output),
                              ImageLayoutTransitionPoint::FromTransferDstGeneral(),
                              ImageLayoutTransitionPoint::ToColorAttachmentOutput());

        output.ProtectBackingEmulatedMemory(*context.mem, *resource_manager);

        // TODO: Transition to color/depth attachment
        input.image_layout = vk::ImageLayout::eColorAttachmentOptimal;
        output.image_layout = vk::ImageLayout::eColorAttachmentOptimal;

        }
        command_buffer->end();
    }

    {
        vk::PipelineStageFlags submit_wait_flags = vk::PipelineStageFlagBits::eTransfer;
        vk::SubmitInfo submit_info {
            0, nullptr,
            &submit_wait_flags, 1, &*command_buffer, 0, nullptr };

        std::unique_lock lock(g_vulkan_queue_mutex);
        (void)graphics_queue.submit(1, &submit_info, *completion_fence);
    }

    resource_manager->InvalidateOverlappingResources(output);

    return true;
}

} // namespace Vulkan

} // namespace Pica
