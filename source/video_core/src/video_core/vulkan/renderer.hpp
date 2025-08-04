#pragma once

#include "../renderer.hpp"
#include "display.hpp"
#include "awaitable.hpp"

#include <vulkan_utils/memory_types.hpp>
#include <optional>

#include <vulkan/vulkan.hpp>

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

namespace spdlog {
class logger;
}

namespace vk {
class Device;
}

namespace Profiler {
namespace Activities {
struct GPU;
}
class Profiler;
template<typename> struct TaggedActivity;
}

namespace EmuDisplay {
struct EmuDisplay;
struct Frame;
}

namespace Pica {

namespace Vulkan {

class PipelineCache;
class ResourceManager;

class Renderer final : public Pica::Renderer {
public:
    Renderer(Memory::PhysicalMemory&, std::shared_ptr<spdlog::logger>, Profiler::Profiler&, vk::PhysicalDevice, vk::Device, uint32_t graphics_queue_index, vk::Queue graphics_queue);
    ~Renderer();

private:
    void ProduceFrame(EmuDisplay::EmuDisplay&, EmuDisplay::Frame&, Memory::PhysicalMemory&, EmuDisplay::DataStreamId, uint32_t addr, uint32_t stride, EmuDisplay::Format) override;

    void PrepareTriangleBatch(Context&, const VertexShader::ShaderEngine&, uint32_t max_triangles, bool is_indexed) override;

    void AddPreassembledTriangle(Context& context, VertexShader::OutputVertex &v0, VertexShader::OutputVertex &v1, VertexShader::OutputVertex &v2) override;
    void AddVertex(Context& context, uint32_t num_attributes, VertexShader::InputVertex&) override;

    template<bool>
    friend void DoAddTriangle(Renderer& renderer, Context&, VertexShader::OutputVertex& v0, VertexShader::OutputVertex& v1, VertexShader::OutputVertex& v2);

    void BeginTriangleBatch(Context&);
    void FinalizeTriangleBatch(Context&, const VertexShader::ShaderEngine&, bool is_indexed) override;
    void FinalizeTriangleBatchInternal(Context&, const VertexShader::ShaderEngine&, bool is_indexed);
    void FlushTriangleBatches(Context&); // TODO: Rename to SubmitPending?
    void AwaitTriangleBatches(Context&); // TODO: Should this flush any pending batch? TODO: Better interface to await for specific resources to become free?

    void InvalidateRange(uint32_t /* TODO: PAddr */ start, uint32_t num_bytes) override;
    void FlushRange(uint32_t /* TODO: PAddr */ start, uint32_t num_bytes) override;

    bool BlitImage(Context&, uint32_t /* TODO: PAddr */ input_addr, uint32_t input_width, uint32_t input_height, uint32_t input_stride,
                   uint32_t input_format, uint32_t output_addr, uint32_t output_width, uint32_t output_height, uint32_t output_stride,
                   uint32_t output_format, bool flip_y) override;

    std::shared_ptr<spdlog::logger> logger;
    Profiler::Profiler& profiler;
    Profiler::TaggedActivity<Profiler::Activities::GPU>& activity;

    vk::Device device;
    uint32_t graphics_queue_index;
    vk::Queue graphics_queue;

    MemoryTypeDatabase memory_types;

    std::unique_ptr<ResourceManager> resource_manager;

    // Indexed by raw texture configuration
    std::unordered_map<uint32_t, vk::UniqueSampler> texture_samplers;

    std::array<std::unordered_map<std::string, vk::UniqueShaderModule>, 2> shader_cache;
    vk::UniqueDescriptorPool desc_pool;
    vk::UniqueDescriptorSetLayout pica_render_desc_set_layout;

    vk::UniquePipelineLayout layout;

    vk::UniqueCommandPool command_pool;
    std::vector<vk::UniqueCommandBuffer> command_buffers;

    vk::UniqueBuffer vertex_buffer;
    vk::UniqueDeviceMemory vertex_buffer_memory;
    vk::DeviceSize vertex_buffer_offset = 0;
    vk::DeviceSize next_vertex_buffer_offset = 0; // TODO: This is state that can be solely kept in FinalizeTriangleBatch!
    std::array<vk::DeviceSize, 13> vertex_binding_offset {}; // 13th offset reserved for default attribute data

    std::vector<vk::VertexInputBindingDescription> vertex_binding_descs;
    std::vector<vk::VertexInputAttributeDescription> vertex_attribute_descs;

    uint32_t num_vertices = 0;
    char* next_vertex_ptr = nullptr;

    vk::BufferCreateInfo pica_uniform_buffer_info;
    vk::UniqueBuffer pica_uniform_buffer;
    vk::UniqueDeviceMemory pica_uniform_memory;
    vk::DeviceSize pica_uniform_buffer_offset = 0;

    // vk::BufferCreateInfo pica_light_lut_buffer_info;
    vk::UniqueBuffer pica_light_lut_buffer;
    vk::UniqueDeviceMemory pica_light_lut_memory;
    std::array<vk::UniqueBufferView, 48> pica_light_lut_buffer_views;
    vk::DeviceSize pica_light_lut_slot_next = 0; // next buffer view to write data to
    // 256 entries, each a pair of 16-bit integers
    static constexpr unsigned pica_lut_data_slot_size = 256 * sizeof(uint16_t) * 2;

    std::unique_ptr<PipelineCache> pipeline_cache;

    struct TriangleBatchInFlight {
        // TODO: vertex buffer offset/size

        vk::UniqueCommandBuffer command_buffer;

        vk::UniqueDescriptorSet desc_set;

        vk::UniqueFence fence;

        CPUAwaitable fence_awaitable;
    };
    std::optional<TriangleBatchInFlight> pending_batch;
    std::vector<TriangleBatchInFlight> triangle_batches;

    struct BlitResources {
        // TODO: Having two separate command buffers shouldn't be necessary
        std::array<vk::UniqueCommandBuffer, 2> command_buffers;
        vk::UniqueFence completion_fence;
    };

    std::array<BlitResources, 5> blit_resources;
    int next_blit_resource = 0;
};

} // namespace Vulkan

} // namespace Pica
