#pragma once

#include <vulkan/vulkan.hpp>

#include <functional>

namespace spdlog {
class logger;
}

struct VulkanInstanceManager {
#if VK_HEADER_VERSION >= 301
    vk::detail::DynamicLoader vulkan_loader;
#else
    vk::DynamicLoader vulkan_loader;
#endif
    vk::UniqueInstance instance;

    VulkanInstanceManager(spdlog::logger&, const char* app_name, const std::vector<const char*>& required_instance_extensions);
};

struct VulkanDeviceManager {
    vk::PhysicalDevice physical_device;
    vk::UniqueDevice device;

    uint32_t present_queue_index;
    uint32_t graphics_queue_index;
    vk::Queue present_queue;
    vk::Queue graphics_queue;

    VulkanDeviceManager(VulkanInstanceManager&, spdlog::logger&, vk::SurfaceKHR, bool is_wayland);
};

/**
 * Check if we're running inside of RenderDoc
 */
bool IsRenderDocActive();
