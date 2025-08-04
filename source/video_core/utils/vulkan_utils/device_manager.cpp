#define VULKAN_HPP_DISPATCH_LOADER_DYNAMIC 1
#define VK_ENABLE_BETA_EXTENSIONS // For vk::PhysicalDevicePortabilitySubsetFeaturesKHR

#include "device_manager.hpp"

#include <spdlog/logger.h>

#include <range/v3/algorithm/find_if.hpp>
#include <range/v3/front.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/filter.hpp>
#include <range/v3/view/iota.hpp>
#include <range/v3/view/take.hpp>

#include <iostream>
#include <optional>

#ifdef _WIN32
#include <windows.h> // Required for GetModuleHandleA
#endif

VULKAN_HPP_DEFAULT_DISPATCH_LOADER_DYNAMIC_STORAGE

// TODO: Make runtime-configurable
inline constexpr bool enable_debug_exts = false;

VulkanInstanceManager::VulkanInstanceManager(spdlog::logger& logger, const char* app_name, const std::vector<const char*>& required_instance_extensions) {
    auto get_proc_addr = vulkan_loader.getProcAddress<PFN_vkGetInstanceProcAddr>("vkGetInstanceProcAddr");
    VULKAN_HPP_DEFAULT_DISPATCHER.init(get_proc_addr);

    vk::ApplicationInfo application_info { app_name, VK_MAKE_VERSION(0, 1, 0), nullptr, VK_MAKE_VERSION(1, 0, 0), VK_API_VERSION_1_0 };

    // TODO: Enumerate instance extensions that are actually supported here

    instance = std::invoke([&]() {
        std::vector<const char*> enabled_layers = { };
        if (enable_debug_exts) {
            enabled_layers.push_back("VK_LAYER_KHRONOS_validation");
        }
        for (auto ext : required_instance_extensions) {
            logger.info("Requesting instance extension \"{}\"", ext);
        }
#ifdef __APPLE__
        auto flags = vk::InstanceCreateFlagBits::eEnumeratePortabilityKHR;
#else
        auto flags = vk::InstanceCreateFlagBits {};
#endif
        vk::InstanceCreateInfo info { flags, &application_info,
                                    static_cast<uint32_t>(std::size(enabled_layers)), enabled_layers.data(),
                                    static_cast<uint32_t>(std::size(required_instance_extensions)), required_instance_extensions.data() };
        return vk::createInstanceUnique(info);
    });

    VULKAN_HPP_DEFAULT_DISPATCHER.init(*instance);
}

bool IsRenderDocActive() {
    #ifndef _WIN32
    // Check if the RenderDoc shared library is loaded (note the use of RTLD_NOLOAD)

    auto renderdoc_so = dlopen("librenderdoc.so", RTLD_NOW | RTLD_NOLOAD);
    if (!renderdoc_so) {
        // Used on Android
        renderdoc_so = dlopen("libVkLayer_GLES_RenderDoc.so", RTLD_NOW | RTLD_NOLOAD);
    }
    bool is_active = (renderdoc_so != nullptr);
    if (renderdoc_so) {
        dlclose(renderdoc_so);
    }
    return is_active;
    #else
    // Check if the RenderDoc DLL is loaded on Windows
    auto renderdoc_dll = GetModuleHandleA("renderdoc.dll");
    return renderdoc_dll != nullptr;
    #endif
}

VulkanDeviceManager::VulkanDeviceManager(VulkanInstanceManager& instance, spdlog::logger& logger, vk::SurfaceKHR surface, bool is_wayland) {
    physical_device = std::invoke([&]() {
        auto physical_devices = instance.instance->enumeratePhysicalDevices();
        for (auto& phys_device : physical_devices) {
            auto properties = phys_device.getProperties();
            std::cerr << "Found device: \"" << properties.deviceName << "\"" << std::endl;
        }
        if (physical_devices.empty()) {
            throw std::runtime_error("Found no physical Vulkan devices");
        }

        // TODO: Do more sophisticated feature checks
        return std::move(physical_devices[0]);
    });

    // NOTE: Adreno tends to have 3 "universal" queues (GRAPHICS|COMPUTE|PRESENT), Mali has 2 (GRAPHICS|COMPUTE|TRANSFER|PRESENT)
    //       On Desktop, Intel and AMD only support 1 graphics queue
    auto queue_families = physical_device.getQueueFamilyProperties();
    for (uint32_t i = 0; i < queue_families.size(); ++i) {
        auto& queue_family = queue_families[i];
        std::cerr << "Queue family: " << vk::to_string(queue_family.queueFlags);
        if (physical_device.getSurfaceSupportKHR(i, vk::SurfaceKHR { surface })) {
            std::cerr << ", supports presentation";
        }
        std::cerr << ", " << std::dec << queue_family.queueCount << " queues";
        std::cerr << std::endl;
    }

    // Setup queue family indexes.
    // Ideally, pick a single queue that supports both presentation and graphics.
    // Note that access to this "universal" queue from multiple threads must be
    // synchronized using a mutex.
    // NOTE: On Wayland, presentation must currently be done on a separate
    //       queue. This is due to current Wayland releases blocking for vsync
    //       in vkQueuePresentKHR, which prevents the use of mutexes to ensure
    //       thread-safety without starving other threads. Future Wayland
    //       releases as expected to fix this behavior.
    // TODO: If multiple render windows are used, each of them needs their
    //       own present queue.
    {
        auto supports_graphics = [&](size_t idx) { return static_cast<bool>(queue_families[idx].queueFlags & vk::QueueFlagBits::eGraphics); };
        auto supports_present = [&](size_t idx) { return physical_device.getSurfaceSupportKHR(idx, vk::SurfaceKHR { surface }); };
        auto filter_queues = [&](auto&& predicate) {
            return  ranges::views::iota(std::size_t { }, queue_families.size()) | ranges::views::filter(predicate);
        };

        auto universal_queue_index = filter_queues(supports_graphics) | ranges::views::filter(supports_present) | ranges::views::take(1) | ranges::to_vector;
        if (!universal_queue_index.empty() && !is_wayland) {
            graphics_queue_index = present_queue_index = universal_queue_index.front();
        } else {
            auto graphics_queue_indexes = filter_queues(supports_graphics) | ranges::to_vector;
            if (graphics_queue_indexes.size() == 0) {
                throw std::runtime_error("No graphics queues found");
            }

            auto present_queue_indexes = filter_queues(supports_present) | ranges::to_vector;
            if (present_queue_indexes.size() == 0) {
                throw std::runtime_error("No present queues found");
            }

            // Ensure there's a dedicated present queue
            if (present_queue_indexes[0] != graphics_queue_indexes[0]) {
                graphics_queue_index = graphics_queue_indexes[0];
                present_queue_index = present_queue_indexes[0];
            } else if (present_queue_indexes.size() > 1) {
                graphics_queue_index = graphics_queue_indexes[0];
                present_queue_index = present_queue_indexes[1];
            } else if (graphics_queue_indexes.size() > 1) {
                present_queue_index = present_queue_indexes[0];
                graphics_queue_index = graphics_queue_indexes[1];
            } else {
                // TODO: Fall back to a present mode other than VK_PRESENT_MODE_FIFO_KHR
//                throw std::runtime_error("Unsupported hardware: No dedicated present queue found. Please report this as a bug.");
                graphics_queue_index = graphics_queue_indexes[0];
                present_queue_index = present_queue_indexes[0];
            }
        }

        std::cerr << "Using queue " << std::dec << graphics_queue_index << " for rendering and queue " << present_queue_index << " for presentation\n";
    }

    device = std::invoke([&]() {
        float priorities[] = { 1.0 };

        std::vector<vk::DeviceQueueCreateInfo> queue_info;
        queue_info.emplace_back(vk::DeviceQueueCreateFlagBits { }, graphics_queue_index, 1, priorities);
        if (present_queue_index != graphics_queue_index) {
            queue_info.emplace_back(vk::DeviceQueueCreateFlagBits { }, present_queue_index, 1, priorities);
        }

        std::vector<const char*> enabled_layers;
        std::vector<const char*> enabled_extensions = { "VK_KHR_swapchain" };
#ifdef __APPLE__
        enabled_extensions.push_back("VK_KHR_portability_subset");
#endif
        bool debug_markers_enabled = false;
        if (enable_debug_exts || IsRenderDocActive()) {
            auto supported_extensions = physical_device.enumerateDeviceExtensionProperties();
            auto debug_marker_extension_it = ranges::find_if(supported_extensions, [](auto& ext) { return static_cast<std::string_view>(ext.extensionName) == "VK_EXT_debug_marker"; });
            if (debug_marker_extension_it != supported_extensions.end()) {
                enabled_extensions.push_back("VK_EXT_debug_marker");
                debug_markers_enabled = true;
            }
        }
        if (!debug_markers_enabled) {
            // Explicitly null out debugging-related function pointers so we can check for their presence later
            VULKAN_HPP_DEFAULT_DISPATCHER.vkDebugMarkerSetObjectNameEXT = nullptr;
            VULKAN_HPP_DEFAULT_DISPATCHER.vkCmdDebugMarkerBeginEXT = nullptr;
            VULKAN_HPP_DEFAULT_DISPATCHER.vkCmdDebugMarkerEndEXT = nullptr;
        }

        auto supported_features = physical_device.getFeatures();
        auto features = vk::PhysicalDeviceFeatures { };
        if (supported_features.logicOp) {
            features.logicOp = true;
        } else {
            // TODO: Implement fallback
            logger.warn("Warning: GPU driver does not support logic operations.");
        }

        vk::StructureChain<vk::DeviceCreateInfo, vk::PhysicalDevicePortabilitySubsetFeaturesKHR> info {
            vk::DeviceCreateInfo {
                vk::DeviceCreateFlagBits { },
                static_cast<uint32_t>(queue_info.size()), queue_info.data(),
                static_cast<uint32_t>(enabled_layers.size()), enabled_layers.data(),
                static_cast<uint32_t>(enabled_extensions.size()), enabled_extensions.data(),
                &features
            },
            {}
        };
#ifdef __APPLE__
        info.get<vk::PhysicalDevicePortabilitySubsetFeaturesKHR>().constantAlphaColorBlendFactors = true;
#else
        info.unlink<vk::PhysicalDevicePortabilitySubsetFeaturesKHR>();
#endif
        return physical_device.createDeviceUnique(info.get<vk::DeviceCreateInfo>());
    });

    VULKAN_HPP_DEFAULT_DISPATCHER.init(*device);

    graphics_queue = device->getQueue(graphics_queue_index, 0);
    present_queue = device->getQueue(present_queue_index, 0);
}
