cmake_minimum_required(VERSION 3.13)

#if(NOT DEFINED PROJECT_NAME)
#    set(NOT_SUBPROJET ON)
#endif()

project(video_core LANGUAGES CXX)

add_subdirectory(utils/vulkan_utils)

add_library(video_core STATIC)

target_sources(video_core PRIVATE
    src/core/hw/gpu.cpp
    src/video_core/clipper.cpp
    src/video_core/command_processor.cpp
    src/video_core/primitive_assembly.cpp
    src/video_core/rasterizer.cpp
    src/video_core/shader.cpp
    src/video_core/shader_analysis.cpp
    src/video_core/shader_disassembler.cpp
    #src/video_core/shader_glsl.cpp
    src/video_core/shader_interpreter.cpp
    src/video_core/shader_microcode.cpp
    src/video_core/debug_utils/debug_utils.cpp
    src/video_core/vulkan/pipeline_cache.cpp
    src/video_core/vulkan/renderer.cpp
    src/video_core/vulkan/resource_manager.cpp
    src/video_core/vulkan/shader_gen.cpp
    )
if (PISTACHE_FOUND)
    target_sources(video_core PRIVATE src/debug/gpu.cpp)
endif()


target_include_directories(video_core PRIVATE src/support src/ externals/nihstro/include)
target_include_directories(video_core PRIVATE ../)

#target_link_libraries(video_core PRIVATE framework platform)
# target_include_directories(video_core PRIVATE externals/vulkan-hpp/vulkan) TODO: Need to also include Vulkan headers with matching version... For now, I'm just using the headers shipping with my Linux distribution
target_link_libraries(video_core PRIVATE vulkan-util)
target_link_libraries(video_core PRIVATE Boost::boost)
target_link_libraries(video_core PRIVATE range-v3::range-v3)

target_link_libraries(video_core PRIVATE spdlog::spdlog)

if (Pistache_FOUND)
    target_sources(video_core PRIVATE
                   src/debug/gpu.cpp)
    target_link_libraries(video_core PRIVATE Pistache::Pistache)
endif()
target_link_libraries(video_core PRIVATE Tracy::TracyClient)
target_link_libraries(video_core PRIVATE xxHash::xxhash)

if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # Required for g_vulkan_queue_mutex
    target_link_options(video_core PRIVATE "-undefined;dynamic_lookup")
endif()

# Selectively disable Werror to cover false positives
target_compile_options(video_core PRIVATE -Wno-error=return-type)
