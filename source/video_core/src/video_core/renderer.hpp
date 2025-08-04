#pragma once

#include "display.hpp"

namespace spdlog {
class logger;
}

namespace EmuDisplay {
struct EmuDisplay;
struct Frame;
}

namespace Memory {
struct PhysicalMemory;
}

namespace Pica {

struct Context;

namespace VertexShader {
struct OutputVertex;
struct InputVertex;
struct ShaderEngine;
}

class Renderer {
public:
    virtual ~Renderer() = default;

    /**
     * @param stride Number of bytes between two consecutive rows in the source image
     */
    virtual void ProduceFrame(EmuDisplay::EmuDisplay&, EmuDisplay::Frame&, Memory::PhysicalMemory&, EmuDisplay::DataStreamId, uint32_t addr, uint32_t stride, EmuDisplay::Format) = 0;

    /**
     * @param max_triangles Upper bound for the number of triangles that are going to be rendered
     */
    virtual void PrepareTriangleBatch(Context&, const VertexShader::ShaderEngine&, uint32_t max_triangles, bool is_indexed) = 0;

    /**
     * Adds a pre-assembled, unclipped triangle to the current batch
     */
    virtual void AddPreassembledTriangle(Context&, VertexShader::OutputVertex &v0, VertexShader::OutputVertex &v1, VertexShader::OutputVertex &v2) = 0;

    /**
     * Adds a single vertex to the current batch for hardware primitive assembly
     */
    virtual void AddVertex(Context&, uint32_t num_attributes, VertexShader::InputVertex&) = 0;

    virtual void FinalizeTriangleBatch(Context&, const VertexShader::ShaderEngine&, bool is_indexed) = 0;

    virtual void InvalidateRange(uint32_t /* TODO: PAddr */ start, uint32_t num_bytes) = 0;
    virtual void FlushRange(uint32_t /* TODO: PAddr */ start, uint32_t num_bytes) = 0;

    /**
     * Performs an image-to-image copy with automatic color conversion and
     * linear filtering enabled. FlushRange must be used to make results
     * visible in emulated memory.
     *
     * @param input_format GPU::Regs::FramebufferFormat
     * @return true if the Renderer performed a blit, false if a software fallback needs to be executed by the caller
     */
    virtual bool BlitImage(Context&, uint32_t /* TODO: PAddr */ input_addr, uint32_t input_width, uint32_t input_height, uint32_t input_stride,
                           uint32_t input_format, uint32_t output_addr, uint32_t output_width, uint32_t output_height,
                           uint32_t output_stride, uint32_t output_format, bool flip_y) = 0;
};

} // namespace Pica
