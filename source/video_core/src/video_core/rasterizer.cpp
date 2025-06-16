#include <algorithm>

#include "common/common_types.h"

#include "math.h"
#include "context.h"
#include "rasterizer.h"
#include "shader.hpp"

#include "debug_utils/debug_utils.h"

#include <platform/gpu/pica.hpp>

#include "../../framework/exceptions.hpp"
#include <common/log.h>

namespace Pica {

namespace Rasterizer {

static void ValidatePipelineConfiguration(const Pica::Regs& regs) {
    // NOTE: Read operations have well-defined results on hardware even if
    //       access is disabled, however this hasn't been observed in any
    //       applications.
    const auto& framebuffer = regs.framebuffer;
    const auto& output_merger = regs.output_merger;
    if (!framebuffer.color_read_enabled() && framebuffer.color_write_enabled()) {
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
    if (!framebuffer.depth_stencil_read_enabled() && framebuffer.depth_stencil_write_enabled()) {
        throw Mikage::Exceptions::NotImplemented("Cannot render to a write-only depth buffer");
    }
    if (!framebuffer.depth_stencil_read_enabled() && output_merger.depth_test_enable && output_merger.depth_test_func != DepthFunc::Always) {
        throw Mikage::Exceptions::NotImplemented("Cannot perform depth test without depth buffer read access");
    }
    if (!framebuffer.depth_stencil_read_enabled() && output_merger.stencil_test.enabled()) {
        throw Mikage::Exceptions::NotImplemented("Cannot perform depth test without depth buffer read access");
    }
}

static void DrawPixel(Context& context, int x, int y, const Math::Vec4<u8>& color) {
    const auto& registers = context.registers;
    const PAddr addr = registers.framebuffer.GetColorBufferPhysicalAddress();

    // Similarly to textures, the render framebuffer is laid out from bottom to top, too.
    // NOTE: The framebuffer height register contains the actual FB height minus one.
    y = (registers.framebuffer.height - y);

    switch (ToGenericFormat(registers.framebuffer.GetColorFormat())) {
    case GenericImageFormat::RGBA8:
    {
        u32 value = (color.r() << 24) | (color.g() << 16) | (color.b() << 8) | color.a();
        Memory::WriteLegacy<uint32_t>(*context.mem, addr + 4 * (x + y * registers.framebuffer.GetWidth()), value);
        break;
    }

    case GenericImageFormat::RGB565:
    {
        u32 value = ((color.r() >> 3) << 11) | ((color.g() >> 2) << 5) | (color.b() >> 3);
        Memory::WriteLegacy<uint16_t>(*context.mem, addr + 2 * (x + y * registers.framebuffer.GetWidth()), value);
        break;
    }

    case GenericImageFormat::RGBA5551:
    {
        u32 value = ((color.r() >> 3) << 11) | ((color.g() >> 3) << 6) | ((color.b() >> 3) << 1) | (color.a() >> 7);
        Memory::WriteLegacy<uint16_t>(*context.mem, addr + 2 * (x + y * registers.framebuffer.GetWidth()), value);
        break;
    }

    case GenericImageFormat::RGBA4:
    {
        u32 value = ((color.r() >> 4) << 12) | ((color.g() >> 4) << 8) | (color.b() & 0xf0) | (color.a() >> 4);
        Memory::WriteLegacy<uint16_t>(*context.mem, addr + 2 * (x + y * registers.framebuffer.GetWidth()), value);
        break;
    }

    default:
        throw Mikage::Exceptions::NotImplemented("Unknown framebuffer color format {}", ToGenericFormat(registers.framebuffer.GetColorFormat()));
    }
}

static const Math::Vec4<u8> GetPixel(Context& context, int x, int y) {
    const auto& registers = context.registers;
    const PAddr addr = registers.framebuffer.GetColorBufferPhysicalAddress();

    y = (registers.framebuffer.height - y);

    switch (ToGenericFormat(registers.framebuffer.GetColorFormat())) {
    case GenericImageFormat::RGBA8:
    {
        u32 value = Memory::ReadLegacy<uint32_t>(*context.mem, addr + 4 * (x + y * registers.framebuffer.GetWidth()));
        Math::Vec4<u8> ret;
        ret.r() = value >> 24;
        ret.g() = (value >> 16) & 0xFF;
        ret.b() = (value >> 8) & 0xFF;
        ret.a() = value & 0xFF;
        return ret;
    }

    case GenericImageFormat::RGB565:
    {
        u32 value = Memory::ReadLegacy<uint16_t>(*context.mem, addr + 2 * (x + y * registers.framebuffer.GetWidth()));
        Math::Vec4<u8> ret;
        auto extend_5_to_8 = [](uint8_t val) { return static_cast<uint8_t>((val << 3) | (val >> 2)); };
        auto extend_6_to_8 = [](uint8_t val) { return static_cast<uint8_t>((val << 2) | (val >> 4)); };
        ret.r() = extend_5_to_8(value >> 11);
        ret.g() = extend_6_to_8((value >> 5) & 0x3F);
        ret.b() = extend_5_to_8(value & 0x1F);
        ret.a() = 255;
        return ret;
    }

    case GenericImageFormat::RGBA5551:
    {
        u32 value = Memory::ReadLegacy<uint16_t>(*context.mem, addr + 2 * (x + y * registers.framebuffer.GetWidth()));
        Math::Vec4<u8> ret;
        auto extend_5_to_8 = [](uint8_t val) { return static_cast<uint8_t>((val << 3) | (val >> 2)); };
        ret.r() = extend_5_to_8(value >> 11);
        ret.g() = extend_5_to_8((value >> 6) & 0x1F);
        ret.b() = extend_5_to_8((value >> 1) & 0x1F);
        ret.a() = (value & 0x1) ? 255 : 0;
        return ret;
    }

    case GenericImageFormat::RGBA4:
    {
        u32 value = Memory::ReadLegacy<uint16_t>(*context.mem, addr + 2 * (x + y * registers.framebuffer.GetWidth()));
        Math::Vec4<u8> ret;
        auto extend_4_to_8 = [](uint8_t val) { return static_cast<uint8_t>((val << 4) | val); };
        ret.r() = extend_4_to_8(value >> 12);
        ret.g() = extend_4_to_8((value >> 8) & 0xF);
        ret.b() = extend_4_to_8((value >> 4) & 0xF);
        ret.a() = extend_4_to_8(value & 0xF);
        return ret;
    }

    default:
        throw Mikage::Exceptions::NotImplemented("Unknown framebuffer color format {}", ToGenericFormat(registers.framebuffer.GetColorFormat()));
    }
 }

static uint32_t GetDepth(Context& context, int x, int y) {
    const auto& registers = context.registers;
    const PAddr addr = registers.framebuffer.GetDepthBufferPhysicalAddress();

    y = (registers.framebuffer.height - y);

    switch (ToGenericFormat(registers.framebuffer.GetDepthStencilFormat())) {
//    case GenericImageFormat::D24:
//    {
//        return Memory::ReadLegacy<uint32_t>(*context.mem, addr + 3 * (x + y * registers.framebuffer.GetWidth()));
//    }

    case GenericImageFormat::D24S8:
        return Memory::ReadLegacy<uint32_t>(*context.mem, addr + 4 * (x + y * registers.framebuffer.GetWidth())) & 0xffffff;

    case GenericImageFormat::D16:
        return Memory::ReadLegacy<uint16_t>(*context.mem, addr + 2 * (x + y * registers.framebuffer.GetWidth()));

    default:
        throw Mikage::Exceptions::NotImplemented("Unknown framebuffer depth format {}", ToGenericFormat(registers.framebuffer.GetDepthStencilFormat()));
    }
}

// TODO: Change to combined SetDepthStencil
static void SetDepth(Context& context, int x, int y, uint32_t value) {
    const auto& registers = context.registers;
    const PAddr addr = registers.framebuffer.GetDepthBufferPhysicalAddress();

    y = (registers.framebuffer.height - y);

    switch (ToGenericFormat(registers.framebuffer.GetDepthStencilFormat())) {
    case GenericImageFormat::D24S8:
        Memory::WriteLegacy<uint8_t>(*context.mem, addr + 4 * (x + y * registers.framebuffer.GetWidth()), value & 0xff);
        Memory::WriteLegacy<uint8_t>(*context.mem, addr + 1 + 4 * (x + y * registers.framebuffer.GetWidth()), (value >> 8) & 0xff);
        Memory::WriteLegacy<uint8_t>(*context.mem, addr + 2 + 4 * (x + y * registers.framebuffer.GetWidth()), (value >> 16) & 0xff);
        break;

    case GenericImageFormat::D16:
        // TODO: Should this value be rescaled?
        Memory::WriteLegacy<uint16_t>(*context.mem, addr + 2 * (x + y * registers.framebuffer.GetWidth()), value);
        break;

    default:
        throw Mikage::Exceptions::NotImplemented("Unknown framebuffer depth format {}", ToGenericFormat(registers.framebuffer.GetDepthStencilFormat()));
    }
}

static uint8_t GetStencil(Context& context, int x, int y) {
    const auto& registers = context.registers;
    const PAddr addr = registers.framebuffer.GetDepthBufferPhysicalAddress();

    y = (registers.framebuffer.height - y);

    switch (ToGenericFormat(registers.framebuffer.GetDepthStencilFormat())) {
    case GenericImageFormat::D24S8:
        return Memory::ReadLegacy<uint8_t>(*context.mem, addr + 3 + 4 * (x + y * registers.framebuffer.GetWidth()));

    default:
        throw Mikage::Exceptions::NotImplemented("Unknown framebuffer stencil format {}", ToGenericFormat(registers.framebuffer.GetDepthStencilFormat()));
    }
}

static void ApplyStencilOp(Context& context, StencilTest::Op op, uint8_t mask, int x, int y, uint8_t value, uint8_t ref) {
    if (op == StencilTest::Op::Keep) {
        return;
    }

    const auto& registers = context.registers;
    PAddr addr = registers.framebuffer.GetDepthBufferPhysicalAddress();

    y = (registers.framebuffer.height - y);

    switch (ToGenericFormat(registers.framebuffer.GetDepthStencilFormat())) {
    case GenericImageFormat::D24S8:
        addr += 3 + 4 * (x + y * registers.framebuffer.GetWidth());
        break;

    default:
        throw Mikage::Exceptions::NotImplemented("Unknown framebuffer stencil format {}", ToGenericFormat(registers.framebuffer.GetDepthStencilFormat()));
    }

    uint8_t new_value = std::invoke([=]() -> uint8_t {
        switch (op) {
        case StencilTest::Op::Zero:
            return 0;

        case StencilTest::Op::Replace:
            return ref;

        case StencilTest::Op::IncrementAndClamp:
            return std::min<uint8_t>(value, 254) + 1;

        case StencilTest::Op::DecrementAndClamp:
            return std::max<uint8_t>(value, 1) - 1;

        case StencilTest::Op::Invert:
            return ~value;

        case StencilTest::Op::IncrementAndWrap:
            return value + 1;

        case StencilTest::Op::DecrementAndWrap:
            return value - 1;

        default:
            throw Mikage::Exceptions::NotImplemented("Unknown stencil test op");
        }
    });

    Memory::WriteLegacy<uint8_t>(*context.mem, addr, (new_value & mask) | (value & ~mask));
}

static bool AlphaTestFailed(uint32_t value, uint32_t reference, AlphaTest::Function function) {
    switch (function) {
    case AlphaTest::Function::NotEqual:
        return !(value != reference);

    case AlphaTest::Function::GreaterThan:
        return !(value > reference);

    default:
        throw std::runtime_error(fmt::format("Alpha test function {:#x} not implemented yet", static_cast<uint32_t>(function)));
    }
}

// NOTE: Assuming that rasterizer coordinates are 12.4 fixed-point values
struct Fix12P4 {
    Fix12P4() {}
    Fix12P4(u16 val) : val(val) {}

    static u16 FracMask() { return 0xF; }
    static u16 IntMask() { return (u16)~0xF; }

    operator u16() const {
        return val;
    }

    bool operator < (const Fix12P4& oth) const {
        return (u16)*this < (u16)oth;
    }

private:
    u16 val;
};

/**
 * Calculate signed area of the triangle spanned by the three argument vertices.
 * The sign denotes an orientation.
 *
 * @todo define orientation concretely.
 */
static int64_t SignedArea (const Math::Vec2<Fix12P4>& vtx1,
                       const Math::Vec2<Fix12P4>& vtx2,
                       const Math::Vec2<Fix12P4>& vtx3) {
    const auto vec1 = Math::MakeVec((vtx2 - vtx1).Cast<int64_t>(), int64_t { 0 });
    const auto vec2 = Math::MakeVec((vtx3 - vtx1).Cast<int64_t>(), int64_t { 0 });
    // TODO: There is a very small chance this will overflow for sizeof(int) == 4
    return Math::Cross(vec1, vec2).z;
};

/**
 * Helper function for ProcessTriangle with the "reversed" flag to allow for implementing
 * culling via recursion.
 */
static void ProcessTriangleInternal(Context& context,
                                    const VertexShader::OutputVertex& v0,
                                    const VertexShader::OutputVertex& v1,
                                    const VertexShader::OutputVertex& v2,
                                    bool reversed = false)
{
    const auto& registers = context.registers;

    // vertex positions in rasterizer coordinates
    static auto FloatToFix = [](float24 flt) {
        // TODO: Rounding here is necessary to prevent garbage pixels at
        //       triangle borders. Is it that the correct solution, though?
        return Fix12P4(static_cast<unsigned short>(round(flt.ToFloat32() * 16.0f)));
    };
    static auto ScreenToRasterizerCoordinates = [](const Math::Vec3<float24>& vec) {
        return Math::Vec3<Fix12P4>{FloatToFix(vec.x), FloatToFix(vec.y), FloatToFix(vec.z)};
    };

    Math::Vec3<Fix12P4> vtxpos[3]{ ScreenToRasterizerCoordinates(v0.screenpos),
                                   ScreenToRasterizerCoordinates(v1.screenpos),
                                   ScreenToRasterizerCoordinates(v2.screenpos) };

    if (registers.cull_mode == CullMode::KeepAll) {
        // Make sure we always end up with a triangle wound counter-clockwise
        if (!reversed && SignedArea(vtxpos[0].xy(), vtxpos[1].xy(), vtxpos[2].xy()) <= 0) {
            ProcessTriangleInternal(context, v0, v2, v1, true);
            return;
        }
    } else {
        if (!reversed && registers.cull_mode == CullMode::KeepClockWise) {
            // Reverse vertex order and use the CCW code path.
            ProcessTriangleInternal(context, v0, v2, v1, true);
            return;
        }

        // Cull away triangles which are wound clockwise.
        if (SignedArea(vtxpos[0].xy(), vtxpos[1].xy(), vtxpos[2].xy()) <= 0)
            return;
    }

    // TODO: Proper scissor rect test!
    u16 min_x = std::min({vtxpos[0].x, vtxpos[1].x, vtxpos[2].x});
    u16 min_y = std::min({vtxpos[0].y, vtxpos[1].y, vtxpos[2].y});
    u16 max_x = std::max({vtxpos[0].x, vtxpos[1].x, vtxpos[2].x});
    u16 max_y = std::max({vtxpos[0].y, vtxpos[1].y, vtxpos[2].y});

    min_x &= Fix12P4::IntMask();
    min_y &= Fix12P4::IntMask();
    max_x = ((max_x + Fix12P4::FracMask()) & Fix12P4::IntMask());
    max_y = ((max_y + Fix12P4::FracMask()) & Fix12P4::IntMask());

    // Triangle filling rules: Pixels on the right-sided edge or on flat bottom edges are not
    // drawn. Pixels on any other triangle border are drawn. This is implemented with three bias
    // values which are added to the barycentric coordinates w0, w1 and w2, respectively.
    // NOTE: These are the PSP filling rules. Not sure if the 3DS uses the same ones...
    auto IsRightSideOrFlatBottomEdge = [](const Math::Vec2<Fix12P4>& vtx,
                                          const Math::Vec2<Fix12P4>& line1,
                                          const Math::Vec2<Fix12P4>& line2)
    {
        if (line1.y == line2.y) {
            // just check if vertex is above us => bottom line parallel to x-axis
            return vtx.y < line1.y;
        } else {
            // check if vertex is on our left => right side
            // TODO: Not sure how likely this is to overflow
            return (int)vtx.x < (int)line1.x + ((int)line2.x - (int)line1.x) * ((int)vtx.y - (int)line1.y) / ((int)line2.y - (int)line1.y);
        }
    };
    int bias0 = IsRightSideOrFlatBottomEdge(vtxpos[0].xy(), vtxpos[1].xy(), vtxpos[2].xy()) ? -1 : 0;
    int bias1 = IsRightSideOrFlatBottomEdge(vtxpos[1].xy(), vtxpos[2].xy(), vtxpos[0].xy()) ? -1 : 0;
    int bias2 = IsRightSideOrFlatBottomEdge(vtxpos[2].xy(), vtxpos[0].xy(), vtxpos[1].xy()) ? -1 : 0;

    ValidatePipelineConfiguration(context.registers);

//    auto& fb_registers = context.registers.framebuffer;
//    auto color_memory = Memory::LookupContiguousMemoryBackedPage(*context.mem, fb_registers.GetColorBufferPhysicalAddress(), TextureSize(ToGenericFormat(fb_registers.GetColorFormat()), fb_registers.GetWidth(), fb_registers.GetHeight()));
//    // TODO: Only query if non-zero
//    auto ds_memory = Memory::LookupContiguousMemoryBackedPage(*context.mem, fb_registers.GetDepthBufferPhysicalAddress(), TextureSize(ToGenericFormat(fb_registers.GetDepthStencilFormat()), fb_registers.GetWidth(), fb_registers.GetHeight()));

    // Enter rasterization loop, starting at the center of the topleft bounding box corner.
    // TODO: Not sure if looping through x first might be faster
    for (u16 y = min_y + 8; y < max_y; y += 0x10) {
        for (u16 x = min_x + 8; x < max_x; x += 0x10) {
            // Calculate the barycentric coordinates w0, w1 and w2
            int64_t w0 = bias0 + SignedArea(vtxpos[1].xy(), vtxpos[2].xy(), {x, y});
            int64_t w1 = bias1 + SignedArea(vtxpos[2].xy(), vtxpos[0].xy(), {x, y});
            int64_t w2 = bias2 + SignedArea(vtxpos[0].xy(), vtxpos[1].xy(), {x, y});
            int64_t wsum = w0 + w1 + w2;

            // If current pixel is not covered by the current primitive
            if (w0 < 0 || w1 < 0 || w2 < 0)
                continue;

            // Perspective correct attribute interpolation:
            // Attribute values cannot be calculated by simple linear interpolation since
            // they are not linear in screen space. For example, when interpolating a
            // texture coordinate across two vertices, something simple like
            //     u = (u0*w0 + u1*w1)/(w0+w1)
            // will not work. However, the attribute value divided by the
            // clipspace w-coordinate (u/w) and and the inverse w-coordinate (1/w) are linear
            // in screenspace. Hence, we can linearly interpolate these two independently and
            // calculate the interpolated attribute by dividing the results.
            // I.e.
            //     u_over_w   = ((u0/v0.pos.w)*w0 + (u1/v1.pos.w)*w1)/(w0+w1)
            //     one_over_w = (( 1/v0.pos.w)*w0 + ( 1/v1.pos.w)*w1)/(w0+w1)
            //     u = u_over_w / one_over_w
            //
            // The generalization to three vertices is straightforward in baricentric coordinates.
            auto GetInterpolatedAttribute = [&](float24 attr0, float24 attr1, float24 attr2) {
                auto attr_over_w = Math::MakeVec(attr0 / v0.pos.w,
                                                 attr1 / v1.pos.w,
                                                 attr2 / v2.pos.w);
                auto w_inverse   = Math::MakeVec(float24::FromFloat32(1.f) / v0.pos.w,
                                                 float24::FromFloat32(1.f) / v1.pos.w,
                                                 float24::FromFloat32(1.f) / v2.pos.w);
                auto baricentric_coordinates = Math::MakeVec(float24::FromFloat32(static_cast<float>(w0)),
                                                             float24::FromFloat32(static_cast<float>(w1)),
                                                             float24::FromFloat32(static_cast<float>(w2)));

                float24 interpolated_attr_over_w = Math::Dot(attr_over_w, baricentric_coordinates);
                float24 interpolated_w_inverse   = Math::Dot(w_inverse,   baricentric_coordinates);
                return interpolated_attr_over_w / interpolated_w_inverse;
            };

            Math::Vec4<u8> primary_color{
                (u8)(GetInterpolatedAttribute(v0.color.r(), v1.color.r(), v2.color.r()).ToFloat32() * 255),
                (u8)(GetInterpolatedAttribute(v0.color.g(), v1.color.g(), v2.color.g()).ToFloat32() * 255),
                (u8)(GetInterpolatedAttribute(v0.color.b(), v1.color.b(), v2.color.b()).ToFloat32() * 255),
                (u8)(GetInterpolatedAttribute(v0.color.a(), v1.color.a(), v2.color.a()).ToFloat32() * 255)
            };

            Math::Vec2<float24> uv[3];
            uv[0].u() = GetInterpolatedAttribute(v0.tc0.u(), v1.tc0.u(), v2.tc0.u());
            uv[0].v() = GetInterpolatedAttribute(v0.tc0.v(), v1.tc0.v(), v2.tc0.v());
            uv[1].u() = GetInterpolatedAttribute(v0.tc1.u(), v1.tc1.u(), v2.tc1.u());
            uv[1].v() = GetInterpolatedAttribute(v0.tc1.v(), v1.tc1.v(), v2.tc1.v());
            uv[2].u() = GetInterpolatedAttribute(v0.tc2.u(), v1.tc2.u(), v2.tc2.u());
            uv[2].v() = GetInterpolatedAttribute(v0.tc2.v(), v1.tc2.v(), v2.tc2.v());

            Math::Vec4<u8> texture_color[3]{};
            for (int i = 0; i < 3; ++i) {
                auto texture = registers.GetTextures()[i];
                if (!texture.enabled || texture.config.width == 0 || texture.config.height == 0)
                    continue;

                _dbg_assert_(HW_GPU, 0 != texture.config.address);

                int s = (int)(uv[i].u() * float24::FromFloat32(static_cast<float>(texture.config.width))).ToFloat32();
                int t = (int)(uv[i].v() * float24::FromFloat32(static_cast<float>(texture.config.height))).ToFloat32();
                static auto GetWrappedTexCoord = [](TexWrapMode mode, int val, unsigned size) {
                    switch (mode) {
                        case TexWrapMode::ClampToEdge:
                            val = std::max(val, 0);
                            val = std::min(val, (int)size - 1);
                            return val;

                        case TexWrapMode::Repeat:
                            return (int)((unsigned)val % size);

                        case TexWrapMode::MirroredRepeat:
                        {
//                            int val2 = (int)((unsigned)val % (2 * size));
//                            if (val2 >= size)
//                                val2 = 2 * size - 1 - val2;
//                            return val2;
                            unsigned val2 = ((unsigned)val % (2 * size));
                            if (val2 >= size)
                                val2 = 2 * size - 1 - val2;
                            return (int)val2;
                        }

                        default:
                            LOG_ERROR(HW_GPU, "Unknown texture coordinate wrapping mode %x\n", (int)mode);
                            _dbg_assert_(HW_GPU, 0);
                            return 0;
                    }
                };

                // Textures are laid out from bottom to top, hence we invert the t coordinate.
                // NOTE: This may not be the right place for the inversion.
                // TODO: Check if this applies to ETC textures, too.
                s = GetWrappedTexCoord(texture.config.wrap_s, s, texture.config.width);
                t = texture.config.height - 1 - GetWrappedTexCoord(texture.config.wrap_t, t, texture.config.height);

                auto info = DebugUtils::TextureInfo::FromPicaRegister(texture.config, texture.format);

                auto source_memory = Memory::LookupContiguousMemoryBackedPage(*context.mem, texture.config.GetPhysicalAddress(), TextureSize(ToGenericFormat(texture.format), texture.config.width, texture.config.height));
                texture_color[i] = DebugUtils::LookupTexture(source_memory, s, t, info);
                // DebugUtils::DumpTexture(texture.config, texture_data);
            }

            // Texture environment - consists of 6 stages of color and alpha combining.
            //
            // Color combiners take three input color values from some source (e.g. interpolated
            // vertex color, texture color, previous stage, etc), perform some very simple
            // operations on each of them (e.g. inversion) and then calculate the output color
            // with some basic arithmetic. Alpha combiners can be configured separately but work
            // analogously.
            // TODO: Generally, not all tev stages will be in use - but currently we run lots of branches for each anyway. Instead, we should compile a bytecode script ahead of the rasterizer loop!
            Math::Vec4<u8> combiner_buffer = {
                static_cast<uint8_t>(registers.combiner_buffer_init.r()),
                static_cast<uint8_t>(registers.combiner_buffer_init.g()),
                static_cast<uint8_t>(registers.combiner_buffer_init.b()),
                static_cast<uint8_t>(registers.combiner_buffer_init.a())
            };
            // TODO: Should this indeed be initialized with the combiner buffer? If not, what effect does TevStageUpdatesRGB really have for stage 0?
            Math::Vec4<u8> combiner_output = combiner_buffer;
            auto tev_stages = registers.GetTevStages();
            for (std::size_t tev_stage_index = 0; tev_stage_index < tev_stages.size(); ++tev_stage_index) {
                auto& tev_stage = tev_stages[tev_stage_index];
                using Source = Regs::TevStageConfig::Source;
                using ColorModifier = Regs::TevStageConfig::ColorModifier;
                using AlphaModifier = Regs::TevStageConfig::AlphaModifier;
                using Operation = Regs::TevStageConfig::Operation;

                auto GetCombinerSource = [&](Source source) -> Math::Vec4<u8> {
                    switch (source) {
                    case Source::PrimaryColor:
                    case Source::PrimaryFragmentColor:
                        return primary_color;

                    case static_cast<Source>(2): // TODO: Implement properly
                        return Math::Vec4<u8> { };

                    case Source::Texture0:
                        return texture_color[0];

                    case Source::Texture1:
                        return texture_color[1];

                    case Source::Texture2:
                        return texture_color[2];

                    case Source::Constant:
                        return {tev_stage.const_r()(), tev_stage.const_g()(), tev_stage.const_b()(), tev_stage.const_a()()};

                    case Source::CombinerBuffer:
                        return combiner_buffer;

                    case Source::Previous:
                        return combiner_output;

                    default:
                        throw std::runtime_error(fmt::format("Unknown combiner source {}", static_cast<uint32_t>(source)));
                    }
                };

                static auto GetColorModifier = [](ColorModifier factor, const Math::Vec4<u8>& values) -> Math::Vec3<u8> {
                    switch (factor)
                    {
                    case ColorModifier::SourceColor:
                        return values.rgb();

                    case ColorModifier::OneMinusSourceColor:
                        return (Math::Vec3<u8>(255, 255, 255) - values.rgb()).Cast<u8>();

                    case ColorModifier::SourceAlpha:
                        return { values.a(), values.a(), values.a() };

                    case ColorModifier::OneMinusSourceAlpha:
                        return { (uint8_t)(255 - values.a()), (uint8_t)(255 - values.a()), (uint8_t)(255 - values.a()) };

                    case ColorModifier::SourceRed:
                        return { values.r(), values.r(), values.r() };

                    case ColorModifier::OneMinusSourceRed:
                        return { (uint8_t)(255 - values.r()), (uint8_t)(255 - values.r()), (uint8_t)(255 - values.r()) };

                    case ColorModifier::SourceGreen:
                        return { values.g(), values.g(), values.g() };

                    case ColorModifier::OneMinusSourceGreen:
                        return { (uint8_t)(255 - values.g()), (uint8_t)(255 - values.g()), (uint8_t)(255 - values.g()) };

                    case ColorModifier::SourceBlue:
                        return { values.b(), values.b(), values.b() };

                    case ColorModifier::OneMinusSourceBlue:
                        return { (uint8_t)(255 - values.b()), (uint8_t)(255 - values.b()), (uint8_t)(255 - values.b()) };

                    default:
                        throw std::runtime_error(fmt::format("Unknown color factor {:#x}", static_cast<uint32_t>(factor)));
                    }
                };

                static auto GetAlphaModifier = [](AlphaModifier factor, const Math::Vec4<uint8_t>& values) -> u8 {
                    switch (factor) {
                    case AlphaModifier::SourceAlpha:
                        return values.a();

                    case AlphaModifier::OneMinusSourceAlpha:
                        return 255 - values.a();

                    case AlphaModifier::SourceRed:
                        return values.r();

                    case AlphaModifier::OneMinusSourceRed:
                        return 255 - values.r();

                    case AlphaModifier::SourceGreen:
                        return values.g();

                    case AlphaModifier::OneMinusSourceGreen:
                        return 255 - values.g();

                    case AlphaModifier::SourceBlue:
                        return values.b();

                    case AlphaModifier::OneMinusSourceBlue:
                        return 255 - values.b();

                    default:
                        throw std::runtime_error(fmt::format("Unknown alpha factor {:#x}", static_cast<uint32_t>(factor)));
                    }
                };

                // TODO: Compare bit accuracy of these operations against hardware
                static auto ColorCombine = [](Operation op, const Math::Vec3<u8> input[3]) -> Math::Vec3<u8> {
                    switch (op) {
                    case Operation::Replace:
                        return input[0];

                    case Operation::Modulate:
                        return ((input[0] * input[1]) / 255).Cast<u8>();

                    case Operation::Add:
                    {
                        auto result = input[0] + input[1];
                        result.r() = std::min(255, result.r());
                        result.g() = std::min(255, result.g());
                        result.b() = std::min(255, result.b());
                        return result.Cast<u8>();
                    }

                    case Operation::AddSigned:
                    {
                        // TODO: Is it 127 or 128?
                        auto result = input[0] + input[1];
                        result.r() = std::min(255, std::max(127, result.r()) - 127);
                        result.g() = std::min(255, std::max(127, result.g()) - 127);
                        result.b() = std::min(255, std::max(127, result.b()) - 127);
                        return result.Cast<u8>();
                    }

                    case Operation::Lerp:
                        return ((input[0] * input[2] + input[1] * (Math::MakeVec<u8>(255, 255, 255) - input[2]).Cast<u8>()) / 255).Cast<u8>();

                    case Operation::Subtract:
                    {
                        auto result = input[0].Cast<int>() - input[1].Cast<int>();
                        result.r() = std::max(0, result.r());
                        result.g() = std::max(0, result.g());
                        result.b() = std::max(0, result.b());
                        return result.Cast<u8>();
                    }

                    case Operation::MultiplyThenAdd:
                    {
                        auto result = (input[0] * input[1] + 255 * input[2].Cast<int>()) / 255;
                        result.r() = std::min(255, result.r());
                        result.g() = std::min(255, result.g());
                        result.b() = std::min(255, result.b());
                        return result.Cast<u8>();
                    }

                    case Operation::AddThenMultiply:
                    {
                        auto result = (input[0] + input[1]) * input[2].Cast<int>() / 255;
                        result.r() = std::min(255, result.r());
                        result.g() = std::min(255, result.g());
                        result.b() = std::min(255, result.b());
                        return result.Cast<u8>();
                    }

                    default:
                        throw std::runtime_error(fmt::format("Unknown color combiner operation {:#x}", static_cast<uint32_t>(op)));
                    }
                };

                static auto AlphaCombine = [](Operation op, const std::array<u8,3>& input) -> u8 {
                    switch (op) {
                    case Operation::Replace:
                        return input[0];

                    case Operation::Modulate:
                        return input[0] * input[1] / 255;

                    case Operation::Add:
                        return std::min(255, input[0] + input[1]);

                    case Operation::AddSigned:
                        // TODO: Is it 127 or 128?
                        return std::min(255, std::max(127, input[0] + input[1]) - 127);

                    case Operation::Lerp:
                        return (input[0] * input[2] + input[1] * (255 - input[2])) / 255;

                    case Operation::Subtract:
//                        return std::max(0, (int)input[0] - (int)input[1]);
                        return std::max(input[0], input[1]) - (int)input[1];

                    case Operation::MultiplyThenAdd:
                        return std::min(255, (input[0] * input[1] + 255 * input[2]) / 255);

                    case Operation::AddThenMultiply:
                        return std::min(255, (input[0] + input[1]) * input[2]) / 255;

                    default:
                        throw std::runtime_error(fmt::format("Unknown alpha combiner operation {:#x}", static_cast<uint32_t>(op)));
                    }
                };

                // color combiner
                // NOTE: Not sure if the alpha combiner might use the color output of the previous
                //       stage as input. Hence, we currently don't directly write the result to
                //       combiner_output.rgb(), but instead store it in a temporary variable until
                //       alpha combining has been done.
                Math::Vec3<u8> color_result[3] = {
                    GetColorModifier(tev_stage.color_modifier1(), GetCombinerSource(tev_stage.color_source1())),
                    GetColorModifier(tev_stage.color_modifier2(), GetCombinerSource(tev_stage.color_source2())),
                    GetColorModifier(tev_stage.color_modifier3(), GetCombinerSource(tev_stage.color_source3()))
                };
                auto color_output = ColorCombine(tev_stage.color_op(), color_result);

                // alpha combiner
                std::array<u8,3> alpha_result = {
                    GetAlphaModifier(tev_stage.alpha_modifier1(), GetCombinerSource(tev_stage.alpha_source1())),
                    GetAlphaModifier(tev_stage.alpha_modifier2(), GetCombinerSource(tev_stage.alpha_source2())),
                    GetAlphaModifier(tev_stage.alpha_modifier3(), GetCombinerSource(tev_stage.alpha_source3()))
                };
                auto alpha_output = AlphaCombine(tev_stage.alpha_op(), alpha_result);

                // TODO: Move to pica.h
                if (tev_stage_index > 0) {
                    // Update combiner buffer with result from previous stage.
                    // NOTE: This lags behind by one stage, i.e. stage 2 uses the result
                    //       of stage 0, stage 3 the result of stage 1, etc.
                    //       Hence we update the combiner buffer *after* the stage inputs
                    //       have been read, and it is updated *before* writing the
                    //       combiner output
                    if (registers.combiner_buffer.TevStageUpdatesRGB(tev_stage_index - 1)) {
                        combiner_buffer.r() = combiner_output.r();
                        combiner_buffer.g() = combiner_output.g();
                        combiner_buffer.b() = combiner_output.b();
                    }

                    if (registers.combiner_buffer.TevStageUpdatesA(tev_stage_index - 1)) {
                        combiner_buffer.a() = combiner_output.a();
                    }
                }

                combiner_output.r() = static_cast<uint8_t>(std::min<unsigned>(255, color_output.r() * tev_stage.GetMultiplierRGB()));
                combiner_output.g() = static_cast<uint8_t>(std::min<unsigned>(255, color_output.g() * tev_stage.GetMultiplierRGB()));
                combiner_output.b() = static_cast<uint8_t>(std::min<unsigned>(255, color_output.b() * tev_stage.GetMultiplierRGB()));
                combiner_output.a() = static_cast<uint8_t>(std::min<unsigned>(255, alpha_output * tev_stage.GetMultiplierA()));
            }

            if (registers.output_merger.alpha_test.enable() && registers.output_merger.alpha_test.function() != AlphaTest::Function::Always) {
                if (AlphaTestFailed(combiner_output.a(), registers.output_merger.alpha_test.reference(), registers.output_merger.alpha_test.function())) {
                    continue;
                }
            }

            auto& stencil_test = registers.output_merger.stencil_test;
            bool stencil_passed = true;
            uint8_t current_stencil = 0;
            if (stencil_test.enabled()) {
                current_stencil = GetStencil(context, x >> 4, y >> 4);

                // TODO: Assert that fb format is D24S8

                auto compare_stencil = [](StencilTest::CompareFunc func, uint8_t ref, uint8_t current) {
                    switch (func) {
                    case StencilTest::CompareFunc::Never:
                        return false;

                    case StencilTest::CompareFunc::Always:
                        return true;

                    case StencilTest::CompareFunc::Equal:
                        return ref == current;

                    case StencilTest::CompareFunc::NotEqual:
                        return ref != current;

                    case StencilTest::CompareFunc::LessThan:
                        return ref < current;

                    case StencilTest::CompareFunc::LessThanOrEqual:
                        return ref <= current;

                    case StencilTest::CompareFunc::GreaterThan:
                        return ref > current;

                    case StencilTest::CompareFunc::GreaterThanOrEqual:
                        return ref >= current;
                    }
                };
                stencil_passed = compare_stencil(   stencil_test.compare_function(),
                                                    stencil_test.reference() & stencil_test.mask_in(),
                                                    current_stencil & stencil_test.mask_in());
                if (!stencil_passed) {
                    ApplyStencilOp(context, stencil_test.op_fail_stencil(), stencil_test.mask_out(), x >> 4, y >> 4, current_stencil, stencil_test.reference());
                    continue;
                }
            }

            // TODO: Does depth indeed only get written even if depth testing is enabled?
            if (registers.output_merger.depth_test_enable) {
                // TODO: Port Citra change 547da374b83063a3ca8111ba49049353c3388de8
                uint32_t depth_bits;
                switch (ToGenericFormat(context.registers.framebuffer.GetDepthStencilFormat())) {
                case GenericImageFormat::D16:
                    depth_bits = 16;
                    break;

                case GenericImageFormat::D24:
                case GenericImageFormat::D24S8:
                    // TODO: OoT titlescreen shows artifacts when using 24
                    depth_bits = 23;
                    break;

                default:
                    throw Mikage::Exceptions::NotImplemented("Unknown depth format");
                }

                // NOTE: It's important to store this number as a double, since (1 << 24) - 1 can't be represented exactly with single-precision floats
                double scale = ((1 << depth_bits) - 1);
                uint32_t z = (uint32_t)((v0.screenpos[2].ToFloat32() * w0 +
                                         v1.screenpos[2].ToFloat32() * w1 +
                                         v2.screenpos[2].ToFloat32() * w2) * scale / wsum);
                u32 ref_z = GetDepth(context, x >> 4, y >> 4);
//                u16 z = (u16)((v0.screenpos[2].ToFloat32() * w0 +
//                            v1.screenpos[2].ToFloat32() * w1 +
//                            v2.screenpos[2].ToFloat32() * w2) * 65535.f / wsum);
//                u16 ref_z = GetDepth(context, x >> 4, y >> 4);

                bool pass = false;

                switch (registers.output_merger.depth_test_func) {
                case DepthFunc::Never: // TODO: Should we hit this if things are guarded properly???
                    pass = false;
                    break;

                case DepthFunc::Always:
                    pass = true;
                    break;

                case DepthFunc::LessThan:
                    pass = z < ref_z;
                    break;

                case DepthFunc::GreaterThan:
                    pass = z > ref_z;
                    break;

                case DepthFunc::GreaterThanOrEqual:
                    pass = z >= ref_z;
                    break;

                default:
                    throw std::runtime_error(fmt::format("Unknown depth test function {:#x}",
                                                         static_cast<uint32_t>(registers.output_merger.depth_test_func.Value())));
                }

                if (!pass) {
                    if (stencil_test.enabled()) {
                        ApplyStencilOp(context, stencil_test.op_pass_stencil_fail_depth(), stencil_test.mask_out(), x >> 4, y >> 4, current_stencil, stencil_test.reference());
                    }
                    continue;
                }

                if (registers.framebuffer.depth_stencil_write_enabled() && registers.output_merger.depth_write_enable)
                    SetDepth(context, x >> 4, y >> 4, z);
            }

            // NOTE: Stencil is updated even if depth testing is disabled
            if (stencil_test.enabled()) {
                ApplyStencilOp(context, stencil_test.op_pass_both(), stencil_test.mask_out(), x >> 4, y >> 4, current_stencil, stencil_test.reference());
            }

            if (!registers.framebuffer.color_write_enabled()) {
                continue;
            }

            // TODO: Read this only if needed
            const auto dest = GetPixel(context, x >> 4, y >> 4);
            Math::Vec4<u8> blend_output = combiner_output;

            if (registers.output_merger.alphablend_enable) {
                auto params = registers.output_merger.alpha_blending;

                auto LookupFactorRGB = [&](AlphaBlendFactor factor) -> Math::Vec3<u8> {
                    switch(factor) {
                    case AlphaBlendFactor::Zero:
                        return Math::Vec3<u8>(0, 0, 0);

                    case AlphaBlendFactor::One:
                        return Math::Vec3<u8>(255, 255, 255);

                    case AlphaBlendFactor::SourceColor:
                        return Math::MakeVec(combiner_output.r(), combiner_output.g(), combiner_output.b());

                    case AlphaBlendFactor::DestinationColor:
                        return Math::MakeVec(dest.r(), dest.g(), dest.b());

                    case AlphaBlendFactor::SourceAlpha:
                        return Math::MakeVec(combiner_output.a(), combiner_output.a(), combiner_output.a());

                    case AlphaBlendFactor::OneMinusSourceAlpha:
                        return Math::Vec3<u8>(255 - combiner_output.a(), 255 - combiner_output.a(), 255 - combiner_output.a());

                    case AlphaBlendFactor::DestinationAlpha:
                        return Math::MakeVec(dest.a(), dest.a(), dest.a());

                    case AlphaBlendFactor::OneMinusDestinationAlpha:
                        return Math::Vec3<u8>(255 - dest.a(), 255 - dest.a(), 255 - dest.a());

                    case AlphaBlendFactor::OneMinusConstantColor:
                        return Math::Vec3<u8>(  255 - context.registers.output_merger.blend_constant.r(),
                                                255 - context.registers.output_merger.blend_constant.g(),
                                                255 - context.registers.output_merger.blend_constant.b());

                    case AlphaBlendFactor::OneMinusConstantAlpha:
                    {
                        uint8_t value = 255 - context.registers.output_merger.blend_constant.a();
                        return Math::Vec3<u8>(value, value, value);
                    }

                    default:
                        throw std::runtime_error(fmt::format("Unknown color blend factor {:#x}", static_cast<uint32_t>(factor)));
                    }
                };

                auto LookupFactorA = [&](AlphaBlendFactor factor) -> u8 {
                    switch(factor) {
                    case AlphaBlendFactor::Zero:
                        return 0;

                    case AlphaBlendFactor::One:
                        return 255;

                    case AlphaBlendFactor::DestinationColor:
                        return dest.a();

                    case AlphaBlendFactor::SourceAlpha:
                        return combiner_output.a();

                    case AlphaBlendFactor::OneMinusSourceAlpha:
                        return 255 - combiner_output.a();

                    case AlphaBlendFactor::DestinationAlpha:
                        return dest.a();

                    case AlphaBlendFactor::OneMinusDestinationAlpha:
                        return 255 - dest.a();

                    default:
                        throw std::runtime_error(fmt::format("Unknown alpha blend factor {:#x}", static_cast<uint32_t>(factor)));
                    }
                };

                static auto EvaluateBlendEquation = [](const Math::Vec4<u8>& src, const Math::Vec4<u8>& srcfactor,
                                                       const Math::Vec4<u8>& dest, const Math::Vec4<u8>& destfactor,
                                                       AlphaBlendEquation equation) {
                    switch (equation) {
                    case AlphaBlendEquation::Add:
                    {
                        auto result = ((src * srcfactor).Cast<int>() + (dest * destfactor).Cast<int>()) / 255;
                        result.r() = std::min(255, result.r());
                        result.g() = std::min(255, result.g());
                        result.b() = std::min(255, result.b());
                        result.a() = std::min(255, result.a());
                        return result.Cast<u8>();
                    }

                    case AlphaBlendEquation::ReverseSubtract:
                    {
                        auto result = ((dest * destfactor).Cast<int>() - (src * srcfactor).Cast<int>()) / 255;
                        result.r() = std::max(0, result.r());
                        result.g() = std::max(0, result.g());
                        result.b() = std::max(0, result.b());
                        result.a() = std::max(0, result.a());
                        return result.Cast<u8>();
                    }

                    default:
                        throw std::runtime_error(fmt::format("Unknown RGB blend equation {:#x}", static_cast<uint32_t>(equation)));
                    }
                };

                auto srcfactor = Math::MakeVec(LookupFactorRGB(params.factor_source_rgb),
                                               LookupFactorA(params.factor_source_a));
                auto dstfactor = Math::MakeVec(LookupFactorRGB(params.factor_dest_rgb),
                                               LookupFactorA(params.factor_dest_a));

                blend_output     = EvaluateBlendEquation(combiner_output, srcfactor, dest, dstfactor, params.blend_equation_rgb);
                blend_output.a() = EvaluateBlendEquation(combiner_output, srcfactor, dest, dstfactor, params.blend_equation_a).a();
            } else {
                switch (registers.output_merger.logic_op.op) {
                case LogicOp::Set:
                    blend_output = combiner_output;
                    break;

                case LogicOp::Noop:
                    blend_output = dest;
                    break;

                default:
                    throw std::runtime_error(fmt::format("Unknown logic op {:#x}", static_cast<uint32_t>(registers.output_merger.logic_op.op.Value())));
                }
            }

            if (!registers.output_merger.color_write_enable_r) {
                blend_output.r() = dest.r();
            }
            if (!registers.output_merger.color_write_enable_g) {
                blend_output.g() = dest.g();
            }
            if (!registers.output_merger.color_write_enable_b) {
                blend_output.b() = dest.b();
            }
            if (!registers.output_merger.color_write_enable_a) {
                blend_output.a() = dest.a();
            }

            DrawPixel(context, x >> 4, y >> 4, blend_output);
        }
    }
}

void ProcessTriangle(Context& context,
                     const VertexShader::OutputVertex& v0,
                     const VertexShader::OutputVertex& v1,
                     const VertexShader::OutputVertex& v2) {
    ProcessTriangleInternal(context, v0, v1, v2);
}

} // namespace Rasterizer

} // namespace Pica
