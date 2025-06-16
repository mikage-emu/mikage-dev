#pragma once

#include <fmt/format.h>

#include <array>
#include <cstdint>
#include <functional>
#include <stdexcept>

enum class GenericImageFormat {
    // Color framebuffer formats
    RGBA8,
    RGB8,
    RGB565,
    RGBA5551,
    RGBA4,

    // Depth-stencil buffer formats
    D16,
    D24,
    D24S8,

    // Texture formats
    IA8,
    RG8,
    I8,
    A8,
    IA4,
    I4,
    A4,
    ETC1,   // compressed
    ETC1A4, // compressed

    Unknown
};

template<> struct fmt::formatter<GenericImageFormat> : fmt::formatter<std::string_view> {
    template<typename FormatContext>
    auto format(GenericImageFormat format, FormatContext& ctx) const -> decltype(ctx.out()) {
        std::string_view name = std::invoke([format]() -> std::string_view {
            switch (format) {
            case GenericImageFormat::RGBA8:    return "RGBA8";
            case GenericImageFormat::RGB8:     return "RGB8";
            case GenericImageFormat::RGB565:   return "RGB565";
            case GenericImageFormat::RGBA5551: return "RGBA5551";
            case GenericImageFormat::RGBA4:    return "RGBA4";
            case GenericImageFormat::D16:      return "D16";
            case GenericImageFormat::D24:      return "D24";
            case GenericImageFormat::D24S8:    return "D24S8";
            case GenericImageFormat::IA8:      return "IA8";
            case GenericImageFormat::RG8:      return "RG8";
            case GenericImageFormat::I8:       return "I8";
            case GenericImageFormat::A8:       return "A8";
            case GenericImageFormat::IA4:      return "IA4";
            case GenericImageFormat::I4:       return "I4";
            case GenericImageFormat::A4:       return "A4";
            case GenericImageFormat::ETC1:     return "ETC1";
            case GenericImageFormat::ETC1A4:   return "ETC1A4";

            default:
                throw std::runtime_error("formatter: Unknown GenericImageFormat");
            }
        });
        return formatter<std::string_view>::format(name, ctx);
    }
};

static constexpr uint32_t NibblesPerPixel(GenericImageFormat format) {
    switch (format) {
    case GenericImageFormat::RGBA8:
    case GenericImageFormat::D24S8:
        return 8;

    case GenericImageFormat::RGB8:
    case GenericImageFormat::D24:
        return 6;

    case GenericImageFormat::RGB565:
    case GenericImageFormat::RGBA5551:
    case GenericImageFormat::RGBA4:
    case GenericImageFormat::D16:
    case GenericImageFormat::IA8:
    case GenericImageFormat::RG8:
        return 4;

    case GenericImageFormat::I8:
    case GenericImageFormat::A8:
    case GenericImageFormat::IA4:
        return 2;

    case GenericImageFormat::I4:
    case GenericImageFormat::A4:
        return 1;

    default:
        throw std::runtime_error("NibblesPerPixel: Unknown GenericImageFormat");
    }
}

static constexpr uint32_t TextureSize(GenericImageFormat format, uint32_t width, uint32_t height) {
    switch (format) {
    case GenericImageFormat::ETC1:
    case GenericImageFormat::ETC1A4:
    {
        // TODO: Untested
        if ((width % 8) || (height % 8)) {
            throw std::runtime_error("Unaligned ETC texture dimensions");
        }
        // Previous had the wrong size here. citrace-player research uncovered these textures should be larger
        auto bpp = (format == GenericImageFormat::ETC1) ? 1 : 2;
//        return (width / 8) * 4 * bpp * (height / 8);
        return width * bpp * height / 2;
    }

    default:
        return width * height * NibblesPerPixel(format) / 2;
    }
}

template<typename Type>
constexpr GenericImageFormat ToGenericFormat(Type format) {
    auto [raw] = format;
    if (raw < std::size(Type::format_map)) {
        return Type::format_map[raw];
    } else {
        return GenericImageFormat::Unknown;
    }
}

template<typename Type>
constexpr Type FromGenericFormat(GenericImageFormat format) {
    for (uint32_t raw_target_format = 0; raw_target_format < std::size(Type::format_map); ++raw_target_format) {
        if (Type::format_map[raw_target_format] == format) {
            return Type { raw_target_format };
        }
    }

    throw std::runtime_error("Unknown GenericImageFormat");
}

template<typename T>
constexpr bool operator ==(T format, GenericImageFormat reference) {
    auto [raw_left] = format;
    auto [raw_right] = FromGenericFormat<T>(reference);
    return (raw_left == raw_right);
}

template<typename Enum>
[[maybe_unused]] constexpr static uint32_t NibblesPerPixel(Enum format) {
    return NibblesPerPixel(ToGenericFormat(format));
}

template<typename To, typename From>
[[maybe_unused]] constexpr static To ConvertFormatTo(From format) {
    return FromGenericFormat<To>(ToGenericFormat(format));
}

template<typename Type>
constexpr auto GetStorage(Type format) {
    // The format may only have one member, which is the storage
    auto [storage] = format;
    static_assert(sizeof(storage) == sizeof(format), "Format type may not have more than one member");
    return storage;
}

template<typename Type>
Type FromRawValue(decltype(GetStorage(std::declval<Type>())) value) {
    if (value >= std::size(Type::format_map)) {
        throw std::runtime_error("Failed to construct format from raw value");
    }
    return Type { value };
}
