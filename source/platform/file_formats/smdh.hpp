#pragma once

#include <framework/formats.hpp>
#include <framework/bit_field_new.hpp>

#include <boost/hana/define_struct.hpp>

#include <cstdint>
#include <array>

namespace FileFormat {
struct SMDH {
    struct SMDHApplicationTitle {
        BOOST_HANA_DEFINE_STRUCT(SMDHApplicationTitle,
            (std::array<uint16_t, 0x40>, short_description),
            (std::array<uint16_t, 0x80>, long_description),
            (std::array<uint16_t, 0x40>, publisher_name)
        );
        
        struct Tags : expected_size_tag<0x200> {};
    };
    
    struct SMDHEULAVersion {
        BOOST_HANA_DEFINE_STRUCT(SMDHEULAVersion,
            (uint8_t, minor),
            (uint8_t, major)
        );
        
        struct Tags : expected_size_tag<0x2> {};
    };
    
    enum SMDHFlags : uint32_t {
        Visible                      = 1 << 0,
        Autoboot                     = 1 << 1,
        Allow3D                      = 1 << 2,
        RequireAcceptEULA            = 1 << 3,
        AutoSaveOnExit               = 1 << 4,
        UseExtendedBanner            = 1 << 5,
        RequireGameRating            = 1 << 6,
        UsesSaveData                 = 1 << 7,
        RecordUsageData              = 1 << 8,
        DisableSaveBackup            = 1 << 10,
        New3DSExclusive              = 1 << 12,
        RestrictedByParentalControls = 1 << 14,
    };
    
    struct SMDHApplicationSettings {
        BOOST_HANA_DEFINE_STRUCT(SMDHApplicationSettings,
            (std::array<uint8_t, 16>, age_ratings),
            (uint32_t, region_flags),
            (uint32_t, matchmaker_id),
            (uint64_t, matchmaker_bit_id),
            (uint32_t, flags),
            (SMDHEULAVersion, eula_version),
            (uint16_t, reserved),
            (uint32_t, optimal_animation_default_frame),
            (uint32_t, cec_id)
        );
        
        struct Tags : expected_size_tag<0x30> {};
    };
    
    BOOST_HANA_DEFINE_STRUCT(SMDH,
        (std::array<uint8_t, 4>, magic),
        (uint16_t, version),
        (std::array<uint8_t, 2>, reserved0),
        (std::array<SMDHApplicationTitle, 16>, application_titles),
        (SMDHApplicationSettings, application_settings),
        (std::array<uint8_t, 8>, reserved1),
        (std::array<uint8_t, 0x480>, small_icon),
        (std::array<uint8_t, 0x1200>, large_icon)
    );
    
    struct Tags : expected_size_tag<0x36C0> {};
};

}  // namespace FileFormat