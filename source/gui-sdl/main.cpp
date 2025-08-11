#define SDL_MAIN_HANDLED
#include "audio_frontend_sdl.hpp"

#include <ui/key_database.hpp>

#include "platform/file_formats/cia.hpp"
#include "platform/file_formats/ncch.hpp"
#include "processes/pxi_fs.hpp"
#define VULKAN_HPP_DISPATCH_LOADER_DYNAMIC 1

#include "session.hpp"
#include "os.hpp"

#include "framework/logging.hpp"
#include "framework/meta_tools.hpp"
#include "framework/ranges.hpp"
#include "framework/settings.hpp"
#include <framework/profiler.hpp>

#include <SDL.h>
#include <SDL_vulkan.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <boost/program_options.hpp>
#include <boost/endian/arithmetic.hpp>

#include <range/v3/algorithm/any_of.hpp>
#include <range/v3/algorithm/equal.hpp>
#include <range/v3/algorithm/none_of.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/split.hpp>

#include <chrono>
#include <codecvt>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <thread>

#include <vulkan/vulkan.hpp>



void InstallCIA(std::filesystem::path, spdlog::logger&, const KeyDatabase&, HLE::PXI::FS::FileContext&, HLE::PXI::FS::File&);


using boost::endian::big_uint32_t;

static const char* app_name = "Mikage";

#include "sdl_vulkan_display.hpp"

std::mutex g_vulkan_queue_mutex; // TODO: Turn into a proper interface

namespace bpo = boost::program_options;


static volatile int wait_debugger = 0;

namespace Settings {


inline std::istream& operator>>(std::istream& is, ShaderEngine& engine) {
    std::string str;
    is >> str;
    if (str == "interpreter") {
        engine = ShaderEngine::Interpreter;
    } else if (str == "bytecode") {
        engine = ShaderEngine::Bytecode;
    } else if (str == "glsl") {
        engine = ShaderEngine::GLSL;
    } else {
        is.setstate(std::ios_base::failbit);
    }
    return is;
}

inline std::ostream& operator<<(std::ostream& os, ShaderEngine engine) {
    switch (engine) {
    case ShaderEngine::Interpreter:
        return (os << "interpreter");

    case ShaderEngine::Bytecode:
        return (os << "bytecode");

    case ShaderEngine::GLSL:
        return (os << "glsl");
    }
    return os;
}

}

namespace CustomEvents {
enum {
    CirclePadPosition = SDL_USEREVENT
};
}

int main(int argc, char* argv[]) {
    while (wait_debugger) {

    }

    Settings::Settings settings;

    bool enable_logging;
    bool bootstrap_nand;
    {
        std::string filename;
        bool enable_debugging;


        bpo::options_description desc("Allowed options");
        desc.add_options()
            ("help", "produce help message")
            ("input", bpo::value<std::string>(&filename), "Input file to load")
            ("launch_menu", bpo::bool_switch(), "Launch Home Menu from NAND on startup")
            ("debug", bpo::bool_switch(&enable_debugging), "Connect to GDB upon startup")
            ("dump_frames", bpo::bool_switch(), "Dump frame data")
            // TODO: Instead read this from the game image... or add support for software reboots!
            ("appmemtype", bpo::value<unsigned>()->default_value(0), "APPMEMTYPE for configuration memory")
            ("attach_to_process", bpo::value<unsigned>(), "Process to attach the debugger (if enabled) to during startup")
            ("render_on_cpu", bpo::bool_switch(), "Render 3D graphics in software")
            ("shader_engine", bpo::value<Settings::ShaderEngine>()->default_value(Settings::ShaderEngineTag::default_value()), "Select which Shader engine to use (interpreter, bytecode, or glsl)")
            ("enable_logging", bpo::bool_switch(&enable_logging), "Enable logging (slow!)")
            ("bootstrap_nand", bpo::bool_switch(&bootstrap_nand), "Bootstrap NAND from game update partition")
            ("enable_audio", bpo::bool_switch(), "Enable audio emulation (slow!)")
            ;

        boost::program_options::positional_options_description p;
        p.add("input", -1);

        bpo::variables_map vm;
        try {
            bpo::store(bpo::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
            if (vm.count("help")) {
                std::cout << desc << std::endl;
                return 0;
            }
            if (!vm.count("input") && !vm["launch_menu"].as<bool>())
                throw bpo::required_option("input or launch_menu"); // TODO: Better string?

            if (vm["debug"].as<bool>() || vm.count("attach_to_process")) {
                if (!vm["debug"].as<bool>() || !vm.count("attach_to_process")) {
                    throw std::runtime_error("Cannot use either of --debug or --attach_to_process without specifying the other");
                }
            }

            bpo::notify(vm);
        } catch (bpo::required_option& e) {
            std::cerr << "ERROR: " << e.what() << std::endl;
            return 1;
        } catch (bpo::invalid_command_line_syntax& e) {
            std::cerr << "ERROR, invalid command line syntax: " << e.what() << std::endl;
            return 1;
        } catch (bpo::multiple_occurrences& e) {
            std::cerr << "ERROR: " << e.what() << std::endl;
            return 1;
        }



        // Prefer XDG_DATA_DIRS, then /usr/local/share, then /usr/share
        auto xdg_data_dirs = getenv("XDG_DATA_DIRS");

        #ifdef _WIN32
            // On Windows, use the AppData/Roaming directory for the mikage folder
            char* appdata = getenv("APPDATA");
            if (!appdata) {
                throw std::runtime_error("Could not determine APPDATA path. Please ensure the APPDATA environment variable is set.");
            }
            auto data_dirs = std::string { appdata } + "\\mikage";
            if (!std::filesystem::exists(data_dirs)) {
                std::filesystem::create_directories(data_dirs);
            }
        #else
            auto data_dirs = std::string { (xdg_data_dirs && *xdg_data_dirs != 0) ? xdg_data_dirs : "/usr/local/share:/usr/share" };
        #endif
        std::cout << "Using data directory: " << data_dirs << std::endl;

        #ifdef _WIN32
            // On Windows, ensure paths use backslashes and check for the mikage folder directly
            auto candidate = data_dirs;
            if (std::filesystem::exists(candidate)) {
                settings.set<Settings::PathImmutableDataDir>(std::move(candidate));
            }
        #else
            for (auto data_dir : data_dirs | ranges::views::split(':')) {
                auto candidate = ranges::to<std::string>(data_dir) + "/mikage";
                if (std::filesystem::exists(candidate)) {
                    settings.set<Settings::PathImmutableDataDir>(std::move(candidate));
                    break;
                }
            }
        #endif
        if (!std::filesystem::exists(settings.get<Settings::PathImmutableDataDir>())) {
            throw std::runtime_error("Immutable data directory does not exist. Re-run the install step");
        }

        auto fill_home_path = [](std::string path) {
        #ifdef _WIN32
            // On Windows, use USERPROFILE instead of HOME
            auto home_dir = getenv("USERPROFILE");
        #else
            auto home_dir = getenv("HOME");
        #endif
            if (!home_dir) {
                throw std::runtime_error("Could not determine path to home directory. Please set the HOME or USERPROFILE environment variable");
            }
            if (!path.starts_with("/HOME~/")) {
                return path;
            }
            return path.replace(0, 6, home_dir);
        };
        settings.set<Settings::PathConfigDir>(fill_home_path(settings.get<Settings::PathConfigDir>()));
        settings.set<Settings::PathDataDir>(fill_home_path(settings.get<Settings::PathDataDir>()));
        settings.set<Settings::PathCacheDir>(fill_home_path(settings.get<Settings::PathCacheDir>()));

        settings.set<Settings::DumpFrames>(vm["dump_frames"].as<bool>());
        settings.set<Settings::BootToHomeMenu>(vm["launch_menu"].as<bool>());
        if (enable_debugging) {
            settings.set<Settings::ConnectToDebugger>(true);
            settings.set<Settings::AttachToProcessOnStartup>(vm["attach_to_process"].as<unsigned>());
        }
        settings.set<Settings::AppMemType>(vm["appmemtype"].as<unsigned>());
        if (vm["render_on_cpu"].as<bool>()) {
            settings.set<Settings::RendererTag>(Settings::Renderer::Software);
            if (!vm.count("shader_engine")) {
                // Switch default from GLSL to the bytecode processor
                settings.set<Settings::ShaderEngineTag>(Settings::ShaderEngine::Bytecode);
            }
        }
        settings.set<Settings::ShaderEngineTag>(vm["shader_engine"].as<Settings::ShaderEngine>());
        if (settings.get<Settings::RendererTag>() == Settings::Renderer::Software && settings.get<Settings::ShaderEngineTag>() == Settings::ShaderEngine::GLSL) {
            std::cerr << "ERROR: Cannot use GLSL shader engine with software rendering" << std::endl;
            std::exit(1);
        }

        settings.set<Settings::EnableAudioEmulation>(vm["enable_audio"].as<bool>());

        if (vm.count("input")) {
            Settings::InitialApplicationTag::HostFile file{vm["input"].as<std::string>()};
            settings.set<Settings::InitialApplicationTag>({file});
        }
    }

    auto log_manager = Meta::invoke([enable_logging]() {
        spdlog::sink_ptr logging_sink;
        if (!enable_logging) {
            logging_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
        } else {
            logging_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        }
        return std::make_unique<LogManager>(logging_sink);
    });
    auto frontend_logger = log_manager->RegisterLogger("FRONTEND");

    auto keydb = LoadKeyDatabase(*frontend_logger, "aes_keys.txt");

if (bootstrap_nand) // Experimental system bootstrapper
    try {
        // TODO: Replicate the functionality of ns:s's CardUpdateInitialize on boot:
        //       Compare the title version of CVer in emulated NAND against the title
        //       version in the TMD of the CVer CIA in the game update partition.

        auto gamecard = LoadGameCard(*frontend_logger, settings);
        auto update_partition = gamecard->GetPartitionFromId(Loader::NCSDPartitionId::UpdateData);
        if (!update_partition) {
            throw std::runtime_error("Couldn't find update partition");
        }

        auto file_context = HLE::PXI::FS::FileContext { *frontend_logger };
        auto [result] = (*update_partition)->OpenReadOnly(file_context);
        if (result != HLE::OS::RESULT_OK) {
            throw std::runtime_error("Failed to open update partition");
        }

        // Open RomFS for update partition
        auto romfs = HLE::PXI::FS::NCCHOpenExeFSSection(*frontend_logger, file_context, keydb, std::move(*update_partition), 0, {});

        FileFormat::RomFSLevel3Header level3_header;
        const uint32_t lv3_offset = 0x1000;

        std::tie(result) = romfs->OpenReadOnly(file_context);
        uint32_t bytes_read;
        std::tie(result, bytes_read) = romfs->Read(file_context, lv3_offset, sizeof(level3_header), HLE::PXI::FS::FileBufferInHostMemory(level3_header));
        if (result != HLE::OS::RESULT_OK) {
            throw std::runtime_error("Failed to read update partition RomFS");
        }

        std::filesystem::path content_dir = settings.get<Settings::PathDataDir>() + "/data";

        for (uint32_t metadata_offset = 0; metadata_offset < level3_header.file_metadata_size;) {
            FileFormat::RomFSFileMetadata file_metadata;
            std::tie(result, bytes_read) = romfs->Read(file_context, lv3_offset + level3_header.file_metadata_offset + metadata_offset, sizeof(file_metadata), HLE::PXI::FS::FileBufferInHostMemory(file_metadata));
            if (result != HLE::OS::RESULT_OK) {
                throw std::runtime_error("Failed to read file metadata");
            }
            metadata_offset += sizeof(file_metadata);

            std::u16string filename;
            filename.resize((file_metadata.name_size + 1) / 2);
            std::tie(result, bytes_read) = romfs->Read(file_context, lv3_offset + level3_header.file_metadata_offset + metadata_offset, file_metadata.name_size, HLE::PXI::FS::FileBufferInHostMemory(filename.data(), file_metadata.name_size));
            if (result != HLE::OS::RESULT_OK) {
                throw std::runtime_error("Failed to read filename from metadata");
            }

            std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> conversion;
            std::string filename2 { conversion.to_bytes(filename) };

            fprintf(stderr, "FOUND FILENAME: %s\n", filename2.c_str());

            if (filename2.ends_with(".cia")) {
                auto cia_file = std::make_unique<HLE::PXI::FS::FileView>(std::move(romfs), lv3_offset + level3_header.file_data_offset + file_metadata.data_offset, file_metadata.data_size);
                FileFormat::CIAHeader cia_header;
                std::tie(result, bytes_read) = cia_file->Read(file_context, 0, sizeof(cia_header), HLE::PXI::FS::FileBufferInHostMemory(cia_header));
                if (result != HLE::OS::RESULT_OK) {
                    throw std::runtime_error("Failed to read file data");
                }

                fprintf(stderr, "CIA header size: %#x\n", cia_header.header_size);

                InstallCIA(content_dir, *frontend_logger, keydb, file_context, *cia_file);

                romfs = cia_file->ReleaseParentAndClose();
            }

            // Align filename size to 4 bytes
            metadata_offset += (file_metadata.name_size + 3) & ~3;
        }

        // Copy substitute titles
        std::filesystem::copy(  settings.get<Settings::PathImmutableDataDir>() + "/nand/title", content_dir,
                                std::filesystem::copy_options::skip_existing | std::filesystem::copy_options::recursive);

        std::filesystem::create_directories(content_dir / "ro/sys");
        std::filesystem::create_directories(content_dir / "rw/sys");
        std::filesystem::create_directories(content_dir / "twlp");

        // Create dummy HWCAL0, required for cfg module to work without running initial system setup first
        char zero[128]{};
        {
            std::ofstream hwcal0(content_dir / "ro/sys/HWCAL0.dat");
            const auto size = 2512;
            for (unsigned i = 0; i < size / sizeof(zero); ++i) {
                hwcal0.write(zero, sizeof(zero));
            }
            hwcal0.write(zero, size % sizeof(zero));
        }

        // Dump "logo" to have one for the 3DSX -> Gamecard adaptor
        {
            auto cxi_partition = gamecard->GetPartitionFromId(Loader::NCSDPartitionId::Executable);
            if (!cxi_partition) {
                throw std::runtime_error("Could not find executable partition in gamecard image");
            }
            auto [cxi_open_res] = (*cxi_partition)->OpenReadOnly(file_context);

            if (cxi_open_res != HLE::OS::RESULT_OK) {
                throw std::runtime_error("Could not open executable partition of gamecard image");
            }

            static constexpr const std::array<uint8_t, 8> logo_section_name = { 'l', 'o', 'g', 'o' };
            auto logo_section = HLE::PXI::FS::NCCHOpenExeFSSection(*frontend_logger, file_context, keydb, std::move(*cxi_partition), 2, std::basic_string_view<uint8_t>(logo_section_name.data(), logo_section_name.size()));

            std::ofstream logo_file(settings.get<Settings::PathDataDir>() + "/placeholder_logo.bin", std::ios::binary);

            auto [res, logosize] = logo_section->GetSize(file_context);
            if (res != HLE::OS::RESULT_OK || !logosize) {
                throw std::runtime_error("Could not get size of logo section in gamecart executable partition");
            }

            std::vector<char> logobuf(logosize);
            auto read_res = logo_section->Read(file_context, 0, logosize, HLE::PXI::FS::FileBufferInHostMemory(logobuf.data(), logosize));
            if (read_res != std::tuple{ HLE::OS::RESULT_OK, logosize }) {
                throw std::runtime_error("Could not read logo section in gamecart executable partition");
            }
            logo_file.write(logobuf.data(), logosize);
        }

        // Set up dummy rw/sys/SecureInfo_A with region EU
        // TODO: Let the user select the region
        {
            std::ofstream info(content_dir / "rw/sys/SecureInfo_A");
            info.write(zero, sizeof(zero));
            info.write(zero, sizeof(zero));
            char region = 2; // Europe
            info.write(&region, 1);
            info.write(zero, 0x10);
        }

        // TODO: Set up shared font
        // TODO: Set up GPIO
    } catch (std::runtime_error&) {
        throw;
    }

    // Initialize SDL
//    const unsigned window_width = 800, window_height = 960;
//    const unsigned window_width = 720, window_height = 864;
    const unsigned window_width = 400, window_height = 480;
//    const unsigned window_width = 800, window_height = 480;

    // TODO: Fix indentation... but we do want this scope so that all cleanup is finished by the time we print the final log message
    {
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        frontend_logger->critical("Failed to initialize SDL: {}", SDL_GetError());
        return 1;
    }

    auto audio_frontend = std::make_unique<SDLAudioFrontend>();

    // TODO: For some reason, SDL picks RGB565 as the surface format for us... these hints don't help, either :(
    SDL_GL_SetAttribute(SDL_GL_RED_SIZE, 8);
    SDL_GL_SetAttribute(SDL_GL_BLUE_SIZE, 8);
    SDL_GL_SetAttribute(SDL_GL_GREEN_SIZE, 8);
    SDL_GL_SetAttribute(SDL_GL_ALPHA_SIZE, 8);

    const bool enable_fullscreen = false;
//    const bool enable_fullscreen = true;
    auto sdl_window_flags = enable_fullscreen ? (SDL_WINDOW_VULKAN | SDL_WINDOW_FULLSCREEN_DESKTOP) : SDL_WINDOW_VULKAN;
    std::unique_ptr<SDL_Window, void(*)(SDL_Window*)> window(SDL_CreateWindow(app_name, SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED, window_width, window_height, sdl_window_flags), SDL_DestroyWindow);
    if (!window) {
        throw std::runtime_error("Failed to create window");
    }

    int actual_window_width, actual_window_height;
    SDL_GetWindowSize(&*window, &actual_window_width, &actual_window_height);

    std::array<Layout, SDLVulkanDisplay::FrameData::num_screen_ids> layouts;
    if (enable_fullscreen) {
        // Stretch top screen image by an integral factor; hide the bottom screen
        // TODO: Allow for unhiding the bottom screen!
        unsigned factor = std::min(actual_window_width / 400, actual_window_height / 480);
        unsigned usable_window_width = factor * 400;
        unsigned usable_window_height = factor * 240;
        // NOTE: For recording, make sure the screen positions are aligned by 16
        layouts = {{
//            { true, 0/*(actual_window_width - usable_window_width) / 2*/, 0, static_cast<uint32_t>(usable_window_width), static_cast<uint32_t>(usable_window_width * 240 / 400) },
//            { false, 0, 0, 0, 0 },
////            { false, 0, 0, 0, 0 },
//            { true, static_cast<uint32_t>(usable_window_width) * 40 / 400, (actual_window_height - usable_window_height), static_cast<uint32_t>(usable_window_width) * 320 / 400, static_cast<uint32_t>(usable_window_width * 240 / 400) },
            { true, 28, /*40*/ 180, 400 * 3, 240 * 3 },
            { false, 0, 0, 0, 0 },
//            { false, 0, 0, 0, 0 },
//            { true, 1920 - 640 - 35 + 3, 1080 - 300 - 480 + 4, 640, 480 }, // vertically-centered bottom screen
            { true, 1920 - 640 - 28 + 3, 180, 640, 480 }, // top-aligned bottom screen
        }};
    } else {
        unsigned usable_window_width = actual_window_width;
        unsigned usable_window_height = actual_window_height;
        unsigned bottom_width = usable_window_width * 320 / 400;
        unsigned bottom_height = bottom_width * 240 / 320;
        if (bottom_height * 2 > (unsigned)usable_window_height) {
            bottom_height = usable_window_height / 2;
            bottom_width = bottom_height * 320 / 240;
            usable_window_width = bottom_width * 400 / 320;
        }
        layouts = {{
            { true, (actual_window_width - usable_window_width) / 2, 0, static_cast<uint32_t>(usable_window_width), static_cast<uint32_t>(bottom_width * 240 / 320) },
            { false, 0, 0, 0, 0 },
            { true, (actual_window_width - bottom_width) / 2, static_cast<uint32_t>(bottom_width * 240 / 320), static_cast<uint32_t>(bottom_width), static_cast<uint32_t>(bottom_width * 240 / 320) },
//            { true, 0, 0, 400, 240 },
//            { false, 0, 0, 0, 0 },
//            { true, 400, 120, 320, 240 },
        }};
    }

    if (settings.get<Settings::DumpFrames>()) {
        throw std::runtime_error("Frame dumping not implemented");
    }


    auto display = std::make_unique<SDLVulkanDisplay>(frontend_logger, *window, layouts);



    std::thread emuthread;
    std::exception_ptr emuthread_exception = nullptr;

    std::unique_ptr<EmuSession> session;

    try {
        for (auto key_index : ranges::views::indexes(keydb.aes_slots)) {
            auto& aes_slot = keydb.aes_slots[key_index];
            for (auto key_type : { 'X', 'Y', 'N' }) {
                auto& key = key_type == 'X' ? aes_slot.x
                            : key_type == 'Y' ? aes_slot.y
                            : aes_slot.n;
                if (key.has_value()) {
                    frontend_logger->info("Parsed key{} for slot {:#4x}", key_type, key_index);
                }
            }
        }
        for (auto key_index : ranges::views::indexes(keydb.common_y)) {
            auto& key = keydb.common_y[key_index];
            if (key.has_value()) {
                frontend_logger->info("Parsed common{}", key_index);
            }
        }

    auto gamecard = LoadGameCard(*frontend_logger, settings);
    session = std::make_unique<EmuSession>(*log_manager, settings, *audio_frontend, *display, *display, keydb, std::move(gamecard));

    emuthread = std::thread {
        [&emuthread_exception, &session]() {
            try {
                session->Run();
            } catch (...) {
                emuthread_exception = std::current_exception();
            }
        }
    };

    bool background = false;

    auto& input = session->input;
    auto& circle_pad = session->circle_pad;

//    std::array<bool, 3> active_images { };
//    std::array<bool, 3> active_images { true, false, true };
    std::array<bool, 3> active_images { true, true, true };

    // Application loop
    for (;;) {
        // Process event queue
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            switch (event.type) {
            case SDL_WINDOWEVENT:
                switch (event.window.event) {
                case SDL_WINDOWEVENT_EXPOSED:
                    frontend_logger->error("SDL_WINDOWEVENT_EXPOSED");
//                    SDL_RenderClear(renderer.get());
//                    SDL_RenderPresent(renderer.get());
                    break;

                case SDL_WINDOWEVENT_CLOSE:
                    frontend_logger->error("SDL_WINDOWEVENT_CLOSE");
                    goto quit_application_loop;

                case SDL_WINDOWEVENT_RESIZED:
                    frontend_logger->error("SDL_WINDOWEVENT_RESIZED");
                    break;

                default:
                    break;
                }
                break;

            case SDL_QUIT:
                frontend_logger->error("SDL_QUIT");
                goto quit_application_loop;

            case SDL_APP_WILLENTERBACKGROUND:
                frontend_logger->error("About to enter background, destroying swapchain");
                display->ResetSwapchainResources();
                background = true;
                break;

            case SDL_APP_DIDENTERFOREGROUND:
                frontend_logger->error("Entered foreground, recreating swapchain");
                display->CreateSwapchain();
                background = false;
                break;

            case SDL_MOUSEBUTTONDOWN:
            {
                if (event.button.button != SDL_BUTTON_LEFT) {
                    break;
                }

                float x = (event.button.x - layouts[2].x) / static_cast<float>(layouts[2].width);
                float y = (event.button.y - layouts[2].y) / static_cast<float>(layouts[2].height);
                if (x >= 0.f && x <= 1.f && y >= 0.f && y <= 1.f) {
                    input.SetTouch(x, y);
                }

                break;
            }

            // NOTE: SDL provides a separate event type for touch events, but
            //       (at least on Android) it dispatches both touch events and
            //       mouse events upon touch input. Hence, we only need to
            //       handle mouse events
            case SDL_MOUSEMOTION:
            {
                if ((event.motion.state & SDL_BUTTON_LMASK) == 0) {
                    break;
                }

                float x = (event.button.x - layouts[2].x) / static_cast<float>(layouts[2].width);
                float y = (event.button.y - layouts[2].y) / static_cast<float>(layouts[2].height);
                if (x >= 0.f && x <= 1.f && y >= 0.f && y <= 1.f) {
                    input.SetTouch(x, y);
                } else {
                    // NOTE: If the user keeps holding the mouse button when
                    //       moving the mouse outside the emulated screen area,
                    //       they presumably do not intend to stop the touch
                    //       gesture, yet
                }

                break;
            }

            case SDL_MOUSEBUTTONUP:
                if (event.button.button != SDL_BUTTON_LEFT) {
                    break;
                }

                input.EndTouch();
                break;

            // TODO: Need a way for the emulator to acknowledge key presses!
            //       Otherwise, we might process a KEYDOWN event followed by
            //       KEYUP before the emulator core provides the next content
            //       frame
            case SDL_KEYDOWN:
            case SDL_KEYUP:
            {
                // Ignore repeats
                if (event.key.repeat) {
                    // TODO: Does this actually occur in practice?
                    break;
                }

                bool pressed = (event.type == SDL_KEYDOWN);

                // TODO: For the default key mappings, use scancodes (physical key positions in QWERTY layout) and map them to key codes (the key actually pressed as seen by the user)
                switch (event.key.keysym.sym) {
                case SDLK_LEFT:
                    input.SetPressedY(pressed);
                    break;

                case SDLK_UP:
                    input.SetPressedX(pressed);
                    break;

                case SDLK_DOWN:
                    input.SetPressedB(pressed);
                    break;

                case SDLK_RIGHT:
                    input.SetPressedA(pressed);
                    break;

                case SDLK_BACKSPACE:
                    input.SetPressedHome(pressed);
                    break;

                case SDLK_q:
                case SDLK_VOLUMEUP:
                    input.SetPressedL(pressed);
                    break;

                case SDLK_e:
                case SDLK_VOLUMEDOWN:
                    input.SetPressedR(pressed);
                    break;

                case SDLK_RETURN:
                    input.SetPressedStart(pressed);
                    break;

                case SDLK_LSHIFT:
                case SDLK_RSHIFT:
                    input.SetPressedSelect(pressed);
                    break;

                case SDLK_a:
                    circle_pad.first -= 1.0f * (pressed ? 1.0 : -1.0);
                    input.SetCirclePad(circle_pad.first, circle_pad.second);
                    break;

                case SDLK_d:
                    circle_pad.first += 1.0f * (pressed ? 1.0 : -1.0);
                    input.SetCirclePad(circle_pad.first, circle_pad.second);
                    break;

                case SDLK_w:
                    circle_pad.second += 1.0f * (pressed ? 1.0 : -1.0);
                    input.SetCirclePad(circle_pad.first, circle_pad.second);
                    break;

                case SDLK_s:
                    circle_pad.second -= 1.0f * (pressed ? 1.0 : -1.0);
                    input.SetCirclePad(circle_pad.first, circle_pad.second);
                    break;

                case SDLK_j:
                    input.SetPressedDigiLeft(pressed);
                    break;

                case SDLK_l:
                    input.SetPressedDigiRight(pressed);
                    break;

                case SDLK_i:
                    input.SetPressedDigiUp(pressed);
                    break;

                case SDLK_k:
                    input.SetPressedDigiDown(pressed);
                    break;

                case SDLK_7:
                    if (settings.get<Settings::RendererTag>() == Settings::Renderer::Vulkan) {
                        settings.set<Settings::RendererTag>(Settings::Renderer::Software);
                    } else {
                        settings.set<Settings::RendererTag>(Settings::Renderer::Vulkan);
                    }
                    break;

                case SDLK_AC_BACK:
                    if (event.type == SDL_KEYDOWN) {
                        goto quit_application_loop;
                    }
                    break;
                }
                break;
            }


            case CustomEvents::CirclePadPosition:
            {
                float x, y;
                memcpy(&x, &event.user.data1, sizeof(x));
                memcpy(&y, reinterpret_cast<char*>(&event.user.data1) + sizeof(x), sizeof(y));
                input.SetCirclePad(x, y);
                break;
            }

            default:
                break;
            }
        }

        if (background) {
            continue;
        }

        // Limit to ~60 FPS. This avoids starving the emulation thread when locking g_vulkan_queue_mutex
        std::this_thread::sleep_for(std::chrono::milliseconds { 15 });

        // Process next frame from the emulation core, if any (and do so three times for each screen id... TODO: Find a nicer way of doing this)
        display->BeginFrame();

        // Repeat until at least one image is active

static int loll = 0;
loll++;

// TODO: Proper time keeping
display->SeekTo(loll * 3);

// TODO: If recording via renderdoc, wait for all active images to arrive
//std::this_thread::sleep_for(std::chrono::milliseconds { 20 });
//std::this_thread::sleep_for(std::chrono::milliseconds { 30 });
        for (auto stream_id : { EmuDisplay::DataStreamId::TopScreenLeftEye, EmuDisplay::DataStreamId::TopScreenRightEye, EmuDisplay::DataStreamId::BottomScreen }) {
            // TODO: If capturing with renderdoc, sync presentation to rendering
//            while (stream_id == EmuDisplay::DataStreamId::TopScreenLeftEye && display->ready_frames[Meta::to_underlying(stream_id)].empty()) {
//                display->SeekTo(loll * 3);
//                std::this_thread::yield();
//            }

            // TODO: Add EmuDisplay interface
            if (display->ready_frames[Meta::to_underlying(stream_id)].empty()) {
                continue;
            }
            auto& frame = display->GetCurrent(stream_id);
//            fprintf(stderr, "Processing frame %lu\n", frame.timestamp);
            display->ProcessDataSource(frame, stream_id);
        }

#if 0 // TODO: Port entire logic over
        auto begin_frame_time = std::chrono::steady_clock::now();
        for (std::array<bool, 3> has_new_image { }; true;) {
#ifdef RENDERDOC_WORKAROUND
            if (!has_new_image[0] && !has_new_image[2]) {
                dumb_lock = true;
            }
#endif

            if (!has_new_image[0]) {
                has_new_image[0] = display->initial_stage->TryToDisplayNextDataSource(EmuDisplay::DataStreamId::TopScreenLeftEye);
            }
            if (!has_new_image[1]) {
                has_new_image[1] = display->initial_stage->TryToDisplayNextDataSource(EmuDisplay::DataStreamId::TopScreenRightEye);
            }
            if (!has_new_image[2]) {
                has_new_image[2] = display->initial_stage->TryToDisplayNextDataSource(EmuDisplay::DataStreamId::BottomScreen);
            }

            // If any image has been submitted, wait until at least one top screen and one bottom screen image have arrived. Otherwise, we'd artificially limit ourselves to 30 fps (on a 60 Hz display) by pulling the two images in separate frames since since the images don't arrive simultaneously

            if (emuthread_exception) {
                break;
            }

            // Infer screen activity information from MMIO instead
            using namespace std::chrono_literals;
            // Check if any new images have become active
            if (!ranges::equal(has_new_image, active_images, std::less_equal{})) {
                for (unsigned i = 0; i < std::size(active_images); ++i) {
                    active_images[i] |= has_new_image[i];
                }
                if (ranges::find(active_images, false) != std::end(active_images)) {
                    // Wait a bit in case others become active too so that we
                    // avoid displaying the images in separate host frames.
                    std::this_thread::sleep_for(3ms);
                    continue;
                } else {
                    break;
                }
            }

            // Wait until *any* image is active
            if (ranges::find(active_images, true) == ranges::end(active_images)) {
                std::this_thread::yield();
                continue;
            }

            // Wait until all images have been submitted that have been found to be active
            if (has_new_image[0] == active_images[0] && has_new_image[1] == active_images[1] && has_new_image[2] == active_images[2]) {
                break;
            }

            // Move frames to "inactive" state if no new image is received for more than one host frame interval
            if (std::chrono::steady_clock::now() - begin_frame_time > 17ms) {
                for (unsigned i = 0; i < std::size(active_images); ++i) {
                    active_images[i] &= has_new_image[i];
                }
                break;
            }

            std::this_thread::yield();
        }
#endif

        {
            std::unique_lock lock(g_vulkan_queue_mutex);
            display->EndFrame();
        }
#ifdef RENDERDOC_WORKAROUND
        dumb_lock = true;
#endif

        auto metrics = session->profiler.Freeze();
        auto print_metrics = [&frontend_logger](std::string indent, Profiler::FrozenMetrics& frozen, auto& cont) -> void {
            frontend_logger->info("{}{}: {} ms", indent, frozen.activity.GetName(), frozen.metric.total.count() / 1000.f);
            indent += "  ";
            auto misc_activity = std::accumulate(frozen.sub_metrics.begin(), frozen.sub_metrics.end(), frozen.metric.total,
                                                 [](auto& dur, auto& frozen) { return dur - frozen.metric.total; });
            if (misc_activity.count() < 0) {
                // TODO
//                throw std::runtime_error("Negative misc activity?");
            }
            // Don't print misc activity if there are any sub activities to begin with, or if the relative difference is negligible
            if (!frozen.sub_metrics.empty() && misc_activity >= frozen.metric.total * 0.03 ) {
                frontend_logger->info("{}Misc: {} ms", indent, misc_activity.count() / 1000.f);
            }
            for (auto& sub_activity : frozen.sub_metrics) {
                cont(indent, sub_activity, cont);
            }
        };
//        frontend_logger->info("PROFILE:");
//        print_metrics("", metrics, print_metrics);

        // TODO: Have the emu thread post an SDL event about this instead of checking every frame
        if (emuthread_exception) {
            std::rethrow_exception(emuthread_exception);
        }
    }
    } catch (std::exception& err) {
        // TODO: On Android, the "back" button doesn't do anything while this is displayed
        frontend_logger->error(err.what());
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Emulation error", err.what(), nullptr);
        goto quit_application_loop;
    } catch (...) {
        auto message = "Unhandled exception!\n";
        frontend_logger->error(message);
        // TODO: On Android, the "back" button doesn't do anything while this is displayed
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Emulation error", "Unknown exception", nullptr);
        goto quit_application_loop;
    }
quit_application_loop:
    frontend_logger->info("Initiating emulator shutdown...");

    if (session) {
        display->exit_requested = true;
        if (session->setup->os) {
            session->setup->os->RequestStop();
        }

        // Wait for emulation thread (OS) to shut down.
        // This may be in one of these blocking states:
        // * OS scheduler stuck in an infinite idle loop
        //   * An internal flag set by RequestStop() is checked here
        // * Attempting to push frame data when no queue slot is available
        //   * Display::exit_requested is checked here
        // * CPU emulation stuck in a loop (e.g. due to the emulated app waiting on external events using a spinlock)
        //   * This is handled indirectly by regular preemption
        frontend_logger->info("Waiting for emulation thread...");
        emuthread.join();

        // Wait for the host GPU to catch up now that no more work will be pushed
        frontend_logger->info("Waiting for host GPU to be idle...");
        display->graphics_queue.waitIdle();
        display->present_queue.waitIdle();
        display->device->waitIdle();


        session.reset();
    }

    frontend_logger->info("Clearing display resources...");
    display->ClearResources();

    frontend_logger->info("Clearing remaining resources...");
    }
    frontend_logger->info("... done. Have a nice day!");

    // NOTE: This function isn't actually the true main(), since SDL overrides
    //       it. Hence we must explicitly return 0 here (whereas usually 0 is
    //       implicitly returned from main)
    return 0;
}
