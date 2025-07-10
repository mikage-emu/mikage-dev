#include "session.hpp"

#include "os.hpp"
#include "processes/pxi_fs.hpp" // Required to check if gamecard has an update partition

#include <loader/gamecard.hpp>

#include <framework/console.hpp>
#include <framework/logging.hpp>
#include <framework/meta_tools.hpp>
#include <framework/profiler.hpp>
#include <framework/settings.hpp>

#include <spdlog/spdlog.h>

#include <memory>

std::unique_ptr<Loader::GameCard> LoadGameCard(spdlog::logger& logger, Settings::Settings& settings) {
    // TODO: Move gamecard initialization below setup so that we can gracefully display gamecard loading errors
    logger.info("Loading gamecard image");
    auto gamecard = Meta::invoke([&]() {
        auto&& visitor = [&](auto&& val) -> std::unique_ptr<Loader::GameCard> {
            if constexpr (std::is_same_v<std::decay_t<decltype(val)>, Settings::InitialApplicationTag::HostFile>) {
                try {
                    if (Loader::GameCardFrom3DSX::IsLoadableFile(val.filename))
                        return std::unique_ptr<Loader::GameCard> { new Loader::GameCardFrom3DSX(val.filename, settings) };
                    else if (Loader::GameCardFromCXI::IsLoadableFile(val.filename))
                        return std::unique_ptr<Loader::GameCard> { new Loader::GameCardFromCXI(val.filename) };
                    else if (Loader::GameCardFromCCI::IsLoadableFile(val.filename))
                        return std::unique_ptr<Loader::GameCard> { new Loader::GameCardFromCCI(val.filename) };
                } catch (std::ios_base::failure& err) {
                    throw std::runtime_error(fmt::format("Could not load game file \"{}\"", val.filename));
                }
            } else if constexpr (std::is_same_v<std::decay_t<decltype(val)>, Settings::InitialApplicationTag::FileDescriptor>) {
                if (Loader::GameCardFrom3DSX::IsLoadableFile(val.fd))
                    return std::unique_ptr<Loader::GameCard> { new Loader::GameCardFrom3DSX(val.fd, settings) };
                else if (Loader::GameCardFromCXI::IsLoadableFile(val.fd))
                    return std::unique_ptr<Loader::GameCard> { new Loader::GameCardFromCXI(val.fd) };
                else if (Loader::GameCardFromCCI::IsLoadableFile(val.fd))
                    return std::unique_ptr<Loader::GameCard> { new Loader::GameCardFromCCI(val.fd) };
            } else if constexpr (std::is_same_v<std::decay_t<decltype(val)>, std::monostate>) {
                return nullptr;
            }
            throw std::runtime_error("Unrecognized input file format. Input must be decrypted and in 3DSX, CCI, or CXI format.");
        };
        return std::visit(visitor, settings.get<Settings::InitialApplicationTag>());
    });

    return gamecard;
}

EmuSession::EmuSession( LogManager& log_manager, Settings::Settings& settings,
                        AudioFrontend& audio, VulkanDeviceManager& vulkan_device_manager,
                        EmuDisplay::EmuDisplay& display, const KeyDatabase& keydb,
                        std::unique_ptr<Loader::GameCard> gamecard)
        : setup(std::make_shared<Interpreter::Setup>(log_manager, keydb, std::move(gamecard), profiler, debug_server)),
        pica {  log_manager.RegisterLogger("Pica"), debug_server, settings, setup->mem, profiler,
                vulkan_device_manager.physical_device, *vulkan_device_manager.device,
                vulkan_device_manager.graphics_queue_index, vulkan_device_manager.graphics_queue } {
    setup->cpus[0].cpu.cpsr.mode = ARM::InternalProcessorMode::User;

    setup->mem.InjectDependency(audio);

    std::unique_ptr<ConsoleModule> os_module;
    std::tie(setup->os, os_module) = HLE::OS::OS::Create(settings, *setup, log_manager, profiler, audio, pica, display);
    for (auto& cpu : setup->cpus)
        cpu.os = setup->os.get();
    setup->os->Initialize();

    pica.InjectDependency(*setup->os.get());
    pica.InjectDependency(setup->mem);
    setup->mem.InjectDependency(pica);

    setup->mem.InjectDependency(input);

    // TODO: Check if we can enable this on Android, too
    network_console = std::make_unique<NetworkConsole>(12347);
    console_thread = std::thread { [os_module=std::move(os_module), &console=*network_console]() mutable {
        console.RegisterModule("os", std::move(os_module));
        console.Run();
    } };

#if ENABLE_PISTACHE
    std::thread debug_server_thread([&]() {
        try {
            debug_server.Run(3001);
        } catch (...) {
//            QMetaObject::invokeMethod(&window, "onEmulatorException", Qt::BlockingQueuedConnection, Q_ARG(std::exception_ptr, std::current_exception()));
////            emuthread_exception = std::current_exception();
//            while(true);
        }
    });
    debug_server_thread.detach();

#endif
}

EmuSession::~EmuSession() {
    // Stop NetworkConsole first so that the console thread can return
    network_console->Stop();
    console_thread.join();

    // TODO: Shut down debug_server
}

void EmuSession::Run() {
    setup->os->Run(setup);
}
