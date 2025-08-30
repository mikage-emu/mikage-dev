add_subdirectory(framework)
add_subdirectory(platform)
add_subdirectory(video_core)

add_executable(mikage)
target_sources(mikage PRIVATE
               display.cpp
               gdb_stub.cpp
               interpreter.cpp
               input.cpp
               ipc.cpp
               memory.cpp
               pica.cpp
               os.cpp
               os_console.cpp
               os_hypervisor.cpp
               os_serialization.cpp
               session.cpp
               settings.cpp
               arm/processor_default.cpp
               arm/thumb.cpp
               framework/console.cpp
               gui-sdl/main.cpp
               hardware/dsp.cpp
               loader/firm.cpp
               loader/gamecard.cpp
               loader/host_file.cpp
               processes/ac_hpv.cpp
               processes/ac.cpp
               processes/act.cpp
               processes/am.cpp
               processes/am_hpv.cpp
               processes/cam.cpp
               processes/cdc.cpp
               processes/cecd.cpp
               processes/cfg_hpv.cpp
               processes/csnd.cpp
               processes/dlp.cpp
               processes/dsp.cpp
               processes/dsp_hpv.cpp
               processes/dummy.cpp
               processes/errdisp.cpp
               processes/fake_process.cpp
               processes/friend.cpp
               processes/fs.cpp
               processes/fs_common.cpp
               processes/fs_hpv.cpp
               processes/gpio.cpp
               processes/hid.cpp
               processes/http.cpp
               processes/i2c.cpp
               processes/mcu.cpp
               processes/mic.cpp
               processes/ndm.cpp
               processes/ns.cpp
               processes/ns_hpv.cpp
               processes/news.cpp
               processes/nwm.cpp
               processes/pdn.cpp
               processes/ps.cpp
               processes/ptm.cpp
               processes/pxi.cpp
               processes/pxi_fs.cpp
               processes/pxi_fs_host_file.cpp
               processes/ro_hpv.cpp
               processes/sm_hpv.cpp
               processes/soc.cpp
               processes/soc_hpv.cpp
               processes/ssl.cpp
               ui/installer.cpp
               ui/key_database.cpp
               utility/simple_tcp.cpp)


if (Pistache_FOUND)
    target_sources(mikage PRIVATE
               debug_server.cpp
               debug/jit.cpp
               debug/os.cpp)
endif()

target_include_directories(mikage PUBLIC .)
target_link_libraries(mikage PRIVATE framework platform video_core)
target_link_libraries(mikage PRIVATE vulkan-util)
target_link_libraries(mikage PRIVATE teakra)
target_link_libraries(mikage PRIVATE cryptopp::cryptopp)

# std::filesystem library must explicitly be linked on older stdlibc++ versions.
# If needed, set this variable to stdc++fs or c++fs depending on the standard library used.
if (STD_FILESYSTEM_LIBRARY)
    target_link_libraries(mikage PRIVATE ${STD_FILESYSTEM_LIBRARY})
endif ()



target_link_libraries(mikage PRIVATE Boost::boost Boost::context Boost::filesystem Boost::iostreams Boost::program_options Boost::thread)

if (Pistache_FOUND)
    target_link_libraries(mikage PRIVATE Pistache::Pistache)
endif()


target_link_libraries(mikage PRIVATE SDL2::SDL2)

target_link_libraries(mikage PRIVATE spdlog::spdlog)
target_link_libraries(mikage PRIVATE Tracy::TracyClient)

