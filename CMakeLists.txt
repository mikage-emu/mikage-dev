# 3.11 added support for interface libraries
# 3.13 detects and target-izes all of our boost dependencies properly
# 3.15 added CMAKE_FIND_PACKAGE_PREFER_CONFIG
cmake_minimum_required(VERSION 3.15)

include(ExternalProject)

project(mikage)

enable_testing()

set(OVERRIDE_LINKER "" CACHE STRING "Linker to use for compilation")
if (OVERRIDE_LINKER)
    add_link_options("-fuse-ld=${OVERRIDE_LINKER}")
endif()

option(USE_ASAN "Enable address sanitizer" OFF)
if (USE_ASAN)
    add_compile_definitions(BOOST_USE_ASAN)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-Werror=implicit-fallthrough)
add_compile_options(-Werror=return-type)
add_compile_options(-Werror=unused-result)

# Prefer Conan-provided packages over system ones
set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)


# TODO: Move these flags into a "boost" cmake target
add_definitions(-DBOOST_FILESYSTEM_NO_DEPRECATED -DBOOST_COROUTINES_NO_DEPRECATION_WARNING)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fstrict-aliasing -Wpedantic -Wfatal-errors -Wdocumentation -Weverything -Wextra -Wconversion -Wno-c++98-compat -Wno-c++98-c++11-compat-pedantic -Wno-c++98-compat-pedantic")
# TODO: Consider -Wsuggest-override (since GCC 5.1)
# TODO: When using clang, use -Wno-gnu-statement-expression: Necessary to prevent warning spam when using clang and the assert macro
# TODO: When using clang, -Weverything
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fstrict-aliasing -Wpedantic -Wfatal-errors -Wdocumentation")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fstrict-aliasing -Wpedantic")

set(BOOST_COMPONENTS context filesystem iostreams program_options thread)
find_package(Boost 1.84.0 REQUIRED COMPONENTS ${BOOST_COMPONENTS})

find_package(fmt REQUIRED)

find_package(range-v3 REQUIRED)

find_package(SDL2 REQUIRED)

find_package(spdlog REQUIRED)

include(FindPkgConfig)

find_package(cryptopp)
if (NOT cryptopp_FOUND)
    pkg_search_module(cryptopp REQUIRED IMPORTED_TARGET cryptopp libcryptopp)
    add_library(cryptopp::cryptopp ALIAS PkgConfig::cryptopp)
endif()

find_package(Pistache)
if (Pistache_FOUND)
    add_compile_definitions(ENABLE_PISTACHE=1)
else()
    add_compile_definitions(ENABLE_PISTACHE=0)
endif()

find_package(Catch2 REQUIRED)

find_package(Tracy REQUIRED)

find_package(xxHash)
if (NOT xxHash_FOUND)
    pkg_search_module(xxHash REQUIRED IMPORTED_TARGET xxHash libxxhash)
    add_library(xxHash::xxhash ALIAS PkgConfig::xxHash)
endif()

find_package(Vulkan REQUIRED)

find_package(glslang REQUIRED)

# TODO: These don't actually work for some reason :<
#set_property(TARGET proj PROPERTY CXX_STANDARD 14)
#set_property(TARGET proj PROPERTY CXX_STANDARD_REQUIRED ON)

if(NOT ANDROID)
    find_package(libunwind)
    if (NOT libunwind_FOUND)
        pkg_search_module(libunwind IMPORTED_TARGET libunwind)
        add_library(libunwind::unwind ALIAS PkgConfig::libunwind)
    endif()
endif ()

include(FetchContent)
FetchContent_Declare(teakra
  GIT_REPOSITORY https://github.com/mikage-emu/teakra.git
  GIT_TAG        f99ce8b0c0400b6e20a566ca0a3483ffb4b4e95c)
FetchContent_MakeAvailable(teakra)
set_target_properties(teakra_c PROPERTIES EXCLUDE_FROM_ALL 1)

add_subdirectory(source)
add_subdirectory(data/nand_archives)
if(NOT ANDROID)
    add_subdirectory(tools/3dsx_to_cia)
    #add_subdirectory(tools/embed_title)
    #add_subdirectory(tools/install_cia)
endif()
