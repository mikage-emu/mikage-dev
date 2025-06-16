from conan import ConanFile

class MikageConan(ConanFile):
    name = "mikage"
    settings = "os", "compiler", "build_type", "arch"
    generators = ["CMakeDeps", "CMakeToolchain"]

    requires = [
        #"boost/1.79.0",
        "boost/1.84.0",
        "spdlog/1.15.3",
        "cryptopp/8.5.0",
        "sdl/2.30.7", # 2.0.18 fixed swapped X/Y buttons on Switch Pro Controller
        "range-v3/0.12.0",
        "catch2/2.13.7",
        "glslang/1.3.268.0",
        "spirv-tools/1.3.268.0",
        "tracy/0.11.1",
        "xxhash/0.8.0",
        "fmt/11.2.0",
    ]

    options = {
        "enable_profiler": [True, False]
    }

    default_options = {
        "enable_profiler": False
    }

    def configure(self):
        # TODO: Works around conan-center-index issue 7118
        self.options["sdl"].nas = False
        self.options["sdl"].alsa = False
        self.options["sdl"].shared = True
        self.options["pulseaudio"].shared = True
        self.options["pulseaudio"].with_alsa = False
        #self.options["sdl"].nas = True

        self.options["tracy"].enable = self.options.enable_profiler
        self.options["tracy"].fibers = True

        if self.settings.os == "Android":
            # With zlib, libxml2 pulls in pkgconf, which Conan can't build for Android
            self.options["libxml2"].zlib = False

    def requirements(self):
        # Conan does not support building Pistache on Windows and Android
        if self.settings.os != "Windows" and self.settings.os != "Android":
            self.requires("pistache/0.4.25")

        if self.settings.os == "Linux":
            self.requires("libunwind/1.8.0")

        if self.settings.os == "Macos":
            self.requires("vulkan-loader/1.3.268.0", force=True)
            self.requires("spirv-cross/1.3.268.0", force=True) # for moltenvk
            self.requires("moltenvk/1.2.2", force=True)
            self.requires("vulkan-headers/1.3.268.0", force=True) # must be a direct dependency to avoid homebrew headers from being pulled in
