from conan import ConanFile

class MikageConan(ConanFile):
    name = "mikage"
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps"

    requires = [
        #"boost/1.79.0",
        "boost/1.84.0",
        "spdlog/1.15.0",
        "cryptopp/8.5.0",
        "sdl/2.0.20", # 2.0.18 fixed swapped X/Y buttons on Switch Pro Controller
        "range-v3/0.11.0",
        "catch2/2.13.7",
        "glslang/1.3.268.0",
        "spirv-tools/1.3.268.0",
        "tracy/0.11.1",
        "xxhash/0.8.0",
        "fmt/11.1.1",
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
        # Pistache does not build on clang
        if self.settings.os != "Android" and self.settings.compiler != "clang":
            self.requires("pistache/cci.20201127")

        if self.settings.os != "Android":
            self.requires("libunwind/1.8.0")
