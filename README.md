# Mikage Developer Edition

## Build instructions

CMake and Conan 2 are required to build Mikage.
* `mkdir build`
* `cd build`
* `conan install .. -of . --build=missing` (add `-s build_type=Debug` for Debug builds)
* `cmake .. -G Ninja --toolchain conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release`
* `ninja && sudo ninja install`

NOTE: On Linux, Vulkan libraries are also required and will NOT be built by Conan.

Some dependencies may be provided by system packages instead of building them
via Conan. To enable this behavior, add the following to your Conan profile
(`~/.conan2/profiles/default`):
```ini
[platform_requires]
boost/1.80.0
cryptopp/8.5.0
sdl/2.0.20
range-v3/0.11.0
catch2/2.13.7
libunwind/1.8.0
```

### GCC 15 and newer

Due to a change in default compilation flags in GCC 15, the `conan` step above may fail. If this happens, append the following two lines to your Conan profile (`~/.conan2/profiles/default`) and try again:
```ini
[conf]
tools.build:cflags=["-std=gnu17"]
```

## Usage

For the first launch, three things must be set up:
1. a complete `aes_keys.txt` must be placed in the `build` folder
2. a virtual NAND must be bootstrapped from a game update partition
3. the 3DS initial system setup must be run

Given any game with an update partition, steps 2 and 3 can be done by running:
```
cd build && source conanrun.sh && ./source/mikage game.cci --bootstrap_nand --launch_menu
```
NOTE: Currently, this probably requires a game of the EU region. Patching
`SecureInfo_A` by hand after bootstrapping may work, too.

Once set up, it's sufficient to run `./source/mikage game.cci` or `./source/mikage --launch_menu`.
You'll need to `source conanrun.sh` to set up library directories.

## Key bindings

* Arrow →: A
* Arrow ↓: B
* Arrow ↑: X
* Arrow ←: Y
* WASD keys: Circle pad
* Backspace: HOME (press twice to power down)
* Q key: L
* E key: R
* IJKL keys: D-pad
* Enter key: START
* Shift key: SELECT

## Debugging

Individual processes may be debugged through an embedded GDB remote server over
network port 12345. To enable it, pass `--debug` and `--attach_to_process <pid>`
when launching Mikage. After startup, connect via gdb using `tar ext :12345`,
wait until Mikage prints a message about waiting for the debugger attach, then
type `attach <PID>` in the gdb shell. Note that a gdb build for ARM targets may
be necessary to do this. Debuggers other than gdb may work but are untested.

Processes running in the emulated kernel can be introspected through a simple
debug console available via telnet on port 12347.

## Profiling

Mikage uses [Tracy](https://github.com/wolfpld/tracy) for profiling. To enable it,
pass `-o enable_profiler=True` to `conan install` and rebuild Mikage.
Get your Tracy server (often available from the system package manager) up and
running and start listening for clients. Then launch Mikage and your server will
start recording. Each emulator frame will be captured containing the Tracy Zones
that have been defined throughout Mikage's code.
