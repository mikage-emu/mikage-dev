#include "fs_common.hpp"
#include "pxi.hpp"

#include <range/v3/algorithm/find.hpp>
#include <range/v3/algorithm/generate_n.hpp>
#include <range/v3/algorithm/search.hpp>
#include <range/v3/iterator/insert_iterators.hpp>

#include <codecvt>

namespace HLE {

CommonPath CommonPath::FromUtf16(std::u16string_view utf16_data) {
    while (!utf16_data.empty() && utf16_data.back() == 0) {
        utf16_data.remove_suffix(1);
    }
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> conversion;
    return { Utf8PathType { conversion.to_bytes(utf16_data.begin(), utf16_data.end()) } };
}

CommonPath CommonPath::FromUtf16(std::basic_string_view<uint16_t> utf16_data) {
    while (!utf16_data.empty() && utf16_data.back() == 0) {
        utf16_data.remove_suffix(1);
    }
    std::vector<char16_t> char16_data(utf16_data.size());
    std::copy(utf16_data.begin(), utf16_data.end(), char16_data.begin());
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> conversion;
    return { Utf8PathType { conversion.to_bytes(&*char16_data.begin(), &*char16_data.end()) } };
}

CommonPath::CommonPath(OS::Thread& thread, uint32_t type, uint32_t num_bytes, const IPC::StaticBuffer& path)
    : CommonPath(type, num_bytes, [&,offset=0]() mutable { return thread.ReadMemory(path.addr + offset++); }) {
}

CommonPath::CommonPath(OS::Thread& thread, uint32_t type, uint32_t num_bytes, const PXI::PXIBuffer& path)
    : CommonPath(type, num_bytes, [&,offset=0]() mutable { return path.Read<uint8_t>(thread, offset++); }) {
}

template<typename ReadByte>
CommonPath::CommonPath(uint32_t type, uint32_t num_bytes, ReadByte&& read) {
    switch (type) {
    case 1: // empty path
    {
        data = Utf8PathType { };
        break;
    }

    case 2: // binary path
    {
        data = BinaryPathType { };
        auto& path_data = std::get<BinaryPathType>(data);

        if (num_bytes > max_length) {
            throw std::runtime_error(fmt::format("Path length {} exceeded maximum {}", num_bytes, path_data.capacity()));
        }

        ranges::generate_n(ranges::back_inserter(path_data), num_bytes, read);
        break;
    }

    case 3: // ASCII path
    {
        data = Utf8PathType { };
        auto& path = std::get<Utf8PathType>(data);

        path.reserve(num_bytes);
        ranges::generate_n(ranges::back_inserter(path), num_bytes, read);

        // Strip characters past the null terminator
        path.erase(ranges::find(path, '\0'), path.end());
        break;
    }

    case 4: // UTF-16 path
    {
        if (num_bytes % 2)
            throw std::runtime_error("Expected path size for UTF16 to be a multiple of 2");

        // Read in data as UTF-16 with host byte order
        std::u16string utf16_data;
        utf16_data.reserve(num_bytes / 2);
        auto ReadFromAddr = [&]() -> char16_t {
            uint16_t low = read();
            uint32_t high = read();
            return low | (high << uint16_t { 8 });
        };
        ranges::generate_n(ranges::back_inserter(utf16_data), num_bytes / 2, ReadFromAddr);

        // Strip characters past the null terminator
        utf16_data.erase(ranges::find(utf16_data, u'\0'), utf16_data.end());

        *this = FromUtf16(utf16_data);

        break;
    }

    default:
        throw std::runtime_error(fmt::format("Unknown path type {}", type));
    }
}

ValidatedHostPath PathValidator::ValidateAndGetSandboxedTreePath(const Utf8PathType& utf8_path) const {
    auto path = utf8_path.to_std_path().lexically_normal();
    auto path_elements = std::distance(path.begin(), path.end());
    if (path_elements == 0 || *path.begin() != "/") {
        test_mode ? throw IPC::IPCError { 0, 0xe0e046be } // TODO: Throw PathValidator errors instead
                  : throw std::runtime_error("Path does not start with '/'");
    }

    if (path_elements > 1 && *std::next(path.begin()) == "..") {
        test_mode ? throw IPC::IPCError { 0, 0xe0e046be }
                  : throw std::runtime_error("Path escapes root directory");
    }

//        const uint32_t max_filename_length = 0x10; // TODO: Where does this come from? Seems overly short for HostArchives
    const uint32_t max_filename_length = 0x100;
    if (std::prev(path.end())->u8string().size() > max_filename_length) {
        test_mode ? throw IPC::IPCError { 0, 0xe0e046c7 }
                  : throw std::runtime_error("Filename too long");
    }

    // Append path to the sandbox root and double-check that we won't leak out of it
    auto sandbox_root = GetSandboxHostRoot();
    if (!sandbox_root.is_absolute()) {
    // TODO: Required for cfg
//            throw std::runtime_error("Sandbox root is not an absolute path: " + sandbox_root.string());
    }
    sandbox_root = canonical(sandbox_root);

    auto new_path = sandbox_root;
    new_path += utf8_path.to_std_path();
    new_path = new_path.lexically_normal();
    auto new_path_str = new_path.string();
    if (ranges::begin(new_path_str) != ranges::search(new_path_str, sandbox_root.string()).begin()) {
        throw std::runtime_error(fmt::format("Requested path leaked out of sandbox: Got path {}, expected a child of {}", new_path, sandbox_root));
    }
    return ValidatedHostPath { std::move(new_path) };
}

std::filesystem::path GetRootDataDirectory(Settings::Settings& settings) {
    return std::filesystem::path { settings.get<Settings::PathDataDir>() } / "data/";
}

}
