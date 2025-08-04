#pragma once

#include "framework/settings.hpp"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace HLE {
namespace PXI {
namespace FS {
class Archive;
class File;
}
}
}

namespace Loader {

/// TODO: This is what's called "Content Index" in other places
enum class NCSDPartitionId {
    Executable        = 0,
    Manual            = 1,
    DownloadPlayChild = 2,
    UpdateDataNew3DS  = 6,
    UpdateData        = 7
};

/**
 * Top-level game card interface.
 */
class GameCard {
public:
    /**
     * Return a pointer to a File from which the partition's NCCH data can be accessed, or std::nullopt if the partition doesn't exist.
     */
    virtual std::optional<std::unique_ptr<HLE::PXI::FS::File>> GetPartitionFromId(NCSDPartitionId id) = 0;
    virtual bool HasPartition(NCSDPartitionId id) = 0;

    virtual ~GameCard();
};

/**
 * Utility to wrap a CXI container into a single-partition GameCard.
 */
class GameCardFromCXI final : public GameCard {
    std::optional<std::unique_ptr<HLE::PXI::FS::File>> GetPartitionFromId(NCSDPartitionId id) override;
    bool HasPartition(NCSDPartitionId id) override;

    // Filename or file descriptor
    std::variant<std::string, int> source;

public:
    GameCardFromCXI(std::string_view filename);
    GameCardFromCXI(int file_descriptor);

    static bool IsLoadableFile(std::string_view filename);
    static bool IsLoadableFile(int file_descriptor);
};

class GameCardFromCCI final : public GameCard {
    std::optional<std::unique_ptr<HLE::PXI::FS::File>> GetPartitionFromId(NCSDPartitionId id) override;
    bool HasPartition(NCSDPartitionId id) override;

    // Filename or file descriptor
    std::variant<std::string, int> source;

public:
    GameCardFromCCI(std::string_view filename);
    GameCardFromCCI(int file_descriptor);

    static bool IsLoadableFile(std::string_view filename);
    static bool IsLoadableFile(int file_descriptor);
};

/**
 * Utility to wrap a 3DSX file into a single-partition GameCard.
 */
class GameCardFrom3DSX final : public GameCard {
    std::optional<std::unique_ptr<HLE::PXI::FS::File>> GetPartitionFromId(NCSDPartitionId id) override;
    bool HasPartition(NCSDPartitionId id) override;

    // Filename or file descriptor
    std::variant<std::string, int> source;

    std::string data_dir_path;

public:
    GameCardFrom3DSX(std::string_view filename, const std::string& data_dir_path);
    GameCardFrom3DSX(int file_descriptor, const std::string& data_dir_path);

    static bool IsLoadableFile(std::string_view filename);
    static bool IsLoadableFile(int file_descriptor);
};

} // namespace Loader
