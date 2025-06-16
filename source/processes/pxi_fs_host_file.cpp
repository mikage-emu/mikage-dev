#include "pxi_fs.hpp"
#include "pxi.hpp"

#include "pxi_fs_file_buffer_emu.hpp"

#include <framework/exceptions.hpp>

#include <boost/filesystem.hpp>

#include <iostream>

namespace HLE {

namespace PXI {

namespace FS {

using OS::FakeThread;
using OS::ResultAnd;

HostFile::HostFile(std::string_view path, Policy policy) : path(std::begin(path), std::end(path)), policy(policy) {
    stream.exceptions(std::ifstream::failbit | std::ifstream::badbit | std::ifstream::eofbit);
}

ResultAnd<> HostFile::Open(FileContext& context, OpenFlags flags) {
    context.logger.info("Attempting to open {} (create={})", path.string(), flags.create);

    if (!flags.create && !boost::filesystem::exists(path)) {
        return std::make_tuple(-1);
    }

    // NOTE: When we only specify read-mode, this would fail to create a file. Test what happens on the actual system in such a case!
    auto stream_flags = std::ios_base::binary;
    if (flags.read) {
        stream_flags |= std::ios_base::in;
    }
    if (flags.write) {
        stream_flags |= std::ios_base::out;
    }
    if (flags.create) {
        stream_flags |= std::ios_base::trunc;
    }

    try {
        // TODO: We should make sure files are never opened twice instead (currently, this happens for gamecard though). What if, for instance, one were to call Open twice with different flags? The stream wouldn't get updated for this change!
        if (!stream.is_open())
            stream.open(path, stream_flags);
    } catch (...) {
        throw std::runtime_error(fmt::format("Failed to open {}, err: {}", path.string(), strerror(errno)));
    }
    return std::make_tuple(OS::RESULT_OK);
}

void HostFile::Close(/*FakeThread& thread*/) {
    stream.close();
}

ResultAnd<uint64_t> HostFile::GetSize(FileContext& context) {
    context.logger.info("Attempting to get size of file {}", path.string());

    uint64_t size = boost::filesystem::file_size(path);

    return std::make_tuple(OS::RESULT_OK, size);
}

ResultAnd<> HostFile::SetSize(FakeThread& thread, uint64_t size) {
    thread.GetLogger()->info("Attempting to set size of file {} to {:#x}", path.string(), size);

    // TODO: Does this zero-fill the file as expected?
    // TODO: Expected by whom? If these are not the 3DS semantics, we still would want to have deterministic buffer contents here!
    boost::filesystem::resize_file(path, size);

    return std::make_tuple(OS::RESULT_OK);
}

ResultAnd<uint32_t> HostFile::Read(FileContext&, uint64_t offset, uint32_t num_bytes, FileBuffer&& dest) {
    // TODO: Support partial reads
    std::vector<uint8_t> data;
    data.resize(num_bytes);
    stream.seekg(offset, std::ios_base::beg);
    stream.read(reinterpret_cast<char*>(data.data()), num_bytes);

    dest.Write(reinterpret_cast<char*>(data.data()), num_bytes);

    return std::make_tuple(OS::RESULT_OK, num_bytes);
}

ResultAnd<uint32_t> HostFile::Overwrite(OS::FakeThread& thread, uint64_t offset, uint32_t num_bytes, const PXIBuffer& input) {
    stream.seekp(0, std::ios_base::end);
    auto end = stream.tellp();
    stream.seekp(offset, std::ios_base::beg);
    auto bytes_left = end - stream.tellp();

    if (bytes_left < num_bytes)
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);

    // TODO: Support partial writes
    std::vector<uint8_t> data;
    data.reserve(num_bytes);
    for (uint32_t buffer_offset = 0; buffer_offset < num_bytes; ++buffer_offset)
        data.push_back(input.Read<uint8_t>(thread, buffer_offset));

    stream.write(reinterpret_cast<char*>(data.data()), num_bytes);

    return std::make_tuple(OS::RESULT_OK, num_bytes);
}

FileView::FileView(std::unique_ptr<File> file, uint64_t offset, uint32_t num_bytes, boost::optional<std::array<uint8_t, 0x20>> precomputed_hash)
    : file(std::move(file)), offset(offset), num_bytes(num_bytes), precomputed_hash(precomputed_hash) {
    // NOTE: Apparently loader always tries to load the RomFS via PXIFS archive 0x2345678e, even when no RomFS is present. Hence we must be able to let this pass, at least for now...
//     if (num_bytes != 0) {
//         throw std::runtime_error("Cannot have a zero-sized FileView");
//     }
}

OS::ResultAnd<> FileView::Open(FileContext& context, OpenFlags flags) {
    context.logger.info("Opening FileView at offset={:#x} for {:#x} bytes of data", offset, num_bytes);

    if (auto [result, size] = file->GetSize(context); result != OS::RESULT_OK || offset + num_bytes > size) {
        throw Mikage::Exceptions::Invalid(  "Attempted to open FileView at range {:#x}-{:#x} exceeding the original file size {:#x} (result {:#x})",
                                            offset, offset + num_bytes, size, result);
    }

    // The "create" flag doesn't have well-defined semantics for file views
    if (flags.create) {
        throw std::runtime_error("Cannot set create flag on file views");
    }

    return file->Open(context, flags);
}

OS::ResultAnd<uint64_t> FileView::GetSize(FileContext&) {
    return std::make_tuple(OS::RESULT_OK, num_bytes);
}

OS::ResultAnd<uint32_t> FileView::Read(FileContext& context, uint64_t offset_in_view, uint32_t bytes_to_read, FileBuffer&& dest) {
    if (this->num_bytes == 0) {
        return std::make_tuple(OS::RESULT_OK, uint32_t { 0 });
    }
    if (offset_in_view + bytes_to_read > this->num_bytes) {
        throw std::runtime_error(fmt::format("Requested reading {:#x} bytes from offset {:#x}, but there are only {:#x} total bytes of data in this file view", bytes_to_read, offset_in_view, this->num_bytes));
    }

    auto ret = file->Read(context, this->offset + offset_in_view, bytes_to_read, std::move(dest));

    return ret;

//     return file->Read(thread, this->offset + offset_in_view, bytes_to_read, dest);
}

OS::ResultAnd<uint32_t> FileView::Overwrite(OS::FakeThread& thread, uint64_t offset_in_view, uint32_t bytes_to_write, const PXIBuffer& input) {
    if (offset_in_view + bytes_to_write > this->num_bytes)
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);

    // TODO: Recompute file hash??? Is this necessary at all?

    return file->Overwrite(thread, this->offset + offset_in_view, bytes_to_write, input);
}

std::array<uint8_t, 0x20> FileView::GetFileHash(OS::FakeThread& thread) const {
    if (!precomputed_hash)
        thread.CallSVC(&OS::OS::SVCBreak, OS::OS::BreakReason::Panic);

    return *precomputed_hash;
}

std::unique_ptr<File> FileView::ReleaseParentAndClose() {
    auto parent = std::move(file);
    Close();
    return parent;
}

} // namespace FS

} // namespace PXI

} // namespace HLE
