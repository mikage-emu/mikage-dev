#pragma once

#include "pxi_fs.hpp"

namespace HLE {

namespace PXI {

namespace FS {

class FileBufferInEmulatedMemory : public FileBuffer {
    OS::FakeThread& thread;
    PXIBuffer buffer;

public:
    FileBufferInEmulatedMemory(OS::FakeThread& thread, const PXIBuffer& buffer) : thread(thread), buffer(buffer) {
    }

    void Write(const char* source, uint32_t num_bytes) override {
        for (uint32_t buffer_offset = 0; buffer_offset < num_bytes; ++buffer_offset) {
            buffer.Write<uint8_t>(thread, buffer_offset, source[buffer_offset]);
        }
    }
};

} // namespace FS

} // namespace PXI

} // namespace HLE
