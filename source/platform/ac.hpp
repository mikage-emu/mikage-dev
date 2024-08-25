#pragma once

#include "ipc.hpp"

namespace Platform::AC {

struct NetworkSetting {
  char data[0xc00];
};

using CreateDefaultConfig = IPC::IPCCommand<0x1>::response::add_static_buffer;

using ConnectAsync = IPC::IPCCommand<0x4>::add_process_id::add_handle<IPC::HandleType::Event>::add_static_buffer::response;

using CancelConnectAsync = IPC::IPCCommand<0x7>::add_process_id::response;

// Reports status after calling ConnectSync?
// According to libctru: 1 = not connected, 3 = connected
using GetConnectStatus = IPC::IPCCommand<0xc>::response::add_uint32;

using GetWifiStatus = IPC::IPCCommand<0xd>::response::add_uint32;

// Response unknown
using Unknown_ViaConnectTest = IPC::IPCCommand<0x15>::add_process_id::add_handle<IPC::HandleType::Event>::response;

using Unknown_0x16 = IPC::IPCCommand<0x16>::add_process_id::response;

using Unknown_0x19 = IPC::IPCCommand<0x19>::add_process_id::add_handle<IPC::HandleType::Event>::response;

using Unknown_0x1a = IPC::IPCCommand<0x1a>::add_process_id::response;

using Unknown_0x22 = IPC::IPCCommand<0x22>::add_uint32::add_static_buffer::response::add_static_buffer;

using Unknown_0x25 = IPC::IPCCommand<0x25>::add_uint32::add_static_buffer::response::add_static_buffer;

using SetInfraPriority = IPC::IPCCommand<0x26>::add_uint32::add_static_buffer::response::add_static_buffer;
using GetInfraPriority = IPC::IPCCommand<0x27>::add_static_buffer::response::add_uint32;

// Returns a static buffer of 0x200 bytes
using SetRequestEulaVersion = IPC::IPCCommand<0x2d>::add_uint32::add_uint32::add_static_buffer::response::add_static_buffer;

// TODO: Unknown what reply this sends
// NOTE: Contrary to what the name (taken from 3dbrew) suggests, the client sends the event
using GetNZoneBeaconNotFoundEvent = IPC::IPCCommand<0x2f>::add_process_id::add_handle<IPC::HandleType::Event>::response;

using GetStatusChangeEvent = IPC::IPCCommand<0x31>::add_process_id::response::add_handle<IPC::HandleType::Event>;

using SetClientVersion = IPC::IPCCommand<0x40>::add_uint32::add_process_id::response;

} // namespace Platform::AC
