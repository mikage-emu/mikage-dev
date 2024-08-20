#pragma once

#include "ipc.hpp"

namespace Platform {

/**
 * SOC: Handles network sockets
 */
namespace SOC {

using InitializeSockets = Platform::IPC::IPCCommand<0x1>::add_uint32::add_process_id::add_handle<IPC::HandleType::SharedMemoryBlock>::response;
using Socket = Platform::IPC::IPCCommand<0x2>::add_uint32::add_uint32::add_uint32::add_process_id::response::add_uint32;
using Listen = Platform::IPC::IPCCommand<0x3>::add_uint32::add_uint32::add_process_id::response::add_uint32;
using Accept = Platform::IPC::IPCCommand<0x4>::add_uint32::add_uint32::add_process_id::response::add_uint32::add_static_buffer;
using Bind = Platform::IPC::IPCCommand<0x5>::add_uint32::add_uint32::add_process_id::add_static_buffer::response::add_uint32;
using Connect = Platform::IPC::IPCCommand<0x6>::add_uint32::add_uint32::add_process_id::add_static_buffer::response::add_uint32;
using RecvFromOther = Platform::IPC::IPCCommand<0x7>::add_uint32::add_uint32::add_uint32::add_uint32::add_process_id::add_buffer_mapping_write::response::add_uint32::add_static_buffer::add_buffer_mapping_write;
using RecvFrom = Platform::IPC::IPCCommand<0x8>::add_uint32::add_uint32::add_uint32::add_uint32::add_process_id::response::add_uint32::add_uint32::add_static_buffer::add_static_buffer;
using SendToOther = Platform::IPC::IPCCommand<0x9>::add_uint32::add_uint32::add_uint32::add_uint32::add_process_id::add_static_buffer::add_buffer_mapping_read::response::add_uint32::add_buffer_mapping_read;
using SendTo = Platform::IPC::IPCCommand<0xA>::add_uint32::add_uint32::add_uint32::add_uint32::add_process_id::add_static_buffer::add_static_buffer::response::add_uint32;
using Close = Platform::IPC::IPCCommand<0xB>::add_uint32::add_process_id::response::add_uint32;
using Shutdown = Platform::IPC::IPCCommand<0xC>::add_uint32::add_uint32::add_process_id::response::add_uint32;
using GetHostByName = Platform::IPC::IPCCommand<0xD>::add_uint32::add_uint32::add_static_buffer::response::add_uint32::add_static_buffer;
using GetHostByAddr = Platform::IPC::IPCCommand<0xE>::add_uint32::add_uint32::add_uint32::add_static_buffer::response::add_uint32::add_static_buffer;
using GetAddrInfo = Platform::IPC::IPCCommand<0xF>::add_uint32::add_uint32::add_uint32::add_uint32::add_static_buffer::add_static_buffer::add_static_buffer::response::add_uint32::add_uint32::add_static_buffer;
using GetNameInfo = Platform::IPC::IPCCommand<0x10>::add_uint32::add_uint32::add_uint32::add_uint32::add_static_buffer::response::add_uint32::add_static_buffer::add_static_buffer;
using GetSockOpt = Platform::IPC::IPCCommand<0x11>::add_uint32::add_uint32::add_uint32::add_uint32::add_process_id::response::add_uint32::add_uint32::add_static_buffer;
using SetSockOpt = Platform::IPC::IPCCommand<0x12>::add_uint32::add_uint32::add_uint32::add_uint32::add_process_id::add_static_buffer::response::add_uint32;
using Fcntl = Platform::IPC::IPCCommand<0x13>::add_uint32::add_uint32::add_uint32::add_process_id::response::add_uint32;
using Poll = Platform::IPC::IPCCommand<0x14>::add_uint32::add_uint32::add_process_id::add_static_buffer::response::add_uint32::add_static_buffer;
using SockAtMark = Platform::IPC::IPCCommand<0x15>::add_uint32::add_process_id::response::add_uint32;
using GetHostId = Platform::IPC::IPCCommand<0x16>::response::add_uint32;
using GetSockName = Platform::IPC::IPCCommand<0x17>::add_uint32::add_uint32::add_process_id::response::add_uint32::add_static_buffer;
using GetPeerName = Platform::IPC::IPCCommand<0x18>::add_uint32::add_uint32::add_process_id::response::add_uint32::add_static_buffer;
using ShutdownSockets = Platform::IPC::IPCCommand<0x19>::response;
using GetNetworkOpt = Platform::IPC::IPCCommand<0x1A>::add_uint32::add_uint32::add_uint32::response::add_uint32::add_uint32::add_static_buffer;
using SendToMultiple = Platform::IPC::IPCCommand<0x20>::add_uint32::add_uint32::add_uint32::add_uint32::add_uint32::add_process_id::add_static_buffer::add_static_buffer::response::add_uint32;
using CloseSockets = Platform::IPC::IPCCommand<0x21>::add_process_id::response;
using AddGlobalSocket = Platform::IPC::IPCCommand<0x23>::add_uint32::response;

} // namespace SOC

} // namespace Platform
