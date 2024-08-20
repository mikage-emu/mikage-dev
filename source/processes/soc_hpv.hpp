#pragma once

#include "os_hypervisor_private.hpp"

namespace HLE {

namespace OS {

namespace HPV {

struct SOCContext : SessionContext {
};

HPV::RefCounted<Object> CreateSocService(RefCounted<Port> port, SOCContext&);

} // namespace HPV

} // namespace HOS

} // namespace HLE
