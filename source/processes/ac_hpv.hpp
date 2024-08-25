#pragma once

#include "os_hypervisor_private.hpp"

namespace HLE::OS::HPV {

struct ACContext : SessionContext {
};

HPV::RefCounted<Object> CreateAcService(RefCounted<Port> port, ACContext&);

} // namespace HLE::OS::HPV
