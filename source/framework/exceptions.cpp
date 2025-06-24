#include "exceptions.hpp"

#if __has_include(<libunwind.h>)
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#endif

#include <boost/core/demangle.hpp>

#include <filesystem>
#include <string>

namespace Mikage::Exceptions {

std::string generate_backtrace() {
    std::string ret;

#if __has_include(<libunwind.h>)
    unw_cursor_t cursor; unw_context_t uc;
    unw_word_t ip, sp;

    char name[256];

    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);

    int frame = 0;
    while (unw_step(&cursor) > 0) {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        unw_get_reg(&cursor, UNW_REG_SP, &sp);
        unw_word_t offp;
        unw_get_proc_name(&cursor, name, sizeof(name), &offp);
        ret += fmt::format("{:>3} {:#014x} in {} (sp={:#014x})\n", "#" + std::to_string(frame++), ip, boost::core::demangle(name).c_str(), sp);
    }
#endif
    return ret;
}

std::string ContractViolated::FormatMessage(std::string_view condition, std::string_view function, std::string_view file, int line) {
    return fmt::format( "Failed assertion '{}' in {} ({}:{})\n",
                        condition, function, std::filesystem::path(file).filename().string(), line);
}

} // namespace Mikage::Exceptions
