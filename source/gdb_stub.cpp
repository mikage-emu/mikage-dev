#include "gdb_stub.h"
#include "interpreter.h"
#include "os.hpp"

#include "utility/simple_tcp.hpp"

#include "framework/logging.hpp"

#include <boost/asio.hpp>
#include <boost/endian/buffers.hpp>
#include <boost/range/adaptor/indexed.hpp>
#include <boost/range/adaptor/indirected.hpp>
#include <boost/range/adaptor/sliced.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/algorithm/copy.hpp>
#include <boost/range/algorithm/find.hpp>
#include <boost/range/numeric.hpp>

#include <range/v3/algorithm/find.hpp>

#include <cstring>
#include <optional>

#include <iomanip>
#include <iostream>
#include <sstream>

namespace Interpreter {

HLE::OS::Process& GDBStub::GetCurrentProcess() const {
    return GetCurrentThread().GetParentProcess();
}

HLE::OS::Thread& GDBStub::GetCurrentThread() const {
    return *env.active_thread;
}

std::vector<std::shared_ptr<HLE::OS::Thread>> GDBStub::GetThreadList() const {
    throw std::runtime_error("Deprecated.");
    return env.GetThreadList();
}

/*
 * Return the combined process-thread ID for the given OS thread according to
 * the GDB remote protocol (using the format "p<pid>.<tid>").
 * @todo const-ify the "thread" parameter
 */
static std::string GetThreadIdString(HLE::OS::Thread& thread) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << "p"
              << thread.GetParentProcess().GetId() << "."
              << thread.GetId();
    return ss.str();
}

static unsigned char GetChecksum(const std::string& buffer) {
    return boost::accumulate(buffer, (unsigned char)0);
}

static std::optional<unsigned> HexCharToInt(char ch) {
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 0xa;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 0xa;
    if (ch >= '0' && ch <= '9')
        return ch - '0';

    return {};
}

// Optionally returns a number + the number of characters parsed
template<typename RangeType>
static std::optional<std::pair<uint32_t, size_t>> ReadHexNumber(const RangeType& str) {
    uint32_t ret = 0;
    size_t index = 0;

    // Reject pathological inputs
    if (boost::empty(str) || !HexCharToInt(*boost::begin(str)))
        return {};

    for (const auto& c : str) {
        auto digit = HexCharToInt(c);
        // Stop once we reach a character which can't be converted
        if (!digit)
            return std::make_pair(ret, index);

        // Check if there is room for one more digit, return failure otherwise
        if (ret & 0xF0000000)
            return {};

        ret <<= 4;
        ret |= *digit;
        ++index;
    }

    return std::make_pair(ret, (size_t)boost::size(str));
}

using CombinedProcessThreadId = std::pair<HLE::OS::ProcessId, HLE::OS::ThreadId>;

// Parse a combined process and thread id (format "pPID.TID") from the given string.
static std::optional<CombinedProcessThreadId> ParseProcessThreadId(const std::string& str) {
    std::stringstream ss(str, std::ios_base::in);
    uint32_t process_id;
    uint32_t thread_id;
    ss.ignore(1); // Skip "p" (TODO: Assert that it's there!)
    ss >> std::hex >> process_id;
    ss.ignore(1); // Skip period (TODO: Assert that it's there!)
    ss >> std::hex >> thread_id;
    return {{process_id, thread_id}};
}

/**
 * Return true if the given process id refers to "any" process according to the GDB protocol.
 * @todo we shouldn't be using the HLE::OS::ProcessId type for this protocol-specific quantity!
 */
static bool IsAnyProcess(HLE::OS::ProcessId pid) {
    return pid == 0 || pid == -1;
}

/**
 * Return true if the given thread id refers to "any" thread according to the GDB protocol.
 * @todo we shouldn't be using the HLE::OS::ThreadId type for this protocol-specific quantity!
 */
static bool IsAnyThread(HLE::OS::ThreadId tid) {
    return tid == 0 || tid == -1;
}

/**
 * Return true if the given id matches the given process id according to the GDB protocol (i.e. considering that "-1" should match any process).
 * @todo we shouldn't be using the HLE::OS::ProcessId type for the protocol-specific first parameter!
 */
static bool IsSameProcess(HLE::OS::ProcessId gdb_pid, HLE::OS::ProcessId pid) {
    if (IsAnyProcess(gdb_pid)) {
        return true;
    } else {
        return gdb_pid == pid;
    }
}

/**
 * Return true if the given id matches the given thread id according to the GDB protocol (i.e. considering that "-1" should match any thread).
 * @todo we shouldn't be using the HLE::OS::ThreadId type for the protocol-specific first parameter!
 */
static bool IsSameThread(HLE::OS::ThreadId gdb_tid, HLE::OS::ThreadId tid) {
    if (IsAnyThread(gdb_tid)) {
        return true;
    } else {
        return gdb_tid == tid;
    }
}
/**
 * GDB expects these register indices:
 * reg_index = N < 16: rN
 * reg_index = 25: CPSR
 * reg_index = 58: FPSCR
 *
 * Returns no value if the corresponding register hasn't been implemented, yet.
 */
static std::optional<uint32_t> GetRegisterValue(HLE::OS::Thread& thread, size_t reg_index) {
    if (reg_index < 16)
        return thread.GetCPURegisterValue(reg_index);

    if (reg_index == 25)
        return thread.GetCPURegisterValue(17);

    // s0-s31 and fpscr
    if (reg_index >= 26 && reg_index <= 58)
        return thread.GetCPURegisterValue(reg_index - 26 + 18);

    // Unknown register
    return {};
}

// Refer to the GetRegisterValue documentation
static void SetRegisterValue(HLE::OS::Thread& thread, size_t reg_index, uint32_t value) {
    if (reg_index < 16)
        return thread.SetCPURegisterValue(reg_index, value);
}

class GDBStubTCPServer : public SimpleTCPServer {
    GDBStub& stub;

    std::optional<boost::asio::ip::tcp::socket> client;

    boost::asio::streambuf streambuf {};

    char token;

    void OnClientConnected(boost::asio::ip::tcp::socket socket) override {
        client = std::move(socket);
        SetupTokenReceivedHandler();
    }

    void SetupTokenReceivedHandler();

    void SetupCommandLineReceivedHandler();

    void AckReply() {
        char data = '+';
        boost::asio::write(*client, boost::asio::buffer(&data, sizeof(data)));
    }

    void NackReply() {
        char data = '-';
        boost::asio::write(*client, boost::asio::buffer(&data, sizeof(data)));
    }

    void SendPacket(const std::string& message) {
        auto encoded_message = fmt::format("${}#{:02x}", message, GetChecksum(message));
        boost::asio::write(*client, boost::asio::buffer(encoded_message.data(), encoded_message.size()));
        stub.logger->info("Stub{} sending message \"{}\" (length {})", stub.GetCPUId(), encoded_message, encoded_message.length());
    }

    void ReportSignal(HLE::OS::ProcessId pid, HLE::OS::ThreadId tid, int signum) {
        // Format: T05thread:p<processid>.<threadid>;
        // TODO: In addition to the signalled thread, we can (and should) send
        //       register values along with this message. GDB usually requests
        //       those in reaction to this message anyway, hence sending them
        //       directly reduces network bandwidth (especially when stepping
        //       through the program).
        std::stringstream ss;

        ss << "T" << std::hex << std::setfill('0') << std::setw(2) << signum << "thread:p"
           << std::setw(2) << pid << "."
           << std::setw(2) << tid << ";";
        SendPacket(ss.str());

        // Reporting signals seem to reset the thread defined by 'H' operations.
        // TODO: Not sure if this is correct
        // TODO: Especially not sure if this is correct when pid and tid are 0 or -1 (i.e. the "any" IDs)
        for (auto& thread_for_op : stub.thread_for_operation) {
            thread_for_op.second = std::make_pair(pid, tid);
        }
    }

    void ReportSignal(HLE::OS::Thread& thread, int signum) {
        // Format: T05thread:p<processid>.<threadid>;
        // TODO: In addition to the signalled thread, we can (and should) send
        //       register values along with this message. GDB usually requests
        //       those in reaction to this message anyway, hence sending them
        //       directly reduces network bandwidth (especially when stepping
        //       through the program).
        std::stringstream ss;

        ss << "T" << std::hex << std::setfill('0') << std::setw(2) << signum << "thread:p"
           << std::setw(2) << thread.GetParentProcess().GetId() << "."
           << std::setw(2) << thread.GetId() << ";";
        SendPacket(ss.str());

        // Reporting signals seem to reset the thread defined by 'H' operations.
        // TODO: Not sure if this is correct
        for (auto& thread_for_op : stub.thread_for_operation) {
            thread_for_op.second = std::make_pair(thread.GetParentProcess().GetId(), thread.GetId());
        }
    }

    void ReportWatchpointSignal(HLE::OS::Thread& thread, uint32_t address/*, bool read, bool write*/) {
        auto message = fmt::format("T05thread:p{:02x}.{:02x};watch:{:08x};", thread.GetParentProcess().GetId(), thread.GetId(), address);
        SendPacket(message);

        // Reporting signals seem to reset the thread defined by 'H' operations.
        // TODO: Not sure if this is correct
        for (auto& thread_for_op : stub.thread_for_operation) {
            thread_for_op.second = std::make_pair(thread.GetParentProcess().GetId(), thread.GetId());
        }
    }

public:
    void QueuePacket(std::string message) {
        boost::asio::post(io_context, [this, message=std::move(message)]() {
            SendPacket(message);
        });
    }

    void QueueReportSignal(HLE::OS::Thread& thread, int signum) {
        boost::asio::post(io_context, [&thread, signum, this]() {
            ReportSignal(thread, signum);
        });
    }


    GDBStubTCPServer(GDBStub& stub, uint16_t port) : SimpleTCPServer(port), stub(stub) {

    }
};

GDBStub::GDBStub(HLE::OS::OS& os, LogManager& log_manager, unsigned port)
    : env(os), server(std::make_unique<GDBStubTCPServer>(*this, port)), logger(log_manager.RegisterLogger("GDB")) {
    logger->set_pattern("[%T.%e] [%n] [%l] %v");
    logger->info("Stub{} connected!", GetCPUId());

    // Be paused after startup.
    paused = false;
    request_pause = false;
}

GDBStub::~GDBStub() = default;

// TODO: Get rid of this easy-to-get-rid-of global!
static bool core_running = false;

void GDBStub::Continue(bool single_step) {
    if (single_step) {
        RequestStep();
    } else {
        RequestContinue();
        core_running = true;
    }
}

std::shared_ptr<HLE::OS::Thread> GDBStub::GetThreadForOperation(char operation) {
    switch (operation) {
    case 'g':
    case 'm':
    case 'p':
    case 'P':
    case 'X':
    case 'Z':
    case 'z':
    {
        // NOTE: 'g' is the index used for most non-stepping/non-continuing operations.
        // TODO: Input verification (the process ID may be invalid!)
        auto combined_id = thread_for_operation.at('g');
        auto& process = IsAnyProcess(combined_id.first) ? GetCurrentProcess() : *env.GetProcessFromId(combined_id.first);
        auto thread = IsAnyThread(combined_id.second) ? process.threads.back() : process.GetThreadFromId(combined_id.second);
        return thread;
    }

    default:
        return nullptr;
    }
}

std::optional<std::string> GDBStub::HandlePacket(const std::string& command) {
    auto MatchesSubcmd = [&command](const char* subcmd) -> bool{
        return command.compare(1, std::strlen(subcmd), subcmd) == 0;
    };

    // TODO: Assert that the OS is paused!

    switch (command[0]) {
    case '!':
    {
         // Enable extended mode (remote server is persistent)
 //      SendPacket("!");
        return "OK";
    }
    case '?':
    {
        // Sent by GDB upon connecting. This command is fairly ill-documented,
        // but essentially GDB assumes that when attaching to a process,
        // execution of a running process was paused. Hence, we reply with
        // a stop reply.
        // Reply format: T05thread:p<processid>.<threadid>;

        // Let's assume for now this is indeed only used upon connecting, so we won't ever be attached to any processes here.
        assert(attached_processes.empty());
        return "W00";

//        std::stringstream ss;
//        ss << "T" << std::hex << std::setfill('0') << std::setw(2) << 5/*SIGTRAP*/ << "thread:" << GetThreadIdString(GetCurrentThread()) << ";";
//        SendPacket(ss.str());
//        break;
    }

    // NOTE: The following commands have been superseded by "vCont"
/*    case 'c':
    {
        // continue until we find a reason to stop
        Continue();
        return true;
    }*/

/*    case 'C':
    {
        auto signum = (!!HexCharToInt(command[2]))
                     ? ((*HexCharToInt(command[1]) << 4) | *HexCharToInt(command[2]))
                     : *HexCharToInt(command[1]);
        // TODO: Actually handle this properly, for now we just do the same as if 'c' had been sent...
        Continue();
        return true;
    }*/

/*    case 's':
    {
        // single step
        Continue(true);
        ReportSignal(GetCurrentThread(), 5);
        return true; // Let the other CPU core advance by one instruction, too
    }*/

    case 'g':
    {
        if (attached_processes.empty()) {
            return "E01";
        }

        auto thread = GetThreadForOperation('g');

        // Report register values
        std::stringstream ss;
        auto AddU32Value = [&ss](uint32_t val) {
            // NOTE: Register values need to be output in guest byte order!
            boost::endian::endian_buffer<boost::endian::order::little, uint32_t, 32> le_val(val);
            for (auto digit_ptr = le_val.data(); digit_ptr < le_val.data() + sizeof(le_val); ++digit_ptr) {
                ss << std::hex << std::setfill('0') << std::setw(2) << +*(unsigned char*)digit_ptr;
            }
        };
        // Send each register to the server individually
        // (order specified by gdb's internal arm_register_names variable,
        // see GDB's arm-tdep.c; no, this does not seem to be documented elsewhere)
        for (unsigned i = 0; i < 16; ++i) {
            AddU32Value(*GetRegisterValue(*thread, i));
        }
        AddU32Value(*GetRegisterValue(*thread, 25));
        for (unsigned i = 26; i < 58; ++i) {
            AddU32Value(*GetRegisterValue(*thread, i));
        }
        AddU32Value(*GetRegisterValue(*thread, 58)); // FPSCR
        if (ss.str().length())
            return ss.str();
        break;
    }

    case 'H':
    {
        // Set thread for subsequent operations
        // TODO: This needs more testing!
        logger->info("Stub{} set thread for subsequent operations: {}", GetCPUId(), command);
        if (command.length() < 3)
            return "E00";
        auto operation = command[1]; // "c" for continue/step operations, "g" for others
        auto combined_id = ParseProcessThreadId(command.data() + 2);
        if (!combined_id)
            return "E01";

        // NOTE: gdbserver returns an error when the debugger is attached to no threads, so we're doing the same...
        if (attached_processes.empty()) {
            return "E02";
        } else {
            thread_for_operation[operation] = *combined_id;
            return "OK";
        }
        break;
    }

    case 'm':
    {
        auto thread = GetThreadForOperation('m');
        if (!thread)
            return "E00";

        // Read "length" bytes from the given address
        std::stringstream ss(command, std::ios_base::in);
        uint32_t address;
        uint32_t length;
        ss.ignore(1, 'm');
        ss >> std::hex >> address;
        ss.ignore(1, ',');
        ss >> std::hex >> length;

        logger->info("Stub{} reading from {:#x} to {:#x}", GetCPUId(), address, address + length);

        std::stringstream ss_out;
        try {
            for (; length;) {
                // TODO: Optimize this by reading as much data as possible in
                //       32/16-bit chunks. Make sure to consider GDB's
                //       expected byte order for this command, though.
                uint8_t val = thread->ReadMemory(address);
                ss_out << std::hex << std::setfill('0') << std::setw(2) << +val;
                length--;
                address++;
            }
            return ss_out.str();
        } catch (...) {
            auto message = fmt::format("Stub{} invalid memory access", GetCPUId());
            if (!ss_out.str().empty()) {
                logger->warn(message + " (returning partial region)");
                return ss_out.str();
            } else {
                logger->warn(message + " (returning error)");
                return "E00";
            }
        }
        break;
    }

    case 'P':
    {
        auto thread = GetThreadForOperation('P');
        if (!thread)
            return "E00";

        // Set value of register N
        auto index = (!!HexCharToInt(command[2]))
                     ? ((*HexCharToInt(command[1]) << 4) | *HexCharToInt(command[2]))
                     : *HexCharToInt(command[1]);
        auto value_pos = command.find('=', 2);
        if (value_pos == std::string::npos) {
            return "E00";
        }
        ++value_pos;

        // TODO: Setting floating-point registers is untested
        if (index >= 26) {
            throw 5;
        }

        uint32_t value = 0;
        for (unsigned digit_pair = 0; digit_pair < 4; ++digit_pair) {
            uint32_t byte = (*HexCharToInt(command[value_pos + digit_pair * 2]) << 4) | *HexCharToInt(command[value_pos + digit_pair * 2 + 1]);
            value |= byte << (digit_pair * 8);
        }

        SetRegisterValue(*thread, index, value);
        return "OK";
    }

    // Read value of register N
    case 'p':
    {
        auto thread = GetThreadForOperation('p');
        if (!thread)
            return "E00";

        auto index = (!!HexCharToInt(command[2]))
                     ? ((*HexCharToInt(command[1]) << 4) | *HexCharToInt(command[2]))
                     : *HexCharToInt(command[1]);
        std::stringstream ss;

        // TODO: Reading floating-point registers is untested
        if (index >= 26) {
            throw 5;
        }

        auto val = GetRegisterValue(*thread, index);
        if (val) {
            boost::endian::endian_buffer<boost::endian::order::little, uint32_t, 32> le_val(*val);
            for (auto digit_ptr = le_val.data(); digit_ptr < le_val.data() + sizeof(le_val); ++digit_ptr) {
                ss << std::hex << std::setfill('0') << std::setw(2) << +*(unsigned char*)digit_ptr;
            }
        } else {
            ss << "xxxxxxxx";
        }

        return ss.str();
    }

    // Query request
    case 'q':
    {
        if (MatchesSubcmd("Supported")) {
            // PacketSize: We don't have any limit on the maximal packet size - hence report a really large value to speed up memory dumping.
            // multiprocess: Make thread-ids use the syntax "process_id.thread_id" (TODO: Abort if the debugger does not specify "multiprocess+")
            // qXfer:features:read: The command 'qXfer:features:read:...' may be used to obtain register description
            // qXfer:memory-map:read: The command 'qXfer:memory-map:read:...' may be used to query memory mappings
            // exec-events/fork-events: We "support" reporting process forks and execs. We actually abuse this feature to report process launches, since any other method to do so hits unstable code paths in GDB.
            return "PacketSize=16000;multiprocess+;qXfer:features:read+;qXfer:memory-map:read+;exec-events+;fork-events+";
            //SendPacket("PacketSize=200000;multiprocess+");
        } else if (MatchesSubcmd("C")) {
            // TODO: Report current thread ID
            // Send an empty reply until implemented
            // TODO: This causes an assertion failure in GDB 11.2
            return "";
        } else if (MatchesSubcmd("TStatus")) {
            return "T0;tnotrun:0";
        } else if (MatchesSubcmd("Attached:")) {
            // Return whether gdb created a new process (0) or attached to an existing one (1)
            // For now, we always have the remote server attach to a FakeDebugProcess
            // NOTE: This code is disabled for now, since GDB seems to deal just fine with an empty reply
//            SendPacket("E01");
            auto pid_opt = ReadHexNumber(command | boost::adaptors::sliced(10, command.length()));
            if (!pid_opt) {
                return "E01";
            }
//            bool attached = (attached_processes.end() != boost::find(attached_processes, pid_opt->first));
            bool attached = (attached_processes.end() != ranges::find(attached_processes, pid_opt->first));
//            if (!attached)
//                attached_processes.push_back(*pid_opt);
//            SendPacket("1");
            return attached ? "1" : "0";
//            SendPacket(attached ? "1" : "0");
        } else if (MatchesSubcmd("Offsets")) {
            // Contrary to GDB documentation, GDB 7.10 does require a Bss
            // section offset to be given, and oddly enough the offset must
            // match the one given for Data.
            // TODO: Either way, the Data and Bss values just placeholder
            // constants for now and should eventually be retrieved via a
            // proper interface instead.
            return "Text=00100000;Data=00200000;Bss=00200000";
        } else if (MatchesSubcmd("fThreadInfo")) {
            if (attached_processes.empty()) {
                return "l";
            } else {
                // Build and return a list of thread IDs of the format "mp1.2,p2.1,p2.2,p2.3,p5.1"
                using boost::accumulate;
                using boost::adaptors::indirected;
                using boost::adaptors::transformed;
//                auto message = accumulate(GetThreadList() | indirected | transformed(GetThreadIdString),
                auto message = std::string("m");
                for (auto& process : attached_processes) {
                    auto& process_ref = *env.GetProcessFromId(process);
                    message += accumulate(process_ref.threads | indirected | transformed(GetThreadIdString),
                                              std::string(""), [](const auto& str, const auto& next) { return str + next + ","; });
                }
//                auto message = accumulate(attached_processes | transformed(GetThreadIdString),
//                                          std::string("m"), [](const auto& str, const auto& next) { return str + next + ","; });
                message.pop_back(); // Drop trailing comma

                return message;
            }
        } else if (MatchesSubcmd("sThreadInfo")) {
            // Continue list of thread IDs submitted by qfThreadInfo or the previous qsThreadInfo replies.
            // (in our case, we just end the list since we assume the qfThreadInfo reply contained all threads)
            return "l";
        } else if (MatchesSubcmd("ThreadExtraInfo,p")) {
            auto combined_id = ParseProcessThreadId(command.data() + std::string("qThreadExtraInfo,").length());
            if (!combined_id)
                return "E00";

            HLE::OS::ProcessId process_id = combined_id->first;
            HLE::OS::ThreadId thread_id = combined_id->second;

            auto process = env.GetProcessFromId(process_id);
            auto thread = process->GetThreadFromId(thread_id);
            auto raw_reply = process->GetName() + "(" + thread->GetName() + ")";

            // Convert the thread name to a hex encoding of ASCII data
            // NOTE: The ostream_iterator is intentionally using "unsigned"
            //       because otherwise the characters would be output as
            //       actual characters rather than as hex values.
            std::stringstream message_stream;
            message_stream << std::hex;
            boost::copy(raw_reply, std::ostream_iterator<unsigned>(message_stream));
            return message_stream.str();
        } else if (MatchesSubcmd("Xfer:features:read:target.xml")) {
            // Reply with a list of registers present in our emulated CPU
            // NOTE: Do *not* include any '#' in this xml! GDB might interpret that as a message terminator instead
            static const char* xml=R"(l<?xml version="1.0"?>
<!-- Copyright (C) 2007-2016 Free Software Foundation, Inc.

     Copying and distribution of this file, with or without modification,
     are permitted in any medium without royalty provided the copyright
     notice and this notice are preserved.  -->

<!DOCTYPE feature SYSTEM "gdb-target.dtd">
<target>
  <architecture>arm</architecture>
  <feature name="org.gnu.gdb.arm.core">
    <reg name="r0" bitsize="32" type="uint32"/>
    <reg name="r1" bitsize="32" type="uint32"/>
    <reg name="r2" bitsize="32" type="uint32"/>
    <reg name="r3" bitsize="32" type="uint32"/>
    <reg name="r4" bitsize="32" type="uint32"/>
    <reg name="r5" bitsize="32" type="uint32"/>
    <reg name="r6" bitsize="32" type="uint32"/>
    <reg name="r7" bitsize="32" type="uint32"/>
    <reg name="r8" bitsize="32" type="uint32"/>
    <reg name="r9" bitsize="32" type="uint32"/>
    <reg name="r10" bitsize="32" type="uint32"/>
    <reg name="r11" bitsize="32" type="uint32"/>
    <reg name="r12" bitsize="32" type="uint32"/>
    <reg name="sp" bitsize="32" type="data_ptr"/>
    <reg name="lr" bitsize="32"/>
    <reg name="pc" bitsize="32" type="code_ptr"/>

    <!-- The CPSR is register 25, rather than register 16, because
         the FPA registers historically were placed between the PC
         and the CPSR in the "g" packet.  -->
    <reg name="cpsr" bitsize="32" regnum="25"/>
  </feature>
  <feature name="org.gnu.gdb.arm.vfp">
    <reg name="d0" bitsize="64" type="ieee_double"/>
    <reg name="d1" bitsize="64" type="ieee_double"/>
    <reg name="d2" bitsize="64" type="ieee_double"/>
    <reg name="d3" bitsize="64" type="ieee_double"/>
    <reg name="d4" bitsize="64" type="ieee_double"/>
    <reg name="d5" bitsize="64" type="ieee_double"/>
    <reg name="d6" bitsize="64" type="ieee_double"/>
    <reg name="d7" bitsize="64" type="ieee_double"/>
    <reg name="d8" bitsize="64" type="ieee_double"/>
    <reg name="d9" bitsize="64" type="ieee_double"/>
    <reg name="d10" bitsize="64" type="ieee_double"/>
    <reg name="d11" bitsize="64" type="ieee_double"/>
    <reg name="d12" bitsize="64" type="ieee_double"/>
    <reg name="d13" bitsize="64" type="ieee_double"/>
    <reg name="d14" bitsize="64" type="ieee_double"/>
    <reg name="d15" bitsize="64" type="ieee_double"/>

    <reg name="fpscr" bitsize="32" type="int" group="float"/>
  </feature>
</target>)";
            return xml;
        } else if (MatchesSubcmd("Xfer:memory-map:read::")) {
            // Reply with a list of registers present in our emulated CPU
            // NOTE: Do *not* include any '#' in this xml! GDB might interpret that as a message terminator instead
            static const char* xml=R"(l<?xml version="1.0"?>
<!DOCTYPE memory-map
          PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN"
                 "http://sourceware.org/gdb/gdb-memory-map.dtd">
<memory-map>
  <memory type="ram" start="0x100000" length="0x100"/>
</memory-map>)";
            return xml;
        } else {
            // Send an empty reply
            return "";
        }

        break;
    }

    case 'T':
    {
        // Check if a given thread is still alive
        auto combined_id = ParseProcessThreadId(command.data() + 1);
        if (!combined_id)
            return "E00";

        // TODO: Should we recognize the special ids 0 and -1 here?

        auto process = env.GetProcessFromId(combined_id->first);
        if (!process)
            return "E01";

        auto thread = env.GetProcessFromId(combined_id->first);
        if (!process)
            return "E02";

        // TODO: Should check whether "thread" has actually not yet reached the end of its life

        return "OK";
    }

    case 'v':
    {
        if (MatchesSubcmd("Cont?")) {
            // a "vCont?" packet is sent to query what kind of operations are supported for vCont.
            return "vCont;c;s;C;S";
        } else if (MatchesSubcmd("Cont")) {
            // TODO: We currently only pay attention to a single continue
            //       action. Other actions may be used e.g. to resume other
            //       threads of the current process, while the current thread
            //       may only be stepping.
            //       Example: "vCont;s:p2.1;c:p2.-1".

            // TODO: Make sure command[5] == ';'
            // Same as "c", "s", ...
            if (command[6] == 'c') {
                Continue();
            } else if (command[6] == 's' || command[6] == 'S') {
                auto colon_it = boost::find(command, ':');
                if (colon_it == command.end())
                    throw std::runtime_error("Malformed message: No colon found");

                auto ptid_opt = ParseProcessThreadId(std::string(colon_it+1, command.end()));
                assert(ptid_opt);

                // If the ptid refers to our FakeDebugProcess, allow pausing in any thread.
//                if (*ptid_opt == std::make_pair<uint32_t, uint32_t>(1, 1))
//                    *ptid_opt = std::make_pair<uint32_t, uint32_t>(0, 0);

                // Step until we enter the given thread.
                do {
                    // TODO: Breakpoints in other threads may mess this up!
                    if (IsAnyProcess(ptid_opt->first))
                        RequestStep(std::nullopt);
                    else if (IsAnyThread(ptid_opt->second))
                        RequestStep({{ ptid_opt->first, std::nullopt }});
                    else
                        RequestStep({{ ptid_opt->first, ptid_opt->second }});
                    if (!core_running)
                        break;
                } while (!IsSameProcess(ptid_opt->first, GetCurrentProcess().GetId()) || !IsSameThread(ptid_opt->second, GetCurrentThread().GetId()));
                thread_to_pause = std::nullopt;

                // Send stop packet if and only if we stopped in the thread we were supposed to step in
                // If this is not the case, the stop trigger was something else and the corresponding code should have taken care of sending a stop signal
                // NOTE: No idea how nice this place if we step "onto" a breakpoint: Two stop packets might be sent in such case?
                if (IsSameProcess(ptid_opt->first, GetCurrentProcess().GetId()) && IsSameThread(ptid_opt->second, GetCurrentThread().GetId()))
                    server->QueueReportSignal(GetCurrentThread(), 5);
            } else  if (command[6] == 'C') {
                Continue();
            } else {
                throw std::runtime_error("TODO: Unexpected character");
            }
        } else if (MatchesSubcmd("Attach;")) {
            auto pid_opt = ReadHexNumber(command | boost::adaptors::sliced(8, command.length()));
            if (!pid_opt) {
                return "E00";
            }

            auto process = env.GetProcessFromId(pid_opt->first);
            if (!process) {
                logger->warn("Debugger attempting to attach to nonexistent process {}", pid_opt->first);
                return "E01";
            }

            auto emu_process = std::dynamic_pointer_cast<HLE::OS::EmuProcess>(process);
            if (!emu_process) {
                auto process_printer = HLE::OS::ProcessPrinter { *process.get() };
                logger->warn("Debugger attempting to attach to non-emulated process {} ({})",
                             pid_opt->first, process_printer);
                return "E02";
            }

            logger->info("Debugger attached to process {} ({})", pid_opt->first, emu_process->GetName());

            thread_to_pause = {std::make_pair(HLE::OS::ProcessId{pid_opt->first}, std::optional<uint32_t>{})};
            request_pause = true;
            for (auto& thread : emu_process->threads) {
                auto emu_thread = std::static_pointer_cast<HLE::OS::EmuThread>(thread);
                emu_thread->context->SetDebuggingEnabled(true);
            }

            // Pause the specified process (if the process was just created, tell the main thread to stop waiting for us to attach)
            (void)TryAccess(attach_info, [&](const AttachInfo& info) {
                                             return pid_opt->first == info.pid;
                                         });
            // TODO: Allow this to timeout or something
            while (!paused) {
            }
            request_pause = false;
            assert(paused);

            attached_processes.push_back(pid_opt->first);
            // TODO: Potential race condition here: The process might have exited since we send the interrupt request
            server->QueueReportSignal(*process->threads.front(), 5);
        } else if (MatchesSubcmd("File:setfs")) {
            // Send empty reply to signal we don't support this!
            return "";
        } else if (MatchesSubcmd("File")) {
            // Apparently, this is how you report errors for file IO operations
            return "F-1,16"; // 16 = FILEIO_EINVAL
        } else if (MatchesSubcmd("MustReplyEmpty")) {
            // Apparently, this command is sent as a workaround for buggy (and nowadays fixed) gdbserver behavior,
            // where gdbserver would send "OK" as reply to unknown "v" commands. Instead, we just return an empty reply.
            return "";
        }
        break;
    }

    case 'X':
    {
        // Write data to memory (used e.g. for breakpoints)
        size_t start = 1;
        auto addr_opt = ReadHexNumber(command | boost::adaptors::sliced(start, command.length()));
        if (!addr_opt) {
            return "E00";
        }

        // Skip address and comma
        start += addr_opt->second + 1;

        auto length_opt = ReadHexNumber(command | boost::adaptors::sliced(start, command.length()));
        if (!length_opt) {
            return "E01";
        }

        // skip length and double colon
        start += length_opt->second + 1;

        auto thread = GetThreadForOperation('X');

        std::string log_message = "'X' data: ";
        for (auto c : command.substr(start, std::string::npos)) {
            log_message += fmt::format("{:02x}", static_cast<uint8_t>(c));
        }
        logger->info(log_message);

        log_message += "'X' writing ";
        for (uint32_t offset = 0; offset < length_opt->first; ++offset) {
            // Check for escape character
            auto value = command[start + offset];
            if (value == 0x7d) {
                // The escaped character is the following byte XOR 0x20
                value = command[++start + offset] ^ 0x20;
            }
            thread->WriteMemory(addr_opt->first + offset, value);
            log_message += fmt::format("{:02x}", static_cast<uint8_t>(value));
        }
        log_message += fmt::format(" to address {:#x}", addr_opt->first);
        logger->info(log_message);

        return "OK";
    }

    case 'z':
    case 'Z':
    {
        // Add breakpoint at the given address
        // Zn,addr,kind
        // n = 0: memory breakpoint (replace instruction at given address with SIGTRAP), kind = size of the breakpoint instruction in bytes
        // n = 1: hardware breakpoint, kind = same as memory breakpoint
        // n = 2: write watchpoint, kind = number of bytes to watch
        // n = 3: read watchpoint, kind = same as write watchpoints
        // n = 4: access watchpoint, kind = same as write watchpoints

        auto thread = GetThreadForOperation(command[0]);
        if (!thread) {
            return "E00";
        }

        size_t start = 1;
        uint32_t type;
        uint32_t addr;
        uint32_t length;

        // Read type
        auto hexnum = ReadHexNumber(command | boost::adaptors::sliced(start, command.length()));
        if (hexnum) {
            type = hexnum->first;
            start += hexnum->second;
        }
        if (!hexnum || command.length() < start || command[start] != ',') {
            // Malformed request, error
            return "E xx";
        }

        // Skip comma
        ++start;

        // Read address
        hexnum = ReadHexNumber(command | boost::adaptors::sliced(start, command.length()));
        if (hexnum) {
            addr = hexnum->first;
            start += hexnum->second;
        }
        if (!hexnum || command.length() < start || command[start] != ',') {
            // Malformed request, error
            return "E xx";
        }

        // Skip comma
        ++start;

        // Read length
        hexnum = ReadHexNumber(command | boost::adaptors::sliced(start, command.length()));
        if (hexnum) {
            length = hexnum->first;
        } else {
            // Malformed request, error
            return "E xx";
        }

        bool add_breakpoint = (command[0] == 'Z');
        if (type == 1) {
            // Hardware breakpoint
            const auto handler = add_breakpoint ? &HLE::OS::Thread::AddBreakpoint : &HLE::OS::Thread::RemoveBreakpoint;
            const auto action = add_breakpoint ? "added" : "removed";
            for (auto process_thread : thread->GetParentProcess().threads)
                (process_thread.get()->*handler)(addr);
            logger->info("Stub{} {} breakpoint {:#x} in thread {}", GetCPUId(), action, addr, GetThreadIdString(*thread));
        } else if (type >= 2 && type <= 4) {
            // Create read or write watch points (or both if type == 4)
            if (type == 2 || type == 4) {
                // Write watchpoint
                const auto handler = add_breakpoint ? &HLE::OS::Thread::AddWriteWatchpoint : &HLE::OS::Thread::RemoveWriteWatchpoint;
                const auto action = add_breakpoint ? "added" : "removed";
                for (auto process_thread : thread->GetParentProcess().threads)
                    (process_thread.get()->*handler)(addr);
                logger->info("Stub{} {} write watchpoint {:#x} in thread {}", GetCPUId(), action, addr, GetThreadIdString(*thread));
            }

            if (type == 3 || type == 4) {
                // Read watchpoint
                const auto handler = add_breakpoint ? &HLE::OS::Thread::AddReadWatchpoint : &HLE::OS::Thread::RemoveReadWatchpoint;
                const auto action = add_breakpoint ? "added" : "removed";
                for (auto process_thread : thread->GetParentProcess().threads)
                    (process_thread.get()->*handler)(addr);
                logger->info("Stub{} {} read watchpoint {:#x} in thread {}", GetCPUId(), action, addr, GetThreadIdString(*thread));
            }
        } else {
            // Empty reply = breakpoint type not supported
            return "";
        }

        return "OK";
    }

    default:
        logger->info("Stub{} received unknown command: \"{}\"", GetCPUId(), command);
        return "E xx";
    }

    return {};
}

unsigned GDBStub::GetCPUId() {
    // TODO: Implement. Returning 0 for now.
    //    return ctx.cpu.cp15.CPUId().CPUID;
    return 0;
}

void GDBStub::ProcessQueue() {
    server->RunTCPServer();
}

void GDBStubTCPServer::SetupTokenReceivedHandler() {
    boost::asio::async_read(*client, boost::asio::buffer(&token, 1), [this](boost::system::error_code ec, std::size_t /* bytes_read */) {
        if (ec) {
            // TODO
            return;
        }

        if (core_running && token != 3) {
            throw std::runtime_error("Should never receive anything other than SIGINT while emulator core is running!");
        }

        switch (token) {
        case '+':
            stub.logger->info("Stub{} received ACK", stub.GetCPUId());
            SetupTokenReceivedHandler();
            break;

        case '-':
            stub.logger->info("Stub{} received NACK", stub.GetCPUId());
            SetupTokenReceivedHandler();
            break;

        case 3:
        {
            if (core_running) {
                stub.logger->info("Stub{} received SIGINT", stub.GetCPUId());

                stub.RequestPause();
                // TODO:REVISE:Report that all threads have paused by using pid/tid 0
//                stub.ReportSignal(1, 1, 2);
                auto&& current_thread = stub.GetCurrentThread();
                stub.logger->info("Reporting that we stopped in thread {}.{}", current_thread.GetParentProcess().GetId(), current_thread.GetId());
                ReportSignal(current_thread, 2);
//                stub.ReportSignal(14, 1, 2);
                // SIGINT with ID 0 seems to make GDB assume we are in thread 1.1 TODO REVISE
                // TODO: Not sure if this is correct
                for (auto& thread : stub.thread_for_operation) {
                    thread.second = std::make_pair(current_thread.GetParentProcess().GetId(), current_thread.GetId());
//                    thread.second = std::make_pair(14, 1);
                }

                core_running = false;
            } else {
                // TODO: This may actually happen when stepping by LOTS instructions ("si 500") and then sending SIGINT...
                throw std::runtime_error("Should only receive SIGINT when running!");
//                stub.logger->info("Stub{} received SIGINT", stub.GetCPUId());
//                std::stringstream ss;
//                ss << std::hex << "T" << std::setw(2) << std::setfill('0') << +token;
//                SendPacket(ss.str());
            }
            SetupTokenReceivedHandler();
            break;
        }

        case '$':
            SetupCommandLineReceivedHandler();
            break;

        default:
            stub.logger->info("Stub{} skipping char '{}' ({:#02x})", stub.GetCPUId(), token, token);
            SetupTokenReceivedHandler();
            break;
        }
    });

    // TODO: Integrate this as well
//    try {
//        ProcessEventQueue();
//    } catch (std::runtime_error& e) {
//        logger->info("Stub{} reporting SIGABRT due to exception in CPU emulator: {}", GetCPUId(), e.what());
//        ReportSignal(GetCurrentThread(), 6);
//        return;
//    }
}

void GDBStubTCPServer::SetupCommandLineReceivedHandler() {
    auto handler = [&](boost::system::error_code ec, std::size_t /*bytes_received*/) {
        if (!ec) {
            std::istream stream(&streambuf);
            std::string command;
            std::getline(stream, command, '#');
//                streambuf.consume(command.length());

            stub.logger->info("Stub{} command received: {}", stub.GetCPUId(), command);

            unsigned char checksum_bytes[2];
            int checksum_bytes_read = 0;
            while (streambuf.size() > 0 && checksum_bytes_read != 2) {
                checksum_bytes[checksum_bytes_read] = stream.get();
                ++checksum_bytes_read;
            }
            if (checksum_bytes_read != 2) {
                boost::asio::read(*client, boost::asio::buffer(&checksum_bytes[checksum_bytes_read], 2 - checksum_bytes_read), ec);
                if (ec) {
                    // TODO
                    std::abort();
                }
            }

            unsigned char expected_checksum = (*HexCharToInt(checksum_bytes[0]) << 4);
            expected_checksum |= *HexCharToInt(checksum_bytes[1]);
            if (expected_checksum != GetChecksum(command)) {
                stub.logger->info("Stub{} checksum mismatch! Expected {:#02x}, got {:#02x}", stub.GetCPUId(), expected_checksum, GetChecksum(command));
                NackReply();
            } else {
                stub.logger->info("Stub{} sends ACK", stub.GetCPUId());
                AckReply();
            }

            auto reply = stub.HandlePacket(command);
            if (reply) {
                SendPacket(*reply);
            }
            if (reply && command[0] == 's') {
                // TODO: Transition to stopped state
                fprintf(stderr, "TODO: Transition to stopped state\n");
                std::abort();
            } else {
                SetupTokenReceivedHandler();
            }
        }
    };
    boost::asio::async_read_until(*client, streambuf, '#', handler);
}


void GDBStub::OnSegfault(uint32_t process_id, uint32_t thread_id) {
    server->QueueReportSignal(*env.GetProcessFromId(process_id)->GetThreadFromId(thread_id), 6);
    core_running = false;
}

void GDBStub::OnBreakpoint(uint32_t process_id, uint32_t thread_id) {
    logger->info("Stub{} was notified about a breakpoint in thread {:#x}.{:#x}", GetCPUId(), process_id, thread_id);
    server->QueueReportSignal(*env.GetProcessFromId(process_id)->GetThreadFromId(thread_id), 5);
    core_running = false;
}

void GDBStub::OnReadWatchpoint(uint32_t process_id, uint32_t thread_id, uint32_t address) {
    throw std::runtime_error("Watchpoints are not implemented\n");

    logger->info("Stub{} was notified about a read watchpoint in thread {:#x}.{:#x}", GetCPUId(), process_id, thread_id);
//    GDBStub::ReportWatchpointSignal(*env.GetProcessFromId(process_id)->GetThreadFromId(thread_id), address);
    core_running = false;
}

void GDBStub::OnWriteWatchpoint(uint32_t process_id, uint32_t thread_id, uint32_t address) {
    throw std::runtime_error("Watchpoints are not implemented\n");

    logger->info("Stub{} was notified about a write watchpoint in thread {:#x}.{:#x}", GetCPUId(), process_id, thread_id);
//    GDBStub::ReportWatchpointSignal(*env.GetProcessFromId(process_id)->GetThreadFromId(thread_id), address);
    core_running = false;
}

void GDBStub::OnProcessLaunched(uint32_t process_id, uint32_t thread_id, uint32_t launched_process_id) {
    logger->info("Stub{} was notified about a launched process: .{:#x}", GetCPUId(), launched_process_id);

    // Pause the emulator: We report launched processes as forks of the
    // current process, which GDB assumes to pause the current process.
    // Hence, we request the emulator core to pause here until the debugger
    // resumes execution.
    RequestPause();

    // Format: T05thread:p<processid>.<threadid>;fork:p<launched_processid>.1;)
    std::stringstream ss;

    auto thread = env.GetProcessFromId(process_id)->GetThreadFromId(thread_id);
    auto launched_thread = env.GetProcessFromId(launched_process_id)->threads.front();
    ss << "T" << std::hex << std::setfill('0') << std::setw(2) << 5 /*SIGTRAP*/ << "thread:"
       << GetThreadIdString(*thread) << ";fork:" << GetThreadIdString(*launched_thread) << ";";
    server->QueuePacket(ss.str());

    // Spawning processes seem to reset the thread defined by 'H' operations.
    // TODO: Not sure if this is correct
    for (auto& thread_for_op : thread_for_operation) {
        thread->GetLogger()->info("BREAKPOINTREMOVEME resetting thread for operations to {}", GetThreadIdString(*launched_thread));
        thread_for_op.second = std::make_pair(launched_process_id, launched_thread->GetId());
    }

    core_running = false;
}

void GDBStub::OfferAttach(std::weak_ptr<Interpreter::WrappedAttachInfo> attach_info) {
    this->attach_info = attach_info;
}

} // namespace
