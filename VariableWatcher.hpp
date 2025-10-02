#pragma once
#include <format>
#include <ios>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <cstring>
#include <cerrno>
#include <sys/uio.h>
#include <cstring>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/iostreams/stream.hpp>

#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH 0x404
#endif

typedef boost::iostreams::stream<boost::iostreams::file_descriptor_source> boost_stream;

/**
 * Class to watch one particular global variable. Created for convinient way to test the solution.
 */
class VariableWatcher {
public:
    explicit VariableWatcher(std::string path_, std::string variableName_, pid_t pid_): pid(pid_),
                                                            path(std::move(path_)),
                                                            variableName(std::move(variableName_)) {
        auto runtimeShift = getRuntimeShift();
        auto [linkerOffset ,size] = getLinkerOffsetAndVariableSize();
        runtimeVariable = {linkerOffset + runtimeShift, size};
        runtimeMainAddr = getMainVirtAddress() + runtimeShift;
        std::cout << "Runtime variable: addr=0x" << std::hex << runtimeVariable.address
                  << ", size=0x" << runtimeVariable.size << std::endl;
    }

    /**
     * Run watcher. Output every change of the specified global variable.
     * Do it in step by step approach.
     * @return return code
     */
    int run() {
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return 1;
        }
        if (!skipToMain()) {
            return 1;
        }

        errno = 0;
        long last_val = ptrace(PTRACE_PEEKDATA, pid, reinterpret_cast<void *>(runtimeVariable.address), nullptr);
        if (errno) {
            perror("PTRACE_PEEKDATA (initial)");
            return 1;
        }
        std::cout << "Initial value at 0x" << std::hex << runtimeVariable.address
                  << " = 0x" << last_val << std::dec << "\n";

        // Trying to set watchpoints here, unfortunately does not work in Docker alpine/ARM :(
        if (!set_watchpoint() || !check_watchpoint()) {
            return 1;
        }

        // Continue with a simple approach = step and check;
        while (true) {
            // Single step the child process
            if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) == -1) {
                perror("PTRACE_SINGLESTEP");
                return 1;
            }

            // Wait for the child to stop after single step
            if (waitpid(pid, &status, 0) == -1) {
                perror("waitpid");
                return 1;
            }

            if (WIFEXITED(status)) {
                std::cout << "Child exited with status " << WEXITSTATUS(status) << "\n";
                return 0;
            }

            if (WIFSIGNALED(status)) {
                std::cout << "Child terminated by signal " << WTERMSIG(status) << "\n";
                return 0;
            }

            if (WIFSTOPPED(status)) {
                int sig = WSTOPSIG(status);

                // If stopped by signal other than SIGTRAP (from single-step), handle it
                if (sig != SIGTRAP) {
                    std::cout << "Child stopped by signal: " << sig << " (" << strsignal(sig) << ")\n";
                    // Forward the signal to the child
                    if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, reinterpret_cast<void *>(static_cast<long>(sig))) == -1) {
                        perror("PTRACE_SINGLESTEP with signal");
                        return 1;
                    }
                    continue;
                }

                // Check the variable value after each instruction
                errno = 0;
                long cur_val = ptrace(PTRACE_PEEKDATA, pid, reinterpret_cast<void *>(runtimeVariable.address), nullptr);
                if (errno) {
                    perror("PTRACE_PEEKDATA");
                    return 1;
                }

                if (cur_val != last_val) {
                    std::cout << "<" << variableName<<"> write " << std::hex  << last_val << " -> " << cur_val << std::endl;
                    last_val = cur_val;
                }
            }
        }
    }

private:
    struct user_hwdebug_state {
        struct {
            uint64_t addr;
            uint32_t ctrl;
            uint32_t pad;
        } dbg_regs[16];
    };

    bool skipToMain() const {
        int status;
        // Set breakpoint at main()
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, pid, reinterpret_cast<void *>(runtimeMainAddr), nullptr);
        if (errno) {
            perror("PTRACE_PEEKDATA for breakpoint");
            return false;
        }

        // Insert breakpoint (replace first instruction with trap)
        unsigned long data_with_trap = (data & ~0xFFFFFFFFUL) | 0xd4200000UL;
        if (ptrace(PTRACE_POKEDATA, pid, reinterpret_cast<void *>(runtimeMainAddr), data_with_trap) == -1) {
            perror("PTRACE_POKEDATA for breakpoint");
            return false;
        }

        std::cout << "Breakpoint set at main(), continuing...\n";
        if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
            perror("PTRACE_CONT to main");
            return false;
        }

        // Wait for breakpoint to hit
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid for breakpoint");
            return false;
        }

        if (WIFEXITED(status)) {
            std::cerr << "Child exited before reaching main()\n";
            return false;
        }

        std::cout << "Reached main()!\n";

        // Restore original instruction
        if (ptrace(PTRACE_POKEDATA, pid, reinterpret_cast<void *>(runtimeMainAddr), data) == -1) {
            perror("PTRACE_POKEDATA restore");
            return false;
        }

        // Reset PC to re-execute the original instruction
        user_regs_struct regs{};
        iovec iov{};
        iov.iov_base = &regs;
        iov.iov_len = sizeof(regs);
        if (ptrace(PTRACE_GETREGSET, pid, reinterpret_cast<void *>(1), &iov) == -1) {
            perror("PTRACE_GETREGSET");
            return false;
        }
        regs.pc = runtimeMainAddr;
        if (ptrace(PTRACE_SETREGSET, pid, reinterpret_cast<void *>(1), &iov) == -1) {
            perror("PTRACE_SETREGSET");
            return false;
        }

        return true;
    }

    /**
     * Check states of the dbg ARM registers
     * @return successfully checked or not
     */
    [[nodiscard]] bool check_watchpoint() const {
        user_hwdebug_state st{};
        memset(&st, 0, sizeof(st));

        iovec iov{};
        iov.iov_base = &st;
        iov.iov_len = sizeof(st);

        if (ptrace(PTRACE_GETREGSET, pid, reinterpret_cast<void *>(static_cast<uintptr_t>(NT_ARM_HW_WATCH)), &iov) != 0) {
            perror("PTRACE_GETREGSET NT_ARM_HW_WATCH");
            return false;
        }

        std::cout << "Read " << iov.iov_len << " bytes from debug registers\n";
        int num_regs = iov.iov_len / sizeof(st.dbg_regs[0]);
        std::cout << "Number of debug registers: " << num_regs << "\n";

        bool found_any = false;
        for (int i = 0; i < num_regs; ++i) {
            std::cout << "Debug reg " << i << ": addr=0x" << std::hex << st.dbg_regs[i].addr
                      << ", ctrl=0x" << st.dbg_regs[i].ctrl;
            if (st.dbg_regs[i].ctrl & 1) {
                std::cout << " [ENABLED]";
                found_any = true;
            }
            std::cout << "\n";
        }

        if (!found_any) {
            std::cerr << "WARNING: No watchpoints are enabled!\n";
        }

        return true;
    }


    /**
     * Try to set watchpoint for the runtime global variable address by setting ARM dbg registers
     * @return success or not
     */
    [[nodiscard]] bool set_watchpoint() const {

     // First, read the current state to determine the proper size
        user_hwdebug_state st{};
        memset(&st, 0, sizeof(st));

        iovec iov{};
        iov.iov_base = &st;
        iov.iov_len = sizeof(st);

        if (ptrace(PTRACE_GETREGSET, pid, reinterpret_cast<void *>(static_cast<uintptr_t>(NT_ARM_HW_WATCH)), &iov) != 0) {
            perror("PTRACE_GETREGSET NT_ARM_HW_WATCH");
            return false;
        }

        size_t actual_size = iov.iov_len;
        std::cout << "Debug register size: " << actual_size << " bytes\n";

        unsigned enable_bit = 1;
        unsigned type_rw = 3;
        unsigned size_enc = 0;
        switch (runtimeVariable.size) {
            case 1: size_enc = 0; break;
            case 2: size_enc = 1; break;
            case 4: size_enc = 3; break;
            case 8: size_enc = 2; break;
            default: std::cerr << "Unsupported watch size\n"; return false;
        }

        memset(&st, 0, sizeof(st));
        st.dbg_regs[0].addr = runtimeVariable.address;
        st.dbg_regs[0].ctrl = (size_enc << 5) | (type_rw << 3) | enable_bit;

        std::cout << "Setting watchpoint: addr=0x" << std::hex << st.dbg_regs[0].addr
                  << ", ctrl=0x" << st.dbg_regs[0].ctrl << std::dec << "\n";

        iov.iov_base = &st;
        iov.iov_len = actual_size;

        if (ptrace(PTRACE_SETREGSET, pid, reinterpret_cast<void *>(static_cast<uintptr_t>(NT_ARM_HW_WATCH)), &iov) != 0) {
            perror("PTRACE_SETREGSET NT_ARM_HW_WATCH");
            return false;
        }

        std::cout << "Watchpoint set successfully\n";
        return true;
    }


    struct RuntimeGlobalVariable {
        uint64_t address;
        size_t size;
    };

    pid_t pid;
    std::string path;
    std::string variableName;
    RuntimeGlobalVariable runtimeVariable;
    uintptr_t runtimeMainAddr;

    /**
     * Get shift to calculate runtime variable addr
     * @return shift produced by ASLR at runtime
     */
    [[nodiscard]] uintptr_t getRuntimeShift() {
        uintptr_t virtBaseAddr = getVirtualBaseAddress();
        uintptr_t runtimeBaseAddr = getRuntimeBaseAddress();
        std::cout << "ASLR shift: " << std::hex << runtimeBaseAddr - virtBaseAddr << "\n";
        return runtimeBaseAddr - virtBaseAddr;
    }

    /**
     * Get the virtual base address from ELF binary
     * @return virtual base address from ELF LOAD segment
     */
    [[nodiscard]] uintptr_t getVirtualBaseAddress() {
        std::stringstream ss;
        executeCommandToPipe(std::format("readelf -l {} | grep LOAD", path).c_str(), ss);
        
        std::string load;
        uintptr_t offsetAddr, virtBaseAddr;
        ss >> load >> std::hex >> offsetAddr >> virtBaseAddr;
        if (load != "LOAD") {
            throw std::runtime_error("Invalid readelf output");
        }
        std::cout << "Virtual base address: " << std::hex << virtBaseAddr << "\n";
        return virtBaseAddr;
    }

    /**
     * Get the runtime base address from process memory maps
     * @return runtime base address from /proc/[pid]/maps
     */
    [[nodiscard]] uintptr_t getRuntimeBaseAddress() {
        std::stringstream ss;
        executeCommandToPipe(std::format("cat /proc/{}/maps | grep ' {}$'", pid, path).c_str(), ss);
        
        std::string runtimeBaseRangeStr;
        ss >> runtimeBaseRangeStr;
        
        uintptr_t runtimeBaseAddr;
        if (sscanf(runtimeBaseRangeStr.c_str(), "%lx", &runtimeBaseAddr) != 1) {
            throw std::runtime_error("Invalid /proc/[pid]/maps output");
        }
        std::cout << "Runtime base address: " << std::hex << runtimeBaseAddr<< "\n";
        
        return runtimeBaseAddr;
    }

    /**
     * Get offset of the variable from the ELF binary and size of this variable
     * @return {offset from ELF binary, size from ELF binary}
     */
    [[nodiscard]] std::pair<uintptr_t, size_t> getLinkerOffsetAndVariableSize() {
        std::stringstream ss;
        // Get variable virtual address from symbol table
        executeCommandToPipe(
            std::format("nm -C -S {} 2>/dev/null | grep ' {}$'", path, variableName).c_str(), ss);
        uintptr_t variableSize;
        uintptr_t offset;
        ss >> std::hex >> offset >> variableSize;
        std::cout << "Variable offset: " <<std::hex << offset << ", variable size: " << variableSize << std::endl;
        return {offset, variableSize};
    }

    /**
     * Get the runtime address of main() function
     * @return runtime address of main()
     */
    [[nodiscard]] uintptr_t getMainVirtAddress() {
        std::stringstream ss;
        executeCommandToPipe(std::format("nm {} | grep ' T main$'", path).c_str(), ss);

        uintptr_t mainOffset;
        char type;
        std::string name;
        ss >> std::hex >> mainOffset >> type >> name;

        if (name != "main") {
            throw std::runtime_error("Could not find main() in symbol table");
        }
        return mainOffset;
    }


    /**
     * Execute command in the pipe and return the result.
     * @param command command to run
     * @param ss stream for output
     */
    static void executeCommandToPipe(const char *command, std::stringstream &ss) {
        FILE* pipe = popen(command, "r");
        if (!pipe) {
            perror("popen");
            return;
        }
        boost_stream stream(fileno(pipe), boost::iostreams::never_close_handle);
        std::string curString;
        while (std::getline(stream, curString)) {
            ss << curString;
        }
        pclose(pipe);
    }
};
