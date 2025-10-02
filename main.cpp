#include <iostream>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <fstream>
#include <iomanip>
#include <boost/program_options.hpp>

#include "VariableWatcher.hpp"
namespace po = boost::program_options;

int main(int argc, char *argv[]) {

    std::string variableName;
    std::vector<std::string> exec;
    po::options_description desc("Allowed options");
    po::positional_options_description p;
    bool help = false;
    desc.add_options()
            ("help,h", po::bool_switch(&help), "Show help message")
            ("var", po::value(&variableName), "Variable name")
            ("exec", po::value(&exec), "Executable path");
    p.add("exec", -1);
    try {
        po::variables_map vm;
        po::parsed_options parsed = po::command_line_parser(argc, argv).options(desc).positional(p).run();
        po::store(parsed, vm);
        po::notify(vm);
    }
    catch (po::error &e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    char *args[exec.size() + 1];
    args[exec.size()] = nullptr;
    for (size_t i = 0; i < exec.size(); ++i) {
        args[i] = strdup(exec[i].c_str());
    }
    if (help) {
        std::cout << desc << std::endl;
        return 0;
    }
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "fork failed" << std::endl;
        return 1;
    }
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
            perror("PTRACE_TRACEME");
            return 1;
        }
        execv(exec[0].c_str(), args);
        perror("execv");
        return 1;
    }
    try {
        VariableWatcher watcher(exec[0], variableName, pid);
        watcher.run();
    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}