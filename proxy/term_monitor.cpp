#include "term_monitor.hpp"
#include <csignal>
#include <cstdlib>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

namespace obfs4::proxy {

std::atomic<int> TermMonitor::sigint_count_{0};
TermMonitor* TermMonitor::instance_ = nullptr;

TermMonitor::~TermMonitor() {
    stop();
}

void TermMonitor::signal_handler(int sig) {
    if (sig == SIGTERM) {
        if (instance_) {
            instance_->shutdown_requested_ = true;
            if (instance_->callback_) {
                instance_->callback_();
            }
        }
        std::_Exit(0);
    }

    if (sig == SIGINT) {
        int count = ++sigint_count_;
        if (instance_) {
            instance_->shutdown_requested_ = true;
            if (count == 1 && instance_->callback_) {
                instance_->callback_();
            } else if (count >= 2) {
                std::_Exit(1);
            }
        }
    }
}

void TermMonitor::install_signal_handlers() {
    instance_ = this;

    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);

    // Ignore SIGPIPE (common in socket programming)
    signal(SIGPIPE, SIG_IGN);
}

void TermMonitor::start(ShutdownCallback callback, bool exit_on_stdin_close) {
    callback_ = std::move(callback);
    running_ = true;

    install_signal_handlers();

#ifdef __linux__
    // Linux: get notified when parent dies
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    // Check if parent already died between fork and prctl
    if (getppid() == 1) {
        shutdown_requested_ = true;
        if (callback_) callback_();
        return;
    }
#endif

    if (exit_on_stdin_close) {
        stdin_thread_ = std::jthread([this](std::stop_token st) {
            monitor_stdin(st);
        });
    }
}

void TermMonitor::stop() {
    running_ = false;
    if (stdin_thread_.joinable()) {
        stdin_thread_.request_stop();
        stdin_thread_.join();
    }
}

void TermMonitor::monitor_stdin(std::stop_token stoken) {
    // Poll stdin for EOF
    char buf[1];
    while (!stoken.stop_requested() && running_) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv);
        if (ret > 0) {
            ssize_t n = read(STDIN_FILENO, buf, 1);
            if (n <= 0) {
                // stdin closed
                shutdown_requested_ = true;
                if (callback_) callback_();
                return;
            }
        }
    }
}

}  // namespace obfs4::proxy
