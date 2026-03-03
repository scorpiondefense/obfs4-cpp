#pragma once

#include <atomic>
#include <functional>
#include <thread>

namespace obfs4::proxy {

// Termination monitor for obfs4proxy.
// Handles: SIGTERM (immediate exit), SIGINT (graceful then force),
// parent death detection, and stdin close detection.
class TermMonitor {
public:
    using ShutdownCallback = std::function<void()>;

    TermMonitor() = default;
    ~TermMonitor();

    TermMonitor(const TermMonitor&) = delete;
    TermMonitor& operator=(const TermMonitor&) = delete;

    // Start monitoring. Callback is called on shutdown signal.
    void start(ShutdownCallback callback, bool exit_on_stdin_close = false);

    // Stop monitoring
    void stop();

    // Check if shutdown has been requested
    bool should_shutdown() const { return shutdown_requested_.load(); }

private:
    std::atomic<bool> shutdown_requested_{false};
    std::atomic<bool> running_{false};
    ShutdownCallback callback_;
    std::jthread stdin_thread_;

    void monitor_stdin(std::stop_token stoken);

    // Static signal handler state
    static std::atomic<int> sigint_count_;
    static TermMonitor* instance_;

    static void signal_handler(int sig);
    void install_signal_handlers();
};

}  // namespace obfs4::proxy
