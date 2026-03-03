#pragma once

#include <atomic>
#include <cstdint>
#include <thread>

namespace obfs4::proxy {

// Bidirectional relay between two file descriptors.
// Two threads: A->B and B->A. When one direction errors/EOFs,
// both sides are closed.
class CopyLoop {
public:
    CopyLoop() = default;
    ~CopyLoop();

    CopyLoop(const CopyLoop&) = delete;
    CopyLoop& operator=(const CopyLoop&) = delete;

    // Start bidirectional copying between fd_a and fd_b.
    // Takes ownership of both fds (closes them when done).
    void start(int fd_a, int fd_b);

    // Wait for completion
    void wait();

    // Force stop
    void stop();

    bool running() const { return running_.load(); }

private:
    int fd_a_ = -1;
    int fd_b_ = -1;
    std::atomic<bool> running_{false};
    std::jthread thread_a_to_b_;
    std::jthread thread_b_to_a_;

    void copy(int from, int to, std::stop_token stoken);
    void close_both();
};

}  // namespace obfs4::proxy
