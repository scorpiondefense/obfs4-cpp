#include "copy_loop.hpp"
#include <unistd.h>
#include <sys/socket.h>

namespace obfs4::proxy {

CopyLoop::~CopyLoop() {
    stop();
}

void CopyLoop::start(int fd_a, int fd_b) {
    fd_a_ = fd_a;
    fd_b_ = fd_b;
    running_ = true;

    thread_a_to_b_ = std::jthread([this](std::stop_token st) {
        copy(fd_a_, fd_b_, st);
    });

    thread_b_to_a_ = std::jthread([this](std::stop_token st) {
        copy(fd_b_, fd_a_, st);
    });
}

void CopyLoop::wait() {
    if (thread_a_to_b_.joinable()) thread_a_to_b_.join();
    if (thread_b_to_a_.joinable()) thread_b_to_a_.join();
}

void CopyLoop::stop() {
    close_both();
    if (thread_a_to_b_.joinable()) {
        thread_a_to_b_.request_stop();
        thread_a_to_b_.join();
    }
    if (thread_b_to_a_.joinable()) {
        thread_b_to_a_.request_stop();
        thread_b_to_a_.join();
    }
}

void CopyLoop::copy(int from, int to, std::stop_token stoken) {
    constexpr size_t BUF_SIZE = 32768;
    uint8_t buf[BUF_SIZE];

    while (!stoken.stop_requested() && running_) {
        ssize_t n = ::recv(from, buf, BUF_SIZE, 0);
        if (n <= 0) break;  // EOF or error

        size_t written = 0;
        while (written < static_cast<size_t>(n)) {
            ssize_t w = ::send(to, buf + written, n - written, 0);
            if (w <= 0) {
                running_ = false;
                close_both();
                return;
            }
            written += w;
        }
    }

    running_ = false;
    close_both();
}

void CopyLoop::close_both() {
    if (fd_a_ >= 0) {
        ::shutdown(fd_a_, SHUT_RDWR);
        ::close(fd_a_);
        fd_a_ = -1;
    }
    if (fd_b_ >= 0) {
        ::shutdown(fd_b_, SHUT_RDWR);
        ::close(fd_b_);
        fd_b_ = -1;
    }
}

}  // namespace obfs4::proxy
