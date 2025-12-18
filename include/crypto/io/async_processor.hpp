// include/crypto/io/async_processor.hpp

#pragma once
#include <future>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <vector>

namespace crypto {

// Класс ThreadPool для выполнения задач в отдельных потоках
class ThreadPool {
private:
    std::vector<std::thread> workers_;
    std::queue<std::packaged_task<void()>> tasks_;
    std::mutex queueMutex_;
    std::condition_variable condition_;
    std::atomic<bool> stop_{false};
    
public:
    ThreadPool(size_t threads = std::thread::hardware_concurrency());
    ~ThreadPool();
    
    template<class F>
    auto enqueue(F&& f) -> std::future<decltype(f())> {
        using ReturnType = decltype(f());
        std::packaged_task<ReturnType()> task(std::forward<F>(f));
        std::future<ReturnType> result = task.get_future();
        
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            if (stop_) {
                throw std::runtime_error("ThreadPool is stopped");
            }
            tasks_.emplace(std::move(task));
        }
        
        condition_.notify_one();
        return result;
    }
};

}