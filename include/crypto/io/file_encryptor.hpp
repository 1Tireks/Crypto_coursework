// include/crypto/io/file_encryptor.hpp

#pragma once
#include "../modes/mode.hpp"
#include "../core/types.hpp"
#include "async_processor.hpp"
#include <string>
#include <future>
#include <memory>

namespace crypto {

// Класс для асинхронного шифрования/дешифрования файлов
class AsyncFileEncryptor {
private:
    std::shared_ptr<IBlockCipherMode> mode_;
    std::unique_ptr<ThreadPool> threadPool_;
    size_t chunkSize_;
    
    // Синхронные методы
    bool encryptFileSync(const std::string& inputFile, const std::string& outputFile);
    bool decryptFileSync(const std::string& inputFile, const std::string& outputFile);
    
public:
    AsyncFileEncryptor(std::shared_ptr<IBlockCipherMode> mode, 
                      size_t numThreads = 0,
                      size_t chunkSize = 1024 * 1024);
    
    ~AsyncFileEncryptor();
    
    // Асинхронные методы
    std::future<bool> encryptFileAsync(const std::string& inputFile,
                                       const std::string& outputFile);
    std::future<bool> decryptFileAsync(const std::string& inputFile,
                                       const std::string& outputFile);
                                       
};

}

