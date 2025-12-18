// src/io/file_encryptor.cpp

#include "../../include/crypto/io/file_encryptor.hpp"
#include "../../include/crypto/io/async_processor.hpp"
#include <fstream>

namespace crypto {

AsyncFileEncryptor::AsyncFileEncryptor(std::shared_ptr<IBlockCipherMode> mode, 
                                      size_t numThreads,
                                      size_t chunkSize)
    : mode_(std::move(mode))
    , chunkSize_(chunkSize) {
    
    if (numThreads == 0) {
        numThreads = std::thread::hardware_concurrency();
    }
    threadPool_ = std::make_unique<ThreadPool>(numThreads);
}

AsyncFileEncryptor::~AsyncFileEncryptor() = default;

std::future<bool> AsyncFileEncryptor::encryptFileAsync(const std::string& inputFile,
                                                       const std::string& outputFile) {
    return threadPool_->enqueue([this, inputFile, outputFile]() {
        return encryptFileSync(inputFile, outputFile);
    });
}

std::future<bool> AsyncFileEncryptor::decryptFileAsync(const std::string& inputFile,
                                                       const std::string& outputFile) {
    return threadPool_->enqueue([this, inputFile, outputFile]() {
        return decryptFileSync(inputFile, outputFile);
    });
}

bool AsyncFileEncryptor::encryptFileSync(const std::string& inputFile,
                                        const std::string& outputFile) {
    try {
        std::ifstream input(inputFile, std::ios::binary);
        std::ofstream output(outputFile, std::ios::binary);
        
        if (!input || !output) {
            return false;
        }
        
        // Читаем файл блоками и шифруем
        ByteArray buffer(chunkSize_);
        while (input.read(reinterpret_cast<char*>(buffer.data()), chunkSize_)) {
            size_t bytesRead = input.gcount();
            if (bytesRead < chunkSize_) {
                buffer.resize(bytesRead);
            }
            
            ByteArray encrypted = mode_->encrypt(buffer);
            output.write(reinterpret_cast<const char*>(encrypted.data()), 
                        encrypted.size());
        }
        
        // Последний блок
        size_t bytesRead = input.gcount();
        if (bytesRead > 0) {
            buffer.resize(bytesRead);
            ByteArray encrypted = mode_->encrypt(buffer);
            output.write(reinterpret_cast<const char*>(encrypted.data()), 
                        encrypted.size());
        }
        
        return true;
    } catch (...) {
        return false;
    }
}

bool AsyncFileEncryptor::decryptFileSync(const std::string& inputFile,
                                        const std::string& outputFile) {
    try {
        std::ifstream input(inputFile, std::ios::binary);
        std::ofstream output(outputFile, std::ios::binary);
        
        if (!input || !output) {
            return false;
        }
        
        // Читаем файл блоками и дешифруем
        ByteArray buffer(chunkSize_);
        while (input.read(reinterpret_cast<char*>(buffer.data()), chunkSize_)) {
            size_t bytesRead = input.gcount();
            if (bytesRead < chunkSize_) {
                buffer.resize(bytesRead);
            }
            
            ByteArray decrypted = mode_->decrypt(buffer);
            output.write(reinterpret_cast<const char*>(decrypted.data()), 
                        decrypted.size());
        }
        
        // Последний блок
        size_t bytesRead = input.gcount();
        if (bytesRead > 0) {
            buffer.resize(bytesRead);
            ByteArray decrypted = mode_->decrypt(buffer);
            output.write(reinterpret_cast<const char*>(decrypted.data()), 
                        decrypted.size());
        }
        
        return true;
    } catch (...) {
        return false;
    }
}

}

