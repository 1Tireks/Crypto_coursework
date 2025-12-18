#pragma once
#include "cipher.hpp"

namespace crypto {

class IBlockCipher : public ICipher {
public:
    virtual void encryptBlock(const Byte* input, Byte* output) = 0;
    
    virtual void decryptBlock(const Byte* input, Byte* output) = 0;

    virtual void encryptBlocks(const Byte* input, Byte* output, size_t numBlocks) {
        for (size_t i = 0; i < numBlocks; ++i) {
            encryptBlock(input + i * blockSize(), output + i * blockSize());
        }
    }
    
    virtual void decryptBlocks(const Byte* input, Byte* output, size_t numBlocks) {
        for (size_t i = 0; i < numBlocks; ++i) {
            decryptBlock(input + i * blockSize(), output + i * blockSize());
        }
    }
};

}

