#pragma once
#include "cipher.hpp"

namespace crypto {

class IBlockCipher : public ICipher {
public:
    virtual void encryptBlock(const Byte* input, Byte* output) = 0;
    
    virtual void decryptBlock(const Byte* input, Byte* output) = 0;
};

}

