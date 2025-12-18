// src/padding/ansix923.cpp

#include "../../include/crypto/padding/padding.hpp"
#include "../../include/crypto/core/utils.hpp"
#include <algorithm>
#include <stdexcept>

namespace crypto {

ByteArray ANSIX923Padding::pad(const ByteArray& data, size_t blockSize) {
    if (blockSize == 0 || blockSize > 255) {
        throw PaddingException("ANSI X9.23: Block size must be between 1 and 255 bytes");
    }
    
    size_t paddingSize = blockSize - (data.size() % blockSize);
    if (paddingSize == 0) {
        paddingSize = blockSize;
    }
    
    ByteArray padded = data;
    
    padded.resize(data.size() + paddingSize - 1, 0x00);
    
    padded.push_back(static_cast<Byte>(paddingSize));
    
    return padded;
}

ByteArray ANSIX923Padding::unpad(const ByteArray& paddedData) const {
    if (paddedData.empty()) {
        throw PaddingException("ANSI X9.23: Cannot unpad empty data");
    }
    
    Byte padByte = paddedData.back();
    size_t paddingSize = static_cast<size_t>(padByte);
    
    if (paddingSize == 0) {
        throw PaddingException("ANSI X9.23: Padding size cannot be zero");
    }
    
    if (paddingSize > paddedData.size()) {
        throw PaddingException("ANSI X9.23: Padding size exceeds data size");
    }
    
    if (paddingSize > 255) {
        throw PaddingException("ANSI X9.23: Padding size exceeds maximum (255)");
    }
    
    for (size_t i = paddedData.size() - paddingSize; i < paddedData.size() - 1; ++i) {
        if (paddedData[i] != 0x00) {
            throw PaddingException("ANSI X9.23: Non-zero bytes in padding");
        }
    }
    
    if (paddedData.back() != padByte) {
        throw PaddingException("ANSI X9.23: Invalid padding size byte");
    }
    
    return ByteArray(paddedData.begin(), paddedData.end() - paddingSize);
}

bool ANSIX923Padding::validate(const ByteArray& paddedData) const {
    try {
        unpad(paddedData);
        return true;
    } catch (const PaddingException&) {
        return false;
    }
}

}