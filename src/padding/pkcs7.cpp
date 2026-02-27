#include "../../include/crypto/padding/padding.hpp"
#include "../../include/crypto/core/utils.hpp"
#include <algorithm>
#include <stdexcept>

namespace crypto {

ByteArray PKCS7Padding::pad(const ByteArray& data, size_t blockSize) {
    if (blockSize == 0 || blockSize > 255) {
        throw PaddingException("PKCS7: Block size must be between 1 and 255 bytes");
    }
    
    size_t paddingSize = blockSize - (data.size() % blockSize);
    if (paddingSize == 0) {
        paddingSize = blockSize;
    }
    
    ByteArray padded = data;
    Byte padByte = static_cast<Byte>(paddingSize);
    
    padded.resize(data.size() + paddingSize, padByte);
    
    return padded;
}

ByteArray PKCS7Padding::unpad(const ByteArray& paddedData) const {
    if (paddedData.empty()) {
        throw PaddingException("PKCS7: Cannot unpad empty data");
    }
    
    Byte padByte = paddedData.back();
    size_t paddingSize = static_cast<size_t>(padByte);
    
    if (paddingSize == 0) {
        throw PaddingException("PKCS7: Padding size cannot be zero");
    }
    
    if (paddingSize > paddedData.size()) {
        throw PaddingException("PKCS7: Padding size exceeds data size");
    }
    
    if (paddingSize > 255) {
        throw PaddingException("PKCS7: Padding size exceeds maximum (255)");
    }
    
    for (size_t i = paddedData.size() - paddingSize; i < paddedData.size(); ++i) {
        if (paddedData[i] != padByte) {
            throw PaddingException("PKCS7: Invalid padding bytes");
        }
    }
    
    return ByteArray(paddedData.begin(), paddedData.end() - paddingSize);
}

bool PKCS7Padding::validate(const ByteArray& paddedData) const {
    try {
        unpad(paddedData);
        return true;
    } catch (const PaddingException&) {
        return false;
    }
}

}