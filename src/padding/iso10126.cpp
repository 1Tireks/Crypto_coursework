#include "../../include/crypto/padding/padding.hpp"
#include "../../include/crypto/core/utils.hpp"
#include "../../include/crypto/math/random.hpp"
#include <random>
#include <algorithm>
#include <stdexcept>

namespace crypto {

ByteArray ISO10126Padding::pad(const ByteArray& data, size_t blockSize) {
    if (blockSize == 0 || blockSize > 255) {
        throw PaddingException("ISO 10126: Block size must be between 1 and 255 bytes");
    }
    
    size_t paddingSize = blockSize - (data.size() % blockSize);
    if (paddingSize == 0) {
        paddingSize = blockSize;
    }
    
    ByteArray padded = data;
    
    ByteArray randomBytes = math::randomBytes(paddingSize - 1);
    padded.insert(padded.end(), randomBytes.begin(), randomBytes.end());
    
    padded.push_back(static_cast<Byte>(paddingSize));
    
    return padded;
}

ByteArray ISO10126Padding::unpad(const ByteArray& paddedData) const {
    if (paddedData.empty()) {
        throw PaddingException("ISO 10126: Cannot unpad empty data");
    }
    
    Byte padByte = paddedData.back();
    size_t paddingSize = static_cast<size_t>(padByte);
    
    if (paddingSize == 0) {
        throw PaddingException("ISO 10126: Padding size cannot be zero");
    }
    
    if (paddingSize > paddedData.size()) {
        throw PaddingException("ISO 10126: Padding size exceeds data size");
    }
    
    if (paddingSize > 255) {
        throw PaddingException("ISO 10126: Padding size exceeds maximum (255)");
    }
    
    if (paddedData.back() != padByte) {
        throw PaddingException("ISO 10126: Invalid padding size byte");
    }
    
    return ByteArray(paddedData.begin(), paddedData.end() - paddingSize);
}

bool ISO10126Padding::validate(const ByteArray& paddedData) const {
    try {
        unpad(paddedData);
        return true;
    } catch (const PaddingException&) {
        return false;
    }
}

}