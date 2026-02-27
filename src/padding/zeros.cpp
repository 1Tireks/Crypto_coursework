#include "../../include/crypto/padding/padding.hpp"
#include "../../include/crypto/core/utils.hpp"
#include <algorithm>
#include <cstring>

namespace crypto {

ByteArray ZeroPadding::pad(const ByteArray& data, size_t blockSize) {
    if (blockSize == 0) {
        throw PaddingException("Block size cannot be zero");
    }
    
    size_t paddingSize = blockSize - (data.size() % blockSize);
    if (paddingSize == blockSize) {
        paddingSize = 0;
    }
    
    ByteArray padded = data;
    padded.resize(data.size() + paddingSize, 0x00);
    
    return padded;
}

ByteArray ZeroPadding::unpad(const ByteArray& paddedData) const {
    if (paddedData.empty()) {
        return ByteArray();
    }
    
    auto it = std::find_if(paddedData.rbegin(), paddedData.rend(),
        [](Byte b) { return b != 0; });
    
    if (it == paddedData.rend()) {
        return ByteArray();
    }
    
    size_t dataSize = std::distance(paddedData.begin(), it.base());
    
    return ByteArray(paddedData.begin(), paddedData.begin() + dataSize);
}

bool ZeroPadding::validate(const ByteArray& paddedData) const {
    return true;
}

}