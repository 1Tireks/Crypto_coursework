#include "../../include/crypto/core/utils.hpp"
#include "../../include/crypto/core/exceptions.hpp"
#include "../../include/crypto/math/random.hpp"
#include "../../include/crypto/algorithms/des/des_constants.hpp"
#include <bitset>
#include <sstream>
#include <iomanip>

using namespace crypto::des;

namespace crypto {
namespace utils {

ByteArray hexToBytes(const std::string& hex) {

    if (hex.length() % 2 != 0) {
        throw CryptoException("Hex string must have even length");
    }
    
    ByteArray bytes;
    bytes.reserve(hex.length() / 2); 
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        try {
            std::string byteString = hex.substr(i, 2);
            Byte byte = static_cast<Byte>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        catch (const std::exception&) {
            throw CryptoException("Invalid hex character in string"); 
        }
    }
    
    return bytes;
}

std::string bytesToHex(const ByteArray& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (Byte b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    
    return ss.str();
}

using math::randomBytes;
using math::randomKey;

void xorBlocks(const Byte* a, const Byte* b, Byte* result, size_t size) {
    if (a == nullptr) {
        throw CryptoException("xorBlocks: parameter 'a' is nullptr");
    }
    if (b == nullptr) {
        throw CryptoException("xorBlocks: parameter 'b' is nullptr");
    }
    if (result == nullptr) {
        throw CryptoException("xorBlocks: parameter 'result' is nullptr");
    }
    
    if (size == 0) {
        return;
    }
    
    for (size_t i = 0; i < size; ++i) {
        result[i] = a[i] ^ b[i];
    }
}

void xorBlocksInPlace(Byte* target, const Byte* source, size_t size) {
    if (target == nullptr) {
        throw CryptoException("xorBlocksInPlace: parameter 'target' is nullptr");
    }
    if (source == nullptr) {
        throw CryptoException("xorBlocksInPlace: parameter 'source' is nullptr");
    }
    
    if (size == 0) {
        return;
    }
    
    if (target == source) {
        for (size_t i = 0; i < size; ++i) {
            target[i] = 0;
        }
        return;
    }
    
    for (size_t i = 0; i < size; ++i) {
        target[i] ^= source[i];
    }
}

}

}
