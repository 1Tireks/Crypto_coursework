// src/core/utils.cpp

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
            throw CryptoException("Invalid hex character in string"); // если в строке есть невалидные символы
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

bool isWeakDESKey(const Key& key) {
    if (key.size() != DES_KEY_SIZE) return false;
    
    uint64_t keyBits = extractDESKeyBits(key.bytes());
    
    for (uint64_t weakKey : WEAK_DES_KEYS) {
        if (keyBits == weakKey) {
            return true;
        }
    }
    
    return false;
}

bool isSemiWeakDESKey(const Key& key) {
    if (key.size() != DES_KEY_SIZE) return false;
    
    uint64_t keyBits = extractDESKeyBits(key.bytes());
    
    for (const auto& [key1, key2] : SEMI_WEAK_DES_KEY_PAIRS) {
        uint64_t key1WithoutParity = key1 & 0xFEFEFEFEFEFEFEFEULL;
        uint64_t key2WithoutParity = key2 & 0xFEFEFEFEFEFEFEFEULL;
        if (keyBits == key1WithoutParity || keyBits == key2WithoutParity) {
            return true;
        }
    }
    
    return false;
}

uint64_t extractDESKeyBits(const Byte* keyData) {
    uint64_t key = 0;
    for (int i = 0; i < 8; ++i) {
        key = (key << 8) | (keyData[i] & 0xFE);  
    }
    return key;
}

bool isValidDESKey(const Key& key) {
    if (key.size() != DES_KEY_SIZE) {  
        return false;
    }
    
    const Byte* keyData = key.bytes();
    
    for (size_t i = 0; i < DES_KEY_SIZE; ++i) {
        Byte currentByte = keyData[i];
        
        int onesCount = 0;
        for (int bit = 7; bit >= 1; --bit) {  
            if (currentByte & (1 << (bit - 1))) {
                ++onesCount;
            }
        }
        
        bool parityBit = (currentByte & 0x01) != 0;
        
        bool expectedParity = (onesCount % 2) == 0;
        
        if (parityBit != expectedParity) {
            return false;  
        }
    }
    
    if (isWeakDESKey(key)) {
        return false;
    }
    
    if (isSemiWeakDESKey(key)) {
        return false;
    }
    
    return true;
}

bool isValidTripleDESKey(const Key& key) {
    if (key.size() != TRIPLE_DES_KEY_SIZE_2KEY &&  
        key.size() != TRIPLE_DES_KEY_SIZE_3KEY) {
        return false;
    }
    
    const Byte* keyData = key.bytes();
    
    bool allZeros = true;
    bool allOnes = true;
    for (size_t i = 0; i < key.size(); ++i) {
        if (keyData[i] != 0x00) allZeros = false;
        if (keyData[i] != 0xFF) allOnes = false;
        if (!allZeros && !allOnes) break;
    }
    if (allZeros || allOnes) {
        return false;
    }
    
    if (key.size() >= 2) {
        Byte first = keyData[0];
        bool allSame = true;
        for (size_t i = 1; i < key.size(); ++i) {
            if (keyData[i] != first) {
                allSame = false;
                break;
            }
        }
        if (allSame) return false;
    }
    
    if (key.size() == TRIPLE_DES_KEY_SIZE_2KEY) {
        bool halvesEqual = true;
        for (size_t i = 0; i < 8; ++i) {
            if (keyData[i] != keyData[i + 8]) {
                halvesEqual = false;
                break;
            }
        }
        if (halvesEqual) return false;
    }
    
    else if (key.size() == TRIPLE_DES_KEY_SIZE_3KEY) {
        bool allPartsEqual = true;
        for (size_t i = 0; i < 8; ++i) {
            if (!(keyData[i] == keyData[i + 8] && 
                  keyData[i] == keyData[i + 16])) {
                allPartsEqual = false;
                break;
            }
        }
        if (allPartsEqual) return false;
        
        bool firstThirdEqual = true;
        for (size_t i = 0; i < 8; ++i) {
            if (keyData[i] != keyData[i + 16]) {
                firstThirdEqual = false;
                break;
            }
        }
        if (firstThirdEqual) return false;
    }
    
    return true;
}

bool isValidDEALKey(const Key& key) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        return false;
    }
    
    const Byte* keyData = key.bytes();
    const size_t size = key.size();
    
    bool allZeros = true;
    bool allOnes = true;
    for (size_t i = 0; i < size; ++i) {
        if (keyData[i] != 0x00) allZeros = false;
        if (keyData[i] != 0xFF) allOnes = false;
        if (!allZeros && !allOnes) break;
    }
    if (allZeros || allOnes) {
        return false;
    }
    
    if (size >= 4) {
        Byte first = keyData[0];
        bool allSame = true;
        for (size_t i = 1; i < size; ++i) {
            if (keyData[i] != first) {
                allSame = false;
                break;
            }
        }
        if (allSame) return false;
        
        if (size % 2 == 0) {
            bool repeatingPairs = true;
            for (size_t i = 2; i < size; i += 2) {
                if (keyData[i] != keyData[0] || keyData[i+1] != keyData[1]) {
                    repeatingPairs = false;
                    break;
                }
            }
            if (repeatingPairs) return false;
        }
        
        bool sequential = true;
        for (size_t i = 1; i < size; ++i) {
            if (keyData[i] != keyData[i-1] + 1) {
                sequential = false;
                break;
            }
        }
        if (sequential) return false;
    }
    
    std::array<bool, 256> seen = {false};
    int uniqueCount = 0;
    
    for (size_t i = 0; i < size; ++i) {
        Byte b = keyData[i];
        if (!seen[b]) {
            seen[b] = true;
            uniqueCount++;
        }
    }
    
    if (uniqueCount < size / 2) {
        return false;
    }
    
    return true;
}

}

}
