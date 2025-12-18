// include/crypto/core/utils.hpp

#pragma once
#include "types.hpp"
#include <string>

namespace crypto {
namespace utils {

inline ByteArray stringToBytes(const std::string& str) {
    return ByteArray(str.begin(), str.end());
}

inline std::string bytesToString(const ByteArray& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

ByteArray hexToBytes(const std::string& hex);
std::string bytesToHex(const ByteArray& bytes);


template<typename T>
inline T rotateLeft(T value, size_t count) {
    const size_t bitCount = sizeof(T) * 8;
    count %= bitCount;
    return (value << count) | (value >> (bitCount - count));
}

template<typename T>
inline T rotateRight(T value, size_t count) {
    const size_t bitCount = sizeof(T) * 8;
    count %= bitCount;
    return (value >> count) | (value << (bitCount - count));
}

void xorBlocks(const Byte* a, const Byte* b, Byte* result, size_t size);
void xorBlocksInPlace(Byte* target, const Byte* source, size_t size);

inline void copyBlock(const Byte* src, Byte* dst, size_t size) {
    std::copy(src, src + size, dst);
}

bool isValidDESKey(const Key& key);
bool isValidTripleDESKey(const Key& key);
bool isValidDEALKey(const Key& key);

bool isWeakDESKey(const Key& key);
bool isSemiWeakDESKey(const Key& key);
uint64_t extractDESKeyBits(const Byte* keyData);

template<size_t From, size_t To>
inline Block<To> resizeBlock(const Block<From>& block) {
    static_assert(To >= From, "Target block must be at least as large as source");
    Block<To> result = {};
    std::copy(block.begin(), block.end(), result.begin());
    return result;
}

}
}
