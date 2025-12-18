// src/core/endianness.cpp

#include "../../include/crypto/core/endianness.hpp"
#include <cstring>
#include <stdexcept>

namespace crypto {
namespace endianness {

bool isBigEndian() {
    static const uint16_t test = 0x0100;
    return *reinterpret_cast<const uint8_t*>(&test) != 0;
}

bool isLittleEndian() {
    return !isBigEndian();
}

uint16_t bytesToUint16BE(const Byte* bytes) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(bytes[0]) << 8) |
        static_cast<uint16_t>(bytes[1])
    );
}

uint32_t bytesToUint32BE(const Byte* bytes) {
    return static_cast<uint32_t>(
        (static_cast<uint32_t>(bytes[0]) << 24) |
        (static_cast<uint32_t>(bytes[1]) << 16) |
        (static_cast<uint32_t>(bytes[2]) << 8) |
        static_cast<uint32_t>(bytes[3])
    );
}

uint64_t bytesToUint64BE(const Byte* bytes) {
    return static_cast<uint64_t>(
        (static_cast<uint64_t>(bytes[0]) << 56) |
        (static_cast<uint64_t>(bytes[1]) << 48) |
        (static_cast<uint64_t>(bytes[2]) << 40) |
        (static_cast<uint64_t>(bytes[3]) << 32) |
        (static_cast<uint64_t>(bytes[4]) << 24) |
        (static_cast<uint64_t>(bytes[5]) << 16) |
        (static_cast<uint64_t>(bytes[6]) << 8) |
        static_cast<uint64_t>(bytes[7])
    );
}

uint16_t bytesToUint16LE(const Byte* bytes) {
    return static_cast<uint16_t>(
        static_cast<uint16_t>(bytes[0]) |
        (static_cast<uint16_t>(bytes[1]) << 8)
    );
}

uint32_t bytesToUint32LE(const Byte* bytes) {
    return static_cast<uint32_t>(
        static_cast<uint32_t>(bytes[0]) |
        (static_cast<uint32_t>(bytes[1]) << 8) |
        (static_cast<uint32_t>(bytes[2]) << 16) |
        (static_cast<uint32_t>(bytes[3]) << 24)
    );
}

uint64_t bytesToUint64LE(const Byte* bytes) {
    return static_cast<uint64_t>(
        static_cast<uint64_t>(bytes[0]) |
        (static_cast<uint64_t>(bytes[1]) << 8) |
        (static_cast<uint64_t>(bytes[2]) << 16) |
        (static_cast<uint64_t>(bytes[3]) << 24) |
        (static_cast<uint64_t>(bytes[4]) << 32) |
        (static_cast<uint64_t>(bytes[5]) << 40) |
        (static_cast<uint64_t>(bytes[6]) << 48) |
        (static_cast<uint64_t>(bytes[7]) << 56)
    );
}

void uint16ToBytesBE(uint16_t value, Byte* bytes) {
    bytes[0] = static_cast<Byte>((value >> 8) & 0xFF);
    bytes[1] = static_cast<Byte>(value & 0xFF);
}

void uint32ToBytesBE(uint32_t value, Byte* bytes) {
    bytes[0] = static_cast<Byte>((value >> 24) & 0xFF);
    bytes[1] = static_cast<Byte>((value >> 16) & 0xFF);
    bytes[2] = static_cast<Byte>((value >> 8) & 0xFF);
    bytes[3] = static_cast<Byte>(value & 0xFF);
}

void uint64ToBytesBE(uint64_t value, Byte* bytes) {
    bytes[0] = static_cast<Byte>((value >> 56) & 0xFF);
    bytes[1] = static_cast<Byte>((value >> 48) & 0xFF);
    bytes[2] = static_cast<Byte>((value >> 40) & 0xFF);
    bytes[3] = static_cast<Byte>((value >> 32) & 0xFF);
    bytes[4] = static_cast<Byte>((value >> 24) & 0xFF);
    bytes[5] = static_cast<Byte>((value >> 16) & 0xFF);
    bytes[6] = static_cast<Byte>((value >> 8) & 0xFF);
    bytes[7] = static_cast<Byte>(value & 0xFF);
}

void uint16ToBytesLE(uint16_t value, Byte* bytes) {
    bytes[0] = static_cast<Byte>(value & 0xFF);
    bytes[1] = static_cast<Byte>((value >> 8) & 0xFF);
}

void uint32ToBytesLE(uint32_t value, Byte* bytes) {
    bytes[0] = static_cast<Byte>(value & 0xFF);
    bytes[1] = static_cast<Byte>((value >> 8) & 0xFF);
    bytes[2] = static_cast<Byte>((value >> 16) & 0xFF);
    bytes[3] = static_cast<Byte>((value >> 24) & 0xFF);
}

void uint64ToBytesLE(uint64_t value, Byte* bytes) {
    bytes[0] = static_cast<Byte>(value & 0xFF);
    bytes[1] = static_cast<Byte>((value >> 8) & 0xFF);
    bytes[2] = static_cast<Byte>((value >> 16) & 0xFF);
    bytes[3] = static_cast<Byte>((value >> 24) & 0xFF);
    bytes[4] = static_cast<Byte>((value >> 32) & 0xFF);
    bytes[5] = static_cast<Byte>((value >> 40) & 0xFF);
    bytes[6] = static_cast<Byte>((value >> 48) & 0xFF);
    bytes[7] = static_cast<Byte>((value >> 56) & 0xFF);
}

uint16_t swapEndian(uint16_t value) {
    return static_cast<uint16_t>(
        ((value & 0xFF00) >> 8) |
        ((value & 0x00FF) << 8)
    );
}

uint32_t swapEndian(uint32_t value) {
    return ((value & 0xFF000000) >> 24) |
           ((value & 0x00FF0000) >> 8) |
           ((value & 0x0000FF00) << 8) |
           ((value & 0x000000FF) << 24);
}

uint64_t swapEndian(uint64_t value) {
    return ((value & 0xFF00000000000000ULL) >> 56) |
           ((value & 0x00FF000000000000ULL) >> 40) |
           ((value & 0x0000FF0000000000ULL) >> 24) |
           ((value & 0x000000FF00000000ULL) >> 8) |
           ((value & 0x00000000FF000000ULL) << 8) |
           ((value & 0x0000000000FF0000ULL) << 24) |
           ((value & 0x000000000000FF00ULL) << 40) |
           ((value & 0x00000000000000FFULL) << 56);
}

uint32_t bytesToUint32BE(const ByteArray& bytes, size_t offset) {
    if (offset + 4 > bytes.size()) {
        throw std::out_of_range("Not enough bytes for uint32_t");
    }
    return bytesToUint32BE(bytes.data() + offset);
}

uint64_t bytesToUint64BE(const ByteArray& bytes, size_t offset) {
    if (offset + 8 > bytes.size()) {
        throw std::out_of_range("Not enough bytes for uint64_t");
    }
    return bytesToUint64BE(bytes.data() + offset);
}

void uint32ToBytesBE(uint32_t value, ByteArray& bytes, size_t offset) {
    if (offset + 4 > bytes.size()) {
        bytes.resize(offset + 4);
    }
    uint32ToBytesBE(value, bytes.data() + offset);
}

void uint64ToBytesBE(uint64_t value, ByteArray& bytes, size_t offset) {
    if (offset + 8 > bytes.size()) {
        bytes.resize(offset + 8);
    }
    uint64ToBytesBE(value, bytes.data() + offset);
}

uint32_t bytesToUint32LE(const ByteArray& bytes, size_t offset) {
    if (offset + 4 > bytes.size()) {
        throw std::out_of_range("Not enough bytes for uint32_t");
    }
    return bytesToUint32LE(bytes.data() + offset);
}

uint64_t bytesToUint64LE(const ByteArray& bytes, size_t offset) {
    if (offset + 8 > bytes.size()) {
        throw std::out_of_range("Not enough bytes for uint64_t");
    }
    return bytesToUint64LE(bytes.data() + offset);
}

void uint32ToBytesLE(uint32_t value, ByteArray& bytes, size_t offset) {
    if (offset + 4 > bytes.size()) {
        bytes.resize(offset + 4);
    }
    uint32ToBytesLE(value, bytes.data() + offset);
}

void uint64ToBytesLE(uint64_t value, ByteArray& bytes, size_t offset) {
    if (offset + 8 > bytes.size()) {
        bytes.resize(offset + 8);
    }
    uint64ToBytesLE(value, bytes.data() + offset);
}

}
}
