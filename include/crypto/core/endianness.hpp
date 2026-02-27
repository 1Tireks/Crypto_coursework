#pragma once
#include "types.hpp"
#include <cstdint>

namespace crypto {
namespace endianness {

bool isBigEndian();
bool isLittleEndian();

uint16_t bytesToUint16BE(const Byte* bytes);
uint32_t bytesToUint32BE(const Byte* bytes);
uint64_t bytesToUint64BE(const Byte* bytes);

uint16_t bytesToUint16LE(const Byte* bytes);
uint32_t bytesToUint32LE(const Byte* bytes);
uint64_t bytesToUint64LE(const Byte* bytes);

void uint16ToBytesBE(uint16_t value, Byte* bytes);
void uint32ToBytesBE(uint32_t value, Byte* bytes);
void uint64ToBytesBE(uint64_t value, Byte* bytes);

void uint16ToBytesLE(uint16_t value, Byte* bytes);
void uint32ToBytesLE(uint32_t value, Byte* bytes);
void uint64ToBytesLE(uint64_t value, Byte* bytes);

uint16_t swapEndian(uint16_t value);
uint32_t swapEndian(uint32_t value);
uint64_t swapEndian(uint64_t value);

uint32_t bytesToUint32BE(const ByteArray& bytes, size_t offset = 0);
uint64_t bytesToUint64BE(const ByteArray& bytes, size_t offset = 0);
void uint32ToBytesBE(uint32_t value, ByteArray& bytes, size_t offset = 0);
void uint64ToBytesBE(uint64_t value, ByteArray& bytes, size_t offset = 0);

uint32_t bytesToUint32LE(const ByteArray& bytes, size_t offset = 0);
uint64_t bytesToUint64LE(const ByteArray& bytes, size_t offset = 0);
void uint32ToBytesLE(uint32_t value, ByteArray& bytes, size_t offset = 0);
void uint64ToBytesLE(uint64_t value, ByteArray& bytes, size_t offset = 0);

}
}
