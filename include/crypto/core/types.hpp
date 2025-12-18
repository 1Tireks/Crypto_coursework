// include/crypto/core/types.hpp

#pragma once
#include <vector>
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <sstream>
#include <iomanip>
#include "exceptions.hpp"

namespace crypto {

using Byte = uint8_t;
using ByteArray = std::vector<Byte>;

template<size_t N>
using Block = std::array<Byte, N>;

using Block128 = Block<16>;  // 128 бит для DEAL
using Block64 = Block<8>;    // 64 бит для DES
using Block32 = Block<4>;    // 32 бит для внутренних операций

struct Key {
    ByteArray data;

    Key() = default;
    explicit Key(const ByteArray& d) : data(d) {}
    explicit Key(const std::string& hex);

    size_t size() const { return data.size(); }
    bool empty() const { return data.empty(); }

    const Byte* bytes() const { return data.data(); }
    Byte* bytes() { return data.data(); }

    std::string toHex() const;
    static Key fromHex(const std::string& hex);

};

// Реализации методов Key
inline Key::Key(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw CryptoException("Hex string must have even length");
    }

    data.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        Byte byte = static_cast<Byte>(std::stoi(byteString, nullptr, 16));
        data.push_back(byte);
    }
}

inline std::string Key::toHex() const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (Byte b : data) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

inline Key Key::fromHex(const std::string& hex) {
    return Key(hex);
}

// Константы
constexpr size_t DES_BLOCK_SIZE = 8;             // 64 бита
constexpr size_t DES_KEY_SIZE = 8;               // 64 бита (56 + 8 parity)
constexpr size_t TRIPLE_DES_KEY_SIZE_2KEY = 16;  // 128 бит
constexpr size_t TRIPLE_DES_KEY_SIZE_3KEY = 24;  // 192 бит
constexpr size_t DEAL_BLOCK_SIZE = 16;           // 128 бит
constexpr size_t DEAL_KEY_SIZE = 16;             // 128 бит (для DEAL-128)

}

