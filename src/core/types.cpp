#include "../../include/crypto/core/types.hpp"
#include <sstream>
#include <iomanip>

namespace crypto {

Key::Key(const std::string& hex) {
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

std::string Key::toHex() const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (Byte b : data) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

Key Key::fromHex(const std::string& hex) {
    return Key(hex);
}

}

