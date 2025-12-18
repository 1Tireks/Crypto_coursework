// include/crypto/algorithms/rc4/rc4.hpp
#pragma once
#include "../../ciphers/stream_cipher.hpp"
#include "../../core/types.hpp"
#include <array>

namespace crypto {

class RC4 : public IStreamCipher {
private:
    static constexpr size_t STATE_SIZE = 256;
    std::array<Byte, STATE_SIZE> S_;
    size_t i_;
    size_t j_;
    Key key_;
    bool initialized_;
    
    void keySchedule(const Byte* key, size_t keyLength);
    Byte generateByte();
    
public:
    RC4();
    ~RC4() override = default;
    
    std::string name() const override { return "RC4"; }
    size_t blockSize() const override { return 1; } // Потоковый шифр
    size_t keySize() const override { return key_.size(); }
    
    void setKey(const Key& key) override;
    bool isValidKey(const Key& key) const override;
    
    void encrypt(const Byte* input, Byte* output, size_t length) override;
    void decrypt(const Byte* input, Byte* output, size_t length) override;
    
    void reset() override;
};

} // namespace crypto

