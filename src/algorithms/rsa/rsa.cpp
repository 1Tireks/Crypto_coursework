#include "../../../include/crypto/algorithms/rsa/rsa.hpp"
#include "../../../include/crypto/core/exceptions.hpp"
#include <algorithm>

namespace crypto {
namespace rsa {

RSA::RSA() : hasPrivateKey_(false) {
}

RSA::RSA(const RSAKey& key) : key_(key), hasPrivateKey_(key.isPrivate()) {
    if (!key_.isValid()) {
        throw CryptoException("Invalid RSA key");
    }
}

void RSA::setPublicKey(const BigInteger& n, const BigInteger& e) {
    key_.n = n;
    key_.e = e;
    key_.d = BigInteger(0);
    key_.p = BigInteger(0);
    key_.q = BigInteger(0);
    hasPrivateKey_ = false;
}

void RSA::setPrivateKey(const BigInteger& n, const BigInteger& d) {
    key_.n = n;
    key_.d = d;
    hasPrivateKey_ = true;
}

void RSA::setKey(const RSAKey& key) {
    key_ = key;
    hasPrivateKey_ = key.isPrivate();
    if (!key_.isValid()) {
        throw CryptoException("Invalid RSA key");
    }
}

size_t RSA::blockSize() const {
    return getBlockSize();
}

size_t RSA::keySize() const {
    if (key_.n.isZero()) {
        return 0;
    }
    return (key_.n.bitLength() + 7) / 8;
}

void RSA::setKey(const Key& key) {
    throw CryptoException("RSA: Use setPublicKey() or setKey(const RSAKey&) instead of setKey(const Key&)");
}

bool RSA::isValidKey(const Key& key) const {
    return false;
}

size_t RSA::getBlockSize() const {
    size_t modBits = key_.n.bitLength();
    return (modBits + 7) / 8 - 1;
}

BigInteger RSA::encryptInteger(const BigInteger& m) const {
    if (m >= key_.n) {
        throw CryptoException("Message too large for RSA encryption");
    }
    return BigInteger::modPow(m, key_.e, key_.n);
}

BigInteger RSA::decryptInteger(const BigInteger& c) const {
    if (!hasPrivateKey_) {
        throw CryptoException("Private key required for decryption");
    }
    if (c >= key_.n) {
        throw CryptoException("Ciphertext too large");
    }
    return BigInteger::modPow(c, key_.d, key_.n);
}

ByteArray RSA::encryptBlock(const ByteArray& block) const {
    if (block.size() > getBlockSize()) {
        throw CryptoException("Block too large for encryption");
    }
    
    BigInteger m = BigInteger::fromBytes(block);
    BigInteger c = encryptInteger(m);
    
    ByteArray result = c.toBytes();
    
    size_t modSize = (key_.n.bitLength() + 7) / 8;
    while (result.size() < modSize) {
        result.insert(result.begin(), 0);
    }
    
    return result;
}

ByteArray RSA::decryptBlock(const ByteArray& block) const {
    if (!hasPrivateKey_) {
        throw CryptoException("Private key required for decryption");
    }
    
    BigInteger c = BigInteger::fromBytes(block);
    BigInteger m = decryptInteger(c);
    
    ByteArray result = m.toBytes();
    
    while (result.size() > 1 && result[0] == 0) {
        result.erase(result.begin());
    }
    
    return result;
}

ByteArray RSA::encrypt(const ByteArray& plaintext) {
    if (!key_.isValid()) {
        throw CryptoException("RSA key not set");
    }
    
    size_t blockSize = getBlockSize();
    ByteArray result;
    
    for (size_t i = 0; i < plaintext.size(); i += blockSize) {
        size_t chunkSize = std::min(blockSize, plaintext.size() - i);
        ByteArray block(plaintext.begin() + i, plaintext.begin() + i + chunkSize);
        
        ByteArray encrypted = encryptBlock(block);
        result.insert(result.end(), encrypted.begin(), encrypted.end());
    }
    
    return result;
}

ByteArray RSA::decrypt(const ByteArray& ciphertext) {
    if (!hasPrivateKey_) {
        throw CryptoException("Private key required for decryption");
    }
    
    size_t modSize = (key_.n.bitLength() + 7) / 8;
    if (ciphertext.size() % modSize != 0) {
        throw CryptoException("Invalid ciphertext size");
    }
    
    ByteArray result;
    
    for (size_t i = 0; i < ciphertext.size(); i += modSize) {
        ByteArray block(ciphertext.begin() + i, ciphertext.begin() + i + modSize);
        ByteArray decrypted = decryptBlock(block);
        result.insert(result.end(), decrypted.begin(), decrypted.end());
    }
    
    return result;
}

ByteArray RSA::padOAEP(const ByteArray& data) const {
    size_t blockSize = getBlockSize();
    if (data.size() >= blockSize) {
        return data;
    }
    
    ByteArray padded = data;
    padded.resize(blockSize, 0);
    padded[blockSize - 1] = static_cast<Byte>(data.size());
    
    return padded;
}

ByteArray RSA::unpadOAEP(const ByteArray& padded) const {
    if (padded.empty()) return {};
    
    size_t dataSize = padded.back();
    if (dataSize > padded.size()) {
        throw CryptoException("Invalid OAEP padding");
    }
    
    return ByteArray(padded.begin(), padded.begin() + dataSize);
}

}
}

