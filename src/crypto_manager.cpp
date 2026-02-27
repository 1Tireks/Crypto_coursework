#include "crypto/crypto_manager.hpp"
#include "crypto/algorithms/des/des.hpp"
#include "crypto/algorithms/des/triple_des.hpp"
#include "crypto/algorithms/deal/deal.hpp"
#include "crypto/core/utils.hpp"
#include "crypto/core/exceptions.hpp"
#include "crypto/math/random.hpp"
#include <algorithm>
#include <cctype>

namespace crypto {

std::shared_ptr<IBlockCipher> CryptoManager::createCipher(
    const std::string& algorithmName,
    const Key& key) {
    
    std::string alg = algorithmName;
    std::transform(alg.begin(), alg.end(), alg.begin(), ::toupper);
    
    if (alg == "DES") {
        auto cipher = std::make_shared<DES>();
        cipher->setKey(key);
        return cipher;
    } else if (alg == "TRIPLEDES" || alg == "3DES") {
        auto cipher = std::make_shared<TripleDES>();
        cipher->setKey(key);
        return cipher;
    } else if (alg == "DEAL") {
        size_t keySize = key.size();
        if (keySize != 16 && keySize != 24 && keySize != 32) {
            throw InvalidKeyException("DEAL requires key size 16, 24, or 32 bytes");
        }
        auto cipher = std::make_shared<DEAL>(keySize);
        cipher->setKey(key);
        return cipher;
    }
    
    throw CryptoException("Unknown algorithm: " + algorithmName);
}

CipherMode CryptoManager::parseMode(const std::string& modeName) const {
    std::string mode = modeName;
    std::transform(mode.begin(), mode.end(), mode.begin(), ::toupper);
    
    if (mode == "ECB") return CipherMode::ECB;
    if (mode == "CBC") return CipherMode::CBC;
    if (mode == "PCBC") return CipherMode::PCBC;
    if (mode == "CFB") return CipherMode::CFB;
    if (mode == "OFB") return CipherMode::OFB;
    if (mode == "CTR") return CipherMode::CTR;
    if (mode == "RANDOMDELTA" || mode == "RANDOM_DELTA") return CipherMode::RANDOM_DELTA;
    
    throw CryptoException("Unknown mode: " + modeName);
}

PaddingType CryptoManager::parsePadding(const std::string& paddingName) const {
    std::string padding = paddingName;
    std::transform(padding.begin(), padding.end(), padding.begin(), ::toupper);
    
    if (padding == "NONE" || padding.empty()) {
        throw CryptoException("Padding cannot be empty for most modes");
    }
    if (padding == "PKCS7" || padding == "PKCS") return PaddingType::PKCS7;
    if (padding == "ZEROS" || padding == "ZERO") return PaddingType::ZEROS;
    if (padding == "ANSIX923" || padding == "ANSI_X923" || padding == "ANSI") {
        return PaddingType::ANSI_X923;
    }
    if (padding == "ISO10126" || padding == "ISO_10126" || padding == "ISO") {
        return PaddingType::ISO_10126;
    }
    
    throw CryptoException("Unknown padding: " + paddingName);
}

std::unique_ptr<IBlockCipherMode> CryptoManager::createEncryptor(
    const std::string& algorithmName,
    const std::string& modeName,
    const std::string& paddingName,
    const Key& key,
    const ByteArray& iv) {
    
    CipherMode mode = parseMode(modeName);
    PaddingType padding = parsePadding(paddingName);
    
    return createEncryptor(algorithmName, mode, padding, key, iv);
}

std::unique_ptr<IBlockCipherMode> CryptoManager::createEncryptor(
    const std::string& algorithmName,
    CipherMode mode,
    PaddingType padding,
    const Key& key,
    const ByteArray& iv) {
    
    auto cipher = createCipher(algorithmName, key);
    auto paddingObj = IPadding::create(padding);
    auto encryptor = IBlockCipherMode::create(mode, cipher, std::move(paddingObj), iv);
    
    return encryptor;
}

Key CryptoManager::generateKey(const std::string& algorithmName) {
    size_t keySize = getKeySize(algorithmName);
    return math::randomKey(keySize);
}

Key CryptoManager::generateKey(size_t keySize) {
    return math::randomKey(keySize);
}

ByteArray CryptoManager::encryptString(
    const std::string& plaintext,
    const std::string& algorithmName,
    const std::string& modeName,
    const std::string& paddingName,
    const Key& key,
    const ByteArray& iv) {
    
    ByteArray data = utils::stringToBytes(plaintext);
    return encrypt(data, algorithmName, modeName, paddingName, key, iv);
}

std::string CryptoManager::decryptString(
    const ByteArray& ciphertext,
    const std::string& algorithmName,
    const std::string& modeName,
    const std::string& paddingName,
    const Key& key,
    const ByteArray& iv) {
    
    ByteArray data = decrypt(ciphertext, algorithmName, modeName, paddingName, key, iv);
    return utils::bytesToString(data);
}

ByteArray CryptoManager::encrypt(
    const ByteArray& plaintext,
    const std::string& algorithmName,
    const std::string& modeName,
    const std::string& paddingName,
    const Key& key,
    const ByteArray& iv) {
    
    auto encryptor = createEncryptor(algorithmName, modeName, paddingName, key, iv);
    return encryptor->encrypt(plaintext);
}

ByteArray CryptoManager::decrypt(
    const ByteArray& ciphertext,
    const std::string& algorithmName,
    const std::string& modeName,
    const std::string& paddingName,
    const Key& key,
    const ByteArray& iv) {
    
    auto encryptor = createEncryptor(algorithmName, modeName, paddingName, key, iv);
    return encryptor->decrypt(ciphertext);
}

bool CryptoManager::isValidConfiguration(
    const std::string& algorithmName,
    const std::string& modeName,
    const std::string& paddingName) const {
    
    try {
        parseMode(modeName);
        parsePadding(paddingName);
        std::string alg = algorithmName;
        std::transform(alg.begin(), alg.end(), alg.begin(), ::toupper);
        return (alg == "DES" || alg == "TRIPLEDES" || alg == "3DES" || alg == "DEAL");
    } catch (...) {
        return false;
    }
}

size_t CryptoManager::getKeySize(const std::string& algorithmName) const {
    std::string alg = algorithmName;
    std::transform(alg.begin(), alg.end(), alg.begin(), ::toupper);
    
    if (alg == "DES") return DES_KEY_SIZE;
    if (alg == "TRIPLEDES" || alg == "3DES") return TRIPLE_DES_KEY_SIZE_3KEY;
    if (alg == "DEAL") return 16;
    
    throw CryptoException("Unknown algorithm: " + algorithmName);
}

size_t CryptoManager::getBlockSize(const std::string& algorithmName) const {
    std::string alg = algorithmName;
    std::transform(alg.begin(), alg.end(), alg.begin(), ::toupper);
    
    if (alg == "DES" || alg == "TRIPLEDES" || alg == "3DES") return DES_BLOCK_SIZE;
    if (alg == "DEAL") return DEAL_BLOCK_SIZE;
    
    throw CryptoException("Unknown algorithm: " + algorithmName);
}

}

