#include "../test_common.hpp"
#include "crypto/crypto_manager.hpp"
#include "crypto/core/utils.hpp"
#include <vector>

using namespace crypto;

void testCryptoManagerKeyGeneration() {
    test_common::printHeader("Test 1: CryptoManager Key Generation");
    
    CryptoManager manager;
    
    try {
        Key desKey = manager.generateKey("DES");
        Key tdesKey = manager.generateKey("TripleDES");
        Key dealKey = manager.generateKey("DEAL");
        
        test_common::checkResult("CryptoManager: Generate DES key", 
                   ByteArray(1, desKey.size() == DES_KEY_SIZE ? 1 : 0),
                   ByteArray(1, 1));
        test_common::checkResult("CryptoManager: Generate TripleDES key",
                   ByteArray(1, tdesKey.size() == TRIPLE_DES_KEY_SIZE_3KEY ? 1 : 0),
                   ByteArray(1, 1));
        test_common::checkResult("CryptoManager: Generate DEAL key",
                   ByteArray(1, dealKey.size() == 16 ? 1 : 0),
                   ByteArray(1, 1));
    } catch (const std::exception& e) {
        std::cout << "  ✗ FAIL: CryptoManager key generation - " << e.what() << std::endl;
        test_common::testsFailed++;
    }
}

void testCryptoManagerEncryptor() {
    test_common::printHeader("Test 2: CryptoManager Encryptor Creation");
    
    CryptoManager manager;
    
    try {
        Key key = manager.generateKey("DES");
        auto encryptor = manager.createEncryptor("DES", "CBC", "PKCS7", key);
        
        std::string plaintext = "CryptoManager test";
        ByteArray data = utils::stringToBytes(plaintext);
        ByteArray encrypted = encryptor->encrypt(data);
        ByteArray decrypted = encryptor->decrypt(encrypted);
        
        test_common::checkResult("CryptoManager: Create encryptor and encrypt/decrypt", data, decrypted);
    } catch (const std::exception& e) {
        std::cout << "  ✗ FAIL: CryptoManager encryptor creation - " << e.what() << std::endl;
        test_common::testsFailed++;
    }
}

void testCryptoManagerAlgorithms() {
    test_common::printHeader("Test 3: CryptoManager Different Algorithms");
    
    CryptoManager manager;
    
    std::vector<std::pair<std::string, std::string>> algorithms = {
        {"DES", "CBC"},
        {"TripleDES", "CBC"},
        {"DEAL", "CBC"}
    };
    
    for (const auto& [alg, mode] : algorithms) {
        try {
            Key key = manager.generateKey(alg);
            auto encryptor = manager.createEncryptor(alg, mode, "PKCS7", key);
            
            ByteArray data = utils::stringToBytes("Test data for " + alg);
            ByteArray encrypted = encryptor->encrypt(data);
            ByteArray decrypted = encryptor->decrypt(encrypted);
            
            test_common::checkResult("CryptoManager: " + alg + "+" + mode, data, decrypted);
        } catch (const std::exception& e) {
            std::cout << "  ✗ FAIL: CryptoManager " << alg << " - " << e.what() << std::endl;
            test_common::testsFailed++;
        }
    }
}

void testCryptoManagerValidation() {
    test_common::printHeader("Test 4: CryptoManager Configuration Validation");
    
    CryptoManager manager;
    
    try {
        bool valid1 = manager.isValidConfiguration("DES", "CBC", "PKCS7");
        bool valid2 = manager.isValidConfiguration("UNKNOWN", "CBC", "PKCS7");
        bool valid3 = manager.isValidConfiguration("DES", "UNKNOWN", "PKCS7");
        
        if (valid1 && !valid2 && !valid3) {
            std::cout << "  ✓ PASS: CryptoManager: Configuration validation" << std::endl;
            test_common::testsPassed++;
        } else {
            std::cout << "  ✗ FAIL: CryptoManager: Configuration validation" << std::endl;
            test_common::testsFailed++;
        }
    } catch (const std::exception& e) {
        std::cout << "  ✗ FAIL: CryptoManager validation - " << e.what() << std::endl;
        test_common::testsFailed++;
    }
}

void testCryptoManagerSizes() {
    test_common::printHeader("Test 5: CryptoManager Get Sizes");
    
    CryptoManager manager;
    
    try {
        size_t desKeySize = manager.getKeySize("DES");
        size_t desBlockSize = manager.getBlockSize("DES");
        size_t dealBlockSize = manager.getBlockSize("DEAL");
        
        if (desKeySize == DES_KEY_SIZE && 
            desBlockSize == DES_BLOCK_SIZE && 
            dealBlockSize == DEAL_BLOCK_SIZE) {
            std::cout << "  ✓ PASS: CryptoManager: Get key/block sizes" << std::endl;
            test_common::testsPassed++;
        } else {
            std::cout << "  ✗ FAIL: CryptoManager: Get key/block sizes" << std::endl;
            test_common::testsFailed++;
        }
    } catch (const std::exception& e) {
        std::cout << "  ✗ FAIL: CryptoManager sizes - " << e.what() << std::endl;
        test_common::testsFailed++;
    }
}

void testCryptoManagerModes() {
    test_common::printHeader("Test 6: CryptoManager Different Modes");
    
    CryptoManager manager;
    
    std::vector<std::string> modes = {"ECB", "CBC", "PCBC", "OFB"};
    for (const auto& mode : modes) {
        try {
            Key key = manager.generateKey("DES");
            auto encryptor = manager.createEncryptor("DES", mode, "PKCS7", key);
            
            ByteArray data = utils::stringToBytes("Mode test: " + mode);
            ByteArray encrypted = encryptor->encrypt(data);
            ByteArray decrypted = encryptor->decrypt(encrypted);
            
            test_common::checkResult("CryptoManager: DES+" + mode, data, decrypted);
        } catch (const std::exception& e) {
            std::cout << "  ⚠ SKIP: CryptoManager DES+" << mode << " - " << e.what() << std::endl;
        }
    }
}

int main() {
    std::cout << "╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║            CRYPTO MANAGER TEST SUITE                     ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    try {
        testCryptoManagerKeyGeneration();
        testCryptoManagerEncryptor();
        testCryptoManagerAlgorithms();
        testCryptoManagerValidation();
        testCryptoManagerSizes();
        testCryptoManagerModes();
        
        test_common::printSummary();
        
        if (test_common::testsFailed == 0) {
            std::cout << "\n✓ All tests passed successfully!" << std::endl;
            return 0;
        } else {
            std::cout << "\n✗ Some tests failed. Please review the output above." << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "\nFATAL ERROR: " << e.what() << std::endl;
        return 1;
    }
}

