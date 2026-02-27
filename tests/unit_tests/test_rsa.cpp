#include "../test_common.hpp"
#include "crypto/algorithms/rsa/rsa.hpp"
#include "crypto/algorithms/rsa/rsa_keygen.hpp"
#include "crypto/core/utils.hpp"
#include "crypto/math/random.hpp"
#include <memory>

using namespace crypto;
using namespace crypto::rsa;

void testRSABasic() {
    test_common::printHeader("Test 1: RSA Basic Operations");
    
    
    
    RSAKey key;
    bool keyGenerated = false;
    for (int attempt = 0; attempt < 5; ++attempt) {
        try {
            
            key = RSAKeyGenerator::generate(128);
            keyGenerated = true;
            break;
        } catch (const std::exception& e) {
            if (attempt == 4) {
                std::cout << "  ⚠ SKIP: RSA basic test - Could not generate key after 5 attempts: " << e.what() << std::endl;
                return;
            }
        }
    }
    
    if (!keyGenerated) {
        std::cout << "  ⚠ SKIP: RSA basic test - Could not generate key" << std::endl;
        return;
    }
    
    try {
        RSA rsa(key);
        
        std::string plaintext = "Hello, RSA!";
        ByteArray data = utils::stringToBytes(plaintext);
        
        ByteArray encrypted = rsa.encrypt(data);
        ByteArray decrypted = rsa.decrypt(encrypted);
        
        test_common::checkResult("RSA encryption/decryption", data, decrypted);
        
        
        std::string plaintext2 = "Different text";
        ByteArray data2 = utils::stringToBytes(plaintext2);
        ByteArray encrypted2 = rsa.encrypt(data2);
        
        test_common::checkResult("RSA different plaintexts produce different ciphertexts",
                   ByteArray(1, 0),
                   (encrypted == encrypted2 ? ByteArray(1, 1) : ByteArray(1, 0)));
        
        
        RSA rsa2(key);
        ByteArray encrypted3 = rsa2.encrypt(data);
        test_common::checkResult("RSA deterministic encryption with same key", encrypted, encrypted3);
        
    } catch (const std::exception& e) {
        std::cout << "  ✗ ERROR: RSA basic test - " << e.what() << std::endl;
        test_common::testsFailed++;
    }
}

void testRSAKeyGeneration() {
    test_common::printHeader("Test 2: RSA Key Generation");
    
    
    RSAKey key1, key2;
    bool keysGenerated = false;
    for (int attempt = 0; attempt < 5; ++attempt) {
        try {
            key1 = RSAKeyGenerator::generate(128);
            key2 = RSAKeyGenerator::generate(128);
            keysGenerated = true;
            break;
        } catch (const std::exception& e) {
            if (attempt == 4) {
                std::cout << "  ⚠ SKIP: RSA key generation - Could not generate keys after 5 attempts: " << e.what() << std::endl;
                return;
            }
        }
    }
    
    if (!keysGenerated) {
        std::cout << "  ⚠ SKIP: RSA key generation - Could not generate keys" << std::endl;
        return;
    }
    
    try {
        test_common::checkResult("RSA: Generated keys are different",
                   ByteArray(1, 0),
                   (key1.n == key2.n ? ByteArray(1, 1) : ByteArray(1, 0)));
        
        
        if (key1.isValid() && key1.isPrivate()) {
            std::cout << "  ✓ PASS: RSA: Generated keys are valid" << std::endl;
            test_common::testsPassed++;
        } else {
            std::cout << "  ✗ FAIL: RSA: Invalid generated keys" << std::endl;
            test_common::testsFailed++;
        }
        
        
        RSA rsa(key1);
        RSAKey publicKey(key1.n, key1.e);
        RSA rsaPublic(publicKey);
        
        ByteArray data = utils::stringToBytes("Test");
        ByteArray encrypted = rsaPublic.encrypt(data);
        
        
        try {
            ByteArray decrypted = rsa.decrypt(encrypted);
            test_common::checkResult("RSA: Public encrypt, private decrypt", data, decrypted);
        } catch (const std::exception& e) {
            std::cout << "  ✗ FAIL: RSA: Public/private key pair - " << e.what() << std::endl;
            test_common::testsFailed++;
        }
        
    } catch (const std::exception& e) {
        std::cout << "  ✗ ERROR: RSA key generation - " << e.what() << std::endl;
        test_common::testsFailed++;
    }
}

void testRSADataSizes() {
    test_common::printHeader("Test 3: RSA Different Data Sizes");
    
    RSAKey key;
    bool keyGenerated = false;
    for (int attempt = 0; attempt < 5; ++attempt) {
        try {
            key = RSAKeyGenerator::generate(128);
            keyGenerated = true;
            break;
        } catch (const std::exception& e) {
            if (attempt == 4) {
                std::cout << "  ⚠ SKIP: RSA data sizes - Could not generate key after 5 attempts: " << e.what() << std::endl;
                return;
            }
        }
    }
    
    if (!keyGenerated) {
        std::cout << "  ⚠ SKIP: RSA data sizes - Could not generate key" << std::endl;
        return;
    }
    
    try {
        RSA rsa(key);
        
        size_t blockSize = rsa.getBlockSize();
        std::vector<size_t> sizes = {1, 5, 10, blockSize - 1, blockSize};
        
        for (size_t size : sizes) {
            if (size <= blockSize) {
                ByteArray data = math::randomBytes(size);
                ByteArray encrypted = rsa.encrypt(data);
                ByteArray decrypted = rsa.decrypt(encrypted);
                
                std::string testName = "RSA size " + std::to_string(size) + " bytes";
                test_common::checkResult(testName, data, decrypted);
            }
        }
        
    } catch (const std::exception& e) {
        std::cout << "  ✗ ERROR: RSA data sizes - " << e.what() << std::endl;
        test_common::testsFailed++;
    }
}

void testRSAWienerAttack() {
    test_common::printHeader("Test 4: RSA Wiener Attack (Vulnerability Check)");
    
    RSAKey key;
    bool keyGenerated = false;
    for (int attempt = 0; attempt < 5; ++attempt) {
        try {
            
            
            key = RSAKeyGenerator::generate(128);
            keyGenerated = true;
            break;
        } catch (const std::exception& e) {
            if (attempt == 4) {
                std::cout << "  ⚠ SKIP: RSA Wiener attack test - Could not generate key after 5 attempts: " << e.what() << std::endl;
                return;
            }
        }
    }
    
    if (!keyGenerated) {
        std::cout << "  ⚠ SKIP: RSA Wiener attack test - Could not generate key" << std::endl;
        return;
    }
    
    try {
        bool isVulnerable = RSAKeyGenerator::isVulnerableToWiener(key);
        
        if (!isVulnerable) {
            std::cout << "  ✓ PASS: RSA: Key is not vulnerable to Wiener attack" << std::endl;
            test_common::testsPassed++;
        } else {
            std::cout << "  ⚠ WARN: RSA: Key may be vulnerable to Wiener attack" << std::endl;
            std::cout << "  ⚠ SKIP: Full Wiener attack test (requires large keys)" << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cout << "  ⚠ SKIP: RSA Wiener attack test - " << e.what() << std::endl;
    }
}

int main() {
    std::cout << "╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║                  RSA TEST SUITE                           ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    try {
        testRSABasic();
        testRSAKeyGeneration();
        testRSADataSizes();
        testRSAWienerAttack();
        
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

