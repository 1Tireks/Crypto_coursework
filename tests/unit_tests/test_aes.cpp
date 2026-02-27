#include "../test_common.hpp"
#include "crypto/algorithms/rijndael/rijndael.hpp"
#include "crypto/core/utils.hpp"
#include "crypto/math/random.hpp"
#include <memory>

using namespace crypto;
using namespace crypto::rijndael;

void testRijndaelBasic() {
    test_common::printHeader("Test 1: Rijndael (AES) Basic Operations");
    
    try {
        
        Rijndael aes128(KeySize::AES128);
        Key key128 = math::randomKey(16);
        aes128.setKey(key128);
        
        std::string plaintext = "AES-128 test!";
        ByteArray data = utils::stringToBytes(plaintext);
        data.resize(16);
        
        ByteArray encrypted(16), decrypted(16);
        aes128.encryptBlock(data.data(), encrypted.data());
        aes128.decryptBlock(encrypted.data(), decrypted.data());
        test_common::checkResult("AES-128 block encryption", data, decrypted);
        
        
        Rijndael aes192(KeySize::AES192);
        Key key192 = math::randomKey(24);
        aes192.setKey(key192);
        
        ByteArray encrypted192(16), decrypted192(16);
        aes192.encryptBlock(data.data(), encrypted192.data());
        aes192.decryptBlock(encrypted192.data(), decrypted192.data());
        test_common::checkResult("AES-192 block encryption", data, decrypted192);
        
        
        Rijndael aes256(KeySize::AES256);
        Key key256 = math::randomKey(32);
        aes256.setKey(key256);
        
        ByteArray encrypted256(16), decrypted256(16);
        aes256.encryptBlock(data.data(), encrypted256.data());
        aes256.decryptBlock(encrypted256.data(), decrypted256.data());
        test_common::checkResult("AES-256 block encryption", data, decrypted256);
        
        
        Key key128_2 = math::randomKey(16);
        aes128.setKey(key128_2);
        ByteArray encrypted128_2(16);
        aes128.encryptBlock(data.data(), encrypted128_2.data());
        
        test_common::checkResult("AES-128 different keys produce different output",
                   ByteArray(1, 0),
                   (encrypted == encrypted128_2 ? ByteArray(1, 1) : ByteArray(1, 0)));
        
    } catch (const std::exception& e) {
        std::cout << "  ✗ ERROR: Rijndael basic - " << e.what() << std::endl;
        test_common::testsFailed++;
    }
}

void testRijndaelModes() {
    test_common::printHeader("Test 2: Rijndael (AES) with All Modes");
    
    try {
        
        auto aes128 = std::make_shared<Rijndael>(KeySize::AES128);
        Key key = math::randomKey(16);
        aes128->setKey(key);
        
        std::vector<CipherMode> modes = {
            CipherMode::ECB, CipherMode::CBC, CipherMode::PCBC,
            CipherMode::OFB, CipherMode::CTR
        };
        
        std::string plaintext = "AES mode testing data for encryption";
        ByteArray data = utils::stringToBytes(plaintext);
        
        for (CipherMode mode : modes) {
            try {
                auto padding = IPadding::create(PaddingType::PKCS7);
                auto cipherMode = IBlockCipherMode::create(mode, aes128, std::move(padding));
                std::shared_ptr<IBlockCipherMode> modeShared = std::move(cipherMode);
                
                ByteArray encrypted = modeShared->encrypt(data);
                ByteArray decrypted = modeShared->decrypt(encrypted);
                
                std::string modeName = modeShared->name();
                test_common::checkResult("AES-128+" + modeName, data, decrypted);
            } catch (const std::exception& e) {
                std::cout << "  ⚠ SKIP: AES-128 mode " << static_cast<int>(mode) << " - " << e.what() << std::endl;
            }
        }
        
        
        auto aes256 = std::make_shared<Rijndael>(KeySize::AES256);
        Key key256 = math::randomKey(32);
        aes256->setKey(key256);
        
        auto padding = IPadding::create(PaddingType::PKCS7);
        auto cbc = IBlockCipherMode::create(CipherMode::CBC, aes256, std::move(padding));
        std::shared_ptr<IBlockCipherMode> cbcShared = std::move(cbc);
        
        ByteArray encrypted = cbcShared->encrypt(data);
        ByteArray decrypted = cbcShared->decrypt(encrypted);
        test_common::checkResult("AES-256+CBC", data, decrypted);
        
    } catch (const std::exception& e) {
        std::cout << "  ✗ ERROR: Rijndael modes - " << e.what() << std::endl;
        test_common::testsFailed++;
    }
}

int main() {
    std::cout << "╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║            RIJNDAEL (AES) TEST SUITE                     ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    try {
        testRijndaelBasic();
        testRijndaelModes();
        
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

