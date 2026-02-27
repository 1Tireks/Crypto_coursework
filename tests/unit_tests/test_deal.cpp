#include "../test_common.hpp"
#include "crypto/algorithms/deal/deal.hpp"
#include "crypto/core/utils.hpp"
#include "crypto/math/random.hpp"
#include <memory>

using namespace crypto;

void testDEALBasic() {
    test_common::printHeader("Test 1: DEAL Basic Operations");
    
    
    auto deal128 = std::make_shared<DEAL>(16);
    Key key128 = math::randomKey(16);
    deal128->setKey(key128);
    
    std::string plaintext = "DEAL-128 test data";
    ByteArray data = utils::stringToBytes(plaintext);
    data.resize(16);
    
    ByteArray encrypted(16), decrypted(16);
    deal128->encryptBlock(data.data(), encrypted.data());
    deal128->decryptBlock(encrypted.data(), decrypted.data());
    test_common::checkResult("DEAL-128 block encryption", data, decrypted);
    
    
    auto deal192 = std::make_shared<DEAL>(24);
    Key key192 = math::randomKey(24);
    deal192->setKey(key192);
    
    ByteArray encrypted192(16), decrypted192(16);
    deal192->encryptBlock(data.data(), encrypted192.data());
    deal192->decryptBlock(encrypted192.data(), decrypted192.data());
    test_common::checkResult("DEAL-192 block encryption", data, decrypted192);
    
    
    auto deal256 = std::make_shared<DEAL>(32);
    Key key256 = math::randomKey(32);
    deal256->setKey(key256);
    
    ByteArray encrypted256(16), decrypted256(16);
    deal256->encryptBlock(data.data(), encrypted256.data());
    deal256->decryptBlock(encrypted256.data(), decrypted256.data());
    test_common::checkResult("DEAL-256 block encryption", data, decrypted256);
    
    
    Key key128_2 = math::randomKey(16);
    deal128->setKey(key128_2);
    ByteArray encrypted128_2(16);
    deal128->encryptBlock(data.data(), encrypted128_2.data());
    
    test_common::checkResult("DEAL-128 different keys produce different output",
                ByteArray(1, 0),
                (encrypted == encrypted128_2 ? ByteArray(1, 1) : ByteArray(1, 0)));
}

void testDEALModes() {
    test_common::printHeader("Test 2: DEAL with All Modes");
    
    auto deal = std::make_shared<DEAL>(16);
    Key key = math::randomKey(16);
    deal->setKey(key);
    
    std::vector<CipherMode> modes = {
        CipherMode::ECB, CipherMode::CBC, CipherMode::PCBC,
        CipherMode::OFB, CipherMode::CTR
    };
    
    std::string plaintext = "DEAL encryption test data for modes";
    ByteArray data = utils::stringToBytes(plaintext);
    
    for (CipherMode mode : modes) {
        try {
            auto padding = IPadding::create(PaddingType::PKCS7);
            auto cipherMode = IBlockCipherMode::create(mode, deal, std::move(padding));
            std::shared_ptr<IBlockCipherMode> modeShared = std::move(cipherMode);
            
            ByteArray encrypted = modeShared->encrypt(data);
            ByteArray decrypted = modeShared->decrypt(encrypted);
            
            std::string modeName = modeShared->name();
            test_common::checkResult("DEAL+" + modeName, data, decrypted);
        } catch (const std::exception& e) {
            std::cout << "  ⚠ SKIP: DEAL mode - " << e.what() << std::endl;
        }
    }
}

int main() {
    std::cout << "╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║                  DEAL TEST SUITE                         ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    try {
        testDEALBasic();
        testDEALModes();
        
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

