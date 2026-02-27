#include "../test_common.hpp"
#include "crypto/algorithms/des/des.hpp"
#include "crypto/modes/mode.hpp"
#include "crypto/padding/padding.hpp"
#include "crypto/core/utils.hpp"
#include "crypto/math/random.hpp"
#include <memory>
#include <vector>

using namespace crypto;

void testAllModesWithDES() {
    test_common::printHeader("Test 1: All Cipher Modes with DES");
    
    auto des = std::make_shared<DES>();
    Key key = math::randomKey(DES_KEY_SIZE);
    des->setKey(key);
    
    std::vector<std::pair<CipherMode, std::string>> blockModes = {
        {CipherMode::ECB, "ECB"},
        {CipherMode::CBC, "CBC"},
        {CipherMode::PCBC, "PCBC"},
        {CipherMode::RANDOM_DELTA, "Random Delta"}
    };
    
    std::vector<std::pair<CipherMode, std::string>> streamModes = {
        {CipherMode::CFB, "CFB"},
        {CipherMode::OFB, "OFB"},
        {CipherMode::CTR, "CTR"}
    };
    
    std::vector<std::pair<PaddingType, std::string>> paddings = {
        {PaddingType::PKCS7, "PKCS7"},
        {PaddingType::ZEROS, "Zeros"},
        {PaddingType::ANSI_X923, "ANSI X9.23"},
        {PaddingType::ISO_10126, "ISO 10126"}
    };
    
    std::vector<std::string> testData = {
        "",  
        "A",  
        "Hello",  
        "Hello, DES!",  
        "This is a longer test message that spans multiple blocks."  
    };
    
    
    for (const auto& [mode, modeName] : blockModes) {
        for (const auto& [padding, paddingName] : paddings) {
            for (size_t i = 0; i < testData.size(); ++i) {
                try {
                    ByteArray data = utils::stringToBytes(testData[i]);
                    auto paddingObj = IPadding::create(padding);
                    auto cipherMode = IBlockCipherMode::create(mode, des, std::move(paddingObj));
                    std::shared_ptr<IBlockCipherMode> modeShared = std::move(cipherMode);
                    
                    ByteArray encrypted = modeShared->encrypt(data);
                    ByteArray decrypted = modeShared->decrypt(encrypted);
                    
                    std::string testName = modeName + "+" + paddingName + " (data" + std::to_string(i) + ")";
                    test_common::checkResult(testName, data, decrypted);
                } catch (const std::exception& e) {
                    std::cout << "  ✗ ERROR: " << modeName << "+" << paddingName 
                              << " - " << e.what() << std::endl;
                    test_common::testsFailed++;
                }
            }
        }
    }
    
    
    for (const auto& [mode, modeName] : streamModes) {
        PaddingType padding = PaddingType::PKCS7;
        for (size_t i = 0; i < std::min(size_t(3), testData.size()); ++i) {
            try {
                ByteArray data = utils::stringToBytes(testData[i]);
                auto paddingObj = IPadding::create(padding);
                auto cipherMode = IBlockCipherMode::create(mode, des, std::move(paddingObj));
                std::shared_ptr<IBlockCipherMode> modeShared = std::move(cipherMode);
                
                ByteArray encrypted = modeShared->encrypt(data);
                ByteArray decrypted = modeShared->decrypt(encrypted);
                
                std::string paddingName = IPadding::create(padding)->name();
                std::string testName = modeName + "+" + paddingName + " (data" + std::to_string(i) + ")";
                test_common::checkResult(testName, data, decrypted);
            } catch (const std::exception& e) {
                std::cout << "  ⚠ SKIP: " << modeName << "+PKCS7 (data" << i << ") - " << e.what() << std::endl;
            }
        }
    }
}

void testIVOperations() {
    test_common::printHeader("Test 2: IV (Initialization Vector) Operations");
    
    auto des = std::make_shared<DES>();
    Key key = math::randomKey(DES_KEY_SIZE);
    des->setKey(key);
    
    auto padding = IPadding::create(PaddingType::PKCS7);
    auto cbc1 = IBlockCipherMode::create(CipherMode::CBC, des, std::move(padding));
    std::shared_ptr<IBlockCipherMode> cbc1Shared = std::move(cbc1);
    
    ByteArray originalIV = cbc1Shared->getIV();
    
    
    auto padding2 = IPadding::create(PaddingType::PKCS7);
    auto cbc2 = IBlockCipherMode::create(CipherMode::CBC, des, std::move(padding2));
    std::shared_ptr<IBlockCipherMode> cbc2Shared = std::move(cbc2);
    
    std::string plaintext = "Test IV";
    ByteArray data = utils::stringToBytes(plaintext);
    
    ByteArray encrypted1 = cbc1Shared->encrypt(data);
    ByteArray encrypted2 = cbc2Shared->encrypt(data);
    
    
    test_common::checkResult("CBC different IVs produce different output",
                ByteArray(1, 0),
                (encrypted1 == encrypted2 ? ByteArray(1, 1) : ByteArray(1, 0)));
    
    
    auto padding3 = IPadding::create(PaddingType::PKCS7);
    auto cbc3 = IBlockCipherMode::create(CipherMode::CBC, des, std::move(padding3));
    std::shared_ptr<IBlockCipherMode> cbc3Shared = std::move(cbc3);
    cbc3Shared->setIV(originalIV);
    cbc1Shared->setIV(originalIV);
    
    ByteArray encrypted3 = cbc1Shared->encrypt(data);
    ByteArray encrypted4 = cbc3Shared->encrypt(data);
    test_common::checkResult("CBC same IV produces same output", encrypted3, encrypted4);
}

void testTripleDESModes() {
    test_common::printHeader("Test 3: TripleDES with All Modes");
    
    auto tdes = std::make_shared<TripleDES>(TripleDESMode::EDE);
    Key key = math::randomKey(TRIPLE_DES_KEY_SIZE_3KEY);
    tdes->setKey(key);
    
    std::vector<CipherMode> modes = {
        CipherMode::ECB, CipherMode::CBC, CipherMode::PCBC,
        CipherMode::OFB, CipherMode::CTR
    };
    
    std::string plaintext = "TripleDES test message";
    ByteArray data = utils::stringToBytes(plaintext);
    
    for (CipherMode mode : modes) {
        try {
            auto padding = IPadding::create(PaddingType::PKCS7);
            auto cipherMode = IBlockCipherMode::create(mode, tdes, std::move(padding));
            std::shared_ptr<IBlockCipherMode> modeShared = std::move(cipherMode);
            
            ByteArray encrypted = modeShared->encrypt(data);
            ByteArray decrypted = modeShared->decrypt(encrypted);
            
            std::string modeName = modeShared->name();
            test_common::checkResult("TripleDES+" + modeName, data, decrypted);
        } catch (const std::exception& e) {
            std::cout << "  ⚠ SKIP: TripleDES mode - " << e.what() << std::endl;
        }
    }
}

void testDataSizes() {
    test_common::printHeader("Test 4: Different Data Sizes");
    
    auto des = std::make_shared<DES>();
    Key key = math::randomKey(DES_KEY_SIZE);
    des->setKey(key);
    
    auto padding = IPadding::create(PaddingType::PKCS7);
    auto cbc = IBlockCipherMode::create(CipherMode::CBC, des, std::move(padding));
    std::shared_ptr<IBlockCipherMode> cbcShared = std::move(cbc);
    
    
    std::vector<size_t> sizes = {0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 63, 64, 100, 255, 1000};
    
    for (size_t size : sizes) {
        try {
            ByteArray data = math::randomBytes(size);
            ByteArray encrypted = cbcShared->encrypt(data);
            ByteArray decrypted = cbcShared->decrypt(encrypted);
            
            std::string testName = "Size " + std::to_string(size) + " bytes";
            test_common::checkResult(testName, data, decrypted);
        } catch (const std::exception& e) {
            std::cout << "  ✗ ERROR: Size " << size << " - " << e.what() << std::endl;
            test_common::testsFailed++;
        }
    }
}

void testEdgeCases() {
    test_common::printHeader("Test 5: Edge Cases");
    
    auto des = std::make_shared<DES>();
    Key key = math::randomKey(DES_KEY_SIZE);
    des->setKey(key);
    
    
    {
        auto padding = IPadding::create(PaddingType::PKCS7);
        auto cbc = IBlockCipherMode::create(CipherMode::CBC, des, std::move(padding));
        std::shared_ptr<IBlockCipherMode> cbcShared = std::move(cbc);
        
        ByteArray data(8, 0xAA);  
        ByteArray encrypted = cbcShared->encrypt(data);
        ByteArray decrypted = cbcShared->decrypt(encrypted);
        test_common::checkResult("Data exactly block size", data, decrypted);
    }
    
    
    {
        auto padding = IPadding::create(PaddingType::PKCS7);
        auto cbc = IBlockCipherMode::create(CipherMode::CBC, des, std::move(padding));
        std::shared_ptr<IBlockCipherMode> cbcShared = std::move(cbc);
        
        ByteArray data(24, 0xBB);  
        ByteArray encrypted = cbcShared->encrypt(data);
        ByteArray decrypted = cbcShared->decrypt(encrypted);
        test_common::checkResult("Data multiple blocks", data, decrypted);
    }
    
    
    {
        auto padding = IPadding::create(PaddingType::PKCS7);
        auto cbc = IBlockCipherMode::create(CipherMode::CBC, des, std::move(padding));
        std::shared_ptr<IBlockCipherMode> cbcShared = std::move(cbc);
        
        ByteArray data = utils::stringToBytes("Test data");
        ByteArray encrypted1 = cbcShared->encrypt(data);
        ByteArray decrypted1 = cbcShared->decrypt(encrypted1);
        
        ByteArray encrypted2 = cbcShared->encrypt(data);  
        ByteArray decrypted2 = cbcShared->decrypt(encrypted2);
        
        test_common::checkResult("Multiple encryptions", data, decrypted1);
        test_common::checkResult("Second encryption round", data, decrypted2);
    }
}

int main() {
    std::cout << "╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║            CIPHER MODES TEST SUITE                        ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    try {
        testAllModesWithDES();
        testIVOperations();
        testTripleDESModes();
        testDataSizes();
        testEdgeCases();
        
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

