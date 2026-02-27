#include "../test_common.hpp"
#include "crypto/padding/padding.hpp"
#include "crypto/core/utils.hpp"
#include <vector>

using namespace crypto;

void testAllPaddings() {
    test_common::printHeader("Test 1: All Padding Types");
    
    std::vector<std::pair<PaddingType, std::string>> paddings = {
        {PaddingType::PKCS7, "PKCS7"},
        {PaddingType::ZEROS, "Zeros"},
        {PaddingType::ANSI_X923, "ANSI X9.23"},
        {PaddingType::ISO_10126, "ISO 10126"}
    };
    
    
    std::vector<ByteArray> testData = {
        {},  
        {0x41},  
        {0x41, 0x42, 0x43},  
        {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47},  
        utils::stringToBytes("Exactly 8 bytes!"),  
        utils::stringToBytes("This is 16 bytes!!")  
    };
    
    for (const auto& [paddingType, paddingName] : paddings) {
        auto padding = IPadding::create(paddingType);
        
        for (size_t i = 0; i < testData.size(); ++i) {
            try {
                ByteArray padded = padding->pad(testData[i], DES_BLOCK_SIZE);
                ByteArray unpadded = padding->unpad(padded);
                
                std::string testName = paddingName + " pad/unpad (size " + std::to_string(testData[i].size()) + ")";
                test_common::checkResult(testName, testData[i], unpadded);
            } catch (const std::exception& e) {
                std::cout << "  ✗ ERROR: " << paddingName << " size " << testData[i].size() 
                          << " - " << e.what() << std::endl;
                test_common::testsFailed++;
            }
        }
    }
}

void testPaddingValidation() {
    test_common::printHeader("Test 2: Padding Validation");
    
    auto pkcs7 = IPadding::create(PaddingType::PKCS7);
    
    
    {
        ByteArray data = {0x41, 0x42, 0x43};
        ByteArray padded = pkcs7->pad(data, 8);
        bool isValid = pkcs7->validate(padded);
        test_common::checkResult("PKCS7 valid padding",
                    ByteArray(1, isValid ? 1 : 0),
                    ByteArray(1, 1));
    }
    
    
    {
        ByteArray data = {0x41, 0x42, 0x43};
        ByteArray padded = pkcs7->pad(data, 8);
        if (!padded.empty()) {
            padded[padded.size() - 1] = 0x00;  
            bool isValid = pkcs7->validate(padded);
            test_common::checkResult("PKCS7 invalid padding detection",
                        ByteArray(1, isValid ? 0 : 1),
                        ByteArray(1, 1));
        }
    }
}

void testPaddingEdgeCases() {
    test_common::printHeader("Test 3: Padding Edge Cases");
    
    auto pkcs7 = IPadding::create(PaddingType::PKCS7);
    
    
    {
        ByteArray data(8, 0xAA);  
        ByteArray padded = pkcs7->pad(data, 8);
        ByteArray unpadded = pkcs7->unpad(padded);
        test_common::checkResult("PKCS7 data already block size", data, unpadded);
    }
    
    
    {
        ByteArray data;
        ByteArray padded = pkcs7->pad(data, 8);
        ByteArray unpadded = pkcs7->unpad(padded);
        test_common::checkResult("PKCS7 empty data", data, unpadded);
    }
    
    
    {
        ByteArray data(1, 0x41);  
        ByteArray padded = pkcs7->pad(data, 8);
        if (padded.size() == 8 && padded.back() == 7) {
            std::cout << "  ✓ PASS: PKCS7 maximum padding size" << std::endl;
            test_common::testsPassed++;
        } else {
            std::cout << "  ✗ FAIL: PKCS7 maximum padding size" << std::endl;
            test_common::testsFailed++;
        }
    }
}

int main() {
    std::cout << "╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║              PADDING TEST SUITE                          ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    try {
        testAllPaddings();
        testPaddingValidation();
        testPaddingEdgeCases();
        
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

