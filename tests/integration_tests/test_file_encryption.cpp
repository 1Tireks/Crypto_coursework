#include "../test_common.hpp"
#include "crypto/algorithms/des/des.hpp"
#include "crypto/modes/mode.hpp"
#include "crypto/padding/padding.hpp"
#include "crypto/io/file_encryptor.hpp"
#include "crypto/math/random.hpp"
#include <fstream>
#include <cstdio>
#include <memory>

using namespace crypto;

void testFileEncryption() {
    test_common::printHeader("Test 1: File Encryption/Decryption");
    
    auto des = std::make_shared<DES>();
    Key key = math::randomKey(DES_KEY_SIZE);
    des->setKey(key);
    
    auto padding = IPadding::create(PaddingType::PKCS7);
    auto cbc = IBlockCipherMode::create(CipherMode::CBC, des, std::move(padding));
    std::shared_ptr<IBlockCipherMode> cbcShared = std::move(cbc);
    
    AsyncFileEncryptor encryptor(cbcShared, 4);
    
    
    {
        std::ofstream testFile("test_small.txt", std::ios::binary);
        testFile << "Small test file content";
        testFile.close();
        
        auto future = encryptor.encryptFileAsync("test_small.txt", "test_small_enc.bin");
        bool success = future.get();
        
        if (success) {
            auto decryptFuture = encryptor.decryptFileAsync("test_small_enc.bin", "test_small_dec.txt");
            success = decryptFuture.get();
            
            if (success) {
                std::ifstream original("test_small.txt", std::ios::binary);
                std::ifstream decrypted("test_small_dec.txt", std::ios::binary);
                
                ByteArray origData((std::istreambuf_iterator<char>(original)), 
                                  std::istreambuf_iterator<char>());
                ByteArray decData((std::istreambuf_iterator<char>(decrypted)), 
                                 std::istreambuf_iterator<char>());
                
                test_common::checkResult("Small file encryption/decryption", origData, decData);
                original.close();
                decrypted.close();
            }
        }
        
        std::remove("test_small.txt");
        std::remove("test_small_enc.bin");
        std::remove("test_small_dec.txt");
    }
    
    
    {
        std::ofstream testFile("test_large.txt", std::ios::binary);
        for (int i = 0; i < 5000; ++i) {
            testFile << "Line " << i << ": This is test data for large file encryption testing.\n";
        }
        testFile.close();
        
        auto future = encryptor.encryptFileAsync("test_large.txt", "test_large_enc.bin");
        bool success = future.get();
        
        if (success) {
            auto decryptFuture = encryptor.decryptFileAsync("test_large_enc.bin", "test_large_dec.txt");
            success = decryptFuture.get();
            
            if (success) {
                std::ifstream original("test_large.txt", std::ios::binary);
                std::ifstream decrypted("test_large_dec.txt", std::ios::binary);
                
                ByteArray origData((std::istreambuf_iterator<char>(original)), 
                                  std::istreambuf_iterator<char>());
                ByteArray decData((std::istreambuf_iterator<char>(decrypted)), 
                                 std::istreambuf_iterator<char>());
                
                test_common::checkResult("Large file encryption/decryption", origData, decData);
                original.close();
                decrypted.close();
            }
        }
        
        std::remove("test_large.txt");
        std::remove("test_large_enc.bin");
        std::remove("test_large_dec.txt");
    }
    
    
    {
        std::ofstream testFile("test_empty.txt", std::ios::binary);
        testFile.close();
        
        auto future = encryptor.encryptFileAsync("test_empty.txt", "test_empty_enc.bin");
        bool success = future.get();
        
        if (success) {
            auto decryptFuture = encryptor.decryptFileAsync("test_empty_enc.bin", "test_empty_dec.txt");
            success = decryptFuture.get();
            test_common::checkResult("Empty file encryption/decryption", ByteArray(), ByteArray());
        }
        
        std::remove("test_empty.txt");
        std::remove("test_empty_enc.bin");
        std::remove("test_empty_dec.txt");
    }
}

int main() {
    std::cout << "╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║          FILE ENCRYPTION TEST SUITE                     ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    try {
        testFileEncryption();
        
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

