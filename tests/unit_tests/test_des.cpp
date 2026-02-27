#include "../test_common.hpp"
#include "crypto/algorithms/des/des.hpp"
#include "crypto/algorithms/des/triple_des.hpp"
#include "crypto/core/utils.hpp"
#include "crypto/math/random.hpp"
#include <memory>

using namespace crypto;

void testDESBasic() {
    test_common::printHeader("Test 1: DES Basic Operations");
    
    auto des = std::make_shared<DES>();
    Key key = math::randomKey(DES_KEY_SIZE);
    des->setKey(key);
    
    
    std::string plaintext1 = "Hello, D";
    ByteArray data1 = utils::stringToBytes(plaintext1);
    ByteArray encrypted1(8), decrypted1(8);
    des->encryptBlock(data1.data(), encrypted1.data());
    des->decryptBlock(encrypted1.data(), decrypted1.data());
    test_common::checkResult("DES single block", data1, decrypted1);
    
    
    Key key2 = math::randomKey(DES_KEY_SIZE);
    des->setKey(key2);
    ByteArray encrypted2(8);
    des->encryptBlock(data1.data(), encrypted2.data());
    test_common::checkResult("DES different keys produce different output", 
                ByteArray(1, 0), 
                (encrypted1 == encrypted2 ? ByteArray(1, 1) : ByteArray(1, 0)));
    
    
    des->setKey(key);
    ByteArray encrypted3(8);
    des->encryptBlock(data1.data(), encrypted3.data());
    test_common::checkResult("DES deterministic encryption", encrypted1, encrypted3);
}

void testTripleDESBasic() {
    test_common::printHeader("Test 2: TripleDES Basic Operations");
    
    auto tdes = std::make_shared<TripleDES>(TripleDESMode::EDE);
    
    
    Key key3 = math::randomKey(TRIPLE_DES_KEY_SIZE_3KEY);
    tdes->setKey(key3);
    std::string plaintext = "TripleDES";
    ByteArray data = utils::stringToBytes(plaintext);
    data.resize(8);
    
    ByteArray encrypted(8), decrypted(8);
    tdes->encryptBlock(data.data(), encrypted.data());
    tdes->decryptBlock(encrypted.data(), decrypted.data());
    test_common::checkResult("TripleDES-3KEY block encryption", data, decrypted);
    
    
    Key key2 = math::randomKey(TRIPLE_DES_KEY_SIZE_2KEY);
    tdes->setKey(key2);
    ByteArray encrypted2(8), decrypted2(8);
    tdes->encryptBlock(data.data(), encrypted2.data());
    tdes->decryptBlock(encrypted2.data(), decrypted2.data());
    test_common::checkResult("TripleDES-2KEY block encryption", data, decrypted2);
    
    
    auto tdesEEE = std::make_shared<TripleDES>(TripleDESMode::EEE);
    tdesEEE->setKey(key3);
    ByteArray encrypted3(8), decrypted3(8);
    tdesEEE->encryptBlock(data.data(), encrypted3.data());
    tdesEEE->decryptBlock(encrypted3.data(), decrypted3.data());
    test_common::checkResult("TripleDES-EEE block encryption", data, decrypted3);
}

int main() {
    std::cout << "╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║              DES & TripleDES TEST SUITE                  ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    try {
        testDESBasic();
        testTripleDESBasic();
        
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

