#include "../test_common.hpp"
#include <iostream>
#include <cstdlib>
#include <string>

int main() {
    std::cout << "╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║     COMPREHENSIVE CRYPTOGRAPHY LIBRARY TEST SUITE         ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << "\nThis is a helper script. Run individual test executables:" << std::endl;
    std::cout << "  - test_des" << std::endl;
    std::cout << "  - test_deal" << std::endl;
    std::cout << "  - test_aes" << std::endl;
    std::cout << "  - test_modes" << std::endl;
    std::cout << "  - test_padding" << std::endl;
    std::cout << "  - test_rsa" << std::endl;
    std::cout << "  - test_crypto_manager" << std::endl;
    std::cout << "  - test_file_encryption" << std::endl;
    std::cout << "\nOr use CTest: ctest" << std::endl;
    return 0;
}

