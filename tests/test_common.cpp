#include "test_common.hpp"

namespace test_common {

int testsPassed = 0;
int testsFailed = 0;

bool checkResult(const std::string& testName, const crypto::ByteArray& original, const crypto::ByteArray& decrypted) {
    bool success = (original == decrypted);
    if (success) {
        std::cout << "  ✓ PASS: " << testName << std::endl;
        testsPassed++;
    } else {
        std::cout << "  ✗ FAIL: " << testName << std::endl;
        testsFailed++;
    }
    return success;
}

void printHeader(const std::string& testName) {
    std::cout << "\n=== " << testName << " ===" << std::endl;
}

void printSummary() {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║                    TEST RESULTS SUMMARY                    ║" << std::endl;
    std::cout << "╠════════════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║  Tests Passed: " << std::right << std::setfill(' ') << std::setw(43) << testsPassed << " ║" << std::endl;
    std::cout << "║  Tests Failed: " << std::right << std::setfill(' ') << std::setw(43) << testsFailed << " ║" << std::endl;
    std::cout << "║  Total Tests:  " << std::right << std::setfill(' ') << std::setw(43) << (testsPassed + testsFailed) << " ║" << std::endl;
    std::cout << "║  Success Rate: " << std::right << std::setfill(' ') << std::setw(42) << std::fixed << std::setprecision(2)
              << (testsPassed + testsFailed > 0 ? 
                  100.0 * testsPassed / (testsPassed + testsFailed) : 0.0) << "% ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
}

} 

