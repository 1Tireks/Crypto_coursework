#pragma once

#include <crypto.hpp>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

namespace test_common {

extern int testsPassed;
extern int testsFailed;

bool checkResult(const std::string& testName, const crypto::ByteArray& original, const crypto::ByteArray& decrypted);

void printHeader(const std::string& testName);
void printSummary();

} 

