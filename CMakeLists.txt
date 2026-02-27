# crypto_coursework/CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(CryptoCoursework VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

#
# Основная библиотека со всеми реализациями из src/
#
add_library(crypto_coursework STATIC
    # Core
    src/core/types.cpp
    src/core/utils.cpp
    src/core/exceptions.cpp
    src/core/endianness.cpp

    # Паддинги
    src/padding/pkcs7.cpp
    src/padding/zeros.cpp
    src/padding/ansix923.cpp
    src/padding/iso10126.cpp

    # Режимы шифрования
    src/modes/ecb.cpp
    src/modes/cbc.cpp
    src/modes/cfb.cpp
    src/modes/ofb.cpp
    src/modes/ctr.cpp
    src/modes/pcbc.cpp
    src/modes/random_delta.cpp
    src/modes/mode_factory.cpp
    src/modes/asymmetric_cipher_mode.cpp

    # Алгоритмы DES/DEAL
    src/algorithms/des/des.cpp
    src/algorithms/des/triple_des.cpp
    src/algorithms/deal/deal.cpp

    # Алгоритмы Rijndael / AES
    src/algorithms/rijndael/aes_constants.cpp
    src/algorithms/rijndael/galois_field.cpp
    src/algorithms/rijndael/polynomials.cpp
    src/algorithms/rijndael/rijndael.cpp

    # Алгоритмы RSA / математика больших чисел
    src/algorithms/rsa/big_integer.cpp
    src/algorithms/rsa/rsa_keygen.cpp
    src/algorithms/rsa/rsa.cpp
    src/algorithms/rsa/wiener_attack.cpp

    # Математические утилиты
    src/math/continued_fraction.cpp
    src/math/modinv.cpp
    src/math/prime.cpp
    src/math/random.cpp

    # IO
    src/io/async_processor.cpp
    src/io/file_encryptor.cpp

    # Manager
    src/crypto_manager.cpp
)

target_include_directories(crypto_coursework PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

#
# Примеры
#
add_executable(crypto_demo examples/demo_cli.cpp)
target_link_libraries(crypto_demo PRIVATE crypto_coursework)

# Опциональные примеры (закомментированы, если файлы не существуют)
# add_executable(crypto_benchmark examples/benchmark.cpp)
# target_link_libraries(crypto_benchmark PRIVATE crypto_coursework)

# add_executable(crypto_simple_encrypt examples/simple_encrypt.cpp)
# target_link_libraries(crypto_simple_encrypt PRIVATE crypto_coursework)

# Тесты
enable_testing()

# Общий модуль для тестов
add_library(test_common STATIC
    tests/test_common.cpp
)
target_include_directories(test_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/tests
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Unit тесты
add_executable(test_des tests/unit_tests/test_des.cpp)
target_link_libraries(test_des crypto_coursework test_common)
add_test(NAME test_des COMMAND test_des)

add_executable(test_deal tests/unit_tests/test_deal.cpp)
target_link_libraries(test_deal crypto_coursework test_common)
add_test(NAME test_deal COMMAND test_deal)

add_executable(test_aes tests/unit_tests/test_aes.cpp)
target_link_libraries(test_aes crypto_coursework test_common)
add_test(NAME test_aes COMMAND test_aes)

add_executable(test_modes tests/unit_tests/test_modes.cpp)
target_link_libraries(test_modes crypto_coursework test_common)
add_test(NAME test_modes COMMAND test_modes)

add_executable(test_padding tests/unit_tests/test_padding.cpp)
target_link_libraries(test_padding crypto_coursework test_common)
add_test(NAME test_padding COMMAND test_padding)

add_executable(test_rsa tests/unit_tests/test_rsa.cpp)
target_link_libraries(test_rsa crypto_coursework test_common)
add_test(NAME test_rsa COMMAND test_rsa)

add_executable(test_crypto_manager tests/unit_tests/test_crypto_manager.cpp)
target_link_libraries(test_crypto_manager crypto_coursework test_common)
add_test(NAME test_crypto_manager COMMAND test_crypto_manager)

# Интеграционные тесты
add_executable(test_file_encryption tests/integration_tests/test_file_encryption.cpp)
target_link_libraries(test_file_encryption crypto_coursework test_common)
add_test(NAME test_file_encryption COMMAND test_file_encryption)