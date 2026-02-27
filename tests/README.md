# Тесты криптографической библиотеки

## Структура тестов

Тесты разделены на модульные (unit tests) и интеграционные (integration tests):

### Unit тесты
- `test_des.cpp` - тесты для DES и TripleDES
- `test_deal.cpp` - тесты для DEAL
- `test_aes.cpp` - тесты для Rijndael/AES
- `test_modes.cpp` - тесты для режимов шифрования
- `test_padding.cpp` - тесты для схем дополнения
- `test_rsa.cpp` - тесты для RSA
- `test_crypto_manager.cpp` - тесты для CryptoManager

### Integration тесты
- `test_file_encryption.cpp` - тесты файлового шифрования

## Запуск тестов

### Через CMake/CTest
```bash
cd build
cmake ..
make
ctest
```

### Запуск отдельных тестов
```bash
./test_des
./test_deal
./test_aes
./test_modes
./test_padding
./test_rsa
./test_crypto_manager
./test_file_encryption
```

## Формат вывода

Все тесты используют единый формат вывода с табличкой результатов:
- ✓ PASS - тест пройден
- ✗ FAIL - тест провален
- ⚠ SKIP - тест пропущен (обычно из-за ограничений или медленной работы)

В конце каждого теста выводится таблица с итоговой статистикой:
- Количество пройденных тестов
- Количество проваленных тестов
- Общее количество тестов
- Процент успешности

