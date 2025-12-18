# Changelog - Исправления проекта

## Выполненные исправления

### 1. ✅ Перенос функций генерации случайных чисел в `random.hpp`

**Изменения:**
- Создан файл `include/crypto/math/random.hpp` с функциями `randomBytes()` и `randomKey()`
- Создан файл `src/math/random.cpp` с реализацией
- Функции перенесены из `src/core/utils.cpp` в `src/math/random.cpp`
- Добавлена обратная совместимость через `using` в `utils.hpp`

**Файлы:**
- `include/crypto/math/random.hpp` (новый)
- `src/math/random.cpp` (новый)
- `include/crypto/core/utils.hpp` (обновлен)
- `src/core/utils.cpp` (обновлен)

---

### 2. ✅ Реализация async file encryption для RC4

**Проблема:** RC4 (потоковый шифр) не мог использоваться с `AsyncFileEncryptor`

**Решение:** Создан адаптер `StreamCipherMode`, который оборачивает `IStreamCipher` в интерфейс `IBlockCipherMode`

**Использование:**
```cpp
#include "crypto/algorithms/rc4/rc4.hpp"
#include "crypto/modes/stream_cipher_mode.hpp"
#include "crypto/io/file_encryptor.hpp"

auto rc4 = std::make_shared<RC4>();
rc4->setKey(key);

auto mode = std::make_shared<StreamCipherMode>(rc4);
AsyncFileEncryptor encryptor(mode);
auto future = encryptor.encryptFileAsync("input.txt", "output.enc");
```

**Файлы:**
- `include/crypto/modes/stream_cipher_mode.hpp` (новый)
- `src/modes/stream_cipher_mode.cpp` (новый)

---

### 3. ✅ Реализация async file encryption для RSA

**Проблема:** RSA (асимметричный шифр) не мог использоваться с `AsyncFileEncryptor`

**Решение:** Создан адаптер `AsymmetricCipherMode`, который оборачивает `IAsymmetricCipher` в интерфейс `IBlockCipherMode`

**Использование:**
```cpp
#include "crypto/algorithms/rsa/rsa.hpp"
#include "crypto/modes/asymmetric_cipher_mode.hpp"
#include "crypto/io/file_encryptor.hpp"

auto rsa = std::make_shared<rsa::RSA>(key);
auto mode = std::make_shared<AsymmetricCipherMode>(rsa);
AsyncFileEncryptor encryptor(mode);
auto future = encryptor.encryptFileAsync("input.txt", "output.enc");
```

**Файлы:**
- `include/crypto/modes/asymmetric_cipher_mode.hpp` (новый)
- `src/modes/asymmetric_cipher_mode.cpp` (новый)

---

### 4. ✅ Добавлена поддержка всех неприводимых полиномов в Rijndael

**Проблема:** Rijndael использовал только один неприводимый полином (0x11B)

**Решение:** 
- Добавлен список всех 30 неприводимых полиномов степени 8 над GF(2)
- Класс `GaloisField` теперь параметризуется полиномом
- Класс `Rijndael` поддерживает выбор полинома в конструкторе
- Сохранена обратная совместимость через глобальные функции

**Использование:**
```cpp
#include "crypto/algorithms/rijndael/rijndael.hpp"

// Использование полинома по умолчанию (0x11B - AES стандарт)
Rijndael aes1(KeySize::AES128);

// Использование другого полинома
uint16_t poly = IrreduciblePolynomials::ALL_POLYNOMIALS[1]; // 0x11D
Rijndael aes2(KeySize::AES128, BlockSize::AES128_BLOCK, poly);

// Получить список всех полиномов
for (auto poly : IrreduciblePolynomials::ALL_POLYNOMIALS) {
    // ...
}
```

**Файлы:**
- `include/crypto/algorithms/rijndael/galois_field.hpp` (обновлен)
- `src/algorithms/rijndael/galois_field.cpp` (обновлен)
- `include/crypto/algorithms/rijndael/rijndael.hpp` (обновлен)
- `src/algorithms/rijndael/rijndael.cpp` (обновлен)
- `src/algorithms/rijndael/aes_constants.cpp` (обновлен)
- `src/algorithms/rijndael/polynomials.cpp` (обновлен)

---

### 5. ✅ Обновлен CMakeLists.txt

**Изменения:**
- Добавлен `src/math/random.cpp`
- Добавлен `src/modes/stream_cipher_mode.cpp`
- Добавлен `src/modes/asymmetric_cipher_mode.cpp`

---

## Статус требований

### ✅ Полностью выполнено:
1. DES, TripleDES, DEAL - все режимы и паддинги
2. RSA - алгоритм, генератор ключей, атака Винера, защита
3. Rijndael - все размеры блоков/ключей, **все неприводимые полиномы**
4. Diffie-Hellman - протокол и распределение ключей
5. **RC4 - async file encryption** ✅
6. Serpent - все режимы и паддинги
7. **RSA - async file encryption** ✅

### Все режимы шифрования:
- ✅ ECB, CBC, PCBC, CFB, OFB, CTR, Random Delta

### Все режимы паддинга:
- ✅ Zeros, ANSI X9.23, PKCS7, ISO 10126

### Async/Multithreaded file encryption:
- ✅ Для всех блочных шифров (DES, TripleDES, DEAL, Rijndael, Serpent)
- ✅ Для RC4 (через StreamCipherMode)
- ✅ Для RSA (через AsymmetricCipherMode)

---

## Обратная совместимость

Все изменения сохраняют обратную совместимость:
- `utils::randomBytes()` и `utils::randomKey()` работают как раньше
- Старый код с Rijndael продолжает работать (использует полином по умолчанию)
- Все существующие тесты должны работать без изменений

---

## Тестирование

Рекомендуется добавить тесты для:
1. RC4 async file encryption
2. RSA async file encryption
3. Различных неприводимых полиномов в Rijndael

