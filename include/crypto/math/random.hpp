// include/crypto/math/random.hpp
#pragma once
#include "../core/types.hpp"
#include <cstddef>

namespace crypto {
namespace math {

/**
 * Генерирует массив случайных байтов
 * @param count Количество байтов для генерации
 * @return Массив случайных байтов
 */
ByteArray randomBytes(size_t count);

/**
 * Генерирует случайный ключ заданного размера
 * @param size Размер ключа в байтах
 * @return Случайный ключ
 */
Key randomKey(size_t size);

} // namespace math
} // namespace crypto

