#pragma once

// Core - Основные типы и утилиты
#include "crypto/core/types.hpp"          
#include "crypto/core/exceptions.hpp"     
#include "crypto/core/utils.hpp"          
#include "crypto/core/endianness.hpp"     

// Ciphers - Интерфейсы шифров
#include "crypto/ciphers/cipher.hpp"      
#include "crypto/ciphers/block_cipher.hpp"
#include "crypto/ciphers/stream_cipher.hpp"
#include "crypto/ciphers/asymmetric_cipher.hpp"

// Algorithms - Блочные шифры
#include "crypto/algorithms/des/des.hpp"           
#include "crypto/algorithms/des/triple_des.hpp"    
#include "crypto/algorithms/deal/deal.hpp"         

// Padding - Схемы дополнения
#include "crypto/padding/padding.hpp"

// Modes - Режимы шифрования
#include "crypto/modes/mode.hpp"
#include "crypto/modes/ecb.hpp"           
#include "crypto/modes/cbc.hpp"           
#include "crypto/modes/pcbc.hpp"          
#include "crypto/modes/cfb.hpp"           
#include "crypto/modes/ofb.hpp"           
#include "crypto/modes/ctr.hpp"           
#include "crypto/modes/random_delta.hpp"  

// IO - Работа с файлами
#include "crypto/io/file_encryptor.hpp"   
#include "crypto/io/async_processor.hpp"  

// Manager - Высокоуровневый API
#include "crypto/crypto_manager.hpp"

// Версия библиотеки
#define CRYPTO_COURSEWORK_VERSION_MAJOR 1
#define CRYPTO_COURSEWORK_VERSION_MINOR 0
#define CRYPTO_COURSEWORK_VERSION_PATCH 0

#define CRYPTO_COURSEWORK_VERSION \
    (CRYPTO_COURSEWORK_VERSION_MAJOR * 10000 + \
     CRYPTO_COURSEWORK_VERSION_MINOR * 100 + \
     CRYPTO_COURSEWORK_VERSION_PATCH)
