#include "../../include/crypto/modes/mode.hpp"
#include "../../include/crypto/modes/ecb.hpp"
#include "../../include/crypto/modes/cbc.hpp"
#include "../../include/crypto/modes/pcbc.hpp"
#include "../../include/crypto/modes/cfb.hpp"
#include "../../include/crypto/modes/ofb.hpp"
#include "../../include/crypto/modes/ctr.hpp"
#include "../../include/crypto/modes/random_delta.hpp"
#include <memory>

namespace crypto {

std::unique_ptr<IBlockCipherMode> IBlockCipherMode::create(
    CipherMode mode,
    std::shared_ptr<IBlockCipher> cipher,
    std::unique_ptr<IPadding> padding,
    const ByteArray& iv) {
    
    std::unique_ptr<IBlockCipherMode> modeObj;
    
    switch (mode) {
        case CipherMode::ECB:
            modeObj = std::make_unique<ECBMode>(cipher, std::move(padding));
            break;
        case CipherMode::CBC:
            modeObj = std::make_unique<CBCMode>(cipher, std::move(padding));
            break;
        case CipherMode::PCBC:
            modeObj = std::make_unique<PCBCMode>(cipher, std::move(padding));
            break;
        case CipherMode::CFB:
            modeObj = std::make_unique<CFBMode>(cipher, std::move(padding));
            break;
        case CipherMode::OFB:
            modeObj = std::make_unique<OFBMode>(cipher, std::move(padding));
            break;
        case CipherMode::CTR:
            modeObj = std::make_unique<CTRMode>(cipher, std::move(padding));
            break;
        case CipherMode::RANDOM_DELTA:
            modeObj = std::make_unique<RandomDeltaMode>(cipher, std::move(padding));
            break;
        default:
            throw CryptoException("Unsupported cipher mode");
    }
    
    if (!iv.empty()) {
        modeObj->setIV(iv);
    }
    
    return modeObj;
}

}