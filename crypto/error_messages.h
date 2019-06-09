#ifndef AES_CPP17_ERROR_MESSAGES_H
#define AES_CPP17_ERROR_MESSAGES_H

#define ENG

#include <string>

namespace doh {

#if defined(ENG)

    /**
     * @brief cipher exception error messages
     */
    static const std::string UNPADDING = " Decryption Failed - Padding Checksum Error! ";
    static const std::string DETERMINISTIC = " Deterministic Random Number Generator! ";

#endif

}

#endif //AES_CPP17_ERROR_MESSAGES_H
