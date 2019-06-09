#ifndef AES_CPP17_CIPHER_EXCEPTION_H
#define AES_CPP17_CIPHER_EXCEPTION_H

#include <stdexcept>

#include "error_messages.h"

namespace doh {

    /**
     * @brief Base crypto exception
     */
    struct cipher_exception: public std::runtime_error {

        using std::runtime_error::runtime_error;

        ~cipher_exception() override = default;

    };

}

#endif //AES_CPP17_CIPHER_EXCEPTION_H
