#ifndef AES_CPP17_BLOCK_CIPHER_CONSTANTS_H
#define AES_CPP17_BLOCK_CIPHER_CONSTANTS_H

#include <cstddef>

namespace crypto {

    /**
     * 128-bit block size.
     * Until the announcement of NIST's AES contest, the majority of block ciphers followed the example of the DES in using a block size of 64 bits (8 bytes).
     * However, the birthday paradox tells us that after accumulating a number of blocks equal to the square root of the total number possible,
     * there will be an approximately 50% chance of two or more being the same, which would start to leak information about the message contents.
     * Consequently, AES candidates were required to support a block length of 128 bits (16 bytes).
     * This should be acceptable for up to 2^64 × 16 B = 256 exabytes of data - which should suffice for quite a few years to come.
     * The winner of the AES contest, Rijstddef.h>ndael, supports block and key sizes of 128, 192, and 256 bits, but in AES the block size is always 128 bits.
     */
    constexpr static size_t BLOCK_SIZE = 16;

    constexpr static size_t BYTES_PER_BLOCK = BLOCK_SIZE * 8;

    constexpr static size_t WORD_SIZE = 4; //bytes

    /**
     * Nonce size (bytes)
     * @warning An 8 byte nonce is not secure as a general recommendation.
     * @note CCM (which uses CTR), RFC5084/CMS recommends 12 bytes for the nonce.
     */
    constexpr static size_t NONCE_SIZE = 12;

#ifdef _MSC_VER

    constexpr static size_t bit_RDRAND = 0x40000000; // bit 30 EBX set if RDSEED instruction implemented

    constexpr static size_t bit_RDSEED = 0x00040000; // bit 18 EBX set if RDSEED instruction implemented

#endif

}


#endif //AES_CPP17_BLOCK_CIPHER_CONSTANTS_H
