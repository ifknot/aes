#ifndef AES_CPP17_NONCE_FACTORY_H
#define AES_CPP17_NONCE_FACTORY_H

#include <cstdint>
#include <random>
#include <array>

//#define NDEBUG
//#define __RDSEED__

#if defined(_MSC_VER)
/* Microsoft C/C++-compatible compiler */
     #include <intrin.h>
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
/* GCC-compatible compiler, targeting x86/x86-64 */
#include <x86intrin.h>
#include <cpuid.h>
#elif defined(__GNUC__) && defined(__ARM_NEON__)
/* GCC-compatible compiler, targeting ARM with NEON */
     #include <arm_neon.h>
#elif defined(__GNUC__) && defined(__IWMMXT__)
     /* GCC-compatible compiler, targeting ARM with WMMX */
     #include <mmintrin.h>
#elif (defined(__GNUC__) || defined(__xlC__)) && (defined(__VEC__) || defined(__ALTIVEC__))
     /* XLC or GCC-compatible compiler, targeting PowerPC with VMX/VSX */
     #include <altivec.h>
#elif defined(__GNUC__) && defined(__SPE__)
     /* GCC-compatible compiler, targeting PowerPC with SPE */
     #include <spe.h>
#endif

#include "block_cipher_constants.h"
#include "cipher_exception.h"

namespace crypto {

#ifdef _MSC_VER  // Use MSVC __cpuid
    /**
     * @brief test if can use HRNG intrinsic RDRAND
     * Use the MSVC compiler intrinsic to call the processor supplementary instruction to discover CPU functionality
     * Specifically the extended feature flags in EBX, ECX, and EDX
     * @return bool true = HRNG can RDRAND
     */
    bool can_rdrand() {
            int regs[4];
            __cpuid(regs, 1);
            return regs[1] & bit_RDRAND;
        }

    /**
     * @brief test if can use HRNG intrinsic RDSEED
     * @note RDSEED is slower but offers greater entropy
     * Use the MSVC compiler intrinsic to call the processor supplementary instruction to discover CPU functionality
     * Specifically the extended feature flags in EBX, ECX, and EDX
     * @return bool true = HRNG can RDSEED
     */
    bool can_rdseed() {
        int regs[4];
        __cpuid(regs, 7);
        return regs[1] & bit_RDSEED;
    }
#else // Use GNU C cpuid.h
#include <cpuid.h>
    /**
     * @brief test ig can use HRNG intrinsic RDRAND
     * Use the GNU (et al) compiler intrinsic to call the processor supplementary instruction to discover CPU functionality
     * Specifically the extended feature flags in EBX, ECX, and EDX
     * @return bool true = HRNG can RDRAND
     */
    bool can_rdrand() {
        unsigned int regs[4]{};
        __get_cpuid (1, &regs[0], &regs[1], &regs[2], &regs[3]);
        return regs[2] & bit_RDRND; //bit_RDRAND predefined in GNU et al
    }

    /**
     * @brief test ig can use HRNG intrinsic RDRAND
     * Use the GNU (et al) compiler intrinsic to call the processor supplementary instruction to discover CPU functionality
     * Specifically the extended feature flags in EBX, ECX, and EDX
     * @return bool true = HRNG can RDSEED
     */
    bool can_rdseed() {
        unsigned int regs[4]{};
        __get_cpuid (7, &regs[0], &regs[1], &regs[2], &regs[3]);
        return regs[2] & bit_RDSEED; //bit_RDSEED predefined in GNU et al
    }
#endif

    /**
     * Nonce modes, two basic groups
     * + Cryptographically secure (for a stream cipher, that is resistant to nonce reuse) using block_t = aes::encrypt<>::block_t;
        using value_type = aes::encrypt<>::value_type;
     * + Pseudo-random (vulnerable to nonce reuse)
     * @note Given a secure random number generator, one can _(almost)_ guarantee to never repeat a nonce twice in a lifetime.
     */
#ifdef __RDSEED__
    enum nonce_mode_t {
#ifndef _MSC_VER
        CSSEED64, CSSEED32, CSSEED16
#else // as of writing MSCV does not provided a read 64 bit seed intrinsic
        CSSEED32, CSSEED16
#endif
    };
#else
    /**
     * @warning Not cryptographically secure - only for testing
     */
    enum nonce_mode_t {
        PRSEED32
    };
#endif


#ifdef __RDSEED__

    /**
     * @brief Generate large stateless _cryptographically secure_ random nonces from 32 bit entropy hardware.
     * RDSEED, whilst similar to RDRAND, provides higher level access to the entropy hardware.
     * The RDSEED generator and processor instruction rdseed are available with Intel Broadwell CPUs (and later)
     * and AMD Zen CPUs (and later).
     * @tparam M
     * @tparam T
     */
    template<nonce_mode_t M = CSSEED32, size_t nonce_size = NONCE_SIZE, typename T = uint8_t>
    /**
      * @note There are a number of problems with writing a nonce factory:
      * + Only certain later CPUs support hardware entropy as hardware random number generators (HRNG) Intel Ivy Bridge 2012, AMD 2015
      * + There does not appear to be any consistent compile time way of detecting HRNG support making conditional compilation impossible
      * + Different compilers implement the intrinsics to read the HRNG differently and incompletely
      * + The __RDSEED__ constant is used to select compile time HRNG vs PRNG but must be set manually by using ```can_rdseed``` first to manually test the target system
      * + A cryptographically secure nonce requires a HRNG
      * + A cryptographically secure nonce must be at least 12 bytes long to effectively mitigate birthday attacks
      * + In the abscence of an HRNG a pseudo-random number generator (PRNG) fallback is provided for testing purposed _but it is not secure_
      * @warning I'm not even sure that providing a PRNG fallback for non-HRNG settings is a good idea?!
      */
    struct nonce {

        using value_type = T;
        using block_t = std::array<T, crypto::BLOCK_SIZE>;
        using seed_t = unsigned int;

        /**
         * @brief secure nonce generator
         * @return a cryptographically secure nonce block with nonce_size high bytes seeded from hardware entropy source
         */
        block_t operator()() {
            block_t block{};
            size_t p{0};
            seed_t seed;
            size_t seed_size = sizeof(seed);
            for (size_t i{0}; i < nonce_size / seed_size; i ++) {
                seed = rdseed();
                for (int j{0}; j < seed_size; ++j) {
                    p = (i * seed_size) + j;
                    block[p] = seed & 0xFF;
                    seed >>= 8;
                }
            }
            seed = rdseed();
            for(size_t j{0}; j < nonce_size % seed_size; ++j) {
                block[p + j +1] = seed & 0xFF;
                seed >>= 8;
            }
            return block;
        }

    private:

        seed_t rdseed() {
#ifdef NDEBUG
            seed_t n;
            if(_rdseed32_step (&n)) {
                return n;
            }
            throw doh::cipher_exception(doh::DETERMINISTIC);
#else //return a debug constant for testing against
            return 0x89ABCDEF;
#endif
        }

    };

    /**
     * @brief Generate large stateless _cryptographically secure_ random nonces from 16 bit entropy hardware.
     * @tparam nonce_size
     * @tparam T
     */
    template<size_t nonce_size, typename T>
    struct nonce<CSSEED16, nonce_size, T> {

        using value_type = T;
        using block_t = std::array<T, crypto::BLOCK_SIZE>;
        using seed_t = unsigned short;

        /**
         * @brief secure nonce generator
         * @return a cryptographically secure nonce block with nonce_size high bytes seeded from hardware entropy source
         */
        block_t operator()() {
            block_t block{};
            size_t p{0};
            seed_t seed;
            size_t seed_size = sizeof(seed);
            for (size_t i{0}; i < nonce_size / seed_size; i ++) {
                seed = rdseed();
                for (int j{0}; j < seed_size; ++j) {
                    p = (i * seed_size) + j;
                    block[p] = seed & 0xFF;
                    seed >>= 8;
                }
            }
            seed = rdseed();
            for(size_t j{0}; j < nonce_size % seed_size; ++j) {
                block[p + j + 1] = seed & 0xFF;
                seed >>= 8;
            }
            return block;
        }

    private:

        seed_t rdseed() {
#ifdef NDEBUG
            seed_t n;
            if(_rdseed16_step (&n)) {
                return n;
            }
            throw cipher_exception(doh::DETERMINISTIC);
#else //return a debug constant for testing against
            return 0xCDEF;
#endif
        }

    };

    #ifndef _MSC_VER // N.B. MSVC intrin.h does not support _rdseed64_step

    /**
     * @brief Generate large stateless _cryptographically secure_ random nonces from 64 bit entropy hardware.
     * @tparam nonce_size
     * @tparam T
     */
    template<size_t nonce_size, typename T>
    struct nonce<CSSEED64, nonce_size, T> {

        using value_type = T;
        using block_t = std::array<T, crypto::BLOCK_SIZE>;
        using seed_t = unsigned long long;

        /**
         * @brief secure nonce generator
         * @return a cryptographically secure nonce block with nonce_size high bytes seeded from hardware entropy source
         */
        block_t operator()() {
            block_t block{};
            size_t p{0};
            seed_t seed;
            size_t seed_size = sizeof(seed);
            for (size_t i{0}; i < nonce_size / seed_size; i ++) {
                seed = rdseed();
                for (int j{0}; j < seed_size; ++j) {
                    p = (i * seed_size) + j;
                    block[p] = seed & 0xFF;
                    seed >>= 8;
                }
            }
            seed = rdseed();
            for(size_t j{0}; j < nonce_size % seed_size; ++j) {
                block[p + j +1] = seed & 0xFF;
                seed >>= 8;
            }
            return block;
        }

    private:

        seed_t rdseed() {
#ifdef NDEBUG
            seed_t n;
            if(_rdseed64_step (&n)) {
                return n;
            }
            throw pug::doh::cipher_exception(pug::doh::DETERMINISTIC);
#else
            return 0x0123456789ABCDEF;
#endif;
        }return rd();

    };
    #endif

#else

    /**
     * @warning Here be cryptographically insecure dragons!
     * @tparam M
     * @tparam nonce_size
     * @tparam T
     */
    template<nonce_mode_t M = PRSEED32, size_t nonce_size = NONCE_SIZE, typename T = uint8_t>
    struct nonce {

        using value_type = T;
        using block_t = std::array<T, crypto::BLOCK_SIZE>;
        using seed_t = std::random_device::result_type;

        /**
         * @brief *in*secure nonce generator
         * @return a cryptographically useless nonce block
         */
        block_t operator()() {
            block_t block{};
            size_t p{0};
            seed_t seed;
            size_t seed_size = sizeof(seed);
            for (size_t i{0}; i < nonce_size / seed_size; i ++) {
                seed = rdseed();
                for (size_t j{0}; j < seed_size; ++j) {
                    p = (i * seed_size) + j;
                    block[p] = seed & 0xFF;
                    seed >>= 8;
                }
            }
            seed = rdseed();
            for(size_t j{0}; j < nonce_size % seed_size; ++j) {
                block[p + j + 1] = seed & 0xFF;
                seed >>= 8;
            }
            return block;
        }


        /**
         * @brief A deterministic random number generator (e.g. a pseudo-random engine) has entropy zero.
         * @note This function is not fully implemented in some standard libraries.
         * For example:
         * + LLVM libc++ always returns zero even though the device _is_ non-deterministic.
         * + Microsoft Visual C++ implementation always returns 32 guarantees that random_device
         * is cryptographically secure and non-deterministic:
         * @link https://msdn.microsoft.com/en-us/library/bb982250.aspx
         * @return double -
         */
        inline double entropy() {
            return rd.entropy();
        }

    private:

        seed_t rdseed() {
#ifdef NDEBUG
            return rd();
#else //return a debug constant for testing against
            return 0x89ABCDEF;
#endif
        }

        std::random_device rd;

    };
#endif

}

#endif //AES_CPP17_NONCE_FACTORY_H
