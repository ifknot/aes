#ifndef AES_CPP17_BLOCK_CIPHER_FACTORY_H
#define AES_CPP17_BLOCK_CIPHER_FACTORY_H

#include <algorithm>
#include <functional>
#include <vector>

#include "aes_encrypt.h"
#include "aes_decrypt.h"

namespace crypto {

    /**
     * Block cipher mode of operation common modes:
     * + Electronic Codebook (ECB)
     * + Cipher Block Chaining (CBC)
     * + Counter (CTR)
     * @todo
     * + Propagating Cipher Block Chaining (PCBC)
     * + Cipher Feedback (CFB)
     * + Output Feedback (OFB)
     */
    enum cipher_mode_t {
        ECB, CBC, CTR // PCBC, CFB, OFB,
    };

    /**
     * @brief Electronic Codebook
     * @warning  Not recommended for use in cryptographic protocols at all!
     * (Due to lack of diffusion does not provide serious message confidentiality.)
     * + Encryption parallelizable:	Yes
     * + Decryption parallelizable:	Yes
     * + Random read access:	Yes
     * @tparam M
     * @tparam T
     * @tparam U
     */
    template<cipher_mode_t M = ECB, typename T = aes::encrypt<>, typename U = aes::decrypt<>>
    struct block_cipher {

        using block_t = typename T::block_t;
        using value_type = typename T::value_type;

        template<class KeySequence>
        explicit block_cipher(KeySequence &&kseq): encrypt_(kseq), decrypt_(kseq) {}

        //Constructor accepting a forwarding reference can hide copy and move constructors
        block_cipher(const block_cipher&) = delete;
        block_cipher(block_cipher&&) = delete;
        block_cipher& operator=(const block_cipher&) = delete;
        block_cipher& operator=(block_cipher&&) = delete;

        template<typename Iterator>
        void encrypt(Iterator front, Iterator back) {
            for(Iterator it = front; it != back; it += 16) {
                encrypt_.block(it);
            }
        }

        template<typename Iterator>
        void decrypt(Iterator front, Iterator back) {
            for(Iterator it = front; it != back; it += 16) {
                decrypt_.block(it);
            }
        }

        static inline cipher_mode_t mode() {
            return M;
        }

        static inline size_t block_size() {
            return T::block_size();
        }

    private:

        T encrypt_;

        U decrypt_;

    };

    /**
     * @brief Cipher Block Chaining
     * + Encryption parallelizable:	No
     * + Decryption parallelizable:	Yes
     * + Random read access:	Yes
     * @tparam T
     * @tparam U
     */
    template<typename T, typename U>
    class block_cipher<CBC, T, U> {

    public:

        using block_t = typename T::block_t;
        using value_type = typename T::value_type;

        template<class KeySequence>
        explicit block_cipher(KeySequence &&kseq): encrypt_(kseq), decrypt_(kseq) {}

        //Constructor accepting a forwarding reference can hide copy and move constructors
        block_cipher(const block_cipher&) = delete;
        block_cipher(block_cipher&&) = delete;
        block_cipher& operator=(const block_cipher&) = delete;
        block_cipher& operator=(block_cipher&&) = delete;

        /**
         * @note predicated on the presence of the initialisation vector prepended to the front
         * @tparam Iterator
         * @param front
         * @param back
         */
        template<typename Iterator>
        void encrypt(Iterator front, Iterator back) {
            for(Iterator it = front; it != back; it += 16) {
                //reach back 16 bytes to xor the previous block into this one
                //std::transform(it, it + 16, it - 16, it, std::bit_xor<uint8_t>());
                std::transform(it, it + 16, it - 16, it, std::bit_xor<>());
                encrypt_.block(it);
            }
        }

        /**
         * @note predicated on the presence of the initialisation vector prepended to the front
         * @tparam Iterator
         * @param front
         * @param back
         */
        template<typename Iterator>
        void decrypt(Iterator front, Iterator back) {
            //initialize the xor block with the iv block preceding the front
            std::vector<value_type>xor_block(front - 16, front);
            std::vector<value_type>xor_next(block_size());
            for(Iterator it = front; it != back; it += 16) {
                //copy this block as the next xor block before decrypting it
                xor_next.assign(it, it + 16);
                decrypt_.block(it);
                //xor the copy of the preceding encrypted block
                std::transform(it, it + 16, xor_block.begin(), it, std::bit_xor<>());
                //swap the new xor block
                xor_block.swap(xor_next);
            }
        }

        static inline cipher_mode_t mode() {
            return CBC;
        }

        static inline size_t block_size() {
            return T::block_size();
        }

    private:

        T encrypt_;

        U decrypt_;

    };

    /**
     * @brief Counter - Counter mode turns a block cipher into a stream cipher.
     * @warning Reusing a nonce with AES-CTR destroys the confidentiality of the message to a trivially vulnerable degree!
     *
     * + Encryption parallelizable:	Yes
     * + Decryption parallelizable:	Yes
     * + Random read access:	Yes
     * @note
     * + Counter  mode (CM) is also known as integer counter mode (ICM) and segmented integer counter (SIC) mode
     * + CTR mode was introduced by Whitfield Diffie and Martin Hellman in 1979.
     * + Along with CBC, CTR mode is one of two block cipher modes recommended by Niels Ferguson and Bruce Schneier.
     * @tparam T
     * @tparam U
     */
    template<typename T, typename U>
    class block_cipher<CTR, T, U> {

    public:

        using block_t = typename T::block_t;
        using value_type = typename T::value_type;

        template<class KeySequence>
        explicit block_cipher(KeySequence &&kseq): encrypt_(kseq), decrypt_(kseq) {}

        //Constructor accepting a forwarding reference can hide copy and move constructors
        block_cipher(const block_cipher&) = delete;
        block_cipher(block_cipher&&) = delete;
        block_cipher& operator=(const block_cipher&) = delete;
        block_cipher& operator=(block_cipher&&) = delete;

        /**
         * @note predicated on the presence of a nonce prepended to the front
         * @tparam Iterator
         * @param front
         * @param back
         */
        template<typename Iterator>
        void encrypt(Iterator front, Iterator back) {
            //initialize the counter with the nonce block preceding the front
            std::vector<value_type>ctr(front - 16, front);
            //copy it into the xor block
            std::vector<value_type>xor_block(front - 16, front);
            for(Iterator it = front; it != back; it += 16) {
                encrypt_.block(xor_block.begin()); //encrypt the nonce-counter
                std::transform(it, it + 16, xor_block.begin(), it, std::bit_xor<>()); //XOR the next block of plain/cipher
                inc_block(ctr); //increment nonce-counter
                xor_block = ctr; //copy into the xor block ready for next round
            }
        }

        /**
         *  The counter should represent a 128 bit big endian integer according to the NIST specifications.
         * @param block
         */
        static inline void inc_block(std::vector<value_type>& block) {
            if (block[15] == 255) block[15] = 0; else { block[15] += 1; return; }
            if (block[14] == 255) block[14] = 0; else { block[14] += 1; return; }
            if (block[13] == 255) block[13] = 0; else { block[13] += 1; return; }
            if (block[12] == 255) block[12] = 0; else { block[12] += 1; return; }
            if (block[11] == 255) block[11] = 0; else { block[11] += 1; return; }
            if (block[10] == 255) block[10] = 0; else { block[10] += 1; return; }
            if (block[9 ] == 255) block[9 ] = 0; else { block[9 ] += 1; return; }
            if (block[8 ] == 255) block[8 ] = 0; else { block[8 ] += 1; return; }
            if (block[7 ] == 255) block[7 ] = 0; else { block[7 ] += 1; return; }
            if (block[6 ] == 255) block[6 ] = 0; else { block[6 ] += 1; return; }
            if (block[5 ] == 255) block[5 ] = 0; else { block[5 ] += 1; return; }
            if (block[4 ] == 255) block[4 ] = 0; else { block[4 ] += 1; return; }
            if (block[3 ] == 255) block[3 ] = 0; else { block[3 ] += 1; return; }
            if (block[2 ] == 255) block[2 ] = 0; else { block[2 ] += 1; return; }
            if (block[1 ] == 255) block[1 ] = 0; else { block[1 ] += 1; return; }
            if (block[0 ] == 255) block[0 ] = 0; else { block[0 ] += 1; return; }
        }

        template<typename Iterator>
        void decrypt(Iterator front, Iterator back) {
            //just call encrypt
            encrypt(front, back);
        }

        static inline cipher_mode_t mode() {
            return CTR;
        }

        static inline size_t block_size() {
            return T::block_size();
        }

    private:

        T encrypt_;

        U decrypt_;

    };


}

#endif //AES_CPP17_BLOCK_CIPHER_FACTORY_H
