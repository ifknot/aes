#ifndef AES_CPP17_AES_DECRYPT_H
#define AES_CPP17_AES_DECRYPT_H

#include <array>

#include "aes_reverse_constants.h"

namespace crypto::aes {

    /**
     * @brief AES block cipher algorithm implementation available choices are AES128, AES192, AES256.
     * The implementation is verified against the test vectors in:
     * National Institute of Standards and Technology Special Publication 800-38A 2001 ED
     * @tparam R number of round keys needed (AES-256 default 15)
     * @tparam N length of the key in 32-bit words (AES-256 default 8)
     * @tparam T 8-bit type (default uint8_t) manipulating 8-bit bytes obviates the need to handle endianness across platforms.
     */
    template<ROUNDS R = R256, KEY_LENGTH N = N256, typename T = uint8_t>
    class decrypt {

        /**
         * 128-bit block size.
         * Until the announcement of NIST's AES contest, the majority of block ciphers followed the example of the DES in using a block size of 64 bits (8 bytes).
         * However, the birthday paradox tells us that after accumulating a number of blocks equal to the square root of the total number possible,
         * there will be an approximately 50% chance of two or more being the same, which would start to leak information about the message contents.
         * Consequently, AES candidates were required to support a block length of 128 bits (16 bytes).
         * This should be acceptable for up to 2^64 × 16 B = 256 exabytes of data - which should suffice for quite a few years to come.
         * The winner of the AES contest, Rijndael, supports block and key sizes of 128, 192, and 256 bits, but in AES the block size is always 128 bits.
         */
        constexpr static size_t BLOCK_SIZE = 16;

        /**
          * K as the length of the key in 8-bit bytes:
          * + 16 bytes AES-128
          * + 24 bytes AES-192
          * + 32 bytes AES-256
          * i.e N x 4
          */
        constexpr static size_t K = N * 4;

        /**
         * XK as the length of the expanded key in 8-bit bytes.
         */
        constexpr static size_t XK = R * N * 2;

        using key_t = std::array<T, K>;
        using expanded_key_t = std::array<T, XK>;

    public:

        using value_type = T;

        template<class Sequence>
        explicit decrypt(Sequence&& seq) noexcept;

        //Constructor accepting a forwarding reference can hide copy and move constructors
        decrypt(const decrypt&) = delete;
        decrypt(decrypt&&) = delete;
        decrypt& operator=(const decrypt&) = delete;
        decrypt& operator=(decrypt&&) = delete;

        /**
         * @brief Encrypt a 16 byte block of plaintext using the session key material
         * @param block_t& block the plain text
         * @return 16 byte block of ciphertext
         */
        template<typename Iterator>
        void block(Iterator i);

        /**
         * @brief retrieve this block cipher's block_size
         * @return size_t
         */
        inline static size_t block_size();

    private:

        /**
         * GF add (XOR) the round key to the block in reverse order _decreasing_ the round - 16
         * @note *has side effects* but saves time consuming multiplications
         * @param rkey reference to the round key offset
         * @param block
         */
        template<typename Iterator>
        inline void inv_round_key(size_t &rkey, Iterator i);

        /**
         * @brief Inverse S-box substitution
         * @param block
         */
        template<typename Iterator>
        inline void inv_sub_bytes(Iterator i);

        /**
         * @brief inverse shifts the rows in the block to the right, each by the opposite offset.
         * During decryption the Mix Column the multiplication matrix is changed to:
         * 0E 0B 0D 09
         * 09 0E 0B 0D
         * 0D 09 0E 0B
         * 0B 0D 09 0E
         * @param  block
         */
        template<typename Iterator>
        inline void inv_shift_rows(Iterator i);

        /**
         * @brief inverse mix
         * @param  block
         */
        template<typename Iterator>
        inline void inv_mix_columns(Iterator i);

        /**
         * @brief This function produces Nb(Nr+1) round keys.
         * The round keys are used in each round to decrypt the  blocks.
         * @param key
         */
        void make_expanded_key(const key_t& key);

        expanded_key_t xkey;

    };

// implementation

    template<ROUNDS R, KEY_LENGTH N, typename T>
    template<class Sequence>
    decrypt<R, N, T>::decrypt(Sequence &&seq) noexcept {
        key_t key;
        auto it = std::begin(seq);
        for(size_t i{0}; i < key.size(); ++i) {
            key[i] = *it++;
        }
        make_expanded_key(key);
    }

    template<ROUNDS R, KEY_LENGTH N, typename T>
    void decrypt<R, N, T>::make_expanded_key(const decrypt::key_t &key) {
        size_t j, k;
        std::array<T, 4> w{}; // 32-bit Rijndael word used for the column/row operations
        // The first round key is the key itself.
        for (size_t i{0}; i < N; ++i) {
            xkey[(i * 4) + 0] =key[(i * 4) + 0];
            xkey[(i * 4) + 1] =key[(i * 4) + 1];
            xkey[(i * 4) + 2] =key[(i * 4) + 2];
            xkey[(i * 4) + 3] =key[(i * 4) + 3];
        }
        for (size_t i{N}; i < XK / 4; ++i) { // All other round keys are found from the previous round keys.
            k = (i - 1) << 2u;
            w[0] = xkey[k + 0];
            w[1] = xkey[k + 1];
            w[2] = xkey[k + 2];
            w[3] = xkey[k + 3];
            if (i % N == 0) { //shift the 4 bytes in a word to the left once [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
                const T rol = w[0];
                w[0] = w[1];
                w[1] = w[2];
                w[2] = w[3];
                w[3] = rol;
                //sbox mixing
                w[0] = sbox[w[0]];
                w[1] = sbox[w[1]];
                w[2] = sbox[w[2]];
                w[3] = sbox[w[3]];
                //Galois Field mix xor round constant
                w[0] = w[0] ^ Rcon[i / N];
            }
            if (((R == R256) && i % N == 4)) { //extension for AES-256
                w[0] = sbox[w[0]];
                w[1] = sbox[w[1]];
                w[2] = sbox[w[2]];
                w[3] = sbox[w[3]];
            }
            //use the mixed word _w_ to xor expand preceding key word into subsequent one
            j = i << 2u;
            k = (i - N) << 2u;
            xkey[j + 0] = xkey[k + 0] ^ w[0];
            xkey[j + 1] = xkey[k + 1] ^ w[1];
            xkey[j + 2] = xkey[k + 2] ^ w[2];
            xkey[j + 3] = xkey[k + 3] ^ w[3];
        }
    }

    template<ROUNDS R, KEY_LENGTH N, typename T>
    template<typename Iterator>
    void decrypt<R, N, T>::inv_round_key(size_t &rkey, Iterator i) {
        *(i + 15) ^= xkey[--rkey];
        *(i + 14) ^= xkey[--rkey];
        *(i + 13) ^= xkey[--rkey];
        *(i + 12) ^= xkey[--rkey];
        *(i + 11) ^= xkey[--rkey];
        *(i + 10) ^= xkey[--rkey];
        *(i + 9 ) ^= xkey[--rkey];
        *(i + 8 ) ^= xkey[--rkey];
        *(i + 7 ) ^= xkey[--rkey];
        *(i + 6 ) ^= xkey[--rkey];
        *(i + 5 ) ^= xkey[--rkey];
        *(i + 4 ) ^= xkey[--rkey];
        *(i + 3 ) ^= xkey[--rkey];
        *(i + 2 ) ^= xkey[--rkey];
        *(i + 1 ) ^= xkey[--rkey];
        *(i + 0 ) ^= xkey[--rkey];
    }

    template<ROUNDS R, KEY_LENGTH N, typename T>
    template<typename Iterator>
    void decrypt<R, N, T>::inv_sub_bytes(Iterator i) {
        *(i + 0 ) = rsbox[*(i + 0 )];
        *(i + 1 ) = rsbox[*(i + 1 )];
        *(i + 2 ) = rsbox[*(i + 2 )];
        *(i + 3 ) = rsbox[*(i + 3 )];
        *(i + 4 ) = rsbox[*(i + 4 )];
        *(i + 5 ) = rsbox[*(i + 5 )];
        *(i + 6 ) = rsbox[*(i + 6 )];
        *(i + 7 ) = rsbox[*(i + 7 )];
        *(i + 8 ) = rsbox[*(i + 8 )];
        *(i + 9 ) = rsbox[*(i + 9 )];
        *(i + 10) = rsbox[*(i + 10)];
        *(i + 11) = rsbox[*(i + 11)];
        *(i + 12) = rsbox[*(i + 12)];
        *(i + 13) = rsbox[*(i + 13)];
        *(i + 14) = rsbox[*(i + 14)];
        *(i + 15) = rsbox[*(i + 15)];
    }

    template<ROUNDS R, KEY_LENGTH N, typename T>
    template<typename Iterator>
    void decrypt<R, N, T>::inv_shift_rows(Iterator i) {
        // Rotate first row 3 columns to right
        value_type ror{*(i + 13)};
        *(i + 13) = *(i + 9);
        *(i + 9 ) = *(i + 5);
        *(i + 5 ) = *(i + 1);
        *(i + 1 ) = ror;
        // Rotate second row 2 columns to right n.b. same as the ROL in shift_rows
        ror = *(i + 2);
        *(i + 2 ) = *(i + 10);
        *(i + 10) = ror;
        ror = *(i + 6);
        *(i + 6 ) = *(i + 14);
        *(i + 14) = ror;
        // Rotate third row 1 columns to right
        ror = *(i + 3);
        *(i + 3 ) = *(i + 7);
        *(i + 7 ) = *(i + 11);
        *(i + 11) = *(i + 15);
        *(i + 15) = ror;
    }

    template<ROUNDS R, KEY_LENGTH N, typename T>
    template<typename Iterator>
    void decrypt<R, N, T>::inv_mix_columns(Iterator i) {
        //value_type a, b, c, d;
        value_type a{ *(i + 0) };
        value_type b{ *(i + 1) };
        value_type c{ *(i + 2) };
        value_type d{ *(i + 3) };

        *(i + 0) = GFmul(a, 0x0e) ^ GFmul(b, 0x0b) ^ GFmul(c, 0x0d) ^ GFmul(d, 0x09);
        *(i + 1) = GFmul(a, 0x09) ^ GFmul(b, 0x0e) ^ GFmul(c, 0x0b) ^ GFmul(d, 0x0d);
        *(i + 2) = GFmul(a, 0x0d) ^ GFmul(b, 0x09) ^ GFmul(c, 0x0e) ^ GFmul(d, 0x0b);
        *(i + 3) = GFmul(a, 0x0b) ^ GFmul(b, 0x0d) ^ GFmul(c, 0x09) ^ GFmul(d, 0x0e);

        a = *(i + 4);
        b = *(i + 5);
        c = *(i + 6);
        d = *(i + 7);

        *(i + 4) = GFmul(a, 0x0e) ^ GFmul(b, 0x0b) ^ GFmul(c, 0x0d) ^ GFmul(d, 0x09);
        *(i + 5) = GFmul(a, 0x09) ^ GFmul(b, 0x0e) ^ GFmul(c, 0x0b) ^ GFmul(d, 0x0d);
        *(i + 6) = GFmul(a, 0x0d) ^ GFmul(b, 0x09) ^ GFmul(c, 0x0e) ^ GFmul(d, 0x0b);
        *(i + 7) = GFmul(a, 0x0b) ^ GFmul(b, 0x0d) ^ GFmul(c, 0x09) ^ GFmul(d, 0x0e);

        a = *(i + 8);
        b = *(i + 9);
        c = *(i + 10);
        d = *(i + 11);

        *(i + 8 ) = GFmul(a, 0x0e) ^ GFmul(b, 0x0b) ^ GFmul(c, 0x0d) ^ GFmul(d, 0x09);
        *(i + 9 ) = GFmul(a, 0x09) ^ GFmul(b, 0x0e) ^ GFmul(c, 0x0b) ^ GFmul(d, 0x0d);
        *(i + 10) = GFmul(a, 0x0d) ^ GFmul(b, 0x09) ^ GFmul(c, 0x0e) ^ GFmul(d, 0x0b);
        *(i + 11) = GFmul(a, 0x0b) ^ GFmul(b, 0x0d) ^ GFmul(c, 0x09) ^ GFmul(d, 0x0e);

        a = *(i + 12);
        b = *(i + 13);
        c = *(i + 14);
        d = *(i + 15);

        *(i + 12) = GFmul(a, 0x0e) ^ GFmul(b, 0x0b) ^ GFmul(c, 0x0d) ^ GFmul(d, 0x09);
        *(i + 13) = GFmul(a, 0x09) ^ GFmul(b, 0x0e) ^ GFmul(c, 0x0b) ^ GFmul(d, 0x0d);
        *(i + 14) = GFmul(a, 0x0d) ^ GFmul(b, 0x09) ^ GFmul(c, 0x0e) ^ GFmul(d, 0x0b);
        *(i + 15) = GFmul(a, 0x0b) ^ GFmul(b, 0x0d) ^ GFmul(c, 0x09) ^ GFmul(d, 0x0e);
    }

    template<ROUNDS R, KEY_LENGTH N, typename T>
    template<typename Iterator>
    void decrypt<R, N, T>::block(Iterator i) {
        size_t rkey{ R * BLOCK_SIZE }; //start at the back of the expanded key
        // xor the last round key to the block before starting the inverse rounds
        inv_round_key(rkey, i); //decrements the rkey offest - 16
        for(auto j{ R - 1 }; --j;) { // the R - 1 rounds are identical...
            inv_shift_rows(i);
            inv_sub_bytes(i);
            inv_round_key(rkey, i); //decrements the rkey offest - 16
            inv_mix_columns(i);
        }
        inv_shift_rows(i);
        inv_sub_bytes(i);
        inv_round_key(rkey, i); //decrements the rkey offest - 16
    }

    template<ROUNDS R, KEY_LENGTH N, typename T>
    size_t decrypt<R, N, T>::block_size() {
        return BLOCK_SIZE;
    }

}

#endif //AES_CPP17_AES_DECRYPT_H
