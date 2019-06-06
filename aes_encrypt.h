#ifndef AES_CPP17_AES_ENCRYPT_H
#define AES_CPP17_AES_ENCRYPT_H

#include <array>

#include "block_cipher_constants.h"
#include "aes_constants.h"

namespace crypto::aes {

    /**
    * @brief AES block cipher encrypt functor implementation available choices are AES128, AES192, AES256.
    * The implementation is verified against the test vectors in:
    * National Institute of Standards and Technology Special Publication 800-38A 2001 ED
    * @tparam R number of round keys needed (AES-256 default 15)
    * @tparam N length of the key in 32-bit words (AES-256 default 8)
    * @tparam T 8-bit type (default uint8_t) manipulating 8-bit bytes obviates the need to handle endianness across platforms.
    */
    template<ROUNDS R = R256, KEY_LENGTH N = N256, typename T = uint8_t>
    class encrypt {

        /**
          * K as the length of the key in 8-bit bytes:
          * + 16 bytes AES-128
          * + 24 bytes AES-192
          * + 32 bytes AES-256
          * i.e N x 4
          */
        constexpr static size_t K = N * WORD_SIZE;

        /**
         * XK as the length of the expanded key in 8-bit bytes.
         */
        constexpr static size_t XK = R * N * 2;

        using key_t = std::array<T, K>;
        using expanded_key_t = std::array<T, XK>;

    public:

        using value_type = T;
        using block_t = std::array<T, crypto::BLOCK_SIZE>;

        template<class Sequence>
        explicit encrypt(Sequence &&seq) noexcept;

        //Constructor accepting a forwarding reference can hide copy and move constructors
        encrypt(const encrypt&) = delete;
        encrypt(encrypt&&) = delete;
        encrypt& operator=(const encrypt&) = delete;
        encrypt& operator=(encrypt&&) = delete;

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
         * @breif GF add (XOR) the round key to the block _increasing_ the round + 16
         * @note *has side effects* but saves time consuming multiplications
         * @param rkey reference to the round key offset
         * @param block
         */
        template<typename Iterator>
        inline void add_round_key(size_t &rkey, Iterator i);

        /**
         * @brief S-box substitution
         *
         * @param  block
         */
        template<typename Iterator>
        inline void sub_bytes(Iterator i);

        /**
         * @brief shifts the rows in the block to the left, each by a different offset.
         * @param  block
         */
        template<typename Iterator>
        inline void shift_rows(Iterator i);

        /**
         * @brief consider 16 byte block as 4x4 matrix and mix columns as per Rijndael algorithm.
         * The operation consists in the modular multiplication of two four-term polynomials, whose coefficients are
         * elements of _GF(2^8)_. The modulo used for this operation is _x^4+1_.
         * During encryption the Mix Column the multiplication matrix is
         * 02 03 01 01
         * 01 02 03 01
         * 01 01 02 03
         * 03 01 01 02
         * @param  block
         */
        template<typename Iterator>
        inline void mix_columns(Iterator i);


        /**
         * @brief This function produces Nb(Nr+1) round keys.
         * The round keys are used in each round to decrypt the  blocks.
         * @param key
         */
        void make_expanded_key(const key_t &key);

        expanded_key_t xkey;

    };

// implementation

    template<aes::ROUNDS R, aes::KEY_LENGTH N, typename T>
    template<class Sequence>
    encrypt<R, N, T>::encrypt(Sequence &&seq) noexcept {
        key_t key;
        auto it = std::begin(seq);
        for (size_t i{0}; i < key.size(); ++i) {
            key[i] = *it++;
        }
        make_expanded_key(key);
    }

    template<aes::ROUNDS R, aes::KEY_LENGTH N, typename T>
    void encrypt<R, N, T>::make_expanded_key(const encrypt::key_t &key) {
        size_t j, k;
        std::array<T, 4> w; // 32-bit Rijndael word used for the column/row operations
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
    void encrypt<R, N, T>::add_round_key(size_t &rkey, Iterator i) {
        *(i + 0 ) ^= xkey[rkey++];
        *(i + 1 ) ^= xkey[rkey++];
        *(i + 2 ) ^= xkey[rkey++];
        *(i + 3 ) ^= xkey[rkey++];
        *(i + 4 ) ^= xkey[rkey++];
        *(i + 5 ) ^= xkey[rkey++];
        *(i + 6 ) ^= xkey[rkey++];
        *(i + 7 ) ^= xkey[rkey++];
        *(i + 8 ) ^= xkey[rkey++];
        *(i + 9 ) ^= xkey[rkey++];
        *(i + 10) ^= xkey[rkey++];
        *(i + 11) ^= xkey[rkey++];
        *(i + 12) ^= xkey[rkey++];
        *(i + 13) ^= xkey[rkey++];
        *(i + 14) ^= xkey[rkey++];
        *(i + 15) ^= xkey[rkey++];
    }

    template<ROUNDS R, KEY_LENGTH N, typename T>
    template<typename Iterator>
    void encrypt<R, N, T>::sub_bytes(Iterator i) {
        *(i + 0 ) = sbox[*(i + 0 )];
        *(i + 1 ) = sbox[*(i + 1 )];
        *(i + 2 ) = sbox[*(i + 2 )];
        *(i + 3 ) = sbox[*(i + 3 )];
        *(i + 4 ) = sbox[*(i + 4 )];
        *(i + 5 ) = sbox[*(i + 5 )];
        *(i + 6 ) = sbox[*(i + 6 )];
        *(i + 7 ) = sbox[*(i + 7 )];
        *(i + 8 ) = sbox[*(i + 8 )];
        *(i + 9 ) = sbox[*(i + 9 )];
        *(i + 10) = sbox[*(i + 10)];
        *(i + 11) = sbox[*(i + 11)];
        *(i + 12) = sbox[*(i + 12)];
        *(i + 13) = sbox[*(i + 13)];
        *(i + 14) = sbox[*(i + 14)];
        *(i + 15) = sbox[*(i + 15)];
    }

    template<ROUNDS R, KEY_LENGTH N, typename T>
    template<typename Iterator>
    void encrypt<R, N, T>::shift_rows(Iterator i) {
        // Rotate first row 1 columns to left
        value_type rol{*(i + 1 )};
        *(i + 1 ) = *(i + 5 );
        *(i + 5 ) = *(i + 9 );
        *(i + 9 ) = *(i + 13);
        *(i + 13) = rol;
        // Rotate second row 2 columns to left
        rol = *(i + 2 );
        *(i + 2 ) = *(i + 10);
        *(i + 10) = rol;
        rol = *(i + 6 );
        *(i + 6 ) = *(i + 14);
        *(i + 14) = rol;
        // Rotate third row 3 columns to left
        rol = *(i + 3 );
        *(i + 3 ) = *(i + 15);
        *(i + 15) = *(i + 11);
        *(i + 11) = *(i + 7 );
        *(i + 7 ) = rol;
    }

    template<ROUNDS R, KEY_LENGTH N, typename T>
    template<typename Iterator>
    void encrypt<R, N, T>::mix_columns(Iterator i) {
        value_type a, b, c;
        a = *(i + 0);
        b = *(i + 0) ^ *(i + 1);
        c = *(i + 0) ^ *(i + 1) ^ *(i + 2) ^ *(i + 3);

        b = GF2(b);
        *(i + 0) ^= b ^ c;
        b = *(i + 1) ^ *(i + 2);
        b = GF2(b);
        *(i + 1) ^= b ^ c;
        b = *(i + 2) ^ *(i + 3);
        b = GF2(b);
        *(i + 2) ^= b ^ c;
        b = *(i + 3) ^ a;
        b = GF2(b);
        *(i + 3) ^= b ^ c;

        a = *(i + 4);
        c = *(i + 4) ^ *(i + 5) ^ *(i + 6) ^ *(i + 7);
        b = *(i + 4) ^ *(i + 5);
        b = GF2(b);
        *(i + 4) ^= b ^ c;
        b = *(i + 5) ^ *(i + 6);
        b = GF2(b);
        *(i + 5) ^= b ^ c;
        b = *(i + 6) ^ *(i + 7);
        b = GF2(b);
        *(i + 6) ^= b ^ c;
        b = *(i + 7) ^ a;
        b = GF2(b);
        *(i + 7) ^= b ^ c;

        a = *(i + 8);
        c = *(i + 8) ^ *(i + 9) ^ *(i + 10) ^ *(i + 11);
        b = *(i + 8) ^ *(i + 9);
        b = GF2(b);
        *(i + 8) ^= b ^ c;
        b = *(i + 9) ^ *(i + 10);
        b = GF2(b);
        *(i + 9) ^= b ^ c;
        b = *(i + 10) ^ *(i + 11);
        b = GF2(b);
        *(i + 10) ^= b ^ c;
        b = *(i + 11) ^ a;
        b = GF2(b);
        *(i + 11) ^= b ^ c;

        a = *(i + 12);
        c = *(i + 12) ^ *(i + 13) ^ *(i + 14) ^ *(i + 15);
        b = *(i + 12) ^ *(i + 13);
        b = GF2(b);
        *(i + 12) ^= b ^ c;
        b = *(i + 13) ^ *(i + 14);
        b = GF2(b);
        *(i + 13) ^= b ^ c;
        b = *(i + 14) ^ *(i + 15);
        b = GF2(b);
        *(i + 14) ^= b ^ c;
        b = *(i + 15) ^ a;
        b = GF2(b);
        *(i + 15) ^= b ^ c;
    }

    template<ROUNDS R, KEY_LENGTH N, typename T>
    template<typename Iterator>
    void encrypt<R, N, T>::block(Iterator i) {
        size_t rkey{0}; //offset in to the expanded keystruct
        // xor the first round key to the block before starting the rounds
        add_round_key(rkey, i); //increments the rkey offest iterator _i_ + 16
        for(auto j{ R - 1 }; --j;) { // the R - 1 rounds are identical...
            sub_bytes(i);
            shift_rows(i);  // Rijndael diffusion
            mix_columns(i); // Rijndael diffusion
            add_round_key(rkey, i);
        }
        // final round lacks mix_columns diffusion
        sub_bytes(i);
        shift_rows(i);
        add_round_key(rkey, i);
    }

    template<ROUNDS R, KEY_LENGTH N, typename T>
    size_t encrypt<R, N, T>::block_size() {
        return BLOCK_SIZE;
    }

}

#endif //AES_CPP17_AES_ENCRYPT_H
