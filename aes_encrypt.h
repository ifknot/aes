#ifndef AES_CPP17_AES_ENCRYPT_H
#define AES_CPP17_AES_ENCRYPT_H

#include <array>

#include "block_cipher.h"
#include "aes.h"

namespace crypto::aes {

    /**
     * @brief AES block cipher encrypt functor implementation available choices are AES128, AES192, AES256.
     * The implementation is verified against the test vectors in:
     * National Institute of Standards and Technology Special Publication 800-38A 2001 ED
     * @tparam R number of round keys needed (AES-256 default 15)
     * @tparam N length of the key in 32-bit words (AES-256 default 8)
     * @tparam T 8-bit type (default uint8_t) manipulating 8-bit bytes obviates the need to handle endian-ness across platforms.
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

        /**
         * @brief the standard S-box
         * S-box (substitution-box) basic component of symmetric key algorithms which performs substitution.
         * Used to obscure the relationship between the key and the ciphertext — Shannon's property of confusion.
         * Takes some number of input bits _m_ and transforms them into some number of output bits _n_.
         * An m×n S-box can be implemented as a lookup table with 2m words of n bits each.
         * Fixed tables are normally used, as in the AES, but in some ciphers the tables are generated dynamically from the key
         * e.g. the _Blowfish_ and the _Twofish_ encryption algorithms.
         */
        static constexpr value_type sbox[256] = {
                //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 10
                0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 20
                0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 30
                0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 40
                0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 50
                0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 60
                0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 70
                0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 80
                0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 90
                0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // A0
                0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // B0
                0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // C0
                0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // D0
                0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // E0
                0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // F0
                0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

        /**
         * The round constant word array, Rcon[i], contains the values given by x^(i-1) being powers of x in the Galois field GF(2^8)
         */
        static constexpr uint8_t Rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

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
        std::array<T, WORD_SIZE> w{}; // 32-bit Rijndael word used for the column/row operations
        for (size_t i{0}; i < N; ++i) { // The first round key is the key itself.
            xkey[(i * 4) + 0] = key[(i * 4) + 0];
            xkey[(i * 4) + 1] = key[(i * 4) + 1];
            xkey[(i * 4) + 2] = key[(i * 4) + 2];
            xkey[(i * 4) + 3] = key[(i * 4) + 3];
        }
        for (size_t i{N}; i < XK / WORD_SIZE; ++i) { // All other round keys are found from the previous round keys.
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
            if (((R == R256) && i % N == WORD_SIZE)) { //extension for AES-256
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
