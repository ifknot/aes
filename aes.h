#ifndef RPTX_AES_H
#define RPTX_AES_H

#include <array>

#define ECB

namespace pug::crypto {

    /**
     * R as the round number - round keys needed:
     * + 11 round keys for AES-128
     * + 13 keys for AES-192
     * + 15 keys for AES-256
     */
    //constexpr size_t R128 = 11;
    //constexpr size_t R192 = 13;
    constexpr size_t R256 = 15;

    /**
     * N as the length of the key in 32-bit words:
     * + 4 words AES-128
     * + 6 words AES-192
     * + 8 words AES-256
     */
    //constexpr size_t N128 = 4;
    //constexpr size_t N192 = 6;
    constexpr size_t N256 = 8;

    /**
     * @brief AES block cipher algorithm implementation available choices are AES128, AES192, AES256.
     * The implementation is verified against the test vectors in:
     * National Institute of Standards and Technology Special Publication 800-38A 2001 ED
     * @tparam R number of round keys needed (AES-256 default 15)
     * @tparam N length of the key in 32-bit words (AES-256 default 8)
     * @tparam T 8-bit type (default uint8_t) manipulating 8-bit bytes obviates the need to handle endianness across platforms.
     */
    template<size_t R = R256, size_t N = N256, typename T = uint8_t>
    class aes {

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
        using block_t = std::array<T, BLOCK_SIZE>;

        template<class Sequence>
        explicit aes(Sequence&& seq) noexcept;

        aes(aes const&) = delete;

        aes& operator=(aes const&) = delete;

        ~aes() = default;

        /**
         * @brief Encrypt a 16 byte block of plaintext using the session key material
         * @param block_t& block the plain text
         * @return 16 byte block of ciphertext
         */
        void encrypt(block_t& block);

#if defined ECB || defined CBC
        /**
         * @brief Decrypt a 16 byte block of cyphertext using the session key material
         * @param c the cyphertext
         * @return 16 byte block of plaintext
         */
        void decrypt(block_t& block) {
/*
 uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (round = (Nr - 1); round > 0; --round)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey);
    InvMixColumns(state);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(0, state, RoundKey);
 */
        }
#endif

#ifndef NDEBUG
        expanded_key_t& debug_xkey() {
            return xkey;
        }
#endif

    private:

        inline void add_round_key(size_t& round, block_t& block);

        /**
         * @brief S-box substitution
         * @param  block
         */
        inline void sub_bytes(block_t& block);

        /**
         * @brief shifts the rows in the block to the left, each by a different offset.
         * @param  block
         */
        inline void shift_rows(block_t& block);

        /**
         * multiply by 2 in the Rijndael algo's Galois field
         * @param x
         * @return
         */
        inline value_type GF2(T x);

        /**
         * @brief consider 16 byte block as 4x4 matrix and mix columns as per Rijndael algorithm.
         * The operation consists in the modular multiplication of two four-term polynomials, whose coefficients are
         * elements of _GF(2^8)_. The modulo used for this operation is _x^4+1_.
         * @param  block
         */
        inline void mix_columns(block_t& block);

#if defined ECB || defined CBC

        /**
         * @brief Multiply is used to multiply numbers in the field GF(2^8)
         * @note The last call to GF2() is unneeded, but often ends up generating a smaller binary.
         * The compiler seems to be able to vectorize the operation better this way.
         * @see https://github.com/kokke/tiny-AES-c/pull/34
         * @param x
         * @param y
         * @return
         */
        inline value_type mul(value_type x, value_type y) {
            return (((y & 1) * x) ^
                    ((y >> 1 & 1) * GF2(x)) ^
                    ((y >> 2 & 1) * GF2(GF2(x))) ^
                    ((y >> 3 & 1) * GF2(GF2(GF2(x)))) ^
                    ((y >> 4 & 1) * GF2(GF2(GF2(GF2(x))))));
        }

        /**
         * @brief Inverse S-box substitution
         * @param block
         */
        inline void inv_sub_bytes(aes::block_t &block) {
            block[ + 0 ]  = rsbox[ block[ + 0 ] ];
            block[ + 1 ]  = rsbox[ block[ + 1 ] ];
            block[ + 2 ]  = rsbox[ block[ + 2 ] ];
            block[ + 3 ]  = rsbox[ block[ + 3 ] ];
            block[ + 4 ]  = rsbox[ block[ + 4 ] ];
            block[ + 5 ]  = rsbox[ block[ + 5 ] ];
            block[ + 6 ]  = rsbox[ block[ + 6 ] ];
            block[ + 7 ]  = rsbox[ block[ + 7 ] ];
            block[ + 8 ]  = rsbox[ block[ + 8 ] ];
            block[ + 9 ]  = rsbox[ block[ + 9 ] ];
            block[ + 10]  = rsbox[ block[ + 10] ];
            block[ + 11]  = rsbox[ block[ + 11] ];
            block[ + 12]  = rsbox[ block[ + 12] ];
            block[ + 13]  = rsbox[ block[ + 13] ];
            block[ + 14]  = rsbox[ block[ + 14] ];
            block[ + 15]  = rsbox[ block[ + 15] ];
        }

        inline void inv_shift_rows(aes::block_t &block) {
            uint8_t temp;
/*
            // Rotate first row 1 columns to right
            temp = (*state)[3][1];
            (*state)[3][1] = (*state)[2][1];
            (*state)[2][1] = (*state)[1][1];
            (*state)[1][1] = (*state)[0][1];
            (*state)[0][1] = temp;

            // Rotate second row 2 columns to right
            temp = (*state)[0][2];
            (*state)[0][2] = (*state)[2][2];
            (*state)[2][2] = temp;

            temp = (*state)[1][2];
            (*state)[1][2] = (*state)[3][2];
            (*state)[3][2] = temp;

            // Rotate third row 3 columns to right
            temp = (*state)[0][3];
            (*state)[0][3] = (*state)[1][3];
            (*state)[1][3] = (*state)[2][3];
            (*state)[2][3] = (*state)[3][3];
            (*state)[3][3] = temp;
            */
        }


#endif

        /*
         only needed for ECB and CBC



 Multiply is used to multiply numbers in the field GF(2^8)
Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
       The compiler seems to be able to vectorize the operation better this way.
       See https://github.com/kokke/tiny-AES-c/pull/34
        static uint8_t Multiply(uint8_t x, uint8_t y)
        {
            return (((y & 1) * x) ^
                    ((y>>1 & 1) * xtime(x)) ^
                    ((y>>2 & 1) * xtime(xtime(x))) ^
                    ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
                    ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); //this last call to xtime() can be omitted
        }


         / MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  {
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}
         */
        
        /**
         * @brief This function produces Nb(Nr+1) round keys. 
         * The round keys are used in each round to decrypt the  blocks.
         * @param key 
         */
        void make_expanded_key(const key_t& key);

        /**
         * S-box (substitution-box) basic component of symmetric key algorithms which performs substitution. 
         * Used to obscure the relationship between the key and the ciphertext — Shannon's property of confusion.
         * Takes some number of input bits _m_ and transforms them into some number of output bits _n_.
         * An m×n S-box can be implemented as a lookup table with 2m words of n bits each. 
         * Fixed tables are normally used, as in the AES, but in some ciphers the tables are generated dynamically from the key 
         * e.g. the _Blowfish_ and the _Twofish_ encryption algorithms.
         */
        static constexpr value_type sbox[256] = {
                //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

#if defined ECB || defined CBC

        /**
         * The Rijndael inverse S-Box lookup table for decryption if using ECB or CBC
         */
        static constexpr value_type rsbox[256] = {
                //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
                0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
#endif

        /**
         * The round constant word array, Rcon[i], contains the values given by x^(i-1) being powers of x in the Galois field GF(2^8)
         */
        static constexpr uint8_t Rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

        expanded_key_t xkey;

    };

    template<size_t R, size_t N, typename T>
    template<class Sequence>
    aes<R, N, T>::aes(Sequence &&seq) noexcept {
        key_t key;
        auto it = std::begin(seq);
        for(int i = 0; i < key.size(); ++i) {
            key[i] = *it++;
        }
        make_expanded_key(key);
    }

    template<size_t R, size_t N, typename T>
    void aes<R, N, T>::make_expanded_key(const aes::key_t &key) {
        size_t i, j, k;
        std::array<T, 4> w{}; // 32-bit Rijndael word used for the column/row operations
        // The first round key is the key itself.
        for (i = 0; i < N; ++i) {
            xkey[(i * 4) + 0] =key[(i * 4) + 0];
            xkey[(i * 4) + 1] =key[(i * 4) + 1];
            xkey[(i * 4) + 2] =key[(i * 4) + 2];
            xkey[(i * 4) + 3] =key[(i * 4) + 3];
        }
        // All other round keys are found from the previous round keys.
        for (i = N; i < XK / 4; ++i) {
            k = (i - 1) << 2u;
            w[0]=xkey[k + 0];
            w[1]=xkey[k + 1];
            w[2]=xkey[k + 2];
            w[3]=xkey[k + 3];

            if (i % N == 0) {
                //shift the 4 bytes in a word to the left once [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
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
                w[0] = w[0] ^ Rcon[ i / N];
            }
#if (R == R256) //extension for AES-256
            if (i % N == 4) {
                w[0] = sbox[w[0]];
                w[1] = sbox[w[1]];
                w[2] = sbox[w[2]];
                w[3] = sbox[w[3]];
            }
#endif
            //use the mixed word _w_ to xor expand preceding key word into subsequent one
            j = i << 2u;
            k = (i - N) << 2u;
            xkey[j + 0] = xkey[k + 0] ^ w[0];
            xkey[j + 1] = xkey[k + 1] ^ w[1];
            xkey[j + 2] = xkey[k + 2] ^ w[2];
            xkey[j + 3] = xkey[k + 3] ^ w[3];
        }
    }

    template<size_t R, size_t N, typename T>
    void aes<R, N, T>::encrypt(aes::block_t &block) {
        size_t round = 0;
        // add the First round key to the block before starting the rounds.
        add_round_key(round, block);
        // first R - 1 rounds are identical...
        auto i = R - 1;         * @brief shifts the rows in the block to the left, each by a different offset.
141
         * @param  block
142
         */
143
        inline void shift_rows(block_t& block);
144
​
145
        /**
146
         * multiply by 2 in the Rijndael algo's Galois field
147
         * @param x
148
         * @return
149
         */
150
        inline value_type GF2(T x);
151
​
152
        /**
153
         * @brief consider 16 byte block as 4x4 matrix and mix columns as per Rijndael algorithm.
154
         * The operation consists in the modular multiplication of two four-term polynomials, whose coefficients are
155
         * elements of _GF(2^8)_. The modulo used for this operation is _x^4+1_.
156
         * @param  block
157
         */
158
        inline void mix_columns(block_t& block);
159
​
160
#if defined ECB || defined CBC
161
​
162
        /**
163
         * @brief Multiply is used to multiply numbers in the field GF(2^8)
164
         * @note The last call to GF2() is unneeded, but often ends up generating a smaller binary.
165
         * The compiler seems to be able to vectorize the operation better this way.
166
         * @see https://github.com/kokke/tiny-AES-c/pull/34
167
         * @param x
168
         * @param y
169
         * @return
170
         */
171
        inline value_type mul(value_type x, value_type y) {
172
            return (((y & 1) * x) ^
173
                    ((y >> 1 & 1) * GF2(x)) ^
174
                    ((y >> 2 & 1) * GF2(GF2(x))) ^
175
                    ((y >> 3 & 1) * GF2(GF2(GF2(x)))) ^
176
                    ((y >> 4 & 1) * GF2(GF2(GF2(GF2(x))))));
177
        }
178
​
179
        /**
180
         * @brief Inverse S-box substitution
181
         * @param block
182
         */
183
        inline void inv_sub_bytes(aes::block_t &block) {
184
            size_t i{0};
185
            block[ i + 0 ]  = rsbox[ block[ i + 0 ] ];
186
            block[ i + 1 ]  = rsbox[ block[ i + 1 ] ];
187
            block[ i + 2 ]  = rsbox[ block[ i + 2 ] ];
188
            block[ i + 3 ]  = rsbox[ block[ i + 3 ] ];
189
            block[ i + 4 ]  = rsbox[ block[ i + 4 ] ];
190
            block[ i + 5 ]  = rsbox[ block[ i + 5 ] ];
191
            block[ i + 6 ]  = rsbox[ block[ i + 6 ] ];
192
            block[ i + 7 ]  = rsbox[ block[ i + 7 ]         * @brief shifts the rows in the block to the left, each by a different offset.
141
         * @param  block
142
         */
143
        inline void shift_rows(block_t& block);
144
​
145
        /**
146
         * multiply by 2 in the Rijndael algo's Galois field
147
         * @param x
148
         * @return
149
         */
150
        inline value_type GF2(T x);
151
​
152
        /**
153
         * @brief consider 16 byte block as 4x4 matrix and mix columns as per Rijndael algorithm.
154
         * The operation consists in the modular multiplication of two four-term polynomials, whose coefficients are
155
         * elements of _GF(2^8)_. The modulo used for this operation is _x^4+1_.
156
         * @param  block
157
         */
158
        inline void mix_columns(block_t& block);
159
​
160
#if defined ECB || defined CBC
161
​
162
        /**
163
         * @brief Multiply is used to multiply numbers in the field GF(2^8)
164
         * @note The last call to GF2() is unneeded, but often ends up generating a smaller binary.
165
         * The compiler seems to be able to vectorize the operation better this way.
166
         * @see https://github.com/kokke/tiny-AES-c/pull/34
167
         * @param x
168
         * @param y
169
         * @return
170
         */
171
        inline value_type mul(value_type x, value_type y) {
172
            return (((y & 1) * x) ^
173
                    ((y >> 1 & 1) * GF2(x)) ^
174
                    ((y >> 2 & 1) * GF2(GF2(x))) ^
175
                    ((y >> 3 & 1) * GF2(GF2(GF2(x)))) ^
176
                    ((y >> 4 & 1) * GF2(GF2(GF2(GF2(x))))));
177
        }
178
​
179
        /**
180
         * @brief Inverse S-box substitution
181
         * @param block
182
         */
183
        inline void inv_sub_bytes(aes::block_t &block) {
184
            size_t i{0};
185
            block[ i + 0 ]  = rsbox[ block[ i + 0 ] ];
186
            block[ i + 1 ]  = rsbox[ block[ i + 1 ] ];
187
            block[ i + 2 ]  = rsbox[ block[ i + 2 ] ];
188
            block[ i + 3 ]  = rsbox[ block[ i + 3 ] ];
189
            block[ i + 4 ]  = rsbox[ block[ i + 4 ] ];
190
            block[ i + 5 ]  = rsbox[ block[ i + 5 ] ];
191
            block[ i + 6 ]  = rsbox[ block[ i + 6 ] ];
192
            block[ i + 7 ]  = rsbox[ block[ i + 7 ] ];
193
            block[ i + 8 ]  = rsbox[ block[ i + 8 ] ];
194
            block[ i + 9 ]  = rsbox[ block[ i + 9 ] ];
195
            block[ i + 10]  = rsbox[ block[ i + 10] ];
196
            block[ i + 11]  = rsbox[ block[ i + 11] ];
197
            block[ i + 12]  = rsbox[ block[ i + 12] ];
198
            block[ i + 13]  = rsbox[ block[ i + 13] ];
199
            block[ i + 14]  = rsbox[ block[ i + 14] ];
200
            block[ i + 15]  = rsbox[ block[ i + 15         * @brief shifts the rows in the block to the left, each by a different offset.
141
         * @param  block
142
         */
143
        inline void shift_rows(block_t& block);
144
​
145
        /**
146
         * multiply by 2 in the Rijndael algo's Galois field
147
         * @param x
148
         * @return
149
         */
150
        inline value_type GF2(T x);
151
​
152
        /**
153
         * @brief consider 16 byte block as 4x4 matrix and mix columns as per Rijndael algorithm.
154
         * The operation consists in the modular multiplication of two four-term polynomials, whose coefficients are
155
         * elements of _GF(2^8)_. The modulo used for this operation is _x^4+1_.
156
         * @param  block
157
         */
158
        inline void mix_columns(block_t& block);
159
​
160
#if defined ECB || defined CBC
161
​
162
        /**
163
         * @brief Multiply is used to multiply numbers in the field GF(2^8)
164
         * @note The last call to GF2() is unneeded, but often ends up generating a smaller binary.
165
         * The compiler seems to be able to vectorize the operation better this way.
166
         * @see https://github.com/kokke/tiny-AES-c/pull/34
167
         * @param x
168
         * @param y
169
         * @return
170
         */
171
        inline value_type mul(value_type x, value_type y) {
172
            return (((y & 1) * x) ^
173
                    ((y >> 1 & 1) * GF2(x)) ^
174
                    ((y >> 2 & 1) * GF2(GF2(x))) ^
175
                    ((y >> 3 & 1) * GF2(GF2(GF2(x)))) ^
176
                    ((y >> 4 & 1) * GF2(GF2(GF2(GF2(x))))));
177
        }
178
​
179
        /**
180
         * @brief Inverse S-box substitution
181
         * @param block
182
         */
183
        inline void inv_sub_bytes(aes::block_t &block) {
184
            size_t i{0};
185
            block[ i + 0 ]  = rsbox[ block[ i + 0 ] ];
186
            block[ i + 1 ]  = rsbox[ block[ i + 1 ] ];
187
            block[ i + 2 ]  = rsbox[ block[ i + 2 ] ];
188
            block[ i + 3 ]  = rsbox[ block[ i + 3 ] ];
189
            block[ i + 4 ]  = rsbox[ block[ i + 4 ] ];
190
            block[ i + 5 ]  = rsbox[ block[ i + 5 ] ];
191
            block[ i + 6 ]  = rsbox[ block[ i + 6 ] ];
192
            block[ i + 7 ]  = rsbox[ block[ i + 7 ] ];
193
            block[ i + 8 ]  = rsbox[ block[ i + 8 ] ];
194
            block[ i + 9 ]  = rsbox[ block[ i + 9 ] ];
195
            block[ i + 10]  = rsbox[ block[ i + 10] ];
196
            block[ i + 11]  = rsbox[ block[ i + 11] ];
197
            block[ i + 12]  = rsbox[ block[ i + 12] ];
198
            block[ i + 13]  = rsbox[ block[ i + 13] ];
199
            block[ i + 14]  = rsbox[ block[ i + 14] ];
200
            block[ i + 15]  = rsbox[ block[ i + 15] ];
201
        }
202
​
203
        inline void inv_shift_rows(aes::block_t &block) {
204
            uint8_t temp;
205
/*
206
            // Rotate first row 1 columns to right
207
            temp = (*state)[3][1];
208
            (*state)[3][1] = (*state)[2][1];
209
            (*state)[2][1] = (*state)[1][1];
210
            (*state)[1][1] = (*state)[0][1];
211
            (*state)[0][1] = temp;
212
​
213
            // Rotate second row 2 columns to right
214
            temp = (*state)[0][2];
215
            (*state)[0][2] = (*state)[2][2];
216
            (*state)[2][2] = temp;] ];
201
        }
202
​
203
        inline void inv_shift_rows(aes::block_t &block) {
204
            uint8_t temp;
205
/*
206
            // Rotate first row 1 columns to right
207
            temp = (*state)[3][1];
208
            (*state)[3][1] = (*state)[2][1];
209
            (*state)[2][1] = (*state)[1][1];
210
            (*state)[1][1] = (*state)[0][1];
211
            (*state)[0][1] = temp;
212
​
213
            // Rotate second row 2 columns to right
214
            temp = (*state)[0][2];
215
            (*state)[0][2] = (*state)[2][2];
216
            (*state)[2][2] = temp; ];
193
            block[ i + 8 ]  = rsbox[ block[ i + 8 ] ];
194
            block[ i + 9 ]  = rsbox[ block[ i + 9 ] ];
195
            block[ i + 10]  = rsbox[ block[ i + 10] ];
196
            block[ i + 11]  = rsbox[ block[ i + 11] ];
197
            block[ i + 12]  = rsbox[ block[ i + 12] ];
198
            block[ i + 13]  = rsbox[ block[ i + 13] ];
199
            block[ i + 14]  = rsbox[ block[ i + 14] ];
200
            block[ i + 15]  = rsbox[ block[ i + 15] ];
201
        }
202
​
203
        inline void inv_shift_rows(aes::block_t &block) {
204
            uint8_t temp;
205
/*
206
            // Rotate first row 1 columns to right
207
            temp = (*state)[3][1];
208
            (*state)[3][1] = (*state)[2][1];
209
            (*state)[2][1] = (*state)[1][1];
210
            (*state)[1][1] = (*state)[0][1];
211
            (*state)[0][1] = temp;
212
​
213
            // Rotate second row 2 columns to right
214
            temp = (*state)[0][2];
215
            (*state)[0][2] = (*state)[2][2];
216
            (*state)[2][2] = temp;
        while(--i) {
            sub_bytes(block);
            shift_rows(block);  // Rijndael diffusion
            mix_columns(block); // Rijndael diffusion
            add_round_key(round, block);
        }
        // final round lacks mix_columns diffusion
        sub_bytes(block);
        shift_rows(block);
        add_round_key(round, block);
    }

    template<size_t R, size_t N, typename T>
    void aes<R, N, T>::add_round_key(size_t& round, aes::block_t &block) {
        size_t i{0};
        block[i++] ^= xkey[round++];
        block[i++] ^= xkey[round++];
        block[i++] ^= xkey[round++];
        block[i++] ^= xkey[round++];
        block[i++] ^= xkey[round++];
        block[i++] ^= xkey[round++];
        block[i++] ^= xkey[round++];
        block[i++] ^= xkey[round++];
        block[i++] ^= xkey[round++];
        block[i++] ^= xkey[round++];
        block[i++] ^= xkey[round++];
        block[i++] ^= xkey[round++];
        block[i++] ^= xkey[round++];
        block[i++] ^= xkey[round++];
        block[i++] ^= xkey[round++];
        block[i  ] ^= xkey[round++];
    }

    template<size_t R, size_t N, typename T>
    void aes<R, N, T>::sub_bytes(aes::block_t &block) {
        block[ 0 ]  = sbox[ block[ 0 ] ];
        block[ 1 ]  = sbox[ block[ 1 ] ];
        block[ 2 ]  = sbox[ block[ 2 ] ];
        block[ 3 ]  = sbox[ block[ 3 ] ];
        block[ 4 ]  = sbox[ block[ 4 ] ];
        block[ 5 ]  = sbox[ block[ 5 ] ];
        block[ 6 ]  = sbox[ block[ 6 ] ];
        block[ 7 ]  = sbox[ block[ 7 ] ];
        block[ 8 ]  = sbox[ block[ 8 ] ];
        block[ 9 ]  = sbox[ block[ 9 ] ];
        block[ 10]  = sbox[ block[ 10] ];
        block[ 11]  = sbox[ block[ 11] ];
        block[ 12]  = sbox[ block[ 12] ];
        block[ 13]  = sbox[ block[ 13] ];
        block[ 14]  = sbox[ block[ 14] ];
        block[ 15]  = sbox[ block[ 15] ];
    }

    template<size_t R, size_t N, typename T>
    void aes<R, N, T>::shift_rows(aes::block_t &block) {
        uint8_t rol;
        // Rotate first row 1 columns to left
        rol = block[ 1];
        block[ 1 ]= block[ 5 ];
        block[ 5 ]= block[ 9 ];
        block[ 9 ]= block[ 13];
        block[ 13]= rol;
        // Rotate second row 2 columns to left
        rol = block[ 2];
        block[ 2 ]= block[ 10];
        block[ 10]= rol;
        rol = block[ 6];
        block[ 6 ]= block[ 14];
        block[ 14]= rol;
        // Rotate third row 3 columns to left
        rol = block[ 3];
        block[ 3 ]= block[ 15];
        block[ 15]= block[ 11];
        block[ 11]= block[ 7 ];
        block[ 7 ]= rol;
    }

    template<size_t R, size_t N, typename T>
    typename aes<R, N, T>::value_type aes<R, N, T>::GF2(T x) {
        return (x << 1)           //implicitly removes high bit because 8-bit, (so * 0x1b and not 0x11b)
               ^                  //xor
               (((x >> 7) & 1)    // arithmetic right shift, thus shifting in either zeros or ones
                * 0x1b);          // Rijndael's Galois field
    }

    template<size_t R, size_t N, typename T>
    void aes<R, N, T>::mix_columns(aes::block_t &block) {
        uint8_t c, b, a;
        a = block [0];
        c = block [0] ^ block [1] ^ block [2 ] ^ block [3];
        b = block [0] ^ block [1];
        b = GF2(b);
        block [0] ^= b ^ c;
        b = block [1] ^ block [2];
        b = GF2(b);

        block [1] ^= b ^ c;
        b = block [2] ^ block [3];
        b = GF2(b);
        block [2] ^= b ^ c;
        b = block [3] ^ a ;
        b = GF2(b);
        block [3] ^= b ^ c;

        a = block [4];
        c = block [4] ^ block [5 ] ^ block [6 ] ^ block [7];
        b = block [4] ^ block [5];
        b = GF2(b);
        block [4] ^= b ^ c;
        b = block [5] ^ block [6];
        b = GF2(b);
        block [5] ^= b ^ c;
        b = block [6] ^ block [7];
        b = GF2(b);
        block [6] ^= b ^ c;
        b = block [7] ^ a ;
        b = GF2(b);
        block [7] ^= b ^ c;

        a = block [8];
        c = block [8] ^ block [9] ^ block [10] ^ block [11];
        b = block [8] ^ block [9];
        b = GF2(b);
        block [8] ^= b ^ c;
        b = block [9] ^ block [10];
        b = GF2(b);
        block [9] ^= b ^ c;
        b = block [10] ^ block [11];
        b = GF2(b);
        block [10] ^= b ^ c;
        b = block [11] ^ a ;
        b = GF2(b);
        block [11] ^= b ^ c;

        a = block [12];
        c = block [12] ^ block [13] ^ block [14] ^ block [15];
        b = block [12] ^ block [13];
        b = GF2(b);
        block [12] ^= b ^ c;
        b = block [13] ^ block [14];
        b = GF2(b);
        block [13] ^= b ^ c;
        b = block [14] ^ block [15];
        b = GF2(b);
        block [14] ^= b ^ c;
        b = block [15] ^ a ;
        b = GF2(b);
        block [15] ^= b ^ c;
    }

}

#endif //RPTX_AES_H
