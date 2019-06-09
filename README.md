# AES-C++17 (cipher happiness)
![happy key](https://cldup.com/3JHRDKNv4C.png)
<!--- Derivative of Jef Lippiatt https://dribbble.com/nogginfuel --->
## Header only, iterator driven, in-place block cipher software
#### C++17 implementation of [Kokke's AES-C](https://github.com/kokke/tiny-AES-c)
Learning C++17, implementing C++ idioms, and experimenting with loop-unrolling to produce a class based C++17 version of Kokke's AES-C (https://github.com/kokke/tiny-AES-c)
#### History:
2019/08/09 _Beta_ 0.1.1 (release)
+ aes_encrypt
+ aes_decrypt
+ block_cipher_factory (ECB, CFB, CTR)
+ padder_factory (PKCS5)
+ nonce_factory (crypto secure hardware entropy & pseudo random fall back)

2019/08/06 _Beta_ 0.1.0
+ aes_encrypt
+ aes_decrypt
+ ~~block_cipher_factory (ECB, CFB, CTR)~~
+ padder_factory (PKCS5)
+ ~~nonce_factory (crypto secure hardware entropy & pseudo random fall back)~~

### Usage:

#### Given _any_ container that provides a non-const forward iterator then for **inplace** encryption:

```cpp
//request an AES (default) counter (CTR) block_cipher from the compile time factory
using cipher_t = crypto::block_cipher<crypto::CTR>;
// 256 bit key
using key_t = std::array<aes_t::value_type, 32>;

// a container of plain text 
std::vector<uint8_t> plain = 
{ 0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
  0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
  0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
  0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6 };

// a key
key_t key = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
             0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

// generate a cryptographically secure (CPU permitting) nonce of 12 bytes length to seed the counter
crypto::nonce<> n;
auto nonce_block = n();

// put the nonce (64 bit) + counter (64 bit) at the front
// because the block cipher expects it this way
plain.insert(test.begin(), nonce.begin(), nonce.end());

// AES CTR block cipher
cipher_t CTR_aes(key);

//encrypt a section of the container as defined by the passed iterators
CTR_aes.encrypt(test.begin() + 16, test.end());

//decrypt a section of the container as defined by the passed iterators
CTR_aes.decrypt(test.begin() + 16, test.end()); // yes it just calls encrypt but it maintains the API


```
#### Want to use 2fish instead of AES in a padded CBC 128bit key block cipher?
```cpp
//request a 2FISH CBC 128bit key block_cipher from the compile time factory
using cipher_t = crypto::block_cipher<crypto::CBC, crypto::2fish<crypto::N128>>;
//default PKCS5 padder
using padder_t = crypto::padder<>;
// 128 bit key
using key_t = std::array<aes_t::value_type, 16>;

// a container of plain text 
std::vector<uint8_t> plain = 
{ 0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
  0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
  0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
  0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6 };

// a key
key_t key = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81};

// a padder 
padder_t pkcs5;
// space for padding
std::vector<padder_t::value_type> padding(padder_t::block_size());
// fill the padding vector
size_t n = pkcs5.pad(plain.begin(), plain.end(), padding.begin());
// pad out the plain text
for(size_t j{0}; j < n; ++j) plain.push_back(padding[j]);

// 2FISH CBC block cipher
cipher_t CBC_2fish(key);

//encrypt a section of the container as defined by the passed iterators
CBC_2fish.encrypt(test.begin() + 16, test.end());

//decrypt a section of the container as defined by the passed iterators
try {
    CBC_2fish.decrypt(test.begin() + 16, test.end());
} catch(doh::cipher_exception& e) {
    e.what();
}

```



