#ifndef AES_CPP17_PHEX_H
#define AES_CPP17_PHEX_H

#include <cstdio>

namespace util {

    /**
     * @brief utility to pretty print 16byte hex blocks in debug mode
     * @tparam Sequence
     * @param seq
     */
    template<typename Sequence>
    void phex(Sequence &&seq) {
#ifndef NDEBUG
        size_t n = 0;
        for (auto i : seq) {
            printf("%.2x", i);
            n++;
            if(n == 16) {
                printf(" ");
                n = 0;
            }
        }
        printf("\n");
#endif
    }

}

#endif //AES_CPP17_PHEX_H
