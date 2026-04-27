#include <string.h>
#include "kalyna.h"
#include "kalyna-utility.h"

// #define print_key std::cout << std::hex << t1[0] << " " << t1[1] << " " << t2[0] << " " << t2[1] << " " << k[0] << ' ' << k[1] << ' ' << kswapped[0] << ' ' << kswapped[1]  << std::dec << std::endl;
// #define print_key printf("%llx %llx %llx %llx %llx %llx %llx %llx\n", t1[0], t1[1], t2[0], t2[1], k[0], k[1], kswapped[0], kswapped[1]);
#define print_key 
void kalyna_key_schedule(uint64_t m_rkeys[KALYNA_ROUNDS * 2], const uint8_t byte_key[KALYNA_KEY_BYTES]){
    word64 key[KALYNA_KEY_BYTES / 8] = {0};
    // parse byte_key to key (little-endian)
    for (int i = 0; i < KALYNA_KEY_BYTES; i++) {
        key[i / 8] |= (word64)byte_key[i] << (8 * (i % 8));
    }

    word64 ks[2] = {0}, ksc[2] = {0}, t1[2] = {0}, t2[2] = {0}, k[2] = {0}, kswapped[2] = {0};
    t1[0] = (128 + 128 + 64) / 64;

    AddKey(t1, t2, key, 2);
    G128(t2, t1, key);
    GL128(t1, t2, key);
    G0128(t2, ks);

    print_key

    word64 constant = 0x0001000100010001ull;
    memcpy(k, key, 16);
    kswapped[1] = k[0];
    kswapped[0] = k[1];

    print_key

    for (unsigned int i = 0; i < KALYNA_ROUNDS; i+=2) {
        AddConstant(ks, ksc, constant, 2);
        if ((i / 2) % 2 == 0) {
            AddKey(k, t2, ksc, 2);
        } else {
            AddKey(kswapped, t2, ksc, 2);
        }
        
        G128(t2, t1, ksc);
        GL128(t1, &m_rkeys[2 * i], ksc);
        if (i+1 != KALYNA_ROUNDS) { 
            MakeOddKeyLen2(&m_rkeys[2 * i], &m_rkeys[2 * (i + 1)]);
        }
        print_key
        constant <<= 1;
    }
    
}
