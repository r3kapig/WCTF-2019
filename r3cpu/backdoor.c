#include <stdio.h>
#include <stdint.h>
#include <string.h>

static inline uint64_t rotl(uint64_t n, uint32_t i){i=i%64;return((n<<i)|(n>>(64-i)));}

#define rng() do{seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;} while(0)

#define RC6(A,B,C,D)                    \
        R = rotl(B * (B + B + 1),6);    \
        S = rotl(D * (D + D + 1),6);    \
        A = rotl(A ^ R, S) + seed;rng();\
        C = rotl(C ^ S, R) + seed;rng()

#define MUL(x,y)                                    \
        do {uint16_t _t16; uint32_t _t32;           \
            if( (_t16 = (y)) ) {                    \
                if( (x = (x)&0xffff) ) {            \
                    _t32 = (uint32_t)x * _t16;      \
                    x = _t32 & 0xffff;              \
                    _t16 = _t32 >> 16;              \
                    x = ((x)-_t16) + (x<_t16?1:0);  \
                }                                   \
                else {                              \
                    x = 1 - _t16;                   \
                }                                   \
            }                                       \
            else {                                  \
                x = 1 - x;                          \
            }                                       \
        } while(0)

#define IDEA(x1,x2,x3,x4)                           \
        MUL(x1, (uint16_t)seed);rng();              \
        x2 += (uint16_t)seed;rng();                 \
        x3 += (uint16_t)seed;rng();                 \
        MUL(x4, (uint16_t)seed);rng();              \
        s = x3;                                     \
        x3 ^= x1;                                   \
        MUL(x3, (uint16_t)seed);rng();              \
        r = x2;                                     \
        x2 ^=x4;                                    \
        x2 += x3;                                   \
        MUL(x2, (uint16_t)seed);rng();              \
        x3 += x2;                                   \
        x1 ^= x2;                                   \
        x4 ^= x3;                                   \
        x2 ^= s;                                    \
        x3 ^= r

void check(uint32_t r1, uint32_t r2, uint32_t r3, uint32_t r4, uint32_t r5, uint32_t r6, uint32_t r7, uint32_t r8){
    union {
        uint8_t byte[32];
        uint32_t r[8];
        uint64_t T[4];
        uint16_t t[16];
    } core;
    uint8_t result[32]={0x26, 0xff, 0xd4, 0xcd, 0x04, 0x4f, 0x47, 0x20, 0x50, 0xb0, 0x58, 0x21, 0x42, 0x69, 0xfd, 0xb9, 0xda, 0xa1, 0x23, 0x68, 0xc9, 0x91, 0x1f, 0x63, 0x5b, 0x5f, 0x6f, 0x35, 0xba, 0x8e, 0xa1, 0x20};
    uint64_t R,S;
    uint16_t r,s;
    int i,j;
    uint64_t seed = 0x1234abcd4321dcbaUL;

    core.r[0] = r1;
    core.r[1] = r2;
    core.r[2] = r3;
    core.r[3] = r4;
    core.r[4] = r5;
    core.r[5] = r6;
    core.r[6] = r7;
    core.r[7] = r8;
    
    for(i = 0; i < 8; i++){
        RC6(core.T[0],core.T[1],core.T[2],core.T[3]);
        for(j = 0; j < 5; j++){
            core.T[j%4] ^= core.T[(j+1)%4] ^ core.T[(j+2)%4] ^ core.T[(j+3)%4];
        }
        for(j = 0; j < 4; j++){
            IDEA(core.t[j],core.t[j+4],core.t[j+8],core.t[j+12]);
        }
    }
    for(i = 0; i < 32; i++){
        if(core.byte[i] != result[i])
            goto fail;
    }
    puts("Congrats.");
    return;
fail:
    puts("Wrong flag.");
}

int main(){
    char* flag="This_is_not_a_bug_it's_a_feature";
    uint32_t r[8];
    memcpy(r,flag,32);
    check(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7]);
    return 0;
}