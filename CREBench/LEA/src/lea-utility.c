#include "lea.h"
#include "lea-utility.h"

word32 rotlConstant(word32 value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

word32 rotrConstant(word32 value, int shift) {
    return (value >> shift) | (value << (32 - shift));
}