#ifndef BASE58_HH
#define BASE58_HH 1

#include <algorithm>
#include <string>

#include "../common/common.hh"

static const char* BASE58_CHAR_SET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

byte_array_t base58_decode(const std::string& b58);
std::string base58_encode(const byte_array_t& input);

#endif
