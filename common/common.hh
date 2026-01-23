#ifndef COMMON_HXX
#define COMMON_HXX 1

#include <openssl/sha.h>
#include <stdexcept>
#include <vector>

#include <cstdlib>
#include <string>
#include <vector>

using u8 = unsigned char;
using byte_array = std::vector<u8>;

void sha256(const byte_array& data, u8* const digest);
void HASH256(const byte_array& data, u8* const digest);

#endif
