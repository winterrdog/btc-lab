#include "common.hh"

void HASH256(const byte_array& data, u8* const digest) {
  // 1st round.
  byte_array temp_digest(SHA256_DIGEST_LENGTH, 0x0);
  sha256(data, temp_digest.data());

  // 2nd round
  sha256(temp_digest, digest);
}

void sha256(const byte_array& data, u8* const digest) {
  SHA256_CTX ctx;

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, data.data(), data.size());
  SHA256_Final(digest, &ctx);
}
