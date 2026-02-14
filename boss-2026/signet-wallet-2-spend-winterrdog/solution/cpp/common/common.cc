#define OPENSSL_API_COMPAT 0x10100000L  // use an older OpenSSL (v1.1.0) API
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "common.hh"

void HASH256(std::span<const u8> data, u8* const digest) {
  // 1st round
  byte_array_t temp_digest(32, 0x0);
  sha256(data, temp_digest.data());

  // 2nd round
  sha256(temp_digest, digest);
}

void sha256(std::span<const u8> data, u8* const digest) {
  SHA256_CTX _ctx;
  SHA256_CTX* ctx = &_ctx;

  SHA256_Init(ctx);
  SHA256_Update(ctx, data.data(), data.size());
  SHA256_Final(digest, ctx);
}

void hmac_sha512(const byte_array_t& key,
                 const byte_array_t& data,
                 sha512_hash_t& digest) {
  u32 md_len{0};

  HMAC(EVP_sha512(), key.data(), key.size(), data.data(), data.size(),
       digest.data(), &md_len);
  if (md_len != digest.size()) {
    throw std::runtime_error("message digest length is wrong");
  }
}

std::string bcli(const std::string& cmd) {
  using pipe_ptr = std::unique_ptr<std::FILE, decltype(&pclose)>;

  std::string final_cmd{cmd + " 2>&1"};
  pipe_ptr pipe{popen(final_cmd.c_str(), "r"), pclose};
  if (!pipe)
    return {};

  std::string result{};
  std::array<char, 128> buf{};
  while (std::fgets(buf.data(), buf.size(), pipe.get()) != nullptr) {
    result += buf.data();
  }

  // remove trailing spaces
  while (!result.empty() && (result.back() == '\n')) {
    result.pop_back();
  }

  return result;
}

json fetch_300_blocks_to_json() {
  std::string base_cmd = "bitcoin-cli -signet ";

  // for testing
  // std::string base_cmd{
  //     "/home/winterrdog/Documents/saving-satoshi/boss-2026/"
  //     "bitcoin-core-test-the-test-winterrdog/bitcoin/build/bin/bitcoin-cli "
  //     "-signet "
  //     "-datadir=/home/winterrdog/Documents/saving-satoshi/boss-2026/"
  //     "bitcoin-core-test-the-test-winterrdog/bitcoin/build/bin/signet "};

  // build the JSON array string manually for parsing
  std::string full_json = "[";

  // ignore genesis block
  constexpr unsigned short MAX_BLOCKS = 300;
  for (unsigned short i = 1; i <= MAX_BLOCKS; ++i) {
    // get block hash and data in one go
    std::string block_cmd = base_cmd + "getblock $(" + base_cmd +
                            "getblockhash " + std::to_string(i) + ") 2";

    std::string block_data = bcli(block_cmd);
    if (block_data.empty())
      continue;

    full_json += block_data;

    // place comma between objects
    if (i < MAX_BLOCKS)
      full_json += ",";
  }

  full_json += "]";

  try {
    return json::parse(full_json);
  } catch (const json::parse_error& e) {
    std::cerr << "json parse error: " << e.what() << "\n";
    return {};
  }
}
