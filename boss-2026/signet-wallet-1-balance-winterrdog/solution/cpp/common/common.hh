#ifndef COMMON_HXX
#define COMMON_HXX 1

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "json.hpp"

using u8 = unsigned char;
using u32 = unsigned int;
using u64 = unsigned long long;
using byte_array = std::vector<u8>;
using json = nlohmann::json;

using pub_key_t = std::array<u8, 33>;

using utxo_key_t = std::array<u8, 36>;
using outpoint_ser_t = utxo_key_t;

using secret_key_t = std::array<u8, 32>;
using txid_t = secret_key_t;
using chaincode_t = secret_key_t;
using sha256_hash_t = secret_key_t;

using witness_program_t = std::array<u8, 34>;

using sha512_hash_t = std::array<u8, 64>;

constexpr char SHA256_HASH_LENGTH = 32;

json fetch_300_blocks_to_json();
std::string bcli(const std::string& cmd);
void sha256(const byte_array& data, u8* const digest);
void HASH256(const byte_array& data, u8* const digest);
void hmac_sha512(const byte_array& key,
                 const byte_array& data,
                 sha512_hash_t& digest);

class BitcoinAmt {
 public:
  // explicit constructor to prevent accidental long long -> BitcoinAmt
  // conversions
  explicit BitcoinAmt(u64 sats);

  static BitcoinAmt fromBTC(double btc);

  u64 getSats() const;
  std::string to_string() const;

  // operator overloads
  BitcoinAmt operator+(const BitcoinAmt& other) const;
  BitcoinAmt operator-(const BitcoinAmt& other) const;

 private:
  u64 satoshis;
  static constexpr u64 COIN = 100'000'000;
  static constexpr u64 MAX_MONEY = 21'000'000 * COIN;
};

struct Hex {
  // change a hex string to a byte vector
  static byte_array Decode(const std::string& hex) {
    if (hex.length() % 2 != 0)
      throw std::invalid_argument("hex string must be even length");

    u8 val{};
    byte_array out{};

    for (size_t i = 0; i != hex.size(); i += 2) {
      // set high and low nibbles then OR them
      val = (char_to_hex(hex[i]) << 4) | (char_to_hex(hex[i + 1]));
      out.push_back(val);
    }

    return out;
  }

  static constexpr char HEX_CHARS[] = "0123456789abcdef";

  // change a byte container (vector, array, etc.) to a hex string
  static std::string Encode(const byte_array& bytes) {
    std::string result{};
    result.reserve(bytes.size() * 2);  // each byte is 2chars

    u8 high, low;
    for (u8 b : bytes) {
      // high nibble
      high = (b >> 4) & 0x0f;
      result.push_back(HEX_CHARS[high]);

      // low nibble
      low = b & 0x0f;
      result.push_back(HEX_CHARS[low]);
    }

    return result;
  }

 private:
  static int char_to_hex(char c) {
    if (c >= '0' && c <= '9')
      return c - '0';

    // we use +10 since a=10 in hex then b=11...
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;

    throw std::invalid_argument("invalid hex character detected");
  }
};

// Protocol-defined Bitcoin primitives
// https://en.bitcoin.it/wiki/Protocol_documentation#Common_structures
// We are only tracking taproot outputs which have a witness program of 34 bytes
struct Outpoint {
  u32 vout = 0;
  txid_t txid = {};

  outpoint_ser_t serialize() const {
    outpoint_ser_t buf{};

    std::memcpy(buf.data(), txid.data(), 32);

    // copy the next 4 bytes into buf in LE
    // (on intel/amd chips this is already done otherwise u hv to do the
    // conversion)
    std::memcpy(buf.data() + 32, &vout, 4);

    return buf;
  }

  static Outpoint deserialize(const outpoint_ser_t& data) {
    Outpoint outpoint;

    std::memcpy(outpoint.txid.data(), data.data(), 32);
    std::memcpy(&outpoint.vout, data.data() + 32, 4);

    return outpoint;
  }

  static Outpoint from_str(const std::string& txid_str, u32 vout) {
    Outpoint outpoint;

    outpoint.vout = vout;

    byte_array v = Hex::Decode(txid_str);
    u8 size = v.size() > 32 ? 32 : v.size();
    std::memcpy(outpoint.txid.data(), v.data(), size);

    // internal structures demand txid is in LE, not BE
    std::reverse(outpoint.txid.begin(), outpoint.txid.end());

    return outpoint;
  }
};

struct Utxo {
  Utxo() : value(BitcoinAmt(0)), scriptpubkey() {}

  BitcoinAmt value;
  std::array<u8, 34> scriptpubkey;
};

// used for locating a key (pub or priv) in a BIP32 HD tree
// BIP32 extended key
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
// 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private;
// testnet: 0x043587CF public, 0x04358394 private) 1 byte: depth: 0x00 for
// master nodes, 0x01 for level-1 derived keys, .... 4 bytes: the fingerprint of
// the parent's key (0x00000000 if master key) 4 bytes: child number. This is
// ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000
// if master key) 32 bytes: the chain code 33 bytes: the public key or private
// key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
struct ExtendedKey {
  std::array<u8, 4> version;
  u8 depth;
  std::array<u8, 4> fingerprint;
  std::array<u8, 4> index;
  chaincode_t chaincode;
  std::array<u8, 33> key;
};

// An intermediate object for deriving BIP32 keys
struct Bip32Key {
  secret_key_t key;  // 32-byte private key
  chaincode_t chaincode;
};

// Used internally for this wallet program
struct State {
  State() : balance(BitcoinAmt(0)), utxos(), programs(), pubs(), privs() {}

  BitcoinAmt balance;
  std::map<utxo_key_t, Utxo> utxos;
  std::vector<secret_key_t> privs;  // 2K priv keys provided by program
  std::vector<pub_key_t> pubs;      // 2K pub keys provided by program
  std::vector<witness_program_t> programs;
};

#endif
