#ifndef BALANCE_HH
#define BALANCE_HH 1

#include <sstream>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include "../base58/base58.hh"
#include "../common/common.hh"

ExtendedKey deserialize_key(const byte_array& data);
sha256_hash_t tagged_hash(const byte_array& data, const std::string& tag);
State recover_wallet_state(secp256k1_context* ctx, const std::string& xprv);
pub_key_t get_pub_from_priv(secp256k1_context* ctx, const secret_key_t& priv);

witness_program_t get_p2tr_keypath_program(secp256k1_context* ctx,
                                           const pub_key_t& pubkey);

Bip32Key derive_priv_child(secp256k1_context* ctx,
                           const secret_key_t& key,
                           const chaincode_t& chaincode,
                           u32 index,
                           bool hardened);

std::vector<secret_key_t> get_wallet_privs(
    secp256k1_context* ctx,
    const secret_key_t& key,
    const chaincode_t& chaincode,
    const std::vector<std::pair<u32, bool>>& deriv_path);

#endif
