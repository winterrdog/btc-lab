#ifndef SPEND_HXX
#define SPEND_HXX 1

#include "../balance/balance.hh"
#include "../common/common.hh"

// Nothing-up-my-sleeve point from BIP 341.
// Used as a taproot internal key to effectively disable key-path spends,
// forcing a script-path spend.
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
secp256k1_xonly_pubkey get_nums(const secp256k1_context* ctx);

void get_random_bytes(u8* buf, size_t count);

secp256k1_xonly_pubkey get_compressed_pubkey_x_only(secp256k1_context* ctx,
                                                    const pub_key_t& pubkey);

// Get Schnorr ready key pair for consumption in Taproot calculations
void get_schnorr_keypair(secp256k1_context* ctx,
                         secp256k1_keypair* keypair,
                         const u8* raw_priv);

// If a public key derived from a private key has an odd-Y value instead of
// an even-Y value, we need to negate the private key, which will result in
// the required even-Y public key. Converts the private key data in-place
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
void maybe_negate_priv(secp256k1_context* ctx, secret_key_t& private_key);

// Given 2 secp256k1 PublicKey objects, construct a 2-of-2 multisig taproot
// script. Return raw bytes of the script (without a length byte prefix)
byte_array_t create_multisig_script(
    secp256k1_context* ctx,
    std::span<const secp256k1_xonly_pubkey> keys);

// Given a single taproot script as a byte array, compute the taptree root hash.
sha256_hash_t get_taptree_root(std::span<const u8> script);

// Given a secp256k1 PublicKey object and a taptree root as bytes, construct the
// witness program as bytes. This is a SegWit version 1 pay-to-taproot witness
// program:
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#script-validation-rules
witness_program_t get_p2tr_scriptpath_program(
    secp256k1_context* ctx,
    const secp256k1_xonly_pubkey* internal_key,
    const sha256_hash_t& taptree_root);

// Given a secp256k1 PublicKey object and a taptree root as bytes, determine if
// the Y coordinate of the output key (which is a tweaked internal key) is odd.
// This bit is required in the first byte of the control block in the witness.
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-10
bool get_p2tr_scriptpath_program_parity_bit(
    secp256k1_context* ctx,
    const secp256k1_xonly_pubkey* internal_key,
    const sha256_hash_t& taptree_root);

// Given an Outpoint, return a serialized transaction input spending it.
// Use hard-coded defaults for sequence and scriptSig.
byte_array_t input_from_utxo(const Outpoint& outpoint);

// Given an output script and value (in satoshis), return a serialized
// transaction output.
byte_array_t output_from_options(std::span<const u8> script, u64 value);

// Compute the commitment hash for a single input and return bytes to sign.
// This implements the BIP 341 transaction digest algorithm
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#common-signature-message
// We assume only a single input and two outputs, SIGHASH_DEFAULT (which aka
// SIGHASH_ALL) as well as constant default values for sequence and locktime
sha256_hash_t get_commitment_hash(
    const outpoint_ser_t& outpoint,
    std::span<const u8> scriptpubkey,
    const u64 value,
    const std::vector<std::span<const u8>>& outputs,
    u8 ext_flag,
    std::span<const u8> taptree_root);

// Given the witness program as bytes from a transaction output ScriptPubKey and
// a wallet State, return the secp256k1 SecretKey object we need to sign with
secret_key_t get_private_key_for_program(const witness_program_t& program,
                                         const State& state);

pub_key_t get_pubkey_for_program(const witness_program_t& program,
                                 const State& state);

void compute_tweaked_priv_key(secp256k1_context* ctx,
                              secret_key_t& private_key);

byte_array_t create_op_return();

// Given a secp256k1 PrivateKey object and TapSighash message as bytes, compute
// the BIP 340 Schnorr signature.
schnorr_sig_t sign(secp256k1_context* ctx,
                   const secret_key_t& private_key,
                   std::span<const u8> msg);

// Given a secp256k1 PrivateKey object and TapSighash message to sign,
// compute the signature and assemble the serialized p2tr key-path witness
// as defined in BIP 341 (1 stack item only: signature)
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#script-validation-rules
byte_array_t get_p2tr_keypath_witness(secp256k1_context* ctx,
                                      const secret_key_t& private_key,
                                      std::span<const u8> msg);

// Given two secp256k1 PrivateKey objects and a transaction commitment hash to
// sign, compute both signatures and assemble the serialized p2tr script-path
// witness as defined in BIP 341 (4 stack items: signature0, signature1, script,
// control block)
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#script-validation-rules
byte_array_t get_p2tr_scriptpath_witness(secp256k1_context* ctx,
                                         std::vector<secret_key_t> private_keys,
                                         const sha256_hash_t& msg,
                                         bool parity_bit);

// Given vectors of inputs, outputs, and witnesses, assemble the complete
// transaction and serialize it for broadcast. Return bytes as hex-encoded
// string suitable to broadcast with Bitcoin Core RPC.
// https://en.bitcoin.it/wiki/Protocol_documentation#tx
std::string assemble_transaction(
    const std::vector<std::span<const u8>>& inputs,
    const std::vector<std::span<const u8>>& outputs,
    const std::vector<std::span<const u8>>& witnesses);

// Given arrays of inputs and outputs (no witnesses!) compute the txid.
// Return the 32 byte txid as a *reversed* hex-encoded string.
// https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
std::string get_txid(const std::vector<std::span<const u8>>& inputs,
                     const std::vector<std::span<const u8>>& outputs);

// Create a transaction that spends a p2tr key-path utxo to a 2-of-2 multisig
// p2tr script-path program and return both the txid and the final transaction
// as hex strings
std::pair<std::string, std::string> spend_p2tr_keypath(secp256k1_context* ctx,
                                                       State& state);

// Create a transaction that spends a 2-of-2 multisig p2tr script-path utxo to a
// an OP_RETURN output that contains YOUR GITHUB HANDLE as a string!
// Return the final transaction as a hex string.
std::string spend_p2tr_scriptpath(secp256k1_context* ctx,
                                  const State& state,
                                  const std::string& txid);

#endif
