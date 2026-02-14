#include "spend.hh"
#include <cstddef>

// Nothing-up-my-sleeve point from BIP 341.
// Used as a taproot internal key to effectively disable key-path spends,
// forcing a script-path spend.
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
secp256k1_xonly_pubkey get_nums(const secp256k1_context* ctx) {
  // store pubkey in the data segment, not stack to avoid recomputations
  static bool initialized{false};
  static secp256k1_xonly_pubkey pubkey;

  if (!initialized) {
    std::string nums_hex{
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"};
    byte_array_t nums_bytes{Hex::Decode(nums_hex)};

    if (!secp256k1_xonly_pubkey_parse(ctx, &pubkey, nums_bytes.data()))
      throw std::runtime_error("failed to create NUMS pubkey.");

    initialized = true;
  }

  return pubkey;
}

/**
 * This ensures the internal secret key matches the
 * even-parity (Schnorr-ready) public key and places the
 * key pair into the keypair pointer
 */
void get_schnorr_keypair(secp256k1_context* ctx,
                         secp256k1_keypair* keypair,
                         const u8* raw_priv) {
  if (secp256k1_keypair_create(ctx, keypair, raw_priv) != 1)
    throw std::runtime_error("failed to create keypair");

  // check the parity of the public key
  int parity{};
  secp256k1_xonly_pubkey pub;
  secp256k1_keypair_xonly_pub(ctx, &pub, &parity, keypair);

  // if parity is 1 (i.e. odd), we must negate the secret key
  if (parity == 1) {
    secret_key_t sk{};
    secp256k1_keypair_sec(ctx, sk.data(), keypair);

    // negate it priv key: d = n - d
    if (secp256k1_ec_seckey_negate(ctx, sk.data()) != 1) {
      throw std::runtime_error(
          "failed to negate private because it was corrupt.");
    }

    // re-create the keypair with the "negated" key now the public key's Y
    // will be even
    if (1 != secp256k1_keypair_create(ctx, keypair, sk.data())) {
      throw std::runtime_error(
          "failed to get schnorr signature because private keys could not be "
          "found.");
    }
  }
}

// If the public key derived from a private key has an odd-Y value instead of
// an even-Y value, we need to negate the private key, which will result in
// the required even-Y public key.
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
void maybe_negate_priv(secp256k1_context* ctx, secret_key_t& private_key) {
  // extract the "correct" (maybe negated) secret key from the keypair
  secp256k1_keypair keypair;
  get_schnorr_keypair(ctx, &keypair, private_key.data());
  secp256k1_keypair_sec(ctx, private_key.data(), &keypair);

  // clear keypair data
  memset(&keypair, 0, sizeof(keypair));
}

// Given 2 secp256k1 PublicKey objects, construct a 2-of-2 multisig taproot
// script. Return raw bytes of the script (without a length byte prefix)
byte_array_t create_multisig_script(
    secp256k1_context* ctx,
    std::span<const secp256k1_xonly_pubkey> keys) {
  // multisig script: <pub1> OP_CHECKSIG <pub2> OP_CHECKSIGADD OP_2 OP_EQUAL

  // opcodes from:
  // https://github.com/bitcoin/bitcoin/blob/master/src/script/script.h
  constexpr u8 OP_2{0x52};
  constexpr u8 OP_PUSH32{32};  // the next bytes are 32 bytes long
  constexpr u8 OP_EQUAL{0x87};
  constexpr u8 OP_CHECKSIG{0xac};
  constexpr u8 OP_CHECKSIGADD{0xba};

  // serialise pubkeys into bytes
  bytes32 pubkey1{}, pubkey2{};
  secp256k1_xonly_pubkey_serialize(ctx, pubkey1.data(), &keys[0]);
  secp256k1_xonly_pubkey_serialize(ctx, pubkey2.data(), &keys[1]);

  byte_array_t script{};
  // calculation: (1 byte push + 32 byte key) * 2 + 4 opcodes = 70 bytes
  script.reserve(70);

  // OP_PUSH32 <pub1> OP_CHECKSIG
  script.push_back(OP_PUSH32);
  std::ranges::copy(pubkey1, std::back_inserter(script));
  script.push_back(OP_CHECKSIG);

  // OP_PUSH32 <pub2> OP_CHECKSIGADD
  script.push_back(OP_PUSH32);
  std::ranges::copy(pubkey2, std::back_inserter(script));
  script.push_back(OP_CHECKSIGADD);

  // OP_2 OP_EQUAL
  script.push_back(OP_2);
  script.push_back(OP_EQUAL);

  return script;
}

// Given a single taproot script as a byte array, compute the taptree root hash.
sha256_hash_t get_taptree_root(std::span<const u8> script) {
  byte_array_t leaf_data{};
  u8 script_size{static_cast<u8>(script.size())};

  leaf_data.reserve(2 * sizeof(u8) + script_size);

  leaf_data.push_back(0xc0);                                 // leaf version
  leaf_data.push_back(script_size);                          // script size
  std::ranges::copy(script, std::back_inserter(leaf_data));  // script

  return tagged_hash(leaf_data, {"TapLeaf"});
}

// Given a secp256k1 PublicKey object and a taptree root as bytes, construct the
// witness program as bytes. This is a SegWit version 1 pay-to-taproot witness
// program:
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#script-validation-rules
witness_program_t get_p2tr_scriptpath_program(
    secp256k1_context* ctx,
    const secp256k1_xonly_pubkey* internal_key,
    const sha256_hash_t& taptree_root) {
  // Compute the TapTweak
  sha256_hash_t tweak{};

  {
    // Get the 32-byte X coordinate from the internal public key
    bytes32 internal_key_x_bytes{};
    secp256k1_xonly_pubkey_serialize(ctx, internal_key_x_bytes.data(),
                                     internal_key);

    byte_array_t pub_key_merk_rt;
    pub_key_merk_rt.reserve(internal_key_x_bytes.size() + taptree_root.size());

    // add pubkey, and then add taptree root i.e. (pub || km)
    std::ranges::copy(internal_key_x_bytes,
                      std::back_inserter(pub_key_merk_rt));
    std::ranges::copy(taptree_root, std::back_inserter(pub_key_merk_rt));

    tweak = tagged_hash(pub_key_merk_rt, {"TapTweak"});
  }

  // Compute the output public key by tweaking the internal key

  // Q = P + (tap_tweak * G)
  secp256k1_pubkey tweaked_pubkey;
  if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_pubkey, internal_key,
                                        tweak.data())) {
    return {};
  }

  // convert the tweaked pubkey to xonly to extract the x-coordinate
  secp256k1_xonly_pubkey tweaked_pubkey_x_only;
  secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_pubkey_x_only, nullptr,
                                     &tweaked_pubkey);

  // extract the x-coordinate of Q for the witness program
  bytes32 q_bytes;
  secp256k1_xonly_pubkey_serialize(ctx, q_bytes.data(), &tweaked_pubkey_x_only);

  // Compile the version 1 witness program
  // https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-Witness_program
  constexpr u8 OP_1{0x51};
  constexpr u8 TWEAKED_PUBKEY_X_LEN{32};

  witness_program_t witness_program{};
  witness_program[0] = OP_1;
  witness_program[1] = TWEAKED_PUBKEY_X_LEN;
  std::memcpy(witness_program.data() + 2, q_bytes.data(), TWEAKED_PUBKEY_X_LEN);

  return witness_program;
}

// Given a secp256k1 PublicKey object and a taptree root as bytes, determine if
// the Y coordinate of the output key (which is a tweaked internal key) is odd.
// This bit is required in the first byte of the control block in the witness.
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-10
bool get_p2tr_scriptpath_program_parity_bit(
    secp256k1_context* ctx,
    const secp256k1_xonly_pubkey* internal_key,
    const sha256_hash_t& taptree_root) {
  // Compute the TapTweak
  sha256_hash_t tweak{};

  {
    // Get the 32-byte X coordinate from the internal public key
    bytes32 internal_key_x_bytes;
    secp256k1_xonly_pubkey_serialize(ctx, internal_key_x_bytes.data(),
                                     internal_key);

    byte_array_t pub_key_merk_rt{};
    pub_key_merk_rt.reserve(64);  // size of pubkey and merkle root = 64;

    // concatenate p and merkle root
    std::ranges::copy(internal_key_x_bytes,
                      std::back_inserter(pub_key_merk_rt));
    std::ranges::copy(taptree_root, std::back_inserter(pub_key_merk_rt));

    tweak = tagged_hash(pub_key_merk_rt, {"TapTweak"});
  }

  // Compute the output public key by tweaking the internal key

  // Q = P + (tap_tweak * G)
  secp256k1_pubkey tweaked_pubkey;
  if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_pubkey, internal_key,
                                        tweak.data())) {
    throw std::runtime_error(
        "failed to find the witness parity bit (invalid taptree root or public "
        "key)");
  }

  // convert the tweaked pubkey to xonly to extract the x-coordinate
  int pk_parity{0};
  secp256k1_xonly_pubkey tweaked_pubkey_x_only;
  secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_pubkey_x_only, &pk_parity,
                                     &tweaked_pubkey);

  return pk_parity == 1;
}

// Given an Outpoint, return a serialized transaction input spending it.
// Use hard-coded defaults for sequence and scriptSig.
byte_array_t input_from_utxo(const Outpoint& op) {
  byte_array_t input_bytes;

  // size: 36 (outpoint) + 1 (len) + 0 (script) + 4 (seq) = 41
  input_bytes.reserve(41);

  // 1. Previous Outpoint (txid & index)
  outpoint_ser_t output_bytes{op.serialize()};
  std::ranges::copy(output_bytes, std::back_inserter(input_bytes));

  // 2. Script Length
  input_bytes.push_back(0x00);

  // 3. scriptSig - not needed for segwit/taproot since we use witness section
  // for this data

  // 4. sequence - default is "0xffffffff" in little endian
  input_bytes.insert(input_bytes.end(), 4, 0xff);

  return input_bytes;
}

// Given an output script and value (in satoshis), return a serialized
// transaction output.
byte_array_t output_from_options(std::span<const u8> script, u64 value) {
  byte_array_t output_bytes{};
  output_bytes.reserve(8 + 1 + script.size());

  // 1. value/amount, in little endian
  for (u8 i{0}; i != 8; ++i) {
    output_bytes.push_back(static_cast<u8>((value >> (i * 8)) & 0xff));
  }

  // 2. scriptPubKey's compact size
  output_bytes.push_back(static_cast<u8>(script.size()));

  // 3. scriptPubKey
  std::ranges::copy(script, std::back_inserter(output_bytes));

  return output_bytes;
}

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
    std::span<const u8> taptree_root) {
  // Initialize serialization
  byte_array_t sig_msg{};
  sig_msg.reserve(200);

  // Sighash Epoch
  // https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-20
  constexpr u8 epoch{0x00};
  sig_msg.push_back(epoch);

  // Control
  //   Hash Type (SIGHASH_DEFAULT aka SIGHASH_ALL)
  constexpr u8 hash_type{0x00};
  sig_msg.push_back(hash_type);

  // Transaction data
  //   Version, default=0x00000002
  constexpr u8 version[4]{2, 0, 0, 0};
  std::ranges::copy(version, std::back_inserter(sig_msg));

  //   Locktime, default=0x00000000
  sig_msg.insert(sig_msg.end(), 4, 0x0);

  //   SHA256 of the serialization of all input outpoints (only one in our case)
  sha256_hash_t sha_prevouts{};
  sha256(outpoint, sha_prevouts.data());
  std::ranges::copy(sha_prevouts, std::back_inserter(sig_msg));

  //   SHA256 of the serialization of all input amounts (only one in our case)
  sha256_hash_t sha_amounts{};
  std::array<u8, 8> serialize_amount{};
  std::memcpy(serialize_amount.data(), (u8*)&value, 8);
  sha256(serialize_amount, sha_amounts.data());
  std::ranges::copy(sha_amounts, std::back_inserter(sig_msg));

  //   SHA256 of all spent outputs' scriptPubKeys including length prefix (only
  //   one in our case)
  byte_array_t scriptpubkey_with_len{};
  u8 scriptpubkey_len = scriptpubkey.size();
  scriptpubkey_with_len.reserve(1 + scriptpubkey_len);
  scriptpubkey_with_len.push_back(static_cast<u8>(scriptpubkey_len));
  std::ranges::copy(scriptpubkey, std::back_inserter(scriptpubkey_with_len));

  sha256_hash_t sha_scriptpubkeys{};
  sha256(scriptpubkey_with_len, sha_scriptpubkeys.data());
  std::ranges::copy(sha_scriptpubkeys, std::back_inserter(sig_msg));

  //   SHA256 of the serialization of all input nSequence, default
  //   0xffffffff (only one in our case)
  constexpr std::array<u8, 4> seq{0xff, 0xff, 0xff, 0xff};
  sha256_hash_t sha_seqs{};
  sha256(seq, sha_seqs.data());
  std::ranges::copy(sha_seqs, std::back_inserter(sig_msg));

  //   SHA256 of the serialization of all outputs including length prefix
  byte_array_t all_output_data{};
  for (const auto& output : outputs) {
    std::ranges::copy(output, std::back_inserter(all_output_data));
  }
  sha256_hash_t sha_outputs{};
  sha256(all_output_data, sha_outputs.data());
  std::ranges::copy(sha_outputs, std::back_inserter(sig_msg));

  // Data about this input
  //   Spend type (0 for key-path spend, 2 for script-path spend)
  constexpr u8 annex_present{0x00};
  const u8 spend_type = (ext_flag * 2) + annex_present;
  sig_msg.push_back(spend_type);

  // index of this input in the transaction input vector i.e. 0x00000000 since
  // it's one
  sig_msg.insert(sig_msg.end(), 4, 0x00);

  // Data about this output
  // (nothing needed here for key-path since we are signing SIGHASH_ALL)
  // ...

  if (ext_flag == 1) {
    //   For script-path spends, extend the message
    //   https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#common-signature-message-extension

    // The tapleaf hash as defined in BIP341
    // Since we only have one script in our tree the leaf hash *is* the tree
    // root hash already hashed from a step before
    std::ranges::copy(taptree_root, std::back_inserter(sig_msg));

    // # A constant value 0x00 representing the current version of public keys
    // in the tapscript signature opcode execution.
    sig_msg.push_back(0x00);

    // # The opcode position of the last executed OP_CODESEPARATOR (or
    // 0xffffffff if none executed)
    sig_msg.insert(sig_msg.end(), 4, 0xff);
  }

  // Return the TapSighash-tagged hash of the above serialization
  return tagged_hash(sig_msg, {"TapSighash"});
}

// Given the witness program as bytes from a transaction output ScriptPubKey and
// a wallet State, return the secp256k1 SecretKey object we need to sign with
secret_key_t get_private_key_for_program(const witness_program_t& program,
                                         const State& state) {
  // during creating of programs they are created in the same sequential order
  // as the private keys that birthed them

  if (state.programs.size() != state.privs.size()) {
    throw std::runtime_error(
        "state is corrupted: programs and privs count mismatch.");
  }

  // - hex encode all the witness programs and the tgt witness
  // - then in the witness array look for the index that matches the tgt witness
  // hex.
  // - use the found index to look for the corresponding priv key
  //   in the state.privs vector

  auto it{std::ranges::find(state.programs, program)};
  if (it != state.programs.end()) {
    long int index{std::distance(state.programs.begin(), it)};
    return state.privs[index];
  }

  throw std::runtime_error(
      "private key for program not found in wallet state.");
}

void get_random_bytes(u8* buf, size_t count) {
  int fd{open("/dev/urandom", O_RDONLY)};
  if (fd < 0)
    return;
  if (read(fd, buf, count) < 0)
    return;
  close(fd);
}

// Given a secp256k1 PrivateKey object and TapSighash message as bytes, compute
// the BIP 340 Schnorr signature.
schnorr_sig_t sign(secp256k1_context* ctx,
                   const secret_key_t& private_key,
                   std::span<const u8> msg) {
  secp256k1_keypair keypair;
  get_schnorr_keypair(ctx, &keypair, private_key.data());

  u8 aux_rand[32]{};
  get_random_bytes(aux_rand, 32);

  schnorr_sig_t sig64;
  if (!secp256k1_schnorrsig_sign32(ctx, sig64.data(), msg.data(), &keypair,
                                   aux_rand)) {
    throw std::runtime_error(
        "failed to generate schnorr signature for provided msg.");
  }

  return sig64;
}

// Given a secp256k1 PrivateKey object (must be tweaked) and TapSighash message
// to sign, compute the signature and assemble the serialized p2tr key-path
// witness as defined in BIP 341 (1 stack item only: signature).
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#script-validation-rules
byte_array_t get_p2tr_keypath_witness(secp256k1_context* ctx,
                                      const secret_key_t& private_key,
                                      std::span<const u8> msg) {
  byte_array_t witness_stack{};

  // stack item cnt + compact item size + signature size
  witness_stack.reserve(1 + 1 + 64);

  // 1. stack items cnt. for key-path, there is exactly 1 item: the signature
  witness_stack.push_back(0x1);

  schnorr_sig_t signature{sign(ctx, private_key, msg)};

  // 2. compact size of a schnorr signature
  witness_stack.push_back(static_cast<u8>(signature.size()));

  // 3. actual schnorr signature data
  std::ranges::copy(signature, std::back_inserter(witness_stack));

  return witness_stack;
}

// Given two secp256k1 PrivateKey objects and a transaction commitment hash to
// sign, compute both signatures and assemble the serialized p2tr script-path
// witness as defined in BIP 341 (4 stack items: signature0, signature1, script,
// control block)
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#script-validation-rules
byte_array_t get_p2tr_scriptpath_witness(secp256k1_context* ctx,
                                         std::vector<secret_key_t> private_keys,
                                         const sha256_hash_t& msg,
                                         bool parity_bit) {
  // ====
  //  1. Collect ALL The Stack Items
  // ====

  // represents our stack items
  std::vector<byte_array_t> stack;
  stack.reserve(4);

  // A. Signatures (pushing in order of consumption: sig0, then sig1)
  // remember: to have sig0 on TOP of the stack, it must be the LAST item pushed
  // during serialization. so we collect them in the order: sig1, sig0.
  for (int i{1}; i >= 0; --i) {
    schnorr_sig_t sig = sign(ctx, private_keys[i], msg);
    stack.push_back(byte_array_t(sig.begin(), sig.end()));
  }

  // B. The Script

  // derive public keys first
  secp256k1_pubkey full_pubkey;
  secp256k1_xonly_pubkey pubs[2]{};
  for (u8 i{0}; i != 2; ++i) {
    pub_key_t pubkey = get_pub_from_priv(ctx, private_keys[i]);
    if (1 != secp256k1_ec_pubkey_parse(ctx, &full_pubkey, pubkey.data(),
                                       pubkey.size())) {
      throw std::runtime_error(
          "failed to derive public keys when deriving scriptpath witnesses.");
    }
    secp256k1_xonly_pubkey_from_pubkey(
        ctx, &pubs[i], nullptr,
        &full_pubkey);  // forces an even Y-coordinate
  }

  // compile script
  stack.push_back(create_multisig_script(ctx, pubs));

  // C. The Control Block

  // Because we only have one script in our taptree, the control block
  // is just the control byte plus the internal key, which is our NUMS point.
  // when nodes are verifying the transaction, they'll notice there's no merkle
  // path and they will assume we only hv a single leaf and just hash the script
  // to get the merkle root
  constexpr u8 leaf_version{0xc0};
  u8 control_byte = (parity_bit ? 1 : 0) | leaf_version;

  // this effectively blocks a keypath spend and forces a script spend cuz
  // nobody knows the private key to the NUMS point
  bytes32 nums_point_bytes{};
  secp256k1_xonly_pubkey nums_point = get_nums(ctx);
  secp256k1_xonly_pubkey_serialize(ctx, nums_point_bytes.data(), &nums_point);

  byte_array_t control_block;
  control_block.push_back(control_byte);
  std::ranges::copy(nums_point_bytes, std::back_inserter(control_block));
  stack.push_back(control_block);

  // ====
  // 2. Finally, Serialize Them ALL Into The Witness Buffer
  // ====

  byte_array_t witness_buffer;

  // Push number of witness items i.e. (4: sig1, sig0, script, control_block)
  witness_buffer.push_back(static_cast<u8>(stack.size()));

  // add each item: [compact_size length] [data]
  for (const auto& item : stack) {
    // used a simple push_back for length since these items will ALWAYS be less
    // than 253 bytes
    witness_buffer.push_back(static_cast<u8>(item.size()));
    std::ranges::copy(item, std::back_inserter(witness_buffer));
  }

  return witness_buffer;
}

// Given vectors of inputs, outputs, and witnesses, assemble the complete
// transaction and serialize it for broadcast. Return bytes as hex-encoded
// string suitable to broadcast with Bitcoin Core RPC.
// https://en.bitcoin.it/wiki/Protocol_documentation#tx
std::string assemble_transaction(
    const std::vector<std::span<const u8>>& inputs,
    const std::vector<std::span<const u8>>& outputs,
    const std::vector<std::span<const u8>>& witnesses) {
  byte_array_t all_data{};
  all_data.reserve(512);

  // 1. version - 0x00000002, in little endian
  constexpr u8 version[4]{2, 0, 0, 0};
  std::ranges::copy(version, std::back_inserter(all_data));

  // 2. marker + flag. indicate a segwit tx
  all_data.push_back(0x0);  // marker
  all_data.push_back(0x1);  // flag

  // 3. input cnt and then inputs
  u8 input_cnt{static_cast<u8>(inputs.size())};
  all_data.push_back(input_cnt);
  for (const auto& input : inputs) {
    std::ranges::copy(input, std::back_inserter(all_data));
  }

  // 4. output cnt and then outputs
  u8 output_cnt{static_cast<u8>(outputs.size())};
  all_data.push_back(output_cnt);
  for (const auto& output : outputs) {
    std::ranges::copy(output, std::back_inserter(all_data));
  }

  // 5. witness data
  if (witnesses.size() != inputs.size()) {
    throw std::runtime_error(
        "each input must have a witness stack (even if empty).");
  }
  for (const auto& witness : witnesses) {
    std::ranges::copy(witness, std::back_inserter(all_data));
  }

  // 6. locktime - 0x00000000, in little endian
  all_data.insert(all_data.end(), 4, 0x0);

  return Hex::Encode(all_data);
}

// Given arrays of inputs and outputs (no witnesses!) compute the txid.
// Return the 32 byte txid as a *reversed* hex-encoded string.
// https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
std::string get_txid(const std::vector<std::span<const u8>>& inputs,
                     const std::vector<std::span<const u8>>& outputs) {
  byte_array_t all_data{};
  all_data.reserve(256);

  // version - 0x00000002, in little endian
  constexpr u8 version[4]{2, 0, 0, 0};
  std::ranges::copy(version, std::back_inserter(all_data));

  // input cnt and then inputs
  u8 input_cnt{static_cast<u8>(inputs.size())};
  all_data.push_back(input_cnt);
  for (const auto& input : inputs) {
    std::ranges::copy(input, std::back_inserter(all_data));
  }

  // output cnt and then outputs
  u8 output_cnt{static_cast<u8>(outputs.size())};
  all_data.push_back(output_cnt);
  for (const auto& output : outputs) {
    std::ranges::copy(output, std::back_inserter(all_data));
  }

  // locktime - 0x00000000, in little endian
  all_data.insert(all_data.end(), 4, 0x00);

  // get hash
  sha256_hash_t digest{};
  HASH256(all_data, digest.data());

  // reverse hash bytes
  std::ranges::reverse(digest);

  return Hex::Encode(digest);
}

secp256k1_xonly_pubkey get_compressed_pubkey_x_only(secp256k1_context* ctx,
                                                    const pub_key_t& pubkey) {
  secp256k1_pubkey full_pubkey;
  if (!secp256k1_ec_pubkey_parse(ctx, &full_pubkey, pubkey.data(),
                                 pubkey.size())) {
    return {};
  }

  secp256k1_xonly_pubkey internal_xonly;
  secp256k1_xonly_pubkey_from_pubkey(
      ctx, &internal_xonly, nullptr,
      &full_pubkey);  // forces an even Y-coordinate

  return internal_xonly;
}

void compute_tweaked_priv_key(secp256k1_context* ctx,
                              secret_key_t& private_key) {
  secp256k1_keypair keypair;
  if (!secp256k1_keypair_create(ctx, &keypair, private_key.data()))
    return;

  // 1. Compute the TapTweak (no script tree thus no merkle root hash needed)
  secp256k1_xonly_pubkey internal_xonly;
  secp256k1_keypair_xonly_pub(ctx, &internal_xonly, nullptr, &keypair);

  bytes32 x_bytes{};
  secp256k1_xonly_pubkey_serialize(ctx, x_bytes.data(), &internal_xonly);
  sha256_hash_t tap_tweak{tagged_hash(x_bytes, {"TapTweak"})};

  // 2. compute tweaked private key
  // this turns d into (d + t) internally
  if (!secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tap_tweak.data()))
    return;

  // overwrite input priv bytes with tweaked priv key bytes
  secp256k1_keypair_sec(ctx, private_key.data(), &keypair);
}

byte_array_t create_op_return() {
  byte_array_t script{};

  constexpr u8 OP_RETURN{0x6a};
  std::string_view name{"winterrdog"};
  script.reserve(name.size() + 1 + 1);

  // script: [OP_RETURN] [PUSH_COUNT] [DATA]
  script.push_back(OP_RETURN);
  script.push_back(static_cast<u8>(name.size()));
  std::ranges::copy(name, std::back_inserter(script));

  return script;
}

// Create a transaction that spends a p2tr key-path utxo to a 2-of-2 multisig
// p2tr script-path program and return both the txid and the final transaction
// as hex strings
std::pair<std::string, std::string> spend_p2tr_keypath(secp256k1_context* ctx,
                                                       State& state) {
  constexpr double AMT = 0.01000000;  // 0.01000000 BTC
  constexpr double FEE = 0.00001000;  // 0.00001000 BTC

  // Choose an unspent coin worth more than 0.01 BTC
  outpoint_ser_t tgt_outpoint_bytes;
  BitcoinAmt amount{BitcoinAmt::fromBTC(AMT)};
  BitcoinAmt fee{BitcoinAmt::fromBTC(FEE)};
  BitcoinAmt total_bill{amount + fee};

  Utxo tgt_utxo;
  for (auto& [ser_outpoint, utxo] : state.utxos) {
    if (utxo.value > total_bill) {
      tgt_utxo = utxo;
      tgt_outpoint_bytes = ser_outpoint;
      break;
    }
  }

  // Create the input from the utxo
  Outpoint tgt_outpoint{Outpoint::deserialize(tgt_outpoint_bytes)};
  byte_array_t spend_input{input_from_utxo(tgt_outpoint)};

  // Compute destination output script
  std::array<secp256k1_xonly_pubkey, 2> pub_keys{};
  pub_keys[0] = get_compressed_pubkey_x_only(ctx, state.pubs[0]);  // key1
  pub_keys[1] = get_compressed_pubkey_x_only(ctx, state.pubs[1]);  // key2
  byte_array_t output_script{create_multisig_script(ctx, pub_keys)};

  // Compute taptree root
  sha256_hash_t taptree_root{get_taptree_root(output_script)};

  // Compute witness program from taptree root and "NUMS" internal key
  secp256k1_xonly_pubkey nums_xonly_pubkey{get_nums(ctx)};
  witness_program_t multisig_witness_program{
      get_p2tr_scriptpath_program(ctx, &nums_xonly_pubkey, taptree_root)};

  // compute output for multisig i.e. 0.01 BTC
  byte_array_t multisig_output{
      output_from_options(multisig_witness_program, amount.getSats())};

  // Get a change output script (one of our wallet's witness programs) and
  // create a change output. return change to first key's wit_prog
  witness_program_t change_witness_program{state.programs[0]};
  BitcoinAmt change{tgt_utxo.value - total_bill};
  byte_array_t change_output{
      output_from_options(change_witness_program, change.getSats())};

  // Get the message to sign (key paths hv no taptrees)
  witness_program_t utxo_witness_program{tgt_utxo.scriptpubkey};
  std::vector<std::span<const u8>> outputs = {multisig_output, change_output};
  sha256_hash_t sig_hash{
      get_commitment_hash(tgt_outpoint_bytes, utxo_witness_program,
                          tgt_utxo.value.getSats(), outputs, 0, {})};

  // Fetch the private key we need to sign with
  secret_key_t private_key{
      get_private_key_for_program(utxo_witness_program, state)};

  // Might need to negate original wallet private key before continuing
  maybe_negate_priv(ctx, private_key);

  // Tweak the private key according to
  // https://github.com/bitcoin/bips/blob/master/bip-0386.mediawiki#tr
  compute_tweaked_priv_key(ctx, private_key);

  // Sign and Assemble
  byte_array_t sig64{get_p2tr_keypath_witness(ctx, private_key, sig_hash)};
  std::vector<std::span<const u8>> witnesses = {sig64};
  std::vector<std::span<const u8>> inputs = {spend_input};
  std::string raw_tx{assemble_transaction(inputs, outputs, witnesses)};

  // Reserialize without witness data and double-SHA256 to get the txid
  std::string txid{get_txid(inputs, outputs)};

  // ==== UPDATE STATE!! since u burnt the coins ====

  // remove the spent utxo
  state.utxos.erase(tgt_outpoint_bytes);

  Outpoint new_outpoint{Outpoint::from_str(txid, 0)};
  Outpoint change_outpoint{Outpoint::from_str(txid, 1)};

  //  register the new multisig utxo (at index 0)
  Utxo multisig_utxo;
  multisig_utxo.value = amount;
  multisig_utxo.scriptpubkey = multisig_witness_program;
  state.utxos[new_outpoint.serialize()] = multisig_utxo;

  // register change utxo (at index 1)
  Utxo change_utxo;
  change_utxo.value = change;
  change_utxo.scriptpubkey = change_witness_program;
  state.utxos[change_outpoint.serialize()] = change_utxo;

  return {txid, raw_tx};
}

// Create a transaction that spends a 2-of-2 multisig p2tr script-path utxo to a
// an OP_RETURN output that contains YOUR GITHUB HANDLE as a string!
// Return the final transaction as a hex string.
std::string spend_p2tr_scriptpath(secp256k1_context* ctx,
                                  const State& state,
                                  const std::string& txid) {
  constexpr double AMT = 0.00000;
  constexpr double FEE = 0.00001;

  BitcoinAmt amount{BitcoinAmt::fromBTC(AMT)};
  BitcoinAmt fee{BitcoinAmt::fromBTC(FEE)};
  BitcoinAmt total_bill{amount + fee};

  // Create the input from the utxo
  // note: reverse the txid hash from human-readable JSON format to bitcoin wire
  // format -- done in the from_str() static method
  u32 output_index{0x0};
  Outpoint input_outpoint{Outpoint::from_str(txid, output_index)};
  byte_array_t script_path_input{input_from_utxo(input_outpoint)};

  outpoint_ser_t input_outpoint_bytes{input_outpoint.serialize()};
  Utxo tgt_utxo{state.utxos.at(input_outpoint_bytes)};

  // Compute destination output script and output
  byte_array_t dest_output_script{create_op_return()};
  byte_array_t op_return_output{
      output_from_options(dest_output_script, amount.getSats())};

  // Compute change output script and output
  witness_program_t change_witness_program{state.programs[0]};
  BitcoinAmt change{tgt_utxo.value - total_bill};
  byte_array_t change_output{
      output_from_options(change_witness_program, change.getSats())};

  // Get taproot spending data //

  //   Compute taptree root from the original multisig script
  std::array<secp256k1_xonly_pubkey, 2> pub_keys{};
  pub_keys[0] = (get_compressed_pubkey_x_only(ctx, state.pubs[0]));  // key1
  pub_keys[1] = (get_compressed_pubkey_x_only(ctx, state.pubs[1]));  // key2
  byte_array_t output_script{create_multisig_script(ctx, pub_keys)};

  sha256_hash_t taptree_root{get_taptree_root(output_script)};

  //   Compute witness program from taptree root and "NUMS" internal key
  secp256k1_xonly_pubkey nums_xonly_pubkey{get_nums(ctx)};

  witness_program_t prev_witness{
      get_p2tr_scriptpath_program(ctx, &nums_xonly_pubkey, taptree_root)};

  if (prev_witness != tgt_utxo.scriptpubkey) {
    throw std::runtime_error(
        "utxo scriptpubkey does not match calculated witness.");
  }

  //   Determine if the output key (which is a tweaked internal key) has an odd
  //   Y-coordinate
  bool parity_bit{get_p2tr_scriptpath_program_parity_bit(
      ctx, &nums_xonly_pubkey, taptree_root)};

  // Get the message to sign
  std::vector<std::span<const u8>> outputs = {op_return_output, change_output};
  sha256_hash_t sig_hash{
      get_commitment_hash(input_outpoint_bytes, tgt_utxo.scriptpubkey,
                          tgt_utxo.value.getSats(), outputs, 1, taptree_root)};

  // Sign and Assemble
  std::vector<secret_key_t> private_keys = {state.privs[0], state.privs[1]};
  byte_array_t witness{
      get_p2tr_scriptpath_witness(ctx, private_keys, sig_hash, parity_bit)};

  std::vector<std::span<const u8>> witnesses = {witness};
  std::vector<std::span<const u8>> inputs = {script_path_input};

  return assemble_transaction(inputs, outputs, witnesses);
}
