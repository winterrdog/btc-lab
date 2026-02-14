#include "balance.hh"

// Deserialize the extended key bytes and return an ExtendedKey object
ExtendedKey deserialize_key(const byte_array& data) {
  ExtendedKey key{};
  const u8* next = data.data();

  // version (4 bytes)
  std::memcpy(key.version.data(), next, key.version.size());
  next += key.version.size();

  // depth (1 byte)
  std::memcpy(&key.depth, next, sizeof(u8));
  next += sizeof(u8);

  // fingerprint (4 bytes)
  std::memcpy(key.fingerprint.data(), next, key.fingerprint.size());
  next += key.fingerprint.size();

  // index (4 bytes)
  std::memcpy(key.index.data(), next, key.index.size());
  next += key.index.size();

  // chaincode (32 bytes)
  std::memcpy(key.chaincode.data(), next, key.chaincode.size());
  next += key.chaincode.size();

  // explicitly add the "0x00" byte at the start of the key array
  key.key[0] = 0x00;

  // Skip the leading zero byte in the source data (the tprv padding)
  next += 1;

  // Copy exactly 32 bytes into the rest of the key array (indices 1 to 32)
  std::memcpy(key.key.data() + 1, next, 32);

  return key;
}

// Compute a tagged hash as defined in
// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#design
sha256_hash_t tagged_hash(const byte_array& data, const std::string& tag) {
  // sha256 hash the tag to get hashA
  sha256_hash_t hashA{};  // hash of the input tag
  byte_array tag_vec(tag.begin(), tag.end());
  sha256(tag_vec, static_cast<u8* const>(hashA.data()));

  // concatenate hashA, hashA and data to get combined data
  // and then get the tagged hash
  byte_array all_data{};
  all_data.reserve(data.size() + (hashA.size() * 2));
  all_data.insert(all_data.end(), hashA.begin(), hashA.end());  // hashA
  all_data.insert(all_data.end(), hashA.begin(), hashA.end());  // hashA
  all_data.insert(all_data.end(), data.begin(), data.end());    // data

  sha256_hash_t tag_hash{};
  sha256(all_data, static_cast<u8* const>(tag_hash.data()));

  // NOTE:
  // i could have just used libsecp256k1 like below, but i was here to learn.
  // secp256k1_tagged_sha256(ctx, tag_hash.data(), reinterpret_cast<const
  // u8*>(tag.c_str()), tag.size(),
  //                         data.data(), data.size());

  return tag_hash;
}

// Derive the secp256k1 compressed public key from a given private key
// BONUS POINTS: Implement secp256k1 yourself and multiply your key by the
// generator point!
pub_key_t get_pub_from_priv(secp256k1_context* ctx, const secret_key_t& priv) {
  // create uncompressed public key
  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv.data())) {
    throw std::runtime_error("Invalid private key");
  }

  // convert opaque secp256k1_pubkey struct into a compressed public key of 33
  // bytes
  pub_key_t key;
  size_t key_size = key.size();
  secp256k1_ec_pubkey_serialize(ctx, key.data(), &key_size, &pubkey,
                                SECP256K1_EC_COMPRESSED);

  return key;
}

// Perform a BIP32 parent private key -> child private key operation
// Return a JSON object with "key" and "chaincode" properties as bytes
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Private_parent_key_rarr_private_child_key
Bip32Key derive_priv_child(secp256k1_context* ctx,
                           const secret_key_t& key,
                           const chaincode_t& chaincode,
                           u32 index,
                           bool hardened) {
  auto u32_to_msb_array = [](u32 value) -> std::array<u8, 4> {
    return {
        static_cast<u8>(value >> 24),  // msb
        static_cast<u8>(value >> 16), static_cast<u8>(value >> 8),
        static_cast<u8>(value)  // lsb
    };
  };

  sha512_hash_t hmac{};
  if (hardened || index >= 0x80000000) {
    // use parent private key. hardened keys ALWAYS have an index >= 2^31
    byte_array all_data{};
    all_data.reserve(1 + sizeof(u32) + key.size());
    all_data.push_back(0x00);
    all_data.insert(all_data.end(), key.begin(), key.end());

    std::array<u8, 4> index_bytes{u32_to_msb_array(index)};
    all_data.insert(all_data.end(), index_bytes.begin(), index_bytes.end());

    byte_array chaincode_bytes{chaincode.begin(), chaincode.end()};
    hmac_sha512(chaincode_bytes, all_data, hmac);
  } else {
    // use parent public key
    pub_key_t parent_pubkey{get_pub_from_priv(ctx, key)};

    byte_array all_data{};
    all_data.reserve(sizeof(u32) + parent_pubkey.size());
    all_data.insert(all_data.end(), parent_pubkey.begin(), parent_pubkey.end());

    std::array<u8, 4> index_bytes{u32_to_msb_array(index)};
    all_data.insert(all_data.end(), index_bytes.begin(), index_bytes.end());

    byte_array chaincode_bytes{chaincode.begin(), chaincode.end()};
    hmac_sha512(chaincode_bytes, all_data, hmac);
  }

  // split 512 hash into 2 i.e. key tweak/distance and child chaincode
  byte_array tweak(hmac.begin(), hmac.begin() + 32);

  chaincode_t child_chaincode;
  std::memcpy(child_chaincode.data(), hmac.data() + 32, 32);

  // does tweak happen to be on the secp256k1 curve
  if (!secp256k1_ec_seckey_verify(ctx, tweak.data())) {
    // note:
    // chance of this happening is lower than
    // "1 in 2^127" i.e. very unlikely to happen
    return {};
  }

  // create Bip32Key struct and return that
  Bip32Key priv_child;
  priv_child.chaincode = child_chaincode;
  priv_child.key = key;  // will be modified in-place
                         // by secp256k1_ec_seckey_tweak_add()

  // add the parent priv key to the tweak using EC Point Addition
  if (!secp256k1_ec_seckey_tweak_add(ctx, priv_child.key.data(),
                                     tweak.data())) {
    return {};
  }

  return priv_child;
}

// Given a master secp256k1 SecretKey object, a chaincode as bytes, and a BIP32
// derivation path, compute the first 2000 child private keys. Return an array
// of keys encoded as secp256k1 SecretKey objects. The derivation path is
// formatted as an array of (index: int, hardened: bool) tuples.
std::vector<secret_key_t> get_wallet_privs(
    secp256k1_context* ctx,
    const secret_key_t& key,
    const chaincode_t& chaincode,
    const std::vector<std::pair<u32, bool>>& deriv_path) {
  constexpr u32 CHILD_KEY_CNT = 2'000;

  std::vector<secret_key_t> priv_keys;
  priv_keys.reserve(CHILD_KEY_CNT);

  // traverse to the parent node in the derivation path
  Bip32Key parent_node{key, chaincode};
  for (const auto& step : deriv_path) {
    parent_node = derive_priv_child(ctx, parent_node.key, parent_node.chaincode,
                                    step.first, step.second);
  }

  // loop 2,000 times creating
  // a new bip32key sibling key from the parent node each time, then appending
  // it to the array
  Bip32Key child_node{};
  for (u32 i = 0; i != CHILD_KEY_CNT; ++i) {
    // derive keys from the parent, not the previous child
    child_node = derive_priv_child(ctx, parent_node.key, parent_node.chaincode,
                                   i, false);

    if (!std::all_of(child_node.key.begin(), child_node.key.end(),
                     [](u8 b) { return b == 0x00; })) {
      priv_keys.push_back(child_node.key);
    }
  }

  return priv_keys;
}

// Derive the p2tr witness program for a given public key as a secp256k1
// PublicKey object. Return a bytes array to be compared with the ScriptPubKey
// in transaction outputs in the JSON response from Bitcoin Core RPC getblock so
// we can determine if the transaction output is "received" by our wallet. These
// are SegWit version 1 pay-to-taproot witness programs.
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#script-validation-rules
// ref: https://learnmeabitcoin.com/technical/upgrades/taproot
witness_program_t get_p2tr_keypath_program(secp256k1_context* ctx,
                                           const pub_key_t& pubkey) {
  // Get the 32-byte X coordinate from the public key (P2TR only uses this)
  secp256k1_pubkey full_pubkey;
  if (!secp256k1_ec_pubkey_parse(ctx, &full_pubkey, pubkey.data(),
                                 pubkey.size())) {
    return {};
  }

  secp256k1_xonly_pubkey internal_xonly;
  secp256k1_xonly_pubkey_from_pubkey(
      ctx, &internal_xonly, nullptr,
      &full_pubkey);  // forces an even Y-coordinate

  // Compute the TapTweak (no script tree thus no merkle root hash needed)
  std::array<u8, 32> internal_x_bytes;
  secp256k1_xonly_pubkey_serialize(ctx, internal_x_bytes.data(),
                                   &internal_xonly);

  sha256_hash_t tap_tweak;
  {
    std::string tag{"TapTweak"};
    byte_array bytes(internal_x_bytes.begin(), internal_x_bytes.end());
    tap_tweak = tagged_hash(bytes, tag);
  }

  // Q = P + (tap_tweak * G), where tag_tweak = tagged_hash("TapTweak",
  // internal_pubkey) Compute the output public key by tweaking the internal key
  // https://github.com/bitcoin/bips/blob/master/bip-0386.mediawiki#tr
  secp256k1_pubkey tweaked_pubkey;
  if (!secp256k1_xonly_pubkey_tweak_add(
          ctx,
          &tweaked_pubkey,  // This function takes the struct pointer
          &internal_xonly, tap_tweak.data())) {
    return {};
  }

  // convert the tweaked pubkey to xonly to extract the x-coordinate
  secp256k1_xonly_pubkey output_xonly;
  secp256k1_xonly_pubkey_from_pubkey(ctx, &output_xonly, nullptr,
                                     &tweaked_pubkey);

  // extract the x-coordinate of Q for the witness program
  constexpr u8 HASH_LENGTH = 32;
  std::array<u8, HASH_LENGTH> q_bytes;
  secp256k1_xonly_pubkey_serialize(ctx, q_bytes.data(), &output_xonly);

  // Compile the version 1 witness program
  // https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-Witness_program
  witness_program_t prog;
  prog[0] = 0x51;  // OP_1
  prog[1] = HASH_LENGTH;
  std::memcpy(prog.data() + 2, q_bytes.data(), HASH_LENGTH);

  return prog;
}

static std::vector<std::pair<u32, bool>> parse_deriv_path(
    const std::string& deriv_path) {
  std::vector<std::pair<u32, bool>> path;

  std::stringstream ss{deriv_path};  // deriv paths look like "86h/1h/0h/0"
  for (std::string segment{}; std::getline(ss, segment, '/');) {
    if (segment == "m" || segment.empty()) {
      continue;  // ignore master prefix ('m')
    } else {
      bool hardened = false;
      if (segment.back() == 'h' || segment.back() == '\'') {
        hardened = true;
        segment.pop_back();  // remove 'h' to parse the number
      }

      u32 index = std::stoul(segment);
      if (hardened) {
        index += 0x80000000;
      }
      path.push_back({index, hardened});
    }
  }

  return path;
}

State recover_wallet_state(secp256k1_context* ctx, const std::string& xprv) {
  // Initialize State
  State state;
  state.pubs.reserve(2'000);
  state.programs.reserve(2'000);

  // Generate all the keypairs and witness programs to search for

  ExtendedKey xpriv_key;

  {
    // decode xprv desc into bytes
    byte_array xprv_bytes{base58_decode(xprv)};

    // extract priv key and chaincode
    xpriv_key = deserialize_key(xprv_bytes);
  }

  // Derive the key and chaincode at the path in the descriptor (86h/1h/0h/0)
  // and derive 2000 private keys from that path
  std::string deriv_path{"86h/1h/0h/0"};
  std::vector<std::pair<u32, bool>> parsed_deriv_paths =
      parse_deriv_path(deriv_path);

  // pass in the 32-byte priv key to derivation function
  secret_key_t actual_priv;
  std::memcpy(actual_priv.data(), xpriv_key.key.data() + 1, 32);
  state.privs = get_wallet_privs(ctx, actual_priv, xpriv_key.chaincode,
                                 parsed_deriv_paths);

  pub_key_t pub;
  witness_program_t program;
  for (const auto& priv : state.privs) {
    pub = get_pub_from_priv(ctx, priv);
    program = get_p2tr_keypath_program(ctx, pub);

    state.pubs.push_back(pub);
    state.programs.push_back(program);
  }

  // pre-encode/compute witness programs into a set
  std::unordered_set<std::string> tgt_witness_hexes{};
  {
    byte_array bytes{};
    for (const auto& program : state.programs) {
      bytes = byte_array(program.begin(), program.end());
      tgt_witness_hexes.insert(Hex::Encode(bytes));
    }
  }

  // Scan for the "first 300" blocks
  json blocks = fetch_300_blocks_to_json();
  for (const auto& block : blocks) {
    // Scan every tx in every block
    if (!block.contains("tx") || !block["tx"].is_array())
      continue;

    auto txs = block["tx"];
    for (const auto& tx : txs) {
      // NOTE: process RECEIVES first, then SPENDS next

      // Check every tx output for our own witness programs.
      // These are coins we have received.
      if (tx.contains("vout") && tx.contains("txid")) {
        std::string txid = tx["txid"];

        for (const auto& vout : tx["vout"]) {
          if (!(vout.contains("value") && vout.contains("n")))
            continue;

          if (!(vout.contains("scriptPubKey") &&
                vout["scriptPubKey"].contains("hex") &&
                vout["scriptPubKey"].contains("type"))) {
            continue;
          }

          // check for our witness program.
          std::string script_pubkey_type = vout["scriptPubKey"]["type"];
          if ("witness_v1_taproot" != script_pubkey_type)
            continue;

          std::string witness_program_hex = vout["scriptPubKey"]["hex"];
          // std::cout << "! " << witness_program_hex << "\n";
          if (tgt_witness_hexes.count(witness_program_hex) == 0)
            continue;

          // std::cout << "+ " << witness_program_hex << ": MATCH FOUND!!\n";

          Outpoint outpoint = Outpoint::from_str(txid, vout["n"].get<u32>());

          // make utxo
          Utxo utxo;
          utxo.value = BitcoinAmt::fromBTC(vout["value"].get<double>());

          byte_array scriptpubkey_vec =
              Hex::Decode(std::string(vout["scriptPubKey"]["hex"]));
          std::memcpy(utxo.scriptpubkey.data(), scriptpubkey_vec.data(), 34);

          // Add to our total balance
          state.balance = state.balance + utxo.value;

          // Track this UTXO by its outpoint in case we spend it later
          auto utxo_key = outpoint.serialize();
          state.utxos[utxo_key] = utxo;
        }
      }

      // Check every tx input for our own utxos, by their outpoint (vout & txid)
      // These are coins we have spent.
      if (tx.contains("vin") && tx["vin"].is_array()) {
        for (const auto& vin : tx["vin"]) {
          if (!(vin.contains("txid") && vin.contains("vout")))
            continue;

          std::string txid = vin["txid"];
          Outpoint outpoint = Outpoint::from_str(txid, vin["vout"].get<u32>());

          auto utxo_key = outpoint.serialize();
          if (state.utxos.count(utxo_key) > 0) {
            // Remove this found coin from our wallet state utxo pool
            // so we don't double spend it later and deduct from our balance
            auto utxo = state.utxos[utxo_key];
            state.balance = state.balance - utxo.value;
            state.utxos.erase(utxo_key);
          }
        }
      }
    }
  }

  return state;
}
