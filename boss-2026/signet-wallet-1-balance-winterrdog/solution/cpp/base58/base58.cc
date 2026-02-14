#include "base58.hh"

std::string base58_encode(const byte_array& input) {
  if (input.empty())
    return "";

  std::string result{};
  byte_array temp = input;  // mutate local copy not original data

  // count leading zeros
  int leading_zeros{0};
  for (u8 byte : input) {
    if (byte != 0)
      break;
    leading_zeros++;
  }

  // treat input as one large integer
  // keep dividing by input 58 till the input is all zeros. feels like long
  // division
  int rem;
  bool allZero;
  for (;;) {
    // NOTE:
    // since n will always be small we do not care if it's O(n^2)

    rem = 0;
    allZero = true;

    /*
      we use long division.
      if there's a carry over u add it to the current byte.

      mental model:
        In standard base-10 long division (like 432÷5),
        if you divide the first digit (4÷5), the answer is 0
        with a remainder of 4.

        When you move to the next digit (3), you don't just divide
        3÷5. You "carry" that 4 over. Because that 4 was in the "hundreds"
      place, it's actually worth 4×10 when it moves to the "tens" place. So you
      divide 43 by 5.
    */
    for (size_t i = 0; i != temp.size(); ++i) {
      // (rem<<8) is == to carrying over in long division. OR just combines the
      // bits
      int curr_val = temp[i] | (rem << 8);

      temp[i] = curr_val / 58;
      rem = curr_val % 58;

      if (temp[i] != 0)
        allZero = false;
    }

    // map remainder to char set
    result += BASE58_CHAR_SET[rem];

    if (allZero)
      break;
  }

  // cleanup up any false-positive leading zeros that appear
  // after the math at the end of the result. these can
  // to wrong encodings after reversing cuz they will be interpreted as zeros
  // that the data had
  while (result.size() > 1 && result.back() == BASE58_CHAR_SET[0]) {
    result.pop_back();
  }

  for (int i = 0; i != leading_zeros; ++i) {
    result += BASE58_CHAR_SET[0];
  }

  // flip the result cuz division gives us the digits in right-to-left format
  std::reverse(result.begin(), result.end());

  return result;
}

byte_array base58_decode(const std::string& b58) {
  if (b58.empty())
    return {};

  byte_array result{};
  const std::string ALPHABET = std::string(BASE58_CHAR_SET);

  for (const char c : b58) {
    // find char index in char set
    size_t index = ALPHABET.find(c);
    if (index == std::string::npos) {
      throw std::runtime_error("Invalide base58 character.");
    }

    int carry = static_cast<int>(index);

    // accumulatively convert to base58 by repeated multiplication and adding
    // the carry. start from the right to left, like it happens naturally
    for (int i = result.size() - 1; i >= 0; --i) {
      int curr_val = (result[i] * 58) + carry;

      result[i] = curr_val % 256;
      carry = curr_val / 256;  // carry overflow to the left
    }

    // extend the result's size if there's still more carry values
    while (carry > 0) {
      result.insert(result.begin(), carry % 256);
      carry /= 256;
    }
  }

  // add leading zero bytes to the start of the result
  int leading_zeros = 0;
  for (char c : b58) {
    if (c != BASE58_CHAR_SET[0]) {
      break;
    }
    leading_zeros++;
  }

  byte_array final_output(leading_zeros, 0x0);
  final_output.insert(final_output.end(), result.begin(), result.end());

  // If the original encoding had a zero-value that was NOT a leading zero,
  // the math loop might leave a stray 0x00 at the front.
  // we trim one leading zero if the vector is larger than 1.
  if (final_output.size() > 1 && final_output[leading_zeros] == 0) {
    final_output.erase(final_output.begin() + leading_zeros);
  }

  // verify checksum
  if (final_output.size() < 4) {
    throw std::runtime_error("Input too short to contain a checksum.");
  }

  byte_array checksum(final_output.end() - 4, final_output.end());

  u8 hash[SHA256_HASH_LENGTH]{};
  byte_array original(final_output.begin(), final_output.end() - 4);
  HASH256(original, hash);

  for (int i = 0; i < 4; ++i) {
    if (hash[i] != checksum[i]) {
      throw std::runtime_error("failed checksum validation. data is corrupt.");
    }
  }

  return original;
}

static byte_array prep_base58_payload(const byte_array& original) {
  u8 hash[SHA256_HASH_LENGTH]{};
  HASH256(original, hash);

  // append first 4 bytes of hash
  byte_array payload = original;
  for (int i = 0; i < 4; ++i)
    payload.push_back(hash[i]);

  return payload;
}

// tests

#ifdef DTEST

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

// Helper to print bytes as Hex
void print_hex(const std::string& label, const byte_array& bytes) {
  std::cout << label << ": ";
  for (u8 b : bytes) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
  }
  std::cout << std::dec << std::endl;
}

int main() {
  try {
    // 1. The Genesis Address
    std::string b58_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    std::cout << "Input Base58: " << b58_address << std::endl;

    // 2. Test Decoding
    byte_array decoded = base58_decode(b58_address);
    print_hex("Decoded Hex ", decoded);

    // Expected result for comparison:
    // 0062e907b15cbf27d5425399ebf6f0fb50ebb88f18

    // 3. Test Encoding back
    // (Note: To encode back to the address, you'd need a base58_encode_check
    // wrapper that adds the checksum back before calling your base58_encode)

    std::cout
        << "\nStatus: If the hex matches 0062e9...f18, your code is perfect!"
        << std::endl;

  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
  }

  return 0;
}
#endif
