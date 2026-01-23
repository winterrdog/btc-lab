#include "common.hh"

struct Hex {
  static std::vector<u8> hexToBytes(const std::string &hex) {
    // use strtoul
    std::vector<u8> buf{};

    u8 val{};
    for (int i = 0; i != hex.length(); i += 2) {
      char st[] = {hex[i], hex[i + 1], 0};

      char *end;
      val = static_cast<u8>(strtoul(st, &end, 16));
      buf.push_back(val);
    }

    return buf;
  }

  static std::string bytesToHex(const std::vector<u8> &data) {
    //   use snprintf
    std::string res{};
    char s[3]{};
    for (u8 byte : data) {
      snprintf(s, sizeof(s), "%02hhx", byte);
      res.append(s);
    }
    return res;
  }
};

/*
        you can test it like so:
*/

#ifdef DTEST

#include <iostream>

int main(int argc, char const *argv[]) {
  // test 1: Hex to Bytes
  std::string hexInput = "48656c6c6f"; // "Hello" in hex
  std::vector<u8> bytes = Hex::hexToBytes(hexInput);

  std::cout << "hex input: " << hexInput << std::endl;
  std::cout << "decoded chars: ";
  for (u8 b : bytes) {
    std::cout << (char)b;
  }
  std::cout << "\n\n";

  // test 2: Bytes to Hex
  std::vector<u8> dataToEncode = {0xde, 0xad, 0xbe, 0xef, 0x01};
  std::string hexOutput = Hex::bytesToHex(dataToEncode);

  std::cout << "byte input: { 0xDE, 0xAD, 0xBE, 0xEF, 0x01 }" << std::endl;
  std::cout << "encoded hex: " << hexOutput << std::endl;

  // validation
  if (hexToBytes(bytesToHex(dataToEncode)) == dataToEncode) {
    std::cout << "\ntest passed!" << std::endl;
  }

  return 0;
}

#endif