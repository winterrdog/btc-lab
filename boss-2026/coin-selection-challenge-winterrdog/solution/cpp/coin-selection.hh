#ifndef COIN_SELECTION_HH
#define COIN_SELECTION_HH 1

#include "./common.hh"

struct Payment {
  std::string address;
  double amount;
  double rate;
};

struct Coin {
  // Will be read and written as JSON to and from bitcoin-cli
  // so no need to parse as bytes or reverse byte-order.
  std::string txid;

  u64 vout;

  // Could also use scriptPubKey but it might be easier
  // to determine required spending conditions from an address.
  std::string address;

  double amount;
};

void make_payments(const std::vector<Payment>& payments);

#endif
