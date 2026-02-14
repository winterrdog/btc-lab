#include "common.hh"

BitcoinAmt::BitcoinAmt(u64 sats) : satoshis(sats) {
  if (satoshis > MAX_MONEY) {
    throw std::out_of_range("Amount exceeds 21M BTC limit");
  }
}

BitcoinAmt BitcoinAmt::fromBTC(double btc) {
  // round to nearest satoshi
  return BitcoinAmt(static_cast<u64>(std::round(btc * 100'000'000.0)));
}

u64 BitcoinAmt::getSats() const {
  return satoshis;
}

std::string BitcoinAmt::to_string() const {
  char buf[32];
  double btc = static_cast<double>(satoshis) / COIN;

  // formats to exactly 8 decimal places
  snprintf(buf, sizeof(buf), "%.8f", btc);
  return std::string(buf);
}

BitcoinAmt BitcoinAmt::operator+(const BitcoinAmt& other) const {
  return BitcoinAmt(this->satoshis + other.satoshis);
}

BitcoinAmt BitcoinAmt::operator-(const BitcoinAmt& other) const {
  if (other.satoshis > this->satoshis) {
    throw std::underflow_error("Satoshi balance cannot be negative");
  }
  return BitcoinAmt(this->satoshis - other.satoshis);
}
