#include "./coin-selection.hh"

void make_payments(const std::vector<Payment>& payments) {
  // Make payments
  for (const Payment& payment : payments) {
    // Get all UTXO in wallet coin pool
    std::string list_unspent{bcli("listunspent")};

    // Objectify coins to spend
    json coins_json{json::parse(list_unspent)};
    std::vector<Coin> coins{coins_json.get<std::vector<Coin>>()};

    // Select coins

    // Create transaction
    std::string inputs{};
    std::string outputs{};
    std::string unsigned_tx{
        bcli("createrawtransaction " + inputs + " " + outputs)};

    // Sign transaction
    std::string signed_tx_res{
        bcli("signrawtransactionwithwallet " + unsigned_tx)};
    json signed_tx_json{json::parse(signed_tx_res)};
    std::string signed_tx{signed_tx_json["hex"].get<std::string>()};

    // Broadcast transaction without maxfeerate protection
    bcli("sendrawtransaction " + signed_tx + " 0");

    // Confirm transaciton
    bcli("generatetoaddress 1 bcrt1pqqqqrldkrl");
  }
}
