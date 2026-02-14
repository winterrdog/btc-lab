#include "./balance/balance.hh"
#include "./common/common.hh"
#include "./spend/spend.hh"

int main(int argc, const char* argv[]) {
  if (argc < 2) {
    std::cerr << "usage: " << argv[0] << " <command>\n";
    std::cerr << "commands: balance, spend\n";
    return 1;
  }

  const std::string WALLET_NAME{"wallet_202"};
  const std::string EXTENDED_PRIVATE_KEY{
      "tprv8ZgxMBicQKsPczPoEAq9MvqLaR8eHmzSaq4xAMsRgB1NMF9dGX4Qyd9z9LBJ4GKfUX8y"
      "szCwkASZtaG1SqPXa3KVKJoHyDhRhvxRkB7opAH"};

  SecpContext sc{};  // SecpContext has RAII
  State state{recover_wallet_state(sc, EXTENDED_PRIVATE_KEY)};
  std::string command(argv[1]);
  if (command == "balance") {
    std::cout << WALLET_NAME << " " << state.balance.to_string() << "\n";
  } else if (command == "spend") {
    auto [txid, tx1] = spend_p2tr_keypath(sc, state);
    std::string tx2{spend_p2tr_scriptpath(sc, state, txid)};
    std::cout << tx1 << "\n" << tx2 << "\n";

    // Un-comment the line below to test your answer locally
    // Don't submit your code like that though or autograder will fail!
    // std::cout << bcli(base_cmd + "testmempoolaccept [\"" + tx1 + "\",\"" +
    // tx2 + "\"]")
    // << "\n";
  }

  return 0;
}
