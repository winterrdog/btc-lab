#include "./common/common.hh"

#include "./balance/balance.hh"

int main(int argc, char const* argv[]) {
  if (argc < 2 || std::string(argv[1]) != "balance") {
    std::cerr << "usage: " << argv[0] << " balance\n";
    return 1;
  }

  const std::string WALLET_NAME{"wallet_202"};
  const std::string EXTENDED_PRIVATE_KEY{
      "tprv8ZgxMBicQKsPczPoEAq9MvqLaR8eHmzSaq4xAMsRgB1NMF9dGX4Qyd9z9LBJ4GKfUX8y"
      "szCwkASZtaG1SqPXa3KVKJoHyDhRhvxRkB7opAH"};

  secp256k1_context* ctx;
  ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                 SECP256K1_CONTEXT_VERIFY);
  State state{recover_wallet_state(ctx, EXTENDED_PRIVATE_KEY)};
  secp256k1_context_destroy(ctx);

  std::cout << WALLET_NAME << " " << state.balance.to_string() << "\n";

  return 0;
}
