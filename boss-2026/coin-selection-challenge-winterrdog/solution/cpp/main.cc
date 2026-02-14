#include "./coin-selection.hh"
#include "./common.hh"

int main(void) {
  // Create wallet
  bcli("createwallet student false true");

  // Import descriptors
  // NOTE:
  // "PROJECT_DIR" is passed in as a define during compilation
  fs::path student_wallet{fs::path(PROJECT_DIR) / ".." / "datadir" /
                          "student_wallet.json"};
  std::string student_wallet_data{read_file(student_wallet)};
  std::string descriptors{remove_whitespace(student_wallet_data)};

  bcli("importdescriptors " + descriptors);

  // Import payments
  fs::path payments_file{fs::path(PROJECT_DIR) / ".." / "payments.json"};
  std::string payments_json{read_file(payments_file)};
  json payments_data{json::parse(payments_json)};
  std::vector<Payment> payments{payments_data.get<std::vector<Payment>>()};

  // Make payments
  make_payments(payments);

  return 0;
}
