#include "./common.hh"

std::string read_file(const fs::path& path) {
  std::ifstream file(path);
  if (!file)
    throw std::runtime_error("- failed to open file: " + path.string());

  std::stringstream buffer{};
  buffer << file.rdbuf();
  return buffer.str();
}

std::string remove_whitespace(const std::string& str) {
  std::string result{};
  std::ranges::copy_if(str, std::back_inserter(result), [](char c) {
    return !std::isspace(static_cast<u8>(c));
  });
  return result;
}

void from_json(const json& j, Payment& p) {
  j.at("address").get_to(p.address);
  j.at("amount").get_to(p.amount);
  j.at("rate").get_to(p.rate);
}

void from_json(const json& j, Coin& c) {
  j.at("txid").get_to(c.txid);
  j.at("vout").get_to(c.vout);
  j.at("address").get_to(c.address);
  j.at("amount").get_to(c.amount);
}

std::string bcli(const std::string& cmd) {
  using pipe_ptr_t = std::unique_ptr<std::FILE, decltype(&pclose)>;

  std::ostringstream full_cmd;
  full_cmd << "bitcoin-cli"
           << " -regtest"
           << " -rpcuser=student"
           << " -rpcpassword=boss2026"
           << " " << cmd << " 2>&1";

  pipe_ptr_t pipe{popen(full_cmd.str().c_str(), "r"), pclose};
  if (!pipe)
    throw std::runtime_error("bitcoin-cli command failed");

  std::string result{};
  std::array<char, 128> buffer{};
  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    result += buffer.data();
  }

  // remove trailing spaces
  while (!result.empty() && (result.back() == '\n')) {
    result.pop_back();
  }

  return result;
}
