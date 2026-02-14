#ifndef COMMON_HH
#define COMMON_HH 1

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <json.hpp>
#include <memory>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

using u8 = unsigned char;
using u64 = unsigned long long;

using json = nlohmann::json;

std::string bcli(const std::string& cmd);
std::string read_file(const fs::path& path);
std::string remove_whitespace(const std::string& str);

// JSON serialization
void from_json(const json& j, Coin& c);
void from_json(const json& j, Payment& p);

#endif
