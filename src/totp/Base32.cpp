#include "totp/Base32.h"

namespace totp {
namespace {

constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Map a base32 character to its 5-bit value, or -1 if it is not part of the
// alphabet. Separators handled by the caller.
int decodeChar(char c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a';
  }
  if (c >= '2' && c <= '7') {
    return 26 + (c - '2');
  }
  return -1;
}

}  // namespace

bool base32Decode(const std::string &input, std::vector<uint8_t> &out) {
  out.clear();
  uint32_t buffer = 0;
  int bitsLeft = 0;
  for (char c : input) {
    if (c == '=' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '-') {
      continue;  // padding / separators are ignored
    }
    const int value = decodeChar(c);
    if (value < 0) {
      out.clear();
      return false;
    }
    buffer = (buffer << 5) | static_cast<uint32_t>(value);
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      out.push_back(static_cast<uint8_t>((buffer >> bitsLeft) & 0xFF));
    }
  }
  return true;
}

std::string base32Encode(const uint8_t *data, size_t len) {
  std::string out;
  uint32_t buffer = 0;
  int bitsLeft = 0;
  for (size_t i = 0; i < len; ++i) {
    buffer = (buffer << 8) | data[i];
    bitsLeft += 8;
    while (bitsLeft >= 5) {
      bitsLeft -= 5;
      out.push_back(kAlphabet[(buffer >> bitsLeft) & 0x1F]);
    }
  }
  if (bitsLeft > 0) {
    out.push_back(kAlphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
  }
  return out;
}

}  // namespace totp
