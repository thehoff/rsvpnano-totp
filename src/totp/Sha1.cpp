#include "totp/Hash.h"

namespace totp {
namespace {

inline uint32_t rotl32(uint32_t value, int bits) {
  return (value << bits) | (value >> (32 - bits));
}

}  // namespace

std::vector<uint8_t> sha1(const uint8_t *data, size_t len) {
  uint32_t h0 = 0x67452301u;
  uint32_t h1 = 0xEFCDAB89u;
  uint32_t h2 = 0x98BADCFEu;
  uint32_t h3 = 0x10325476u;
  uint32_t h4 = 0xC3D2E1F0u;

  // Pad: 0x80, then zeros, then 64-bit big-endian bit length.
  const uint64_t bitLen = static_cast<uint64_t>(len) * 8u;
  std::vector<uint8_t> msg(data, data + len);
  msg.push_back(0x80);
  while (msg.size() % 64 != 56) {
    msg.push_back(0x00);
  }
  for (int i = 7; i >= 0; --i) {
    msg.push_back(static_cast<uint8_t>((bitLen >> (i * 8)) & 0xFF));
  }

  for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
      const size_t b = chunk + static_cast<size_t>(i) * 4;
      w[i] = (static_cast<uint32_t>(msg[b]) << 24) |
             (static_cast<uint32_t>(msg[b + 1]) << 16) |
             (static_cast<uint32_t>(msg[b + 2]) << 8) |
             (static_cast<uint32_t>(msg[b + 3]));
    }
    for (int i = 16; i < 80; ++i) {
      w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    for (int i = 0; i < 80; ++i) {
      uint32_t f, k;
      if (i < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999u;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1u;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDCu;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6u;
      }
      const uint32_t tmp = rotl32(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = rotl32(b, 30);
      b = a;
      a = tmp;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  std::vector<uint8_t> out(20);
  const uint32_t h[5] = {h0, h1, h2, h3, h4};
  for (int i = 0; i < 5; ++i) {
    out[i * 4 + 0] = static_cast<uint8_t>((h[i] >> 24) & 0xFF);
    out[i * 4 + 1] = static_cast<uint8_t>((h[i] >> 16) & 0xFF);
    out[i * 4 + 2] = static_cast<uint8_t>((h[i] >> 8) & 0xFF);
    out[i * 4 + 3] = static_cast<uint8_t>(h[i] & 0xFF);
  }
  return out;
}

}  // namespace totp
