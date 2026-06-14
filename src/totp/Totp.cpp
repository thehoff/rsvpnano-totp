#include "totp/Totp.h"

namespace totp {
namespace {

// Power-of-ten table for digit truncation (RFC 4226 supports up to 8 digits;
// keep a couple of spares for safety).
uint32_t powerOfTen(uint8_t digits) {
  static const uint32_t kTable[11] = {1u,         10u,        100u,       1000u,
                                      10000u,     100000u,    1000000u,   10000000u,
                                      100000000u, 1000000000u, 1000000000u};
  if (digits > 10) {
    digits = 10;
  }
  return kTable[digits];
}

}  // namespace

std::string hotp(const uint8_t *secret, size_t secretLen, uint64_t counter, uint8_t digits,
                 HashType algorithm) {
  if (digits < 1) {
    digits = 6;
  }
  if (digits > 9) {
    digits = 9;  // a uint32 truncation can represent at most 9 reliable digits
  }

  // Counter is encoded as an 8-byte big-endian value.
  uint8_t message[8];
  for (int i = 7; i >= 0; --i) {
    message[i] = static_cast<uint8_t>(counter & 0xFF);
    counter >>= 8;
  }

  const std::vector<uint8_t> mac = hmac(algorithm, secret, secretLen, message, sizeof(message));

  // Dynamic truncation (RFC 4226 section 5.3).
  const size_t offset = mac[mac.size() - 1] & 0x0F;
  const uint32_t binary = ((static_cast<uint32_t>(mac[offset]) & 0x7F) << 24) |
                          ((static_cast<uint32_t>(mac[offset + 1]) & 0xFF) << 16) |
                          ((static_cast<uint32_t>(mac[offset + 2]) & 0xFF) << 8) |
                          (static_cast<uint32_t>(mac[offset + 3]) & 0xFF);

  const uint32_t code = binary % powerOfTen(digits);

  std::string out = std::to_string(code);
  while (out.size() < digits) {
    out.insert(out.begin(), '0');
  }
  return out;
}

std::string totpAt(const uint8_t *secret, size_t secretLen, uint64_t unixTime,
                   const OtpParams &params) {
  const uint32_t period = params.periodSeconds == 0 ? 30 : params.periodSeconds;
  const uint64_t counter = unixTime / period;
  return hotp(secret, secretLen, counter, params.digits, params.algorithm);
}

uint32_t totpSecondsRemaining(uint64_t unixTime, uint32_t periodSeconds) {
  if (periodSeconds == 0) {
    periodSeconds = 30;
  }
  return periodSeconds - static_cast<uint32_t>(unixTime % periodSeconds);
}

}  // namespace totp
