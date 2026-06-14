#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "totp/Hash.h"

namespace totp {

// Parameters shared by an OTP account, with the common authenticator defaults.
struct OtpParams {
  HashType algorithm = HashType::Sha1;
  uint8_t digits = 6;       // 6 or 8 in practice
  uint32_t periodSeconds = 30;  // TOTP step (RFC 6238 default)
};

// HOTP (RFC 4226): counter-based one-time password from a raw shared secret.
// Returns the zero-padded code of the requested digit length.
std::string hotp(const uint8_t *secret, size_t secretLen, uint64_t counter,
                 uint8_t digits = 6, HashType algorithm = HashType::Sha1);

// TOTP (RFC 6238): time-based code. `unixTime` is seconds since the epoch.
std::string totpAt(const uint8_t *secret, size_t secretLen, uint64_t unixTime,
                   const OtpParams &params = OtpParams());

// Seconds remaining in the current TOTP window for the given time/period.
uint32_t totpSecondsRemaining(uint64_t unixTime, uint32_t periodSeconds = 30);

}  // namespace totp
