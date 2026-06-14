#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace totp {

// Decode an RFC 4648 base32 string (the encoding used by otpauth secrets).
//
// Lower/upper case is accepted, spaces and '-' separators are ignored, and an
// optional '=' pad is tolerated. Returns false if any non-alphabet character is
// present. An empty/whitespace-only input decodes to an empty buffer and
// returns true.
bool base32Decode(const std::string &input, std::vector<uint8_t> &out);

// Encode bytes to an unpadded upper-case base32 string (handy for tests and for
// showing a secret back to the user).
std::string base32Encode(const uint8_t *data, size_t len);

}  // namespace totp
