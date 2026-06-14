#pragma once

// Self-contained hashing + HMAC used by the TOTP engine.
//
// These implementations deliberately avoid Arduino and mbedTLS so the TOTP core
// compiles and runs unchanged on the host (unit tests / CI) and on the ESP32-S3
// firmware. SHA-1/256/512 are small, standard, and verified against the RFC
// 2202 / 4231 / 6234 test vectors in test/test_totp.

#include <cstddef>
#include <cstdint>
#include <vector>

namespace totp {

enum class HashType : uint8_t {
  Sha1 = 0,
  Sha256 = 1,
  Sha512 = 2,
};

// Raw digest of a message.
std::vector<uint8_t> sha1(const uint8_t *data, size_t len);
std::vector<uint8_t> sha256(const uint8_t *data, size_t len);
std::vector<uint8_t> sha512(const uint8_t *data, size_t len);

// Digest length in bytes for an algorithm (20 / 32 / 64).
size_t hashDigestLength(HashType type);

// Internal HMAC block size in bytes (64 for SHA-1/256, 128 for SHA-512).
size_t hashBlockSize(HashType type);

// Generic HMAC over one of the supported hashes (RFC 2104).
std::vector<uint8_t> hmac(HashType type, const uint8_t *key, size_t keyLen,
                          const uint8_t *message, size_t messageLen);

}  // namespace totp
