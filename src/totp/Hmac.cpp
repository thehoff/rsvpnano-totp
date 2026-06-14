#include "totp/Hash.h"

namespace totp {
namespace {

std::vector<uint8_t> hashWith(HashType type, const uint8_t *data, size_t len) {
  switch (type) {
    case HashType::Sha256:
      return sha256(data, len);
    case HashType::Sha512:
      return sha512(data, len);
    case HashType::Sha1:
    default:
      return sha1(data, len);
  }
}

}  // namespace

size_t hashDigestLength(HashType type) {
  switch (type) {
    case HashType::Sha256:
      return 32;
    case HashType::Sha512:
      return 64;
    case HashType::Sha1:
    default:
      return 20;
  }
}

size_t hashBlockSize(HashType type) {
  switch (type) {
    case HashType::Sha512:
      return 128;
    case HashType::Sha1:
    case HashType::Sha256:
    default:
      return 64;
  }
}

std::vector<uint8_t> hmac(HashType type, const uint8_t *key, size_t keyLen,
                          const uint8_t *message, size_t messageLen) {
  const size_t blockSize = hashBlockSize(type);

  // Keys longer than the block size are hashed down first (RFC 2104).
  std::vector<uint8_t> normalizedKey;
  if (keyLen > blockSize) {
    normalizedKey = hashWith(type, key, keyLen);
  } else {
    normalizedKey.assign(key, key + keyLen);
  }
  normalizedKey.resize(blockSize, 0x00);

  std::vector<uint8_t> inner;
  inner.reserve(blockSize + messageLen);
  for (size_t i = 0; i < blockSize; ++i) {
    inner.push_back(normalizedKey[i] ^ 0x36);
  }
  inner.insert(inner.end(), message, message + messageLen);
  const std::vector<uint8_t> innerHash = hashWith(type, inner.data(), inner.size());

  std::vector<uint8_t> outer;
  outer.reserve(blockSize + innerHash.size());
  for (size_t i = 0; i < blockSize; ++i) {
    outer.push_back(normalizedKey[i] ^ 0x5c);
  }
  outer.insert(outer.end(), innerHash.begin(), innerHash.end());
  return hashWith(type, outer.data(), outer.size());
}

}  // namespace totp
