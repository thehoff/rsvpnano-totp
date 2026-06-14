#include "totp/AccountCodec.h"

#include <string>

namespace totp {
namespace {

void putU16(std::vector<uint8_t> &out, uint16_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void putU32(std::vector<uint8_t> &out, uint32_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

void putBlob(std::vector<uint8_t> &out, const uint8_t *data, size_t len) {
  // String/secret fields are capped so a malformed blob cannot request an
  // absurd allocation on decode.
  if (len > 0xFFFF) {
    len = 0xFFFF;
  }
  putU16(out, static_cast<uint16_t>(len));
  out.insert(out.end(), data, data + len);
}

struct Reader {
  const uint8_t *data;
  size_t len;
  size_t pos = 0;

  bool u8(uint8_t &value) {
    if (pos + 1 > len) return false;
    value = data[pos++];
    return true;
  }
  bool u16(uint16_t &value) {
    if (pos + 2 > len) return false;
    value = static_cast<uint16_t>(data[pos]) | (static_cast<uint16_t>(data[pos + 1]) << 8);
    pos += 2;
    return true;
  }
  bool u32(uint32_t &value) {
    if (pos + 4 > len) return false;
    value = static_cast<uint32_t>(data[pos]) | (static_cast<uint32_t>(data[pos + 1]) << 8) |
            (static_cast<uint32_t>(data[pos + 2]) << 16) |
            (static_cast<uint32_t>(data[pos + 3]) << 24);
    pos += 4;
    return true;
  }
  bool blob(std::vector<uint8_t> &out) {
    uint16_t n = 0;
    if (!u16(n)) return false;
    if (pos + n > len) return false;
    out.assign(data + pos, data + pos + n);
    pos += n;
    return true;
  }
  bool str(std::string &out) {
    std::vector<uint8_t> bytes;
    if (!blob(bytes)) return false;
    out.assign(bytes.begin(), bytes.end());
    return true;
  }
};

HashType clampAlgorithm(uint8_t raw) {
  switch (raw) {
    case static_cast<uint8_t>(HashType::Sha256):
      return HashType::Sha256;
    case static_cast<uint8_t>(HashType::Sha512):
      return HashType::Sha512;
    default:
      return HashType::Sha1;
  }
}

}  // namespace

std::vector<uint8_t> serializeAccounts(const std::vector<TotpAccount> &accounts) {
  std::vector<uint8_t> out;
  out.push_back(kAccountBlobMagic);
  out.push_back(kAccountBlobVersion);

  uint16_t count = accounts.size() > 0xFFFF ? 0xFFFF : static_cast<uint16_t>(accounts.size());
  putU16(out, count);

  for (uint16_t i = 0; i < count; ++i) {
    const TotpAccount &a = accounts[i];
    out.push_back(static_cast<uint8_t>(a.params.algorithm));
    out.push_back(a.params.digits);
    putU32(out, a.params.periodSeconds);
    putBlob(out, reinterpret_cast<const uint8_t *>(a.issuer.data()), a.issuer.size());
    putBlob(out, reinterpret_cast<const uint8_t *>(a.accountName.data()), a.accountName.size());
    putBlob(out, a.secret.data(), a.secret.size());
  }
  return out;
}

bool deserializeAccounts(const uint8_t *data, size_t len, std::vector<TotpAccount> &out) {
  out.clear();
  if (data == nullptr || len < 4) {
    // An empty/absent blob is treated as "no accounts" rather than an error.
    return len == 0;
  }

  Reader r{data, len};
  uint8_t magic = 0, version = 0;
  if (!r.u8(magic) || !r.u8(version)) return false;
  if (magic != kAccountBlobMagic || version != kAccountBlobVersion) return false;

  uint16_t count = 0;
  if (!r.u16(count)) return false;

  out.reserve(count);
  for (uint16_t i = 0; i < count; ++i) {
    TotpAccount a;
    uint8_t algorithm = 0;
    uint32_t period = 0;
    std::vector<uint8_t> secret;
    if (!r.u8(algorithm)) return false;
    if (!r.u8(a.params.digits)) return false;
    if (!r.u32(period)) return false;
    if (!r.str(a.issuer)) return false;
    if (!r.str(a.accountName)) return false;
    if (!r.blob(secret)) return false;

    a.params.algorithm = clampAlgorithm(algorithm);
    if (a.params.digits < 6 || a.params.digits > 8) a.params.digits = 6;
    a.params.periodSeconds = (period > 0 && period <= 600) ? period : 30;
    a.secret = std::move(secret);
    out.push_back(std::move(a));
  }
  return true;
}

}  // namespace totp
