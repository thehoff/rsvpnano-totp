#pragma once

#include <cstdint>
#include <vector>

#include "totp/TotpAccount.h"

namespace totp {

// Serialize / deserialize the account list to a compact binary blob suitable for
// a single NVS entry. Kept free of Arduino/NVS types so the wire format is
// host-testable.
//
// Layout (little-endian lengths):
//   u8   magic 'T'
//   u8   version (kAccountBlobVersion)
//   u16  account count
//   repeated:
//     u8   algorithm (HashType)
//     u8   digits
//     u32  period seconds
//     u16  issuer length, issuer bytes
//     u16  account-name length, account-name bytes
//     u16  secret length, secret bytes
constexpr uint8_t kAccountBlobMagic = 'T';
constexpr uint8_t kAccountBlobVersion = 1;

std::vector<uint8_t> serializeAccounts(const std::vector<TotpAccount> &accounts);

// Returns false if the blob is malformed or uses an unknown version. On success
// `out` holds the decoded accounts (possibly empty).
bool deserializeAccounts(const uint8_t *data, size_t len, std::vector<TotpAccount> &out);

}  // namespace totp
