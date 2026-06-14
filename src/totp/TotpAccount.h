#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "totp/Totp.h"

namespace totp {

// A provisioned authenticator account. The secret is held decoded (raw bytes)
// so the UI can generate codes without repeating base32 work each second.
struct TotpAccount {
  std::string issuer;            // e.g. "GitHub" (may be empty)
  std::string accountName;       // e.g. "alice@example.com"
  std::vector<uint8_t> secret;   // decoded shared secret
  OtpParams params;              // algorithm / digits / period

  bool valid() const { return !secret.empty(); }

  // Human-friendly label: "Issuer (account)", "Issuer", or the account name.
  std::string displayLabel() const {
    if (!issuer.empty() && !accountName.empty()) {
      return issuer + " (" + accountName + ")";
    }
    if (!issuer.empty()) {
      return issuer;
    }
    return accountName;
  }
};

}  // namespace totp
