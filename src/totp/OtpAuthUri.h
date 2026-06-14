#pragma once

#include <string>

#include "totp/TotpAccount.h"

namespace totp {

// Parse an otpauth:// provisioning URI (the format produced by QR codes), e.g.
//   otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6
//
// Only the TOTP type is accepted. The label is split on ':' into issuer/account
// and percent-decoded; the `issuer` query parameter takes precedence when set.
// Unknown algorithm/digit/period values fall back to authenticator defaults.
//
// Returns true and fills `out` on success. On failure returns false and, when
// `error` is non-null, sets a short human-readable reason.
bool parseOtpAuthUri(const std::string &uri, TotpAccount &out, std::string *error = nullptr);

}  // namespace totp
