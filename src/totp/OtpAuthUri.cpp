#include "totp/OtpAuthUri.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>

#include "totp/Base32.h"

namespace totp {
namespace {

void setError(std::string *error, const char *message) {
  if (error != nullptr) {
    *error = message;
  }
}

std::string toLower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Percent-decode, also turning '+' into space (form-style components).
std::string urlDecode(const std::string &value) {
  std::string out;
  out.reserve(value.size());
  for (size_t i = 0; i < value.size(); ++i) {
    const char c = value[i];
    if (c == '%' && i + 2 < value.size()) {
      const int hi = hexValue(value[i + 1]);
      const int lo = hexValue(value[i + 2]);
      if (hi >= 0 && lo >= 0) {
        out.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
        continue;
      }
    }
    if (c == '+') {
      out.push_back(' ');
    } else {
      out.push_back(c);
    }
  }
  return out;
}

}  // namespace

bool parseOtpAuthUri(const std::string &uri, TotpAccount &out, std::string *error) {
  out = TotpAccount();

  const std::string lower = toLower(uri);
  const std::string scheme = "otpauth://";
  if (lower.compare(0, scheme.size(), scheme) != 0) {
    setError(error, "Not an otpauth URI");
    return false;
  }

  size_t pos = scheme.size();
  const size_t queryPos = uri.find('?', pos);

  // type/label sit between the scheme and the query string.
  const std::string typeAndLabel =
      uri.substr(pos, (queryPos == std::string::npos ? uri.size() : queryPos) - pos);
  const size_t slash = typeAndLabel.find('/');
  const std::string type = toLower(typeAndLabel.substr(0, slash));
  if (type != "totp") {
    setError(error, "Only TOTP is supported");
    return false;
  }

  std::string label;
  if (slash != std::string::npos) {
    label = urlDecode(typeAndLabel.substr(slash + 1));
  }
  // Label form is "issuer:account" (issuer optional). Whitespace after ':' is
  // common and trimmed.
  const size_t colon = label.find(':');
  if (colon != std::string::npos) {
    out.issuer = label.substr(0, colon);
    std::string account = label.substr(colon + 1);
    while (!account.empty() && account.front() == ' ') {
      account.erase(account.begin());
    }
    out.accountName = account;
  } else {
    out.accountName = label;
  }

  // Parse the query parameters.
  std::string secretB32;
  std::string algorithm;
  long digits = 0;
  long period = 0;
  if (queryPos != std::string::npos) {
    size_t i = queryPos + 1;
    while (i <= uri.size()) {
      const size_t amp = uri.find('&', i);
      const std::string pair = uri.substr(i, (amp == std::string::npos ? uri.size() : amp) - i);
      const size_t eq = pair.find('=');
      if (eq != std::string::npos) {
        const std::string key = toLower(pair.substr(0, eq));
        const std::string value = urlDecode(pair.substr(eq + 1));
        if (key == "secret") {
          secretB32 = value;
        } else if (key == "issuer") {
          if (!value.empty()) {
            out.issuer = value;  // query issuer wins over the label prefix
          }
        } else if (key == "algorithm") {
          algorithm = toLower(value);
        } else if (key == "digits") {
          digits = std::strtol(value.c_str(), nullptr, 10);
        } else if (key == "period") {
          period = std::strtol(value.c_str(), nullptr, 10);
        }
      }
      if (amp == std::string::npos) {
        break;
      }
      i = amp + 1;
    }
  }

  if (secretB32.empty()) {
    setError(error, "Missing secret");
    return false;
  }
  if (!base32Decode(secretB32, out.secret) || out.secret.empty()) {
    setError(error, "Invalid base32 secret");
    return false;
  }

  if (algorithm == "sha256") {
    out.params.algorithm = HashType::Sha256;
  } else if (algorithm == "sha512") {
    out.params.algorithm = HashType::Sha512;
  } else {
    out.params.algorithm = HashType::Sha1;  // default and SHA1
  }

  out.params.digits = (digits >= 6 && digits <= 8) ? static_cast<uint8_t>(digits) : 6;
  out.params.periodSeconds = (period > 0 && period <= 600) ? static_cast<uint32_t>(period) : 30;

  return true;
}

}  // namespace totp
