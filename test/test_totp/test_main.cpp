#include <unity.h>

#include <string>
#include <vector>

#include "totp/AccountCodec.h"
#include "totp/Base32.h"
#include "totp/Hash.h"
#include "totp/OtpAuthUri.h"
#include "totp/Totp.h"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string bytesToHex(const std::vector<uint8_t> &bytes) {
  static const char *kHex = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    out.push_back(kHex[(b >> 4) & 0x0F]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

static std::vector<uint8_t> asBytes(const std::string &s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

static void assertHash(const std::vector<uint8_t> &digest, const char *expectedHex) {
  TEST_ASSERT_EQUAL_STRING(expectedHex, bytesToHex(digest).c_str());
}

// The RFC 6238 reference seeds (ASCII, used directly as the HMAC key).
static const std::string kSeedSha1 = "12345678901234567890";
static const std::string kSeedSha256 = "12345678901234567890123456789012";
static const std::string kSeedSha512 =
    "1234567890123456789012345678901234567890123456789012345678901234";

static std::string totpAtHelper(const std::string &seed, uint64_t t, totp::HashType alg) {
  totp::OtpParams params;
  params.algorithm = alg;
  params.digits = 8;
  params.periodSeconds = 30;
  const std::vector<uint8_t> secret = asBytes(seed);
  return totp::totpAt(secret.data(), secret.size(), t, params);
}

// ---------------------------------------------------------------------------
// Raw hash vectors (FIPS 180 / RFC 6234)
// ---------------------------------------------------------------------------

void test_sha1_abc(void) {
  assertHash(totp::sha1(reinterpret_cast<const uint8_t *>("abc"), 3),
             "a9993e364706816aba3e25717850c26c9cd0d89d");
}

void test_sha1_empty(void) {
  assertHash(totp::sha1(nullptr, 0), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

void test_sha256_abc(void) {
  assertHash(totp::sha256(reinterpret_cast<const uint8_t *>("abc"), 3),
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

void test_sha256_empty(void) {
  assertHash(totp::sha256(nullptr, 0),
             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

void test_sha512_abc(void) {
  assertHash(totp::sha512(reinterpret_cast<const uint8_t *>("abc"), 3),
             "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba"
             "3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

// SHA-512 with a 112-byte message exercises the two-block padding path.
void test_sha512_two_block(void) {
  const std::string msg =
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmn"
      "opqrsmnopqrstnopqrstu";
  assertHash(totp::sha512(reinterpret_cast<const uint8_t *>(msg.data()), msg.size()),
             "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b"
             "99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

// ---------------------------------------------------------------------------
// HMAC vectors (RFC 2202 case 2 / RFC 4231 case 2): key="Jefe"
// ---------------------------------------------------------------------------

void test_hmac_sha1_jefe(void) {
  const std::string key = "Jefe";
  const std::string data = "what do ya want for nothing?";
  assertHash(totp::hmac(totp::HashType::Sha1, reinterpret_cast<const uint8_t *>(key.data()),
                        key.size(), reinterpret_cast<const uint8_t *>(data.data()), data.size()),
             "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
}

void test_hmac_sha256_jefe(void) {
  const std::string key = "Jefe";
  const std::string data = "what do ya want for nothing?";
  assertHash(totp::hmac(totp::HashType::Sha256, reinterpret_cast<const uint8_t *>(key.data()),
                        key.size(), reinterpret_cast<const uint8_t *>(data.data()), data.size()),
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

void test_hmac_sha512_jefe(void) {
  const std::string key = "Jefe";
  const std::string data = "what do ya want for nothing?";
  assertHash(totp::hmac(totp::HashType::Sha512, reinterpret_cast<const uint8_t *>(key.data()),
                        key.size(), reinterpret_cast<const uint8_t *>(data.data()), data.size()),
             "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d03"
             "4f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
}

// HMAC with an over-long key (RFC 4231 case 4 uses a 131-byte key) exercises the
// key-shortening branch.
void test_hmac_sha256_long_key(void) {
  const std::vector<uint8_t> key(131, 0xaa);
  const std::string data = "Test Using Larger Than Block-Size Key - Hash Key First";
  assertHash(totp::hmac(totp::HashType::Sha256, key.data(), key.size(),
                        reinterpret_cast<const uint8_t *>(data.data()), data.size()),
             "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

// ---------------------------------------------------------------------------
// HOTP (RFC 4226 Appendix D): secret = "12345678901234567890"
// ---------------------------------------------------------------------------

void test_hotp_rfc4226(void) {
  const std::vector<uint8_t> secret = asBytes(kSeedSha1);
  const char *expected[10] = {"755224", "287082", "359152", "969429", "338314",
                              "254676", "287922", "162583", "399871", "520489"};
  for (uint64_t c = 0; c < 10; ++c) {
    TEST_ASSERT_EQUAL_STRING(expected[c], totp::hotp(secret.data(), secret.size(), c).c_str());
  }
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238 Appendix B): 8-digit codes across all three algorithms
// ---------------------------------------------------------------------------

void test_totp_rfc6238_sha1(void) {
  TEST_ASSERT_EQUAL_STRING("94287082", totpAtHelper(kSeedSha1, 59, totp::HashType::Sha1).c_str());
  TEST_ASSERT_EQUAL_STRING("07081804",
                           totpAtHelper(kSeedSha1, 1111111109, totp::HashType::Sha1).c_str());
  TEST_ASSERT_EQUAL_STRING("14050471",
                           totpAtHelper(kSeedSha1, 1111111111, totp::HashType::Sha1).c_str());
  TEST_ASSERT_EQUAL_STRING("89005924",
                           totpAtHelper(kSeedSha1, 1234567890, totp::HashType::Sha1).c_str());
  TEST_ASSERT_EQUAL_STRING("69279037",
                           totpAtHelper(kSeedSha1, 2000000000, totp::HashType::Sha1).c_str());
  TEST_ASSERT_EQUAL_STRING("65353130",
                           totpAtHelper(kSeedSha1, 20000000000ull, totp::HashType::Sha1).c_str());
}

void test_totp_rfc6238_sha256(void) {
  TEST_ASSERT_EQUAL_STRING("46119246",
                           totpAtHelper(kSeedSha256, 59, totp::HashType::Sha256).c_str());
  TEST_ASSERT_EQUAL_STRING("68084774",
                           totpAtHelper(kSeedSha256, 1111111109, totp::HashType::Sha256).c_str());
  TEST_ASSERT_EQUAL_STRING("77737706",
                           totpAtHelper(kSeedSha256, 20000000000ull, totp::HashType::Sha256).c_str());
}

void test_totp_rfc6238_sha512(void) {
  TEST_ASSERT_EQUAL_STRING("90693936",
                           totpAtHelper(kSeedSha512, 59, totp::HashType::Sha512).c_str());
  TEST_ASSERT_EQUAL_STRING("25091201",
                           totpAtHelper(kSeedSha512, 1111111109, totp::HashType::Sha512).c_str());
  TEST_ASSERT_EQUAL_STRING("47863826",
                           totpAtHelper(kSeedSha512, 20000000000ull, totp::HashType::Sha512).c_str());
}

void test_totp_default_is_six_digits(void) {
  const std::vector<uint8_t> secret = asBytes(kSeedSha1);
  // RFC 6238 SHA1 at T=59 is 94287082; the low 6 digits are 287082.
  const std::string code = totp::totpAt(secret.data(), secret.size(), 59);
  TEST_ASSERT_EQUAL_STRING("287082", code.c_str());
}

void test_totp_seconds_remaining(void) {
  TEST_ASSERT_EQUAL_UINT32(30u, totp::totpSecondsRemaining(0, 30));
  TEST_ASSERT_EQUAL_UINT32(1u, totp::totpSecondsRemaining(59, 30));
  TEST_ASSERT_EQUAL_UINT32(15u, totp::totpSecondsRemaining(45, 30));
  TEST_ASSERT_EQUAL_UINT32(30u, totp::totpSecondsRemaining(60, 30));
}

// ---------------------------------------------------------------------------
// Base32 (RFC 4648)
// ---------------------------------------------------------------------------

void test_base32_decode_vectors(void) {
  std::vector<uint8_t> out;
  TEST_ASSERT_TRUE(totp::base32Decode("MZXW6YTBOI", out));
  TEST_ASSERT_EQUAL_STRING("foobar", std::string(out.begin(), out.end()).c_str());

  TEST_ASSERT_TRUE(totp::base32Decode("MY======", out));
  TEST_ASSERT_EQUAL_STRING("f", std::string(out.begin(), out.end()).c_str());

  TEST_ASSERT_TRUE(totp::base32Decode("MZXW6===", out));
  TEST_ASSERT_EQUAL_STRING("foo", std::string(out.begin(), out.end()).c_str());
}

void test_base32_decode_ignores_spaces_and_case(void) {
  std::vector<uint8_t> out;
  TEST_ASSERT_TRUE(totp::base32Decode("mzxw 6ytb-oi", out));
  TEST_ASSERT_EQUAL_STRING("foobar", std::string(out.begin(), out.end()).c_str());
}

void test_base32_decode_rejects_invalid(void) {
  std::vector<uint8_t> out;
  TEST_ASSERT_FALSE(totp::base32Decode("MZXW6YTB0I", out));  // '0' is not in the alphabet
  TEST_ASSERT_TRUE(out.empty());
}

void test_base32_round_trip(void) {
  const std::string original = "foobar";
  const std::string encoded =
      totp::base32Encode(reinterpret_cast<const uint8_t *>(original.data()), original.size());
  TEST_ASSERT_EQUAL_STRING("MZXW6YTBOI", encoded.c_str());
}

// ---------------------------------------------------------------------------
// otpauth:// URI parsing
// ---------------------------------------------------------------------------

void test_uri_parse_full(void) {
  totp::TotpAccount account;
  std::string error;
  const bool ok = totp::parseOtpAuthUri(
      "otpauth://totp/GitHub:alice@example.com?secret=MZXW6YTBOI&issuer=GitHub&algorithm=SHA256&"
      "digits=8&period=60",
      account, &error);
  TEST_ASSERT_TRUE_MESSAGE(ok, error.c_str());
  TEST_ASSERT_EQUAL_STRING("GitHub", account.issuer.c_str());
  TEST_ASSERT_EQUAL_STRING("alice@example.com", account.accountName.c_str());
  TEST_ASSERT_EQUAL_STRING("foobar",
                           std::string(account.secret.begin(), account.secret.end()).c_str());
  TEST_ASSERT_EQUAL(totp::HashType::Sha256, account.params.algorithm);
  TEST_ASSERT_EQUAL_UINT8(8, account.params.digits);
  TEST_ASSERT_EQUAL_UINT32(60u, account.params.periodSeconds);
}

void test_uri_parse_minimal_defaults(void) {
  totp::TotpAccount account;
  TEST_ASSERT_TRUE(totp::parseOtpAuthUri("otpauth://totp/Example?secret=MZXW6YTBOI", account));
  TEST_ASSERT_EQUAL_STRING("", account.issuer.c_str());
  TEST_ASSERT_EQUAL_STRING("Example", account.accountName.c_str());
  TEST_ASSERT_EQUAL(totp::HashType::Sha1, account.params.algorithm);
  TEST_ASSERT_EQUAL_UINT8(6, account.params.digits);
  TEST_ASSERT_EQUAL_UINT32(30u, account.params.periodSeconds);
}

void test_uri_parse_percent_encoded_label(void) {
  totp::TotpAccount account;
  TEST_ASSERT_TRUE(totp::parseOtpAuthUri(
      "otpauth://totp/ACME%20Co%3A%20john%40example.com?secret=MZXW6YTBOI&issuer=ACME%20Co",
      account));
  TEST_ASSERT_EQUAL_STRING("ACME Co", account.issuer.c_str());
  TEST_ASSERT_EQUAL_STRING("john@example.com", account.accountName.c_str());
}

void test_uri_parse_rejects_hotp(void) {
  totp::TotpAccount account;
  std::string error;
  TEST_ASSERT_FALSE(
      totp::parseOtpAuthUri("otpauth://hotp/Example?secret=MZXW6YTBOI&counter=0", account, &error));
  TEST_ASSERT_FALSE(error.empty());
}

void test_uri_parse_rejects_missing_secret(void) {
  totp::TotpAccount account;
  TEST_ASSERT_FALSE(totp::parseOtpAuthUri("otpauth://totp/Example?issuer=Example", account));
}

void test_uri_parse_rejects_non_otpauth(void) {
  totp::TotpAccount account;
  TEST_ASSERT_FALSE(totp::parseOtpAuthUri("https://example.com", account));
}

void test_account_display_label(void) {
  totp::TotpAccount account;
  account.issuer = "GitHub";
  account.accountName = "alice";
  TEST_ASSERT_EQUAL_STRING("GitHub (alice)", account.displayLabel().c_str());
  account.accountName.clear();
  TEST_ASSERT_EQUAL_STRING("GitHub", account.displayLabel().c_str());
  account.issuer.clear();
  account.accountName = "alice";
  TEST_ASSERT_EQUAL_STRING("alice", account.displayLabel().c_str());
}

// ---------------------------------------------------------------------------
// Account blob codec
// ---------------------------------------------------------------------------

static totp::TotpAccount makeAccount(const std::string &issuer, const std::string &name,
                                     const std::string &secretAscii, totp::HashType alg,
                                     uint8_t digits, uint32_t period) {
  totp::TotpAccount a;
  a.issuer = issuer;
  a.accountName = name;
  a.secret = asBytes(secretAscii);
  a.params.algorithm = alg;
  a.params.digits = digits;
  a.params.periodSeconds = period;
  return a;
}

void test_codec_round_trip(void) {
  std::vector<totp::TotpAccount> accounts = {
      makeAccount("GitHub", "alice@example.com", "foobar", totp::HashType::Sha1, 6, 30),
      makeAccount("AWS", "root", "12345678901234567890", totp::HashType::Sha256, 8, 60),
      makeAccount("", "standalone", "secret", totp::HashType::Sha512, 6, 30),
  };

  const std::vector<uint8_t> blob = totp::serializeAccounts(accounts);
  std::vector<totp::TotpAccount> decoded;
  TEST_ASSERT_TRUE(totp::deserializeAccounts(blob.data(), blob.size(), decoded));
  TEST_ASSERT_EQUAL(3u, decoded.size());

  for (size_t i = 0; i < accounts.size(); ++i) {
    TEST_ASSERT_EQUAL_STRING(accounts[i].issuer.c_str(), decoded[i].issuer.c_str());
    TEST_ASSERT_EQUAL_STRING(accounts[i].accountName.c_str(), decoded[i].accountName.c_str());
    TEST_ASSERT_EQUAL(accounts[i].params.algorithm, decoded[i].params.algorithm);
    TEST_ASSERT_EQUAL_UINT8(accounts[i].params.digits, decoded[i].params.digits);
    TEST_ASSERT_EQUAL_UINT32(accounts[i].params.periodSeconds, decoded[i].params.periodSeconds);
    TEST_ASSERT_EQUAL(accounts[i].secret.size(), decoded[i].secret.size());
    TEST_ASSERT_EQUAL_STRING(
        std::string(accounts[i].secret.begin(), accounts[i].secret.end()).c_str(),
        std::string(decoded[i].secret.begin(), decoded[i].secret.end()).c_str());
  }
}

void test_codec_empty_round_trip(void) {
  const std::vector<uint8_t> blob = totp::serializeAccounts({});
  std::vector<totp::TotpAccount> decoded;
  TEST_ASSERT_TRUE(totp::deserializeAccounts(blob.data(), blob.size(), decoded));
  TEST_ASSERT_TRUE(decoded.empty());
}

void test_codec_zero_length_is_empty(void) {
  std::vector<totp::TotpAccount> decoded;
  TEST_ASSERT_TRUE(totp::deserializeAccounts(nullptr, 0, decoded));
  TEST_ASSERT_TRUE(decoded.empty());
}

void test_codec_rejects_bad_magic(void) {
  std::vector<uint8_t> blob = {'X', 1, 0, 0};
  std::vector<totp::TotpAccount> decoded;
  TEST_ASSERT_FALSE(totp::deserializeAccounts(blob.data(), blob.size(), decoded));
}

void test_codec_rejects_truncated(void) {
  std::vector<totp::TotpAccount> accounts = {
      makeAccount("GitHub", "alice", "foobar", totp::HashType::Sha1, 6, 30)};
  std::vector<uint8_t> blob = totp::serializeAccounts(accounts);
  blob.resize(blob.size() - 3);  // chop the secret short
  std::vector<totp::TotpAccount> decoded;
  TEST_ASSERT_FALSE(totp::deserializeAccounts(blob.data(), blob.size(), decoded));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_sha1_abc);
  RUN_TEST(test_sha1_empty);
  RUN_TEST(test_sha256_abc);
  RUN_TEST(test_sha256_empty);
  RUN_TEST(test_sha512_abc);
  RUN_TEST(test_sha512_two_block);

  RUN_TEST(test_hmac_sha1_jefe);
  RUN_TEST(test_hmac_sha256_jefe);
  RUN_TEST(test_hmac_sha512_jefe);
  RUN_TEST(test_hmac_sha256_long_key);

  RUN_TEST(test_hotp_rfc4226);

  RUN_TEST(test_totp_rfc6238_sha1);
  RUN_TEST(test_totp_rfc6238_sha256);
  RUN_TEST(test_totp_rfc6238_sha512);
  RUN_TEST(test_totp_default_is_six_digits);
  RUN_TEST(test_totp_seconds_remaining);

  RUN_TEST(test_base32_decode_vectors);
  RUN_TEST(test_base32_decode_ignores_spaces_and_case);
  RUN_TEST(test_base32_decode_rejects_invalid);
  RUN_TEST(test_base32_round_trip);

  RUN_TEST(test_uri_parse_full);
  RUN_TEST(test_uri_parse_minimal_defaults);
  RUN_TEST(test_uri_parse_percent_encoded_label);
  RUN_TEST(test_uri_parse_rejects_hotp);
  RUN_TEST(test_uri_parse_rejects_missing_secret);
  RUN_TEST(test_uri_parse_rejects_non_otpauth);
  RUN_TEST(test_account_display_label);

  RUN_TEST(test_codec_round_trip);
  RUN_TEST(test_codec_empty_round_trip);
  RUN_TEST(test_codec_zero_length_is_empty);
  RUN_TEST(test_codec_rejects_bad_magic);
  RUN_TEST(test_codec_rejects_truncated);

  return UNITY_END();
}
