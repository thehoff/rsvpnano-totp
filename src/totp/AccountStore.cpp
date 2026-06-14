#include "totp/AccountStore.h"

#include <esp_log.h>

#include "totp/AccountCodec.h"

namespace totp {
namespace {

constexpr const char *kTag = "totp.store";
constexpr const char *kNamespace = "totp";
constexpr const char *kAccountsKey = "accounts";

}  // namespace

bool AccountStore::begin() { return load(); }

bool AccountStore::load() {
  accounts_.clear();
  if (!preferences_.begin(kNamespace, true)) {
    // Namespace may not exist yet on a fresh device; treat as empty.
    return true;
  }
  const size_t blobLen = preferences_.getBytesLength(kAccountsKey);
  bool ok = true;
  if (blobLen > 0) {
    std::vector<uint8_t> blob(blobLen);
    const size_t read = preferences_.getBytes(kAccountsKey, blob.data(), blobLen);
    ok = deserializeAccounts(blob.data(), read, accounts_);
    if (!ok) {
      ESP_LOGW(kTag, "stored account blob was malformed; starting empty");
      accounts_.clear();
    }
  }
  preferences_.end();
  ESP_LOGI(kTag, "loaded %u account(s)", static_cast<unsigned>(accounts_.size()));
  return ok;
}

bool AccountStore::save() {
  const std::vector<uint8_t> blob = serializeAccounts(accounts_);
  if (!preferences_.begin(kNamespace, false)) {
    ESP_LOGE(kTag, "failed to open NVS namespace for write");
    return false;
  }
  const size_t written = preferences_.putBytes(kAccountsKey, blob.data(), blob.size());
  preferences_.end();
  if (written != blob.size()) {
    ESP_LOGE(kTag, "short write persisting accounts (%u/%u)", static_cast<unsigned>(written),
             static_cast<unsigned>(blob.size()));
    return false;
  }
  return true;
}

bool AccountStore::add(const TotpAccount &account) {
  if (!account.valid() || accounts_.size() >= kMaxAccounts) {
    return false;
  }
  accounts_.push_back(account);
  if (!save()) {
    accounts_.pop_back();
    return false;
  }
  return true;
}

bool AccountStore::removeAt(size_t index) {
  if (index >= accounts_.size()) {
    return false;
  }
  TotpAccount removed = accounts_[index];
  accounts_.erase(accounts_.begin() + index);
  if (!save()) {
    accounts_.insert(accounts_.begin() + index, removed);
    return false;
  }
  return true;
}

void AccountStore::clear() {
  if (accounts_.empty()) {
    return;
  }
  accounts_.clear();
  save();
}

}  // namespace totp
