#pragma once

#include <Preferences.h>

#include <vector>

#include "totp/TotpAccount.h"

namespace totp {

// In-memory account list backed by a single NVS blob. The whole list is loaded
// on begin() and rewritten on every mutation, which is fine for the handful of
// accounts a personal authenticator holds.
class AccountStore {
 public:
  static constexpr size_t kMaxAccounts = 64;

  // Loads accounts from NVS. Safe to call once at startup.
  bool begin();

  const std::vector<TotpAccount> &accounts() const { return accounts_; }
  size_t count() const { return accounts_.size(); }
  bool empty() const { return accounts_.empty(); }

  // Appends an account and persists. Returns false if the secret is empty or the
  // store is full.
  bool add(const TotpAccount &account);

  // Removes the account at `index` and persists. Returns false if out of range.
  bool removeAt(size_t index);

  // Removes every account and persists.
  void clear();

 private:
  bool load();
  bool save();

  Preferences preferences_;
  std::vector<TotpAccount> accounts_;
};

}  // namespace totp
