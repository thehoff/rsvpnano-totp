#pragma once

#include <Arduino.h>
#include <WebServer.h>

#include "totp/AccountStore.h"
#include "totp/TimeService.h"

namespace totp {

// Soft-AP web companion used to provision TOTP accounts from a phone or laptop.
//
// The device hosts its own Wi-Fi network ("Authenticator-XXXXXX") and a small
// page at http://192.168.4.1 where the user pastes an otpauth:// URI (or types a
// label + base32 secret). Secrets are write-only over the API: the listing
// endpoint never returns them. The browser can also push the current time, which
// is handy when the device has no internet for NTP.
class TotpWebServer {
 public:
  bool begin(AccountStore &store, TimeService &time);
  void update();
  void end();

  bool active() const { return active_; }
  String ssid() const { return ssid_; }
  String url() const { return url_; }

 private:
  static void handleRootStatic();
  static void handleAccountsGetStatic();
  static void handleAccountsPostStatic();
  static void handleAccountDeleteStatic();
  static void handleTimePostStatic();
  static void handleNotFoundStatic();

  void handleRoot();
  void handleAccountsGet();
  void handleAccountsPost();
  void handleAccountDelete();
  void handleTimePost();
  void handleNotFound();

  String deviceSuffix() const;
  static String jsonEscape(const String &value);

  static TotpWebServer *instance_;

  WebServer server_{80};
  AccountStore *store_ = nullptr;
  TimeService *time_ = nullptr;
  String ssid_;
  String url_;
  bool active_ = false;
};

}  // namespace totp
