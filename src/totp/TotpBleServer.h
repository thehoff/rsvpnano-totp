#pragma once

#include <Arduino.h>

#include <string>

#include "totp/AccountStore.h"
#include "totp/TimeService.h"

class BLEServer;
class BLECharacteristic;

namespace totp {

// BLE GATT provisioning service: an app-free alternative to the Wi-Fi page.
//
// A hosted Web Bluetooth page (web/authenticator.html) connects to this service
// and provisions accounts + pushes the clock — no Wi-Fi network to join and no
// app to install (Android Chrome / desktop Chrome/Edge; iOS Safari lacks Web
// Bluetooth).
//
// Protocol: a write characteristic (RX) receives newline-delimited text
// commands; long values (otpauth URIs) may be split across several BLE writes
// and are reassembled until a '\n' arrives. Commands:
//   OTP <otpauth://...>    add an account from a provisioning URI
//   TIME <unix-seconds>    set the device clock
//   DEL <index>            delete the account at index
//   LIST                   (re)publish the status
// A read/notify characteristic (TX) publishes a small JSON status (count,
// clock validity, and account labels — never secrets).
class TotpBleServer {
 public:
  bool begin(AccountStore &store, TimeService &time);
  void end();
  void update();

  bool active() const { return active_; }
  String deviceName() const { return deviceName_; }

  // Called from the BLE write callback; processes any complete command lines.
  void ingest(const std::string &chunk);

 private:
  void processLine(const std::string &line);
  void publishStatus();
  std::string statusJson() const;
  String deviceSuffix() const;

  AccountStore *store_ = nullptr;
  TimeService *time_ = nullptr;
  BLEServer *server_ = nullptr;
  BLECharacteristic *txCharacteristic_ = nullptr;
  std::string rxBuffer_;
  String deviceName_;
  bool active_ = false;
};

}  // namespace totp
