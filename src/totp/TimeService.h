#pragma once

#include <Arduino.h>
#include <Preferences.h>

#include <cstdint>

namespace totp {

// Owns wall-clock time for TOTP generation.
//
// The board has no battery-backed RTC, but the ESP32 keeps its internal clock
// running through light-sleep standby, so once the time is set it stays correct
// while the device is on battery. Strategy:
//   * On boot, seed the system clock from the last value persisted in NVS so we
//     start "roughly right" even before any sync.
//   * Sync precisely from NTP when WiFi is available (configTime / SNTP).
//   * Allow an external source (BLE / Android companion) to push the time via
//     setUnixTime().
//   * Periodically persist the current time so a later cold boot has a recent
//     seed.
//
// "Valid" means the clock is past a sanity epoch (2023-01-01); TOTP codes should
// only be shown once the time is valid.
class TimeService {
 public:
  // Sanity threshold: any clock earlier than this is considered unset.
  static constexpr uint32_t kMinValidEpoch = 1672531200u;  // 2023-01-01 UTC

  // Seeds the system clock from NVS. Call once at startup.
  void begin();

  // Current UTC time in seconds since the Unix epoch.
  uint64_t now() const;

  // True once the clock has been set to a plausible value.
  bool isValid() const;

  // Has an authoritative sync (NTP or external push) succeeded this session?
  bool isSynced() const { return synced_; }

  // True while an NTP sync started by beginNtpSync() is still pending.
  bool ntpSyncPending() const { return ntpPending_; }

  // Begin a non-blocking SNTP sync. Requires WiFi to already be connected.
  void beginNtpSync(const char *server1 = "pool.ntp.org",
                    const char *server2 = "time.nist.gov");

  // Poll an in-flight NTP sync; returns true once it completes successfully.
  // Persists the freshly synced time. Safe to call every loop.
  bool updateNtpSync();

  // Push an authoritative time (e.g. from the Android companion over BLE).
  void setUnixTime(uint64_t unixSeconds);

  // Persist the current clock to NVS so the next cold boot starts close.
  void persist();

  // Convenience: call every loop; persists at most once per persistIntervalMs.
  void maybePersist(uint32_t nowMs, uint32_t persistIntervalMs = 60000u);

 private:
  void applyUnixTime(uint64_t unixSeconds);

  Preferences preferences_;
  bool synced_ = false;
  bool ntpPending_ = false;
  uint32_t ntpStartedMs_ = 0;
  uint32_t lastPersistMs_ = 0;
};

}  // namespace totp
