#include "totp/TimeService.h"

#include <esp_log.h>
#include <sys/time.h>
#include <time.h>

namespace totp {
namespace {

constexpr const char *kTag = "totp.time";
constexpr const char *kNamespace = "totp";
constexpr const char *kLastTimeKey = "lasttime";
constexpr uint32_t kNtpTimeoutMs = 15000u;

}  // namespace

void TimeService::begin() {
  uint64_t seed = 0;
  if (preferences_.begin(kNamespace, true)) {
    seed = preferences_.getULong64(kLastTimeKey, 0);
    preferences_.end();
  }
  if (seed >= kMinValidEpoch) {
    // Seed the clock so codes are roughly right before any sync. This is only a
    // seed, not an authoritative sync, so synced_ stays false.
    applyUnixTime(seed);
    ESP_LOGI(kTag, "seeded clock from NVS (%llu)", static_cast<unsigned long long>(seed));
  }
}

uint64_t TimeService::now() const {
  return static_cast<uint64_t>(::time(nullptr));
}

bool TimeService::isValid() const { return now() >= kMinValidEpoch; }

void TimeService::applyUnixTime(uint64_t unixSeconds) {
  struct timeval tv;
  tv.tv_sec = static_cast<time_t>(unixSeconds);
  tv.tv_usec = 0;
  settimeofday(&tv, nullptr);
}

void TimeService::setUnixTime(uint64_t unixSeconds) {
  if (unixSeconds < kMinValidEpoch) {
    return;
  }
  applyUnixTime(unixSeconds);
  synced_ = true;
  ntpPending_ = false;
  persist();
  ESP_LOGI(kTag, "clock set externally (%llu)", static_cast<unsigned long long>(unixSeconds));
}

void TimeService::beginNtpSync(const char *server1, const char *server2) {
  // configTime kicks off background SNTP; UTC (no offset / DST) because TOTP
  // works entirely in UTC.
  configTime(0, 0, server1, server2);
  ntpPending_ = true;
  ntpStartedMs_ = millis();
  ESP_LOGI(kTag, "NTP sync started (%s, %s)", server1, server2);
}

bool TimeService::updateNtpSync() {
  if (!ntpPending_) {
    return false;
  }
  if (isValid()) {
    ntpPending_ = false;
    synced_ = true;
    persist();
    ESP_LOGI(kTag, "NTP sync complete (%llu)", static_cast<unsigned long long>(now()));
    return true;
  }
  if (millis() - ntpStartedMs_ > kNtpTimeoutMs) {
    ntpPending_ = false;
    ESP_LOGW(kTag, "NTP sync timed out");
  }
  return false;
}

void TimeService::persist() {
  const uint64_t value = now();
  if (value < kMinValidEpoch) {
    return;
  }
  if (preferences_.begin(kNamespace, false)) {
    preferences_.putULong64(kLastTimeKey, value);
    preferences_.end();
  }
}

void TimeService::maybePersist(uint32_t nowMs, uint32_t persistIntervalMs) {
  if (lastPersistMs_ != 0 && nowMs - lastPersistMs_ < persistIntervalMs) {
    return;
  }
  lastPersistMs_ = nowMs;
  persist();
}

}  // namespace totp
