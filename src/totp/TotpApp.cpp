#include "totp/TotpApp.h"

#include <Preferences.h>
#include <WiFi.h>
#include <esp_log.h>
#include <esp_sleep.h>

#include "board/BoardConfig.h"
#include "totp/Totp.h"

namespace totp {
namespace {

constexpr const char *kTag = "totp.app";

// UI preference store (kept separate from the account/time namespace).
constexpr const char *kUiNamespace = "totpui";
constexpr const char *kPrefBrightness = "bright";
constexpr const char *kPrefDarkMode = "dark";

// Station Wi-Fi credentials are shared with the legacy companion settings so an
// existing device keeps working for the NTP-at-boot path.
constexpr const char *kRsvpNamespace = "rsvp";
constexpr const char *kPrefWifiSsid = "wifi_ssid";
constexpr const char *kPrefWifiPass = "wifi_pass";

constexpr uint32_t kPowerHoldMs = 800;
constexpr uint32_t kBootSplashMs = 700;
constexpr uint32_t kPowerOffReleaseWaitMs = 4000;

constexpr uint32_t kStaConnectTimeoutMs = 6000;
constexpr uint32_t kNtpWaitTimeoutMs = 10000;

constexpr int kSwipeThresholdPx = 24;
constexpr int kAxisBiasPx = 8;
constexpr int kTapSlopPx = 14;

const uint8_t kBrightnessLevels[] = {10, 30, 55, 80, 100};
constexpr uint8_t kBrightnessLevelCount = sizeof(kBrightnessLevels) / sizeof(kBrightnessLevels[0]);

}  // namespace

TotpApp::TotpApp()
    : bootButton_(BoardConfig::PIN_BOOT_BUTTON), powerButton_(BoardConfig::PIN_PWR_BUTTON) {}

void TotpApp::begin() {
  BoardConfig::begin();
  bootButton_.begin();
  powerButton_.begin();
  bootStartedMs_ = millis();

  loadUiPreferences();

  display_.begin();
  display_.setDarkMode(darkMode_);
  display_.setBrightnessPercent(brightnessPercent());
  display_.renderStatus("AUTHENTICATOR", "Starting up", "");

  touchReady_ = touch_.begin();
  store_.begin();
  time_.begin();

  attemptBootTimeSync();

  screen_ = Screen::List;
  lastListRenderSecond_ = 0;
  renderList(millis(), true);
  ESP_LOGI(kTag, "ready: %u account(s)", static_cast<unsigned>(store_.count()));
}

void TotpApp::loadUiPreferences() {
  Preferences prefs;
  if (prefs.begin(kUiNamespace, true)) {
    brightnessIndex_ = prefs.getUChar(kPrefBrightness, brightnessIndex_);
    darkMode_ = prefs.getBool(kPrefDarkMode, darkMode_);
    prefs.end();
  }
  if (brightnessIndex_ >= kBrightnessLevelCount) {
    brightnessIndex_ = kBrightnessLevelCount - 1;
  }
}

uint8_t TotpApp::brightnessPercent() const { return kBrightnessLevels[brightnessIndex_]; }

void TotpApp::attemptBootTimeSync() {
  String ssid;
  String pass;
  Preferences prefs;
  if (prefs.begin(kRsvpNamespace, true)) {
    ssid = prefs.getString(kPrefWifiSsid, "");
    pass = prefs.getString(kPrefWifiPass, "");
    prefs.end();
  }
  if (ssid.isEmpty()) {
    ESP_LOGI(kTag, "no saved Wi-Fi; skipping NTP (clock may be from NVS seed)");
    return;
  }

  display_.renderStatus("AUTHENTICATOR", "Syncing time", ssid);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid.c_str(), pass.c_str());
  const uint32_t connectStart = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - connectStart < kStaConnectTimeoutMs) {
    delay(100);
  }

  if (WiFi.status() == WL_CONNECTED) {
    time_.beginNtpSync();
    const uint32_t ntpStart = millis();
    while (!time_.updateNtpSync() && time_.ntpSyncPending() &&
           millis() - ntpStart < kNtpWaitTimeoutMs) {
      delay(100);
    }
  } else {
    ESP_LOGW(kTag, "Wi-Fi connect failed; using seeded clock");
  }

  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
}

void TotpApp::update(uint32_t nowMs) {
  bootButton_.update(nowMs);
  powerButton_.update(nowMs);

  handlePowerButton(nowMs);
  handleBootButton(nowMs);

  if (touchReady_) {
    handleTouch(nowMs);
  }

  switch (screen_) {
    case Screen::List:
      renderList(nowMs);
      time_.maybePersist(nowMs);
      break;
    case Screen::Setup:
      web_.update();
      if (nowMs - lastSetupRenderMs_ >= 1000) {
        renderSetup();
      }
      break;
    case Screen::SetupBle:
      ble_.update();
      if (nowMs - lastSetupRenderMs_ >= 1000) {
        renderSetupBle();
      }
      break;
    case Screen::Menu:
    case Screen::Boot:
      break;
  }

  delay(5);
}

// --- buttons ----------------------------------------------------------------

void TotpApp::handlePowerButton(uint32_t nowMs) {
  if (powerButton_.isHeld()) {
    if (!powerHandledThisPress_ && powerButton_.heldDurationMs(nowMs) >= kPowerHoldMs) {
      powerHandledThisPress_ = true;
      if (screen_ == Screen::Setup) {
        exitSetup();
      } else if (screen_ == Screen::SetupBle) {
        exitSetupBle();
      } else {
        powerOff();  // does not return
      }
    }
    return;
  }

  if (powerButton_.wasReleasedEvent()) {
    if (!powerHandledThisPress_) {
      if (screen_ == Screen::List) {
        openMenu();
      } else if (screen_ == Screen::Menu) {
        closeMenu();
      }
      // Setup exits via hold, not a short press.
    }
    powerHandledThisPress_ = false;
  }
}

void TotpApp::handleBootButton(uint32_t nowMs) {
  (void)nowMs;
  if (bootButton_.wasReleasedEvent()) {
    cycleBrightness();
  }
}

void TotpApp::cycleBrightness() {
  brightnessIndex_ = (brightnessIndex_ + 1) % kBrightnessLevelCount;
  display_.setBrightnessPercent(brightnessPercent());
  Preferences prefs;
  if (prefs.begin(kUiNamespace, false)) {
    prefs.putUChar(kPrefBrightness, brightnessIndex_);
    prefs.end();
  }
  // Force a redraw so any brightness-dependent chrome refreshes.
  if (screen_ == Screen::List) {
    renderList(millis(), true);
  } else if (screen_ == Screen::Menu) {
    renderMenu();
  }
}

// --- touch ------------------------------------------------------------------

void TotpApp::handleTouch(uint32_t nowMs) {
  TouchEvent event;
  if (!touch_.poll(event)) {
    return;
  }
  if (screen_ != Screen::List && screen_ != Screen::Menu) {
    return;
  }

  if (event.phase == TouchPhase::Start) {
    gestureActive_ = true;
    gestureStartX_ = event.x;
    gestureStartY_ = event.y;
    return;
  }
  if (!gestureActive_ || event.phase != TouchPhase::End) {
    return;
  }
  gestureActive_ = false;

  const int deltaX = static_cast<int>(event.x) - static_cast<int>(gestureStartX_);
  const int deltaY = static_cast<int>(event.y) - static_cast<int>(gestureStartY_);
  const int absX = abs(deltaX);
  const int absY = abs(deltaY);

  if (absY >= kSwipeThresholdPx && absY > absX + kAxisBiasPx) {
    const int direction = deltaY < 0 ? -1 : 1;
    if (screen_ == Screen::List) {
      applyListSwipe(direction);
    } else {
      const size_t count = menuItems_.size();
      if (count > 0) {
        menuSelectedIndex_ = (menuSelectedIndex_ + count + direction) % count;
        renderMenu();
      }
    }
    return;
  }

  if (absX <= kTapSlopPx && absY <= kTapSlopPx) {
    if (screen_ == Screen::Menu) {
      selectMenuItem(nowMs);
    }
  }
}

void TotpApp::applyListSwipe(int direction) {
  const size_t count = store_.count();
  if (count == 0) {
    return;
  }
  listSelectedIndex_ = (listSelectedIndex_ + count + direction) % count;
  renderList(millis(), true);
}

// --- menu -------------------------------------------------------------------

void TotpApp::openMenu() {
  menuItems_ = {String("Setup over Wi-Fi"), String("Setup over Bluetooth"), String("Power off"),
                String("Back")};
  menuSelectedIndex_ = 0;
  screen_ = Screen::Menu;
  renderMenu();
}

void TotpApp::closeMenu() {
  screen_ = Screen::List;
  renderList(millis(), true);
}

void TotpApp::selectMenuItem(uint32_t nowMs) {
  (void)nowMs;
  switch (menuSelectedIndex_) {
    case 0:
      enterSetup();
      break;
    case 1:
      enterSetupBle();
      break;
    case 2:
      powerOff();
      break;
    case 3:
    default:
      closeMenu();
      break;
  }
}

// --- setup (Wi-Fi provisioning) ---------------------------------------------

void TotpApp::enterSetup() {
  display_.renderStatus("SETUP", "Starting Wi-Fi", "");
  if (!web_.begin(store_, time_)) {
    display_.renderStatus("SETUP FAILED", "Could not start Wi-Fi", "PWR returns");
    screen_ = Screen::Menu;
    return;
  }
  screen_ = Screen::Setup;
  lastSetupRenderMs_ = 0;
  renderSetup();
}

void TotpApp::exitSetup() {
  web_.end();
  screen_ = Screen::List;
  lastListRenderSecond_ = 0;
  renderList(millis(), true);
}

void TotpApp::enterSetupBle() {
  display_.renderStatus("SETUP", "Starting Bluetooth", "");
  if (!ble_.begin(store_, time_)) {
    display_.renderStatus("SETUP FAILED", "Could not start Bluetooth", "PWR returns");
    screen_ = Screen::Menu;
    return;
  }
  screen_ = Screen::SetupBle;
  lastSetupRenderMs_ = 0;
  renderSetupBle();
}

void TotpApp::exitSetupBle() {
  ble_.end();
  screen_ = Screen::List;
  lastListRenderSecond_ = 0;
  renderList(millis(), true);
}

void TotpApp::powerOff() {
  display_.renderStatus("OFF", "Release PWR", "Hold PWR to start");
  if (web_.active()) {
    web_.end();
  }
  if (ble_.active()) {
    ble_.end();
  }
  delay(300);
  display_.prepareForSleep();
  touch_.end();
  Serial.flush();

  BoardConfig::holdBacklightOffForDeepSleep();
  BoardConfig::releaseBatteryPowerHold();

  const uint32_t waitStart = millis();
  while (powerButton_.isHeld() && millis() - waitStart < kPowerOffReleaseWaitMs) {
    powerButton_.update(millis());
    delay(10);
  }

  esp_sleep_enable_ext0_wakeup(static_cast<gpio_num_t>(BoardConfig::PIN_PWR_BUTTON), 0);
  esp_deep_sleep_start();
}

// --- rendering --------------------------------------------------------------

std::string TotpApp::codeForAccount(const TotpAccount &account, uint64_t now) const {
  return totpAt(account.secret.data(), account.secret.size(), now, account.params);
}

String TotpApp::formatCode(const std::string &code) {
  // Split into two halves with a gap for readability ("123 456" / "1234 5678").
  const size_t mid = code.size() / 2;
  String out;
  for (size_t i = 0; i < code.size(); ++i) {
    if (i == mid) {
      out += ' ';
    }
    out += code[i];
  }
  return out;
}

void TotpApp::renderList(uint32_t nowMs, bool force) {
  if (!time_.isValid()) {
    if (force) {
      display_.renderStatus("CLOCK NOT SET", "PWR > Setup over Wi-Fi", "then Sync clock in browser");
    }
    return;
  }

  const uint64_t now = time_.now();
  const uint32_t second = static_cast<uint32_t>(now);
  if (!force && second == lastListRenderSecond_) {
    return;
  }
  lastListRenderSecond_ = second;
  (void)nowMs;

  if (store_.empty()) {
    display_.renderStatus("NO ACCOUNTS", "PWR > Setup over Wi-Fi", "Add codes from the browser");
    return;
  }

  const auto &accounts = store_.accounts();
  if (listSelectedIndex_ >= accounts.size()) {
    listSelectedIndex_ = accounts.size() - 1;
  }

  std::vector<DisplayManager::LibraryItem> items;
  items.reserve(accounts.size());
  for (const TotpAccount &account : accounts) {
    DisplayManager::LibraryItem item;
    item.title = String(account.displayLabel().c_str());
    const std::string code = codeForAccount(account, now);
    const uint32_t remaining = totpSecondsRemaining(now, account.params.periodSeconds);
    item.subtitle = formatCode(code) + "   " + String(remaining) + "s";
    items.push_back(std::move(item));
  }
  display_.renderLibrary(items, listSelectedIndex_);
}

void TotpApp::renderMenu() { display_.renderMenu(menuItems_, menuSelectedIndex_); }

void TotpApp::renderSetup() {
  lastSetupRenderMs_ = millis();
  String line2 = web_.url() + "  (" + String(static_cast<unsigned>(store_.count())) + ")";
  display_.renderStatus(web_.ssid(), line2, "Open the page, then hold PWR");
}

void TotpApp::renderSetupBle() {
  lastSetupRenderMs_ = millis();
  display_.renderStatus(ble_.deviceName(), "Bluetooth setup ready",
                        "Open the web page, then hold PWR");
}

}  // namespace totp
