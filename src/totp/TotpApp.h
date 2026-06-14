#pragma once

#include <Arduino.h>
#include <vector>

#include "display/DisplayManager.h"
#include "input/ButtonHandler.h"
#include "input/TouchHandler.h"
#include "totp/AccountStore.h"
#include "totp/TimeService.h"
#include "totp/TotpWebServer.h"

namespace totp {

// Top-level authenticator application: boots straight into a live TOTP code
// list, offers a minimal menu, and hosts a Wi-Fi setup mode for adding accounts.
// Replaces the RSVP reader App as the device's primary experience.
class TotpApp {
 public:
  TotpApp();

  void begin();
  void update(uint32_t nowMs);

 private:
  enum class Screen : uint8_t {
    Boot,
    List,   // live codes
    Menu,   // short PWR press from the list
    Setup,  // Wi-Fi provisioning AP is up
  };

  void loadUiPreferences();
  void attemptBootTimeSync();

  void handlePowerButton(uint32_t nowMs);
  void handleBootButton(uint32_t nowMs);
  void handleTouch(uint32_t nowMs);
  void applyListSwipe(int direction);

  void openMenu();
  void closeMenu();
  void selectMenuItem(uint32_t nowMs);
  void enterSetup();
  void exitSetup();
  void powerOff();

  void cycleBrightness();
  uint8_t brightnessPercent() const;

  void renderList(uint32_t nowMs, bool force = false);
  void renderMenu();
  void renderSetup();

  std::string codeForAccount(const TotpAccount &account, uint64_t now) const;
  static String formatCode(const std::string &code);

  DisplayManager display_;
  TouchHandler touch_;
  ButtonHandler bootButton_;
  ButtonHandler powerButton_;
  AccountStore store_;
  TimeService time_;
  TotpWebServer web_;

  Screen screen_ = Screen::Boot;
  size_t listSelectedIndex_ = 0;
  size_t menuSelectedIndex_ = 0;
  std::vector<String> menuItems_;

  uint32_t bootStartedMs_ = 0;
  uint32_t lastListRenderSecond_ = 0;
  uint32_t lastSetupRenderMs_ = 0;

  uint8_t brightnessIndex_ = 3;
  bool darkMode_ = true;
  bool touchReady_ = false;

  bool powerHandledThisPress_ = false;
  bool bootHandledThisPress_ = false;

  // Swipe gesture tracking (mirrors the reader's menu gesture thresholds).
  bool gestureActive_ = false;
  uint16_t gestureStartX_ = 0;
  uint16_t gestureStartY_ = 0;
};

}  // namespace totp
