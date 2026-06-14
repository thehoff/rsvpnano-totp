#include <Arduino.h>
#include <esp_log.h>

#include "board/BoardConfig.h"
#include "totp/TotpApp.h"

totp::TotpApp app;

void setup() {
  Serial.begin(115200);
  esp_log_level_set("*", ESP_LOG_INFO);
  delay(50);
  BoardConfig::begin();
  const uint32_t serialWaitStart = millis();
  while (!Serial && millis() - serialWaitStart < 2000) {
    delay(10);
  }
  Serial.println("[main] authenticator setup");
  app.begin();
}

void loop() {
  const uint32_t now = millis();
  app.update(now);
}
