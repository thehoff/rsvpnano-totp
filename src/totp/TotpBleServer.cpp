#include "totp/TotpBleServer.h"

#include <BLE2902.h>
#include <BLECharacteristic.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <esp_log.h>

#include <cstdlib>

#include "totp/OtpAuthUri.h"

namespace totp {
namespace {

constexpr const char *kTag = "totp.ble";

// Custom 128-bit UUIDs for the provisioning service. The Web Bluetooth page
// filters/looks these up by the same values.
constexpr const char *kServiceUuid = "9a1d0000-3c1a-4f8e-9d2b-7c1e2a4b6d80";
constexpr const char *kRxUuid = "9a1d0001-3c1a-4f8e-9d2b-7c1e2a4b6d80";  // phone -> device
constexpr const char *kTxUuid = "9a1d0002-3c1a-4f8e-9d2b-7c1e2a4b6d80";  // device -> phone

// Keep the published status under a single ATT read (characteristic value max is
// 512 bytes) so labels are truncated rather than overflowing.
constexpr size_t kStatusSoftLimit = 460;

std::string jsonEscape(const std::string &value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (char c : value) {
    if (c == '"' || c == '\\') {
      out.push_back('\\');
      out.push_back(c);
    } else if (static_cast<uint8_t>(c) >= 0x20) {
      out.push_back(c);
    }
  }
  return out;
}

class RxCallbacks : public BLECharacteristicCallbacks {
 public:
  explicit RxCallbacks(TotpBleServer *owner) : owner_(owner) {}
  void onWrite(BLECharacteristic *characteristic) override {
    if (owner_ != nullptr) {
      owner_->ingest(characteristic->getValue());
    }
  }

 private:
  TotpBleServer *owner_;
};

}  // namespace

bool TotpBleServer::begin(AccountStore &store, TimeService &time) {
  store_ = &store;
  time_ = &time;
  deviceName_ = "Authenticator-" + deviceSuffix();
  rxBuffer_.clear();

  BLEDevice::init(std::string(deviceName_.c_str()));
  BLEDevice::setMTU(247);  // request a larger MTU so most URIs fit in one write

  server_ = BLEDevice::createServer();
  BLEService *service = server_->createService(kServiceUuid);

  BLECharacteristic *rx = service->createCharacteristic(
      kRxUuid, BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR);
  rx->setCallbacks(new RxCallbacks(this));

  txCharacteristic_ = service->createCharacteristic(
      kTxUuid, BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY);
  txCharacteristic_->addDescriptor(new BLE2902());

  service->start();

  BLEAdvertising *advertising = BLEDevice::getAdvertising();
  advertising->addServiceUUID(kServiceUuid);
  advertising->setScanResponse(true);
  BLEDevice::startAdvertising();

  publishStatus();
  active_ = true;
  ESP_LOGI(kTag, "BLE provisioning up: %s", deviceName_.c_str());
  return true;
}

void TotpBleServer::end() {
  if (!active_) {
    return;
  }
  BLEDevice::stopAdvertising();
  // Frees the BLE stack memory; the characteristic/server objects are owned by
  // the stack and released here.
  BLEDevice::deinit(true);
  server_ = nullptr;
  txCharacteristic_ = nullptr;
  rxBuffer_.clear();
  active_ = false;
  ESP_LOGI(kTag, "BLE provisioning down");
}

void TotpBleServer::update() {
  // Command handling is callback-driven; nothing to poll here.
}

void TotpBleServer::ingest(const std::string &chunk) {
  // Reassemble writes that were split across BLE packets, processing each
  // complete (newline-terminated) command. Guard against an oversized buffer
  // from a misbehaving/malicious client.
  if (rxBuffer_.size() + chunk.size() > 4096) {
    rxBuffer_.clear();
    return;
  }
  rxBuffer_ += chunk;

  size_t newline;
  while ((newline = rxBuffer_.find('\n')) != std::string::npos) {
    std::string line = rxBuffer_.substr(0, newline);
    rxBuffer_.erase(0, newline + 1);
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (!line.empty()) {
      processLine(line);
    }
  }
}

void TotpBleServer::processLine(const std::string &line) {
  const size_t space = line.find(' ');
  const std::string command = line.substr(0, space);
  const std::string argument = (space == std::string::npos) ? std::string() : line.substr(space + 1);

  if (command == "OTP") {
    TotpAccount account;
    std::string error;
    if (parseOtpAuthUri(argument, account, &error) && store_->add(account)) {
      ESP_LOGI(kTag, "added account via BLE");
    } else {
      ESP_LOGW(kTag, "BLE add failed: %s", error.empty() ? "store full?" : error.c_str());
    }
  } else if (command == "TIME") {
    const uint64_t epoch = strtoull(argument.c_str(), nullptr, 10);
    time_->setUnixTime(epoch);
  } else if (command == "DEL") {
    const long index = strtol(argument.c_str(), nullptr, 10);
    if (index >= 0) {
      store_->removeAt(static_cast<size_t>(index));
    }
  } else if (command == "LIST") {
    // fall through to publish
  } else {
    ESP_LOGW(kTag, "unknown BLE command");
    return;
  }
  publishStatus();
}

std::string TotpBleServer::statusJson() const {
  std::string json = "{\"count\":";
  json += std::to_string(store_->count());
  json += ",\"timeValid\":";
  json += (time_->isValid() ? "true" : "false");
  json += ",\"epoch\":";
  json += std::to_string(static_cast<unsigned long long>(time_->now()));
  json += ",\"accounts\":[";
  const auto &accounts = store_->accounts();
  bool truncated = false;
  for (size_t i = 0; i < accounts.size(); ++i) {
    const TotpAccount &a = accounts[i];
    const char *alg = a.params.algorithm == HashType::Sha256
                          ? "SHA256"
                          : (a.params.algorithm == HashType::Sha512 ? "SHA512" : "SHA1");
    std::string entry = (i > 0 ? std::string(",") : std::string());
    entry += "{\"label\":\"" + jsonEscape(a.displayLabel()) + "\",\"algorithm\":\"" + alg +
             "\",\"digits\":" + std::to_string(a.params.digits) +
             ",\"period\":" + std::to_string(a.params.periodSeconds) + "}";
    if (json.size() + entry.size() > kStatusSoftLimit) {
      truncated = true;
      break;
    }
    json += entry;
  }
  json += "]";
  if (truncated) {
    json += ",\"truncated\":true";
  }
  json += "}";
  return json;
}

void TotpBleServer::publishStatus() {
  if (txCharacteristic_ == nullptr) {
    return;
  }
  const std::string json = statusJson();
  txCharacteristic_->setValue(reinterpret_cast<uint8_t *>(const_cast<char *>(json.data())),
                              json.size());
  txCharacteristic_->notify();
}

String TotpBleServer::deviceSuffix() const {
  const uint64_t mac = ESP.getEfuseMac();
  char suffix[7];
  snprintf(suffix, sizeof(suffix), "%06X", static_cast<unsigned int>(mac & 0xFFFFFF));
  return String(suffix);
}

}  // namespace totp
