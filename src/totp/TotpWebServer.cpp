#include "totp/TotpWebServer.h"

#include <WiFi.h>
#include <esp_log.h>

#include <cstdlib>
#include <string>

#include "totp/Base32.h"
#include "totp/OtpAuthUri.h"

namespace totp {
namespace {

constexpr const char *kTag = "totp.web";

String ipToString(const IPAddress &ip) {
  char buffer[16];
  snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return String(buffer);
}

const char kProvisionHtml[] PROGMEM = R"HTML(<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authenticator setup</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0c1110;color:#f5f1e8;font:15px/1.45 system-ui,sans-serif}
main{max-width:560px;margin:0 auto;padding:18px}
h1{font-size:1.2rem}h2{font-size:1rem;margin:18px 0 8px}
.card{background:#151b18;border:1px solid #2d3430;border-radius:10px;padding:14px;margin-bottom:14px}
label{display:block;font-weight:650;margin:10px 0 4px}
input,select{width:100%;border:1px solid #2d3430;border-radius:8px;background:#0c1110;color:#f5f1e8;font:inherit;padding:9px}
.row{display:flex;gap:8px}.row>*{flex:1}
button{border:1px solid #78d5b1;border-radius:8px;background:#78d5b1;color:#07110e;font:inherit;font-weight:700;padding:10px 12px;margin-top:12px;width:100%}
button.del{background:#0c1110;color:#ff9b73;border-color:#2d3430;width:auto;margin:0;padding:6px 10px}
.item{display:flex;justify-content:space-between;align-items:center;border-top:1px solid #2d3430;padding:10px 0}
.item:first-child{border-top:0}.muted{color:#a7aaa0;font-size:.9rem}
#status{padding:10px;border-radius:8px;background:#1d2924;margin-bottom:12px}
</style></head><body><main>
<h1>Authenticator setup</h1>
<div id="status">Loading...</div>

<div class="card">
<h2>Add account</h2>
<label>Paste otpauth:// URI</label>
<input id="uri" placeholder="otpauth://totp/Issuer:user?secret=...">
<button onclick="addUri()">Add from URI</button>
<p class="muted">Or enter the details manually:</p>
<label>Issuer</label><input id="issuer" placeholder="GitHub">
<label>Account</label><input id="account" placeholder="you@example.com">
<label>Secret (base32)</label><input id="secret" placeholder="JBSWY3DPEHPK3PXP">
<div class="row">
<div><label>Algorithm</label><select id="algorithm"><option>SHA1</option><option>SHA256</option><option>SHA512</option></select></div>
<div><label>Digits</label><select id="digits"><option>6</option><option>8</option></select></div>
<div><label>Period</label><select id="period"><option>30</option><option>60</option></select></div>
</div>
<button onclick="addManual()">Add manually</button>
</div>

<div class="card">
<h2>Accounts</h2>
<div id="list" class="muted">none yet</div>
</div>

<div class="card">
<h2>Device clock</h2>
<div id="clock" class="muted"></div>
<button onclick="setTime()">Sync clock from this browser</button>
</div>

<script>
function setStatus(t){document.getElementById('status').textContent=t}
async function refresh(){
 try{
  const r=await fetch('/api/accounts');const d=await r.json();
  const list=document.getElementById('list');
  if(!d.accounts.length){list.innerHTML='<span class="muted">none yet</span>'}
  else{list.innerHTML=d.accounts.map((a,i)=>
   `<div class="item"><div><div>${a.label||'(unnamed)'}</div><div class="muted">${a.algorithm} · ${a.digits} digits · ${a.period}s</div></div><button class="del" onclick="del(${i})">Delete</button></div>`).join('')}
  document.getElementById('clock').textContent=d.timeValid?('Set ('+d.epoch+' UTC)'):'Not set — sync below';
  setStatus(d.count+' account(s) stored');
 }catch(e){setStatus('Connection lost')}
}
async function post(url,body){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});const d=await r.json();if(!d.ok){setStatus('Error: '+(d.error||'failed'))}else{setStatus('Saved')}refresh();return d}
function enc(o){return Object.entries(o).map(([k,v])=>encodeURIComponent(k)+'='+encodeURIComponent(v)).join('&')}
async function addUri(){const u=document.getElementById('uri').value.trim();if(!u)return;await post('/api/accounts',enc({otpauth:u}));document.getElementById('uri').value=''}
async function addManual(){await post('/api/accounts',enc({issuer:issuer.value,account:account.value,secret:secret.value,algorithm:algorithm.value,digits:digits.value,period:period.value}));secret.value=''}
async function del(i){if(confirm('Delete this account?'))await post('/api/accounts/delete',enc({index:i}))}
async function setTime(){await post('/api/time',enc({epoch:Math.floor(Date.now()/1000)}))}
refresh();setInterval(refresh,5000);
</script>
</main></body></html>)HTML";

}  // namespace

TotpWebServer *TotpWebServer::instance_ = nullptr;

bool TotpWebServer::begin(AccountStore &store, TimeService &time) {
  store_ = &store;
  time_ = &time;
  instance_ = this;

  ssid_ = "Authenticator-" + deviceSuffix();
  WiFi.mode(WIFI_AP);
  if (!WiFi.softAP(ssid_.c_str())) {
    ESP_LOGE(kTag, "softAP failed");
    return false;
  }
  url_ = "http://" + ipToString(WiFi.softAPIP());

  server_.on("/", HTTP_GET, handleRootStatic);
  server_.on("/api/accounts", HTTP_GET, handleAccountsGetStatic);
  server_.on("/api/accounts", HTTP_POST, handleAccountsPostStatic);
  server_.on("/api/accounts/delete", HTTP_POST, handleAccountDeleteStatic);
  server_.on("/api/time", HTTP_POST, handleTimePostStatic);
  server_.onNotFound(handleNotFoundStatic);
  server_.begin();

  active_ = true;
  ESP_LOGI(kTag, "provisioning AP up ssid=%s url=%s", ssid_.c_str(), url_.c_str());
  return true;
}

void TotpWebServer::update() {
  if (active_) {
    server_.handleClient();
  }
}

void TotpWebServer::end() {
  if (!active_) {
    return;
  }
  server_.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_OFF);
  active_ = false;
  instance_ = nullptr;
  ESP_LOGI(kTag, "provisioning AP down");
}

// --- static trampolines -----------------------------------------------------

void TotpWebServer::handleRootStatic() {
  if (instance_) instance_->handleRoot();
}
void TotpWebServer::handleAccountsGetStatic() {
  if (instance_) instance_->handleAccountsGet();
}
void TotpWebServer::handleAccountsPostStatic() {
  if (instance_) instance_->handleAccountsPost();
}
void TotpWebServer::handleAccountDeleteStatic() {
  if (instance_) instance_->handleAccountDelete();
}
void TotpWebServer::handleTimePostStatic() {
  if (instance_) instance_->handleTimePost();
}
void TotpWebServer::handleNotFoundStatic() {
  if (instance_) instance_->handleNotFound();
}

// --- handlers ---------------------------------------------------------------

void TotpWebServer::handleRoot() { server_.send_P(200, "text/html", kProvisionHtml); }

void TotpWebServer::handleAccountsGet() {
  String json = "{\"count\":";
  json += String(static_cast<unsigned>(store_->count()));
  json += ",\"timeValid\":";
  json += (time_->isValid() ? "true" : "false");
  json += ",\"epoch\":";
  json += String(static_cast<unsigned long>(time_->now()));
  json += ",\"accounts\":[";
  const auto &accounts = store_->accounts();
  for (size_t i = 0; i < accounts.size(); ++i) {
    const TotpAccount &a = accounts[i];
    const char *alg = a.params.algorithm == HashType::Sha256
                          ? "SHA256"
                          : (a.params.algorithm == HashType::Sha512 ? "SHA512" : "SHA1");
    if (i > 0) json += ',';
    json += "{\"label\":\"";
    json += jsonEscape(String(a.displayLabel().c_str()));
    json += "\",\"algorithm\":\"";
    json += alg;
    json += "\",\"digits\":";
    json += String(a.params.digits);
    json += ",\"period\":";
    json += String(static_cast<unsigned long>(a.params.periodSeconds));
    json += "}";
  }
  json += "]}";
  server_.send(200, "application/json", json);
}

void TotpWebServer::handleAccountsPost() {
  TotpAccount account;
  std::string error;
  bool parsed = false;

  if (server_.hasArg("otpauth") && server_.arg("otpauth").length() > 0) {
    parsed = parseOtpAuthUri(std::string(server_.arg("otpauth").c_str()), account, &error);
  } else {
    // Manual entry: label + base32 secret + optional params.
    account.issuer = std::string(server_.arg("issuer").c_str());
    account.accountName = std::string(server_.arg("account").c_str());
    const std::string secretB32(server_.arg("secret").c_str());
    if (!base32Decode(secretB32, account.secret) || account.secret.empty()) {
      error = "Invalid base32 secret";
    } else {
      const String alg = server_.arg("algorithm");
      if (alg == "SHA256") {
        account.params.algorithm = HashType::Sha256;
      } else if (alg == "SHA512") {
        account.params.algorithm = HashType::Sha512;
      } else {
        account.params.algorithm = HashType::Sha1;
      }
      const long digits = server_.arg("digits").toInt();
      account.params.digits = (digits == 8) ? 8 : 6;
      const long period = server_.arg("period").toInt();
      account.params.periodSeconds = (period > 0 && period <= 600) ? static_cast<uint32_t>(period)
                                                                   : 30;
      if (account.issuer.empty() && account.accountName.empty()) {
        account.accountName = "Account";
      }
      parsed = true;
    }
  }

  if (!parsed) {
    server_.send(400, "application/json",
                 String("{\"ok\":false,\"error\":\"") + jsonEscape(String(error.c_str())) + "\"}");
    return;
  }
  if (!store_->add(account)) {
    server_.send(400, "application/json",
                 "{\"ok\":false,\"error\":\"Could not store account (full?)\"}");
    return;
  }
  server_.send(200, "application/json", "{\"ok\":true}");
}

void TotpWebServer::handleAccountDelete() {
  if (!server_.hasArg("index")) {
    server_.send(400, "application/json", "{\"ok\":false,\"error\":\"Missing index\"}");
    return;
  }
  const long index = server_.arg("index").toInt();
  if (index < 0 || !store_->removeAt(static_cast<size_t>(index))) {
    server_.send(400, "application/json", "{\"ok\":false,\"error\":\"Bad index\"}");
    return;
  }
  server_.send(200, "application/json", "{\"ok\":true}");
}

void TotpWebServer::handleTimePost() {
  if (!server_.hasArg("epoch")) {
    server_.send(400, "application/json", "{\"ok\":false,\"error\":\"Missing epoch\"}");
    return;
  }
  const uint64_t epoch = strtoull(server_.arg("epoch").c_str(), nullptr, 10);
  time_->setUnixTime(epoch);
  server_.send(200, "application/json", "{\"ok\":true}");
}

void TotpWebServer::handleNotFound() {
  // Redirect everything to the root so captive-portal probes land on the page.
  server_.sendHeader("Location", url_);
  server_.send(302, "text/plain", "");
}

// --- helpers ----------------------------------------------------------------

String TotpWebServer::deviceSuffix() const {
  const uint64_t mac = ESP.getEfuseMac();
  char suffix[7];
  snprintf(suffix, sizeof(suffix), "%06X", static_cast<unsigned int>(mac & 0xFFFFFF));
  return String(suffix);
}

String TotpWebServer::jsonEscape(const String &value) {
  String escaped;
  escaped.reserve(value.length() + 8);
  for (size_t i = 0; i < value.length(); ++i) {
    const char c = value[i];
    if (c == '"' || c == '\\') {
      escaped += '\\';
      escaped += c;
    } else if (c == '\n') {
      escaped += "\\n";
    } else if (static_cast<uint8_t>(c) < 0x20) {
      // skip other control characters
    } else {
      escaped += c;
    }
  }
  return escaped;
}

}  // namespace totp
