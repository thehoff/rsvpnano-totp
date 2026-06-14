# ESP32-S3 Authenticator

An open-source TOTP authenticator (the 6-digit, 30-second codes used for two-factor
authentication) built on the Waveshare ESP32-S3 device. It shows live codes on the
device, stores secrets on the device's internal flash, and lets you add accounts from a
phone or laptop over Bluetooth or Wi-Fi — no app required.

> This project began as the RSVP Nano speed-reader and was converted into an authenticator.
> The reader firmware has been removed; the hardware, display, and input stack are reused.

## Features

- TOTP code generation following RFC 6238 (HOTP RFC 4226), with SHA-1, SHA-256, and
  SHA-512, and 6 or 8 digit codes.
- On-device list of accounts with the current code and a per-code countdown.
- Secrets stored in the ESP32 internal flash (NVS), never on removable media.
- Account provisioning from a phone/laptop, app-free:
  - **Bluetooth** via a hosted Web Bluetooth page (Android / desktop Chrome or Edge).
  - **Wi-Fi** via a captive setup page (works everywhere, including iPhone).
- Time keeping with NTP-at-boot (when Wi-Fi credentials are saved), a soft RTC that
  survives standby, and a browser/Bluetooth "set the clock" fallback.

## What you need

- The ESP32-S3 device.
- A USB-C **data** cable.
- Chrome or Edge on a desktop computer for browser flashing.
- A phone or laptop to add accounts after flashing.

## Flash the firmware

Use the hosted flasher in Chrome or Edge on desktop, connect the device over USB, and
follow the installer prompts. The flasher uses ESP Web Tools and Web Serial, so it must
run from HTTPS or localhost.

## Add accounts

There is no camera for scanning QR codes, so accounts are entered from a phone or laptop.
Both methods accept an `otpauth://` provisioning URI (the string a QR code encodes) or a
manually typed label + base32 secret, and neither ever reads a stored secret back.

### Option 1: Bluetooth (no app — Android / desktop)

1. On the device, press `PWR` to open the menu and choose **Setup over Bluetooth**.
2. Open the hosted **Web Bluetooth setup page** (`authenticator.html` on the flasher site)
   in Chrome or Edge.
3. Tap **Connect** and pick `Authenticator-XXXXXX`.
4. Paste an `otpauth://` URI or fill in the fields, and add the account.
5. Hold `PWR` on the device to leave setup.

> iPhone/iPad Safari does not support Web Bluetooth. Use Wi-Fi setup on iOS, or a
> Web-Bluetooth-capable browser such as Bluefy.

### Option 2: Wi-Fi (works everywhere, including iPhone)

1. On the device, press `PWR` and choose **Setup over Wi-Fi**.
2. Join the `Authenticator-XXXXXX` Wi-Fi network shown on screen.
3. Open `http://192.168.4.1` in any browser.
4. Add accounts, then hold `PWR` on the device to leave setup.

## Keeping time accurate

TOTP needs an accurate clock, and the board has no battery-backed RTC chip. The firmware:

- Keeps the ESP32 internal clock running through light-sleep standby on battery.
- Syncs from NTP at boot when station Wi-Fi credentials are saved.
- Accepts a clock push from the setup pages (over Bluetooth or Wi-Fi) — handy when the
  device has no internet access.
- Persists the time to flash periodically so a cold boot starts close.

If the on-device list shows **CLOCK NOT SET**, open either setup page and use
"Sync clock from this browser".

## Device controls

- `PWR` short press (code list): open the menu.
- `PWR` short press (menu): back to the list.
- `PWR` hold (setup screens): leave setup.
- `PWR` hold (list / menu): power off. Press `PWR` to start again.
- `BOOT` short press: cycle screen brightness.
- Swipe up/down on the code list to move the selection.

## Security notes

- Secrets are stored unencrypted in the device's internal flash (NVS). Anyone with
  physical access to an unlocked device can read codes; a PIN/encryption layer is a
  possible future addition.
- The provisioning APIs are write-only for secrets: the listing endpoints return only
  labels and parameters, never the secret material.
- Provisioning radios (Bluetooth / Wi-Fi AP) are only active while you are in a setup
  screen, and shut down when you leave it.

## Build from source

Firmware builds with PlatformIO:

```bash
pio run                 # build
pio run -t upload       # flash a connected device
pio device monitor      # serial logs
```

## Tests

The TOTP core (SHA-1/256/512, HMAC, Base32, HOTP, TOTP, the `otpauth://` parser, and the
account storage codec) is dependency-free and unit-tested against the official RFC test
vectors. The same code runs on host and on device.

```bash
pio test -e native_test
```

## How it works

| Area | Source |
| --- | --- |
| Crypto core (host-tested) | `src/totp/Sha*.cpp`, `Hmac.cpp`, `Base32.*`, `Totp.*`, `OtpAuthUri.*` |
| Account model + storage | `src/totp/TotpAccount.h`, `AccountCodec.*`, `AccountStore.*` |
| Time keeping | `src/totp/TimeService.*` |
| Device app / UI | `src/totp/TotpApp.*` |
| Wi-Fi provisioning | `src/totp/TotpWebServer.*` |
| Bluetooth provisioning | `src/totp/TotpBleServer.*`, `web/authenticator.html` |

## License

MIT. See [LICENSE](LICENSE).

The embedded OpenDyslexic and Atkinson Hyperlegible typeface assets are derived from the
upstream projects and are included under the SIL Open Font License. See
[third_party/opendyslexic/OFL.txt](third_party/opendyslexic/OFL.txt) and
[third_party/atkinson-hyperlegible/OFL.txt](third_party/atkinson-hyperlegible/OFL.txt).
</content>
