# Privacy Policy

GrizzlyLandVPN is an offline-first Android VPN client. The application:

- **Does not collect, store or transmit any personal data.** There are no analytics,
  no trackers, no crash reporting services and no advertising SDKs in the app.
- **Does not require an account.** No registration, no email, no phone number.
- **Does not have a backend.** The app talks only to the VPN servers that the user
  configures themselves (their own servers or servers of their choice). Credentials
  and configuration files are stored locally on the device only.
- Connection logs, if the user enables the in-app log, are kept **in RAM only**
  (a rotating buffer of the last 3000 lines) and are never sent anywhere.

Permissions used:

- `VPN services` / `INTERNET` — to establish the VPN tunnel itself.
- `Camera` — only on demand, to scan a WireGuard/AmneziaWG configuration QR code.
- `Foreground service` — to keep the VPN connection alive and show its status.

The app is distributed as an APK signed by the developer. Builds and source code:
https://github.com/Grizzly-rel/GrizzlyLandVPN

Contact: open an issue in the repository above.
