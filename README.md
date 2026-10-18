# GrizzlyLandVPN

An Android VPN client that combines **Xray (VLESS/Reality)** and **OpenVPN** in one app,
with four connection modes, per-app split tunneling and a compact dependency set.
Min SDK 24 (Android 7.0+), arm64-v8a.

## Modes

1. **Xray only** — VLESS/Reality via `libxray` (gomobile), TUN fd is passed to the
   core through the `xray.tun.fd` environment variable (no root, no vpnservice-xray hacks).
2. **OpenVPN only** — native `libopenvpn` built with `TARGET_ANDROID`; the TUN fd is
   handed over through the management interface (`OPENTUN` + `SCM_RIGHTS`).
3. **Xray + OpenVPN (nested)** — the OpenVPN tunnel is carried through the local
   Xray SOCKS proxy (`socks-proxy`), useful when the OpenVPN endpoint is only
   reachable through VLESS/Reality.
4. **OpenVPN over SSH** — an SSH session (JSch, bundled jar) with a local TCP
   forward to the OpenVPN server; the OpenVPN server must listen on `proto tcp`.

Additional features:

- **TAP support (TapShim)** — `dev tap` servers are supported on Android's L3-only
  VpnService TUN by an in-app IP↔Ethernet converter (ARP responder included).
  The server mode is taken from the `dev` directive of the OpenVPN config itself.
- **Per-app split tunneling** — pick which apps go through the tunnel (same UX as
  OpenVPN for Android).
- **Settings export/import** — full JSON export/import of every setting, including
  the SSH section (SAF file picker or `adb` intent).
- **SSH host key pinning** — TOFU with SHA-256 fingerprint display and a hard stop
  on host key change.
- **Survivability** — the SSH tunnel supervisor retries network errors forever
  (capped backoff), permanent failures (auth, host key change) stop the service
  with a clear error; power-friendly polling intervals.

## Building

Requirements: JDK 17, Android SDK (platform 34), Gradle 8.7.

```bash
git clone https://github.com/<owner>/GrizzlyLandVPN.git
cd GrizzlyLandVPN
gradle assembleRelease        # or assembleDebug
```

Notes:

- `libxray.aar` (in `app/libs/`) is a gomobile build of Xray-core with a
  gVisor-based TUN inbound and fullcone UDP support; `libopenvpn.so` (in
  `app/src/main/jniLibs/arm64-v8a/`) is OpenVPN built for Android. Both are
  prebuilt and committed so the project builds out of the box.
- Signing: the release config reads `keystore/keystore.properties`
  (see `.gitignore`). Without it the build falls back to debug signing.
- The app is signed; installation requires "install unknown apps" permission.

## Security notes

- No accounts, no telemetry, no analytics. All configuration lives on the device.
- `allowBackup` is disabled; signing keys are not part of the repository.
- Server credentials (UUIDs, keys, passwords) are entered by the user and stored
  only in the app's private storage.

## Disclaimer

This is a personal VPN client. You are responsible for complying with the laws
of your jurisdiction and with the terms of service of any servers you connect to.
