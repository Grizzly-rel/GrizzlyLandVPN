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

## Prebuilt binaries

Three binaries are committed so the project builds out of the box. Their origin:

| File | What it is | Origin |
|------|-----------|--------|
| `app/libs/libxray.aar` | gomobile binding of Xray-core exposing `SetTunFd` / `Run` / `Stop` / `Version` | Built with `gomobile bind` from the wrapper committed under [`native/libxray/`](native/libxray) against a locally patched Xray-core (see below) |
| `app/src/main/jniLibs/arm64-v8a/libopenvpn.so` | OpenVPN **2.6.14** for Android (`TARGET_ANDROID`), built without LZO/LZ4 | Built from the upstream OpenVPN sources; receives the TUN fd through the management interface (`OPENTUN` + `SCM_RIGHTS`) |
| `app/libs/jsch-2.28.0.jar` | JSch SSH client (mwiede fork) | Unmodified Maven Central artifact `com.github.mwiede:jsch:2.28.0` (SHA-1 verified against Maven Central) |

Nothing was downloaded from third parties except the Maven Central artifacts.

Notes on `libxray.aar`:

- The gomobile wrapper is ~40 lines of Go, committed in
  [`native/libxray/libxray.go`](native/libxray/libxray.go). It passes the Android
  TUN file descriptor to the Xray core through the `xray.tun.fd` environment
  variable and starts/stops the core with a JSON config — nothing else.
- It was linked against a local Xray-core checkout (commit `7da5dae` at build
  time) with a gVisor-based `tun` inbound and fullcone UDP support. That patched
  fork is not part of this repository.

Reproducing `libxray.aar`:

```bash
git clone https://github.com/XTLS/Xray-core.git
mkdir libxray && cp <this repo>/native/libxray/* libxray/
# point the `replace github.com/xtls/xray-core => ...` line in libxray/go.mod
# at your Xray-core checkout (stock or patched — the wrapper only needs
# core.StartInstance())
cd libxray
gomobile bind -target=android -androidapi 24 -o libxray.aar .
cp libxray.aar <this repo>/app/libs/libxray.aar
```

For `libopenvpn.so` no build script is included in this repository; any OpenVPN
2.6.x Android build compiled with `TARGET_ANDROID` (management-interface TUN
handover) is a drop-in replacement for
`app/src/main/jniLibs/arm64-v8a/libopenvpn.so`.

If you don't trust committed binaries — a fair position for a VPN client — you
don't have to: replace them with your own builds, or just build the app from
this repository yourself. Every `v*` tag is also built automatically by GitHub
Actions from a clean checkout (`.github/workflows/build-apk.yml`); CI artifacts
are debug-signed (the release keystore is not available to CI), but they
demonstrate that the published sources build into a working APK with no extra
steps.

## Security notes

- No accounts, no telemetry, no analytics. All configuration lives on the device.
- `allowBackup` is disabled; signing keys are not part of the repository.
- Server credentials (UUIDs, keys, passwords) are entered by the user and stored
  only in the app's private storage.

## Disclaimer

This is a personal VPN client. You are responsible for complying with the laws
of your jurisdiction and with the terms of service of any servers you connect to.
