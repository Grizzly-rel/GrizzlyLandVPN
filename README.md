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
5. **WireGuard** — userspace engine (wireguard-go, embedded in the same native
   library as Xray) over the VpnService TUN. The config is a standard wg-quick
   `.conf` (paste it as-is); key pair generation is built in. UDP sockets are
   protected via `VpnService.protect`; on network change the tunnel is
   re-created automatically.

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
| `app/libs/libxray.aar` | gomobile binding of Xray-core exposing `SetTunFd` / `Run` / `Stop` / `Version` | Built with `gomobile bind` from the wrapper committed under [`native/libxray/`](native/libxray) against **pristine upstream Xray-core pinned at commit `7da5dae`** — git submodule [`native/xray-core`](native/xray-core), see below |
| `app/src/main/jniLibs/arm64-v8a/libopenvpn.so` | OpenVPN **2.6.14** for Android (`TARGET_ANDROID`), built without LZO/LZ4 | Built from the upstream OpenVPN sources; receives the TUN fd through the management interface (`OPENTUN` + `SCM_RIGHTS`) |
| `app/libs/jsch-2.28.0.jar` | JSch SSH client (mwiede fork) | Unmodified Maven Central artifact `com.github.mwiede:jsch:2.28.0` (SHA-1 verified against Maven Central) |

Nothing was downloaded from third parties except the Maven Central artifacts.

Notes on `libxray.aar`:

- The gomobile wrapper is ~40 lines of Go, committed in
  [`native/libxray/libxray.go`](native/libxray/libxray.go). It passes the Android
  TUN file descriptor to the Xray core through the `xray.tun.fd` environment
  variable and starts/stops the core with a JSON config — nothing else.
- It links against **upstream Xray-core pinned at commit `7da5dae`** — no local
  patches. At that commit Xray-core itself ships the TUN inbound on the gVisor
  stack (`proxy/tun/stack_gvisor.go`), fullcone UDP handling
  (`proxy/tun/udp_fullcone.go`) and reads the TUN fd from the `xray.tun.fd`
  environment variable (`common/platform/platform.go`). Upstream `main` has
  already diverged from this state, which is why the exact commit is pinned as
  a submodule.

Reproducing `libxray.aar`:

```bash
git clone https://github.com/Grizzly-rel/GrizzlyLandVPN.git
cd GrizzlyLandVPN
git submodule update --init   # checks out native/xray-core @ 7da5dae
cd native/libxray             # go.mod already points at ../xray-core
# -checklinkname=0 is required: github.com/wlynxg/anet (a dependency of the
# tun proxy) uses go:linkname into the net package, which the linker refuses
# by default. The app itself is arm64-v8a only.
gomobile bind -target=android/arm64 -androidapi 24 \
    -ldflags="-checklinkname=0" -o ../../app/libs/libxray.aar .
```

Any other Xray-core version works as the replace target too — the wrapper only
needs `core.StartInstance()`; the pin just records the exact state the shipped
`.aar` was built from.

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
