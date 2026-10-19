// wg.go — WireGuard-движок поверх wireguard-go, живущий в том же bind-пакете,
// что и Xray-обвязка (один libgojni.so на оба ядра: два gomobile-рантайма в
// одном процессе невозможны). Имена функций с префиксом Wg* → в Java это
// Libxray.wgTurnOn(...) и т.д. Схема — как в официальном wireguard-android
// GoBackend: TurnOn(fd, UAPI-конфиг) → PeekLookAtSocketFd → VpnService.protect.
package libxray

import (
	"fmt"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	wgMu         sync.Mutex
	wgHandles    = make(map[int64]*device.Device)
	wgNextHandle int64 = 1
)

// WgVersion возвращает строку версии WireGuard-движка (для журнала).
func WgVersion() string {
	return "wgengine/1.0 (wireguard-go, UAPI)"
}

// WgTurnOn поднимает WireGuard поверх уже созданного VpnService TUN-fd.
// ipcConfig — конфиг в UAPI-формате wireguard-go (private_key=..., peer-секция
// public_key=..., endpoint=..., allowed_ip=..., persistent_keepalive_interval=...).
// Возвращает handle. UDP-сокеты создаются при Up() — сразу после TurnOn заберите
// их через WgGetSocketV4/V6 и защитите (VpnService.protect).
func WgTurnOn(ipcConfig string, fd int32) (int64, error) {
	if strings.TrimSpace(ipcConfig) == "" {
		return 0, fmt.Errorf("пустой конфиг")
	}
	logger := device.NewLogger(device.LogLevelError, "[wg] ")
	tunDev, _, err := tun.CreateUnmonitoredTUNFromFD(int(fd))
	if err != nil {
		return 0, fmt.Errorf("tun из fd %d: %w", fd, err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err = dev.IpcSet(strings.TrimRight(ipcConfig, "\n")); err != nil {
		dev.Close()
		return 0, fmt.Errorf("ipc set: %w", err)
	}
	if err = dev.Up(); err != nil {
		dev.Close()
		return 0, fmt.Errorf("up: %w", err)
	}
	wgMu.Lock()
	defer wgMu.Unlock()
	h := wgNextHandle
	wgNextHandle++
	wgHandles[h] = dev
	return h, nil
}

// WgTurnOff останавливает движок и закрывает TUN-fd (владение fd у движка).
func WgTurnOff(h int64) error {
	wgMu.Lock()
	dev, ok := wgHandles[h]
	if ok {
		delete(wgHandles, h)
	}
	wgMu.Unlock()
	if !ok {
		return fmt.Errorf("нет такого handle: %d", h)
	}
	dev.Close()
	return nil
}

// WgGetSocketV4 — fd UDPv4-сокета движка для VpnService.protect() (-1, если нет).
func WgGetSocketV4(h int64) int32 {
	dev, ok := wgLookup(h)
	if !ok {
		return -1
	}
	return int32(wgSocketFd4(dev))
}

// WgGetSocketV6 — fd UDPv6-сокета движка для VpnService.protect() (-1, если нет).
func WgGetSocketV6(h int64) int32 {
	dev, ok := wgLookup(h)
	if !ok {
		return -1
	}
	return int32(wgSocketFd6(dev))
}

// WgGenPrivateKey генерирует новый приватный ключ (base64).
func WgGenPrivateKey() (string, error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	return k.String(), nil
}

// WgPublicKeyOf вычисляет публичный ключ из приватного (base64).
func WgPublicKeyOf(priv string) (string, error) {
	k, err := wgtypes.ParseKey(strings.TrimSpace(priv))
	if err != nil {
		return "", err
	}
	return k.PublicKey().String(), nil
}

func wgLookup(h int64) (*device.Device, bool) {
	wgMu.Lock()
	defer wgMu.Unlock()
	dev, ok := wgHandles[h]
	return dev, ok
}
