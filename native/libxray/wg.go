// wg.go — WireGuard-движок поверх wireguard-go, живущий в том же bind-пакете,
// что и Xray-обвязка (один libgojni.so на оба ядра: два gomobile-рантайма в
// одном процессе невозможны). Имена функций с префиксом Wg* → в Java это
// Libxray.wgTurnOn(...) и т.д. Схема — как в официальном wireguard-android
// GoBackend: TurnOn(fd, UAPI-конфиг) → PeekLookAtSocketFd → VpnService.protect.
package libxray

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	wgMu         sync.Mutex
	wgHandles    = make(map[int64]*device.Device)
	wgNextHandle int64 = 1

	// Журнал движка: Java (WgRunner) периодически забирает его через
	// WgDrainLogs и льёт в LogStore. Verbose-строки (handshake, keepalive,
	// endpoint-апдейты) пишутся только при включённом подробном журнале.
	wgLogMu  sync.Mutex
	wgLogBuf []string
	wgVerbose atomic.Bool
)

const wgLogCap = 1200

func wgAppend(level, msg string) {
	wgLogMu.Lock()
	defer wgLogMu.Unlock()
	wgLogBuf = append(wgLogBuf, level+" "+msg)
	if len(wgLogBuf) > wgLogCap {
		wgLogBuf = wgLogBuf[len(wgLogBuf)-wgLogCap/2:]
	}
}

// WgVersion возвращает строку версии WireGuard-движка (для журнала).
func WgVersion() string {
	return "wgengine/1.0 (wireguard-go, UAPI)"
}

// WgTurnOn поднимает WireGuard поверх уже созданного VpnService TUN-fd.
// ipcConfig — конфиг в UAPI-формате wireguard-go (private_key=..., peer-секция
// public_key=..., endpoint=..., allowed_ip=..., persistent_keepalive_interval=...).
// verbose включает подробные логи движка (handshake и пр.) в буфер WgDrainLogs.
// Возвращает handle. UDP-сокеты создаются при Up() — сразу после TurnOn заберите
// их через WgGetSocketV4/V6 и защитите (VpnService.protect).
// wgResolveEndpoints резолвит домены в строках endpoint= UAPI-конфига.
// Новый wireguard-go парсит endpoint через netip.ParseAddrPort — ТОЛЬКО IP
// (домены отваливаются с «ParseAddr(...): unexpected character»), поэтому
// резолвим сами — как это делает официальный wg tool (getaddrinfo → системный
// DNS; в gomobile-сборке это cgo-резолвер Android). IPv4 приоритетнее: WG у
// нас поверх VpnService TUN без IPv6-маршрутов. IP-литералы проходят насквозь.
func wgResolveEndpoints(ipc string) (string, error) {
	lines := strings.Split(ipc, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "endpoint=") {
			continue
		}
		val := strings.TrimPrefix(t, "endpoint=")
		host, port, err := net.SplitHostPort(val)
		if err != nil {
			return "", fmt.Errorf("endpoint %q: %w", val, err)
		}
		if net.ParseIP(host) != nil {
			continue
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return "", fmt.Errorf("резолв endpoint %q: %w", host, err)
		}
		var ip net.IP
		for _, a := range ips {
			if a.To4() != nil {
				ip = a
				break
			}
		}
		if ip == nil && len(ips) > 0 {
			ip = ips[0]
		}
		if ip == nil {
			return "", fmt.Errorf("резолв endpoint %q: адресов не получено", host)
		}
		wgAppend("V:", "endpoint "+host+" -> "+ip.String())
		lines[i] = "endpoint=" + net.JoinHostPort(ip.String(), port)
	}
	return strings.Join(lines, "\n"), nil
}

func WgTurnOn(ipcConfig string, fd int32, verbose bool) (int64, error) {
	if strings.TrimSpace(ipcConfig) == "" {
		return 0, fmt.Errorf("пустой конфиг")
	}
	wgVerbose.Store(verbose)
	logger := &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			if wgVerbose.Load() {
				wgAppend("V:", fmt.Sprintf(format, args...))
			}
		},
		Errorf: func(format string, args ...interface{}) {
			wgAppend("E:", fmt.Sprintf(format, args...))
		},
	}
	tunDev, _, err := tun.CreateUnmonitoredTUNFromFD(int(fd))
	if err != nil {
		return 0, fmt.Errorf("tun из fd %d: %w", fd, err)
	}
	// Резолв endpoint'ов ПОСЛЕ создания tun-девайса: при ошибке резолва
	// (сеть пропала / только возвращается — DNS ещё не поднялся; это
	// транзиентная ошибка, Java ретраит старт) tunDev.Close() гарантированно
	// закрывает и fd. Владение fd у WgTurnOn безусловно с момента вызова:
	// при ЛЮБОЙ ошибке fd закрыт здесь, при успехе — закрыт в WgTurnOff.
	// Java после вызова fd не закрывает никогда.
	ipcConfig, err = wgResolveEndpoints(ipcConfig)
	if err != nil {
		tunDev.Close()
		return 0, err
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

// WgDrainLogs возвращает накопленные строки журнала движка (по одной в строке,
// с префиксом V:/E:) и очищает буфер. Java опрашивает раз в ~0.5с.
func WgDrainLogs() string {
	wgLogMu.Lock()
	defer wgLogMu.Unlock()
	if len(wgLogBuf) == 0 {
		return ""
	}
	out := strings.Join(wgLogBuf, "\n")
	wgLogBuf = nil
	return out
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
