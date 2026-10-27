// awg.go — AmneziaWG-движок поверх amneziawg-go v3, живущий в том же
// bind-пакете, что и Xray/WireGuard-обвязки (один libgojni.so на все ядра:
// два gomobile-рантайма в одном процессе невозможны). Имена функций с
// префиксом Awg* → в Java это Libxray.awgTurnOn(...) и т.д. Схема — как у
// wg.go (официальный wireguard-android GoBackend): TurnOn(fd, UAPI-конфиг) →
// PeekLookAtSocketFd → VpnService.protect.
// Отличие от WireGuard: UAPI-конфиг дополнен параметрами обфускации
// jc=, jmin=, jmax=, s1=, s2=, h1=..h4= (их вычисляет AwgConfigParser на Java
// из wg-quick конфига; для «чужих» конфигов — значения из [Interface]).
// Ключи — те же curve25519 base64, что и у WireGuard.
package libxray

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	awgConn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgDevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgTun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	awgMu         sync.Mutex
	awgHandles    = make(map[int64]*awgDevice.Device)
	awgNextHandle int64 = 1

	// Журнал движка: Java (AwgRunner) периодически забирает его через
	// AwgDrainLogs и льёт в LogStore. Verbose-строки (handshake, keepalive,
	// endpoint-апдейты) пишутся только при включённом подробном журнале.
	awgLogMu   sync.Mutex
	awgLogBuf  []string
	awgVerbose atomic.Bool
)

const awgLogCap = 1200

func awgAppend(level, msg string) {
	awgLogMu.Lock()
	defer awgLogMu.Unlock()
	awgLogBuf = append(awgLogBuf, level+" "+msg)
	if len(awgLogBuf) > awgLogCap {
		awgLogBuf = awgLogBuf[len(awgLogBuf)-awgLogCap/2:]
	}
}

// AwgVersion возвращает строку версии AmneziaWG-движка (для журнала).
func AwgVersion() string {
	return "awgengine/1.0 (amneziawg-go v3.1.20260828, UAPI)"
}

// awgResolveEndpoints резолвит домены в строках endpoint= UAPI-конфига.
// ParseEndpoint форка (как и у нового wireguard-go) понимает ТОЛЬКО IP:port
// (netip.ParseAddrPort — домены отваливаются с «unexpected character»),
// поэтому резолвим сами — getaddrinfo → системный DNS (в gomobile-сборке это
// cgo-резолвер Android). IPv4 приоритетнее: AWG у нас поверх VpnService TUN
// без IPv6-маршрутов. IP-литералы проходят насквозь.
func awgResolveEndpoints(ipc string) (string, error) {
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
			return "", fmt.Errorf("%s %q: %w", tr("резолв endpoint", "resolve endpoint"), host, err)
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
			return "", fmt.Errorf("%s %q: %s", tr("резолв endpoint", "resolve endpoint"), host, tr("адресов не получено", "no addresses"))
		}
		awgAppend("V:", "endpoint "+host+" -> "+ip.String())
		lines[i] = "endpoint=" + net.JoinHostPort(ip.String(), port)
	}
	return strings.Join(lines, "\n"), nil
}

// AwgTurnOn поднимает AmneziaWG поверх уже созданного VpnService TUN-fd.
// ipcConfig — конфиг в UAPI-формате amneziawg-go (private_key=..., peer-секции
// public_key=..., endpoint=..., allowed_ip=..., persistent_keepalive_interval=...
// плюс параметры обфускации jc=/jmin=/jmax=/s1=/s2=/h1=..h4=).
// verbose включает подробные логи движка в буфер AwgDrainLogs.
// Возвращает handle. UDP-сокеты создаются при Up() — сразу после TurnOn
// заберите их через AwgGetSocketV4/V6 и защитите (VpnService.protect).
func AwgTurnOn(ipcConfig string, fd int32, verbose bool) (int64, error) {
	if strings.TrimSpace(ipcConfig) == "" {
		return 0, errors.New(tr("пустой конфиг", "empty config"))
	}
	awgVerbose.Store(verbose)
	logger := &awgDevice.Logger{
		Verbosef: func(format string, args ...interface{}) {
			if awgVerbose.Load() {
				awgAppend("V:", fmt.Sprintf(format, args...))
			}
		},
		Errorf: func(format string, args ...interface{}) {
			awgAppend("E:", fmt.Sprintf(format, args...))
		},
	}
	tunDev, _, err := awgTun.CreateUnmonitoredTUNFromFD(int(fd))
	if err != nil {
		return 0, fmt.Errorf("%s %d: %w", tr("tun из fd", "tun from fd"), fd, err)
	}
	// Резолв endpoint'ов ПОСЛЕ создания tun-девайса: при ошибке резолва
	// (транзиентная ошибка — Java ретраит старт) tunDev.Close() гарантированно
	// закрывает и fd. Владение fd у AwgTurnOn безусловно с момента вызова:
	// при ЛЮБОЙ ошибке fd закрыт здесь, при успехе — закрыт в AwgTurnOff.
	// Java после вызова fd не закрывает никогда.
	ipcConfig, err = awgResolveEndpoints(ipcConfig)
	if err != nil {
		tunDev.Close()
		return 0, err
	}
	dev := awgDevice.NewDevice(tunDev, awgConn.NewDefaultBind(), logger)
	if err = dev.IpcSet(strings.TrimRight(ipcConfig, "\n")); err != nil {
		dev.Close()
		return 0, fmt.Errorf("ipc set: %w", err)
	}
	if err = dev.Up(); err != nil {
		dev.Close()
		return 0, fmt.Errorf("up: %w", err)
	}
	awgMu.Lock()
	defer awgMu.Unlock()
	h := awgNextHandle
	awgNextHandle++
	awgHandles[h] = dev
	return h, nil
}

// AwgTurnOff останавливает движок и закрывает TUN-fd (владение fd у движка).
func AwgTurnOff(h int64) error {
	awgMu.Lock()
	dev, ok := awgHandles[h]
	if ok {
		delete(awgHandles, h)
	}
	awgMu.Unlock()
	if !ok {
		return fmt.Errorf("%s %d", tr("нет такого handle", "no such handle"), h)
	}
	dev.Close()
	return nil
}

// AwgDrainLogs возвращает накопленные строки журнала движка (по одной в
// строке, с префиксом V:/E:) и очищает буфер. Java опрашивает раз в ~0.5с.
func AwgDrainLogs() string {
	awgLogMu.Lock()
	defer awgLogMu.Unlock()
	if len(awgLogBuf) == 0 {
		return ""
	}
	out := strings.Join(awgLogBuf, "\n")
	awgLogBuf = nil
	return out
}

// AwgGetSocketV4 — fd UDPv4-сокета движка для VpnService.protect() (-1, если нет).
// PeekLookAtSocketFd4/6 в форке объявлены без android-билдтега (conn/boundif.go),
// поэтому отдельные файлы под платформы, как у wg.go, не нужны.
func AwgGetSocketV4(h int64) int32 {
	dev, ok := awgLookup(h)
	if !ok {
		return -1
	}
	bind, ok := dev.Bind().(*awgConn.StdNetBind)
	if !ok {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd4()
	if err != nil {
		return -1
	}
	return int32(fd)
}

// AwgGetSocketV6 — fd UDPv6-сокета движка для VpnService.protect() (-1, если нет).
func AwgGetSocketV6(h int64) int32 {
	dev, ok := awgLookup(h)
	if !ok {
		return -1
	}
	bind, ok := dev.Bind().(*awgConn.StdNetBind)
	if !ok {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd6()
	if err != nil {
		return -1
	}
	return int32(fd)
}

// AwgGenPrivateKey генерирует новый приватный ключ (base64). Кривая та же,
// что у WireGuard (curve25519) — формат ключей идентичен.
func AwgGenPrivateKey() (string, error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	return k.String(), nil
}

// AwgPublicKeyOf вычисляет публичный ключ из приватного (base64).
func AwgPublicKeyOf(priv string) (string, error) {
	k, err := wgtypes.ParseKey(strings.TrimSpace(priv))
	if err != nil {
		return "", err
	}
	return k.PublicKey().String(), nil
}

func awgLookup(h int64) (*awgDevice.Device, bool) {
	awgMu.Lock()
	defer awgMu.Unlock()
	dev, ok := awgHandles[h]
	return dev, ok
}
