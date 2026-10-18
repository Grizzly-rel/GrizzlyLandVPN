// Package libxray exposes a minimal API to run Xray-core from Java via gomobile bind.
package libxray

import (
	"os"
	"strconv"

	"github.com/xtls/xray-core/core"
	// Регистрирует поддержку JSON-конфигурации и всех протоколов.
	_ "github.com/xtls/xray-core/main/distro/all"
)

var instance *core.Instance

// SetTunFd передаёт файловый дескриптор TUN (созданный Android VpnService)
// в ядро Xray через env-переменную xray.tun.fd. Вызывать до Run().
func SetTunFd(fd int) {
	_ = os.Setenv("xray.tun.fd", strconv.Itoa(fd))
}

// Run запускает Xray с заданным JSON-конфигом. Возвращает ошибку при неудаче.
func Run(configJSON string) error {
	inst, err := core.StartInstance("json", []byte(configJSON))
	if err != nil {
		return err
	}
	instance = inst
	return nil
}

// Stop останавливает запущенный экземпляр Xray.
func Stop() {
	if instance != nil {
		instance.Close()
		instance = nil
	}
}

// Version возвращает версию ядра Xray.
func Version() string {
	return core.Version()
}
