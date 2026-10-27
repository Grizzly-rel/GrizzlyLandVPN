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

// ---- Локализация ошибок обёртки (наш код; ядро xray-core не переводим) ----
// Язык выставляется из Java при старте приложения (L10n.init → Libxray.setLang):
// "ru" — русский, любой другой — английский (дефолт).
var lang = "en"

// SetLang задаёт язык текстов ошибок обёртки ("ru" или "en").
func SetLang(l string) {
	if l == "ru" {
		lang = "ru"
	} else {
		lang = "en"
	}
}

// tr выбирает текст ошибки по текущему языку.
func tr(ru, en string) string {
	if lang == "ru" {
		return ru
	}
	return en
}

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
