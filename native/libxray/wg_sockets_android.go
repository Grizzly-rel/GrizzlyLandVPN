//go:build android

package libxray

import (
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// fd UDP-сокетов движка (Android-сборка): PeekLookAtSocketFd* объявлены в
// conn/boundif_android.go и существуют только в android-сборке wireguard-go
// (их использует официальный wireguard-android для VpnService.protect).
func wgSocketFd4(dev *device.Device) int {
	bind, ok := dev.Bind().(*conn.StdNetBind)
	if !ok {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd4()
	if err != nil {
		return -1
	}
	return fd
}

func wgSocketFd6(dev *device.Device) int {
	bind, ok := dev.Bind().(*conn.StdNetBind)
	if !ok {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd6()
	if err != nil {
		return -1
	}
	return fd
}
