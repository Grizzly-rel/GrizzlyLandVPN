//go:build !android

package libxray

import "golang.zx2c4.com/wireguard/device"

// На не-Android сборках (проверка компиляции на хосте) UDP-сокеты движка
// не добываются: protect существует только в Android VpnService.
func wgSocketFd4(dev *device.Device) int { return -1 }

func wgSocketFd6(dev *device.Device) int { return -1 }
