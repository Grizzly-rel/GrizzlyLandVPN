package com.grizzlyland.vpn;

import android.util.Log;

import java.util.function.IntConsumer;

import libxray.Libxray;

/**
 * Обёртка над движком wireguard-go (внутри app/libs/libxray.aar → Java-класс
 * Libxray, функции wg*).
 *
 * Живёт, пока работает VPN в режиме WireGuard. Схема — как в официальном
 * wireguard-android GoBackend: TurnOn(fd, UAPI-конфиг) → забрать fd UDP-сокетов
 * движка (PeekLookAtSocketFd) → защитить их VpnService.protect(), иначе трафик
 * движка зациклится через собственный TUN. При смене сети сервис пересоздаёт
 * туннель целиком (сокеты движка перепривязываются).
 */
public class WgRunner {

    public interface Listener {
        /** Движок поднят, сокеты защищены — можно отмечать VPN подключённым. */
        void onUp();

        /** Финальная ошибка запуска (конфиг/TUN) — сервис глушит VPN. */
        void onError(String message);
    }

    private final IntConsumer protect;
    private final Listener listener;
    private volatile long handle = -1;
    private volatile boolean engineRunning = false;
    private Thread logPoller;

    public WgRunner(IntConsumer protect, Listener listener) {
        this.protect = protect;
        this.listener = listener;
    }

    /**
     * Запускает движок в отдельном потоке (IpcSet/Up могут занять время).
     * @param verbose подробные логи движка (handshake и пр.) — флаг «Подробный
     *                журнал»; ошибки движка пишутся в журнал всегда.
     */
    public synchronized void start(int tunFd, String ipcConfig, boolean verbose) {
        if (handle != -1) {
            LogStore.add("Wg", "start(): движок уже запущен — пропуск");
            return;
        }
        Thread t = new Thread(() -> {
            try {
                long h = Libxray.wgTurnOn(ipcConfig, tunFd, verbose);
                handle = h;
                engineRunning = true;
                startLogPoller();
                int fd4 = Libxray.wgGetSocketV4(h);
                int fd6 = Libxray.wgGetSocketV6(h);
                if (fd4 > 0) {
                    protect.accept(fd4);
                }
                if (fd6 > 0) {
                    protect.accept(fd6);
                }
                LogStore.add("Wg", "движок поднят (handle=" + h + ", udp4 fd=" + fd4
                        + ", udp6 fd=" + fd6 + ")");
                listener.onUp();
            } catch (Exception e) {
                handle = -1;
                engineRunning = false;
                // Движок мог успеть что-то залогировать до падения (например,
                // разбор UAPI) — забираем и это.
                drainLogs();
                Log.e("WgRunner", "turnOn failed", e);
                listener.onError(e.getMessage() == null ? e.toString() : e.getMessage());
            }
        }, "wg-engine");
        t.setDaemon(true);
        t.start();
    }

    /** Опросчик журнала движка: раз в 0.5с забирает строки в LogStore. */
    private void startLogPoller() {
        logPoller = new Thread(() -> {
            while (engineRunning) {
                drainLogs();
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    return;
                }
            }
        }, "wg-log-poll");
        logPoller.setDaemon(true);
        logPoller.start();
    }

    /** Забирает накопленные строки журнала движка в LogStore. */
    private static void drainLogs() {
        try {
            String chunk = Libxray.wgDrainLogs();
            if (chunk == null || chunk.isEmpty()) {
                return;
            }
            for (String line : chunk.split("\n")) {
                if (!line.isEmpty()) {
                    LogStore.add("Wg", line);
                }
            }
        } catch (Throwable ignored) {
        }
    }

    public synchronized void stop() {
        engineRunning = false;
        long h = handle;
        handle = -1;
        if (h == -1) {
            return;
        }
        try {
            Libxray.wgTurnOff(h);
            LogStore.add("Wg", "движок остановлен (handle=" + h + ")");
        } catch (Exception e) {
            Log.e("WgRunner", "turnOff failed", e);
            LogStore.add("Wg", "ошибка остановки движка: " + e);
        } finally {
            drainLogs();
        }
    }

    public boolean isRunning() {
        return handle != -1;
    }
}
