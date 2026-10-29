package com.grizzlyland.vpn;

import android.util.Log;

import java.util.function.BooleanSupplier;
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
    /** Живой флаг «Подробный журнал»: подробные строки (V:) попадают в журнал
     *  только при включённом флаге, ошибки (E:) — всегда. Движок при этом ВСЕГДА
     *  пишет в кольцевой буфер памяти (не на диск), поэтому переключение флага
     *  применяется на лету, без перезапуска движка. */
    private final BooleanSupplier verboseSupplier;
    private volatile long handle = -1;
    private volatile boolean engineRunning = false;
    private Thread logPoller;

    // ---- Сторож «движок не может отправлять» --------------------------------
    // Серия E:-строк «Failed to send …» = мёртвый маршрут под защищёнными
    // (protect) сокетами: например, после смены сети самовосстановление не
    // сработало. Серия тянется, пока ошибки появляются чаще, чем раз в
    // SEND_FAIL_GAP_MS; если она длится дольше SEND_FAIL_EPISODE_MS — один раз
    // зовём onPersistentSendFailure (сервис пересоздаёт туннель, не чаще
    // раза в несколько минут — его сторона). Короткие всплески при обычном
    // обрыве сети (1-10 с до возврата маршрута или до грейс-глушения) серию
    // не набирают и НЕ вызывают перезапуск.
    private static final long SEND_FAIL_EPISODE_MS = 90_000;
    private static final long SEND_FAIL_GAP_MS = 60_000;
    private volatile Runnable onPersistentSendFailure;
    private volatile long sendFailFirstMs;
    private volatile long sendFailLastMs;

    /** Колбэк «движок 90+ с подряд не может отправлять пакеты» (один раз на
     *  серию; вызывается из потока поллера журнала). */
    public void setOnPersistentSendFailure(Runnable r) {
        onPersistentSendFailure = r;
    }

    private void noteSendFailure() {
        long now = android.os.SystemClock.elapsedRealtime();
        if (sendFailFirstMs == 0 || now - sendFailLastMs > SEND_FAIL_GAP_MS) {
            sendFailFirstMs = now; // новая серия (или пауза слишком длинная)
        }
        sendFailLastMs = now;
        if (now - sendFailFirstMs >= SEND_FAIL_EPISODE_MS) {
            sendFailFirstMs = 0; // одна сигнализация на серию
            Runnable r = onPersistentSendFailure;
            if (r != null) {
                try {
                    r.run();
                } catch (Exception ignored) {
                }
            }
        }
    }
    // --------------------------------------------------------------------------

    public WgRunner(IntConsumer protect, BooleanSupplier verboseSupplier, Listener listener) {
        this.protect = protect;
        this.verboseSupplier = verboseSupplier;
        this.listener = listener;
    }

    /**
     * Запускает движок в отдельном потоке (IpcSet/Up могут занять время).
     * Verbose-логи движка (handshake и пр.) всегда пишутся в кольцевой буфер
     * памяти; видимость их в журнале регулирует живой флаг verboseSupplier.
     */
    public synchronized void start(int tunFd, String ipcConfig) {
        if (handle != -1) {
            LogStore.add("Wg", L10n.s(R.string.log_arun_01));
            return;
        }
        Thread t = new Thread(() -> {
            try {
                long h = Libxray.wgTurnOn(ipcConfig, tunFd, true);
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
                LogStore.add("Wg", L10n.s(R.string.log_arun_02) + h + ", udp4 fd=" + fd4
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
                    // Опрос раз в секунду: буфер движка вмещает 1200 строк
                    // (переполнение маловероятно), строки не теряются, CPU
                    // просыпается вдвое реже.
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    return;
                }
            }
        }, "wg-log-poll");
        logPoller.setDaemon(true);
        logPoller.start();
    }

    /** Забирает накопленные строки журнала движка в LogStore.
     *  Подробные строки (префикс V:) проходят только при включённом «Подробном
     *  журнале» — флаг читается на каждой порции, поэтому кнопка срабатывает
     *  мгновенно (поллер 0.5с), без перезапуска движка. Ошибки (E:) — всегда. */
    private void drainLogs() {
        try {
            String chunk = Libxray.wgDrainLogs();
            if (chunk == null || chunk.isEmpty()) {
                return;
            }
            boolean verbose = verboseSupplier == null || verboseSupplier.getAsBoolean();
            for (String line : chunk.split("\n")) {
                if (line.isEmpty()) {
                    continue;
                }
                if (!verbose && line.startsWith("V:")) {
                    continue;
                }
                if (line.startsWith("E:") && line.contains("Failed to send")) {
                    noteSendFailure();
                }
                LogStore.add("Wg", line);
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
            LogStore.add("Wg", L10n.s(R.string.log_arun_03) + h + ")");
        } catch (Exception e) {
            Log.e("WgRunner", "turnOff failed", e);
            LogStore.add("Wg", L10n.s(R.string.log_arun_04) + e);
        } finally {
            drainLogs();
        }
    }

    public boolean isRunning() {
        return handle != -1;
    }
}
