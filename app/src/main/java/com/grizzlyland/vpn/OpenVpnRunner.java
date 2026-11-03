package com.grizzlyland.vpn;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;

/**
 * Управляет нативным процессом OpenVPN.
 *
 * Собирает .ovpn-конфиг через {@link OpenVpnConfigBuilder}, пишет его вместе с
 * ключами в приватный каталог приложения и запускает нативный бинарник openvpn.
 *
 * Нативный openvpn собран с TARGET_ANDROID (см. jniLibs/arm64-v8a/libopenvpn.so) и
 * открывает TUN-интерфейс через management-интерфейс: {@link OpenVpnManagementThread}
 * поднимает UNIX-сокет, openvpn подключается к нему (--management-client), и на команду
 * OPENTUN приложение отдаёт файловый дескриптор TUN от VpnService через SCM_RIGHTS.
 * Бинарник поставляется как нативная библиотека в nativeLibraryDir (на Android 10+
 * exec из filesDir запрещён SELinux).
 */
public class OpenVpnRunner {

    private static final String TAG = "OpenVpnRunner";
    private static final String BINARY_NAME = "libopenvpn.so";

    private Process process;
    private boolean running = false;
    private OpenVpnManagementThread managementThread;
    /** true между началом штатного stop() и смертью процесса — watcher молчит. */
    private volatile boolean intentionalStop = false;
    /** Фатальная ошибка в выводе (битый конфиг, отказ авторизации) — рестарт
     *  процесса не поможет, ретраить смысла нет. Сбрасывается в start(). */
    private volatile boolean fatalFailureSeen = false;

    /** Был ли в выводе открытого процесса признак фатальной ошибки. */
    public boolean sawFatalFailure() {
        return fatalFailureSeen;
    }
    /**
     * Режим OpenVPN-через-SSH: локальный порт SSH-форварда (127.0.0.1:порт),
     * установленный SshTunnel. 0/отрицательное — обычный запуск (форварда нет).
     */
    private volatile int sshLocalPort = 0;

    public boolean isRunning() {
        return running;
    }

    /** Живая смена verb openvpn через management-интерфейс (кнопка «Подробный
     *  журнал»), без перезапуска движка. Молча игнорируется, если движок не стартован. */
    public void setVerb(int verb) {
        OpenVpnManagementThread m = managementThread;
        if (m != null) {
            m.setVerb(verb);
        }
    }

    /** Сообщает раннеру локальный порт SSH-форварда (вызывается сервисом до start). */
    public void setSshLocalPort(int port) {
        this.sshLocalPort = port;
    }

    /**
     * Запускает OpenVPN-клиент.
     *
     * @param context      контекст приложения
     * @param config       настройки
     * @param tunProvider      провайдер TUN-интерфейса VpnService (вызывается на OPENTUN)
     * @param protectCallback  колбэк для исключения сокета openvpn из VPN-маршрутизации
     * @param socksProxy       SOCKS-прокси для режима Xray+OpenVPN (например "127.0.0.1:10808"),
     *                         или null для режима «только OpenVPN»
     */
    public synchronized void start(Context context, ConfigManager config,
                                   OpenVpnManagementThread.TunProvider tunProvider,
                                   java.util.function.IntConsumer protectCallback,
                                   String socksProxy,
                                   Runnable onProcessExit) throws Exception {
        if (running) {
            // Ранее здесь был тихий return: после смены режима/настроек при живом
            // старом процессе новый конфиг (например с socks-proxy) не применялся,
            // и openvpn продолжал работать со СТАРЫМ конфигом. Теперь перезапускаем.
            LogStore.add("OpenVPN", L10n.s(R.string.log_orun_01));
            stop();
        }
        intentionalStop = false;
        fatalFailureSeen = false;
        File dir = context.getFilesDir();
        String keyPath = null, caPath = null, certPath = null, keyFilePath = null;

        String staticKey = config.getOvpnStaticKey();
        if (staticKey != null && !staticKey.trim().isEmpty()) {
            File keyFile = new File(dir, "ovpn_static.key");
            writeFile(keyFile, staticKey);
            keyPath = keyFile.getAbsolutePath();
        } else {
            if (!config.getOvpnCa().isEmpty()) {
                caPath = writeText(dir, "ovpn_ca.pem", config.getOvpnCa());
            }
            if (!config.getOvpnCert().isEmpty()) {
                certPath = writeText(dir, "ovpn_cert.pem", config.getOvpnCert());
            }
            if (!config.getOvpnKey().isEmpty()) {
                keyFilePath = writeText(dir, "ovpn_key.pem",
                        OpenVpnConfigBuilder.normalizePrivateKeyPem(config.getOvpnKey()));
            }
        }

        // Если есть импортированный сырой .ovpn — работаем с ним (сохраняя все директивы),
        // внося только runtime-правки (socks-proxy для Xray+OpenVPN и verb).
        // Иначе собираем конфиг из полей.
        String cfg;
        String raw = config.getOvpnRaw();
        if (raw != null && !raw.trim().isEmpty()) {
            cfg = OpenVpnConfigBuilder.prepareForRun(raw, config, socksProxy);
            LogStore.add("OpenVPN", L10n.s(R.string.log_orun_02));
        } else {
            cfg = OpenVpnConfigBuilder.build(config, keyPath, caPath, certPath, keyFilePath, socksProxy);
        }
        // Режим OpenVPN-через-SSH: сервер достижим только через локальный
        // SSH-форвард (порт сообщает GrizzlyLandVpnService после подъёма туннеля).
        if (sshLocalPort > 0) {
            cfg = OpenVpnConfigBuilder.patchSshLocal(cfg, sshLocalPort);
            LogStore.add("OpenVPN", L10n.s(R.string.log_orun_03) + sshLocalPort
                    + L10n.s(R.string.log_orun_04));
        }
        // Режим интерфейса СЕРВЕРА — из самого конфига: "dev tap…" → L2-пара и
        // TapShim (бриджевый сервер), "dev tun*" → обычный L3. Авто-детекта нет.
        boolean tap = OpenVpnConfigBuilder.isTapConfig(cfg);
        String linkMode = tap ? "tap" : "tun";
        LogStore.add("OpenVPN", L10n.s(R.string.log_orun_05) + linkMode
                + L10n.s(R.string.log_orun_06));
        File cfgFile = new File(dir, "client.ovpn");
        writeFile(cfgFile, cfg);
        Log.i(TAG, "OpenVPN config:\n" + cfg);
        LogStore.add("OpenVPN", L10n.s(R.string.log_orun_07) + config.getOvpnRemoteHost()
                + ":" + config.getOvpnRemotePort()
                + " proto=" + config.getOvpnProtocol()
                + (socksProxy != null ? " via " + socksProxy : ""));
        LogStore.add("OpenVPN", L10n.s(R.string.log_orun_08) + cfg);

        // Поднимаем management-интерфейс (UNIX-сокет) до старта openvpn.
        managementThread = new OpenVpnManagementThread(context, tunProvider, protectCallback,
                config.getOvpnKeyPassword(), config.getOvpnUsername(), config.getOvpnPassword());
        managementThread.setLinkMode(linkMode);
        managementThread.start();
        String mgmtSocket = managementThread.getSocketPath();

        // Нативный бинарник поставляется как библиотека (можно exec из nativeLibraryDir).
        File binary = new File(context.getApplicationInfo().nativeLibraryDir, BINARY_NAME);
        if (!binary.exists() || !binary.canExecute()) {
            Log.e(TAG, "native openvpn binary not found/executable: " + binary);
            LogStore.add("OpenVPN", L10n.s(R.string.log_orun_09) + binary);
            throw new IllegalStateException("openvpn binary unavailable: " + binary);
        }

        ProcessBuilder pb = new ProcessBuilder(
                binary.getAbsolutePath(),
                "--config", cfgFile.getAbsolutePath(),
                "--tmp-dir", context.getCacheDir().getAbsolutePath(),
                "--management", mgmtSocket, "unix",
                "--management-client",
                "--management-hold",
                "--management-query-passwords");
        pb.redirectErrorStream(true);
        process = pb.start();
        running = true;
        // Читаем вывод openvpn и пишем его в logcat (для диагностики на устройстве).
        Thread logThread = new Thread(() -> {
            try (java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream(), "UTF-8"))) {
                String line;
                while ((line = br.readLine()) != null) {
                    Log.i("OpenVPN", line);
                    LogStore.add("OpenVPN", line);
                    // Темп реконнектов: неудачный резолв → бэкофф hold-шлюза,
                    // успешное подключение → сброс.
                    OpenVpnManagementThread m = managementThread;
                    if (m != null) {
                        m.noteOpenVpnLine(line);
                    }
                    // Фатальные ошибки: неверный конфиг/креды/PEM — рестарт не
                    // поможет. «Exiting due to fatal error» — общий маркер
                    // фатального выхода openvpn (сам решил, что продолжать
                    // нельзя). [PUSH-OPTIONS] исключаем: ошибки пуша сервером
                    // не фатальны (openvpn продолжает, проверено на
                    // block-outside-dns). Внезапная смерть БЕЗ этой строки
                    // (kill, management-exit) — транзиентная, её ретраим.
                    if (line.contains("AUTH_FAILED")
                            || line.contains("Exiting due to fatal error")
                            || (line.startsWith("Options error:")
                                && !line.contains("[PUSH-OPTIONS]"))) {
                        fatalFailureSeen = true;
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "reading openvpn output failed", e);
            }
        }, "openvpn-log");
        logThread.setDaemon(true);
        logThread.start();

        // Watcher: если openvpn умер сам (плохой конфиг, отказ auth, недоступен сервер),
        // сообщаем сервису — иначе UI останется в «подключено» при мёртвом туннеле.
        final Process proc = process;
        Thread watcher = new Thread(() -> {
            try {
                int code = proc.waitFor();
                LogStore.add("OpenVPN", L10n.s(R.string.log_orun_10) + code);
            } catch (InterruptedException e) {
                return;
            }
            // Процесс мёртв — флаг running надо сбросить СРАЗУ: иначе ретрай-супервизор
            // видит isRunning()=true и молча не переподключается (баг 26.10: ретрай-цикл
            // умирал после второй попытки).
            running = false;
            if (!intentionalStop && onProcessExit != null) {
                onProcessExit.run();
            }
        }, "openvpn-watch");
        watcher.setDaemon(true);
        watcher.start();

        Log.i(TAG, "OpenVPN started, mgmt socket=" + mgmtSocket);
        LogStore.add("OpenVPN", L10n.s(R.string.log_orun_11));
    }

    public synchronized void stop() {
        intentionalStop = true;
        if (managementThread != null) {
            managementThread.close();
            managementThread = null;
        }
        if (!running || process == null) {
            return;
        }
        try {
            process.destroy();
            if (!process.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error stopping OpenVPN", e);
            LogStore.add("OpenVPN", L10n.s(R.string.log_orun_12) + e);
        }
        process = null;
        running = false;
        Log.i(TAG, "OpenVPN stopped");
        LogStore.add("OpenVPN", L10n.s(R.string.log_orun_13));
    }

    private String writeText(File dir, String name, String content) {
        File f = new File(dir, name);
        writeFile(f, content);
        return f.getAbsolutePath();
    }

    private void writeFile(File f, String content) {
        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(content.getBytes("UTF-8"));
        } catch (Exception e) {
            Log.e(TAG, "writeFile failed: " + f, e);
        }
    }
}
