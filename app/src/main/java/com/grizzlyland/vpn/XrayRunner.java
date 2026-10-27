package com.grizzlyland.vpn;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.RandomAccessFile;

import libxray.Libxray;

/**
 * Обёртка над нативным ядром Xray (libxray.so).
 * Поддерживает три режима:
 *  - tun:  Xray читает пакеты из TUN-интерфейса VpnService (режим "только Xray").
 *  - socks: Xray поднимает локальный SOCKS-прокси (режим Xray+OpenVPN).
 *  - custom: пользовательский JSON-конфиг (inbounds подменяются на tun-вход).
 *
 * Xray пишет свои логи (access/error) в файлы в {@code logDir}; поток-хвостовик
 * читает эти файлы и добавляет строки в {@link LogStore} (журнал подключения).
 */
public class XrayRunner {

    private static final String TAG = "XrayRunner";

    private volatile boolean running = false;

    /**
     * Обнуляет файлы логов прошлых сессий. Xray открывает их в append-режиме —
     * без этого они растут от сессии к сессии неограниченно. Вызывать ДО
     * Libxray.run(): новый инстанс создаст файлы заново, а хвостовик начнёт
     * читать с нуля (existed=false → pos=0).
     */
    private static void resetLogFiles(String logDir) {
        if (logDir == null) {
            return;
        }
        new File(logDir, "xray_access.log").delete();
        new File(logDir, "xray_error.log").delete();
    }

    public boolean isRunning() {
        return running;
    }

    /** Запуск Xray в TUN-режиме (весь трафик VPN-интерфейса идёт через сервер). */
    public synchronized void startTun(ConfigManager config, int tunFd, String logDir) throws Exception {
        if (running) {
            return;
        }
        resetLogFiles(logDir);
        Libxray.setTunFd(tunFd);
        String json = XrayConfigBuilder.buildTun(config, logDir);
        Log.i(TAG, "Starting Xray (TUN mode), fd=" + tunFd + " config:\n" + json);
        LogStore.add("Xray", L10n.s(R.string.log_xrun_01) + tunFd);
        LogStore.add("Xray", L10n.s(R.string.log_orun_08) + json);
        Libxray.run(json);
        running = true;
        startLogTailer(logDir, config.getLogDebug());
        Log.i(TAG, "Xray TUN started, version=" + Libxray.version());
        LogStore.add("Xray", L10n.s(R.string.log_xrun_02) + Libxray.version());
    }

    /**
     * Запуск Xray в TUN-режиме "WireGuard через Xray": tun-вход, дефолтный
     * outbound — wireguard, чей UDP завёрнут в proxy через dialerProxy.
     * Endpoint peer передаётся в конфиг КАК ЕСТЬ (домен или IP): домен Xray
     * резолвит сам через свой DNS-модуль, чьи запросы идут через proxy
     * (правило inboundTag "dns-internal" → proxy) — «DNS через Xray».
     */
    public synchronized void startTunWg(ConfigManager config, int tunFd, String logDir) throws Exception {
        if (running) {
            return;
        }
        resetLogFiles(logDir);
        Libxray.setTunFd(tunFd);
        String json = XrayConfigBuilder.buildTunWg(config, logDir);
        Log.i(TAG, "Starting Xray (TUN+WG mode), fd=" + tunFd + " config:\n" + json);
        LogStore.add("Xray", L10n.s(R.string.log_xrun_03) + tunFd);
        LogStore.add("Xray", L10n.s(R.string.log_orun_08) + json);
        Libxray.run(json);
        running = true;
        startLogTailer(logDir, config.getLogDebug());
        Log.i(TAG, "Xray TUN+WG started, version=" + Libxray.version());
        LogStore.add("Xray", L10n.s(R.string.log_xrun_04) + Libxray.version());
    }

    /**
     * Запуск Xray в режиме "custom": используется пользовательский JSON-конфиг
     * как есть, но inbounds подменяются на tun-вход (чтобы трафик из VPN-интерфейса
     * попадал в Xray). Конфиг валидируется (наличие outbounds), при ошибке бросается
     * исключение с понятным сообщением.
     */
    public synchronized void startTunCustom(ConfigManager config, int tunFd, String logDir) throws Exception {
        if (running) {
            return;
        }
        resetLogFiles(logDir);
        String raw = config.getXrayCustomJson();
        if (raw == null || raw.trim().isEmpty()) {
            LogStore.add("Xray", L10n.s(R.string.log_xrun_05));
            throw new IllegalArgumentException(L10n.s(R.string.log_xrun_06));
        }
        JSONObject o;
        try {
            o = new JSONObject(raw);
        } catch (Exception e) {
            LogStore.add("Xray", L10n.s(R.string.log_xrun_07) + e.getMessage());
            throw new IllegalArgumentException(L10n.s(R.string.log_xrun_08) + e.getMessage());
        }
        JSONArray outbounds = o.optJSONArray("outbounds");
        if (outbounds == null || outbounds.length() == 0) {
            LogStore.add("Xray", L10n.s(R.string.log_xrun_09));
            throw new IllegalArgumentException(L10n.s(R.string.log_xrun_10));
        }

        // Подменяем inbounds на tun-вход (трафик из VPN-интерфейса).
        JSONObject tunInbound = new JSONObject();
        tunInbound.put("tag", "tun");
        tunInbound.put("protocol", "tun");
        JSONObject settings = new JSONObject();
        settings.put("name", "tun0");
        settings.put("mtu", 1400);
        JSONArray dns = new JSONArray();
        for (String d : config.getXrayDnsPlain().split(",")) {
            String dd = d.trim();
            if (!dd.isEmpty()) dns.put(dd);
        }
        if (dns.length() == 0) dns.put("8.8.8.8");
        settings.put("dns", dns);
        JSONArray gateway = new JSONArray();
        gateway.put("10.0.0.1");
        settings.put("gateway", gateway);
        tunInbound.put("settings", settings);
        JSONArray inbounds = new JSONArray();
        inbounds.put(tunInbound);
        o.put("inbounds", inbounds);

        // Приводим лог к нашим настройкам (уровень + файлы для журнала).
        applyLogConfig(o, config, logDir);

        Libxray.setTunFd(tunFd);
        String json = o.toString(2);
        Log.i(TAG, "Starting Xray (CUSTOM mode), fd=" + tunFd + " config:\n" + json);
        LogStore.add("Xray", L10n.s(R.string.log_xrun_11) + tunFd);
        LogStore.add("Xray", L10n.s(R.string.log_orun_08) + json);
        Libxray.run(json);
        running = true;
        startLogTailer(logDir, config.getLogDebug());
        Log.i(TAG, "Xray CUSTOM started, version=" + Libxray.version());
        LogStore.add("Xray", L10n.s(R.string.log_xrun_12) + Libxray.version());
    }

    /** Запуск Xray в SOCKS-режиме (локальный прокси для OpenVPN). */
    public synchronized void startSocks(ConfigManager config, String logDir) throws Exception {
        if (running) {
            return;
        }
        resetLogFiles(logDir);
        String json = XrayConfigBuilder.build(config, logDir);
        Log.i(TAG, "Starting Xray (SOCKS mode) config:\n" + json);
        LogStore.add("Xray", L10n.s(R.string.log_xrun_13) + config.getXraySocksPort());
        LogStore.add("Xray", L10n.s(R.string.log_orun_08) + json);
        Libxray.run(json);
        running = true;
        startLogTailer(logDir, config.getLogDebug());
        Log.i(TAG, "Xray SOCKS started, version=" + Libxray.version());
        LogStore.add("Xray", L10n.s(R.string.log_xrun_14) + Libxray.version());
    }

    public synchronized void stop() {
        stopLogTailer();
        if (!running) {
            return;
        }
        try {
            Libxray.stop();
        } catch (Throwable t) {
            Log.e(TAG, "Error stopping Xray", t);
            LogStore.add("Xray", L10n.s(R.string.log_xrun_15) + t);
        }
        running = false;
        Log.i(TAG, "Xray stopped");
        LogStore.add("Xray", L10n.s(R.string.log_xrun_16));
    }

    public String version() {
        try {
            return Libxray.version();
        } catch (Throwable t) {
            return "unknown";
        }
    }

    // ============================================================
    // Логи Xray -> журнал подключения
    // ============================================================

    /** Подставляет log-настройки (уровень + файлы) в пользовательский custom-конфиг. */
    private static void applyLogConfig(JSONObject o, ConfigManager config, String logDir) throws Exception {
        // Уровень управляется флагом «Подробный журнал» (см. XrayConfigBuilder.baseConfig):
        // OFF → warning + access: none (беречь flash-память телефона), ON → debug + файл.
        boolean verbose = config.getLogDebug();
        String level = verbose ? "debug" : "warning";
        JSONObject log = new JSONObject();
        log.put("loglevel", level);
        if (logDir != null) {
            log.put("access", verbose ? logDir + "/xray_access.log" : "none");
            log.put("error", logDir + "/xray_error.log");
        }
        o.put("log", log);
    }

    /** Запускает поток, который дочитывает файлы логов Xray в журнал. */
    private volatile Thread logTailer;
    private volatile Thread errorTailer;

    private void startLogTailer(String logDir, boolean accessEnabled) {
        stopLogTailer();
        if (logDir == null) {
            return;
        }
        File access = new File(logDir, "xray_access.log");
        File error = new File(logDir, "xray_error.log");
        // Access-файл существует только при включённом «Подробном журнале»
        // (иначе в конфиге Xray access: none) — tailer для него не нужен.
        if (accessEnabled) {
            logTailer = new Thread(() -> tailLogFile(access, "Xray"), "xray-log-tail");
            logTailer.setDaemon(true);
            logTailer.start();
        }
        // Фикс: читаем и error-лог (раньше ошибки Xray были невидимы).
        errorTailer = new Thread(() -> tailLogFile(error, "XrayErr"), "xray-error-tail");
        errorTailer.setDaemon(true);
        errorTailer.start();
    }

    private void stopLogTailer() {
        Thread t = logTailer;
        logTailer = null;
        if (t != null) {
            t.interrupt();
        }
        Thread e = errorTailer;
        errorTailer = null;
        if (e != null) {
            e.interrupt();
        }
    }

    private static void tailLogFile(File file, String source) {
        try {
            boolean existed = file.exists();
            if (!existed) {
                file.createNewFile();
            }
            try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
                // Фикс: начинаем с конца файла (EOF), чтобы не тащить в журнал
                // мегабайты старых записей прошлых сессий при каждом запуске.
                long pos = existed ? raf.length() : 0;
                while (!Thread.currentThread().isInterrupted()) {
                    long len = raf.length();
                    if (len < pos) {
                        // Файл перезаписан/обрезан.
                        pos = 0;
                    }
                    if (len > pos) {
                        raf.seek(pos);
                        String line;
                        while ((line = raf.readLine()) != null) {
                            pos = raf.getFilePointer();
                            if (!line.trim().isEmpty()) {
                                LogStore.add(source, line);
                            }
                        }
                    }
                    // Опрос раз в секунду: строки логов не теряются (файл читается
                    // с последней позиции), CPU просыпается вдвое реже.
                    Thread.sleep(1000);
                }
            }
        } catch (InterruptedException ie) {
            // корректное завершение
        } catch (Exception e) {
            Log.e(TAG, "log tailer failed for " + file, e);
        }
    }
}
