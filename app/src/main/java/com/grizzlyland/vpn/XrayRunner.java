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

    public boolean isRunning() {
        return running;
    }

    /** Запуск Xray в TUN-режиме (весь трафик VPN-интерфейса идёт через сервер). */
    public synchronized void startTun(ConfigManager config, int tunFd, String logDir) throws Exception {
        if (running) {
            return;
        }
        Libxray.setTunFd(tunFd);
        String json = XrayConfigBuilder.buildTun(config, logDir);
        Log.i(TAG, "Starting Xray (TUN mode), fd=" + tunFd + " config:\n" + json);
        LogStore.add("Xray", "Запуск Xray (TUN), fd=" + tunFd);
        LogStore.add("Xray", "Конфиг:\n" + json);
        Libxray.run(json);
        running = true;
        startLogTailer(logDir);
        Log.i(TAG, "Xray TUN started, version=" + Libxray.version());
        LogStore.add("Xray", "Xray TUN запущен, version=" + Libxray.version());
    }

    /**
     * Запуск Xray в TUN-режиме "WireGuard через Xray": tun-вход, дефолтный
     * outbound — wireguard, чей UDP завёрнут в proxy через dialerProxy.
     */
    public synchronized void startTunWg(ConfigManager config, int tunFd, String logDir) throws Exception {
        if (running) {
            return;
        }
        Libxray.setTunFd(tunFd);
        String json = XrayConfigBuilder.buildTunWg(config, logDir);
        Log.i(TAG, "Starting Xray (TUN+WG mode), fd=" + tunFd + " config:\n" + json);
        LogStore.add("Xray", "Запуск Xray (TUN+WG), fd=" + tunFd);
        LogStore.add("Xray", "Конфиг:\n" + json);
        Libxray.run(json);
        running = true;
        startLogTailer(logDir);
        Log.i(TAG, "Xray TUN+WG started, version=" + Libxray.version());
        LogStore.add("Xray", "Xray TUN+WG запущен, version=" + Libxray.version());
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
        String raw = config.getXrayCustomJson();
        if (raw == null || raw.trim().isEmpty()) {
            LogStore.add("Xray", "ОШИБКА: custom-конфиг пуст");
            throw new IllegalArgumentException("Пустой custom-конфиг Xray (заполните в настройках)");
        }
        JSONObject o;
        try {
            o = new JSONObject(raw);
        } catch (Exception e) {
            LogStore.add("Xray", "ОШИБКА: невалидный JSON: " + e.getMessage());
            throw new IllegalArgumentException("Невалидный JSON в custom-конфиге: " + e.getMessage());
        }
        JSONArray outbounds = o.optJSONArray("outbounds");
        if (outbounds == null || outbounds.length() == 0) {
            LogStore.add("Xray", "ОШИБКА: в custom-конфиге нет outbounds");
            throw new IllegalArgumentException("В custom-конфиге нет outbounds");
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
        LogStore.add("Xray", "Запуск Xray (custom), fd=" + tunFd);
        LogStore.add("Xray", "Конфиг:\n" + json);
        Libxray.run(json);
        running = true;
        startLogTailer(logDir);
        Log.i(TAG, "Xray CUSTOM started, version=" + Libxray.version());
        LogStore.add("Xray", "Xray custom запущен, version=" + Libxray.version());
    }

    /** Запуск Xray в SOCKS-режиме (локальный прокси для OpenVPN). */
    public synchronized void startSocks(ConfigManager config, String logDir) throws Exception {
        if (running) {
            return;
        }
        String json = XrayConfigBuilder.build(config, logDir);
        Log.i(TAG, "Starting Xray (SOCKS mode) config:\n" + json);
        LogStore.add("Xray", "Запуск Xray (SOCKS) на 127.0.0.1:" + config.getXraySocksPort());
        LogStore.add("Xray", "Конфиг:\n" + json);
        Libxray.run(json);
        running = true;
        startLogTailer(logDir);
        Log.i(TAG, "Xray SOCKS started, version=" + Libxray.version());
        LogStore.add("Xray", "Xray SOCKS запущен, version=" + Libxray.version());
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
            LogStore.add("Xray", "Ошибка остановки Xray: " + t);
        }
        running = false;
        Log.i(TAG, "Xray stopped");
        LogStore.add("Xray", "Xray остановлен");
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
        String level = config.getXrayLoglevel();
        if (level == null || level.isEmpty()) {
            level = "info";
        }
        JSONObject log = new JSONObject();
        log.put("loglevel", level);
        if (logDir != null) {
            log.put("access", logDir + "/xray_access.log");
            log.put("error", logDir + "/xray_error.log");
        }
        o.put("log", log);
    }

    /** Запускает поток, который дочитывает файлы логов Xray в журнал. */
    private volatile Thread logTailer;
    private volatile Thread errorTailer;

    private void startLogTailer(String logDir) {
        stopLogTailer();
        if (logDir == null) {
            return;
        }
        File access = new File(logDir, "xray_access.log");
        File error = new File(logDir, "xray_error.log");
        // Фикс: читаем и error-лог (раньше ошибки Xray были невидимы).
        logTailer = new Thread(() -> tailLogFile(access, "Xray"), "xray-log-tail");
        logTailer.setDaemon(true);
        logTailer.start();
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
                    Thread.sleep(500);
                }
            }
        } catch (InterruptedException ie) {
            // корректное завершение
        } catch (Exception e) {
            Log.e(TAG, "log tailer failed for " + file, e);
        }
    }
}
