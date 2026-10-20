package com.grizzlyland.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileDescriptor;

/**
 * VPN-сервис. Создаёт виртуальный интерфейс через Android VpnService
 * и применяет per-app фильтрацию (addAllowedApplication) — как в OpenVPN for Android.
 *
 * В полной реализации сюда подключаются Xray (внешний туннель) и OpenVPN
 * (внутренний, cipher none, маршрутизация). Здесь реализован сам каркас
 * VpnService с per-app выбором, который можно проверить на устройстве.
 */
public class GrizzlyLandVpnService extends VpnService {

    public static final String ACTION_CONNECT = "com.grizzlyland.vpn.CONNECT";
    public static final String ACTION_DISCONNECT = "com.grizzlyland.vpn.DISCONNECT";
    public static final String ACTION_RECONNECT = "com.grizzlyland.vpn.RECONNECT";
    public static final String ACTION_STATE_CHANGED = "com.grizzlyland.vpn.STATE_CHANGED";
    /** Живое применение флага «Подробный журнал» — БЕЗ реконнекта VPN. */
    public static final String ACTION_SET_DEBUG = "com.grizzlyland.vpn.SET_DEBUG";

    private static final String TAG = "GrizzlyLandVpnService";
    private static final String CHANNEL_ID = "grizzlylandvpn";
    private static final int NOTIF_ID = 1;

    /** Глобальный флаг: подключён ли VPN (для UI). */
    public static volatile boolean connected = false;

    /** Последняя ошибка подключения (показывается в UI). */
    public static volatile String lastError = "";

    private ParcelFileDescriptor vpnInterface;
    private ConfigManager config;
    private XrayRunner xrayRunner = new XrayRunner();
    private OpenVpnRunner openVpnRunner = new OpenVpnRunner();
    /** SSH-туннель для режима openvpn_ssh (живёт, пока работает VPN в этом режиме). */
    private SshTunnel sshTunnel;
    /** WireGuard-движок для режима wireguard (живёт, пока работает VPN в этом режиме). */
    private WgRunner wgRunner;
    /** Сетевой колбэк режима WireGuard: при смене сети пересоздаём туннель
     *  (UDP-сокеты движка перепривязываются). */
    private android.net.ConnectivityManager.NetworkCallback wgNetCallback;
    private android.net.Network wgLastNetwork;
    /** Эпоха старта: инвалидирует асинхронный старт WG-через-Xray при
     *  disconnect/реконнекте (резолв endpoint'а идёт в рабочем потоке). */
    private final java.util.concurrent.atomic.AtomicInteger startEpoch =
            new java.util.concurrent.atomic.AtomicInteger(0);

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        config = new ConfigManager(this);
        String action = intent != null ? intent.getAction() : null;
        if (ACTION_DISCONNECT.equals(action)) {
            disconnect();
            return START_NOT_STICKY;
        }
        startForeground(NOTIF_ID, buildNotification());
        if (ACTION_SET_DEBUG.equals(action)) {
            // Живое применение «Подробного журнала» — реконнект НЕ делаем.
            applyLogFlagLive();
            return START_STICKY;
        }
        if (ACTION_RECONNECT.equals(action)) {
            // Пересоздать VPN с новыми настройками (применение без перезапуска).
            if (connected) {
                xrayRunner.stop();
                openVpnRunner.stop();
                stopSshTunnel();
                stopWgEngine();
                if (vpnInterface != null) {
                    try {
                        vpnInterface.close();
                    } catch (Exception ignored) {
                    }
                    vpnInterface = null;
                }
                connected = false;
                broadcastState();
            }
        }
        connect();
        return START_STICKY;
    }

    /** Попросить сервис применить новые настройки, если VPN подключён. */
    public static void requestApply(Context context) {
        if (!connected) {
            return;
        }
        Intent i = new Intent(context, GrizzlyLandVpnService.class);
        i.setAction(ACTION_RECONNECT);
        context.startService(i);
    }

    /** Применить флаг «Подробный журнал» к живому VPN без реконнекта. */
    public static void requestSetDebug(Context context) {
        if (!connected) {
            return;
        }
        Intent i = new Intent(context, GrizzlyLandVpnService.class);
        i.setAction(ACTION_SET_DEBUG);
        context.startService(i);
    }

    /**
     * Живое применение флага «Подробный журнал» (кнопка в журнале), без
     * реконнекта: OpenVPN — verb через management на лету; Xray — перезапуск
     * ядра с новым loglevel (TUN/движки переживают, восстановление авто);
     * WireGuard (реж. 5) — фильтр в памяти WgRunner, делать ничего не нужно.
     */
    private void applyLogFlagLive() {
        boolean verbose = config.getLogDebug();
        String mode = config.getMode();
        if (openVpnRunner.isRunning()) {
            int verb = verbose ? 5 : config.getOvpnVerb();
            openVpnRunner.setVerb(verb);
            LogStore.add("Service", "OpenVPN verb → " + verb);
        }
        if (xrayRunner.isRunning()) {
            restartXrayForLogFlag();
        }
        if (wgRunner != null && wgRunner.isRunning()) {
            LogStore.add("Service", verbose
                    ? "WireGuard: подробные строки движка показаны (фильтр снят)"
                    : "WireGuard: подробные строки движка скрыты");
        }
    }

    /**
     * Перезапуск ядра Xray с новым loglevel, не трогая TUN и остальные движки.
     * Активные TCP-соединения приложений оборвутся и переустановятся; в режиме
     * Xray+OpenVPN сессия openvpn переподключится сама (SOCKS поднимется заново);
     * WG-движок (реж. «через Xray») поднимет handshake по первому пакету.
     */
    private void restartXrayForLogFlag() {
        String mode = config.getMode();
        try {
            xrayRunner.stop();
            String logDir = getFilesDir().getAbsolutePath();
            if (ConfigManager.MODE_WG_XRAY.equals(mode)) {
                if (vpnInterface != null) {
                    xrayRunner.startTunWg(config, vpnInterface.getFd(), logDir);
                }
            } else if (ConfigManager.MODE_XRAY_OVPN.equals(mode)) {
                xrayRunner.startSocks(config, logDir);
            } else if (vpnInterface != null) {
                // Режим «только Xray»: custom-конфиг или собранный из полей.
                String custom = config.getXrayCustomJson();
                if (custom != null && !custom.trim().isEmpty()) {
                    xrayRunner.startTunCustom(config, vpnInterface.getFd(), logDir);
                } else {
                    xrayRunner.startTun(config, vpnInterface.getFd(), logDir);
                }
            }
            LogStore.add("Service", "Xray перезапущен (loglevel="
                    + (config.getLogDebug() ? "debug" : "info") + "), TUN не пересоздавался");
        } catch (Exception e) {
            Log.e(TAG, "Xray restart (log flag) failed", e);
            LogStore.add("Service", "ОШИБКА перезапуска Xray: " + e);
            lastError = e.getMessage();
            connected = false;
            broadcastState();
            openVpnRunner.stop();
            stopSshTunnel();
            stopWgEngine();
            if (vpnInterface != null) {
                try {
                    vpnInterface.close();
                } catch (Exception ignored) {
                }
                vpnInterface = null;
            }
            stopSelf();
        }
    }

    private void connect() {
        if (vpnInterface != null) {
            LogStore.add("Service", "connect(): интерфейс уже существует — пропуск ("
                    + (openVpnRunner.isRunning() ? "openvpn живой" : "openvpn не запущен") + ")");
            return;
        }
        startEpoch.incrementAndGet();
        try {
            String mode = config.getMode();
            lastError = "";
            LogStore.add("Service", "==== Подключение (режим: " + mode + ") ====");
            if (ConfigManager.MODE_OPENVPN.equals(mode) || ConfigManager.MODE_XRAY_OVPN.equals(mode)
                    || ConfigManager.MODE_OVPN_SSH.equals(mode)) {
                // Режим OpenVPN: TUN-интерфейс создаёт VpnService, но fd отдаётся
                // нативному openvpn через management (команда OPENTUN), поэтому
                // здесь tun НЕ устанавливаем заранее. Устанавливаем провайдер.
                startOpenVpnMode(mode);
            } else if (ConfigManager.MODE_WG.equals(mode)) {
                // Режим WireGuard: TUN создаём сами и отдаём fd движку wireguard-go.
                startWgMode();
            } else if (ConfigManager.MODE_WG_XRAY.equals(mode)) {
                // WireGuard через Xray: TUN как в режиме "только Xray", но дефолтный
                // outbound Xray — wireguard, чей UDP завёрнут в VLESS (dialerProxy).
                startWgXrayMode();
            } else {
                // Режимы "только Xray": устанавливаем TUN и отдаём fd Xray.
                // Если задан пользовательский custom-конфиг — используем его (inbounds
                // подменяются на tun-вход), иначе собираем конфиг из полей.
                vpnInterface = buildBuilder(null, 1400, null, null).establish();
                if (vpnInterface != null) {
                    try {
                        String logDir = getFilesDir().getAbsolutePath();
                        String custom = config.getXrayCustomJson();
                        if (custom != null && !custom.trim().isEmpty()) {
                            xrayRunner.startTunCustom(config, vpnInterface.getFd(), logDir);
                        } else {
                            xrayRunner.startTun(config, vpnInterface.getFd(), logDir);
                        }
                        // connected — только после успешного старта ядра. Раньше флаг
                        // ставился до startTun: при падении Xray UI показывал «подключено»
                        // при мёртвом туннеле.
                        connected = true;
                        broadcastState();
                    } catch (Exception e) {
                        Log.e(TAG, "Xray TUN start failed", e);
                        LogStore.add("Service", "ОШИБКА запуска Xray TUN: " + e);
                        lastError = e.getMessage();
                        // Туннель без работающего ядра бесполезен — закрываем интерфейс.
                        try {
                            vpnInterface.close();
                        } catch (Exception ignored) {
                        }
                        vpnInterface = null;
                        broadcastState();
                        stopSelf();
                        return;
                    }
                } else {
                    LogStore.add("Service", "ОШИБКА: VpnService не разрешил TUN");
                    lastError = "VpnService не разрешил TUN";
                    broadcastState();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            lastError = e.getMessage();
            broadcastState();
            stopSelf();
        }
    }

    /** Запуск режимов с OpenVPN (только OpenVPN / Xray+OpenVPN / OpenVPN-через-SSH). */
    private void startOpenVpnMode(String mode) throws Exception {
        String socks = null;
        String logDir = getFilesDir().getAbsolutePath();
        if (ConfigManager.MODE_OVPN_SSH.equals(mode)) {
            // Сначала поднимаем SSH-форвард; openvpn стартует из onSshReady().
            startSshMode();
            return;
        }
        if (ConfigManager.MODE_XRAY_OVPN.equals(mode)) {
            xrayRunner.startSocks(config, logDir);
            socks = "127.0.0.1:" + config.getXraySocksPort();
        }
        openVpnRunner.start(this, config, this::establishTunForOpenVpn, this::protectFd, socks,
                this::onOpenVpnExited);
    }

    /**
     * Режим OpenVPN-через-SSH: подключаемся к SSH-серверу с локальным форвардом
     * (аналог ssh -L 11940:127.0.0.1:1194). OpenVPN стартует только после того,
     * как форвард реально слушает локальный порт. Реконнекты SSH-сессии туннель
     * переживает сам (openvpn в это время просто ретраит подключение).
     */
    private void startSshMode() {
        if (!config.isSshConfigured()) {
            lastError = "SSH: не заданы хост/пользователь (Настройки → Настройки SSH)";
            LogStore.add("Service", "ОШИБКА: " + lastError);
            broadcastState();
            stopSelf();
            return;
        }
        stopSshTunnel();
        sshTunnel = new SshTunnel(config, this::protectFd, new SshTunnel.Listener() {
            @Override
            public void onReady(int localPort) {
                onSshReady(localPort);
            }

            @Override
            public void onFinalFailure(String reason) {
                onSshFailed(reason);
            }
        });
        sshTunnel.start();
    }

    /** SSH-форвард готов: запускаем openvpn с remote=127.0.0.1:<localPort>. */
    private void onSshReady(int localPort) {
        LogStore.add("Service", "SSH-туннель готов, локальный форвард 127.0.0.1:" + localPort);
        if (openVpnRunner.isRunning()) {
            // Реконнект SSH-сессии: openvpn уже ретраит и подцепится сам.
            return;
        }
        openVpnRunner.setSshLocalPort(localPort);
        try {
            openVpnRunner.start(this, config, this::establishTunForOpenVpn, this::protectFd,
                    null, this::onOpenVpnExited);
        } catch (Exception e) {
            Log.e(TAG, "openvpn start failed (ssh mode)", e);
            LogStore.add("Service", "ОШИБКА запуска OpenVPN (SSH-режим): " + e);
            lastError = e.getMessage();
            connected = false;
            broadcastState();
            stopSshTunnel();
            stopSelf();
        }
    }

    /** SSH не смог подключиться после всех попыток — честно останавливаем VPN. */
    private void onSshFailed(String reason) {
        LogStore.add("Service", "ОШИБКА SSH: " + reason);
        lastError = reason;
        connected = false;
        broadcastState();
        openVpnRunner.stop();
        stopSshTunnel();
        stopSelf();
    }

    /** Останавливает SSH-туннель, если он запущен. */
    private void stopSshTunnel() {
        SshTunnel t = sshTunnel;
        sshTunnel = null;
        if (t != null) {
            t.stop();
        }
    }

    // ===== WireGuard (режим wireguard) =====

    /**
     * Режим WireGuard: парсим wg-quick конфиг, создаём TUN VpnService
     * (адреса/DNS/маршруты из конфига) и отдаём fd движку wireguard-go
     * (libwg.aar). UDP-сокеты движка защищаются через protect сразу после
     * подъёма. При смене сети туннель пересоздаётся (NetworkCallback).
     */
    private void startWgMode() {
        WgConfigParser.WgConfig cfg = WgConfigParser.parse(config.getWgRaw());
        if (!cfg.valid) {
            lastError = "WG: конфиг некорректен"
                    + (cfg.parseError.isEmpty() ? "" : (": " + cfg.parseError))
                    + " (Настройки → Настройки WireGuard)";
            LogStore.add("Service", "ОШИБКА: " + lastError);
            broadcastState();
            stopSelf();
            return;
        }
        LogStore.add("Service", "WG-конфиг: адресов=" + cfg.addresses.size()
                + " peer=" + cfg.peers + " endpoint=" + cfg.endpointForLog
                + " mtu=" + (cfg.mtu > 0 ? cfg.mtu : 1420));
        vpnInterface = buildBuilderForWg(cfg).establish();
        if (vpnInterface == null) {
            LogStore.add("Service", "ОШИБКА: VpnService не разрешил TUN (WG)");
            lastError = "VpnService не разрешил TUN";
            broadcastState();
            stopSelf();
            return;
        }
        // Владение fd переходит движку: detach, чтобы close() обёртки в
        // disconnect() не закрыл fd, которым владеет wireguard-go.
        final int tunFd = vpnInterface.detachFd();
        stopWgEngine();
        wgRunner = new WgRunner(this::protectFd, config::getLogDebug, new WgRunner.Listener() {
            @Override
            public void onUp() {
                connected = true;
                broadcastState();
                LogStore.add("Service", "WireGuard: туннель поднят");
                registerWgNetworkCallback();
            }

            @Override
            public void onError(String message) {
                LogStore.add("Service", "ОШИБКА WG: " + message);
                lastError = message;
                connected = false;
                broadcastState();
                stopWgEngine();
                stopSelf();
            }
        });
        wgRunner.start(tunFd, cfg.ipc);
    }

    /** Останавливает WG-движок, сетевой колбэк и (если жив) TUN-обёртку. */
    private void stopWgEngine() {
        unregisterWgNetworkCallback();
        WgRunner r = wgRunner;
        wgRunner = null;
        if (r != null) {
            r.stop();
        }
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {
            }
            vpnInterface = null;
        }
    }

    /**
     * Режим "WireGuard через Xray": шифрование WG выполняет wireguard-outbound
     * самого Xray (userspace WG-клиент + gVisor-стек внутри ядра), а его UDP к
     * WG-серверу идёт через VLESS-туннель (sockopt.dialerProxy → outbound "proxy").
     * TUN создаётся как в режиме "только Xray" (адрес 10.0.0.2, DNS из Xray-настроек);
     * адреса/DNS из wg-конфига живут внутри WG-стека Xray, а не в VpnService.
     */
    private void startWgXrayMode() {
        WgConfigParser.WgConfig cfg = WgConfigParser.parse(config.getWgRaw());
        if (!cfg.valid) {
            lastError = "WG: конфиг некорректен"
                    + (cfg.parseError.isEmpty() ? "" : (": " + cfg.parseError))
                    + " (Настройки → Настройки WireGuard)";
            LogStore.add("Service", "ОШИБКА: " + lastError);
            broadcastState();
            stopSelf();
            return;
        }
        if (cfg.peerList.size() > 1) {
            LogStore.add("Service", "WG-конфиг содержит " + cfg.peerList.size()
                    + " peer — в режиме через Xray используется только первый ("
                    + cfg.endpointForLog + ")");
        }
        LogStore.add("Service", "WG-через-Xray: endpoint=" + cfg.endpointForLog
                + " адресов=" + cfg.addresses.size() + " peer=" + cfg.peers
                + " mtu=" + (cfg.mtu > 0 ? cfg.mtu : 1420));
        // Endpoint резолвит САМ Xray через свой DNS-модуль (лениво, при первом
        // трафике через wg-outbound), а запросы DNS-модуля идут через proxy
        // (VLESS) — правило inboundTag "dns-internal" в buildTunWg. Это «DNS
        // через Xray»: локальный системный DNS не участвует вовсе, поэтому
        // блокировки/отравление локального DNS не мешают резолву endpoint'а.
        // Java-резолв на стороне приложения убран (он зависел от системного DNS).
        final int myEpoch = startEpoch.get();
        final android.os.ParcelFileDescriptor[] holder = new android.os.ParcelFileDescriptor[1];
        new Thread(() -> {
            try {
                if (startEpoch.get() != myEpoch) {
                    LogStore.add("Service", "Старт WG-через-Xray отменён (состояние изменилось)");
                    return;
                }
                ParcelFileDescriptor tun = buildBuilder(null, 1400, null, null).establish();
                if (tun == null) {
                    LogStore.add("Service", "ОШИБКА: VpnService не разрешил TUN (WG через Xray)");
                    lastError = "VpnService не разрешил TUN";
                    connected = false;
                    broadcastState();
                    stopSelf();
                    return;
                }
                holder[0] = tun;
                vpnInterface = tun;
                if (startEpoch.get() != myEpoch) {
                    LogStore.add("Service", "Старт WG-через-Xray отменён (состояние изменилось)");
                    closeQuietly(tun);
                    if (vpnInterface == tun) {
                        vpnInterface = null;
                    }
                    return;
                }
                String logDir = getFilesDir().getAbsolutePath();
                xrayRunner.startTunWg(config, tun.getFd(), logDir);
                connected = true;
                broadcastState();
                // UDP-сокет WG живёт внутри Xray: при смене сети пересоздаём туннель
                // целиком (тот же NetworkCallback, что у режима WireGuard).
                registerWgNetworkCallback();
            } catch (Exception e) {
                Log.e(TAG, "Xray WG start failed", e);
                LogStore.add("Service", "ОШИБКА запуска Xray (WG через Xray): " + e);
                lastError = e.getMessage();
                connected = false;
                broadcastState();
                ParcelFileDescriptor tun = holder[0];
                if (tun != null) {
                    closeQuietly(tun);
                    if (vpnInterface == tun) {
                        vpnInterface = null;
                    }
                }
                stopSelf();
            }
        }, "wg-xray-start").start();
    }

    /** Закрывает ParcelFileDescriptor, глотая исключения (вспомогательная). */
    private static void closeQuietly(ParcelFileDescriptor p) {
        try {
            p.close();
        } catch (Exception ignored) {
        }
    }

    /**
     * Билдер TUN для WireGuard: адреса и DNS из конфига, маршруты из
     * AllowedIPs (0.0.0.0/0 → весь трафик), per-app фильтрация как везде.
     * Отдельный метод (не общий buildBuilder), чтобы не трогать рабочий код
     * остальных режимов.
     */
    private Builder buildBuilderForWg(WgConfigParser.WgConfig cfg) {
        Builder builder = new Builder()
                .setSession(getString(R.string.app_name))
                .setBlocking(true)
                .setMtu(cfg.mtu > 0 ? cfg.mtu : 1420);
        for (String cidr : cfg.addresses) {
            String[] p = cidr.split("/");
            if (p.length < 1 || !isIpv4(p[0])) {
                continue;
            }
            int prefix = 32;
            if (p.length > 1) {
                try {
                    prefix = Integer.parseInt(p[1].trim());
                } catch (NumberFormatException ignored) {
                }
            }
            if (prefix < 0 || prefix > 32) {
                prefix = 32;
            }
            try {
                builder.addAddress(p[0], prefix);
            } catch (Exception e) {
                Log.e(TAG, "WG addAddress failed for " + cidr, e);
            }
        }
        for (String d : cfg.dns) {
            if (isIpv4(d)) {
                try {
                    builder.addDnsServer(d);
                } catch (Exception e) {
                    Log.e(TAG, "WG addDnsServer failed for " + d, e);
                }
            }
        }
        boolean defaultRoute = false;
        int routesAdded = 0;
        for (String cidr : cfg.allowedIps) {
            String[] p = cidr.split("/");
            if (p.length < 1 || !isIpv4(p[0])) {
                continue;
            }
            int prefix = 32;
            if (p.length > 1) {
                try {
                    prefix = Integer.parseInt(p[1].trim());
                } catch (NumberFormatException ignored) {
                }
            }
            if (p[0].equals("0.0.0.0") && prefix == 0) {
                defaultRoute = true;
                continue;
            }
            try {
                builder.addRoute(p[0], prefix);
                routesAdded++;
                LogStore.add("Service", "WG-маршрут: " + p[0] + "/" + prefix);
            } catch (Exception e) {
                Log.e(TAG, "WG addRoute failed for " + cidr, e);
            }
        }
        if (defaultRoute || routesAdded == 0) {
            builder.addRoute("0.0.0.0", 0);
        }
        for (String pkg : config.getAllowedApps()) {
            try {
                builder.addAllowedApplication(pkg);
            } catch (Exception e) {
                Log.e(TAG, "addAllowedApplication failed for " + pkg, e);
            }
        }
        if (config.getAllowedApps().isEmpty()) {
            try {
                builder.addDisallowedApplication(getPackageName());
            } catch (Exception e) {
                Log.e(TAG, "addDisallowedApplication failed for own package", e);
            }
        }
        return builder;
    }

    /**
     * Смена сети на телефоне: UDP-сокеты движка привязаны к умершему интерфейсу.
     * Простейший корректный ответ (как в официальном приложении) — пересоздать
     * туннель целиком через штатный RECONNECT.
     */
    private void registerWgNetworkCallback() {
        if (wgNetCallback != null) {
            return;
        }
        try {
            android.net.ConnectivityManager cm =
                    (android.net.ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            wgNetCallback = new android.net.ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(android.net.Network network) {
                    // Собственная VPN-сеть (tun) тоже приходит в default-callback.
                    // Её игнорируем ПОЛНОСТЬЮ (в т.ч. не трогаем wgLastNetwork):
                    // иначе каждый реконнект VPN порождает «сменилась сеть» →
                    // новый реконнект → бесконечный цикл рестартов (наблюдалось
                    // ~2.5 рестарта/сек: VPN поднялся → default=VPN → событие →
                    // реконнект → default=Wi-Fi → событие → …).
                    android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                    if (caps != null
                            && caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) {
                        return;
                    }
                    // Только дефолтная сеть (registerDefaultNetworkCallback):
                    // перезапуск нужен один раз при реальной смене сети, иначе
                    // колбэк по каждой сети (Wi-Fi + LTE) даёт цикл рестартов.
                    if (wgLastNetwork != null && !network.equals(wgLastNetwork)
                            && connected
                            && (ConfigManager.MODE_WG.equals(config.getMode())
                                || ConfigManager.MODE_WG_XRAY.equals(config.getMode()))) {
                        LogStore.add("Wg", "сменилась сеть — перезапуск WG-туннеля");
                        Intent i = new Intent(GrizzlyLandVpnService.this,
                                GrizzlyLandVpnService.class);
                        i.setAction(ACTION_RECONNECT);
                        startService(i);
                    }
                    wgLastNetwork = network;
                }
            };
            cm.registerDefaultNetworkCallback(wgNetCallback);
        } catch (Exception e) {
            LogStore.add("Wg", "NetworkCallback не зарегистрирован: " + e);
        }
    }

    private void unregisterWgNetworkCallback() {
        if (wgNetCallback != null) {
            try {
                android.net.ConnectivityManager cm = (android.net.ConnectivityManager)
                        getSystemService(CONNECTIVITY_SERVICE);
                cm.unregisterNetworkCallback(wgNetCallback);
            } catch (Exception ignored) {
            }
            wgNetCallback = null;
        }
        wgLastNetwork = null;
    }

    /**
     * Нативный openvpn завершился сам (плохой конфиг, отказ auth, недоступен сервер).
     * Нельзя оставлять UI в состоянии «подключено» при мёртвом туннеле.
     */
    private void onOpenVpnExited() {
        LogStore.add("Service", "OpenVPN завершился сам — VPN отключён");
        connected = false;
        broadcastState();
        xrayRunner.stop();
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {
            }
            vpnInterface = null;
        }
        stopSelf();
    }

    /**
     * Провайдер TUN для нативного openvpn: вызывается на команду OPENTUN.
     * Создаёт TUN-интерфейс VpnService с текущими настройками и отдаёт fd.
     */
    /** Исключает сокет openvpn из VPN-маршрутизации (иначе VPN зациклится). */
    private void protectFd(int fd) {
        boolean ok = protect(fd);
        Log.i(TAG, "protect fd " + fd + " -> " + ok);
        LogStore.add("Service", "protect(fd=" + fd + ") -> " + ok);
    }

    private ParcelFileDescriptor establishTunForOpenVpn(String localIp, int mtu,
                                                        java.util.List<String> pushedDns,
                                                        java.util.List<String> pushedRoutes) {
        if (vpnInterface == null) {
            vpnInterface = buildBuilder(localIp, mtu, pushedDns, pushedRoutes).establish();
            if (vpnInterface != null) {
                connected = true;
                broadcastState();
                LogStore.add("Service", "TUN создан: ip=" + localIp + " mtu=" + mtu
                        + " (fd=" + tunFdNumber(vpnInterface) + ")"
                        + " pushedDNS=" + (pushedDns == null ? 0 : pushedDns.size())
                        + " pushedRoutes=" + (pushedRoutes == null ? 0 : pushedRoutes.size()));
                startTunFdMonitor();
            } else {
                LogStore.add("Service", "ОШИБКА: VpnService не разрешил TUN (ip=" + localIp + ")");
            }
        }
        return vpnInterface;
    }

    /** Номер дескриптора ParcelFileDescriptor (для диагностики SCM_RIGHTS). */
    private static int tunFdNumber(ParcelFileDescriptor pfd) {
        try {
            java.lang.reflect.Method m = FileDescriptor.class.getDeclaredMethod("getInt$");
            m.setAccessible(true);
            return (Integer) m.invoke(pfd.getFileDescriptor());
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Диагностика: раз в 2с опрашивает TUN-fd на читаемость (POLLIN, 0ms).
     * Если POLLIN есть, а openvpn не читает — fd до openvpn не дошёл/не тот.
     */
    private volatile Thread tunFdMonitor;

    private void startTunFdMonitor() {
        stopTunFdMonitor();
        final ParcelFileDescriptor pfd = vpnInterface;
        if (pfd == null) {
            return;
        }
        tunFdMonitor = new Thread(() -> {
            try {
                FileDescriptor fd = pfd.getFileDescriptor();
                while (connected && !Thread.currentThread().isInterrupted()) {
                    android.system.StructPollfd[] p = new android.system.StructPollfd[1];
                    p[0] = new android.system.StructPollfd();
                    p[0].fd = fd;
                    p[0].events = (short) android.system.OsConstants.POLLIN;
                    try {
                        android.system.Os.poll(p, 0);
                        boolean readable =
                                (p[0].revents & android.system.OsConstants.POLLIN) != 0;
                        boolean err = (p[0].revents
                                & (android.system.OsConstants.POLLERR
                                | android.system.OsConstants.POLLNVAL)) != 0;
                        LogStore.add("TunMon", "poll(fd=" + tunFdNumber(pfd)
                                + ") POLLIN=" + readable + (err ? " POLLERR/NVAL" : ""));
                    } catch (Exception e) {
                        LogStore.add("TunMon", "poll failed: " + e);
                        return;
                    }
                    Thread.sleep(2000);
                }
            } catch (InterruptedException ignored) {
            }
        }, "tunfd-monitor");
        tunFdMonitor.setDaemon(true);
        tunFdMonitor.start();
    }

    private void stopTunFdMonitor() {
        Thread t = tunFdMonitor;
        tunFdMonitor = null;
        if (t != null) {
            t.interrupt();
        }
    }

    /** Строит VpnService.Builder с адресами, DNS и per-app фильтрацией. */
    private Builder buildBuilder(String localIp, int mtu,
                                 java.util.List<String> pushedDns,
                                 java.util.List<String> pushedRoutes) {
        String addr = (localIp != null && !localIp.isEmpty()) ? localIp : "10.0.0.2";

        // В режимах OpenVPN учитываем настройки MTU/DNS из OpenVPN-раздела.
        boolean isOvpnMode = ConfigManager.MODE_OPENVPN.equals(config.getMode())
                || ConfigManager.MODE_XRAY_OVPN.equals(config.getMode())
                || ConfigManager.MODE_OVPN_SSH.equals(config.getMode());
        // MTU: в OpenVPN-режимах ПРИОРИТЕТ у mtu, полученного от openvpn
        // (IFCONFIG/PUSH tun-mtu) — нативный openvpn пишет пакеты размером до
        // СВОЕГО tun_mtu; если VpnService-tun меньше, write() в TUN падает
        // EINVAL ("write to TUN/TAP: Invalid argument"). Пользовательская
        // настройка используется только как fallback.
        int vpnMtu = (mtu > 0) ? mtu : 1400;
        String mtuStr = config.getOvpnMtu();
        if (isOvpnMode && !(mtu > 0) && mtuStr != null && !mtuStr.trim().isEmpty()) {
            try {
                int v = Integer.parseInt(mtuStr.trim());
                if (v > 0) {
                    vpnMtu = v;
                }
            } catch (NumberFormatException ignored) {
            }
        }
        // Приоритет DNS в OpenVPN-режимах: явная настройка пользователя →
        // DNS, запушенный сервером (PUSH_REPLY/dhcp-option DNS) → DNS из Xray-настроек.
        String dnsList = config.getXrayDnsPlain();
        if (isOvpnMode) {
            String oDns = config.getOvpnDns();
            if (oDns != null && !oDns.trim().isEmpty()) {
                dnsList = oDns;
            } else if (pushedDns != null && !pushedDns.isEmpty()) {
                dnsList = String.join(",", pushedDns);
            }
        }
        // DNS-серверы берутся ТОЛЬКО из настроек/импортированного конфига (без
        // жёстко зашитых fallback-адресов), чтобы не подменять DNS пользователя.
        // Для Android VpnService addDnsServer нужны чистые IP, поэтому из поля DNS
        // (которое может содержать tcp://, https:// DoH, ip:853 DoT) берём только IP.

        Builder builder = new Builder()
                .setSession(getString(R.string.app_name))
                .addAddress(addr, 32)
                .addRoute("0.0.0.0", 0)
                .setBlocking(true)
                .setMtu(vpnMtu > 0 ? vpnMtu : 1400);

        // DNS-серверы из настроек (через запятую). addDnsServer принимает только
        // числовые IP: DoH/DoT-форматы и прочий мусор отфильтровываем, иначе
        // establish() упадёт с IllegalArgumentException.
        for (String dns : dnsList.split(",")) {
            String d = dns.trim();
            if (!d.isEmpty() && isIpv4(d)) {
                builder.addDnsServer(d);
            }
        }

        // Маршруты: если сервер пушит конкретные (PUSH_REPLY/ROUTE) — уважаем их
        // (split-VPN как в OpenVPN for Android). Иначе — весь трафик (0.0.0.0/0).
        if (pushedRoutes != null && !pushedRoutes.isEmpty()) {
            for (String r : pushedRoutes) {
                String[] p = r.split("\\s+");
                if (p.length < 2) continue;
                int prefix = prefixFromMask(p[1]);
                if (prefix < 0) continue;
                try {
                    builder.addRoute(p[0], prefix);
                    LogStore.add("Service", "Маршрут сервера: " + p[0] + "/" + prefix);
                } catch (Exception e) {
                    Log.e(TAG, "addRoute failed for " + r, e);
                }
            }
        } else {
            builder.addRoute("0.0.0.0", 0);
        }

        // Per-app: маршрутизируем только выбранные приложения.
        for (String pkg : config.getAllowedApps()) {
            try {
                builder.addAllowedApplication(pkg);
            } catch (Exception e) {
                Log.e(TAG, "addAllowedApplication failed for " + pkg, e);
            }
        }

        // Исключаем собственный пакет из VPN-маршрутизации, чтобы соединение
        // Xray/OpenVPN с сервером не зацикливалось через собственный туннель.
        // Нужно ТОЛЬКО в режиме «весь трафик» (allowed-список пуст): при per-app
        // фильтрации свой пакет и так не входит в allowed, а смешивание
        // addAllowedApplication и addDisallowedApplication на Android 11+ даёт
        // ошибку «Interface rule must specify interface».
        if (config.getAllowedApps().isEmpty()) {
            try {
                builder.addDisallowedApplication(getPackageName());
            } catch (Exception e) {
                Log.e(TAG, "addDisallowedApplication failed for own package", e);
                LogStore.add("Service", "addDisallowedApplication(own) failed: " + e);
            }
        }
        return builder;
    }

    private void disconnect() {
        connected = false;
        lastError = "";
        startEpoch.incrementAndGet(); // отменить асинхронный старт WG-через-Xray, если он в полёте
        broadcastState();
        LogStore.add("Service", "==== Отключение ====");
        stopTunFdMonitor();
        xrayRunner.stop();
        openVpnRunner.stop();
        stopSshTunnel();
        stopWgEngine();
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {
            }
            vpnInterface = null;
        }
        stopForeground(true);
        stopSelf();
    }

    @Override
    public void onDestroy() {
        disconnect();
        super.onDestroy();
    }

    /** Строгая проверка IPv4 (InetAddress.getByName сделал бы DNS-запрос для доменов). */
    private static boolean isIpv4(String s) {
        String[] o = s.split("\\.");
        if (o.length != 4) return false;
        for (String part : o) {
            if (!part.matches("\\d{1,3}")) return false;
            try {
                if (Integer.parseInt(part) > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    /** Маска вида 255.255.255.0 → префикс 24. Некорректная/несмежная маска → -1. */
    private static int prefixFromMask(String mask) {
        if (mask == null) return -1;
        String[] o = mask.split("\\.");
        if (o.length != 4) return -1;
        int bits = 0;
        boolean seenZero = false;
        try {
            for (String part : o) {
                int v = Integer.parseInt(part);
                if (v < 0 || v > 255) return -1;
                for (int i = 7; i >= 0; i--) {
                    if ((v & (1 << i)) != 0) {
                        if (seenZero) return -1;
                        bits++;
                    } else {
                        seenZero = true;
                    }
                }
            }
        } catch (NumberFormatException e) {
            return -1;
        }
        return bits;
    }

    private void broadcastState() {
        Intent i = new Intent(ACTION_STATE_CHANGED);
        i.setPackage(getPackageName());
        sendBroadcast(i);
    }

    private Notification buildNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "GrizzlyLandVPN", NotificationManager.IMPORTANCE_LOW);
            nm.createNotificationChannel(ch);
        }
        Intent disconnectIntent = new Intent(this, GrizzlyLandVpnService.class);
        disconnectIntent.setAction(ACTION_DISCONNECT);
        PendingIntent pi = PendingIntent.getService(
                this, 0, disconnectIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder b = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        return b.setContentTitle("GrizzlyLandVPN")
                .setContentText("VPN активен")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setOngoing(true)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Отключить", pi)
                .build();
    }
}
