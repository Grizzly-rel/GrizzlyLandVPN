package com.grizzlyland.vpn;

import android.content.Context;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.function.IntConsumer;

/**
 * Реализует management-интерфейс OpenVPN (в стиле ics-openvpn) на стороне Android.
 *
 * Нативный openvpn, собранный с TARGET_ANDROID, открывает TUN-устройство через
 * management-интерфейс: он подключается к нашему UNIX-сокету (--management-client),
 * присылает команду "OPENTUN", а мы в ответ должны отдать файловый дескриптор
 * TUN-интерфейса от VpnService через SCM_RIGHTS (setFileDescriptorsForSend).
 *
 * Кроме OPENTUN обрабатываются IFCONFIG / ROUTE / DNS / PERSIST_TUN_ACTION,
 * которые приходят ДО OPENTUN (на Android ifconfig_order = BEFORE_TUN_OPEN).
 */
public class OpenVpnManagementThread implements Runnable {

    public interface TunProvider {
        ParcelFileDescriptor establish(String localIp, int mtu,
                                       java.util.List<String> pushedDns,
                                       java.util.List<String> pushedRoutes);
    }

    private static final String TAG = "OvpnMgmt";

    private final Context context;
    private final TunProvider tunProvider;
    private final IntConsumer protectCallback;
    /** Периодическая диагностика status 3 — только при включённом logDebug. */
    private final boolean diagnosticsEnabled;
    private final String keyPassword;
    private final String authUsername;
    private final String authPassword;

    private LocalServerSocket serverSocket;
    private LocalSocket socket;
    private OutputStream out;
    // Файловые дескрипторы, переданные openvpn через SCM_RIGHTS (для PROTECTFD).
    private final LinkedList<FileDescriptor> fdQueue = new LinkedList<>();

    // Собранная из management-команд конфигурация TUN.
    private volatile String localIp;
    private volatile String remoteNetmask;
    private volatile int mtu = 1400;
    private volatile String topology = "net30";

    // Опции, запушенные сервером (PUSH_REPLY / needok DNSSERVER / ROUTE).
    // Отдаются провайдеру TUN на OPENTUN, чтобы попасть в VpnService.Builder.
    private final java.util.List<String> pushedDns = new java.util.concurrent.CopyOnWriteArrayList<>();
    private final java.util.List<String> pushedRoutes = new java.util.concurrent.CopyOnWriteArrayList<>();

    public java.util.List<String> getPushedDns() {
        return pushedDns;
    }

    public java.util.List<String> getPushedRoutes() {
        return pushedRoutes;
    }

    private void addPushedDns(String ip) {
        if (ip == null || ip.isEmpty()) return;
        if (!pushedDns.contains(ip)) {
            pushedDns.add(ip);
            LogStore.add("Mgmt", "Сервер пушит DNS: " + ip);
        }
    }

    private void addPushedRoute(String route) {
        if (route == null || route.trim().isEmpty()) return;
        if (!pushedRoutes.contains(route)) {
            pushedRoutes.add(route.trim());
            LogStore.add("Mgmt", "Сервер пушит маршрут: " + route);
        }
    }

    private volatile boolean running = true;

    // ==== Темп реконнектов (>HOLD:) ====
    // OpenVPN с --management-hold входит в hold на КАЖДОМ внутреннем рестарте
    // (SIGUSR1), в том числе в цикле «DNS недоступен → рестарт». Мгновенный
    // 'hold release' на каждый hold разгонял этот цикл до десятков рестартов
    // в секунду: штурм DNS, флуд журнала, расход батареи (логи 26.10 00:33 —
    // ~50 циклов за полторы секунды). Теперь каждое событие hold становится
    // в очередь, а отдельный поток-шлюз выпускает их с паузой: бэкофф после
    // неудачных попыток (2→30с) + ожидание реальной сети (не нашей VPN).
    // Сеть вернётся — openvpn подключится сам, без штурма.
    private final java.util.concurrent.BlockingQueue<Long> holdEvents =
            new java.util.concurrent.LinkedBlockingQueue<>();
    private volatile long lastHoldReleaseMs = 0L;
    /** Релизов hold подряд без успешного подключения (TUN/Init-seq сбрасывают).
     *  Считаем В САМОМ шлюзе, а не по stdout openvpn: вывод идёт через пайп
     *  с буферизацией и отстаёт от management-событий на цикл (проверено 26.10). */
    private volatile int releasesSinceSuccess = 0;
    private volatile boolean holdGateStarted = false;
    private static final long HOLD_MIN_INTERVAL_MS = 2000L;
    private static final long HOLD_BACKOFF_MAX_MS = 30000L;

    /** Строка из вывода openvpn (зовёт OpenVpnRunner): успешное подключение
     *  сбрасывает бэкофф шлюза. */
    void noteOpenVpnLine(String line) {
        if (line != null && line.contains("Initialization Sequence Completed")) {
            releasesSinceSuccess = 0;
        }
    }

    /** >HOLD: не отвечаем мгновенно — событие в очередь шлюза. */
    private void gateHoldRelease() {
        holdEvents.add(System.currentTimeMillis());
        if (holdGateStarted) {
            return;
        }
        synchronized (this) {
            if (holdGateStarted) {
                return;
            }
            holdGateStarted = true;
        }
        Thread t = new Thread(this::holdGateLoop, "ovpn-hold-gate");
        t.setDaemon(true);
        t.start();
    }

    /** Цикл шлюза: каждый hold выпускается не раньше паузы (бэкофф 2→30с
     *  растёт с числом релизов подряд без успеха) и только при наличии сети,
     *  отличной от нашей VPN. Читатель management-потока при этом не
     *  блокируется — ждём в отдельном потоке. */
    private void holdGateLoop() {
        while (running) {
            try {
                if (holdEvents.poll(2, java.util.concurrent.TimeUnit.SECONDS) == null) {
                    continue; // таймаут — перепроверяем running
                }
                long backoff = (releasesSinceSuccess <= 0)
                        ? HOLD_MIN_INTERVAL_MS
                        : Math.min(HOLD_MIN_INTERVAL_MS << Math.min(releasesSinceSuccess - 1, 4),
                                   HOLD_BACKOFF_MAX_MS);
                long elapsed = System.currentTimeMillis() - lastHoldReleaseMs;
                if (elapsed < backoff) {
                    Thread.sleep(backoff - elapsed);
                }
                boolean logged = false;
                while (running && !hasUsableUnderlyingNetwork()) {
                    if (!logged) {
                        LogStore.add("Mgmt", "Сеть недоступна — hold не отпускаю, жду интернет"
                                + " (появится — подключусь сам)");
                        logged = true;
                    }
                    Thread.sleep(2000);
                }
                if (!running) {
                    return;
                }
                write("hold release\n");
                lastHoldReleaseMs = System.currentTimeMillis();
                releasesSinceSuccess++;
            } catch (InterruptedException e) {
                // Случайный interrupt не должен убивать шлюз — иначе openvpn
                // навсегда застрянет в hold. Выходим только по running=false.
            }
        }
    }

    /** Есть ли сеть, отличная от нашей VPN, с заявленным интернетом
     *  (Wi-Fi/LTE). Ошибки проверки трактуем как «сеть есть» — не блокируем
     *  подключение из-за особенностей API. */
    private boolean hasUsableUnderlyingNetwork() {
        try {
            android.net.ConnectivityManager cm = (android.net.ConnectivityManager)
                    context.getSystemService(android.content.Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                return true;
            }
            for (android.net.Network n : cm.getAllNetworks()) {
                android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(n);
                if (caps == null) continue;
                if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) continue;
                if (!caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
                return true;
            }
        } catch (Exception e) {
            return true;
        }
        return false;
    }

    /**
     * Режим интерфейса СЕРВЕРА: "tun" (L3, обычный), "tap" (L2, бриджевый сервер),
     * "auto" (пробуем tap с ARP-детектом, при неудаче откатываемся в tun).
     */
    private volatile String linkMode = "tun";
    /** Активный TAP-шим (один на сессию openvpn). */
    private volatile TapShim shim;

    public void setLinkMode(String lm) {
        this.linkMode = (lm == null || lm.isEmpty()) ? "tun" : lm;
    }

    public OpenVpnManagementThread(Context context, TunProvider tunProvider, IntConsumer protectCallback) {
        this(context, tunProvider, protectCallback, null, null, null);
    }

    public OpenVpnManagementThread(Context context, TunProvider tunProvider, IntConsumer protectCallback,
                                   String keyPassword, String authUsername, String authPassword) {
        this.context = context;
        this.tunProvider = tunProvider;
        this.protectCallback = protectCallback;
        this.keyPassword = keyPassword;
        this.authUsername = authUsername;
        this.authPassword = authPassword;
        // Периодическая диагностика (status 3) — только при включённом подробном
        // журнале: в простое она не нужна, а будит CPU и пишет лог каждые N секунд.
        this.diagnosticsEnabled = new ConfigManager(context).getLogDebug();
    }

    public String getSocketPath() {
        return new File(context.getCacheDir(), "mgmtsocket").getAbsolutePath();
    }

    /** Запускает серверный сокет и фоновый поток обработки. */
    public void start() throws IOException {
        String path = getSocketPath();
        new File(path).delete();

        LocalSocket ls = new LocalSocket();
        ls.bind(new LocalSocketAddress(path, LocalSocketAddress.Namespace.FILESYSTEM));
        serverSocket = new LocalServerSocket(ls.getFileDescriptor());
        new Thread(this, "ovpn-mgmt").start();
    }

    @Override
    public void run() {
        try {
            socket = serverSocket.accept();
            serverSocket.close();
            out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            try {
                // Таймаут чтения: будит цикл раз в 15с (экономия батареи — было 4с).
                // По таймауту шлём "status 3" ТОЛЬКО при включённом logDebug —
                // openvpn отвечает счётчиками TUN in/out (диагностика TUN-интерфейса).
                socket.setSoTimeout(15000);
            } catch (Exception ignored) {
            }

            write("version 3\n");

            byte[] buf = new byte[4096];
            StringBuilder pending = new StringBuilder();
            while (running) {
                int n;
                try {
                    n = in.read(buf);
                } catch (java.net.SocketTimeoutException te) {
                    if (running && diagnosticsEnabled) {
                        write("status 3\n");
                    }
                    continue;
                } catch (java.io.IOException ioe) {
                    // LocalSocket на этом Android при SO_TIMEOUT кидает
                    // IOException("Try again") (EAGAIN), а не SocketTimeoutException.
                    // Это ТАЙМАУТ, а не разрыв: иначе openvpn видит закрытие
                    // management-сокета и делает management-exit (SIGTERM, код 0)!
                    String m = ioe.getMessage();
                    if (running && m != null && m.contains("Try again")) {
                        if (diagnosticsEnabled) {
                            write("status 3\n");
                        }
                        continue;
                    }
                    throw ioe;
                }
                if (n < 0) {
                    break;
                }
                // Собираем файловые дескрипторы, переданные через SCM_RIGHTS.
                try {
                    FileDescriptor[] fds = socket.getAncillaryFileDescriptors();
                    if (fds != null) {
                        for (FileDescriptor fd : fds) {
                            fdQueue.add(fd);
                        }
                    }
                } catch (IOException ignored) {
                }

                pending.append(new String(buf, 0, n, StandardCharsets.UTF_8));
                int idx;
                while ((idx = pending.indexOf("\n")) >= 0) {
                    String line = pending.substring(0, idx).trim();
                    pending.delete(0, idx + 1);
                    if (!line.isEmpty()) {
                        handleLine(line);
                    }
                }
            }
        } catch (IOException e) {
            if (running) {
                Log.e(TAG, "management io error", e);
            }
        } finally {
            close();
        }
    }

    private void handleLine(String line) {
        if (line.startsWith(">INFO:")) {
            // Ответы на "status 3" (счётчики TUN in/out) приходят в >INFO —
            // логируем их (диагностика читаемости TUN нативным openvpn).
            LogStore.add("Mgmt", line);
            return;
        } else if (line.startsWith(">HOLD:")) {
            // OpenVPN ждёт, пока мы разрешим продолжить. Через шлюз (бэкофф +
            // ожидание сети): мгновенный ответ разгонял цикл «резолв не удался
            // → рестарт» до десятков итераций в секунду.
            gateHoldRelease();
        } else if (line.startsWith(">NEED-OK:")) {
            handleNeedOk(line);
        } else if (line.startsWith(">PASSWORD:")) {
            // OpenVPN запрашивает пароль (зашифрованный приватный ключ или auth-user-pass).
            // Формат: >PASSWORD:Need '<TYPE>' password confirmation
            String type = extractQuotedType(line.substring(">PASSWORD:".length()));
            Log.d(TAG, "mgmt password request: " + line);
            LogStore.add("Mgmt", "Запрос пароля: " + line);
            if ("Auth".equals(type)) {
                if (authUsername != null && !authUsername.isEmpty()) {
                    write("username 'Auth' " + authUsername + "\n");
                }
                write("password 'Auth' " + (authPassword != null ? authPassword : "") + "\n");
            } else if ("Private Key".equals(type)) {
                write("password 'Private Key' " + (keyPassword != null ? keyPassword : "") + "\n");
            } else {
                write("password '" + type + "' \n");
            }
        } else if (line.startsWith(">PUSH:REPLY")) {
            handlePushReply(line);
        } else if (line.startsWith(">STATE:")) {
            Log.d(TAG, "mgmt state: " + line);
            LogStore.add("Mgmt", line);
        } else {
            Log.d(TAG, "mgmt line: " + line);
            LogStore.add("Mgmt", line);
        }
    }

    /**
     * Разбор опций, запушенных сервером: ">PUSH:REPLY,route ...,dhcp-option DNS ..., ...".
     * Интересны dhcp-option DNS (адреса DNS) и route (маршруты). block-outside-dns —
     * Windows-only, игнорируется.
     */
    private void handlePushReply(String line) {
        String opts = line.substring(">PUSH:REPLY".length());
        if (opts.startsWith(",")) opts = opts.substring(1);
        if (opts.trim().isEmpty()) {
            return;
        }
        LogStore.add("Mgmt", "PUSH_REPLY: " + opts);
        for (String opt : opts.split(",")) {
            String o = opt.trim();
            if (o.isEmpty()) continue;
            String[] p = o.split("\\s+");
            if (p.length >= 3 && "dhcp-option".equals(p[0]) && "DNS".equals(p[1])) {
                addPushedDns(p[2]);
            } else if (p.length >= 3 && "route".equals(p[0])) {
                String gw = p.length >= 4 ? p[3] : "vpn_gateway";
                if (!"net_gateway".equals(gw)) {
                    addPushedRoute(p[1] + " " + p[2] + " " + gw);
                }
            }
        }
    }

    private void handleNeedOk(String line) {
        String argument = line.substring(">NEED-OK:".length());
        int p1 = argument.indexOf('\'');
        if (p1 < 0) {
            return;
        }
        int p2 = argument.indexOf('\'', p1 + 1);
        if (p2 < 0) {
            return;
        }
        String type = argument.substring(p1 + 1, p2);
        // аргумент: "Need 'TYPE' confirmation MSG:extra" -> берём часть после первого ':'
        String extra = "";
        int colon = argument.indexOf(':');
        if (colon >= 0) {
            extra = argument.substring(colon + 1);
        }

        switch (type) {
            case "IFCONFIG": {
                String[] p = extra.split(" ");
                if (p.length >= 3) {
                    localIp = p[0];
                    remoteNetmask = p[1];
                    try {
                        mtu = Integer.parseInt(p[2]);
                    } catch (NumberFormatException ignored) {
                    }
                    if (p.length >= 4) {
                        topology = p[3];
                    }
                }
                write("needok 'IFCONFIG' ok\n");
                // TAP-режим: ifconfig приходит ПОСЛЕ OPENTUN — именно здесь
                // становятся известны IP/маска/MTU, создаём и привязываем TUN.
                TapShim s = shim;
                if (s != null && !s.hasTun() && localIp != null && tunProvider != null) {
                    try {
                        int ipMtu = (mtu > 14) ? mtu - 14 : mtu;
                        ParcelFileDescriptor pfd = tunProvider.establish(
                                localIp, ipMtu, pushedDns, pushedRoutes);
                        if (pfd != null) {
                            s.setNetwork(localIp, remoteNetmask);
                            s.attachTun(pfd);
                            LogStore.add("Mgmt", "TAP: TUN создан после IFCONFIG: ip="
                                    + localIp + " ip-mtu=" + ipMtu);
                        }
                    } catch (Exception e) {
                        Log.e(TAG, "tap tun attach failed", e);
                        LogStore.add("Mgmt", "ОШИБКА привязки TUN в TAP: " + e);
                    }
                }
                break;
            }
            case "IFCONFIG6":
                write("needok 'IFCONFIG6' ok\n");
                break;
            case "ROUTE": {
                // extra: "<network> <netmask> [gateway]". gateway net_gateway = мимо
                // VPN (игнорируем), vpn_gateway/пусто = через туннель.
                String[] p = extra.trim().split("\\s+");
                if (p.length >= 2) {
                    String gw = p.length >= 3 ? p[2] : "vpn_gateway";
                    LogStore.add("Mgmt", "Сервер пушит ROUTE: " + extra.trim());
                    if (!"net_gateway".equals(gw)) {
                        addPushedRoute(p[0] + " " + p[1] + " " + gw);
                    }
                }
                write("needok 'ROUTE' ok\n");
                break;
            }
            case "DNSSERVER": {
                addPushedDns(extra.trim());
                write("needok 'DNSSERVER' ok\n");
                break;
            }
            case "ROUTE6":
            case "DNS6SERVER":
                // IPv6: tun IPv4-only, осознанно не применяем.
                LogStore.add("Mgmt", "IPv6-опция пропущена: " + type);
                write("needok '" + type + "' ok\n");
                break;
            case "DNSDOMAIN":
            case "HTTPPROXY":
                write("needok '" + type + "' ok\n");
                break;
            case "PERSIST_TUN_ACTION":
                // Для первого открытия tun старый fd отсутствует; отвечаем валидным значением.
                write("needok 'PERSIST_TUN_ACTION' OPEN_BEFORE_CLOSE\n");
                break;
            case "PROTECTFD": {
                // openvpn передаёт fd сокета, который нужно исключить из маршрутизации
                // через VPN (иначе VPN-соединение зациклится).
                FileDescriptor fd = fdQueue.pollFirst();
                if (fd != null && protectCallback != null) {
                    try {
                        protectCallback.accept(getFdInt(fd));
                        write("needok 'PROTECTFD' ok\n");
                    } catch (Exception e) {
                        Log.w(TAG, "protect fd failed", e);
                        write("needok 'PROTECTFD' cancel\n");
                    }
                } else {
                    write("needok 'PROTECTFD' cancel\n");
                }
                break;
            }
            case "OPENTUN":
                handleOpentun(type);
                break;
            default:
                Log.w(TAG, "unknown needok: " + type + " (" + line + ")");
                write("needok '" + type + "' cancel\n");
                break;
        }
    }

    private void handleOpentun(String type) {
        if (tunProvider == null) {
            write("needok '" + type + "' cancel\n");
            return;
        }
        String lm = linkMode == null ? "tun" : linkMode;
        boolean tap = "tap".equals(lm) || "auto".equals(lm);
        if (tap) {
            handleOpentunTap(type, lm);
            return;
        }
        ParcelFileDescriptor pfd = tunProvider.establish(localIp, mtu, pushedDns, pushedRoutes);
        if (pfd == null) {
            write("needok '" + type + "' cancel\n");
            return;
        }
        try {
            FileDescriptor fd = pfd.getFileDescriptor();
            // Диагностика: номер fd, тип файла (fstat), есть ли данные к чтению.
            int fdNum = getFdInt(fd);
            String fst = "";
            boolean readable = false;
            try {
                android.system.StructStat st = android.system.Os.fstat(fd);
                // /dev/tun → chr device 10:200 (rdev 0x0a00...); для TUN-устройства
                // старший номер всегда 10, младший 200.
                long rdev = st.st_rdev;
                long maj = (rdev >> 8) & 0xfffL;
                long min = (rdev & 0xffL) | ((rdev >> 32) & 0xfff000L);
                fst = "rdev=" + maj + ":" + min + " mode=0" + Integer.toOctalString(st.st_mode);
                android.system.StructPollfd[] p = new android.system.StructPollfd[1];
                p[0] = new android.system.StructPollfd();
                p[0].fd = fd;
                p[0].events = (short) (android.system.OsConstants.POLLIN);
                android.system.Os.poll(p, 0);
                readable = (p[0].revents & android.system.OsConstants.POLLIN) != 0;
            } catch (Exception pe) {
                fst = "fstat/poll failed: " + pe;
            }
            LogStore.add("Mgmt", "TUN-fd диагностика: fd=" + fdNum + " " + fst
                    + " POLLIN(0ms)=" + readable);
            sendFdToOpenvpn(fd, type);
            Log.i(TAG, "OPENTUN ok, sent tun fd");
            LogStore.add("Mgmt", "OPENTUN ok, TUN-fd передан, ip=" + localIp + " mtu=" + mtu);
            // Туннель открыт = попытка удалась: сброс бэкоффа hold-шлюза.
            releasesSinceSuccess = 0;
        } catch (Exception e) {
            Log.e(TAG, "send tun fd failed", e);
            write("needok '" + type + "' cancel\n");
        }
        // fd остаётся открытым у сервиса (vpnInterface); не закрываем здесь.
    }

    /**
     * OPENTUN в TAP-режиме: openvpn получает НЕ TUN-fd, а конец UNIX-пары
     * (SOCK_SEQPACKET — сохраняет границы Ethernet-кадров). Нативный openvpn
     * (TARGET_ANDROID) просто делает read/write от переданного fd, ioctl не
     * выполняет, тип tun/tap берёт из директивы dev. Конвертацию IP↔Ethernet
     * выполняет {@link TapShim} между этой парой и TUN VpnService.
     */
    private void handleOpentunTap(String type, String linkModeValue) {
        try {
            // Android-сигнатура: socketpair(domain, type, proto, fd1, fd2) — void,
            // пара создаётся в переданные FileDescriptor.
            FileDescriptor a = new FileDescriptor();
            FileDescriptor b = new FileDescriptor();
            android.system.Os.socketpair(android.system.OsConstants.AF_UNIX,
                    android.system.OsConstants.SOCK_SEQPACKET, 0, a, b);
            FileDescriptor[] pair = new FileDescriptor[]{a, b};
            // TUN-интерфейс VpnService создаётся как обычно (его видят приложения),
            // но MTU меньше на размер Ethernet-заголовка: сервер пушит tun-mtu,
            // который для tap означает размер КАДРА.
            // ВАЖНО: для tap openvpn запрашивает OPENTUN ДО IFCONFIG (порядок
            // after-tun-open), поэтому IP может быть ещё неизвестен — тогда шим
            // создаётся без TUN, а TUN привязывается в обработчике IFCONFIG.
            if (localIp != null && !localIp.isEmpty()) {
                int ipMtu = (mtu > 14) ? mtu - 14 : mtu;
                ParcelFileDescriptor pfd = tunProvider.establish(localIp, ipMtu, pushedDns, pushedRoutes);
                if (pfd == null) {
                    write("needok '" + type + "' cancel\n");
                    return;
                }
                shim = makeShim(pfd, pair[0]);
                shim.setNetwork(localIp, remoteNetmask);
                shim.start();
                sendFdToOpenvpn(pair[1], type);
                Log.i(TAG, "OPENTUN ok (tap, ip known), sent socketpair fd");
                LogStore.add("Mgmt", "OPENTUN ok (tap): ip=" + localIp + " mtu=" + mtu
                        + " (ip-mtu=" + ipMtu + ")");
                return;
            }
            shim = makeShim(null, pair[0]);
            shim.start();
            sendFdToOpenvpn(pair[1], type);
            Log.i(TAG, "OPENTUN ok (tap, ip pending), sent socketpair fd");
            LogStore.add("Mgmt", "OPENTUN ok (tap): L2-пара передана, ждём IFCONFIG для создания TUN"
                    + ("auto".equals(linkModeValue) ? " [auto: при неудаче ARP откат в tun]" : ""));
        } catch (Exception e) {
            Log.e(TAG, "tap opentun failed", e);
            LogStore.add("Mgmt", "ОШИБКА TAP OPENTUN: " + e);
            if (shim != null) {
                shim.stop();
                shim = null;
            }
            write("needok '" + type + "' cancel\n");
        }
    }

    private TapShim makeShim(ParcelFileDescriptor pfd, FileDescriptor sockFd) {
        return new TapShim(pfd, sockFd, null, null, new TapShim.Listener() {
            @Override
            public void onTapConfirmed() {
                LogStore.add("Mgmt", "TAP-режим подтверждён (ARP-ответ шлюза)");
            }

            @Override
            public void onTapFailed() {
                // Авто-отката больше нет (режим берётся из dev конфига).
                // Это чисто диагностическое событие: tap выбран, но шлюз не отвечает.
                LogStore.add("Mgmt", "TAP: ARP-ответ шлюза не получен — проверьте сервер/сеть");
            }
        });
    }
    private void sendFdToOpenvpn(FileDescriptor fd, String type) throws Exception {
        Method setFds = LocalSocket.class.getMethod(
                "setFileDescriptorsForSend", FileDescriptor[].class);
        setFds.invoke(socket, (Object) new FileDescriptor[]{fd});
        write("needok '" + type + "' ok\n");
        setFds.invoke(socket, (Object) new FileDescriptor[0]);
    }

    /** Извлекает тип пароля из строки вида "Need 'Private Key' password confirmation". */
    private static String extractQuotedType(String s) {
        int p1 = s.indexOf('\'');
        if (p1 < 0) return null;
        int p2 = s.indexOf('\'', p1 + 1);
        if (p2 < 0) return null;
        return s.substring(p1 + 1, p2);
    }

    /** Возвращает int-дескриптор из FileDescriptor (скрытый метод getInt$). */
    private static int getFdInt(FileDescriptor fd) {
        try {
            Method m = FileDescriptor.class.getDeclaredMethod("getInt$");
            m.setAccessible(true);
            return (Integer) m.invoke(fd);
        } catch (Exception e) {
            throw new RuntimeException("cannot get fd int", e);
        }
    }

    /** Живая смена детальности логов openvpn (management-команда verb) —
     *  применяется на лету, без перезапуска движка. Используется кнопкой
     *  «Подробный журнал» (5) и возвратом к обычному уровню. */
    public void setVerb(int verb) {
        write("verb " + verb + "\n");
    }

    private void write(String s) {
        if (out == null) {
            return;
        }
        try {
            out.write(s.getBytes(StandardCharsets.UTF_8));
            out.flush();
        } catch (IOException e) {
            Log.e(TAG, "write failed", e);
        }
    }

    public void close() {
        running = false;
        TapShim s = shim;
        shim = null;
        if (s != null) {
            s.stop();
        }
        try {
            if (socket != null) {
                socket.close();
            }
        } catch (IOException ignored) {
        }
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ignored) {
        }
    }
}
