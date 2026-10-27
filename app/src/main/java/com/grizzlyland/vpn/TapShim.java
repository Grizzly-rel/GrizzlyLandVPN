package com.grizzlyland.vpn;

import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;

import java.io.FileDescriptor;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * Мост L3↔L2 между TUN-интерфейсом VpnService и OpenVPN, работающим в TAP-режиме.
 *
 * Android VpnService умеет только L3 (tun): приложения кладут в интерфейс готовые
 * IP-пакеты. Некоторые OpenVPN-серверы (бриджевые, "dev tap") ожидают от клиента
 * Ethernet-кадры. Данный шим конвертирует одно в другое:
 *
 *   приложения → VpnService TUN (IP) → [TapShim: IP↔Ethernet + ARP] →
 *   → UNIX-пара (SOCK_SEQPACKET, сохраняет границы кадров) → openvpn (dev tap)
 *
 * Один конец пары передаётся openvpn через management OPENTUN (SCM_RIGHTS) —
 * нативный openvpn на Android просто делает read/write от полученного fd
 * (см. tun.c TARGET_ANDROID: tt->fd = lastfdreceived), ioctl не делает.
 *
 * ARP: шим сам отвечает за L2-резолв — при отправке IP-пакета с неизвестным
 * dst-MAC буферизует пакет и шлёт ARP-запрос; ARP-ответы кешируются; на
 * ARP-запросы сервера ("кто имеет наш IP") отвечает.
 *
 * Детект режима: сразу после старта шим шлёт ARP-запрос шлюзу. Если сервер
 * реально работает в tap-режиме — он ответит (кадр вернётся через туннель).
 * Если ответа нет за DETECT_TIMEOUT_MS — сервер не tap (или не отвечает),
 * слушатель получает onTapFailed() для отката в обычный tun-режим.
 */
public class TapShim {

    public interface Listener {
        /** ARP-ответ от шлюза получен — сервер работает в tap-режиме. */
        void onTapConfirmed();

        /** ARP-ответа нет — сервер, вероятно, не tap. Вызывается один раз. */
        void onTapFailed();
    }

    private static final String TAG = "TapShim";

    private static final int ETH_HLEN = 14;
    private static final int ET_IPV4 = 0x0800;
    private static final int ET_ARP = 0x0806;
    private static final int BUF_LEN = 2048;          // > max кадр (tun_mtu 1500)
    private static final int MAX_PENDING_PER_DST = 64;
    private static final long DETECT_TIMEOUT_MS = 7000;
    private static final long NO_NETWORK_TIMEOUT_MS = 15000;
    private static final long ARP_RETRY_MS = 2000;
    private static final long ARP_PER_DST_INTERVAL_MS = 1000;

    private volatile ParcelFileDescriptor tunPfd; // TUN VpnService (L3, IP-пакеты)
    private final FileDescriptor sockFd;         // наш конец UNIX-пары (L2, кадры)
    private volatile String myIp;                // наш IP в tap-подсети
    private volatile String gatewayIp;           // шлюз (для ARP-детекта)
    private volatile int myMaskInt = 0xFFFFFF00; // маска подсети (int)
    private final byte[] myMac = new byte[6];    // наш виртуальный MAC
    private final Listener listener;

    private volatile boolean running = true;
    private volatile boolean confirmed = false;
    private volatile boolean failedReported = false;

    /** MAC-кеш: ключ = dst IP как int. */
    private final Map<Integer, byte[]> macByIp = new HashMap<>();
    /** Пакеты, ожидающие ARP-резолва dst. */
    private final Map<Integer, ArrayDeque<byte[]>> pending = new HashMap<>();
    /** Время последнего ARP-запроса по dst (анти-флуд). */
    private final Map<Integer, Long> lastArpAt = new HashMap<>();

    // Счётчики для диагностики (нестрогая видимость допустима).
    public volatile long statIpToTap, statIpFromTap, statArpReplies, statDropped, statBufWait;

    private Thread tToTap, tFromTap, tTimer;

    /**
     * @param tunPfd  TUN-интерфейс VpnService (может быть null — тогда привязывается
     *                позже через {@link #attachTun}; закрывается снаружи, сервисом)
     * @param sockFd  наш конец socketpair; второй конец уходит openvpn
     * @param myIp    наш IPv4 в tap-подсети (из PUSH ifconfig), может быть null,
     *                если ifconfig приходит ПОСЛЕ OPENTUN (обычный порядок для tap)
     * @param netmask маска подсети (из PUSH ifconfig), может быть null
     */
    public TapShim(ParcelFileDescriptor tunPfd, FileDescriptor sockFd,
                   String myIp, String netmask, Listener listener) {
        this.tunPfd = tunPfd;
        this.sockFd = sockFd;
        this.myIp = myIp;
        this.listener = listener;
        Random r = new Random();
        // locally administered unicast MAC (первый байт 0x02)
        myMac[0] = 0x02;
        for (int i = 1; i < 6; i++) {
            myMac[i] = (byte) r.nextInt(256);
        }
        this.gatewayIp = (myIp != null) ? computeGateway(myIp, netmask) : null;
    }

    /** Привязывает TUN позже (tap-серверы шлют ifconfig ПОСЛЕ OPENTUN). */
    public synchronized void attachTun(ParcelFileDescriptor pfd) {
        if (tunPfd != null) {
            return;
        }
        tunPfd = pfd;
        tToTap = new Thread(this::toTapLoop, "tapshim-to");
        tToTap.setDaemon(true);
        tToTap.start();
        LogStore.add("TapShim", L10n.s(R.string.log_tap_01));
    }

    public boolean hasTun() {
        return tunPfd != null;
    }

    /**
     * Устанавливает сетевые параметры (вызывается из management при получении
     * IFCONFIG, если они не были известны при создании шима) и запускает
     * ARP-детект. Возвращает вычисленный адрес шлюза (или null).
     */
    public synchronized String setNetwork(String ip, String netmask) {
        if (myIp == null && ip != null) {
            myIp = ip;
            if (netmask != null && !netmask.isEmpty()) {
                try {
                    myMaskInt = ipToInt(netmask);
                } catch (Exception ignored) {
                }
            }
            gatewayIp = computeGateway(ip, netmask);
            detectStartedAt = System.currentTimeMillis();
            LogStore.add("TapShim", L10n.s(R.string.log_tap_02) + ip + L10n.s(R.string.log_tap_03) + netmask
                    + L10n.s(R.string.log_tap_04) + gatewayIp + " mac=" + macToString(myMac));
        }
        return gatewayIp;
    }

    /** Шлюз = адрес сети + 1 (по маске из PUSH). Не удалось — x.y.z.1 по /24. */
    private static String computeGateway(String ip, String mask) {
        try {
            int a = ipToInt(ip);
            int m = (mask != null && !mask.isEmpty()) ? ipToInt(mask) : 0xFFFFFF00;
            if (a != 0 && m != 0) {
                return intToIp((a & m) | 0x00000001);
            }
        } catch (Exception ignored) {
        }
        // fallback: первый адрес /24-подсети
        String[] p = ip.split("\\.");
        if (p.length == 4) {
            return p[0] + "." + p[1] + "." + p[2] + ".1";
        }
        return "172.16.0.1";
    }

    /** Момент старта ARP-детекта (после получения сети). */
    private volatile long detectStartedAt = 0;

    public String getGatewayIp() {
        return gatewayIp;
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    // ------------------------------------------------------------------
    // Запуск/остановка
    // ------------------------------------------------------------------

    public void start() {
        tFromTap = new Thread(this::fromTapLoop, "tapshim-from");
        tTimer = new Thread(this::timerLoop, "tapshim-timer");
        tFromTap.setDaemon(true);
        tTimer.setDaemon(true);
        // toTapLoop: если TUN уже привязан (IFCONFIG пришёл ДО OPENTUN — обычный
        // порядок на Android), стартуем сейчас; иначе — позже из attachTun().
        if (tunPfd != null) {
            tToTap = new Thread(this::toTapLoop, "tapshim-to");
            tToTap.setDaemon(true);
            tToTap.start();
        }
        tFromTap.start();
        tTimer.start();
        LogStore.add("TapShim", L10n.s(R.string.log_tap_05) + macToString(myMac)
                + (myIp != null ? " ip=" + myIp + L10n.s(R.string.log_tap_04) + gatewayIp : L10n.s(R.string.log_tap_06))
                + (tunPfd != null ? L10n.s(R.string.log_tap_07) : "") + L10n.s(R.string.log_tap_08));
    }

    public void stop() {
        running = false;
        for (Thread t : new Thread[]{tToTap, tFromTap, tTimer}) {
            if (t != null) {
                t.interrupt();
            }
        }
        try {
            Os.close(sockFd);
        } catch (Exception ignored) {
        }
    }

    // ------------------------------------------------------------------
    // Поток TUN → socketpair (IP-пакет → Ethernet-кадр)
    // ------------------------------------------------------------------

    private void toTapLoop() {
        byte[] buf = new byte[BUF_LEN];
        try {
            while (running) {
                int n = Os.read(tunPfd.getFileDescriptor(), buf, 0, BUF_LEN);
                if (n < 20) {
                    continue; // не IP-пакет
                }
                if (myIp == null || gatewayIp == null) {
                    // сеть ещё не известна — пакеты бесполезны (нет MAC-резолва)
                    statDropped++;
                    continue;
                }
                int dstIp = ((buf[16] & 0xFF) << 24) | ((buf[17] & 0xFF) << 16)
                        | ((buf[18] & 0xFF) << 8) | (buf[19] & 0xFF);
                // Next-hop как у роутера с default route через tap:
                //  - адресат в НАШЕЙ подсети  → ARP-резолв самого адресата;
                //  - любой другой (интернет) → MAC ШЛЮЗА. Android TUN отдаёт
                //    пакеты с финальным dst IP, и ARP-ить каждый внешний адрес
                //    бессмысленно — за них в tap-сети никто не отвечает.
                int myIpInt = ipToInt(myIp);
                boolean local = ((dstIp & myMaskInt) == (myIpInt & myMaskInt));
                int target = local ? dstIp : ipToInt(gatewayIp);
                byte[] mac = macByIp.get(target);
                if (mac == null) {
                    enqueuePending(target, copyOf(buf, n));
                    maybeSendArpRequest(target);
                    continue;
                }
                writeFrame(buf, n, mac, ET_IPV4);
                statIpToTap++;
            }
        } catch (ErrnoException e) {
            // EBADF после close() — штатная остановка
            if (running) {
                Log.e(TAG, "toTap read/write failed", e);
                LogStore.add("TapShim", L10n.s(R.string.log_tap_09) + e.getMessage());
            }
        } catch (Exception e) {
            if (running) {
                Log.e(TAG, "toTapLoop failed", e);
            }
        }
    }

    /** Кадр в пару: dst MAC, наш MAC, ethertype, полезная нагрузка (buf[0..n)). */
    private void writeFrame(byte[] ipPacket, int len, byte[] dstMac, int ethertype)
            throws ErrnoException, java.io.InterruptedIOException {
        byte[] frame = new byte[ETH_HLEN + len];
        System.arraycopy(dstMac, 0, frame, 0, 6);
        System.arraycopy(myMac, 0, frame, 6, 6);
        frame[12] = (byte) (ethertype >> 8);
        frame[13] = (byte) (ethertype & 0xFF);
        System.arraycopy(ipPacket, 0, frame, ETH_HLEN, len);
        Os.write(sockFd, frame, 0, frame.length);
    }

    private void enqueuePending(int dstIp, byte[] packet) {
        synchronized (pending) {
            ArrayDeque<byte[]> q = pending.get(dstIp);
            if (q == null) {
                q = new ArrayDeque<>();
                pending.put(dstIp, q);
            }
            while (q.size() >= MAX_PENDING_PER_DST) {
                q.pollFirst(); // дропаем старейший при переполнении
                statDropped++;
            }
            q.addLast(packet);
        }
    }

    private void maybeSendArpRequest(int dstIp) {
        Long last = lastArpAt.get(dstIp);
        long now = System.currentTimeMillis();
        if (last != null && now - last < ARP_PER_DST_INTERVAL_MS) {
            return;
        }
        lastArpAt.put(dstIp, now);
        sendArp(dstIp, true);
    }

    // ------------------------------------------------------------------
    // Поток socketpair → TUN (Ethernet-кадр → IP-пакет / ARP-обработка)
    // ------------------------------------------------------------------

    private void fromTapLoop() {
        byte[] buf = new byte[BUF_LEN];
        try {
            while (running) {
                int n = Os.read(sockFd, buf, 0, BUF_LEN);
                if (n < ETH_HLEN) {
                    continue;
                }
                int ethertype = ((buf[12] & 0xFF) << 8) | (buf[13] & 0xFF);
                if (ethertype == ET_IPV4) {
                    ParcelFileDescriptor tun = tunPfd;
                    if (tun == null) {
                        // TUN ещё не привязан (ifconfig не пришёл) — дропаем
                        statDropped++;
                        continue;
                    }
                    Os.write(tun.getFileDescriptor(), buf, ETH_HLEN, n - ETH_HLEN);
                    statIpFromTap++;
                } else if (ethertype == ET_ARP) {
                    handleArp(buf, n);
                }
                // прочие ethertype (IPv6 и т.п.) — молча игнорируем: TUN IPv4-only
            }
        } catch (ErrnoException e) {
            // EBADF после close() — штатная остановка
            if (running) {
                Log.e(TAG, "fromTap read/write failed", e);
                LogStore.add("TapShim", L10n.s(R.string.log_tap_10) + e.getMessage());
            }
        } catch (Exception e) {
            if (running) {
                Log.e(TAG, "fromTapLoop failed", e);
            }
        }
    }

    /**
     * ARP-кадр (payload с offset 14):
     * htype(2) ptype(2) hlen(1) plen(1) oper(2) sha(6) spa(4) tha(6) tpa(4)
     */
    private void handleArp(byte[] frame, int len) {
        if (len < ETH_HLEN + 28 || myIp == null) {
            return; // сеть ещё не известна — ARP-диалог не ведём
        }
        int off = ETH_HLEN;
        int oper = ((frame[off + 6] & 0xFF) << 8) | (frame[off + 7] & 0xFF);
        int spa = ((frame[off + 14] & 0xFF) << 24) | ((frame[off + 15] & 0xFF) << 16)
                | ((frame[off + 16] & 0xFF) << 8) | (frame[off + 17] & 0xFF);
        int tpa = ((frame[off + 24] & 0xFF) << 24) | ((frame[off + 25] & 0xFF) << 16)
                | ((frame[off + 26] & 0xFF) << 8) | (frame[off + 27] & 0xFF);
        int myIpInt = ipToInt(myIp);

        if (oper == 2) { // reply
            if (tpa == myIpInt) {
                byte[] sha = copyOf(frame, off + 8, 6);
                boolean isNew = macByIp.put(spa, sha) == null;
                statArpReplies++;
                flushPending(spa);
                if (isNew && spa == ipToInt(gatewayIp) && !confirmed) {
                    confirmed = true;
                    LogStore.add("TapShim", L10n.s(R.string.log_tap_11) + gatewayIp + " ("
                            + macToString(sha) + L10n.s(R.string.log_tap_12));
                    if (listener != null) {
                        listener.onTapConfirmed();
                    }
                } else if (isNew) {
                    LogStore.add("TapShim", "ARP: " + intToIp(spa) + " → " + macToString(sha));
                }
            }
        } else if (oper == 1) { // request
            if (tpa == myIpInt) {
                byte[] sha = copyOf(frame, off + 8, 6);
                sendArpReply(spa, sha);
            }
        }
    }

    /** Сбрасывает буфер пакетов, ждавших MAC этого dst. */
    private void flushPending(int dstIp) {
        byte[] mac = macByIp.get(dstIp);
        if (mac == null) {
            return;
        }
        byte[] pkt;
        while (true) {
            synchronized (pending) {
                ArrayDeque<byte[]> q = pending.get(dstIp);
                pkt = (q == null || q.isEmpty()) ? null : q.pollFirst();
                if (q != null && q.isEmpty()) {
                    pending.remove(dstIp);
                }
            }
            if (pkt == null) {
                return;
            }
            try {
                writeFrame(pkt, pkt.length, mac, ET_IPV4);
                statBufWait++;
            } catch (Exception e) {
                Log.e(TAG, "flushPending write failed", e);
                return;
            }
        }
    }

    // ------------------------------------------------------------------
    // ARP-кадры
    // ------------------------------------------------------------------

    /** ARP-запрос (broadcast): who-has dstIp tell myIp. */
    private void sendArp(int targetIp, boolean request) {
        sendArpFrame(targetIp, null, request);
    }

    /** ARP-ответ серверу: myIp is-at myMac. */
    private void sendArpReply(int targetIp, byte[] targetMac) {
        sendArpFrame(targetIp, targetMac, false);
    }

    private void sendArpFrame(int targetIp, byte[] targetMac, boolean request) {
        try {
            byte[] frame = new byte[ETH_HLEN + 28 + 18]; // +padding до 60 байт
            if (request) {
                // broadcast
                for (int i = 0; i < 6; i++) {
                    frame[i] = (byte) 0xFF;
                }
            } else if (targetMac != null) {
                System.arraycopy(targetMac, 0, frame, 0, 6);
            }
            System.arraycopy(myMac, 0, frame, 6, 6);
            frame[12] = (byte) (ET_ARP >> 8);
            frame[13] = (byte) (ET_ARP & 0xFF);
            int o = ETH_HLEN;
            frame[o] = 0; frame[o + 1] = 1;          // htype = ethernet
            frame[o + 2] = 0x08; frame[o + 3] = 0;   // ptype = IPv4
            frame[o + 4] = 6;                        // hlen
            frame[o + 5] = 4;                        // plen
            frame[o + 6] = 0;
            frame[o + 7] = (byte) (request ? 1 : 2); // oper
            System.arraycopy(myMac, 0, frame, o + 8, 6);  // sha
            int myIpInt = ipToInt(myIp);
            frame[o + 14] = (byte) (myIpInt >> 24);
            frame[o + 15] = (byte) (myIpInt >> 16);
            frame[o + 16] = (byte) (myIpInt >> 8);
            frame[o + 17] = (byte) myIpInt;                // spa
            // tha (o+18..o+23) = нули для запроса, dstMac для ответа
            if (!request && targetMac != null) {
                System.arraycopy(targetMac, 0, frame, o + 18, 6);
            }
            frame[o + 24] = (byte) (targetIp >> 24);
            frame[o + 25] = (byte) (targetIp >> 16);
            frame[o + 26] = (byte) (targetIp >> 8);
            frame[o + 27] = (byte) targetIp;               // tpa
            Os.write(sockFd, frame, 0, frame.length);
        } catch (Exception e) {
            if (running) {
                Log.e(TAG, "sendArp failed", e);
            }
        }
    }

    // ------------------------------------------------------------------
    // Таймер: ретрансляция ARP-детекта + таймаут
    // ------------------------------------------------------------------

    private void timerLoop() {
        long t0 = System.currentTimeMillis();
        long lastRetry = 0;
        try {
            while (running && !confirmed) {
                Thread.sleep(300);
                long now = System.currentTimeMillis();
                if (gatewayIp == null) {
                    // Сеть ещё неизвестна (IFCONFIG не пришёл). Даём 15с:
                    // tap-серверы шлют ifconfig после OPENTUN, но не бесконечно.
                    if (now - t0 > NO_NETWORK_TIMEOUT_MS) {
                        if (!failedReported && listener != null) {
                            failedReported = true;
                            LogStore.add("TapShim", L10n.s(R.string.log_tap_13));
                            listener.onTapFailed();
                        }
                        return;
                    }
                    continue;
                }
                if (now - lastRetry >= ARP_RETRY_MS) {
                    lastRetry = now;
                    sendArp(ipToInt(gatewayIp), true); // ретранслируем запрос шлюзу
                }
                if (detectStartedAt > 0 && now - detectStartedAt > DETECT_TIMEOUT_MS) {
                    if (!failedReported && listener != null) {
                        failedReported = true;
                        LogStore.add("TapShim", L10n.s(R.string.log_tap_11) + gatewayIp
                                + L10n.s(R.string.log_tap_14) + (DETECT_TIMEOUT_MS / 1000)
                                + L10n.s(R.string.log_tap_15));
                        listener.onTapFailed();
                    }
                    return;
                }
            }
        } catch (InterruptedException e) {
            // штатная остановка
        }
    }

    // ------------------------------------------------------------------
    // Утилиты
    // ------------------------------------------------------------------

    private static byte[] copyOf(byte[] src, int len) {
        byte[] out = new byte[len];
        System.arraycopy(src, 0, out, 0, len);
        return out;
    }

    private static byte[] copyOf(byte[] src, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(src, off, out, 0, len);
        return out;
    }

    private static int ipToInt(String ip) {
        String[] p = ip.split("\\.");
        if (p.length != 4) {
            return 0;
        }
        return ((Integer.parseInt(p[0]) & 0xFF) << 24)
                | ((Integer.parseInt(p[1]) & 0xFF) << 16)
                | ((Integer.parseInt(p[2]) & 0xFF) << 8)
                | (Integer.parseInt(p[3]) & 0xFF);
    }

    private static String intToIp(int v) {
        return ((v >> 24) & 0xFF) + "." + ((v >> 16) & 0xFF) + "."
                + ((v >> 8) & 0xFF) + "." + (v & 0xFF);
    }

    private static String macToString(byte[] mac) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(String.format("%02x", mac[i] & 0xFF));
        }
        return sb.toString();
    }
}
