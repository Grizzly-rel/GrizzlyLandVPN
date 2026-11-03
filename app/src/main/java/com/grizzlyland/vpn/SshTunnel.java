package com.grizzlyland.vpn;

import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Logger;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SocketFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.function.IntConsumer;

/**
 * SSH-сессия с локальным TCP-форвардом (аналог {@code ssh -L localPort:target:port}).
 *
 * Транспорт режима «OpenVPN через SSH» ({@link ConfigManager#MODE_OVPN_SSH}):
 * нативный openvpn подключается к 127.0.0.1:localPort на телефоне, SshTunnel
 * ретранслирует эти соединения через SSH-сервер на targetHost:targetPort
 * (обычно 127.0.0.1:1194 — OpenVPN-сервер на самой SSH-машине).
 *
 * ВАЖНО: SSH форвардит только TCP — OpenVPN-сервер обязан слушать proto tcp.
 *
 * Отказоустойчивость: супервизорный поток держит сессию, при разрыве переподключается
 * БЕСКОНЕЧНО (backoff 2/4/…30с — VPN переживает любую по длительности пропажу сети
 * и смену Wi-Fi↔мобильная) и заново поднимает форвард на ТОМ ЖЕ локальном порту —
 * openvpn в это время просто ретраит connect (см. {@link OpenVpnConfigBuilder#patchSshLocal})
 * и подцепляется сам, без перезапуска сервиса. Финальный отказ — только для ПОСТОЯННЫХ
 * ошибок, где ретраи бессмысленны: неверный логин/пароль/ключ или смена хост-ключа.
 *
 * Хост-ключ пинится по TOFU: первый отпечаток сохраняется в настройках, при смене —
 * жёсткий отказ (анти-MITM; сбросить можно в настройках SSH).
 *
 * Все исходящие сокеты сессии проходят через protect(fd) — иначе SSH-трафик
 * уйдёт в собственный TUN приложения и зациклится.
 */
public class SshTunnel {

    public interface Listener {
        /** Форвард готов: openvpn может стартовать (первый раз) / уже работает. */
        void onReady(int localPort);

        /** Постоянная ошибка (auth/отпечаток хоста) — ретраи бессмысленны, сервис останавливает VPN. */
        void onFinalFailure(String reason);
    }

    /** Постоянная ошибка (аутентификация, битый ключ, смена хост-ключа) — не ретраится. */
    private static class PermanentException extends IOException {
        PermanentException(String message) {
            super(message);
        }
    }

    private static final String TAG = "SshTunnel";
    private static final int CONNECT_TIMEOUT_MS = 15000;
    /** SSH keepalive: компромисс между экономией радио/батареи и скоростью детекта смерти сети. */
    private static final int SERVER_ALIVE_INTERVAL_MS = 45000;
    /** Период опроса состояния сессии супервизором (пробуждения CPU реже — экономия батареи). */
    private static final int SESSION_POLL_MS = 10000;

    static {
        // Диагностику jsch (KEX/auth/ошибки) — в общий журнал.
        JSch.setLogger(new Logger() {
            @Override
            public boolean isEnabled(int level) {
                return level >= Logger.INFO;
            }

            @Override
            public void log(int level, String message) {
                LogStore.add("SSH", "jsch: " + message);
            }
        });
    }

    private final ConfigManager config;
    private final IntConsumer protectFd;
    private final Listener listener;

    private final String host;
    private final int port;
    private final String user;
    private final boolean keyAuth;
    private final String password;
    private final String keyPem;
    private final String keyPass;
    private final String targetHost;
    private final int targetPort;
    private final int wantLocalPort;

    private volatile Session session;
    private volatile boolean running = false;
    private volatile boolean readyReported = false;
    private Thread supervisor;

    public SshTunnel(ConfigManager config, IntConsumer protectFd, Listener listener) {
        this.config = config;
        this.protectFd = protectFd;
        this.listener = listener;
        this.host = config.getSshHost();
        this.port = config.getSshPort();
        this.user = config.getSshUser();
        this.keyAuth = ConfigManager.SSH_AUTH_KEY.equals(config.getSshAuth());
        this.password = config.getSshPassword();
        this.keyPem = config.getSshKey();
        this.keyPass = config.getSshKeyPass();
        String t = config.getSshTarget();
        int colon = t.lastIndexOf(':');
        this.targetHost = colon > 0 ? t.substring(0, colon).trim() : "127.0.0.1";
        int tp = 1194;
        try {
            if (colon > 0 && colon < t.length() - 1) {
                tp = Integer.parseInt(t.substring(colon + 1).trim());
            }
        } catch (NumberFormatException ignored) {
        }
        this.targetPort = tp;
        this.wantLocalPort = config.getSshLocalPort();
    }

    /** Запускает супервизорный поток (идемпотентно). */
    public synchronized void start() {
        if (running) {
            return;
        }
        running = true;
        readyReported = false;
        supervisor = new Thread(this::runSupervisor, "SshTunnel");
        supervisor.start();
    }

    /** Полная остановка: сессия рвётся, супервизор завершается. */
    public void stop() {
        running = false;
        closeSession();
        Thread t = supervisor;
        if (t != null) {
            t.interrupt();
        }
    }

    private void runSupervisor() {
        int fails = 0;
        while (running) {
            try {
                int bound = connectSession();
                fails = 0;
                if (!readyReported) {
                    readyReported = true;
                    listener.onReady(bound);
                } else {
                    LogStore.add("SSH", L10n.s(R.string.log_ssh_01) + bound);
                }
                // Ждём разрыва сессии (ServerAliveInterval сам её закроет при смерти сети).
                Session s = session;
                while (running && s != null && s.isConnected()) {
                    Thread.sleep(SESSION_POLL_MS);
                }
                if (!running) {
                    break;
                }
                LogStore.add("SSH", L10n.s(R.string.log_ssh_02));
            } catch (PermanentException pe) {
                // Ретраить бессмысленно: неверный логин/пароль/ключ или смена хост-ключа.
                LogStore.add("SSH", pe.getMessage());
                listener.onFinalFailure(pe.getMessage());
                return;
            } catch (InterruptedException ie) {
                break;
            } catch (Exception e) {
                if (!running) {
                    break;
                }
                LogStore.add("SSH", L10n.s(R.string.log_ssh_03) + e);
            }
            // Сетевые ошибки ретраятся бесконечно: пропажа интернета, смена
            // Wi-Fi↔мобильная, недоступность сервера — рано или поздно сеть вернётся.
            fails++;
            long wait = Math.min(30000L, 2000L * fails);
            LogStore.add("SSH", L10n.s(R.string.log_ssh_04) + (wait / 1000) + L10n.s(R.string.log_ssh_05) + fails + ")");
            try {
                Thread.sleep(wait);
            } catch (InterruptedException ie) {
                break;
            }
        }
    }

    /** Поднимает сессию и форвард; возвращает фактический локальный порт. */
    private int connectSession() throws Exception {
        closeSession();
        JSch jsch = new JSch();
        if (keyAuth) {
            byte[] pass = (keyPass == null || keyPass.isEmpty()) ? null : keyPass.getBytes("UTF-8");
            try {
                jsch.addIdentity("grizzly_ssh_key", keyPem.getBytes("UTF-8"), null, pass);
            } catch (JSchException e) {
                throw new PermanentException(L10n.s(R.string.log_ssh_06)
                        + L10n.s(R.string.log_ssh_07) + e.getMessage());
            }
            LogStore.add("SSH", L10n.s(R.string.log_ssh_08));
        }
        Session s = jsch.getSession(user, host, port);
        s.setSocketFactory(new ProtectedSocketFactory());
        s.setConfig("StrictHostKeyChecking", "no"); // пин хост-ключа делаем сами (TOFU) ниже
        s.setServerAliveInterval(SERVER_ALIVE_INTERVAL_MS);
        s.setServerAliveCountMax(3);
        if (!keyAuth) {
            s.setPassword(password);
            s.setConfig("PreferredAuthentications", "password,keyboard-interactive");
        } else {
            s.setConfig("PreferredAuthentications", "publickey,password");
        }
        LogStore.add("SSH", L10n.s(R.string.log_ssh_09) + user + "@" + host + ":" + port + " ...");
        try {
            s.connect(CONNECT_TIMEOUT_MS);
        } catch (JSchException e) {
            String m = e.getMessage() == null ? "" : e.getMessage();
            if (m.contains("Auth fail") || m.contains("Auth cancel") || m.contains("AUTH fail")) {
                throw new PermanentException(L10n.s(R.string.log_ssh_10) + user + "@"
                        + host + ":" + port + L10n.s(R.string.log_ssh_11));
            }
            throw e; // сетевые/протокольные — ретраятся супервизором
        }

        // TOFU-пин хост-ключа: первый раз сохраняем, дальше сверяем.
        HostKey hk = s.getHostKey();
        String fp = hk == null ? "" : hk.getFingerPrint(jsch);
        String stored = config.getSshHostKeyFp();
        if (stored == null || stored.trim().isEmpty()) {
            config.setSshHostKeyFp(fp);
            LogStore.add("SSH", L10n.s(R.string.log_ssh_12) + fp);
        } else if (!stored.equals(fp)) {
            s.disconnect();
            throw new PermanentException(L10n.s(R.string.log_ssh_13) + stored
                    + L10n.s(R.string.log_ssh_14) + fp + L10n.s(R.string.log_ssh_15)
                    + L10n.s(R.string.log_ssh_16));
        }

        // Локальный форвард; если порт занят — пробуем несколько следующих.
        int bound = -1;
        Exception last = null;
        for (int p = wantLocalPort; p <= wantLocalPort + 5 && bound < 0; p++) {
            try {
                bound = s.setPortForwardingL("127.0.0.1", p, targetHost, targetPort);
            } catch (Exception e) {
                last = e;
            }
        }
        if (bound < 0) {
            s.disconnect();
            throw new IOException(L10n.s(R.string.log_ssh_17)
                    + wantLocalPort + "-" + (wantLocalPort + 5) + ": " + last);
        }
        session = s;
        LogStore.add("SSH", L10n.s(R.string.log_ssh_18) + bound
                + " → " + targetHost + ":" + targetPort);
        return bound;
    }

    private void closeSession() {
        Session s = session;
        session = null;
        if (s != null) {
            try {
                s.disconnect();
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Фабрика сокетов jsch с protect(): каждый исходящий сокет сессии выводится
     * из-под маршрутизации собственного VPN, иначе трафик зациклится в TUN.
     */
    private class ProtectedSocketFactory implements SocketFactory {
        @Override
        public Socket createSocket(String h, int p) throws IOException {
            Socket s = new Socket();
            try {
                s.connect(new InetSocketAddress(h, p), CONNECT_TIMEOUT_MS);
                try {
                    ParcelFileDescriptor pfd = ParcelFileDescriptor.fromSocket(s);
                    int fd = pfd.detachFd();
                    if (protectFd != null) {
                        protectFd.accept(fd);
                    }
                } catch (Throwable t) {
                    LogStore.add("SSH", L10n.s(R.string.log_ssh_19) + t);
                }
                return s;
            } catch (IOException e) {
                try {
                    s.close();
                } catch (IOException ignored) {
                }
                throw e;
            }
        }

        @Override
        public InputStream getInputStream(Socket s) throws IOException {
            return s.getInputStream();
        }

        @Override
        public OutputStream getOutputStream(Socket s) throws IOException {
            return s.getOutputStream();
        }
    }
}
