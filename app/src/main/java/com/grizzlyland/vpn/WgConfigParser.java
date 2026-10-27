package com.grizzlyland.vpn;

import java.util.ArrayList;
import java.util.List;

/**
 * Парсер wg-quick конфига WireGuard (INI-подобный текст) для режима WireGuard.
 *
 * Разбирает [Interface] (PrivateKey, ListenPort, Address, DNS, MTU) и секции
 * [Peer] (PublicKey, PresharedKey, Endpoint, AllowedIPs, PersistentKeepalive),
 * строит UAPI-строку для движка wireguard-go (private_key=..., public_key=...,
 * endpoint=..., allowed_ip=...), а также списки адресов/DNS/маршрутов для
 * VpnService.Builder. Имена ключей нормализуются как в wg-quick (нижний регистр,
 * без дефисов/подчёркиваний) — «PersistentKeepalive» и «persistent-keepalive»
 * равнозначны.
 */
public class WgConfigParser {

    /** Разобранный конфиг. */
    public static class WgConfig {
        /** true, если есть PrivateKey и хотя бы один peer с PublicKey. */
        public boolean valid = false;
        /** UAPI-строка для движка (wgengine.turnOn). */
        public String ipc = "";
        /** Приватный ключ интерфейса в hex (для xray wireguard-outbound). */
        public String privateKeyHex = "";
        /** Разобранные peer в структурном виде (для xray wireguard-outbound). */
        public final List<PeerInfo> peerList = new ArrayList<>();
        /** Адреса интерфейса (cidr, напр. "10.8.7.2/24"). */
        public List<String> addresses = new ArrayList<>();
        /** DNS из конфига (как есть; фильтрацию IP делает билдер). */
        public List<String> dns = new ArrayList<>();
        /** AllowedIPs всех peer (cidr) — маршруты VpnService. */
        public List<String> allowedIps = new ArrayList<>();
        /** MTU из конфига (0 — не задан). */
        public int mtu = 0;
        /** Endpoint первого peer (host:port) — только для метки в UI/логе. */
        public String endpointForLog = "";
        /** Число разобранных peer. */
        public int peers = 0;
        /** Ошибка разбора/конвертации (пусто — всё хорошо). */
        public String parseError = "";
    }

    /** Один peer в структурном виде (ключи уже в hex). */
    public static class PeerInfo {
        public String publicKeyHex = "";
        public String pskHex = "";
        public String endpoint = "";
        public String keepalive = "";
        public final List<String> allowed = new ArrayList<>();
    }

    /** Накопитель текущей peer-секции (мутабельный холдер вместо inner class). */
    private static class PeerState {
        String pub, psk, endpoint, keepalive;
        final List<String> allowed = new ArrayList<>();

        void reset() {
            pub = null;
            psk = null;
            endpoint = null;
            keepalive = null;
            allowed.clear();
        }
    }

    /** Дописывает накопленный peer в UAPI-строку (peer без PublicKey игнорируется). */
    private static void flushPeer(StringBuilder ipc, WgConfig c, PeerState ps) {
        if (ps.pub == null || ps.pub.isEmpty()) {
            ps.reset();
            return;
        }
        ipc.append("public_key=").append(ps.pub).append('\n');
        if (ps.psk != null && !ps.psk.isEmpty()) {
            ipc.append("pre_shared_key=").append(ps.psk).append('\n');
        }
        if (ps.endpoint != null && !ps.endpoint.isEmpty()) {
            ipc.append("endpoint=").append(ps.endpoint).append('\n');
        }
        for (String cidr : ps.allowed) {
            ipc.append("allowed_ip=").append(cidr).append('\n');
        }
        if (ps.keepalive != null && !ps.keepalive.isEmpty()) {
            ipc.append("persistent_keepalive_interval=").append(ps.keepalive).append('\n');
        }
        if (c.endpointForLog.isEmpty() && ps.endpoint != null) {
            c.endpointForLog = ps.endpoint;
        }
        PeerInfo info = new PeerInfo();
        info.publicKeyHex = ps.pub;
        info.pskHex = ps.psk == null ? "" : ps.psk;
        info.endpoint = ps.endpoint == null ? "" : ps.endpoint;
        info.keepalive = ps.keepalive == null ? "" : ps.keepalive;
        info.allowed.addAll(ps.allowed);
        c.peerList.add(info);
        c.peers++;
        ps.reset();
    }

    public static WgConfig parse(String raw) {
        WgConfig c = new WgConfig();
        if (raw == null || raw.trim().isEmpty()) {
            return c;
        }

        final StringBuilder ipc = new StringBuilder();
        String priv = null, listenPort = null;
        PeerState ps = new PeerState();

        String section = "";
        for (String rawLine : raw.split("\n")) {
            String line = rawLine.trim();
            // Инлайн-комментарии: «Endpoint = host port # Внешний IP сервера».
            // '#' не встречается ни в одном значении wg-quick (base64/hex/IP/
            // порт/CIDR), поэтому срезаем всё от первого '#' — иначе нормализация
            // «host port»→«host:port» превращает хвост комментария в мусорный
            // порт и движок падает на «invalid port».
            int hash = line.indexOf('#');
            if (hash >= 0) {
                line = line.substring(0, hash).trim();
            }
            if (line.isEmpty() || line.startsWith(";")) {
                continue;
            }
            if (line.startsWith("[")) {
                if (section.equals("peer")) {
                    flushPeer(ipc, c, ps);
                }
                int close = line.indexOf(']');
                section = close > 1 ? line.substring(1, close).trim().toLowerCase() : "";
                continue;
            }
            int eq = line.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String key = normalize(line.substring(0, eq));
            String val = line.substring(eq + 1).trim();
            if (val.isEmpty()) {
                continue;
            }
            if (section.equals("interface")) {
                switch (key) {
                    case "privatekey":
                        // wg-quick хранит ключи в base64, UAPI wireguard-go ждёт hex.
                        try {
                            priv = b64ToHex(val);
                        } catch (IllegalArgumentException e) {
                            c.parseError = "PrivateKey: " + e.getMessage();
                        }
                        break;
                    case "listenport": listenPort = val; break;
                    case "address": addCsv(c.addresses, val); break;
                    case "dns": addCsv(c.dns, val); break;
                    case "mtu":
                        try {
                            c.mtu = Integer.parseInt(val);
                        } catch (NumberFormatException ignored) {
                        }
                        break;
                    default: break; // table, saveconfig, preup/postup и пр. — игнорируем
                }
            } else if (section.equals("peer")) {
                switch (key) {
                    case "publickey":
                        try {
                            ps.pub = b64ToHex(val);
                        } catch (IllegalArgumentException e) {
                            c.parseError = "Peer PublicKey: " + e.getMessage();
                        }
                        break;
                    case "presharedkey":
                        try {
                            ps.psk = b64ToHex(val);
                        } catch (IllegalArgumentException e) {
                            c.parseError = "PresharedKey: " + e.getMessage();
                        }
                        break;
                    case "endpoint":
                        // Некоторые генераторы пишут «host port» через пробел, а не
                        // «host:port» (формат wg/UAPI). Нормализуем: первый пробел
                        // (и всю группу) заменяем на двоеточие; скобочную IPv6-форму
                        // это не ломает ([v6] port → [v6]:port).
                        ps.endpoint = val.trim().replaceAll("\\s+", ":");
                        break;
                    case "allowedips": addCsv(ps.allowed, val); break;
                    case "persistentkeepalive": ps.keepalive = val; break;
                    default: break;
                }
            }
        }
        flushPeer(ipc, c, ps);

        c.valid = c.parseError.isEmpty() && priv != null && !priv.isEmpty() && ipc.length() > 0;
        if (c.valid) {
            c.privateKeyHex = priv;
            StringBuilder sb = new StringBuilder("private_key=").append(priv).append('\n');
            if (listenPort != null && !listenPort.isEmpty()) {
                sb.append("listen_port=").append(listenPort).append('\n');
            }
            sb.append(ipc);
            c.ipc = sb.toString();
        }
        return c;
    }

    /** Нормализация имени ключа как в wg-quick: нижний регистр, без '-' и '_'. */
    private static String normalize(String k) {
        return k.trim().toLowerCase().replace("-", "").replace("_", "");
    }

    /**
     * base64 (как в wg-quick) → hex (как ждёт UAPI wireguard-go).
     * Ключ WireGuard — 32 байта; base64-строка — 44 символа с '=' в конце.
     */
    private static String b64ToHex(String b64) {
        byte[] raw = android.util.Base64.decode(b64.trim(), android.util.Base64.DEFAULT);
        if (raw.length != 32) {
            throw new IllegalArgumentException(L10n.s(R.string.log_awgp_05)
                    + raw.length);
        }
        StringBuilder sb = new StringBuilder(64);
        for (byte b : raw) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /** Разбивает значение по запятым и добавляет элементы по одному. */
    private static void addCsv(List<String> list, String csv) {
        for (String item : csv.split(",")) {
            String v = item.trim();
            if (!v.isEmpty()) {
                list.add(v);
            }
        }
    }
}
