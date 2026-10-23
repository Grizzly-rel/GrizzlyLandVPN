package com.grizzlyland.vpn;

import java.util.ArrayList;
import java.util.List;

/**
 * Парсер wg-quick конфига AmneziaWG (INI-подобный текст) для режима
 * AmneziaWG (отдельный режим поверх движка amneziawg-go).
 *
 * Разбирает [Interface] (PrivateKey, ListenPort, Address, DNS, MTU и
 * параметры обфускации Jc/Jmin/Jmax/S1/S2/H1..H4) и секции [Peer]
 * (PublicKey, PresharedKey, Endpoint, AllowedIPs, PersistentKeepalive),
 * строит UAPI-строку для движка amneziawg-go. Формат конфига — надмножество
 * wg-quick: обычные WireGuard-конфиги тоже принимаются, недостающие параметры
 * обфускации заменяются документированными дефолтами AmneziaWG
 * (Jc=4, Jmin=40, Jmax=70, S1=15, S2=68, H1=1, H2=2, H3=3, H4=4).
 * Движок дефолтов НЕ применяет (поля нулевые) — параметры всегда отдаём явно.
 *
 * Имена ключей нормализуются как в wg-quick (нижний регистр, без
 * дефисов/подчёркиваний): «PersistentKeepalive», «persistent-keepalive» и
 * «persistent_keepalive» равнозначны; то же для «JC»/«Jc»/«j_min».
 */
public class AwgConfigParser {

    /** Разобранный конфиг. */
    public static class AwgConfig {
        /** true, если есть PrivateKey и хотя бы один peer с PublicKey. */
        public boolean valid = false;
        /** UAPI-строка для движка (Libxray.awgTurnOn). */
        public String ipc = "";
        /** Адреса интерфейса (cidr, напр. "10.8.9.3/24"). */
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
        /** Параметры обфускации после применения дефолтов (для журнала). */
        public String jc = "", jmin = "", jmax = "", s1 = "", s2 = "";
        public String h1 = "", h2 = "", h3 = "", h4 = "";
    }

    /** Накопитель текущей peer-секции. */
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

    /** Документированные дефолты AmneziaWG (когда параметра нет в конфиге). */
    private static final String DEF_JC = "4", DEF_JMIN = "40", DEF_JMAX = "70";
    private static final String DEF_S1 = "15", DEF_S2 = "68";
    private static final String DEF_H1 = "1", DEF_H2 = "2", DEF_H3 = "3", DEF_H4 = "4";

    /** Дописывает накопленный peer в UAPI-строку (peer без PublicKey игнорируется). */
    private static void flushPeer(StringBuilder ipc, AwgConfig c, PeerState ps) {
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
        c.peers++;
        ps.reset();
    }

    public static AwgConfig parse(String raw) {
        AwgConfig c = new AwgConfig();
        if (raw == null || raw.trim().isEmpty()) {
            return c;
        }

        final StringBuilder ipc = new StringBuilder();
        String priv = null, listenPort = null;
        // Параметры обфускации: null = не задан в конфиге (будет дефолт).
        String jc = null, jmin = null, jmax = null, s1 = null, s2 = null;
        String h1 = null, h2 = null, h3 = null, h4 = null;
        PeerState ps = new PeerState();

        String section = "";
        for (String rawLine : raw.split("\n")) {
            String line = rawLine.trim();
            // Инлайн-комментарии: «Endpoint = host port # Внешний IP сервера».
            // '#' не встречается ни в одном значении wg-quick, срезаем всё от него.
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
                        // wg-quick хранит ключи в base64, UAPI движка ждёт hex.
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
                    case "jc": jc = val; break;
                    case "jmin": jmin = val; break;
                    case "jmax": jmax = val; break;
                    case "s1": s1 = val; break;
                    case "s2": s2 = val; break;
                    case "h1": h1 = val; break;
                    case "h2": h2 = val; break;
                    case "h3": h3 = val; break;
                    case "h4": h4 = val; break;
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
                        // «host:port» (формат wg/UAPI). Нормализуем: первую группу
                        // пробелов заменяем на двоеточие; скобочную IPv6-форму это
                        // не ломает ([v6] port → [v6]:port).
                        ps.endpoint = val.trim().replaceAll("\\s+", ":");
                        break;
                    case "allowedips": addCsv(ps.allowed, val); break;
                    case "persistentkeepalive": ps.keepalive = val; break;
                    default: break;
                }
            }
        }
        flushPeer(ipc, c, ps);

        // Параметры обфускации: из конфига или дефолты; проверяем формат —
        // движок падает на IpcSet с невалидным числом, лучше поймать раньше.
        c.jc = orDefault(jc, DEF_JC);
        c.jmin = orDefault(jmin, DEF_JMIN);
        c.jmax = orDefault(jmax, DEF_JMAX);
        c.s1 = orDefault(s1, DEF_S1);
        c.s2 = orDefault(s2, DEF_S2);
        c.h1 = orDefault(h1, DEF_H1);
        c.h2 = orDefault(h2, DEF_H2);
        c.h3 = orDefault(h3, DEF_H3);
        c.h4 = orDefault(h4, DEF_H4);
        String obfErr = validateObfuscation(c);
        if (obfErr != null && c.parseError.isEmpty()) {
            c.parseError = obfErr;
        }

        c.valid = c.parseError.isEmpty() && priv != null && !priv.isEmpty() && ipc.length() > 0;
        if (c.valid) {
            StringBuilder sb = new StringBuilder("private_key=").append(priv).append('\n');
            if (listenPort != null && !listenPort.isEmpty()) {
                sb.append("listen_port=").append(listenPort).append('\n');
            }
            // Параметры обфускации — всегда явно (движок дефолтов не имеет).
            sb.append("jc=").append(c.jc).append('\n')
              .append("jmin=").append(c.jmin).append('\n')
              .append("jmax=").append(c.jmax).append('\n')
              .append("s1=").append(c.s1).append('\n')
              .append("s2=").append(c.s2).append('\n')
              .append("h1=").append(c.h1).append('\n')
              .append("h2=").append(c.h2).append('\n')
              .append("h3=").append(c.h3).append('\n')
              .append("h4=").append(c.h4).append('\n');
            sb.append(ipc);
            c.ipc = sb.toString();
        }
        return c;
    }

    /** Возвращает value, если задан, иначе default. */
    private static String orDefault(String value, String def) {
        return (value == null || value.trim().isEmpty()) ? def : value.trim();
    }

    /**
     * Проверка параметров обфускации: jc/jmin/jmax/s1/s2 — беззнаковые 32-бит,
     * h1..h4 — беззнаковые 32-бит (десятичные); jmin ≤ jmax.
     * @return текст ошибки или null.
     */
    private static String validateObfuscation(AwgConfig c) {
        String[] names = {"jc", "jmin", "jmax", "s1", "s2"};
        String[] vals = {c.jc, c.jmin, c.jmax, c.s1, c.s2};
        for (int i = 0; i < names.length; i++) {
            if (!validU32(vals[i])) {
                return "Параметр обфускации " + names[i] + "=\"" + vals[i]
                        + "\" — не число 0..4294967295";
            }
        }
        String[] hn = {"h1", "h2", "h3", "h4"};
        String[] hv = {c.h1, c.h2, c.h3, c.h4};
        for (int i = 0; i < hn.length; i++) {
            if (!validU32(hv[i])) {
                return "Параметр обфускации " + hn[i] + "=\"" + hv[i]
                        + "\" — не число 0..4294967295";
            }
        }
        try {
            long jmin = Long.parseLong(c.jmin);
            long jmax = Long.parseLong(c.jmax);
            if (jmin > jmax) {
                return "Jmin (" + c.jmin + ") больше Jmax (" + c.jmax + ")";
            }
        } catch (NumberFormatException ignored) {
        }
        return null;
    }

    /** Десятичное число 0..4294967295 (u32, как ждёт UAPI amneziawg-go). */
    private static boolean validU32(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        try {
            long v = Long.parseLong(s);
            return v >= 0 && v <= 4294967295L;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /** Нормализация имени ключа как в wg-quick: нижний регистр, без '-' и '_'. */
    private static String normalize(String k) {
        return k.trim().toLowerCase().replace("-", "").replace("_", "");
    }

    /**
     * Краткая сводка обфускации для UI: «дефолт», если все параметры равны
     * документированным дефолтам (конфиг без обфускации), иначе — значения.
     */
    public static String obfuscationSummary(AwgConfig c) {
        boolean def = c.jc.equals(DEF_JC) && c.jmin.equals(DEF_JMIN)
                && c.jmax.equals(DEF_JMAX) && c.s1.equals(DEF_S1) && c.s2.equals(DEF_S2)
                && c.h1.equals(DEF_H1) && c.h2.equals(DEF_H2)
                && c.h3.equals(DEF_H3) && c.h4.equals(DEF_H4);
        if (def) {
            return "дефолт (без обфускации)";
        }
        return "jc=" + c.jc + " jmin=" + c.jmin + " jmax=" + c.jmax
                + " s1=" + c.s1 + " s2=" + c.s2
                + " h1=" + c.h1 + " h2=" + c.h2 + " h3=" + c.h3 + " h4=" + c.h4;
    }

    /**
     * base64 (как в wg-quick) → hex (как ждёт UAPI движка).
     * Ключ — 32 байта; base64-строка — 44 символа с '=' в конце.
     */
    private static String b64ToHex(String b64) {
        byte[] raw = android.util.Base64.decode(b64.trim(), android.util.Base64.DEFAULT);
        if (raw.length != 32) {
            throw new IllegalArgumentException("ключ должен быть 32 байта, получено "
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
