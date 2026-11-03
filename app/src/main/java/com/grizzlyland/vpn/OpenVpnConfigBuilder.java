package com.grizzlyland.vpn;

import android.util.Base64;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Генерирует конфигурацию OpenVPN-клиента (.ovpn) из настроек приложения.
 *
 * Два режима:
 *  - статический ключ (--secret): используется, когда задан {@code ovpn_static_key}
 *    (как в тестовом сервере /opt/ovpn-test, cipher none / auth none).
 *  - PKI (ca/cert/key): классический сертификатный режим.
 *
 * В режиме Xray+OpenVPN конфиг дополнительно проксируется через локальный
 * SOCKS Xray (socks-proxy), чтобы вложенный OpenVPN-туннель шёл поверх Xray.
 */
public class OpenVpnConfigBuilder {

    /**
     * Собирает конфиг клиента.
     *
     * @param c           настройки приложения
     * @param keyPath     абсолютный путь к файлу статического ключа (если static key)
     * @param caPath      путь к файлу CA (для PKI)
     * @param certPath    путь к файлу сертификата (для PKI)
     * @param keyFilePath путь к файлу приватного ключа (для PKI)
     * @param socksProxy  строка вида "127.0.0.1:10808" для проксирования через Xray SOCKS,
     *                    или null, если прокси не нужен (режим «только OpenVPN»)
     */
    public static String build(ConfigManager c,
                               String keyPath, String caPath, String certPath, String keyFilePath,
                               String socksProxy) {
        StringBuilder sb = new StringBuilder();

        // Директива "client" подразумевает TLS-клиент и конфликтует с "--secret"
        // (статический ключ), поэтому добавляется только для PKI-режима.
        String staticKey = c.getOvpnStaticKey();
        boolean isStaticKey = staticKey != null && !staticKey.trim().isEmpty();

        if (!isStaticKey) {
            sb.append("client\n");
        }
        sb.append("dev ").append(c.getOvpnDev()).append("\n");
        String proto = c.getOvpnProtocol();
        // Для клиента TCP-режим должен быть явно "tcp-client" (иначе openvpn ругается).
        if ("tcp".equalsIgnoreCase(proto)) {
            proto = "tcp-client";
        }
        sb.append("proto ").append(proto).append("\n");
        sb.append("remote ").append(c.getOvpnRemoteHost()).append(" ")
                .append(c.getOvpnRemotePort()).append("\n");
        appendAuthUserPass(sb, c);
        appendCommon(sb, c);

        // Проксирование через локальный SOCKS Xray (режим Xray+OpenVPN).
        // Формат директивы: "socks-proxy <host> <port>" (не host:port).
        if (socksProxy != null && !socksProxy.isEmpty()) {
            String[] sp = socksProxy.split(":");
            if (sp.length == 2) {
                sb.append("socks-proxy ").append(sp[0].trim()).append(" ")
                        .append(sp[1].trim()).append("\n");
            } else {
                sb.append("socks-proxy ").append(socksProxy).append("\n");
            }
        }

        if (isStaticKey) {
            // Режим pre-shared key (как в /opt/ovpn-test).
            sb.append("secret ").append(keyPath).append("\n");
            sb.append("data-ciphers none\n");
            sb.append("cipher none\n");
            sb.append("auth none\n");
            sb.append("ifconfig 10.8.0.2 10.8.0.1\n");
            sb.append("keepalive 10 60\n");
        } else {
            // Режим PKI.
            if (caPath != null) {
                sb.append("ca ").append(caPath).append("\n");
            }
            if (certPath != null) {
                sb.append("cert ").append(certPath).append("\n");
            }
            if (keyFilePath != null) {
                sb.append("key ").append(keyFilePath).append("\n");
            }
            String cipher = c.getOvpnCipher();
            if (cipher == null || cipher.isEmpty() || "none".equalsIgnoreCase(cipher)) {
                sb.append("data-ciphers none\n");
                sb.append("cipher none\n");
            } else {
                sb.append("data-ciphers ").append(cipher).append("\n");
                sb.append("cipher ").append(cipher).append("\n");
            }
            String auth = c.getOvpnAuth();
            if (auth != null && !"none".equalsIgnoreCase(auth) && !auth.isEmpty()) {
                sb.append("auth ").append(auth).append("\n");
            } else {
                sb.append("auth none\n");
            }
        }

        sb.append("resolv-retry infinite\n");
        sb.append("nobind\n");
        sb.append("persist-key\n");
        sb.append("persist-tun\n");
        sb.append("verb ").append(c.getEffectiveOvpnVerb()).append("\n");

        appendTuning(sb, c);

        return sb.toString();
    }

    /**
     * Готовит импортированный сырой .ovpn к запуску: вносит только runtime-правки,
     * которых нет в файле (прокси через SOCKS Xray для режима Xray+OpenVPN и verb).
     * Все остальные директивы (tls-crypt/tls-auth, remote-cert-tls, шифры и т.д.)
     * сохраняются как есть.
     */
    public static String prepareForRun(String raw, ConfigManager c, String socksProxy) {
        String text = raw;
        if (socksProxy != null && !socksProxy.isEmpty()) {
            String[] sp = socksProxy.split(":");
            String line = sp.length == 2
                    ? "socks-proxy " + sp[0].trim() + " " + sp[1].trim()
                    : "socks-proxy " + socksProxy;
            text = patchDirective(text, "socks-proxy", line);
        }
        text = patchDirective(text, "verb", "verb " + c.getEffectiveOvpnVerb());
        // Нормализуем заголовок PEM в блоке <key>: некоторые экспортёры пишут
        // "-----BEGIN RSA PRIVATE KEY-----" (PKCS#1), а кладут внутрь PKCS#8.
        // mbedTLS в нативном openvpn читает строго по заголовку и падает
        // с "ASN1 tag was of an unexpected value". Исправляем заголовок под формат тела.
        text = normalizeOvpn(text);
        return text;
    }

    // ============================================================
    // Нормализация PEM-блока приватного ключа
    // ============================================================

    /**
     * Приводит заголовок/подпись PEM приватного ключа в соответствие с фактическим
     * форматом тела (PKCS#1 «RSA PRIVATE KEY» или PKCS#8 «PRIVATE KEY»).
     * Если формат определить не удалось или он уже корректен — возвращает вход как есть.
     */
    public static String normalizePrivateKeyPem(String pem) {
        if (pem == null) return pem;
        String b64 = extractBase64(pem);
        if (b64.isEmpty()) return pem;
        byte[] der;
        try {
            der = Base64.decode(b64, Base64.DEFAULT);
        } catch (Exception e) {
            return pem;
        }
        if (der == null || der.length < 8) return pem;
        boolean pkcs8;
        try {
            pkcs8 = isPkcs8(der);
        } catch (Exception e) {
            return pem;
        }
        String desired = pkcs8 ? "PRIVATE KEY" : "RSA PRIVATE KEY";
        String current = currentLabel(pem);
        if (desired.equals(current)) return pem;
        String begin = "-----BEGIN " + desired + "-----";
        String end = "-----END " + desired + "-----";
        String out = pem.replaceFirst("(?s)-----BEGIN [^-\\r\\n]+-----", begin);
        out = out.replaceFirst("(?s)-----END [^-\\r\\n]+-----", end);
        return out;
    }

    /**
     * Нормализует все инлайн-блоки &lt;key&gt; в сыром .ovpn.
     * Применяется к импортированному конфигу перед запуском нативного openvpn.
     */
    public static String normalizeOvpn(String raw) {
        if (raw == null) return raw;
        Matcher m = Pattern.compile("(?is)(<key>\\s*)(.*?)(\\s*</key>)").matcher(raw);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String norm = normalizePrivateKeyPem(m.group(2));
            m.appendReplacement(sb, Matcher.quoteReplacement(m.group(1) + norm + m.group(3)));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /** Извлекает тело base64 из PEM (между BEGIN/END), убирая пробелы. */
    private static String extractBase64(String pem) {
        Matcher m = Pattern.compile("(?s)-----BEGIN [^-]+-----\\s*(.*?)\\s*-----END [^-]+-----").matcher(pem);
        if (m.find()) {
            return m.group(1).replaceAll("\\s", "");
        }
        return "";
    }

    /** Возвращает текущую метку PEM («RSA PRIVATE KEY», «PRIVATE KEY», …) или пустую строку. */
    private static String currentLabel(String pem) {
        Matcher m = Pattern.compile("(?s)-----BEGIN\\s+([^-\\r\\n]+)-----").matcher(pem);
        if (m.find()) return m.group(1).trim();
        return "";
    }

    /**
     * Определяет формат DER приватного ключа.
     * После внешнего SEQUENCE и версии INTEGER (02 01 00):
     *   - следующая метка 0x30 (SEQUENCE AlgorithmIdentifier с OID rsaEncryption) → PKCS#8;
     *   - следующая метка 0x02 (INTEGER, модуль) → PKCS#1.
     */
    private static boolean isPkcs8(byte[] d) {
        if (d.length < 8 || d[0] != 0x30) return false;
        int i = skipDerLength(d, 1); // после внешнего SEQUENCE
        if (i < 0 || i >= d.length) return false;
        // версия INTEGER
        if ((d[i] & 0xFF) != 0x02) return false;
        i = skipTlv(d, i);
        if (i < 0 || i >= d.length) return false;
        return (d[i] & 0xFF) == 0x30; // SEQUENCE → PKCS#8
    }

    /** Пропускает поле длины DER и возвращает индекс после него (или -1). */
    private static int skipDerLength(byte[] d, int pos) {
        if (pos >= d.length) return -1;
        int first = d[pos] & 0xFF;
        if (first < 0x80) return pos + 1;
        if (first == 0x80) return -1; // indefinite — не DER
        int n = first & 0x7F;
        if (pos + 1 + n > d.length) return -1;
        return pos + 1 + n;
    }

    /** Пропускает целый TLV (тег+длина+значение) и возвращает индекс после значения (или -1). */
    private static int skipTlv(byte[] d, int pos) {
        if (pos < 0 || pos >= d.length) return -1;
        pos++; // тег
        int lenPos = skipDerLength(d, pos);
        if (lenPos < 0) return -1;
        int len = derLength(d, pos);
        if (len < 0) return -1;
        return lenPos + len;
    }

    /** Читает значение длины DER (или -1). pos указывает на первый байт длины. */
    private static int derLength(byte[] d, int pos) {
        if (pos < 0 || pos >= d.length) return -1;
        int first = d[pos] & 0xFF;
        if (first < 0x80) return first;
        if (first == 0x80) return -1;
        int n = first & 0x7F;
        if (pos + 1 + n > d.length) return -1;
        int len = 0;
        for (int k = 0; k < n; k++) {
            len = (len << 8) | (d[pos + 1 + k] & 0xFF);
        }
        return len;
    }

    // ============================================================
    // Точечные правки сырого .ovpn (для настроек по полям)
    // ============================================================

    /** Заменяет все строки директивы {@code name} на {@code newLine}; если директивы нет — добавляет её. */
    public static String patchDirective(String raw, String name, String newLine) {
        if (raw == null) {
            raw = "";
        }
        String[] lines = raw.split("\n", -1);
        StringBuilder sb = new StringBuilder();
        boolean replaced = false;
        for (String line : lines) {
            String trimmed = line.trim();
            boolean isMatch = trimmed.equalsIgnoreCase(name)
                    || trimmed.toLowerCase().startsWith(name.toLowerCase() + " ");
            if (isMatch) {
                if (!replaced) {
                    sb.append(newLine).append('\n');
                    replaced = true;
                }
                // исходную строку директивы пропускаем
            } else {
                sb.append(line).append('\n');
            }
        }
        if (!replaced) {
            sb.append(newLine).append('\n');
        }
        return sb.toString();
    }

    /** Заменяет директивы cipher и data-ciphers на значение из настроек. */
    public static String patchCipher(String raw, String cipher) {
        String text = patchDirective(raw, "cipher", "");
        text = patchDirective(text, "data-ciphers", "");
        // Убираем добавленные пустые строки (patchDirective с пустым newLine добавлял пустую строку).
        text = text.replace("\n\n", "\n");
        String cipherLine = (cipher == null || cipher.isEmpty() || "none".equalsIgnoreCase(cipher))
                ? "data-ciphers none\ncipher none"
                : "data-ciphers " + cipher + "\ncipher " + cipher;
        return text + cipherLine + "\n";
    }

    /** Заменяет директиву auth на значение из настроек. */
    public static String patchAuth(String raw, String auth) {
        String line = (auth == null || auth.isEmpty() || "none".equalsIgnoreCase(auth))
                ? "auth none" : "auth " + auth;
        return patchDirective(raw, "auth", line);
    }

    /** Заменяет все строки dhcp-option DNS на значения из настроек (через запятую). */
    public static String patchDns(String raw, String dnsComma) {
        String text = raw;
        // Удаляем все dhcp-option DNS.
        String[] lines = text.split("\n", -1);
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            if (line.trim().toLowerCase().startsWith("dhcp-option dns")) {
                continue;
            }
            sb.append(line).append('\n');
        }
        text = sb.toString();
        if (dnsComma != null && !dnsComma.trim().isEmpty()) {
            for (String d : dnsComma.split(",")) {
                String dd = d.trim();
                if (!dd.isEmpty()) {
                    text = text + "dhcp-option DNS " + dd + "\n";
                }
            }
        }
        return text;
    }

    /** Заменяет директиву dev. */
    public static String patchDev(String raw, String dev) {
        return patchDirective(raw, "dev", "dev " + dev);
    }

    /**
     * Режим OpenVPN-через-SSH: сервер доступен только через локальный SSH-форвард
     * (127.0.0.1:localPort на телефоне). Подменяет remote, форсирует proto tcp
     * (SSH форвардит только TCP) и добавляет терпеливые ретраи: во время
     * реконнекта SSH-сессии локальный слушатель недоступен, и openvpn должен
     * просто повторять попытки, пока форвард не поднимется снова.
     */
    public static String patchSshLocal(String raw, int localPort) {
        String text = patchDirective(raw, "remote", "remote 127.0.0.1 " + localPort);
        // Если в конфиге порт задан отдельной директивой "port N" (remote без порта),
        // заменяем и её — иначе локальный форвард не совпадёт с портом подключения.
        text = patchDirective(text, "port", "port " + localPort);
        // Нативный openvpn требует однозначного суффикса: "proto tcp" отклоняется
        // с "Options error: --proto tcp is ambiguous in this context".
        text = patchDirective(text, "proto", "proto tcp-client");
        text = patchDirective(text, "connect-retry", "connect-retry 3 5");
        text = patchDirective(text, "connect-retry-max", "connect-retry-max 100000");
        return text;
    }

    /**
     * Режим интерфейса СЕРВЕРА берётся ИЗ КОНФИГА: "dev tap…" (в т.ч. tap0 и т.п.)
     * → L2, openvpn работает с парой от {@link TapShim} (для бриджевых серверов —
     * Android VpnService умеет только tun). Любое "dev tun*" (включая tun1 и т.п.)
     * → обычный L3 без шима. Никакого авто-детекта.
     */
    public static boolean isTapConfig(String cfg) {
        if (cfg == null) {
            return false;
        }
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("(?m)^dev\\s+(\\S+)\\s*$").matcher(cfg);
        return m.find() && m.group(1).toLowerCase().startsWith("tap");
    }

    /** Заменяет директиву remote-cert-tls. */
    public static String patchRemoteCertTls(String raw, String rct) {
        if (rct == null || rct.trim().isEmpty()) {
            return patchDirective(raw, "remote-cert-tls", "");
        }
        return patchDirective(raw, "remote-cert-tls", "remote-cert-tls " + rct.trim());
    }

    /** Заменяет директиву compress/comp-lzo. */
    public static String patchCompress(String raw, String comp) {
        String text = patchDirective(raw, "compress", "");
        text = patchDirective(text, "comp-lzo", "");
        text = text.replace("\n\n", "\n");
        if (comp != null && !comp.trim().isEmpty()) {
            text = text + "compress " + comp.trim() + "\n";
        }
        return text;
    }

    /** Заменяет директиву tun-mtu. */
    public static String patchMtu(String raw, String mtu) {
        if (mtu == null || mtu.trim().isEmpty()) {
            return patchDirective(raw, "tun-mtu", "");
        }
        return patchDirective(raw, "tun-mtu", "tun-mtu " + mtu.trim());
    }

    /** Заменяет директиву mssfix. */
    public static String patchMssfix(String raw, String mssfix) {
        if (mssfix == null || mssfix.trim().isEmpty()) {
            return patchDirective(raw, "mssfix", "");
        }
        return patchDirective(raw, "mssfix", "mssfix " + mssfix.trim());
    }

    /** Заменяет все директивы route на значения из настроек. */
    public static String patchRoutes(String raw, String routesComma) {
        String text = raw;
        String[] lines = text.split("\n", -1);
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            if (line.trim().toLowerCase().startsWith("route ")) {
                continue;
            }
            sb.append(line).append('\n');
        }
        text = sb.toString();
        if (routesComma != null && !routesComma.trim().isEmpty()) {
            for (String r : routesComma.split(",")) {
                String rr = r.trim();
                if (!rr.isEmpty()) {
                    text = text + "route " + rr + "\n";
                }
            }
        }
        return text;
    }

    /** Устанавливает/убирает redirect-gateway. */
    public static String patchRedirect(String raw, boolean redirect) {
        if (redirect) {
            return patchDirective(raw, "redirect-gateway", "redirect-gateway def1");
        }
        return patchDirective(raw, "redirect-gateway", "");
    }

    /** Добавляет auth-user-pass, если задан логин (пароль передаётся через management). */
    private static void appendAuthUserPass(StringBuilder sb, ConfigManager c) {
        String user = c.getOvpnUsername();
        if (user != null && !user.trim().isEmpty()) {
            sb.append("auth-user-pass\n");
        }
    }

    /** Добавляет dev / remote-cert-tls / compress / route / redirect-gateway. */
    private static void appendCommon(StringBuilder sb, ConfigManager c) {
        String rct = c.getOvpnRemoteCertTls();
        if (rct != null && !rct.trim().isEmpty()) {
            sb.append("remote-cert-tls ").append(rct.trim()).append("\n");
        }
        String comp = c.getOvpnCompress();
        if (comp != null && !comp.trim().isEmpty()) {
            sb.append("compress ").append(comp.trim()).append("\n");
        }
        String routes = c.getOvpnRoutes();
        if (routes != null && !routes.trim().isEmpty()) {
            for (String r : routes.split(",")) {
                String rr = r.trim();
                if (rr.isEmpty()) continue;
                sb.append("route ").append(rr.replace(" ", " ")).append("\n");
            }
        }
        if (c.getOvpnRedirectGateway()) {
            sb.append("redirect-gateway def1\n");
        }
    }

    /** Добавляет MTU / mssfix / DNS в конфиг, если заданы. */
    private static void appendTuning(StringBuilder sb, ConfigManager c) {
        String mtu = c.getOvpnMtu();
        if (mtu != null && !mtu.trim().isEmpty()) {
            sb.append("tun-mtu ").append(mtu.trim()).append("\n");
        }
        String mssfix = c.getOvpnMssfix();
        if (mssfix != null && !mssfix.trim().isEmpty()) {
            sb.append("mssfix ").append(mssfix.trim()).append("\n");
        }
        String dns = c.getOvpnDns();
        if (dns != null && !dns.trim().isEmpty()) {
            for (String d : dns.split(",")) {
                String dd = d.trim();
                if (!dd.isEmpty()) {
                    sb.append("dhcp-option DNS ").append(dd).append("\n");
                }
            }
        }
    }

    /**
     * Собирает самодостаточный .ovpn для экспорта/импорта:
     * сертификаты и статический ключ встраиваются инлайн-блоками.
     */
    public static String exportOvpn(ConfigManager c) {
        StringBuilder sb = new StringBuilder();

        String staticKey = c.getOvpnStaticKey();
        boolean isStaticKey = staticKey != null && !staticKey.trim().isEmpty();

        if (!isStaticKey) {
            sb.append("client\n");
        }
        sb.append("dev ").append(c.getOvpnDev()).append("\n");
        String proto = c.getOvpnProtocol();
        if ("tcp".equalsIgnoreCase(proto)) {
            proto = "tcp-client";
        }
        sb.append("proto ").append(proto).append("\n");
        sb.append("remote ").append(c.getOvpnRemoteHost()).append(" ")
                .append(c.getOvpnRemotePort()).append("\n");
        appendAuthUserPass(sb, c);
        appendCommon(sb, c);

        if (isStaticKey) {
            sb.append("<secret>\n").append(staticKey.trim()).append("\n</secret>\n");
            sb.append("data-ciphers none\n");
            sb.append("cipher none\n");
            sb.append("auth none\n");
            sb.append("ifconfig 10.8.0.2 10.8.0.1\n");
            sb.append("keepalive 10 60\n");
        } else {
            String ca = c.getOvpnCa();
            if (ca != null && !ca.trim().isEmpty()) {
                sb.append("<ca>\n").append(ca.trim()).append("\n</ca>\n");
            }
            String cert = c.getOvpnCert();
            if (cert != null && !cert.trim().isEmpty()) {
                sb.append("<cert>\n").append(cert.trim()).append("\n</cert>\n");
            }
            String key = c.getOvpnKey();
            if (key != null && !key.trim().isEmpty()) {
                sb.append("<key>\n").append(key.trim()).append("\n</key>\n");
            }
            String cipher = c.getOvpnCipher();
            if (cipher == null || cipher.isEmpty() || "none".equalsIgnoreCase(cipher)) {
                sb.append("data-ciphers none\n");
                sb.append("cipher none\n");
            } else {
                sb.append("data-ciphers ").append(cipher).append("\n");
                sb.append("cipher ").append(cipher).append("\n");
            }
            String auth = c.getOvpnAuth();
            if (auth != null && !"none".equalsIgnoreCase(auth) && !auth.isEmpty()) {
                sb.append("auth ").append(auth).append("\n");
            } else {
                sb.append("auth none\n");
            }
        }

        sb.append("resolv-retry infinite\n");
        sb.append("nobind\n");
        sb.append("persist-key\n");
        sb.append("persist-tun\n");
        sb.append("verb ").append(c.getEffectiveOvpnVerb()).append("\n");

        appendTuning(sb, c);

        return sb.toString();
    }
}
