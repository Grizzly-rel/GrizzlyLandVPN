package com.grizzlyland.vpn;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Генерирует JSON-конфигурацию Xray (клиент) из настроек приложения.
 *
 * Конфиг собирается через JSON-библиотеку (org.json), а не конкатенацией строк.
 * Поддерживаются все современные транспорты (tcp, ws, grpc, httpupgrade, xhttp,
 * http, h2, kcp, quic) и TLS/Reality со всеми параметрами.
 *
 * Два режима:
 *  - build():       локальный SOCKS-прокси (для режима Xray+OpenVPN).
 *  - buildTun():    tun-вход (для режима "только Xray").
 */
public class XrayConfigBuilder {

    public static final int DEFAULT_SOCKS_PORT = 10808;

    /** SOCKS-конфиг (режим Xray+OpenVPN). @param logDir каталог для файлов логов Xray. */
    public static String build(ConfigManager c, String logDir) {
        try {
            JSONObject o = baseConfig(c, logDir);
            JSONArray inbounds = new JSONArray();
            inbounds.put(socksInbound(c));
            o.put("inbounds", inbounds);
            o.put("outbounds", outbounds(c));
            return o.toString(2);
        } catch (JSONException e) {
            return "{}";
        }
    }

    /** TUN-конфиг (режим "только Xray"). @param logDir каталог для файлов логов Xray. */
    public static String buildTun(ConfigManager c, String logDir) {
        try {
            JSONObject o = baseConfig(c, logDir);
            JSONArray inbounds = new JSONArray();
            inbounds.put(tunInbound(c));
            inbounds.put(socksInbound(c));
            o.put("inbounds", inbounds);
            o.put("outbounds", outbounds(c));
            return o.toString(2);
        } catch (JSONException e) {
            return "{}";
        }
    }

    /**
     * TUN-конфиг режима "WireGuard через Xray".
     *
     * Трафик из TUN попадает в wireguard-outbound Xray (полноценный userspace
     * WG-клиент со встроенным gVisor-стеком), а его UDP-пакеты к WG-серверу
     * дialятся ЧЕРЕЗ proxy-outbound (VLESS/Reality) через sockopt.dialerProxy —
     * так протокол WireGuard скрыт от DPI точно так же, как OpenVPN в режиме
     * Xray+OpenVPN (там ovpn ходит через локальный SOCKS).
     *
     * Порядок outbounds важен: ПЕРВЫЙ outbound в Xray — дефолтный (все маршруты,
     * не попавшие в правила). DNS (порт 53 из TUN) идёт в dns-out (модуль Xray),
     * а его собственные запросы уходят в дефолт — то есть тоже сквозь WG-туннель.
     */
    public static String buildTunWg(ConfigManager c, String logDir, String resolvedEndpoint) {
        try {
            WgConfigParser.WgConfig wg = WgConfigParser.parse(c.getWgRaw());
            if (!wg.valid) {
                throw new IllegalStateException("Конфиг WireGuard некорректен"
                        + (wg.parseError.isEmpty() ? "" : (": " + wg.parseError))
                        + " (Настройки → Настройки WireGuard)");
            }

            JSONObject o = baseConfig(c, logDir);
            JSONArray inbounds = new JSONArray();
            inbounds.put(tunInbound(c));
            inbounds.put(socksInbound(c));
            o.put("inbounds", inbounds);

            JSONArray outbounds = new JSONArray();
            // Дефолт (первый) — WG: весь трафик TUN уходит в WG-туннель.
            outbounds.put(wgOutbound(wg, c, resolvedEndpoint));
            // Прокси (VLESS и т.п.) — тот же outbound, что и в остальных режимах;
            // на него ссылается dialerProxy WG-outbound'а.
            JSONObject proxy = new JSONObject();
            proxy.put("protocol", c.getXrayProtocol());
            proxy.put("settings", outboundSettings(c));
            proxy.put("streamSettings", streamSettings(c));
            proxy.put("tag", "proxy");
            outbounds.put(proxy);
            // DNS-выход — как в режиме "только Xray" (правило порта 53 в routing).
            JSONObject dnsOut = new JSONObject();
            dnsOut.put("protocol", "dns");
            dnsOut.put("tag", "dns-out");
            outbounds.put(dnsOut);
            o.put("outbounds", outbounds);
            return o.toString(2);
        } catch (JSONException e) {
            return "{}";
        }
        // IllegalStateException (некорректный WG-конфиг) сознательно пробрасывается
        // наружу: сервис покажет ошибку пользователю и остановится.
    }

    /**
     * WireGuard-outbound из разобранного wg-quick конфига. Используется только
     * ПЕРВЫЙ peer: listenFunc WG-клиента Xray привязывает UDP-сокет к endpoint'у
     * peers[0], пакеты к остальным peer ушли бы туда же.
     */
    private static JSONObject wgOutbound(WgConfigParser.WgConfig wg, ConfigManager c,
                                         String resolvedEndpoint) throws JSONException {
        WgConfigParser.PeerInfo peer = wg.peerList.get(0);
        if (peer.endpoint.isEmpty()) {
            throw new IllegalStateException("В конфиге WireGuard не задан Endpoint peer");
        }
        String endpoint = (resolvedEndpoint != null && !resolvedEndpoint.isEmpty())
                ? resolvedEndpoint : resolveWgEndpoint(peer.endpoint);

        JSONObject out = new JSONObject();
        out.put("tag", "wg-out");
        out.put("protocol", "wireguard");

        JSONObject settings = new JSONObject();
        // Ключи уже в hex (WgConfigParser конвертирует base64 wg-quick для UAPI;
        // Xray принимает и hex, и base64 — ParseWireGuardKey).
        settings.put("secretKey", wg.privateKeyHex);
        JSONArray addr = new JSONArray();
        for (String a : wg.addresses) {
            addr.put(a);
        }
        if (addr.length() == 0) {
            addr.put("10.0.0.2/32");
        }
        settings.put("address", addr);
        // На Android ядерный TUN недоступен — строго gVisor-стек внутри ядра Xray.
        settings.put("noKernelTun", true);
        settings.put("mtu", wg.mtu > 0 ? wg.mtu : 1420);

        JSONArray peers = new JSONArray();
        JSONObject p = new JSONObject();
        p.put("publicKey", peer.publicKeyHex);
        if (!peer.pskHex.isEmpty()) {
            p.put("preSharedKey", peer.pskHex);
        }
        p.put("endpoint", endpoint);
        if (!peer.keepalive.isEmpty()) {
            try {
                p.put("keepAlive", Integer.parseInt(peer.keepalive.trim()));
            } catch (NumberFormatException ignored) {
            }
        }
        if (!peer.allowed.isEmpty()) {
            JSONArray ai = new JSONArray();
            for (String cidr : peer.allowed) {
                ai.put(cidr);
            }
            p.put("allowedIPs", ai);
        }
        // Иначе Xray сам ставит 0.0.0.0/0 + ::/0 (full tunnel).
        peers.put(p);
        settings.put("peers", peers);

        // DNS-серверы внутреннего WG-стека (резолв доменных целей внутри туннеля).
        // Строго IPv4: Xray парсит их через netip.MustParseAddr и паникует на мусоре,
        // а IPv6 в v4-only туннеле бесполезен. Если в wg-конфиге DNS нет — берём
        // plain-IP из настроек Xray (иначе Xray подставит свои дефолты с IPv6).
        JSONArray rdns = new JSONArray();
        for (String d : wg.dns) {
            String dd = d.trim();
            if (isPlainIpv4(dd)) {
                rdns.put(dd);
            }
        }
        if (rdns.length() == 0) {
            for (String d : c.getXrayDnsPlain().split(",")) {
                String dd = d.trim();
                if (isPlainIpv4(dd)) {
                    rdns.put(dd);
                }
            }
        }
        if (rdns.length() > 0) {
            settings.put("remoteDNS", rdns);
        }
        out.put("settings", settings);

        // КЛЮЧЕВОЕ место режима: UDP-сокет WG к серверу dialится через outbound
        // с тегом "proxy" (VLESS/Reality) — UDP-over-XUDP внутри прокси-соединения.
        JSONObject ss = new JSONObject();
        JSONObject sockopt = new JSONObject();
        sockopt.put("dialerProxy", "proxy");
        ss.put("sockopt", sockopt);
        out.put("streamSettings", ss);
        return out;
    }

    /**
     * Резолвит домен в endpoint'е WG ЗАРАНЕЕ, на стороне приложения.
     *
     * Зачем: WG-outbound резолвит endpoint через DNS-модуль Xray (bind.ParseEndpoint
     * → resolveFunc → app/dns), а запросы DNS-модуля в этом режиме уходят в
     * дефолтный outbound — то есть снова в wg-out, который не может подняться,
     * пока его endpoint не зарезолвлен. Получается цикл «резолв через
     * несозданный туннель» (на практике: IpcSet падает по таймаутам DNS, режим
     * не стартует). Java-резолв идёт штатной сетью мимо TUN (свой трафик
     * приложения исключён из VPN), поэтому цикл разрывается. IP-адрес в
     * endpoint'е проходит насквозь без изменений; при реконнекте конфиг
     * строится заново — адрес перепосвежается.
     *
     * ВАЖНО: вызывать ДО establish() TUN — резолв при уже поднятом туннеле
     * уходит в VPN-заглушку DNS и ломается (проверено на устройстве).
     */
    public static String resolveWgEndpoint(String endpoint) {
        int colon = endpoint.lastIndexOf(':');
        if (colon <= 0 || colon == endpoint.length() - 1) {
            throw new IllegalStateException("Некорректный Endpoint peer: \"" + endpoint + "\" (нужен host:port)");
        }
        String host = endpoint.substring(0, colon);
        String port = endpoint.substring(colon + 1);
        if (isPlainIpv4(host) || host.startsWith("[")) {
            return endpoint; // уже IP (или скобочный IPv6) — резолв не нужен
        }
        // Две попытки: разовый сбой резолва (особенно сразу после пробуждения
        // сети) не должен ронять подключение.
        String lastErr = "";
        for (int attempt = 0; attempt < 2; attempt++) {
            try {
                java.net.InetAddress[] addrs = java.net.InetAddress.getAllByName(host);
                String picked = null;
                for (java.net.InetAddress a : addrs) {
                    if (a instanceof java.net.Inet4Address) {
                        picked = a.getHostAddress();
                        break;
                    }
                }
                if (picked == null && addrs.length > 0) {
                    picked = addrs[0].getHostAddress();
                }
                if (picked != null) {
                    return picked + ":" + port;
                }
                lastErr = "сервер не вернул адресов";
            } catch (Exception e) {
                lastErr = e.getClass().getSimpleName()
                        + (e.getMessage() == null ? "" : (": " + e.getMessage()));
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException ignored) {
            }
        }
        throw new IllegalStateException("Не удалось резолвить WG endpoint \""
                + host + "\": " + lastErr);
    }

    /** Строгая проверка IPv4 (для remoteDNS wireguard-outbound). */
    private static boolean isPlainIpv4(String s) {
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

    // ============================================================
    // Общая часть: log, dns, routing
    // ============================================================

    private static JSONObject baseConfig(ConfigManager c, String logDir) throws JSONException {
        JSONObject o = new JSONObject();

        // Уровень журналирования берём из настроек (для подробного журнала — debug).
        String level = c.getXrayLoglevel();
        if (level == null || level.isEmpty()) {
            level = "info";
        }
        JSONObject log = new JSONObject();
        log.put("loglevel", level);
        // Пишем логи Xray в файлы, чтобы приложение могло показать их в журнале.
        if (logDir != null) {
            log.put("access", logDir + "/xray_access.log");
            log.put("error", logDir + "/xray_error.log");
        }
        o.put("log", log);

        // DNS. Серверы поддерживают форматы Xray (UDP, "tcp://", "https://" DoH,
        // "ip:853" DoT). queryStrategy по умолчанию UseIPv4 — tun IPv4-only, чтобы
        // не слать бесполезные AAAA-запросы.
        JSONObject dns = new JSONObject();
        dns.put("servers", dnsArray(c));
        String qs = c.getXrayQueryStrategy();
        if (qs != null && !qs.isEmpty()) {
            dns.put("queryStrategy", qs);
        }
        o.put("dns", dns);

        // Routing: DNS-запросы (порт 53) из TUN направляем во встроенный DNS-модуль
        // Xray (outbound с protocol "dns"), чтобы они резолвились через прокси, а не
        // уходили сырым UDP на DNS-сервер. Без этого правила в TUN-режиме DNS не
        // работает, хотя IP-адреса пингуются (см. Xray docs: "you also need a routing
        // rule sending the interface's port 53 to a dns outbound").
        JSONObject routing = new JSONObject();
        routing.put("domainStrategy", "IPIfNonMatch");
        JSONArray rules = new JSONArray();
        JSONObject dnsRule = new JSONObject();
        dnsRule.put("type", "field");
        JSONArray dnsInbound = new JSONArray();
        dnsInbound.put("tun");
        dnsRule.put("inboundTag", dnsInbound);
        dnsRule.put("port", 53);
        dnsRule.put("outboundTag", "dns-out");
        rules.put(dnsRule);
        routing.put("rules", rules);
        o.put("routing", routing);

        return o;
    }

    private static JSONArray dnsArray(ConfigManager c) throws JSONException {
        String raw = c.getXrayDns();
        if (raw == null || raw.trim().isEmpty()) {
            raw = "8.8.8.8,8.8.4.4";
        }
        JSONArray arr = new JSONArray();
        for (String p : raw.split(",")) {
            String d = p.trim();
            if (!d.isEmpty()) {
                arr.put(d);
            }
        }
        return arr;
    }

    /** DNS-серверы только чистыми IP (для поля dns у tun-входа и т.п.). */
    private static JSONArray dnsArrayPlain(ConfigManager c) throws JSONException {
        JSONArray arr = new JSONArray();
        for (String p : c.getXrayDnsPlain().split(",")) {
            String d = p.trim();
            if (!d.isEmpty()) {
                arr.put(d);
            }
        }
        return arr;
    }

    // ============================================================
    // Inbounds
    // ============================================================

    private static JSONObject socksInbound(ConfigManager c) throws JSONException {
        JSONObject in = new JSONObject();
        in.put("port", c.getXraySocksPort());
        in.put("listen", "127.0.0.1");
        in.put("protocol", "socks");
        JSONObject settings = new JSONObject();
        settings.put("udp", true);
        in.put("settings", settings);
        return in;
    }

    private static JSONObject tunInbound(ConfigManager c) throws JSONException {
        JSONObject in = new JSONObject();
        in.put("tag", "tun");
        in.put("protocol", "tun");
        JSONObject settings = new JSONObject();
        settings.put("name", "tun0");
        settings.put("mtu", 1400);
        // В поле dns tun-входа кладём только чистые IP (как в addDnsServer VpnService).
        // DoH/TCP-форматы идут только в DNS-модуль (baseConfig), а не сюда.
        settings.put("dns", dnsArrayPlain(c));
        JSONArray gateway = new JSONArray();
        gateway.put("10.0.0.1");
        settings.put("gateway", gateway);
        in.put("settings", settings);
        // Sniffing (для корректного определения доменов)
        JSONObject sniffing = new JSONObject();
        sniffing.put("enabled", true);
        JSONArray destOverride = new JSONArray();
        destOverride.put("http");
        destOverride.put("tls");
        sniffing.put("destOverride", destOverride);
        in.put("sniffing", sniffing);
        return in;
    }

    // ============================================================
    // Outbound
    // ============================================================

    private static JSONArray outbounds(ConfigManager c) throws JSONException {
        JSONArray arr = new JSONArray();
        JSONObject out = new JSONObject();
        out.put("protocol", c.getXrayProtocol());
        out.put("settings", outboundSettings(c));
        out.put("streamSettings", streamSettings(c));
        // Тег outbound'а постоянен (не зависит от domainStrategy): на "proxy" могут
        // ссылаться routing-правила (наши и пользовательские), его отсутствие при
        // пустом domainStrategy делало конфиг нестабильным.
        out.put("tag", "proxy");
        arr.put(out);

        // DNS-выход: перехватывает сырые DNS-запросы (порт 53) и резолвит их через
        // встроенный DNS-модуль Xray. Без него DNS в TUN-режиме не работает.
        // На него ссылается routing-правило (outboundTag "dns-out").
        JSONObject dnsOut = new JSONObject();
        dnsOut.put("protocol", "dns");
        dnsOut.put("tag", "dns-out");
        arr.put(dnsOut);
        return arr;
    }

    private static JSONObject outboundSettings(ConfigManager c) throws JSONException {
        JSONObject settings = new JSONObject();
        String protocol = c.getXrayProtocol();
        String addr = c.getXrayAddress();
        int port = c.getXrayPort();
        String id = c.getXrayId();

        if ("vless".equals(protocol) || "vmess".equals(protocol)) {
            JSONArray vnext = new JSONArray();
            JSONObject v = new JSONObject();
            v.put("address", addr);
            v.put("port", port);
            JSONArray users = new JSONArray();
            JSONObject u = new JSONObject();
            u.put("id", id);
            if ("vless".equals(protocol)) {
                u.put("encryption", "none");
                String flow = c.getXrayFlow();
                if (flow != null && !flow.isEmpty() && !"none".equals(flow)) {
                    u.put("flow", flow);
                }
            } else {
                String enc = c.getXrayEncryption();
                if (enc != null && !enc.isEmpty()) {
                    u.put("security", enc);
                }
            }
            users.put(u);
            v.put("users", users);
            vnext.put(v);
            settings.put("vnext", vnext);
        } else {
            // trojan / shadowsocks / socks / http — servers
            JSONArray servers = new JSONArray();
            JSONObject s = new JSONObject();
            s.put("address", addr);
            s.put("port", port);
            if ("trojan".equals(protocol)) {
                s.put("password", id);
            } else if ("shadowsocks".equals(protocol)) {
                s.put("method", c.getXrayEncryption());
                s.put("password", id);
            }
            servers.put(s);
            settings.put("servers", servers);
        }

        String ds = c.getXrayDomainStrategy();
        if (ds != null && !ds.isEmpty()) {
            settings.put("domainStrategy", ds);
        }
        return settings;
    }

    // ============================================================
    // Stream settings
    // ============================================================

    private static JSONObject streamSettings(ConfigManager c) throws JSONException {
        JSONObject s = new JSONObject();
        String transport = c.getXrayTransport();
        String security = c.getXraySecurity();
        String host = c.getXrayHost();
        String path = c.getXrayPath();
        String headerType = c.getXrayHeaderType();

        s.put("network", transport);

        // --- Security ---
        if ("reality".equals(security)) {
            s.put("security", "reality");
            JSONObject r = new JSONObject();
            // SNI (serverName) обязателен для Reality. Если host не задан — берём адрес сервера.
            String sni = (host != null && !host.isEmpty()) ? host : c.getXrayAddress();
            r.put("serverName", sni);
            r.put("publicKey", c.getXrayPublicKey());
            r.put("shortId", c.getXrayShortId());
            // Пустой/не заданный fingerprint → firefox: uTLS-chrome ClientHello дропается
            // сигнатурным DPI-фильтром на пути к серверу (первый сегмент, вместе с ретранsmитами)
            String fp = c.getXrayFingerprint();
            if (fp == null || fp.isEmpty()) fp = "firefox";
            r.put("fingerprint", fp);
            if (c.getXraySpiderX() != null && !c.getXraySpiderX().isEmpty()) {
                r.put("spiderX", c.getXraySpiderX());
            }
            putAlpn(r, c);
            if (c.getXrayAllowInsecure()) {
                r.put("allowInsecure", true);
            }
            s.put("realitySettings", r);
        } else if ("tls".equals(security) || "xtls".equals(security)) {
            s.put("security", security);
            JSONObject t = new JSONObject();
            if (host != null && !host.isEmpty()) {
                t.put("serverName", host);
            }
            String fp = c.getXrayFingerprint();
            if (fp != null && !fp.isEmpty() && !"none".equals(fp)) {
                t.put("fingerprint", fp);
            }
            putAlpn(t, c);
            if (c.getXrayAllowInsecure()) {
                t.put("allowInsecure", true);
            }
            s.put("tlsSettings", t);
        }

        // --- Transport ---
        if ("ws".equals(transport)) {
            JSONObject ws = new JSONObject();
            ws.put("path", path);
            JSONObject headers = new JSONObject();
            if (host != null && !host.isEmpty()) {
                headers.put("Host", host);
            }
            if (headers.length() > 0) {
                ws.put("headers", headers);
            }
            s.put("wsSettings", ws);
        } else if ("grpc".equals(transport)) {
            JSONObject g = new JSONObject();
            g.put("serviceName", path);
            s.put("grpcSettings", g);
        } else if ("httpupgrade".equals(transport)) {
            JSONObject h = new JSONObject();
            h.put("path", path);
            if (host != null && !host.isEmpty()) {
                h.put("host", host);
            }
            s.put("httpupgradeSettings", h);
        } else if ("xhttp".equals(transport)) {
            JSONObject x = new JSONObject();
            x.put("path", path);
            if (host != null && !host.isEmpty()) {
                x.put("host", host);
            }
            s.put("xhttpSettings", x);
        } else if ("http".equals(transport) || "h2".equals(transport)) {
            JSONObject h = new JSONObject();
            h.put("path", path);
            if (host != null && !host.isEmpty()) {
                JSONArray ha = new JSONArray();
                ha.put(host);
                h.put("host", ha);
            }
            s.put("httpSettings", h);
        } else if ("kcp".equals(transport)) {
            JSONObject k = new JSONObject();
            if (headerType != null && !headerType.isEmpty() && !"none".equals(headerType)) {
                JSONObject header = new JSONObject();
                header.put("type", headerType);
                k.put("header", header);
            }
            s.put("kcpSettings", k);
        } else if ("quic".equals(transport)) {
            JSONObject q = new JSONObject();
            if (headerType != null && !headerType.isEmpty() && !"none".equals(headerType)) {
                JSONObject header = new JSONObject();
                header.put("type", headerType);
                q.put("header", header);
            }
            s.put("quicSettings", q);
        } else if ("tcp".equals(transport)) {
            JSONObject t = new JSONObject();
            if (headerType != null && !headerType.isEmpty() && !"none".equals(headerType)) {
                JSONObject header = new JSONObject();
                header.put("type", headerType);
                t.put("header", header);
            }
            s.put("tcpSettings", t);
        }

        return s;
    }

    private static void putAlpn(JSONObject target, ConfigManager c) throws JSONException {
        String alpn = c.getXrayAlpn();
        if (alpn == null || alpn.trim().isEmpty()) {
            return;
        }
        JSONArray arr = new JSONArray();
        for (String a : alpn.split(",")) {
            String v = a.trim();
            if (!v.isEmpty()) {
                arr.put(v);
            }
        }
        if (arr.length() > 0) {
            target.put("alpn", arr);
        }
    }
}
