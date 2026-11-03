package com.grizzlyland.vpn;

import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Распознаёт распространённые форматы сохранённых конфигов и применяет их к настройкам.
 *
 * OpenVPN: стандартный .ovpn (директивы + инлайн-блоки &lt;ca&gt;/&lt;cert&gt;/&lt;key&gt;/&lt;secret&gt;).
 * Xray: share-ссылки (vless://, vmess://, trojan://, ss://), полный Xray JSON-конфиг,
 *       а также собственный JSON-формат приложения ({"xray":{...}}).
 */
public class ConfigParser {

    // ============================================================
    // OpenVPN (.ovpn)
    // ============================================================

    /** Применяет настройки OpenVPN из текста .ovpn (или из JSON-файла прежнего формата). */
    public static void applyOvpn(ConfigManager c, String text) throws Exception {
        String t = text.trim();
        if (t.startsWith("{")) {
            // Прежний (JSON) формат экспорта OpenVPN — для обратной совместимости.
            c.importOpenVpnJson(t);
            return;
        }

        // Сохраняем сырой .ovpn как источник истины: приложение в режиме OpenVPN
        // работает именно с этим файлом (сохраняя все директивы), а правки по полям
        // вносятся точечно (см. OpenVpnConfigBuilder.patch*).
        c.setOvpnRaw(text);

        String proto = null, host = null, port = null;
        String cipher = null, auth = null;
        String ca = null, cert = null, key = null, secret = null;
        String mtu = null, mssfix = null;
        String dev = null, remoteCertTls = null, compress = null;
        String user = null, pass = null;
        boolean redirect = false;
        StringBuilder dns = new StringBuilder();
        StringBuilder routes = new StringBuilder();

        // --- Инлайн-блоки ---
        Pattern inline = Pattern.compile("(?is)<(ca|cert|key|secret|auth-user-pass)>(.*?)</\\1>");
        Matcher im = inline.matcher(t);
        while (im.find()) {
            String tag = im.group(1).toLowerCase();
            String content = im.group(2).trim();
            if ("ca".equals(tag)) ca = content;
            else if ("cert".equals(tag)) cert = content;
            else if ("key".equals(tag)) key = content;
            else if ("secret".equals(tag)) secret = content;
            else if ("auth-user-pass".equals(tag)) {
                // Первая строка — логин, вторая — пароль.
                String[] lines = content.split("\\r?\\n");
                if (lines.length > 0) user = lines[0].trim();
                if (lines.length > 1) pass = lines[1].trim();
            }
        }
        // Удаляем инлайн-блоки, чтобы они не мешали разбору директив.
        t = inline.matcher(t).replaceAll("");

        // --- Директивы ---
        Matcher m;
        // remote host [port] [proto] — порт может отсутствовать.
        m = Pattern.compile("(?im)^\\s*remote\\s+([^\\s]+)(?:\\s+(\\d+))?").matcher(t);
        if (m.find()) {
            host = m.group(1);
            if (m.group(2) != null) port = m.group(2);
        }
        m = Pattern.compile("(?im)^\\s*proto\\s+(\\S+)").matcher(t);
        if (m.find()) proto = m.group(1);
        m = Pattern.compile("(?im)^\\s*port\\s+(\\d+)").matcher(t);
        if (m.find() && port == null) port = m.group(1);
        m = Pattern.compile("(?im)^\\s*cipher\\s+(\\S+)").matcher(t);
        if (m.find()) cipher = m.group(1);
        m = Pattern.compile("(?im)^\\s*data-ciphers\\s+(\\S+)").matcher(t);
        if (m.find() && cipher == null) cipher = m.group(1);
        m = Pattern.compile("(?im)^\\s*auth\\s+(\\S+)").matcher(t);
        if (m.find()) auth = m.group(1);
        m = Pattern.compile("(?im)^\\s*(?:tun-mtu|mtu)\\s+(\\d+)").matcher(t);
        if (m.find()) mtu = m.group(1);
        m = Pattern.compile("(?im)^\\s*mssfix\\s+(\\S+)").matcher(t);
        if (m.find()) mssfix = m.group(1);
        m = Pattern.compile("(?im)^\\s*dhcp-option\\s+DNS\\s+(\\S+)").matcher(t);
        while (m.find()) {
            if (dns.length() > 0) dns.append(",");
            dns.append(m.group(1));
        }
        m = Pattern.compile("(?im)^\\s*dev\\s+(\\S+)").matcher(t);
        if (m.find()) dev = m.group(1);
        m = Pattern.compile("(?im)^\\s*remote-cert-tls\\s+(\\S+)").matcher(t);
        if (m.find()) remoteCertTls = m.group(1);
        m = Pattern.compile("(?im)^\\s*(?:compress|comp-lzo)\\s+(\\S+)").matcher(t);
        if (m.find()) compress = m.group(1);
        m = Pattern.compile("(?im)^\\s*route\\s+(.+)$").matcher(t);
        while (m.find()) {
            if (routes.length() > 0) routes.append(",");
            routes.append(m.group(1).trim());
        }
        m = Pattern.compile("(?im)^\\s*redirect-gateway\\b").matcher(t);
        if (m.find()) redirect = true;
        // secret <файл> — если нет инлайн-блока, сам ключ недоступен, но флаг статики выставим.
        boolean secretDirective = secret == null
                && Pattern.compile("(?im)^\\s*secret\\s+").matcher(t).find();

        // --- Применяем ---
        if (proto != null) {
            String p = proto.toLowerCase();
            if (p.startsWith("tcp")) c.setOvpnProtocol("tcp");
            else if (p.startsWith("udp")) c.setOvpnProtocol("udp");
        }
        if (host != null) c.setOvpnRemoteHost(host);
        if (port != null) c.setOvpnRemotePort(Integer.parseInt(port));
        if (cipher != null) c.setOvpnCipher(cipher);
        if (auth != null) c.setOvpnAuth(auth);
        if (mtu != null) c.setOvpnMtu(mtu);
        if (mssfix != null) c.setOvpnMssfix(mssfix);
        if (dns.length() > 0) c.setOvpnDns(dns.toString());
        if (dev != null) c.setOvpnDev(dev);
        if (remoteCertTls != null) c.setOvpnRemoteCertTls(remoteCertTls);
        if (compress != null) c.setOvpnCompress(compress);
        if (routes.length() > 0) c.setOvpnRoutes(routes.toString());
        if (redirect) c.setOvpnRedirectGateway(true);
        if (user != null) c.setOvpnUsername(user);
        if (pass != null) c.setOvpnPassword(pass);

        if (secret != null) {
            c.setOvpnStaticKey(secret);
            c.setOvpnCa("");
            c.setOvpnCert("");
            c.setOvpnKey("");
        } else if (secretDirective) {
            // Статический ключ указан файлом — пометим как static (без содержимого).
            c.setOvpnStaticKey("__FILE__");
            c.setOvpnCa("");
            c.setOvpnCert("");
            c.setOvpnKey("");
        } else {
            c.setOvpnStaticKey("");
            if (ca != null) c.setOvpnCa(ca);
            if (cert != null) c.setOvpnCert(cert);
            if (key != null) c.setOvpnKey(OpenVpnConfigBuilder.normalizePrivateKeyPem(key));
        }
    }

    // ============================================================
    // Xray
    // ============================================================

    /** Применяет настройки Xray из share-ссылки, полного JSON-конфига или JSON приложения. */
    public static void applyXray(ConfigManager c, String text) throws Exception {
        String t = text.trim();
        if (t.startsWith("vless://")) { parseVless(c, t); return; }
        if (t.startsWith("vmess://")) { parseVmess(c, t); return; }
        if (t.startsWith("trojan://")) { parseTrojan(c, t); return; }
        if (t.startsWith("ss://")) { parseSs(c, t); return; }
        if (t.startsWith("{")) {
            JSONObject o = new JSONObject(t);
            if (o.has("xray")) {
                c.importXrayJson(t); // собственный формат приложения
            } else {
                parseXrayJson(c, o);
            }
            return;
        }
        // Прочие варианты — пробуем как собственный JSON-формат.
        c.importXrayJson(t);
    }

    private static void parseVless(ConfigManager c, String link) throws Exception {
        // vless://uuid@host:port?params#name
        String body = link.substring("vless://".length());
        String[] hp = splitHostPort(body);
        String host = hp[0];
        int port = parseInt(hp[1], 443);
        String query = "";
        int q = body.indexOf('?');
        if (q >= 0) {
            int hash = body.indexOf('#', q);
            query = body.substring(q + 1, hash >= 0 ? hash : body.length());
        }
        Map<String, String> p = parseQuery(query);
        // В vless UUID идёт до @, отдельно от host:port
        int at = body.indexOf('@');
        String id = at >= 0 ? urlDecode(body.substring(0, at)) : "";

        c.setXrayProtocol("vless");
        c.setXrayId(id);
        c.setXrayAddress(host);
        c.setXrayPort(port);
        c.setXraySecurity(p.getOrDefault("security", "none"));
        c.setXrayTransport(p.getOrDefault("type", "tcp"));
        if (p.containsKey("path")) c.setXrayPath(urlDecode(p.get("path")));
        String sni = p.containsKey("sni") ? p.get("sni") : p.get("host");
        // Для Reality/TLS SNI обязателен. Если в ссылке не указан sni/host —
        // берём адрес сервера (обычно это домен). Иначе serverName будет пустым
        // и Reality-соединение не установится (трафик «подключается, но не идёт»).
        if (sni == null || sni.isEmpty()) {
            String sec = p.getOrDefault("security", "none");
            if ("reality".equals(sec) || "tls".equals(sec) || "xtls".equals(sec)) {
                sni = host;
            }
        }
        if (sni != null && !sni.isEmpty()) c.setXrayHost(sni);
        if (p.containsKey("flow")) c.setXrayFlow(p.get("flow"));
        if (p.containsKey("encryption")) c.setXrayEncryption(p.get("encryption"));
        if (p.containsKey("pbk")) c.setXrayPublicKey(p.get("pbk"));
        if (p.containsKey("sid")) c.setXrayShortId(p.get("sid"));
        if (p.containsKey("fp")) c.setXrayFingerprint(p.get("fp"));
        applyCommonXrayParams(c, p);
    }

    private static void parseVmess(ConfigManager c, String link) throws Exception {
        // vmess://base64(json)
        String b64 = link.substring("vmess://".length());
        String json = b64decode(b64);
        JSONObject o = new JSONObject(json);
        String id = o.optString("id", "");
        String host = o.optString("add", "");
        int port = o.optInt("port", 443);
        String net = o.optString("net", "tcp");
        String tls = o.optString("tls", "");
        String sni = o.optString("sni", "");
        if (sni.isEmpty()) sni = o.optString("host", "");
        String path = o.optString("path", "");
        String fp = o.optString("fp", "");
        String scy = o.optString("scy", "");
        String flow = o.optString("flow", "");

        c.setXrayProtocol("vmess");
        c.setXrayId(id);
        c.setXrayAddress(host);
        c.setXrayPort(port);
        c.setXrayTransport(net);
        c.setXraySecurity(tls.isEmpty() ? "none" : tls);
        if (!sni.isEmpty()) c.setXrayHost(sni);
        if (!path.isEmpty()) c.setXrayPath(path);
        if (!fp.isEmpty()) c.setXrayFingerprint(fp);
        if (!scy.isEmpty()) c.setXrayEncryption(scy);
        if (!flow.isEmpty()) c.setXrayFlow(flow);
        if (o.has("alpn")) c.setXrayAlpn(o.getString("alpn"));
        if (o.has("headerType")) c.setXrayHeaderType(o.getString("headerType"));
        if (o.has("spiderX")) c.setXraySpiderX(o.getString("spiderX"));
        if (o.optBoolean("allowInsecure", false)) c.setXrayAllowInsecure(true);
    }

    private static void parseTrojan(ConfigManager c, String link) throws Exception {
        // trojan://password@host:port?params#name
        String body = link.substring("trojan://".length());
        String[] hp = splitHostPort(body);
        String host = hp[0];
        int port = parseInt(hp[1], 443);
        int q = body.indexOf('?');
        String query = "";
        if (q >= 0) {
            int hash = body.indexOf('#', q);
            query = body.substring(q + 1, hash >= 0 ? hash : body.length());
        }
        Map<String, String> p = parseQuery(query);
        int at = body.indexOf('@');
        String password = at >= 0 ? urlDecode(body.substring(0, at)) : "";

        c.setXrayProtocol("trojan");
        c.setXrayId(password);
        c.setXrayAddress(host);
        c.setXrayPort(port);
        c.setXraySecurity("tls");
        c.setXrayTransport(p.getOrDefault("type", "tcp"));
        if (p.containsKey("path")) c.setXrayPath(urlDecode(p.get("path")));
        String sni = p.containsKey("sni") ? p.get("sni") : p.get("host");
        if (sni != null) c.setXrayHost(sni);
        if (p.containsKey("fp")) c.setXrayFingerprint(p.get("fp"));
        applyCommonXrayParams(c, p);
    }

    private static void parseSs(ConfigManager c, String link) throws Exception {
        // ss://base64(method:password)@host:port#name
        String body = link.substring("ss://".length());
        String userinfo = "";
        int at = body.indexOf('@');
        String hostPort = at >= 0 ? body.substring(at + 1) : body;
        if (at >= 0) {
            String before = body.substring(0, at);
            if (before.contains(":")) {
                // plaintext method:password
                userinfo = before;
            } else {
                userinfo = b64decode(before);
            }
        } else {
            // ss://base64(method:password@host:port)
            String decoded = b64decode(hostPort);
            int a2 = decoded.indexOf('@');
            if (a2 >= 0) {
                userinfo = decoded.substring(0, a2);
                hostPort = decoded.substring(a2 + 1);
            }
        }
        String[] hp = hostPort.split(":");
        String host = hp.length > 0 ? hp[0] : "";
        int port = hp.length > 1 ? parseInt(hp[1], 443) : 443;
        String[] up = userinfo.split(":");
        String method = up.length > 0 ? up[0] : "";
        String password = up.length > 1 ? up[1] : "";

        c.setXrayProtocol("shadowsocks");
        c.setXraySecurity("none");
        c.setXrayAddress(host);
        c.setXrayPort(port);
        c.setXrayEncryption(method);
        c.setXrayId(password);
    }

    private static void parseXrayJson(ConfigManager c, JSONObject o) throws Exception {
        JSONArray outbounds = o.optJSONArray("outbounds");
        if (outbounds == null || outbounds.length() == 0) return;
        JSONObject out = null;
        for (int i = 0; i < outbounds.length(); i++) {
            JSONObject ob = outbounds.getJSONObject(i);
            String proto = ob.optString("protocol", "");
            if ("vless".equals(proto) || "vmess".equals(proto)
                    || "trojan".equals(proto) || "shadowsocks".equals(proto)) {
                out = ob;
                break;
            }
        }
        if (out == null) return;

        c.setXrayProtocol(out.optString("protocol", "vless"));

        String address = "", id = "", encryption = "", flow = "";
        int port = 443;
        JSONObject settings = out.optJSONObject("settings");
        if (settings != null) {
            JSONArray vnext = settings.optJSONArray("vnext");
            if (vnext != null && vnext.length() > 0) {
                JSONObject v = vnext.getJSONObject(0);
                address = v.optString("address", "");
                port = v.optInt("port", 443);
                JSONArray users = v.optJSONArray("users");
                if (users != null && users.length() > 0) {
                    JSONObject u = users.getJSONObject(0);
                    id = u.optString("id", "");
                    encryption = u.optString("encryption", "");
                    flow = u.optString("flow", "");
                }
            }
            JSONArray servers = settings.optJSONArray("servers");
            if (servers != null && servers.length() > 0) {
                JSONObject s = servers.getJSONObject(0);
                address = s.optString("address", address);
                port = s.optInt("port", port);
                if (id.isEmpty()) id = s.optString("password", "");
            }
        }
        c.setXrayAddress(address);
        c.setXrayPort(port);
        if (!id.isEmpty()) c.setXrayId(id);
        if (!encryption.isEmpty()) c.setXrayEncryption(encryption);
        if (!flow.isEmpty()) c.setXrayFlow(flow);

        JSONObject stream = out.optJSONObject("streamSettings");
        if (stream != null) {
            String network = stream.optString("network", "tcp");
            String security = stream.optString("security", "none");
            c.setXrayTransport(network);
            c.setXraySecurity(security);
            String sni = "";
            if ("reality".equals(security)) {
                JSONObject r = stream.optJSONObject("realitySettings");
                if (r != null) {
                    c.setXrayPublicKey(r.optString("publicKey", ""));
                    c.setXrayShortId(r.optString("shortId", ""));
                    c.setXrayFingerprint(r.optString("fingerprint", ""));
                    sni = r.optString("serverName", "");
                    if (r.optString("spiderX", "").length() > 0) c.setXraySpiderX(r.optString("spiderX", ""));
                    if (r.optBoolean("allowInsecure", false)) c.setXrayAllowInsecure(true);
                    if (r.has("alpn")) c.setXrayAlpn(joinAlpn(r.optJSONArray("alpn")));
                }
            } else if ("tls".equals(security)) {
                JSONObject ts = stream.optJSONObject("tlsSettings");
                if (ts != null) {
                    sni = ts.optString("serverName", "");
                    c.setXrayFingerprint(ts.optString("fingerprint", ""));
                    if (ts.optBoolean("allowInsecure", false)) c.setXrayAllowInsecure(true);
                    if (ts.has("alpn")) c.setXrayAlpn(joinAlpn(ts.optJSONArray("alpn")));
                }
            }
            // headerType для tcp/kcp
            JSONObject tcp = stream.optJSONObject("tcpSettings");
            if (tcp != null && tcp.optJSONObject("header") != null) {
                String ht = tcp.optJSONObject("header").optString("type", "");
                if (!ht.isEmpty()) c.setXrayHeaderType(ht);
            }
            JSONObject kcp = stream.optJSONObject("kcpSettings");
            if (kcp != null && kcp.optJSONObject("header") != null) {
                String ht = kcp.optJSONObject("header").optString("type", "");
                if (!ht.isEmpty()) c.setXrayHeaderType(ht);
            }
            if ("ws".equals(network)) {
                JSONObject ws = stream.optJSONObject("wsSettings");
                if (ws != null) {
                    c.setXrayPath(ws.optString("path", "/"));
                    JSONObject hd = ws.optJSONObject("headers");
                    if (hd != null && hd.optString("Host", "").length() > 0) {
                        sni = hd.optString("Host", sni);
                    }
                }
            } else if ("grpc".equals(network)) {
                JSONObject g = stream.optJSONObject("grpcSettings");
                if (g != null) c.setXrayPath(g.optString("serviceName", "/"));
            } else if ("http".equals(network)) {
                JSONObject h = stream.optJSONObject("httpSettings");
                if (h != null) c.setXrayPath(h.optString("path", "/"));
            }
            if (!sni.isEmpty()) c.setXrayHost(sni);
        }
    }

    // ============================================================
    // Вспомогательные
    // ============================================================

    /** Общие параметры Xray из query-строки share-ссылок: alpn, spiderX, headerType, allowInsecure. */
    private static void applyCommonXrayParams(ConfigManager c, Map<String, String> p) {
        if (p.containsKey("alpn")) c.setXrayAlpn(p.get("alpn"));
        if (p.containsKey("spiderX")) c.setXraySpiderX(p.get("spiderX"));
        if (p.containsKey("headerType")) c.setXrayHeaderType(p.get("headerType"));
        String ai = p.get("allowInsecure");
        if (ai != null && ("1".equals(ai) || "true".equalsIgnoreCase(ai))) {
            c.setXrayAllowInsecure(true);
        }
    }

    private static String[] splitHostPort(String body) {
        // Отрезаем query/fragment
        String s = body;
        int q = s.indexOf('?');
        if (q >= 0) s = s.substring(0, q);
        int hash = s.indexOf('#');
        if (hash >= 0) s = s.substring(0, hash);
        // Отрезаем userinfo (до @) — host:port идут после @
        int at = s.indexOf('@');
        if (at >= 0) s = s.substring(at + 1);
        int colon = s.lastIndexOf(':');
        if (colon >= 0) {
            return new String[]{s.substring(0, colon), s.substring(colon + 1)};
        }
        return new String[]{s, "443"};
    }

    private static Map<String, String> parseQuery(String q) {
        Map<String, String> map = new HashMap<>();
        if (q == null || q.isEmpty()) return map;
        for (String pair : q.split("&")) {
            int eq = pair.indexOf('=');
            if (eq >= 0) {
                map.put(pair.substring(0, eq), urlDecode(pair.substring(eq + 1)));
            }
        }
        return map;
    }

    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private static int parseInt(String s, int def) {
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return def;
        }
    }

    private static String joinAlpn(JSONArray arr) {
        if (arr == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < arr.length(); i++) {
            if (sb.length() > 0) sb.append(",");
            sb.append(arr.optString(i, ""));
        }
        return sb.toString();
    }

    private static String b64decode(String s) {
        try {
            String b = s.replace('-', '+').replace('_', '/');
            int mod = b.length() % 4;
            if (mod == 2) b += "==";
            else if (mod == 3) b += "=";
            return new String(Base64.decode(b, Base64.DEFAULT), "UTF-8");
        } catch (Exception e) {
            return "";
        }
    }
}
