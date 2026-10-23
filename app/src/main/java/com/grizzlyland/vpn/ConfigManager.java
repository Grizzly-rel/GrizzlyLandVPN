package com.grizzlyland.vpn;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashSet;
import java.util.Set;

/**
 * Хранит настройки приложения.
 *
 * Режимы работы:
 *   MODE_XRAY       - только Xray
 *   MODE_OPENVPN    - только OpenVPN (с шифрованием)
 *   MODE_XRAY_OVPN  - Xray + OpenVPN без шифрования (вложенный туннель)
 *   MODE_OVPN_SSH   - OpenVPN через SSH-форвард (аналог ssh -L до OpenVPN-сервера)
 */
public class ConfigManager {

    public static final String MODE_XRAY = "xray";
    public static final String MODE_OPENVPN = "openvpn";
    public static final String MODE_XRAY_OVPN = "xray_openvpn";
    public static final String MODE_XRAY_CUSTOM = "xray_custom";
    /** OpenVPN через SSH-сессию: локальный TCP-форвард порта OpenVPN-сервера (TCP-only). */
    public static final String MODE_OVPN_SSH = "openvpn_ssh";
    /** WireGuard: userspace-движок wireguard-go поверх VpnService TUN. */
    public static final String MODE_WG = "wireguard";
    /**
     * WireGuard через Xray: WG-пакеты шифруются wireguard-outbound'ом Xray,
     * а его UDP к серверу заворачивается в VLESS-туннель (sockopt.dialerProxy) —
     * аналог режима Xray+OpenVPN для WireGuard. UDP через SSH-форвард невозможен
     * (SSH форвардит только TCP), поэтому здесь роль SSH играет xray.
     */
    public static final String MODE_WG_XRAY = "wireguard_xray";
    /**
     * AmneziaWG: отдельный режим поверх движка amneziawg-go (обфусцированный
     * WireGuard). Схема работы — как MODE_WG, но UAPI-конфиг движка дополняется
     * параметрами обфускации Jc/Jmin/Jmax/S1/S2/H1..H4 из конфига.
     */
    public static final String MODE_AWG = "amneziawg";

    private static final String PREFS = "grizzlyland_config";

    private static final String KEY_MODE = "mode";

    // --- Xray ---
    private static final String KEY_X_PROTOCOL = "xray_protocol";
    private static final String KEY_X_SOCKS_PORT = "xray_socks_port";
    private static final String KEY_X_ADDRESS = "xray_address";
    private static final String KEY_X_PORT = "xray_port";
    private static final String KEY_X_ID = "xray_id";
    private static final String KEY_X_SECURITY = "xray_security";
    private static final String KEY_X_TRANSPORT = "xray_transport";
    private static final String KEY_X_PATH = "xray_path";
    private static final String KEY_X_HOST = "xray_host";
    private static final String KEY_X_FLOW = "xray_flow";
    private static final String KEY_X_ENCRYPTION = "xray_encryption";
    private static final String KEY_X_PUBLICKEY = "xray_publickey";
    private static final String KEY_X_SHORTID = "xray_shortid";
    private static final String KEY_X_FINGERPRINT = "xray_fingerprint";
    private static final String KEY_X_DNS = "xray_dns";
    private static final String KEY_X_QUERY_STRATEGY = "xray_query_strategy";
    private static final String KEY_X_ALPN = "xray_alpn";
    private static final String KEY_X_SPIDER_X = "xray_spider_x";
    private static final String KEY_X_HEADER_TYPE = "xray_header_type";
    private static final String KEY_X_ALLOW_INSECURE = "xray_allow_insecure";
    private static final String KEY_X_DOMAIN_STRATEGY = "xray_domain_strategy";
    private static final String KEY_X_CUSTOM_JSON = "xray_custom_json";

    // --- OpenVPN ---
    private static final String KEY_O_PROTOCOL = "ovpn_protocol";
    private static final String KEY_O_CIPHER = "ovpn_cipher";
    private static final String KEY_O_AUTH = "ovpn_auth";
    private static final String KEY_O_REMOTE_HOST = "ovpn_remote_host";
    private static final String KEY_O_REMOTE_PORT = "ovpn_remote_port";
    private static final String KEY_O_CA = "ovpn_ca";
    private static final String KEY_O_CERT = "ovpn_cert";
    private static final String KEY_O_KEY = "ovpn_key";
    private static final String KEY_O_STATIC_KEY = "ovpn_static_key";
    private static final String KEY_O_MTU = "ovpn_mtu";
    private static final String KEY_O_MSSFIX = "ovpn_mssfix";
    private static final String KEY_O_DNS = "ovpn_dns";
    private static final String KEY_O_DEV = "ovpn_dev";
    private static final String KEY_O_REMOTE_CERT_TLS = "ovpn_remote_cert_tls";
    private static final String KEY_O_COMPRESS = "ovpn_compress";
    private static final String KEY_O_ROUTES = "ovpn_routes";
    private static final String KEY_O_REDIRECT = "ovpn_redirect_gateway";
    private static final String KEY_O_KEY_PASSWORD = "ovpn_key_password";
    private static final String KEY_O_USERNAME = "ovpn_username";
    private static final String KEY_O_PASSWORD = "ovpn_password";
    /** Сырой текст импортированного .ovpn (источник истины для OpenVPN-режима). */
    private static final String KEY_O_RAW = "ovpn_raw";
    /** Уровень журналирования Xray: warning / info / debug / error / none. */
    private static final String KEY_X_LOGLEVEL = "xray_loglevel";
    /** verb OpenVPN (детальность логов openvpn). */
    private static final String KEY_O_VERB = "ovpn_verb";
    /** Общий переключатель подробного журнала (debug). */
    private static final String KEY_LOG_DEBUG = "log_debug";

    // --- SSH (режим openvpn_ssh: OpenVPN через SSH-форвард) ---
    private static final String KEY_SSH_HOST = "ssh_host";
    private static final String KEY_SSH_PORT = "ssh_port";
    private static final String KEY_SSH_USER = "ssh_user";
    /** Способ аутентификации на SSH-сервере. */
    private static final String KEY_SSH_AUTH = "ssh_auth";
    private static final String KEY_SSH_PASSWORD = "ssh_password";
    /** Приватный ключ (PEM/OpenSSH-формат) для аутентификации по ключу. */
    private static final String KEY_SSH_KEY = "ssh_key";
    private static final String KEY_SSH_KEY_PASS = "ssh_key_pass";
    /** host:port OpenVPN-сервера, куда sshd ретранслирует (обычно 127.0.0.1:1194 на сервере). */
    private static final String KEY_SSH_TARGET = "ssh_target";
    /** Локальный порт форварда на телефоне (openvpn ходит на 127.0.0.1:<этот порт>). */
    private static final String KEY_SSH_LOCAL_PORT = "ssh_local_port";
    /** TOFU-отпечаток хост-ключа SSH-сервера (анти-MITM; пусто = ещё не зафиксирован). */
    private static final String KEY_SSH_HOSTKEY_FP = "ssh_hostkey_fp";

    /** Аутентификация SSH по паролю. */
    public static final String SSH_AUTH_PASSWORD = "password";
    /** Аутентификация SSH по приватному ключу. */
    public static final String SSH_AUTH_KEY = "key";

    // --- WireGuard (режим wireguard) ---
    /** Сырой wg-quick конфиг (источник истины для режима WireGuard). */
    private static final String KEY_WG_RAW = "wg_raw";

    // --- AmneziaWG (режим amneziawg) ---
    /** Сырой wg-quick конфиг (+ опциональные параметры обфускации). */
    private static final String KEY_A_RAW = "awg_raw";

    private static final String KEY_ALLOWED = "allowed_apps";
    /** Режим «VPN для всего телефона»: per-app список игнорируется. */
    private static final String KEY_ALL_APPS = "vpn_all_apps";

    private final SharedPreferences prefs;

    public ConfigManager(Context context) {
        prefs = context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    // ===== Режим =====
    public String getMode() {
        return prefs.getString(KEY_MODE, MODE_XRAY_OVPN);
    }

    public void setMode(String v) {
        prefs.edit().putString(KEY_MODE, v).apply();
    }

    // ===== Автовосстановление после перезагрузки/падения =====
    /** «Хотел подключён»: ставится при любом подключении, снимается ТОЛЬКО явным
     *  отключением (кнопка/уведомление) или отзывом VPN системой (onRevoke).
     *  По нему BootReceiver и рестарт после падения решают, восстанавливать ли
     *  соединение. Ошибки подключения флаг НЕ снимают (сеть могла ещё не
     *  подняться). В экспорт/импорт настроек НЕ входит (это runtime-состояние). */
    private static final String KEY_WANT_CONNECTED = "vpn_want_connected";

    public boolean getWantConnected() {
        return prefs.getBoolean(KEY_WANT_CONNECTED, false);
    }

    public void setWantConnected(boolean v) {
        prefs.edit().putBoolean(KEY_WANT_CONNECTED, v).apply();
    }

    // ===== SSH (режим OpenVPN-через-SSH) =====
    public String getSshHost() { return prefs.getString(KEY_SSH_HOST, ""); }
    public void setSshHost(String v) { prefs.edit().putString(KEY_SSH_HOST, v == null ? "" : v.trim()).apply(); }

    public int getSshPort() { return prefs.getInt(KEY_SSH_PORT, 22); }
    public void setSshPort(int v) { prefs.edit().putInt(KEY_SSH_PORT, v).apply(); }

    public String getSshUser() { return prefs.getString(KEY_SSH_USER, ""); }
    public void setSshUser(String v) { prefs.edit().putString(KEY_SSH_USER, v == null ? "" : v.trim()).apply(); }

    public String getSshAuth() { return prefs.getString(KEY_SSH_AUTH, SSH_AUTH_PASSWORD); }
    public void setSshAuth(String v) {
        prefs.edit().putString(KEY_SSH_AUTH, SSH_AUTH_KEY.equals(v) ? SSH_AUTH_KEY : SSH_AUTH_PASSWORD).apply();
    }

    public String getSshPassword() { return prefs.getString(KEY_SSH_PASSWORD, ""); }
    public void setSshPassword(String v) { prefs.edit().putString(KEY_SSH_PASSWORD, v == null ? "" : v).apply(); }

    public String getSshKey() { return prefs.getString(KEY_SSH_KEY, ""); }
    public void setSshKey(String v) { prefs.edit().putString(KEY_SSH_KEY, v == null ? "" : v).apply(); }

    public String getSshKeyPass() { return prefs.getString(KEY_SSH_KEY_PASS, ""); }
    public void setSshKeyPass(String v) { prefs.edit().putString(KEY_SSH_KEY_PASS, v == null ? "" : v).apply(); }

    /** Цель форварда на стороне сервера: host:port, куда sshd ретранслирует TCP. */
    public String getSshTarget() { return prefs.getString(KEY_SSH_TARGET, "127.0.0.1:1194"); }
    public void setSshTarget(String v) { prefs.edit().putString(KEY_SSH_TARGET, v == null ? "" : v.trim()).apply(); }

    /** Локальный порт форварда на телефоне; openvpn подключается к 127.0.0.1:<порт>. */
    public int getSshLocalPort() { return prefs.getInt(KEY_SSH_LOCAL_PORT, 11940); }
    public void setSshLocalPort(int v) { prefs.edit().putInt(KEY_SSH_LOCAL_PORT, v).apply(); }

    /** Отпечаток хост-ключа SSH-сервера (TOFU). */
    public String getSshHostKeyFp() { return prefs.getString(KEY_SSH_HOSTKEY_FP, ""); }
    public void setSshHostKeyFp(String v) { prefs.edit().putString(KEY_SSH_HOSTKEY_FP, v == null ? "" : v).apply(); }

    /** Хватает ли настроек для попытки SSH-подключения. */
    public boolean isSshConfigured() {
        return !prefs.getString(KEY_SSH_HOST, "").trim().isEmpty()
                && !prefs.getString(KEY_SSH_USER, "").trim().isEmpty();
    }

    // ===== WireGuard (режим wireguard) =====
    /** Сырой wg-quick конфиг: [Interface]/[Peer] как в стандартном .conf. */
    public String getWgRaw() { return prefs.getString(KEY_WG_RAW, ""); }
    public void setWgRaw(String v) { prefs.edit().putString(KEY_WG_RAW, v == null ? "" : v).apply(); }

    // ===== AmneziaWG (режим amneziawg) =====
    /** Сырой конфиг: [Interface]/[Peer] как в стандартном .conf (+ Jc/Jmin/Jmax/S1/S2/H1..H4). */
    public String getAwgRaw() { return prefs.getString(KEY_A_RAW, ""); }
    public void setAwgRaw(String v) { prefs.edit().putString(KEY_A_RAW, v == null ? "" : v).apply(); }

    // ===== Xray =====
    public String getXrayProtocol() { return prefs.getString(KEY_X_PROTOCOL, "vless"); }
    public void setXrayProtocol(String v) { prefs.edit().putString(KEY_X_PROTOCOL, v).apply(); }

    /** Порт локального SOCKS-прокси Xray (используется и в режиме Xray+OpenVPN). */
    public int getXraySocksPort() { return prefs.getInt(KEY_X_SOCKS_PORT, 10808); }
    public void setXraySocksPort(int v) { prefs.edit().putInt(KEY_X_SOCKS_PORT, v).apply(); }

    public String getXrayAddress() { return prefs.getString(KEY_X_ADDRESS, ""); }
    public void setXrayAddress(String v) { prefs.edit().putString(KEY_X_ADDRESS, v).apply(); }

    public int getXrayPort() { return prefs.getInt(KEY_X_PORT, 443); }
    public void setXrayPort(int v) { prefs.edit().putInt(KEY_X_PORT, v).apply(); }

    public String getXrayId() { return prefs.getString(KEY_X_ID, ""); }
    public void setXrayId(String v) { prefs.edit().putString(KEY_X_ID, v).apply(); }

    public String getXraySecurity() { return prefs.getString(KEY_X_SECURITY, "tls"); }
    public void setXraySecurity(String v) { prefs.edit().putString(KEY_X_SECURITY, v).apply(); }

    public String getXrayTransport() { return prefs.getString(KEY_X_TRANSPORT, "tcp"); }
    public void setXrayTransport(String v) { prefs.edit().putString(KEY_X_TRANSPORT, v).apply(); }

    public String getXrayPath() { return prefs.getString(KEY_X_PATH, "/"); }
    public void setXrayPath(String v) { prefs.edit().putString(KEY_X_PATH, v).apply(); }

    public String getXrayHost() { return prefs.getString(KEY_X_HOST, ""); }
    public void setXrayHost(String v) { prefs.edit().putString(KEY_X_HOST, v).apply(); }

    public String getXrayFlow() { return prefs.getString(KEY_X_FLOW, ""); }
    public void setXrayFlow(String v) { prefs.edit().putString(KEY_X_FLOW, v).apply(); }

    public String getXrayEncryption() { return prefs.getString(KEY_X_ENCRYPTION, "auto"); }
    public void setXrayEncryption(String v) { prefs.edit().putString(KEY_X_ENCRYPTION, v).apply(); }

    public String getXrayPublicKey() { return prefs.getString(KEY_X_PUBLICKEY, ""); }
    public void setXrayPublicKey(String v) { prefs.edit().putString(KEY_X_PUBLICKEY, v).apply(); }

    public String getXrayShortId() { return prefs.getString(KEY_X_SHORTID, ""); }
    public void setXrayShortId(String v) { prefs.edit().putString(KEY_X_SHORTID, v).apply(); }

    public String getXrayFingerprint() { return prefs.getString(KEY_X_FINGERPRINT, "firefox"); }
    public void setXrayFingerprint(String v) { prefs.edit().putString(KEY_X_FINGERPRINT, v).apply(); }

    /** DNS-серверы VPN (через запятую), например "8.8.8.8,8.8.4.4".
     *  Поддерживаются также форматы Xray: "tcp://8.8.8.8", "https://1.1.1.1/dns-query",
     *  "8.8.8.8:853" (DoT) и т.п. — они используются DNS-модулем Xray. */
    public String getXrayDns() { return prefs.getString(KEY_X_DNS, "8.8.8.8,8.8.4.4"); }
    public void setXrayDns(String v) { prefs.edit().putString(KEY_X_DNS, v).apply(); }

    /** Стратегия DNS-запросов Xray: UseIPv4 / UseIP / UseIPv6 / UseSys.
     *  По умолчанию UseIPv4 — tun у нас IPv4-only, AAAA-запросы бесполезны. */
    public String getXrayQueryStrategy() { return prefs.getString(KEY_X_QUERY_STRATEGY, "UseIPv4"); }
    public void setXrayQueryStrategy(String v) { prefs.edit().putString(KEY_X_QUERY_STRATEGY, v).apply(); }

    /**
     * Чистые IP-адреса DNS-серверов (для Android VpnService addDnsServer).
     * Из поля DNS извлекаются только валидные IPv4: для "https://1.1.1.1/dns-query"
     * вернётся "1.1.1.1", для "tcp://8.8.8.8" — "8.8.8.8", для "8.8.8.8:853" — "8.8.8.8".
     * Пусто, если заданы только DoH/TCP без IP.
     */
    public String getXrayDnsPlain() {
        StringBuilder sb = new StringBuilder();
        for (String entry : getXrayDns().split(",")) {
            String ip = extractHostIp(entry.trim());
            if (ip != null) {
                if (sb.length() > 0) sb.append(",");
                sb.append(ip);
            }
        }
        return sb.toString();
    }

    /** Извлекает IPv4-адрес хоста из записи DNS (учитывает scheme, путь, порт). */
    private static String extractHostIp(String entry) {
        if (entry == null) return null;
        String s = entry.trim();
        int scheme = s.indexOf("://");
        if (scheme >= 0) s = s.substring(scheme + 3);
        int slash = s.indexOf('/');
        if (slash >= 0) s = s.substring(0, slash);
        int colon = s.lastIndexOf(':');
        if (colon > 0) {
            String portPart = s.substring(colon + 1);
            if (!portPart.isEmpty() && portPart.matches("\\d+")) s = s.substring(0, colon);
        }
        if (s.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return s;
        return null;
    }

    /** ALPN (через запятую), напр. "h2,http/1.1". Пусто — не задавать. */
    public String getXrayAlpn() { return prefs.getString(KEY_X_ALPN, ""); }
    public void setXrayAlpn(String v) { prefs.edit().putString(KEY_X_ALPN, v).apply(); }

    /** Reality spiderX. Пусто — не задавать. */
    public String getXraySpiderX() { return prefs.getString(KEY_X_SPIDER_X, ""); }
    public void setXraySpiderX(String v) { prefs.edit().putString(KEY_X_SPIDER_X, v).apply(); }

    /** Header type (для tcp/kcp), напр. "none","http","dtls","wireguard". Пусто — не задавать. */
    public String getXrayHeaderType() { return prefs.getString(KEY_X_HEADER_TYPE, ""); }
    public void setXrayHeaderType(String v) { prefs.edit().putString(KEY_X_HEADER_TYPE, v).apply(); }

    /** Разрешить недоверенный сертификат (allowInsecure). */
    public boolean getXrayAllowInsecure() { return prefs.getBoolean(KEY_X_ALLOW_INSECURE, false); }
    public void setXrayAllowInsecure(boolean v) { prefs.edit().putBoolean(KEY_X_ALLOW_INSECURE, v).apply(); }

    /** domainStrategy для outbound, напр. "AsIs","UseIP","UseIPv4","UseIPv6". Пусто — не задавать. */
    public String getXrayDomainStrategy() { return prefs.getString(KEY_X_DOMAIN_STRATEGY, ""); }
    public void setXrayDomainStrategy(String v) { prefs.edit().putString(KEY_X_DOMAIN_STRATEGY, v).apply(); }

    /** Сырой JSON-конфиг Xray для режима "custom" (берётся как есть, inbounds подменяются). */
    public String getXrayCustomJson() { return prefs.getString(KEY_X_CUSTOM_JSON, ""); }
    public void setXrayCustomJson(String v) { prefs.edit().putString(KEY_X_CUSTOM_JSON, v).apply(); }

    // ===== OpenVPN =====
    public String getOvpnProtocol() { return prefs.getString(KEY_O_PROTOCOL, "udp"); }
    public void setOvpnProtocol(String v) { prefs.edit().putString(KEY_O_PROTOCOL, v).apply(); }

    public String getOvpnCipher() { return prefs.getString(KEY_O_CIPHER, "none"); }
    public void setOvpnCipher(String v) { prefs.edit().putString(KEY_O_CIPHER, v).apply(); }

    public String getOvpnAuth() { return prefs.getString(KEY_O_AUTH, "SHA256"); }
    public void setOvpnAuth(String v) { prefs.edit().putString(KEY_O_AUTH, v).apply(); }

    public String getOvpnRemoteHost() { return prefs.getString(KEY_O_REMOTE_HOST, ""); }
    public void setOvpnRemoteHost(String v) { prefs.edit().putString(KEY_O_REMOTE_HOST, v).apply(); }

    public int getOvpnRemotePort() { return prefs.getInt(KEY_O_REMOTE_PORT, 1194); }
    public void setOvpnRemotePort(int v) { prefs.edit().putInt(KEY_O_REMOTE_PORT, v).apply(); }

    public String getOvpnCa() { return prefs.getString(KEY_O_CA, ""); }
    public void setOvpnCa(String v) { prefs.edit().putString(KEY_O_CA, v).apply(); }

    public String getOvpnCert() { return prefs.getString(KEY_O_CERT, ""); }
    public void setOvpnCert(String v) { prefs.edit().putString(KEY_O_CERT, v).apply(); }

    public String getOvpnKey() { return prefs.getString(KEY_O_KEY, ""); }
    public void setOvpnKey(String v) { prefs.edit().putString(KEY_O_KEY, v).apply(); }

    /**
     * Статический ключ OpenVPN (--secret). Если задан — используется режим
     * pre-shared key (как в тестовом сервере /opt/ovpn-test), иначе — PKI (ca/cert/key).
     */
    public String getOvpnStaticKey() { return prefs.getString(KEY_O_STATIC_KEY, ""); }
    public void setOvpnStaticKey(String v) { prefs.edit().putString(KEY_O_STATIC_KEY, v).apply(); }

    /** MTU туннеля (tun-mtu). Пусто — использовать значение по умолчанию. */
    public String getOvpnMtu() { return prefs.getString(KEY_O_MTU, ""); }
    public void setOvpnMtu(String v) { prefs.edit().putString(KEY_O_MTU, v).apply(); }

    /** MSS-fix (mssfix). Пусто — не задавать. */
    public String getOvpnMssfix() { return prefs.getString(KEY_O_MSSFIX, ""); }
    public void setOvpnMssfix(String v) { prefs.edit().putString(KEY_O_MSSFIX, v).apply(); }

    /** DNS-серверы OpenVPN (через запятую). Пусто — использовать xray_dns. */
    public String getOvpnDns() { return prefs.getString(KEY_O_DNS, ""); }
    public void setOvpnDns(String v) { prefs.edit().putString(KEY_O_DNS, v).apply(); }

    /** Тип устройства: tun или tap. */
    public String getOvpnDev() { return prefs.getString(KEY_O_DEV, "tun"); }
    public void setOvpnDev(String v) { prefs.edit().putString(KEY_O_DEV, v).apply(); }

    /** remote-cert-tls: server (проверять сертификат сервера). Пусто — не задавать. */
    public String getOvpnRemoteCertTls() { return prefs.getString(KEY_O_REMOTE_CERT_TLS, ""); }
    public void setOvpnRemoteCertTls(String v) { prefs.edit().putString(KEY_O_REMOTE_CERT_TLS, v).apply(); }

    /** Сжатие (compress/comp-lzo), напр. "lzo","stub","stub-v2". Пусто — не задавать. */
    public String getOvpnCompress() { return prefs.getString(KEY_O_COMPRESS, ""); }
    public void setOvpnCompress(String v) { prefs.edit().putString(KEY_O_COMPRESS, v).apply(); }

    /** Дополнительные маршруты (route, через запятую "net mask" или "net/mask"). */
    public String getOvpnRoutes() { return prefs.getString(KEY_O_ROUTES, ""); }
    public void setOvpnRoutes(String v) { prefs.edit().putString(KEY_O_ROUTES, v).apply(); }

    /** redirect-gateway: весь трафик через туннель. */
    public boolean getOvpnRedirectGateway() { return prefs.getBoolean(KEY_O_REDIRECT, false); }
    public void setOvpnRedirectGateway(boolean v) { prefs.edit().putBoolean(KEY_O_REDIRECT, v).apply(); }

    /** Пароль зашифрованного приватного ключа. Пусто — не задавать. */
    public String getOvpnKeyPassword() { return prefs.getString(KEY_O_KEY_PASSWORD, ""); }
    public void setOvpnKeyPassword(String v) { prefs.edit().putString(KEY_O_KEY_PASSWORD, v).apply(); }

    /** Логин для auth-user-pass. Пусто — не использовать. */
    public String getOvpnUsername() { return prefs.getString(KEY_O_USERNAME, ""); }
    public void setOvpnUsername(String v) { prefs.edit().putString(KEY_O_USERNAME, v).apply(); }

    /** Пароль для auth-user-pass. */
    public String getOvpnPassword() { return prefs.getString(KEY_O_PASSWORD, ""); }
    public void setOvpnPassword(String v) { prefs.edit().putString(KEY_O_PASSWORD, v).apply(); }

    /**
     * Сырой текст импортированного .ovpn. Если задан — OpenVPN-режим работает именно
     * с этим файлом (сохраняя все директивы: tls-crypt/tls-auth, remote-cert-tls и т.д.),
     * а правки по полям вносятся точечно в этот конфиг. Пусто — конфиг собирается из полей.
     */
    public String getOvpnRaw() { return prefs.getString(KEY_O_RAW, ""); }
    public void setOvpnRaw(String v) { prefs.edit().putString(KEY_O_RAW, v == null ? "" : v).apply(); }

    /** Уровень журналирования Xray (warning/info/debug/error/none). */
    public String getXrayLoglevel() { return prefs.getString(KEY_X_LOGLEVEL, "info"); }
    public void setXrayLoglevel(String v) { prefs.edit().putString(KEY_X_LOGLEVEL, v).apply(); }

    /** verb OpenVPN (детальность логов). */
    public int getOvpnVerb() { return prefs.getInt(KEY_O_VERB, 3); }
    public void setOvpnVerb(int v) { prefs.edit().putInt(KEY_O_VERB, v).apply(); }
    /** Начальный verb openvpn: при включённом «Подробном журнале» форсируется 5,
     *  иначе используется пользовательская настройка. Живое переключение в ходе
     *  сессии делает сервис management-командой verb (без рестарта). */
    public int getEffectiveOvpnVerb() { return getLogDebug() ? 5 : getOvpnVerb(); }

    /** Общий переключатель подробного журнала (debug): Xray=debug, OpenVPN verb=5. */
    public boolean getLogDebug() { return prefs.getBoolean(KEY_LOG_DEBUG, false); }
    public void setLogDebug(boolean v) { prefs.edit().putBoolean(KEY_LOG_DEBUG, v).apply(); }

    // ===== Per-app =====
    public Set<String> getAllowedApps() {
        return prefs.getStringSet(KEY_ALLOWED, new HashSet<String>());
    }

    public void setAllowedApps(Set<String> apps) {
        prefs.edit().putStringSet(KEY_ALLOWED, new HashSet<>(apps)).apply();
    }

    /** Режим «VPN для всего телефона»: туннель без allowed-фильтра
     *  (собственный пакет всё равно исключается), per-app список не действует. */
    public boolean getVpnAllApps() { return prefs.getBoolean(KEY_ALL_APPS, false); }

    public void setVpnAllApps(boolean v) { prefs.edit().putBoolean(KEY_ALL_APPS, v).apply(); }

    // ===== Экспорт / импорт настроек (JSON) =====

    /** Сериализует ВСЕ настройки (режим + Xray + OpenVPN + per-app) в JSON-строку. */
    public String exportJson() {
        try {
            JSONObject o = new JSONObject();
            o.put("version", 1);
            o.put("mode", getMode());
            o.put("xray", xrayToJson());
            o.put("openvpn", openvpnToJson());
            o.put("ssh", sshToJson());
            o.put("wg", wgToJson());
            o.put("awg", awgToJson());
            o.put("logDebug", getLogDebug());

            JSONArray apps = new JSONArray();
            for (String a : getAllowedApps()) {
                apps.put(a);
            }
            o.put("allowedApps", apps);
            o.put("allApps", getVpnAllApps());

            return o.toString(2);
        } catch (JSONException e) {
            return "{}";
        }
    }

    /** Сериализует только настройки Xray в JSON-строку. */
    public String exportXrayJson() {
        try {
            JSONObject o = new JSONObject();
            o.put("version", 1);
            o.put("xray", xrayToJson());
            return o.toString(2);
        } catch (JSONException e) {
            return "{}";
        }
    }

    /** Сериализует только настройки OpenVPN в JSON-строку. */
    public String exportOpenVpnJson() {
        try {
            JSONObject o = new JSONObject();
            o.put("version", 1);
            o.put("openvpn", openvpnToJson());
            return o.toString(2);
        } catch (JSONException e) {
            return "{}";
        }
    }

    private JSONObject xrayToJson() throws JSONException {
        JSONObject x = new JSONObject();
        x.put("protocol", getXrayProtocol());
        x.put("address", getXrayAddress());
        x.put("port", getXrayPort());
        x.put("socksPort", getXraySocksPort());
        x.put("id", getXrayId());
        x.put("security", getXraySecurity());
        x.put("transport", getXrayTransport());
        x.put("path", getXrayPath());
        x.put("host", getXrayHost());
        x.put("flow", getXrayFlow());
        x.put("encryption", getXrayEncryption());
        x.put("publicKey", getXrayPublicKey());
        x.put("shortId", getXrayShortId());
        x.put("fingerprint", getXrayFingerprint());
        x.put("dns", getXrayDns());
        x.put("queryStrategy", getXrayQueryStrategy());
        x.put("alpn", getXrayAlpn());
        x.put("spiderX", getXraySpiderX());
        x.put("headerType", getXrayHeaderType());
        x.put("allowInsecure", getXrayAllowInsecure());
        x.put("domainStrategy", getXrayDomainStrategy());
        x.put("customJson", getXrayCustomJson());
        x.put("loglevel", getXrayLoglevel());
        return x;
    }

    private JSONObject openvpnToJson() throws JSONException {
        JSONObject ov = new JSONObject();
        ov.put("protocol", getOvpnProtocol());
        ov.put("cipher", getOvpnCipher());
        ov.put("auth", getOvpnAuth());
        ov.put("remoteHost", getOvpnRemoteHost());
        ov.put("remotePort", getOvpnRemotePort());
        ov.put("ca", getOvpnCa());
        ov.put("cert", getOvpnCert());
        ov.put("key", getOvpnKey());
        ov.put("staticKey", getOvpnStaticKey());
        ov.put("mtu", getOvpnMtu());
        ov.put("mssfix", getOvpnMssfix());
        ov.put("dns", getOvpnDns());
        ov.put("dev", getOvpnDev());
        ov.put("remoteCertTls", getOvpnRemoteCertTls());
        ov.put("compress", getOvpnCompress());
        ov.put("routes", getOvpnRoutes());
        ov.put("redirectGateway", getOvpnRedirectGateway());
        ov.put("keyPassword", getOvpnKeyPassword());
        ov.put("username", getOvpnUsername());
        ov.put("password", getOvpnPassword());
        ov.put("raw", getOvpnRaw());
        ov.put("verb", getOvpnVerb());
        return ov;
    }

    /**
     * Применяет ВСЕ настройки из JSON-строки, полученной {@link #exportJson()}.
     * Отсутствующие в файле разделы/поля оставляет как есть (не сбрасывает их).
     */
    public void importJson(String json) throws JSONException {
        JSONObject o = new JSONObject(json);

        if (o.has("mode")) {
            setMode(o.getString("mode"));
        }

        JSONObject x = o.optJSONObject("xray");
        if (x != null) {
            applyXray(x);
        }

        JSONObject ov = o.optJSONObject("openvpn");
        if (ov != null) {
            applyOpenVpn(ov);
        }

        JSONObject ssh = o.optJSONObject("ssh");
        if (ssh != null) {
            applySsh(ssh);
        }

        JSONObject wg = o.optJSONObject("wg");
        if (wg != null) {
            applyWg(wg);
        }

        JSONObject awg = o.optJSONObject("awg");
        if (awg != null) {
            applyAwg(awg);
        }

        if (o.has("logDebug")) {
            setLogDebug(o.getBoolean("logDebug"));
        }

        JSONArray apps = o.optJSONArray("allowedApps");
        if (apps != null) {
            Set<String> s = new HashSet<>();
            for (int i = 0; i < apps.length(); i++) {
                s.add(apps.getString(i));
            }
            setAllowedApps(s);
        }

        if (o.has("allApps")) {
            setVpnAllApps(o.getBoolean("allApps"));
        }
    }

    /** Применяет только настройки Xray из JSON-строки, полученной {@link #exportXrayJson()}. */
    public void importXrayJson(String json) throws JSONException {
        JSONObject o = new JSONObject(json);
        JSONObject x = o.optJSONObject("xray");
        if (x != null) {
            applyXray(x);
        }
    }

    /** Применяет только настройки OpenVPN из JSON-строки, полученной {@link #exportOpenVpnJson()}. */
    public void importOpenVpnJson(String json) throws JSONException {
        JSONObject o = new JSONObject(json);
        JSONObject ov = o.optJSONObject("openvpn");
        if (ov != null) {
            applyOpenVpn(ov);
        }
    }

    private void applyXray(JSONObject x) throws JSONException {
        if (x.has("protocol")) setXrayProtocol(x.getString("protocol"));
        if (x.has("address")) setXrayAddress(x.getString("address"));
        if (x.has("port")) setXrayPort(x.getInt("port"));
        if (x.has("socksPort")) setXraySocksPort(x.getInt("socksPort"));
        if (x.has("id")) setXrayId(x.getString("id"));
        if (x.has("security")) setXraySecurity(x.getString("security"));
        if (x.has("transport")) setXrayTransport(x.getString("transport"));
        if (x.has("path")) setXrayPath(x.getString("path"));
        if (x.has("host")) setXrayHost(x.getString("host"));
        if (x.has("flow")) setXrayFlow(x.getString("flow"));
        if (x.has("encryption")) setXrayEncryption(x.getString("encryption"));
        if (x.has("publicKey")) setXrayPublicKey(x.getString("publicKey"));
        if (x.has("shortId")) setXrayShortId(x.getString("shortId"));
        if (x.has("fingerprint")) setXrayFingerprint(x.getString("fingerprint"));
        if (x.has("dns")) setXrayDns(x.getString("dns"));
        if (x.has("queryStrategy")) setXrayQueryStrategy(x.getString("queryStrategy"));
        if (x.has("alpn")) setXrayAlpn(x.getString("alpn"));
        if (x.has("spiderX")) setXraySpiderX(x.getString("spiderX"));
        if (x.has("headerType")) setXrayHeaderType(x.getString("headerType"));
        if (x.has("allowInsecure")) setXrayAllowInsecure(x.getBoolean("allowInsecure"));
        if (x.has("domainStrategy")) setXrayDomainStrategy(x.getString("domainStrategy"));
        if (x.has("customJson")) setXrayCustomJson(x.getString("customJson"));
        if (x.has("loglevel")) setXrayLoglevel(x.getString("loglevel"));
    }

    private void applyOpenVpn(JSONObject ov) throws JSONException {
        if (ov.has("protocol")) setOvpnProtocol(ov.getString("protocol"));
        if (ov.has("cipher")) setOvpnCipher(ov.getString("cipher"));
        if (ov.has("auth")) setOvpnAuth(ov.getString("auth"));
        if (ov.has("remoteHost")) setOvpnRemoteHost(ov.getString("remoteHost"));
        if (ov.has("remotePort")) setOvpnRemotePort(ov.getInt("remotePort"));
        if (ov.has("ca")) setOvpnCa(ov.getString("ca"));
        if (ov.has("cert")) setOvpnCert(ov.getString("cert"));
        if (ov.has("key")) setOvpnKey(ov.getString("key"));
        if (ov.has("staticKey")) setOvpnStaticKey(ov.getString("staticKey"));
        if (ov.has("mtu")) setOvpnMtu(ov.getString("mtu"));
        if (ov.has("mssfix")) setOvpnMssfix(ov.getString("mssfix"));
        if (ov.has("dns")) setOvpnDns(ov.getString("dns"));
        if (ov.has("dev")) setOvpnDev(ov.getString("dev"));
        if (ov.has("remoteCertTls")) setOvpnRemoteCertTls(ov.getString("remoteCertTls"));
        if (ov.has("compress")) setOvpnCompress(ov.getString("compress"));
        if (ov.has("routes")) setOvpnRoutes(ov.getString("routes"));
        if (ov.has("redirectGateway")) setOvpnRedirectGateway(ov.getBoolean("redirectGateway"));
        if (ov.has("keyPassword")) setOvpnKeyPassword(ov.getString("keyPassword"));
        if (ov.has("username")) setOvpnUsername(ov.getString("username"));
        if (ov.has("password")) setOvpnPassword(ov.getString("password"));
        if (ov.has("raw")) setOvpnRaw(ov.getString("raw"));
        if (ov.has("verb")) setOvpnVerb(ov.getInt("verb"));
    }

    private JSONObject sshToJson() throws JSONException {
        JSONObject s = new JSONObject();
        s.put("host", getSshHost());
        s.put("port", getSshPort());
        s.put("user", getSshUser());
        s.put("auth", getSshAuth());
        s.put("password", getSshPassword());
        s.put("key", getSshKey());
        s.put("keyPass", getSshKeyPass());
        s.put("target", getSshTarget());
        s.put("localPort", getSshLocalPort());
        s.put("hostKeyFp", getSshHostKeyFp());
        return s;
    }

    private void applySsh(JSONObject s) throws JSONException {
        if (s.has("host")) setSshHost(s.getString("host"));
        if (s.has("port")) setSshPort(s.getInt("port"));
        if (s.has("user")) setSshUser(s.getString("user"));
        if (s.has("auth")) setSshAuth(s.getString("auth"));
        if (s.has("password")) setSshPassword(s.getString("password"));
        if (s.has("key")) setSshKey(s.getString("key"));
        if (s.has("keyPass")) setSshKeyPass(s.getString("keyPass"));
        if (s.has("target")) setSshTarget(s.getString("target"));
        if (s.has("localPort")) setSshLocalPort(s.getInt("localPort"));
        if (s.has("hostKeyFp")) setSshHostKeyFp(s.getString("hostKeyFp"));
    }

    private JSONObject wgToJson() throws JSONException {
        JSONObject w = new JSONObject();
        w.put("raw", getWgRaw());
        return w;
    }

    private void applyWg(JSONObject w) throws JSONException {
        if (w.has("raw")) setWgRaw(w.getString("raw"));
    }

    private JSONObject awgToJson() throws JSONException {
        JSONObject a = new JSONObject();
        a.put("raw", getAwgRaw());
        return a;
    }

    private void applyAwg(JSONObject a) throws JSONException {
        if (a.has("raw")) setAwgRaw(a.getString("raw"));
    }
}
