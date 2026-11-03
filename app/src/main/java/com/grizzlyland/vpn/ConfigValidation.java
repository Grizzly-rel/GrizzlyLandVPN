package com.grizzlyland.vpn;

import android.app.Activity;
import android.app.AlertDialog;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Проверка «похоже ли это на конфиг данного сервиса» ПЕРЕД сохранением.
 *
 * Правило приложения: конфиг (откуда бы он ни приходил — QR, файл, ручной
 * ввод) сохраняется ТОЛЬКО по кнопке «Сохранить». Если проверка не прошла —
 * ничего не сохраняется и не применяется, показывается список причин.
 */
public final class ConfigValidation {

    private ConfigValidation() {
    }

    /** Диалог «НЕ сохранено» со списком причин (вызывается вместо сохранения). */
    public static void showNotSaved(Activity a, List<String> reasons) {
        StringBuilder sb = new StringBuilder();
        for (String r : reasons) {
            if (sb.length() > 0) {
                sb.append('\n');
            }
            sb.append("• ").append(r);
        }
        new AlertDialog.Builder(a)
                .setTitle(a.getString(R.string.err_not_saved_title))
                .setMessage(sb.toString())
                .setPositiveButton(a.getString(R.string.btn_close), null)
                .show();
    }

    // ===== WireGuard / AmneziaWG (текст wg-quick) =====

    /**
     * Причины, по которым текст не является рабочим wg-quick конфигом
     * (формат одинаков для WireGuard и AmneziaWG). Пустое поле — осознанная
     * очистка конфига, ошибкой не считается.
     */
    public static List<String> wgProblems(String text) {
        return wgProblems(text, false);
    }

    /**
     * То же с выбором парсера значений: для AmneziaWG используется
     * AwgConfigParser — он дополнительно проверяет параметры обфускации
     * (Jc/Jmin/Jmax/S1/S2/H1..H4), которых в обычном WireGuard нет.
     * Формат текста — надмножество wg-quick, обычные WG-конфиги проходят.
     */
    public static List<String> wgProblems(String text, boolean awg) {
        List<String> errs = new ArrayList<>();
        if (text == null || text.trim().isEmpty()) {
            return errs;
        }
        // UTF-8 BOM (файлы из Windows-редакторов) не должен ломать разбор.
        text = text.replace("\uFEFF", "");
        boolean inInterface = false, hasInterface = false;
        boolean hasPriv = false, hasPeer = false, hasPeerPub = false;
        for (String rawLine : text.split("\n")) {
            String line = rawLine.trim();
            int hash = line.indexOf('#');
            if (hash >= 0) {
                line = line.substring(0, hash).trim();
            }
            if (line.isEmpty() || line.startsWith(";")) {
                continue;
            }
            if (line.startsWith("[")) {
                String sec = line.substring(1, line.indexOf(']') > 1
                        ? line.indexOf(']') : line.length()).trim().toLowerCase();
                inInterface = sec.equals("interface");
                if (inInterface) {
                    hasInterface = true;
                }
                if (sec.equals("peer")) {
                    hasPeer = true;
                }
                continue;
            }
            int eq = line.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String key = line.substring(0, eq).trim().toLowerCase()
                    .replace("-", "").replace("_", "");
            String val = line.substring(eq + 1).trim();
            if (val.isEmpty()) {
                continue;
            }
            if (inInterface && key.equals("privatekey")) {
                hasPriv = true;
            }
            if (!inInterface && key.equals("publickey")) {
                hasPeerPub = true;
            }
        }
        if (!hasInterface) {
            errs.add(L10n.s(R.string.err_wg_no_iface));
        } else if (!hasPriv) {
            errs.add(L10n.s(R.string.err_wg_no_private_key));
        }
        if (!hasPeerPub) {
            errs.add(L10n.s(hasPeer ? R.string.err_wg_peer_no_pubkey
                    : R.string.err_wg_no_peer));
        }
        // Ошибки значений (не-base64 ключи, кривые параметры обфускации и пр.) —
        // полным парсером приложения.
        String parseError = awg
                ? AwgConfigParser.parse(text).parseError
                : WgConfigParser.parse(text).parseError;
        if (!parseError.isEmpty()) {
            errs.add(parseError);
        }
        return errs;
    }

    // ===== Xray (поля формы + custom JSON) =====

    /**
     * Причины по экрану Xray. Если заполнен Custom JSON — он один отвечает за
     * конфиг (режим «Xray (свой JSON)»), достаточно валидного JSON. Иначе
     * нужны адрес и ID (для протоколов socks/http ID не требуется).
     */
    public static List<String> xrayProblems(String protocol, String address,
            String port, String socksPort, String id, String customJson) {
        List<String> errs = new ArrayList<>();
        // Локальный SOCKS-порт ядра нужен в любом режиме.
        portErr(errs, L10n.s(R.string.label_socks_port), socksPort);
        String cj = customJson == null ? "" : customJson.trim();
        boolean custom = !cj.isEmpty();
        if (custom) {
            try {
                new JSONObject(cj);
            } catch (Exception e) {
                errs.add(L10n.s(R.string.err_xray_bad_json));
            }
            if (port != null && !port.trim().isEmpty()) {
                portErr(errs, L10n.s(R.string.label_port), port);
            }
        } else {
            // Обычный режим: адрес, ID и порт сервера обязательны.
            portErr(errs, L10n.s(R.string.label_port), port);
            if (address == null || address.trim().isEmpty()) {
                errs.add(L10n.s(R.string.err_xray_no_address));
            }
            if ((id == null || id.trim().isEmpty())
                    && !"socks".equals(protocol) && !"http".equals(protocol)) {
                errs.add(L10n.s(R.string.err_xray_no_id));
            }
        }
        return errs;
    }

    // ===== OpenVPN (импортированный .ovpn + поля формы) =====

    private static final Pattern REMOTE = Pattern.compile("(?im)^\\s*remote[ \\t]+\\S");
    /** Инлайн-блоки с ключевым материалом: CA/сертификат/ключ/статический ключ.
     *  auth-user-pass, tls-auth, tls-crypt материалом НЕ считаются —
     *  TLS-режим OpenVPN без CA/статического ключа не работает. */
    private static final Pattern INLINE_BLOCKS = Pattern.compile(
            "(?is)<\\s*(ca|cert|key|secret)\\s*>");
    /** Директивы-файлы (ca ca.crt и пр.); [ \\t] чтобы не перескакивать строку. */
    private static final Pattern FILE_DIRECTIVES = Pattern.compile(
            "(?im)^\\s*(ca|cert|key|secret)[ \\t]+\\S");

    /** Причины по .ovpn (raw — импортированный или сохранённый) и полям формы. */
    public static List<String> ovpnProblems(String host, String raw,
            String ca, String cert, String key, String staticKey) {
        List<String> errs = new ArrayList<>();
        String r = raw == null ? "" : raw;
        boolean hostEmpty = host == null || host.trim().isEmpty();
        if (hostEmpty && !REMOTE.matcher(r).find()) {
            errs.add(L10n.s(R.string.err_ovpn_no_remote));
        }
        boolean hasMaterial = INLINE_BLOCKS.matcher(r).find()
                || FILE_DIRECTIVES.matcher(r).find()
                || nonEmpty(ca) || nonEmpty(cert) || nonEmpty(key) || nonEmpty(staticKey);
        if (!hasMaterial) {
            errs.add(L10n.s(R.string.err_ovpn_no_key_material));
        }
        return errs;
    }

    // ===== SSH (поля формы) =====

    /** Причины по экрану SSH. */
    public static List<String> sshProblems(String host, String port, String localPort,
            boolean keyAuth, String key) {
        List<String> errs = new ArrayList<>();
        if (host == null || host.trim().isEmpty()) {
            errs.add(L10n.s(R.string.err_ssh_no_host));
        }
        portErr(errs, L10n.s(R.string.label_ssh_port), port);
        portErr(errs, L10n.s(R.string.label_ssh_local_port), localPort);
        if (keyAuth && (key == null || key.trim().isEmpty())) {
            errs.add(L10n.s(R.string.err_ssh_no_key));
        }
        return errs;
    }

    // ===== утилиты =====

    /** Причина «порт пуст/не число/вне диапазона» с именем поля. */
    public static void portErr(List<String> errs, String label, String value) {
        if (value == null || value.trim().isEmpty()) {
            errs.add(L10n.s(R.string.err_port_empty, label));
            return;
        }
        try {
            int p = Integer.parseInt(value.trim());
            if (p >= 1 && p <= 65535) {
                return;
            }
        } catch (NumberFormatException ignored) {
        }
        errs.add(L10n.s(R.string.err_port_bad, label));
    }

    /** Похоже ли на Xray-конфиг: share-ссылка или JSON с outbounds/xray. */
    public static boolean looksLikeXray(String text) {
        String t = text == null ? "" : text.trim();
        if (t.startsWith("vless://") || t.startsWith("vmess://")
                || t.startsWith("trojan://") || t.startsWith("ss://")) {
            return true;
        }
        if (t.startsWith("{")) {
            try {
                JSONObject o = new JSONObject(t);
                return o.has("outbounds") || o.has("xray") || o.has("inbounds");
            } catch (Exception e) {
                return false;
            }
        }
        return false;
    }

    /** Похоже ли на .ovpn: директива remote, инлайн-блоки или прежний JSON-экспорт. */
    public static boolean looksLikeOvpn(String text) {
        String t = text == null ? "" : text;
        return REMOTE.matcher(t).find() || INLINE_BLOCKS.matcher(t).find()
                || t.trim().startsWith("{");
    }

    private static boolean nonEmpty(String s) {
        return s != null && !s.trim().isEmpty();
    }
}
