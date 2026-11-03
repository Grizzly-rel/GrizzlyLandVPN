package com.grizzlyland.vpn;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

/**
 * Все варианты настроек Xray: протокол, security, транспорт и параметры.
 */
public class XraySettingsActivity extends Activity {

    private static final int REQ_EXPORT = 2101;
    private static final int REQ_IMPORT = 2102;
    /** Отдельное хранилище-«черновик» для импорта (основной конфиг не пишется). */
    private static final String STAGING_PREFS = "config_import_staging";

    private ConfigManager config;

    private Spinner protocol;
    private Spinner security;
    private Spinner transport;
    private Spinner flow;
    private Spinner encryption;
    private EditText address;
    private EditText port;
    private EditText socksPort;
    private EditText id;
    private EditText path;
    private EditText host;
    private EditText publicKey;
    private EditText shortId;
    private Spinner fingerprint;
    private EditText dns;
    private Spinner queryStrategy;
    private EditText alpn;
    private EditText spiderX;
    private EditText headerType;
    private android.widget.CheckBox allowInsecure;
    private EditText domainStrategy;
    private android.widget.EditText customJson;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        L10n.init(this);
        config = new ConfigManager(this);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 32, 32, 32);

        TextView title = new TextView(this);
        title.setText(getString(R.string.xray_settings));
        title.setTextSize(24);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        // Кнопки импорта/экспорта — сверху раздела.
        LinearLayout io = new LinearLayout(this);
        io.setOrientation(LinearLayout.HORIZONTAL);

        Button importBtn = new Button(this);
        importBtn.setText(getString(R.string.btn_import_xray));
        importBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                importConfig();
            }
        });
        io.addView(importBtn, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        Button exportBtn = new Button(this);
        exportBtn.setText(getString(R.string.btn_export_xray));
        exportBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                exportConfig();
            }
        });
        io.addView(exportBtn, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        root.addView(io, lp());

        protocol = addSpinner(root, getString(R.string.label_protocol),
                new String[]{"vless", "vmess", "trojan", "shadowsocks", "socks", "http"},
                config.getXrayProtocol());

        address = addField(root, getString(R.string.label_address), config.getXrayAddress());
        port = addField(root, getString(R.string.label_port), String.valueOf(config.getXrayPort()));
        socksPort = addField(root, getString(R.string.label_socks_port),
                String.valueOf(config.getXraySocksPort()));
        id = addField(root, getString(R.string.label_id), config.getXrayId());

        security = addSpinner(root, "Security",
                new String[]{"none", "tls", "reality", "xtls"},
                config.getXraySecurity());

        transport = addSpinner(root, getString(R.string.label_transport),
                new String[]{"tcp", "ws", "grpc", "httpupgrade", "xhttp", "http", "h2", "kcp", "quic"},
                config.getXrayTransport());

        path = addField(root, getString(R.string.label_path), config.getXrayPath());
        host = addField(root, getString(R.string.label_host_sni), config.getXrayHost());

        flow = addSpinner(root, "Flow (VLESS)",
                new String[]{"none", "xtls-rprx-vision"},
                config.getXrayFlow());

        encryption = addSpinner(root, "Encryption (VMess)",
                new String[]{"auto", "aes-128-gcm", "chacha20-poly1305", "none"},
                config.getXrayEncryption());

        publicKey = addField(root, "Reality publicKey", config.getXrayPublicKey());
        shortId = addField(root, "Reality shortId", config.getXrayShortId());
        fingerprint = addSpinner(root, "Reality fingerprint",
                new String[]{"chrome", "firefox", "safari", "random"},
                config.getXrayFingerprint());

        dns = addField(root, getString(R.string.label_dns_servers),
                config.getXrayDns());
        queryStrategy = addSpinner(root, "DNS queryStrategy",
                new String[]{"UseIPv4", "UseIP", "UseIPv6", "UseSys"},
                config.getXrayQueryStrategy());
        alpn = addField(root, getString(R.string.label_alpn), config.getXrayAlpn());
        spiderX = addField(root, "Reality spiderX", config.getXraySpiderX());
        headerType = addField(root, getString(R.string.label_header_type), config.getXrayHeaderType());
        domainStrategy = addField(root, getString(R.string.label_domain_strategy), config.getXrayDomainStrategy());

        TextView aiLabel = new TextView(this);
        aiLabel.setText(getString(R.string.label_allow_insecure));
        root.addView(aiLabel);
        allowInsecure = new android.widget.CheckBox(this);
        allowInsecure.setChecked(config.getXrayAllowInsecure());
        root.addView(allowInsecure, lp());

        // Уровень журнала Xray управляется кнопкой «Подробный журнал» на экране
        // журнала (info ↔ debug, перезапуск ядра на лету) — спиннер убран.

        // --- Custom JSON (необязательно; используется в режиме "Xray") ---
        TextView customLabel = new TextView(this);
        customLabel.setText(getString(R.string.label_custom_json));
        customLabel.setTextSize(14);
        root.addView(customLabel);
        customJson = new android.widget.EditText(this);
        customJson.setMinLines(8);
        customJson.setGravity(android.view.Gravity.TOP | android.view.Gravity.START);
        customJson.setText(config.getXrayCustomJson());
        root.addView(customJson, lp());

        Button save = new Button(this);
        save.setText(getString(R.string.btn_save));
        save.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                save();
            }
        });
        root.addView(save, lp());

        ScrollView scroll = new ScrollView(this);
        scroll.addView(root);
        setContentView(scroll);
    }

    private Spinner addSpinner(LinearLayout root, String label, String[] values, String current) {
        TextView tv = new TextView(this);
        tv.setText(label);
        root.addView(tv);
        Spinner sp = new Spinner(this);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_dropdown_item, values);
        sp.setAdapter(adapter);
        int idx = 0;
        for (int i = 0; i < values.length; i++) {
            if (values[i].equals(current)) {
                idx = i;
                break;
            }
        }
        sp.setSelection(idx);
        root.addView(sp, lp());
        return sp;
    }

    private EditText addField(LinearLayout root, String label, String value) {
        TextView tv = new TextView(this);
        tv.setText(label);
        root.addView(tv);
        EditText et = new EditText(this);
        et.setText(value);
        root.addView(et, lp());
        return et;
    }

    private void exportConfig() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/json");
        intent.putExtra(Intent.EXTRA_TITLE, "grizzlylandvpn_xray.json");
        startActivityForResult(intent, REQ_EXPORT);
    }

    private void importConfig() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        startActivityForResult(intent, REQ_IMPORT);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            return;
        }
        Uri uri = data.getData();
        if (requestCode == REQ_EXPORT) {
            try (OutputStream os = getContentResolver().openOutputStream(uri)) {
                os.write(config.exportXrayJson().getBytes("UTF-8"));
                Toast.makeText(this, getString(R.string.toast_xray_exported), Toast.LENGTH_SHORT).show();
            } catch (Exception e) {
                Toast.makeText(this, getString(R.string.toast_export_error, e.getMessage()), Toast.LENGTH_LONG).show();
            }
        } else if (requestCode == REQ_IMPORT) {
            try (InputStream is = getContentResolver().openInputStream(uri)) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) {
                    bos.write(buf, 0, n);
                }
                stageImportedConfig(new String(bos.toByteArray(), "UTF-8"));
            } catch (Exception e) {
                Toast.makeText(this, getString(R.string.toast_import_error, e.getMessage()), Toast.LENGTH_LONG).show();
            }
        }
    }

    /**
     * Импортированный конфиг только ЗАПОЛНЯЕТ форму: парсер пишет в отдельное
     * staging-хранилище (с затравкой текущими значениями), форма перечитывается
     * из него. Основной конфиг не пишется и не применяется — сохранение только
     * по кнопке «Сохранить».
     */
    private void stageImportedConfig(String text) {
        try {
            ConfigManager staged = new ConfigManager(this, STAGING_PREFS);
            staged.clearAll();
            // Затравка текущими значениями: поля, которые парсер не заполнит,
            // остаются как в сохранённом конфиге, а не сбрасываются в дефолт.
            staged.importXrayJson(config.exportXrayJson());
            ConfigParser.applyXray(staged, text);
            refreshFromConfig(staged);
            staged.clearAll();
            if (ConfigValidation.looksLikeXray(text)) {
                Toast.makeText(this, getString(R.string.toast_import_staged), Toast.LENGTH_LONG).show();
            } else {
                Toast.makeText(this, getString(R.string.warn_import_not_looks_like,
                        getString(R.string.svc_xray)), Toast.LENGTH_LONG).show();
            }
        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.toast_import_error, e.getMessage()),
                    Toast.LENGTH_LONG).show();
        }
    }

    /** Перечитывает поля из указанного хранилища (после импорта — из staging). */
    private void refreshFromConfig(ConfigManager src) {
        setSpinner(protocol, src.getXrayProtocol());
        setSpinner(security, src.getXraySecurity());
        setSpinner(transport, src.getXrayTransport());
        setSpinner(flow, src.getXrayFlow());
        setSpinner(encryption, src.getXrayEncryption());
        setSpinner(fingerprint, src.getXrayFingerprint());
        address.setText(src.getXrayAddress());
        port.setText(String.valueOf(src.getXrayPort()));
        socksPort.setText(String.valueOf(src.getXraySocksPort()));
        id.setText(src.getXrayId());
        path.setText(src.getXrayPath());
        host.setText(src.getXrayHost());
        publicKey.setText(src.getXrayPublicKey());
        shortId.setText(src.getXrayShortId());
        dns.setText(src.getXrayDns());
        setSpinner(queryStrategy, src.getXrayQueryStrategy());
        alpn.setText(src.getXrayAlpn());
        spiderX.setText(src.getXraySpiderX());
        headerType.setText(src.getXrayHeaderType());
        domainStrategy.setText(src.getXrayDomainStrategy());
        allowInsecure.setChecked(src.getXrayAllowInsecure());
        customJson.setText(src.getXrayCustomJson());
    }

    private void setSpinner(Spinner sp, String value) {
        for (int i = 0; i < sp.getAdapter().getCount(); i++) {
            String item = sp.getAdapter().getItem(i).toString();
            if (item.equalsIgnoreCase(value)) {
                sp.setSelection(i);
                return;
            }
        }
    }

    private void save() {
        List<String> errors = ConfigValidation.xrayProblems(
                protocol.getSelectedItem().toString(),
                address.getText().toString().trim(),
                port.getText().toString().trim(),
                socksPort.getText().toString().trim(),
                id.getText().toString().trim(),
                customJson.getText().toString());
        if (!errors.isEmpty()) {
            // НЕ сохраняем и НЕ применяем: сохранённый конфиг не тронут.
            ConfigValidation.showNotSaved(this, errors);
            return;
        }
        try {
            config.setXrayProtocol(protocol.getSelectedItem().toString());
            config.setXraySecurity(security.getSelectedItem().toString());
            config.setXrayTransport(transport.getSelectedItem().toString());
            config.setXrayFlow(flow.getSelectedItem().toString());
            config.setXrayEncryption(encryption.getSelectedItem().toString());
            config.setXrayAddress(address.getText().toString().trim());
            config.setXrayPort(Integer.parseInt(port.getText().toString().trim()));
            config.setXraySocksPort(Integer.parseInt(socksPort.getText().toString().trim()));
            config.setXrayId(id.getText().toString().trim());
            config.setXrayPath(path.getText().toString().trim());
            config.setXrayHost(host.getText().toString().trim());
            config.setXrayPublicKey(publicKey.getText().toString().trim());
            config.setXrayShortId(shortId.getText().toString().trim());
            config.setXrayFingerprint(fingerprint.getSelectedItem().toString());
            config.setXrayDns(dns.getText().toString().trim());
            config.setXrayQueryStrategy(queryStrategy.getSelectedItem().toString());
            config.setXrayAlpn(alpn.getText().toString().trim());
            config.setXraySpiderX(spiderX.getText().toString().trim());
            config.setXrayHeaderType(headerType.getText().toString().trim());
            config.setXrayAllowInsecure(allowInsecure.isChecked());
            config.setXrayDomainStrategy(domainStrategy.getText().toString().trim());
            config.setXrayCustomJson(customJson.getText().toString());
            GrizzlyLandVpnService.requestApply(this);
            Toast.makeText(this, getString(R.string.toast_saved), Toast.LENGTH_SHORT).show();
            finish();
        } catch (NumberFormatException e) {
            Toast.makeText(this, getString(R.string.toast_bad_port), Toast.LENGTH_SHORT).show();
        }
    }

    private LinearLayout.LayoutParams lp() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }
}
