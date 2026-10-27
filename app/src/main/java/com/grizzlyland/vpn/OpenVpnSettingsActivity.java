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

/**
 * Все варианты настроек OpenVPN: протокол, шифрование, auth, сертификаты.
 */
public class OpenVpnSettingsActivity extends Activity {

    private static final int REQ_EXPORT = 2201;
    private static final int REQ_IMPORT = 2202;

    private ConfigManager config;

    private Spinner protocol;
    private Spinner cipher;
    private Spinner auth;
    private EditText remoteHost;
    private EditText remotePort;
    private EditText ca;
    private EditText cert;
    private EditText key;
    private EditText staticKey;
    private EditText mtu;
    private EditText mssfix;
    private EditText dns;
    private Spinner dev;
    private EditText remoteCertTls;
    private EditText compress;
    private EditText routes;
    private android.widget.CheckBox redirect;
    private EditText keyPassword;
    private EditText username;
    private EditText password;
    private EditText verb;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        L10n.init(this);
        config = new ConfigManager(this);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 32, 32, 32);

        TextView title = new TextView(this);
        title.setText(getString(R.string.openvpn_settings));
        title.setTextSize(24);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        // Кнопки импорта/экспорта — сверху раздела.
        LinearLayout io = new LinearLayout(this);
        io.setOrientation(LinearLayout.HORIZONTAL);

        Button importBtn = new Button(this);
        importBtn.setText(getString(R.string.btn_import_ovpn));
        importBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                importConfig();
            }
        });
        io.addView(importBtn, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        Button exportBtn = new Button(this);
        exportBtn.setText(getString(R.string.btn_export_ovpn));
        exportBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                exportConfig();
            }
        });
        io.addView(exportBtn, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        root.addView(io, lp());

        protocol = addSpinner(root, getString(R.string.label_protocol),
                new String[]{"udp", "tcp"}, config.getOvpnProtocol());

        cipher = addSpinner(root, getString(R.string.label_cipher),
                new String[]{
                        "none",                       // без шифрования (для режима Xray+OpenVPN)
                        "AES-256-GCM", "AES-128-GCM",
                        "AES-256-CBC", "AES-128-CBC",
                        "CHACHA20-POLY1305"
                },
                config.getOvpnCipher());

        auth = addSpinner(root, "Auth",
                new String[]{"SHA256", "SHA512", "SHA1", "none"},
                config.getOvpnAuth());

        remoteHost = addField(root, "Remote host", config.getOvpnRemoteHost());
        remotePort = addField(root, "Remote port", String.valueOf(config.getOvpnRemotePort()));
        ca = addField(root, getString(R.string.label_ca), config.getOvpnCa());
        cert = addField(root, "Client cert", config.getOvpnCert());
        key = addField(root, "Client key", config.getOvpnKey());
        staticKey = addField(root, getString(R.string.label_static_key),
                config.getOvpnStaticKey());
        mtu = addField(root, getString(R.string.label_mtu), config.getOvpnMtu());
        mssfix = addField(root, getString(R.string.label_mssfix), config.getOvpnMssfix());
        dns = addField(root, getString(R.string.label_ovpn_dns),
                config.getOvpnDns());
        dev = addSpinner(root, getString(R.string.label_dev),
                new String[]{"tun", "tap"}, config.getOvpnDev());
        remoteCertTls = addField(root, getString(R.string.label_remote_cert_tls),
                config.getOvpnRemoteCertTls());
        compress = addField(root, getString(R.string.label_compress),
                config.getOvpnCompress());
        routes = addField(root, getString(R.string.label_routes),
                config.getOvpnRoutes());

        TextView rdLabel = new TextView(this);
        rdLabel.setText(getString(R.string.label_redirect_gateway));
        root.addView(rdLabel);
        redirect = new android.widget.CheckBox(this);
        redirect.setChecked(config.getOvpnRedirectGateway());
        root.addView(redirect, lp());

        keyPassword = addField(root, getString(R.string.label_key_password),
                config.getOvpnKeyPassword());
        username = addField(root, getString(R.string.label_username),
                config.getOvpnUsername());
        password = addField(root, getString(R.string.label_password),
                config.getOvpnPassword());
        verb = addField(root, getString(R.string.label_verb),
                String.valueOf(config.getOvpnVerb()));

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
        intent.setType("application/x-openvpn-profile");
        intent.putExtra(Intent.EXTRA_TITLE, "grizzlylandvpn.ovpn");
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
                // Если есть импортированный .ovpn — экспортируем его как есть (сохраняя
                // все директивы), иначе собираем из полей.
                String raw = config.getOvpnRaw();
                String out = (raw != null && !raw.trim().isEmpty())
                        ? raw : OpenVpnConfigBuilder.exportOvpn(config);
                os.write(out.getBytes("UTF-8"));
                Toast.makeText(this, getString(R.string.toast_ovpn_exported), Toast.LENGTH_SHORT).show();
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
                ConfigParser.applyOvpn(config, new String(bos.toByteArray(), "UTF-8"));
                refreshFromConfig();
                GrizzlyLandVpnService.requestApply(this);
                Toast.makeText(this, getString(R.string.toast_ovpn_imported), Toast.LENGTH_SHORT).show();
            } catch (Exception e) {
                Toast.makeText(this, getString(R.string.toast_import_error, e.getMessage()), Toast.LENGTH_LONG).show();
            }
        }
    }

    /** Перечитывает поля из конфига (после импорта). */
    private void refreshFromConfig() {
        setSpinner(protocol, config.getOvpnProtocol());
        setSpinner(cipher, config.getOvpnCipher());
        setSpinner(auth, config.getOvpnAuth());
        remoteHost.setText(config.getOvpnRemoteHost());
        remotePort.setText(String.valueOf(config.getOvpnRemotePort()));
        ca.setText(config.getOvpnCa());
        cert.setText(config.getOvpnCert());
        key.setText(config.getOvpnKey());
        staticKey.setText(config.getOvpnStaticKey());
        mtu.setText(config.getOvpnMtu());
        mssfix.setText(config.getOvpnMssfix());
        dns.setText(config.getOvpnDns());
        setSpinner(dev, config.getOvpnDev());
        remoteCertTls.setText(config.getOvpnRemoteCertTls());
        compress.setText(config.getOvpnCompress());
        routes.setText(config.getOvpnRoutes());
        redirect.setChecked(config.getOvpnRedirectGateway());
        keyPassword.setText(config.getOvpnKeyPassword());
        username.setText(config.getOvpnUsername());
        password.setText(config.getOvpnPassword());
        verb.setText(String.valueOf(config.getOvpnVerb()));
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
        try {
            // --- Старые значения (для определения, какие поля изменились) ---
            String oldProtocol = config.getOvpnProtocol();
            String oldCipher = config.getOvpnCipher();
            String oldAuth = config.getOvpnAuth();
            String oldHost = config.getOvpnRemoteHost();
            int oldPort = config.getOvpnRemotePort();
            String oldMtu = config.getOvpnMtu();
            String oldMssfix = config.getOvpnMssfix();
            String oldDns = config.getOvpnDns();
            String oldDev = config.getOvpnDev();
            String oldRct = config.getOvpnRemoteCertTls();
            String oldCompress = config.getOvpnCompress();
            String oldRoutes = config.getOvpnRoutes();
            boolean oldRedirect = config.getOvpnRedirectGateway();

            // --- Новые значения ---
            String newProtocol = protocol.getSelectedItem().toString();
            String newCipher = cipher.getSelectedItem().toString();
            String newAuth = auth.getSelectedItem().toString();
            String newHost = remoteHost.getText().toString().trim();
            int newPort = Integer.parseInt(remotePort.getText().toString().trim());
            String newMtu = mtu.getText().toString().trim();
            String newMssfix = mssfix.getText().toString().trim();
            String newDns = dns.getText().toString().trim();
            String newDev = dev.getSelectedItem().toString();
            String newRct = remoteCertTls.getText().toString().trim();
            String newCompress = compress.getText().toString().trim();
            String newRoutes = routes.getText().toString().trim();
            boolean newRedirect = redirect.isChecked();

            // --- Правки в импортированном .ovpn (точечно, только изменённые поля) ---
            String raw = config.getOvpnRaw();
            if (raw != null && !raw.trim().isEmpty()) {
                String updated = raw;
                if (!newProtocol.equals(oldProtocol)) {
                    String proto = "tcp".equalsIgnoreCase(newProtocol) ? "tcp-client" : newProtocol;
                    updated = OpenVpnConfigBuilder.patchDirective(updated, "proto", "proto " + proto);
                }
                if (!newCipher.equals(oldCipher)) {
                    updated = OpenVpnConfigBuilder.patchCipher(updated, newCipher);
                }
                if (!newAuth.equals(oldAuth)) {
                    updated = OpenVpnConfigBuilder.patchAuth(updated, newAuth);
                }
                if (!newHost.equals(oldHost) || newPort != oldPort) {
                    updated = OpenVpnConfigBuilder.patchDirective(updated, "remote",
                            "remote " + newHost + " " + newPort);
                }
                if (!newMtu.equals(oldMtu)) {
                    updated = OpenVpnConfigBuilder.patchMtu(updated, newMtu);
                }
                if (!newMssfix.equals(oldMssfix)) {
                    updated = OpenVpnConfigBuilder.patchMssfix(updated, newMssfix);
                }
                if (!newDns.equals(oldDns)) {
                    updated = OpenVpnConfigBuilder.patchDns(updated, newDns);
                }
                if (!newDev.equals(oldDev)) {
                    updated = OpenVpnConfigBuilder.patchDev(updated, newDev);
                }
                if (!newRct.equals(oldRct)) {
                    updated = OpenVpnConfigBuilder.patchRemoteCertTls(updated, newRct);
                }
                if (!newCompress.equals(oldCompress)) {
                    updated = OpenVpnConfigBuilder.patchCompress(updated, newCompress);
                }
                if (!newRoutes.equals(oldRoutes)) {
                    updated = OpenVpnConfigBuilder.patchRoutes(updated, newRoutes);
                }
                if (newRedirect != oldRedirect) {
                    updated = OpenVpnConfigBuilder.patchRedirect(updated, newRedirect);
                }
                config.setOvpnRaw(updated);
            }

            // --- Сохраняем поля ---
            config.setOvpnProtocol(newProtocol);
            config.setOvpnCipher(newCipher);
            config.setOvpnAuth(newAuth);
            config.setOvpnRemoteHost(newHost);
            config.setOvpnRemotePort(newPort);
            config.setOvpnCa(ca.getText().toString().trim());
            config.setOvpnCert(cert.getText().toString().trim());
            config.setOvpnKey(key.getText().toString().trim());
            config.setOvpnStaticKey(staticKey.getText().toString().trim());
            config.setOvpnMtu(newMtu);
            config.setOvpnMssfix(newMssfix);
            config.setOvpnDns(newDns);
            config.setOvpnDev(newDev);
            config.setOvpnRemoteCertTls(newRct);
            config.setOvpnCompress(newCompress);
            config.setOvpnRoutes(newRoutes);
            config.setOvpnRedirectGateway(newRedirect);
            config.setOvpnKeyPassword(keyPassword.getText().toString());
            config.setOvpnUsername(username.getText().toString().trim());
            config.setOvpnPassword(password.getText().toString());
            try {
                config.setOvpnVerb(Integer.parseInt(verb.getText().toString().trim()));
            } catch (NumberFormatException ignored) {
            }
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
