package com.grizzlyland.vpn;

import android.app.Activity;
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

/**
 * Настройки SSH для режима «OpenVPN через SSH» ({@link ConfigManager#MODE_OVPN_SSH}):
 * сервер, логин, способ аутентификации и цель форварда (куда sshd ретранслирует TCP).
 * Самосохранение по кнопке, как на остальных экранах настроек.
 */
public class SshSettingsActivity extends Activity {

    private ConfigManager config;

    private EditText host;
    private EditText port;
    private EditText user;
    private Spinner auth;
    private EditText password;
    private EditText key;
    private EditText keyPass;
    private EditText target;
    private EditText localPort;
    private TextView fingerprint;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        config = new ConfigManager(this);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 32, 32, 32);

        TextView title = new TextView(this);
        title.setText(getString(R.string.ssh_settings));
        title.setTextSize(24);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView hint = new TextView(this);
        hint.setText(getString(R.string.hint_ssh));
        hint.setTextSize(12);
        hint.setPadding(0, 8, 0, 16);
        root.addView(hint);

        host = addField(root, getString(R.string.label_ssh_host), config.getSshHost());
        port = addField(root, getString(R.string.label_ssh_port), String.valueOf(config.getSshPort()));
        user = addField(root, getString(R.string.label_ssh_user), config.getSshUser());
        auth = addSpinner(root, getString(R.string.label_auth),
                new String[]{getString(R.string.auth_password), getString(R.string.auth_key)},
                ConfigManager.SSH_AUTH_KEY.equals(config.getSshAuth()) ? 1 : 0);
        password = addField(root, getString(R.string.label_ssh_password), config.getSshPassword());
        key = addMultiline(root, getString(R.string.label_ssh_key), config.getSshKey());
        keyPass = addField(root, getString(R.string.label_ssh_key_pass), config.getSshKeyPass());
        target = addField(root, getString(R.string.label_ssh_target),
                config.getSshTarget());
        localPort = addField(root, getString(R.string.label_ssh_local_port),
                String.valueOf(config.getSshLocalPort()));

        fingerprint = new TextView(this);
        fingerprint.setTextSize(12);
        String fp = config.getSshHostKeyFp();
        fingerprint.setText(getString(R.string.label_hostkey_fp,
                fp == null || fp.isEmpty() ? getString(R.string.fp_not_recorded) : fp));
        fingerprint.setPadding(0, 16, 0, 0);
        root.addView(fingerprint);

        Button forget = new Button(this);
        forget.setText(getString(R.string.btn_forget_fp));
        forget.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                config.setSshHostKeyFp("");
                fingerprint.setText(getString(R.string.label_hostkey_fp, getString(R.string.fp_not_recorded)));
                Toast.makeText(SshSettingsActivity.this,
                        getString(R.string.toast_fp_reset),
                        Toast.LENGTH_SHORT).show();
            }
        });
        root.addView(forget, lp());

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

    private void save() {
        try {
            config.setSshHost(host.getText().toString());
            config.setSshPort(Integer.parseInt(port.getText().toString().trim()));
            config.setSshUser(user.getText().toString());
            config.setSshAuth(auth.getSelectedItemPosition() == 1
                    ? ConfigManager.SSH_AUTH_KEY : ConfigManager.SSH_AUTH_PASSWORD);
            config.setSshPassword(password.getText().toString());
            config.setSshKey(key.getText().toString());
            config.setSshKeyPass(keyPass.getText().toString());
            config.setSshTarget(target.getText().toString());
            config.setSshLocalPort(Integer.parseInt(localPort.getText().toString().trim()));
            Toast.makeText(this, getString(R.string.toast_ssh_saved), Toast.LENGTH_SHORT).show();
            GrizzlyLandVpnService.requestApply(this);
            finish();
        } catch (NumberFormatException e) {
            Toast.makeText(this, getString(R.string.toast_ports_nan), Toast.LENGTH_LONG).show();
        }
    }

    private EditText addField(LinearLayout root, String label, String value) {
        TextView tv = new TextView(this);
        tv.setText(label);
        root.addView(tv);
        EditText et = new EditText(this);
        et.setText(value);
        et.setSingleLine(true);
        root.addView(et, lp());
        return et;
    }

    private EditText addMultiline(LinearLayout root, String label, String value) {
        TextView tv = new TextView(this);
        tv.setText(label);
        root.addView(tv);
        EditText et = new EditText(this);
        et.setText(value);
        et.setSingleLine(false);
        et.setMinLines(3);
        et.setGravity(Gravity.TOP);
        et.setTypeface(android.graphics.Typeface.MONOSPACE);
        root.addView(et, lp());
        return et;
    }

    private Spinner addSpinner(LinearLayout root, String label, String[] items, int selected) {
        TextView tv = new TextView(this);
        tv.setText(label);
        root.addView(tv);
        Spinner sp = new Spinner(this);
        ArrayAdapter<String> a = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_item, items);
        a.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        sp.setAdapter(a);
        sp.setSelection(Math.max(0, Math.min(selected, items.length - 1)));
        root.addView(sp, lp());
        return sp;
    }

    private LinearLayout.LayoutParams lp() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }
}
