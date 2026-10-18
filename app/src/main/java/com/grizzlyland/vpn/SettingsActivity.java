package com.grizzlyland.vpn;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Экран настроек: выбор режима работы + переход к настройкам Xray и OpenVPN.
 */
public class SettingsActivity extends Activity {

    private static final int REQ_EXPORT_ALL = 2001;
    private static final int REQ_IMPORT_ALL = 2002;

    private ConfigManager config;
    private RadioGroup modeGroup;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        config = new ConfigManager(this);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 32, 32, 32);

        TextView title = new TextView(this);
        title.setText("Настройки");
        title.setTextSize(24);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView modeLabel = new TextView(this);
        modeLabel.setText("Режим работы");
        modeLabel.setTextSize(18);
        modeLabel.setPadding(0, 24, 0, 8);
        root.addView(modeLabel);

        modeGroup = new RadioGroup(this);
        addMode(modeGroup, "Только Xray", ConfigManager.MODE_XRAY);
        addMode(modeGroup, "Только OpenVPN (с шифрованием)", ConfigManager.MODE_OPENVPN);
        addMode(modeGroup, "Xray + OpenVPN (без шифрования)", ConfigManager.MODE_XRAY_OVPN);
        addMode(modeGroup, "OpenVPN через SSH", ConfigManager.MODE_OVPN_SSH);
        selectMode(config.getMode());
        // Самосохранение: клик по радиокнопке сразу применяет режим (реконнект,
        // если VPN подключён). Отдельная кнопка «Сохранить режим» излишня.
        // Listener ставится ПОСЛЕ selectMode, чтобы начальная установка не срабатывала.
        modeGroup.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                if (checkedId == -1) {
                    return;
                }
                RadioButton rb = findViewById(checkedId);
                if (rb == null || rb.getTag() == null) {
                    return;
                }
                String mode = rb.getTag().toString();
                if (!mode.equals(config.getMode())) {
                    config.setMode(mode);
                    GrizzlyLandVpnService.requestApply(SettingsActivity.this);
                    Toast.makeText(SettingsActivity.this,
                            "Режим сохранён: " + rb.getText(), Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(modeGroup);

        Button xray = new Button(this);
        xray.setText("Настройки Xray");
        xray.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(SettingsActivity.this, XraySettingsActivity.class));
            }
        });
        root.addView(xray, lp());

        Button ovpn = new Button(this);
        ovpn.setText("Настройки OpenVPN");
        ovpn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(SettingsActivity.this, OpenVpnSettingsActivity.class));
            }
        });
        root.addView(ovpn, lp());

        Button ssh = new Button(this);
        ssh.setText("Настройки SSH");
        ssh.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(SettingsActivity.this, SshSettingsActivity.class));
            }
        });
        root.addView(ssh, lp());

        Button exportAll = new Button(this);
        exportAll.setText("Экспорт всех настроек");
        exportAll.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                exportConfig(REQ_EXPORT_ALL, "grizzlylandvpn_config.json");
            }
        });
        root.addView(exportAll, lp());

        Button importAll = new Button(this);
        importAll.setText("Импорт всех настроек");
        importAll.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                importConfig(REQ_IMPORT_ALL);
            }
        });
        root.addView(importAll, lp());

        ScrollView scroll = new ScrollView(this);
        scroll.addView(root);
        setContentView(scroll);
    }

    /** Открывает системный диалог «Создать файл» и пишет туда конфиг нужного раздела. */
    private void exportConfig(int reqCode, String title) {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/json");
        intent.putExtra(Intent.EXTRA_TITLE, title);
        startActivityForResult(intent, reqCode);
    }

    /** Открывает системный выбор файла и импортирует конфиг нужного раздела. */
    private void importConfig(int reqCode) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        startActivityForResult(intent, reqCode);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            return;
        }
        Uri uri = data.getData();
        switch (requestCode) {
            case REQ_EXPORT_ALL: {
                writeExport(uri, config.exportJson(), "Все настройки экспортированы");
                break;
            }
            case REQ_IMPORT_ALL: {
                doImport(uri, new ImportAction() {
                    @Override
                    public void apply(String json) throws Exception {
                        config.importJson(json);
                    }
                    @Override
                    public String toast() { return "Все настройки импортированы"; }
                });
                break;
            }
        }
    }

    private void writeExport(Uri uri, String json, String okMsg) {
        try (OutputStream os = getContentResolver().openOutputStream(uri)) {
            os.write(json.getBytes("UTF-8"));
            Toast.makeText(this, okMsg, Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this, "Ошибка экспорта: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private interface ImportAction {
        void apply(String json) throws Exception;
        String toast();
    }

    private void doImport(Uri uri, ImportAction action) {
        try (InputStream is = getContentResolver().openInputStream(uri)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) {
                bos.write(buf, 0, n);
            }
            action.apply(new String(bos.toByteArray(), "UTF-8"));
            GrizzlyLandVpnService.requestApply(this);
            Toast.makeText(this, action.toast(), Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this, "Ошибка импорта: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void addMode(RadioGroup group, String label, String mode) {
        RadioButton rb = new RadioButton(this);
        rb.setText(label);
        rb.setTag(mode);
        group.addView(rb);
    }

    private void selectMode(String mode) {
        for (int i = 0; i < modeGroup.getChildCount(); i++) {
            View child = modeGroup.getChildAt(i);
            if (child instanceof RadioButton && mode.equals(((RadioButton) child).getTag())) {
                ((RadioButton) child).setChecked(true);
                break;
            }
        }
    }

    private LinearLayout.LayoutParams lp() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }
}
