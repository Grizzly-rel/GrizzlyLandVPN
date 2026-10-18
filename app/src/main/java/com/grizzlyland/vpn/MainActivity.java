package com.grizzlyland.vpn;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {

    private TextView statusText;
    private Button connectButton;
    private Button disconnectButton;
    private BroadcastReceiver stateReceiver;

    private void handleImportIntent(Intent intent) {
        String importJson = intent != null ? intent.getStringExtra("import_json") : null;
        String b64 = intent != null ? intent.getStringExtra("import_json_b64") : null;
        if ((importJson == null || importJson.isEmpty()) && b64 != null && !b64.isEmpty()) {
            // adb shell съедает кавычки — JSON передаём в base64
            try {
                importJson = new String(android.util.Base64.decode(
                        b64.replaceAll("\\s", ""), android.util.Base64.NO_WRAP), "UTF-8");
            } catch (Exception e) {
                LogStore.add("Settings", "ОШИБКА b64-декода: " + e);
            }
        }
        if (importJson != null && !importJson.isEmpty()) {
            try {
                new ConfigManager(this).importJson(importJson);
                LogStore.add("Settings", "Импорт настроек через intent (" + importJson.length() + " байт)");
                android.widget.Toast.makeText(this, "Настройки импортированы", android.widget.Toast.LENGTH_SHORT).show();
            } catch (Exception e) {
                LogStore.add("Settings", "ОШИБКА intent-импорта: " + e);
            }
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        // am start при живой активности попадает сюда — тоже применяем импорт.
        handleImportIntent(intent);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Автоматизация (adb): am start ... --es import_json '{"openvpn":{...}}' —
        // применяет настройки без файлового пикера. Только локальный intent от shell.
        handleImportIntent(getIntent());

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        root.setPadding(40, 40, 40, 40);

        TextView title = new TextView(this);
        title.setText(getString(R.string.app_name));
        title.setTextSize(28);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        statusText = new TextView(this);
        statusText.setTextSize(16);
        statusText.setGravity(Gravity.CENTER);
        statusText.setPadding(0, 30, 0, 30);
        root.addView(statusText);

        connectButton = new Button(this);
        connectButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                connect();
            }
        });
        root.addView(connectButton, lp());

        Button selectApps = new Button(this);
        selectApps.setText("Выбрать приложения");
        selectApps.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, AppSelectionActivity.class));
            }
        });
        root.addView(selectApps, lp());

        Button settings = new Button(this);
        settings.setText("Настройки");
        settings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, SettingsActivity.class));
            }
        });
        root.addView(settings, lp());

        disconnectButton = new Button(this);
        disconnectButton.setText("Отключить");
        disconnectButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                disconnect();
            }
        });
        root.addView(disconnectButton, lp());

        Button logs = new Button(this);
        logs.setText("Логи");
        logs.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, LogsActivity.class));
            }
        });
        root.addView(logs, lp());

        setContentView(root);
        refreshStatus();
    }

    @Override
    protected void onResume() {
        super.onResume();
        stateReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                refreshStatus();
            }
        };
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(stateReceiver, new IntentFilter(GrizzlyLandVpnService.ACTION_STATE_CHANGED),
                    Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(stateReceiver, new IntentFilter(GrizzlyLandVpnService.ACTION_STATE_CHANGED));
        }
        refreshStatus();
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (stateReceiver != null) {
            unregisterReceiver(stateReceiver);
            stateReceiver = null;
        }
    }

    private void connect() {
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            startActivityForResult(intent, 100);
        } else {
            startVpn();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 100 && resultCode == RESULT_OK) {
            startVpn();
        } else {
            refreshStatus();
        }
    }

    private void startVpn() {
        Intent i = new Intent(this, GrizzlyLandVpnService.class);
        i.setAction(GrizzlyLandVpnService.ACTION_CONNECT);
        startService(i);
        refreshStatus();
    }

    private void disconnect() {
        Intent i = new Intent(this, GrizzlyLandVpnService.class);
        i.setAction(GrizzlyLandVpnService.ACTION_DISCONNECT);
        startService(i);
        refreshStatus();
    }

    /** Готов ли конфиг к подключению для выбранного режима. */
    private boolean isReady(ConfigManager config) {
        String mode = config.getMode();
        boolean xrayOk = !config.getXrayAddress().isEmpty()
                && !config.getXrayId().isEmpty();
        boolean ovpnOk = !config.getOvpnRemoteHost().isEmpty();
        if (ConfigManager.MODE_XRAY.equals(mode) || ConfigManager.MODE_XRAY_CUSTOM.equals(mode)) {
            // Если задан custom-конфиг — он достаточен; иначе нужны поля Xray.
            if (!config.getXrayCustomJson().trim().isEmpty()) {
                return true;
            }
            return xrayOk;
        }
        if (ConfigManager.MODE_OPENVPN.equals(mode)) {
            return ovpnOk;
        }
        // xray_openvpn
        return xrayOk && ovpnOk;
    }

    private void refreshStatus() {
        ConfigManager config = new ConfigManager(this);
        int count = config.getAllowedApps().size();
        String mode = config.getMode();
        String modeLabel = modeLabel(mode);

        StringBuilder sb = new StringBuilder();
        sb.append("Режим: ").append(modeLabel);
        if (ConfigManager.MODE_OVPN_SSH.equals(mode)) {
            // В режиме OpenVPN-через-SSH настройки Xray не участвуют — показываем SSH.
            sb.append("\nSSH: ").append(config.getSshHost()).append(":")
                    .append(config.getSshPort()).append(" (").append(config.getSshUser()).append(")");
            sb.append("\nOpenVPN (через SSH): ").append(config.getSshTarget());
        } else {
            sb.append("\nXray: ").append(config.getXrayAddress()).append(":")
                    .append(config.getXrayPort());
            if (ConfigManager.MODE_XRAY.equals(mode) || ConfigManager.MODE_XRAY_OVPN.equals(mode)) {
                sb.append("\nXray SOCKS: 127.0.0.1:").append(config.getXraySocksPort());
            }
            sb.append("\nOpenVPN: ").append(config.getOvpnRemoteHost()).append(":")
                    .append(config.getOvpnRemotePort());
        }
        sb.append("\nВыбрано приложений: ").append(count);
        String err = GrizzlyLandVpnService.lastError;
        if (err != null && !err.isEmpty()) {
            sb.append("\n\nОшибка: ").append(err);
        }
        statusText.setText(sb.toString());

        boolean ready = isReady(config);
        boolean isConnected = GrizzlyLandVpnService.connected;

        connectButton.setEnabled(ready && !isConnected);
        if (ready) {
            connectButton.setText("Подключить (" + modeLabel + ")");
        } else {
            connectButton.setText("Подключить (настройте параметры)");
        }

        disconnectButton.setEnabled(isConnected);
    }

    private String modeLabel(String mode) {
        if (ConfigManager.MODE_XRAY.equals(mode) || ConfigManager.MODE_XRAY_CUSTOM.equals(mode)) {
            return "Xray";
        }
        if (ConfigManager.MODE_OPENVPN.equals(mode)) {
            return "OpenVPN";
        }
        if (ConfigManager.MODE_OVPN_SSH.equals(mode)) {
            return "OpenVPN через SSH";
        }
        return "Xray + OpenVPN";
    }

    private LinearLayout.LayoutParams lp() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }
}
