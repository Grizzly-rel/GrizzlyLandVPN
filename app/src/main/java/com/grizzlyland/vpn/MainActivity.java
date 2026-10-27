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
                LogStore.add("Settings", L10n.s(R.string.log_main_01) + e);
            }
        }
        if (importJson != null && !importJson.isEmpty()) {
            try {
                new ConfigManager(this).importJson(importJson);
                LogStore.add("Settings", L10n.s(R.string.log_main_02) + importJson.length() + L10n.s(R.string.log_main_03));
                android.widget.Toast.makeText(this, getString(R.string.toast_settings_imported), android.widget.Toast.LENGTH_SHORT).show();
            } catch (Exception e) {
                LogStore.add("Settings", L10n.s(R.string.log_main_04) + e);
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
        L10n.init(this);

        // Android 13+ (API 33): уведомления скрыты без runtime-разрешения. Без него
        // юзер не увидит уведомление VPN с кнопкой «Отключить» (сам сервис при этом
        // работает). Запрашивается один раз; отказ не блокирует работу приложения.
        if (android.os.Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)
                        != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(
                    new String[]{android.Manifest.permission.POST_NOTIFICATIONS}, 200);
        }

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
        selectApps.setText(getString(R.string.select_apps_btn));
        selectApps.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, AppSelectionActivity.class));
            }
        });
        root.addView(selectApps, lp());

        Button settings = new Button(this);
        settings.setText(getString(R.string.settings));
        settings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, SettingsActivity.class));
            }
        });
        root.addView(settings, lp());

        disconnectButton = new Button(this);
        disconnectButton.setText(getString(R.string.action_disconnect));
        disconnectButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                disconnect();
            }
        });
        root.addView(disconnectButton, lp());

        Button logs = new Button(this);
        logs.setText(getString(R.string.logs_btn));
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
    protected void onStart() {
        super.onStart();
        autoRestoreIfWanted();
    }

    /** Восстановление VPN при открытии приложения: если до перезапуска/падения/
     *  переустановки VPN был подключён (ConfigManager.getWantConnected), а сервис
     *  сейчас не жив — подключаем тем же режимом и конфигом. После force-stop и
     *  переустановки приложение находится в stopped-state: система НЕ доставляет
     *  ему BOOT_COMPLETED и будильники до первого ручного запуска, так что
     *  открытие приложения — единственный шанс восстановить подключение.
     *  Если сервис жив (уже подключён или подключается) — не мешаем. */
    private void autoRestoreIfWanted() {
        ConfigManager config = new ConfigManager(this);
        if (!config.getWantConnected()) {
            return;
        }
        if (GrizzlyLandVpnService.connected || GrizzlyLandVpnService.serviceActive) {
            return;
        }
        // Без выданного согласия VpnService автоподключение невозможно
        // (после полного удаления+установки согласие сбрасывается) — юзер
        // нажмёт «Подключить» и выдаст его через системный диалог.
        if (VpnService.prepare(this) != null) {
            LogStore.add("Main", L10n.s(R.string.log_main_05));
            return;
        }
        LogStore.add("Main", L10n.s(R.string.log_main_06) + config.getMode() + ")");
        startVpn();
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
        startServiceCompat(i);
        refreshStatus();
    }

    private void disconnect() {
        Intent i = new Intent(this, GrizzlyLandVpnService.class);
        i.setAction(GrizzlyLandVpnService.ACTION_DISCONNECT);
        startServiceCompat(i);
        refreshStatus();
    }

    /** Активити может оказаться ФОНОМ, даже будучи открытой: autoRestore срабатывает
     *  в onStart ЗА keyguard'ом (экран заблокирован — наблюдено 26.10: краш
     *  «Not allowed to start service … app is in background» и смерть процесса).
     *  startForegroundService из фона разрешён; сервис вызывает startForeground
     *  в onStartCommand сразу, так что требование FGS выполняется. */
    private void startServiceCompat(Intent i) {
        try {
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                startForegroundService(i);
            } else {
                startService(i);
            }
        } catch (IllegalStateException e) {
            // Система совсем запретила старт — не роняем активити, статус покажет состояние.
        }
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
        if (ConfigManager.MODE_WG.equals(mode)) {
            // Для WireGuard достаточно непустого корректного конфига.
            return WgConfigParser.parse(config.getWgRaw()).valid;
        }
        if (ConfigManager.MODE_AWG.equals(mode)) {
            // Для AmneziaWG достаточно непустого корректного конфига.
            return AwgConfigParser.parse(config.getAwgRaw()).valid;
        }
        if (ConfigManager.MODE_WG_XRAY.equals(mode)) {
            // WG-конфиг + рабочие настройки Xray (обёртка VLESS).
            return WgConfigParser.parse(config.getWgRaw()).valid && xrayOk;
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
        sb.append(getString(R.string.status_mode, modeLabel));
        if (ConfigManager.MODE_OVPN_SSH.equals(mode)) {
            // В режиме OpenVPN-через-SSH настройки Xray не участвуют — показываем SSH.
            sb.append("\n").append(getString(R.string.status_ssh,
                    config.getSshHost() + ":" + config.getSshPort(), config.getSshUser()));
            sb.append("\n").append(getString(R.string.status_ovpn_via_ssh, config.getSshTarget()));
        } else if (ConfigManager.MODE_WG.equals(mode)) {
            // В режиме WireGuard показываем сводку по wg-конфигу.
            WgConfigParser.WgConfig c = WgConfigParser.parse(config.getWgRaw());
            sb.append("\n").append(getString(R.string.status_wg, getString(c.valid
                    ? R.string.status_config_set : R.string.status_config_missing)));
            if (c.valid) {
                sb.append("\n").append(getString(R.string.status_endpoint, c.endpointForLog.isEmpty()
                        ? getString(R.string.status_not_set) : c.endpointForLog));
                sb.append("\n").append(getString(R.string.status_peer, c.peers, c.addresses.size()));
            }
        } else if (ConfigManager.MODE_AWG.equals(mode)) {
            // В режиме AmneziaWG показываем сводку по awg-конфигу.
            AwgConfigParser.AwgConfig c = AwgConfigParser.parse(config.getAwgRaw());
            sb.append("\n").append(getString(R.string.status_awg, getString(c.valid
                    ? R.string.status_config_set : R.string.status_config_missing)));
            if (c.valid) {
                sb.append("\n").append(getString(R.string.status_endpoint, c.endpointForLog.isEmpty()
                        ? getString(R.string.status_not_set) : c.endpointForLog));
                sb.append("\n").append(getString(R.string.status_peer, c.peers, c.addresses.size()));
                sb.append("\n").append(getString(R.string.status_obfuscation,
                        AwgConfigParser.obfuscationSummary(c)));
            }
        } else if (ConfigManager.MODE_WG_XRAY.equals(mode)) {
            // WireGuard через Xray: WG-конфиг + Xray-обёртка.
            WgConfigParser.WgConfig c = WgConfigParser.parse(config.getWgRaw());
            sb.append("\n").append(getString(R.string.status_wg, getString(c.valid
                    ? R.string.status_config_set : R.string.status_config_missing)));
            if (c.valid) {
                sb.append("\n").append(getString(R.string.status_wg_endpoint, c.endpointForLog.isEmpty()
                        ? getString(R.string.status_not_set) : c.endpointForLog));
            }
            sb.append("\n").append(getString(R.string.status_xray_wrap,
                    config.getXrayAddress() + ":" + config.getXrayPort()));
        } else {
            sb.append("\n").append(getString(R.string.status_xray,
                    config.getXrayAddress() + ":" + config.getXrayPort()));
            if (ConfigManager.MODE_XRAY.equals(mode) || ConfigManager.MODE_XRAY_OVPN.equals(mode)) {
                sb.append("\n").append(getString(R.string.status_xray_socks,
                        String.valueOf(config.getXraySocksPort())));
            }
            sb.append("\n").append(getString(R.string.status_openvpn,
                    config.getOvpnRemoteHost() + ":" + config.getOvpnRemotePort()));
        }
        if (config.getVpnAllApps()) {
            sb.append("\n").append(getString(R.string.status_all_apps));
        } else {
            sb.append("\n").append(getString(R.string.status_apps_count, count));
        }
        if (GrizzlyLandVpnService.waitingNetwork) {
            sb.append("\n").append(getString(R.string.status_waiting_network));
        } else if (GrizzlyLandVpnService.serviceActive && !GrizzlyLandVpnService.connected) {
            sb.append("\n").append(getString(R.string.status_connecting));
        }
        String err = GrizzlyLandVpnService.lastError;
        if (err != null && !err.isEmpty()) {
            sb.append("\n\n").append(getString(R.string.status_error, err));
        }
        statusText.setText(sb.toString());

        boolean ready = isReady(config);
        boolean isConnected = GrizzlyLandVpnService.connected;

        // ПОДКЛЮЧИТЬ неактивна, пока сервис жив (подключается / ждёт сеть / ретраит) —
        // повторный тап в этот момент только мешает текущей попытке.
        connectButton.setEnabled(ready && !isConnected && !GrizzlyLandVpnService.serviceActive);
        if (ready) {
            connectButton.setText(getString(R.string.connect_fmt, modeLabel));
        } else {
            connectButton.setText(getString(R.string.connect_configure));
        }

        // ОТКЛЮЧИТЬ активна всегда, когда жив процесс VPN (подключается, ждёт сети,
        // ретраит), а не только при connected: раньше во время штурма реконнектов
        // («влип» в фазу коннекта) выключить VPN с главного экрана было невозможно.
        disconnectButton.setEnabled(isConnected || GrizzlyLandVpnService.serviceActive);
    }

    private String modeLabel(String mode) {
        if (ConfigManager.MODE_XRAY.equals(mode) || ConfigManager.MODE_XRAY_CUSTOM.equals(mode)) {
            return "Xray";
        }
        if (ConfigManager.MODE_OPENVPN.equals(mode)) {
            return "OpenVPN";
        }
        if (ConfigManager.MODE_OVPN_SSH.equals(mode)) {
            return getString(R.string.mode_ovpn_ssh);
        }
        if (ConfigManager.MODE_WG.equals(mode)) {
            return "WireGuard";
        }
        if (ConfigManager.MODE_AWG.equals(mode)) {
            return "AmneziaWG";
        }
        if (ConfigManager.MODE_WG_XRAY.equals(mode)) {
            return getString(R.string.mode_wg_xray);
        }
        return getString(R.string.mode_xray_ovpn);
    }

    private LinearLayout.LayoutParams lp() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }
}
