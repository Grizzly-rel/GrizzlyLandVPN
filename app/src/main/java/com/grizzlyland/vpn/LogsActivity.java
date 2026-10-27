package com.grizzlyland.vpn;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Экран просмотра журнала подключения (Xray / OpenVPN / management / сервис).
 * Обновляется в реальном времени из {@link LogStore}.
 */
public class LogsActivity extends Activity implements LogStore.Listener {

    private TextView logView;
    private boolean autoScroll = true;
    private Button debugBtn;
    private ConfigManager config;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(16, 16, 16, 16);

        TextView title = new TextView(this);
        title.setText(getString(R.string.title_logs));
        title.setTextSize(22);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        LinearLayout btnRow = new LinearLayout(this);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);

        Button copy = new Button(this);
        copy.setText(getString(R.string.btn_copy));
        copy.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                copyLogs();
            }
        });
        btnRow.addView(copy, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        Button clear = new Button(this);
        clear.setText(getString(R.string.btn_clear));
        clear.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                LogStore.clear();
            }
        });
        btnRow.addView(clear, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        root.addView(btnRow, lp());

        config = new ConfigManager(this);
        debugBtn = new Button(this);
        updateDebugButton();
        debugBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleDebug();
            }
        });
        root.addView(debugBtn, lp());

        logView = new TextView(this);
        logView.setTextSize(12);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextColor(Color.WHITE);
        logView.setBackgroundColor(Color.parseColor("#111111"));
        logView.setPadding(8, 8, 8, 8);
        logView.setText(LogStore.getText());

        ScrollView scroll = new ScrollView(this);
        scroll.addView(logView);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);
    }

    @Override
    protected void onResume() {
        super.onResume();
        LogStore.addListener(this);
        refresh();
    }

    @Override
    protected void onPause() {
        super.onPause();
        LogStore.removeListener(this);
    }

    /** Дебаунс обновлений: при шторме строк (Xray=debug) setText на каждую строку
     *  перегружает UI-поток вплоть до ANR. Обновляем экран не чаще ~2 раз/сек. */
    private final Runnable pendingRefresh = new Runnable() {
        @Override
        public void run() {
            refresh();
        }
    };

    @Override
    public void onLog() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                logView.removeCallbacks(pendingRefresh);
                logView.postDelayed(pendingRefresh, 500);
            }
        });
    }

    /** Включает/выключает подробный журнал. Применяется на лету БЕЗ реконнекта:
     *  OpenVPN — verb через management, Xray — перезапуск ядра с новым loglevel,
     *  WireGuard — фильтр в памяти. Механизмы выбирает сервис (ACTION_SET_DEBUG). */
    private void toggleDebug() {
        boolean on = !config.getLogDebug();
        config.setLogDebug(on);
        LogStore.add("Log", on ? "Подробный журнал включён" : "Подробный журнал выключен");
        updateDebugButton();
        GrizzlyLandVpnService.requestSetDebug(this);
    }

    private void updateDebugButton() {
        if (config == null) {
            return;
        }
        debugBtn.setText(config.getLogDebug()
                ? getString(R.string.btn_debug_on) : getString(R.string.btn_debug_off));
    }

    private void copyLogs() {
        String text = LogStore.getText();
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText("GrizzlyLandVPN logs", text));
            Toast.makeText(this, getString(R.string.toast_logs_copied), Toast.LENGTH_SHORT).show();
        }
    }

    private void refresh() {
        String text = LogStore.getText();
        logView.setText(text);
        if (autoScroll && text.length() > 0) {
            logView.post(new Runnable() {
                @Override
                public void run() {
                    int scrollAmount = logView.getLayout() != null
                            ? logView.getLayout().getLineTop(logView.getLineCount())
                            : 0;
                    ((ScrollView) logView.getParent()).scrollTo(0, scrollAmount);
                }
            });
        }
    }

    private LinearLayout.LayoutParams lp() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }
}
