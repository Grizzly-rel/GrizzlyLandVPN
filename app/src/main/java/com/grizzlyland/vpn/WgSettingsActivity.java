package com.grizzlyland.vpn;

import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import libxray.Libxray;

/**
 * Настройки WireGuard для режима {@link ConfigManager#MODE_WG}.
 * Конфиг хранится как есть в формате wg-quick ([Interface]/[Peer]) — тот же
 * текст, что в стандартном .conf-файле: можно вставить целиком с сервера.
 * Кнопка «Сгенерировать ключи» создаёт пару ключей и подставляет PrivateKey.
 */
public class WgSettingsActivity extends Activity {

    private ConfigManager config;
    private EditText raw;
    private TextView pubkeyLabel;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        config = new ConfigManager(this);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 32, 32, 32);

        TextView title = new TextView(this);
        title.setText("Настройки WireGuard");
        title.setTextSize(24);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView hint = new TextView(this);
        hint.setText("Вставьте конфиг в формате wg-quick (как в стандартном .conf): "
                + "[Interface] с PrivateKey/Address/DNS и [Peer] с PublicKey/Endpoint/"
                + "AllowedIPs. Можно сгенерировать ключи кнопкой ниже — публичный ключ "
                + "тогда нужно вписать на сервере как Peer.");
        hint.setTextSize(12);
        hint.setPadding(0, 8, 0, 16);
        root.addView(hint);

        TextView rawLabel = new TextView(this);
        rawLabel.setText("Конфиг wg-quick");
        root.addView(rawLabel);

        raw = new EditText(this);
        raw.setText(config.getWgRaw());
        raw.setSingleLine(false);
        raw.setMinLines(8);
        raw.setGravity(Gravity.TOP);
        raw.setTypeface(android.graphics.Typeface.MONOSPACE);
        root.addView(raw, lp());

        Button gen = new Button(this);
        gen.setText("Сгенерировать ключи");
        gen.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                generateKeys();
            }
        });
        root.addView(gen, lp());

        pubkeyLabel = new TextView(this);
        pubkeyLabel.setTextSize(12);
        pubkeyLabel.setPadding(0, 8, 0, 0);
        root.addView(pubkeyLabel, lp());

        Button save = new Button(this);
        save.setText("Сохранить");
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

    /**
     * Генерирует пару ключей и подставляет PrivateKey в [Interface] (строку
     * заменяет, секцию при отсутствии создаёт). Публичный ключ показывается —
     * его нужно прописать на сервере как AllowedIPs-пир.
     */
    private void generateKeys() {
        try {
            String priv = Libxray.wgGenPrivateKey();
            String pub = Libxray.wgPublicKeyOf(priv);
            raw.setText(withPrivateKey(raw.getText().toString(), priv));
            pubkeyLabel.setText("PublicKey интерфейса (впишите на сервере):\n" + pub);
            Toast.makeText(this, "Ключи сгенерированы — не забудьте сохранить",
                    Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this, "Ошибка генерации ключей: " + e.getMessage(),
                    Toast.LENGTH_LONG).show();
        }
    }

    /** Вставляет (или заменяет) PrivateKey в секции [Interface]. */
    private static String withPrivateKey(String conf, String privKey) {
        StringBuilder out = new StringBuilder();
        boolean inInterface = false, replaced = false, hasInterface = false;
        String[] lines = (conf == null ? "" : conf).split("\n");
        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (line.startsWith("[")) {
                if (inInterface && !replaced) {
                    out.append("PrivateKey = ").append(privKey).append('\n');
                    replaced = true;
                }
                String sec = line.substring(1, line.indexOf(']') > 1
                        ? line.indexOf(']') : line.length()).trim().toLowerCase();
                inInterface = sec.equals("interface");
                if (inInterface) {
                    hasInterface = true;
                }
                out.append(rawLine).append('\n');
                continue;
            }
            int eq = line.indexOf('=');
            if (inInterface && eq > 0
                    && line.substring(0, eq).trim().toLowerCase().replace("-", "")
                    .replace("_", "").equals("privatekey")) {
                if (!replaced) {
                    out.append("PrivateKey = ").append(privKey).append('\n');
                    replaced = true;
                }
                continue;
            }
            out.append(rawLine).append('\n');
        }
        if (!replaced) {
            if (!hasInterface) {
                StringBuilder withSection = new StringBuilder("[Interface]\n");
                withSection.append("PrivateKey = ").append(privKey).append("\n\n");
                withSection.append(out);
                return withSection.toString().trim() + "\n";
            }
            out.append("PrivateKey = ").append(privKey).append('\n');
        }
        return out.toString().trim() + "\n";
    }

    private void save() {
        String text = raw.getText().toString();
        config.setWgRaw(text);
        WgConfigParser.WgConfig cfg = WgConfigParser.parse(text);
        if (cfg.valid) {
            Toast.makeText(this, "Конфиг WireGuard сохранён", Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, "Сохранено, но конфиг неполный "
                    + "(нужны [Interface] PrivateKey и [Peer] PublicKey)",
                    Toast.LENGTH_LONG).show();
        }
        GrizzlyLandVpnService.requestApply(this);
        finish();
    }

    private LinearLayout.LayoutParams lp() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }
}
