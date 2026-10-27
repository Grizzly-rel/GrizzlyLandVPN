package com.grizzlyland.vpn;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

import libxray.Libxray;

/**
 * Настройки WireGuard для режима {@link ConfigManager#MODE_WG}.
 * Конфиг хранится как есть в формате wg-quick ([Interface]/[Peer]) — тот же
 * текст, что в стандартном .conf-файле: можно вставить целиком с сервера.
 * Кнопка «Сгенерировать ключи» создаёт пару ключей и подставляет PrivateKey.
 */
public class WgSettingsActivity extends Activity {

    private static final int REQ_EXPORT = 2301;
    private static final int REQ_IMPORT = 2302;
    private static final int REQ_QR_SCAN = 2303;

    private ConfigManager config;
    private EditText raw;
    private TextView pubkeyLabel;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        L10n.init(this);
        config = new ConfigManager(this);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 32, 32, 32);

        TextView title = new TextView(this);
        title.setText(getString(R.string.wg_settings));
        title.setTextSize(24);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView hint = new TextView(this);
        hint.setText(getString(R.string.hint_wg));
        hint.setTextSize(12);
        hint.setPadding(0, 8, 0, 16);
        root.addView(hint);

        // Кнопки импорта/экспорта .conf — как в настройках OpenVPN (.ovpn).
        LinearLayout io = new LinearLayout(this);
        io.setOrientation(LinearLayout.HORIZONTAL);

        Button importBtn = new Button(this);
        importBtn.setText(getString(R.string.btn_import_conf));
        importBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                importConfig();
            }
        });
        io.addView(importBtn, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        Button exportBtn = new Button(this);
        exportBtn.setText(getString(R.string.btn_export_conf));
        exportBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                exportConfig();
            }
        });
        io.addView(exportBtn, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        root.addView(io, lp());

        // QR — как в оригинальном приложении WireGuard: конфиг целиком кодируется
        // в QR (сканировать с другого устройства или с бумаги) и показывается QR
        // текущего конфига (перенос на другое устройство).
        LinearLayout ioQr = new LinearLayout(this);
        ioQr.setOrientation(LinearLayout.HORIZONTAL);

        Button qrScanBtn = new Button(this);
        qrScanBtn.setText(getString(R.string.btn_scan_qr));
        qrScanBtn.setOnClickListener(v -> startActivityForResult(
                new Intent(this, QrScanActivity.class), REQ_QR_SCAN));
        ioQr.addView(qrScanBtn, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        Button qrShowBtn = new Button(this);
        qrShowBtn.setText(getString(R.string.btn_show_qr));
        qrShowBtn.setOnClickListener(v -> showQr());
        ioQr.addView(qrShowBtn, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        root.addView(ioQr, lp());

        TextView rawLabel = new TextView(this);
        rawLabel.setText(getString(R.string.label_wg_raw));
        root.addView(rawLabel);

        raw = new EditText(this);
        raw.setText(config.getWgRaw());
        raw.setSingleLine(false);
        raw.setMinLines(8);
        raw.setGravity(Gravity.TOP);
        raw.setTypeface(android.graphics.Typeface.MONOSPACE);
        root.addView(raw, lp());

        Button gen = new Button(this);
        gen.setText(getString(R.string.btn_generate_keys));
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

    /** SAF-пикер: сохранить текущий конфиг как .conf файл. */
    private void exportConfig() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        // octet-stream, чтобы documentsui не дописывал ".txt" к имени grizzlylandvpn.conf
        intent.setType("application/octet-stream");
        intent.putExtra(Intent.EXTRA_TITLE, "grizzlylandvpn.conf");
        startActivityForResult(intent, REQ_EXPORT);
    }

    /** SAF-пикер: выбрать .conf файл wg-quick и загрузить его. */
    private void importConfig() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        startActivityForResult(intent, REQ_IMPORT);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null) {
            return;
        }
        // Результат QR-сканера не имеет URI — только extra "text". Проверяем его
        // ДО общего требования data.getData(): иначе условие data.getData()==null
        // молча отбрасывало распознанный QR и конфиг никогда не применялся.
        if (requestCode == REQ_QR_SCAN) {
            String text = data.getStringExtra("text");
            if (text == null || text.trim().isEmpty()) {
                Toast.makeText(this, getString(R.string.toast_qr_empty), Toast.LENGTH_LONG).show();
                return;
            }
            applyImportedConfig(text, getString(R.string.toast_conf_from_qr));
            return;
        }
        Uri uri = data.getData();
        if (uri == null) {
            return;
        }
        if (requestCode == REQ_EXPORT) {
            try (OutputStream os = getContentResolver().openOutputStream(uri)) {
                // Экспортируем то, что видно в поле (если пусто — сохранённый конфиг).
                String text = raw.getText().toString();
                String out = (!text.trim().isEmpty() ? text : config.getWgRaw()).trim() + "\n";
                os.write(out.getBytes("UTF-8"));
                Toast.makeText(this, getString(R.string.toast_conf_exported), Toast.LENGTH_SHORT).show();
            } catch (Exception e) {
                Toast.makeText(this, getString(R.string.toast_export_error, e.getMessage()),
                        Toast.LENGTH_LONG).show();
            }
        } else if (requestCode == REQ_IMPORT) {
            try (InputStream is = getContentResolver().openInputStream(uri)) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) {
                    bos.write(buf, 0, n);
                }
                applyImportedConfig(new String(bos.toByteArray(), "UTF-8"),
                        getString(R.string.toast_conf_imported));
            } catch (Exception e) {
                Toast.makeText(this, getString(R.string.toast_import_error, e.getMessage()),
                        Toast.LENGTH_LONG).show();
            }
        }
    }

    /**
     * Применяет импортированный конфиг (из файла или QR): сохраняет, показывает
     * в поле, валидирует и перезапускает VPN, если он подключён.
     */
    private void applyImportedConfig(String text, String okMessage) {
        config.setWgRaw(text);
        raw.setText(text);
        WgConfigParser.WgConfig cfg = WgConfigParser.parse(text);
        GrizzlyLandVpnService.requestApply(this);
        if (cfg.valid) {
            Toast.makeText(this, okMessage, Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, okMessage + getString(R.string.incomplete_with_details),
                    Toast.LENGTH_LONG).show();
        }
    }

    /**
     * Показывает текущий конфиг как QR-код (как экспорт в оригинальном
     * приложении WireGuard) — для переноса на другое устройство сканированием.
     */
    private void showQr() {
        String text = raw.getText().toString();
        if (text.trim().isEmpty()) {
            text = config.getWgRaw();
        }
        if (text.trim().isEmpty()) {
            Toast.makeText(this, getString(R.string.toast_conf_empty), Toast.LENGTH_SHORT).show();
            return;
        }
        final String conf = text;
        // Генерация BitMatrix ~1000x1000 модулей занимает заметное время — в фоне.
        new Thread(() -> {
            try {
                int side = Math.min(getResources().getDisplayMetrics().widthPixels,
                        getResources().getDisplayMetrics().heightPixels) - 80;
                final android.graphics.Bitmap bmp = qrBitmap(conf, side);
                runOnUiThread(() -> showQrDialog(bmp));
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this,
                        getString(R.string.toast_qr_gen_error, e.getMessage()), Toast.LENGTH_LONG).show());
            }
        }, "wg-qr-gen").start();
    }

    private void showQrDialog(android.graphics.Bitmap bmp) {
        android.widget.ImageView iv = new android.widget.ImageView(this);
        iv.setImageBitmap(bmp);
        iv.setAdjustViewBounds(true);
        android.widget.LinearLayout box = new android.widget.LinearLayout(this);
        box.setOrientation(android.widget.LinearLayout.VERTICAL);
        box.setPadding(24, 24, 24, 24);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        TextView note = new TextView(this);
        note.setText(getString(R.string.qr_dialog_note_wg));
        note.setTextSize(12);
        note.setPadding(0, 0, 0, 12);
        box.addView(note);
        box.addView(iv);
        new android.app.AlertDialog.Builder(this)
                .setTitle(getString(R.string.qr_dialog_title_wg))
                .setView(box)
                .setPositiveButton(getString(R.string.btn_close), null)
                .show();
    }

    /**
     * QR-код из текста (zxing core): CHARACTER_SET=UTF-8 (с ECI-сегментом,
     * чтобы сканеры корректно читали не-ASCII), коррекция M, поле 2 модуля.
     */
    private static android.graphics.Bitmap qrBitmap(String text, int sidePx) throws Exception {
        Map<com.google.zxing.EncodeHintType, Object> hints =
                new java.util.EnumMap<>(com.google.zxing.EncodeHintType.class);
        hints.put(com.google.zxing.EncodeHintType.CHARACTER_SET, "UTF-8");
        hints.put(com.google.zxing.EncodeHintType.ERROR_CORRECTION,
                com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.M);
        hints.put(com.google.zxing.EncodeHintType.MARGIN, 2);
        com.google.zxing.qrcode.QRCodeWriter writer = new com.google.zxing.qrcode.QRCodeWriter();
        com.google.zxing.common.BitMatrix m =
                writer.encode(text, com.google.zxing.BarcodeFormat.QR_CODE, sidePx, sidePx, hints);
        int w = m.getWidth(), h = m.getHeight();
        android.graphics.Bitmap bmp = android.graphics.Bitmap.createBitmap(
                w, h, android.graphics.Bitmap.Config.RGB_565);
        int[] pixels = new int[w * h];
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                pixels[y * w + x] = m.get(x, y) ? 0xFF000000 : 0xFFFFFFFF;
            }
        }
        bmp.setPixels(pixels, 0, w, 0, 0, w, h);
        return bmp;
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
            pubkeyLabel.setText(getString(R.string.label_pubkey, pub));
            Toast.makeText(this, getString(R.string.toast_keys_generated),
                    Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.toast_keygen_error, e.getMessage()),
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
            Toast.makeText(this, getString(R.string.toast_wg_saved), Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, getString(R.string.saved_incomplete_prefix) + " "
                            + getString(R.string.incomplete_details),
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
