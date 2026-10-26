package com.grizzlyland.vpn;

import java.util.ArrayList;
import java.util.List;

/**
 * Центральный журнал подключения (кольцевой буфер в памяти).
 *
 * Все компоненты (Xray, OpenVPN, management, сервис) пишут сюда строки,
 * а {@link LogsActivity} отображает их в реальном времени.
 */
public class LogStore {

    private static final int MAX = 3000;
    private static final List<String> lines = new ArrayList<>();
    private static final List<Listener> listeners = new ArrayList<>();
    // Метка времени строки. Без неё интервалы между событиями в журнале не
    // видны вообще (диагностика «TunMon каждые 2с» выглядела как непрерывный
    // поток). add() static synchronized → SimpleDateFormat под тем же замком.
    private static final java.text.SimpleDateFormat TS =
            new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US);

    public interface Listener {
        void onLog();
    }

    public static synchronized void add(String source, String line) {
        if (line == null) {
            return;
        }
        String full = "[" + TS.format(new java.util.Date()) + "][" + source + "] " + line;
        lines.add(full);
        while (lines.size() > MAX) {
            lines.remove(0);
        }
        // Зеркало в logcat: позволяет читать журнал Xray/сервиса через adb
        // (экран «Логи» сильно отстаёт и может ANR'иться на больших объёмах).
        android.util.Log.i("GrizzlyLog", full);
        notifyListeners();
    }

    public static synchronized String getText() {
        StringBuilder sb = new StringBuilder();
        for (String l : lines) {
            sb.append(l).append('\n');
        }
        return sb.toString();
    }

    public static synchronized void clear() {
        lines.clear();
        notifyListeners();
    }

    public static synchronized void addListener(Listener l) {
        if (!listeners.contains(l)) {
            listeners.add(l);
        }
    }

    public static synchronized void removeListener(Listener l) {
        listeners.remove(l);
    }

    private static void notifyListeners() {
        for (Listener l : new ArrayList<>(listeners)) {
            try {
                l.onLog();
            } catch (Exception ignored) {
            }
        }
    }
}
