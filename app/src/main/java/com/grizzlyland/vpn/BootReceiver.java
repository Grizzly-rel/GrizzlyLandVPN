package com.grizzlyland.vpn;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Восстановление VPN после перезагрузки телефона: если до выключения VPN был
 *  подключён (ConfigManager.getWantConnected), стартуем сервис — он подключится
 *  тем же режимом и конфигом. Сетевые сбои на момент загрузки не страшны:
 *  WireGuard/AmneziaWG переживают отсутствие сети (ретраи/самовосстановление),
 *  Xray стартует без сети и оживает при её появлении, SSH ретраит бесконечно.
 *  TUN-интерфейс до первой разблокировки экрана система НЕ выдаёт (establish()
 *  вернёт null) — сервис сам ретраит с бэкоффом и подключится после unlock.
 *  ВАЖНО: если приложение было force-stopнуто или переустановлено, система НЕ
 *  доставит ему BOOT_COMPLETED до следующего ручного запуска (stopped-state,
 *  стандартное поведение Android) — восстановление делает MainActivity при
 *  открытии приложения (autoRestoreIfWanted). ИСКЛЮЧЕНИЕ: MY_PACKAGE_REPLACED
 *  доставляется самому приложению сразу после его обновления — через него
 *  VPN восстанавливается после переустановки без запуска приложения;
 *  на Android 12+ это ещё и документированное исключение для старта
 *  foreground-сервиса из фона. */
public class BootReceiver extends BroadcastReceiver {
    /** Одноразовая будильника из обработчика падений сервиса (см.
     *  GrizzlyLandVpnService.installCrashRestart). */
    public static final String ACTION_ALARM_RESTART = "com.grizzlyland.vpn.ALARM_RESTART";

    @Override
    public void onReceive(Context context, Intent intent) {
        String a = intent == null ? null : intent.getAction();
        boolean boot = Intent.ACTION_BOOT_COMPLETED.equals(a)
                || "android.intent.action.QUICKBOOT_POWERON".equals(a);
        boolean alarm = ACTION_ALARM_RESTART.equals(a);
        // MY_PACKAGE_REPLACED система шлёт САМОМУ приложению сразу после его
        // обновления/переустановки (install -r). Это единственный системный
        // сигнал, проходящий сквозь stopped-state (после переустановки всё
        // остальное — бродкасты, будильники, старты сервисов — не доставляется
        // до первого ручного запуска). Без него после обновления VPN молчал бы,
        // пока юзер не откроет приложение (наблюдено 26.10).
        boolean updated = Intent.ACTION_MY_PACKAGE_REPLACED.equals(a);
        if (!boot && !alarm && !updated) {
            return;
        }
        String source = boot ? "Загрузка телефона"
                : alarm ? "Перезапуск после падения процесса"
                : "Приложение обновлено (переустановлено)";
        ConfigManager config = new ConfigManager(context);
        if (!config.getWantConnected()) {
            LogStore.add("Boot", source + ": VPN не был подключён — не подключаю");
            return;
        }
        LogStore.add("Boot", source + ": VPN был подключён — восстанавливаю (режим " + config.getMode() + ")");
        // Без согласия VpnService подключение невозможно (establish() вернёт null)
        // — ретраи будут впустую. Согласие выдаётся один раз и переживает
        // перезагрузку; если его нет — юзер подключится вручную при открытии
        // приложения (там системный диалог).
        if (android.net.VpnService.prepare(context) != null) {
            LogStore.add("Boot", "Согласие на VPN не выдано — не подключаю (подключите вручную)");
            return;
        }
        Intent i = new Intent(context, GrizzlyLandVpnService.class);
        i.setAction(GrizzlyLandVpnService.ACTION_CONNECT);
        // startForegroundService: сервис обязан вызвать startForeground — он делает
        // это в onStartCommand сразу (до установления туннеля). Метод появился в
        // API 26 — на Android 7 (API 24/25) зовём обычный startService.
        try {
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                context.startForegroundService(i);
            } else {
                context.startService(i);
            }
        } catch (Exception e) {
            // Android 12+: FGS из фона под запретом (будильника не в списке
            // исключений) — на таких устройствах восстановление после падения
            // потребует открыть приложение; BOOT_COMPLETED exemption действует.
            LogStore.add("Boot", "Не смог запустить сервис из фона: " + e);
        }
    }
}
