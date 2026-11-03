package com.grizzlyland.vpn;

import android.content.ComponentName;
import android.content.Intent;
import android.net.VpnService;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

/**
 * Плитка в шторке (Quick Settings), как у WireGuard и OpenVPN for Android:
 * тап — подключить/отключить VPN, не открывая приложение.
 *
 * Почему уведомление при отключении исчезает, а плитка — нет: уведомление
 * принадлежит foreground-сервису и честно удаляется вместе с ним (статус-бар
 * не показывает «ключ» при выключенном VPN — требование 26.10). Плитку же
 * система держит в шторке сама, независимо от состояния VPN — поэтому
 * «отключить и подключить через шторку» делаем через неё.
 *
 * Состояние: ACTIVE = сервис жив (подключён / подключается / ждёт сеть) —
 * тап отключает; INACTIVE = VPN выключен — тап подключает. Сервис после
 * каждого broadcastState() дёргает requestListeningState, система будит
 * плитку и она перечитывает состояние в onStartListening. При раскрытии
 * шторки система тоже вызывает onStartListening — состояние всегда свежее,
 * даже после смерти/перезапуска процесса.
 */
public class VpnTileService extends TileService {

    @Override
    public void onStartListening() {
        updateTile();
    }

    @Override
    public void onClick() {
        if (GrizzlyLandVpnService.connected || GrizzlyLandVpnService.serviceActive) {
            // Тот же путь, что кнопка «Отключить» в уведомлении и на главном
            // экране: wantConnected=false + штатное глушение всего.
            startServiceCompat(GrizzlyLandVpnService.ACTION_DISCONNECT);
            paintTile(false);
        } else {
            // Без выданного согласия VpnService подключение невозможно
            // (полное удаление+установка сбрасывает согласие) — открываем
            // приложение: там системный диалог и кнопка «Подключить».
            if (VpnService.prepare(this) != null) {
                Intent i = new Intent(this, MainActivity.class);
                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(i);
                return;
            }
            // Тап по плитке — пользовательское действие: старт foreground-
            // сервиса из TileService разрешён (сервис вызывает startForeground
            // в самом начале onStartCommand).
            startServiceCompat(GrizzlyLandVpnService.ACTION_CONNECT);
            paintTile(true);
        }
    }

    /** Немедленно перекрасить плитку под выбранное действие (иначе до
     *  следующего onStartListening плитка показывает ПРЕДЫДУЩЕЕ состояние —
     *  наблюдалось на Android 11: requestListeningState из broadcastState()
     *  доезжает с задержкой, а при раскрытии шторки состояние всегда
     *  перечитывается заново). */
    private void paintTile(boolean on) {
        Tile tile = getQsTile();
        if (tile == null) {
            return;
        }
        tile.setState(on ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        tile.updateTile();
    }

    private void startServiceCompat(String action) {
        Intent i = new Intent(this, GrizzlyLandVpnService.class);
        i.setAction(action);
        try {
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                startForegroundService(i);
            } else {
                startService(i);
            }
        } catch (Exception ignored) {
        }
    }

    private void updateTile() {
        Tile tile = getQsTile();
        boolean on = GrizzlyLandVpnService.connected || GrizzlyLandVpnService.serviceActive;
        android.util.Log.d("VpnTile", "updateTile: tile=" + (tile == null ? "null" : "ok")
                + " on=" + on);
        if (tile == null) {
            return; // плитка ещё не добавлена в шторку
        }
        tile.setState(on ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        tile.updateTile();
    }

    /** Попросить систему перечитать плитку (вызывает onStartListening, если
     *  плитка добавлена). Безопасно вызывать всегда — если плитки нет, система
     *  просто ничего не делает. */
    public static void requestUpdate(android.content.Context ctx) {
        try {
            TileService.requestListeningState(ctx,
                    new ComponentName(ctx, VpnTileService.class));
        } catch (Exception ignored) {
        }
    }
}
