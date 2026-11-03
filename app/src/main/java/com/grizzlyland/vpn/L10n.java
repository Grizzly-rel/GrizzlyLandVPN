package com.grizzlyland.vpn;

import android.content.Context;

/**
 * Локализация строк журнала и диагностики НАШЕГО кода (LogStore, lastError,
 * сообщения исключений приложения). Оригинальные строки движков (xray-core,
 * openvpn, wireguard-go/amneziawg-go) не переводятся — только наша обёртка.
 *
 * Контекст запоминается в точках входа (активити, сервис, BootReceiver) до
 * первого логирования; язык следует системной локали. До инициализации s()
 * возвращает заглушку log#<resId> и никогда не бросает исключений (ошибка
 * форматирования в логе не должна ронять приложение).
 */
public final class L10n {

    private static volatile Context appCtx;

    private L10n() {
    }

    /** Запомнить контекст приложения и выставить язык ошибкам Go-обёртки. */
    public static void init(Context c) {
        if (c == null) {
            return;
        }
        if (appCtx == null) {
            appCtx = c.getApplicationContext();
        }
        try {
            // Язык ошибок Go-обёртки туннелей (native/libxray, Libxray.SetLang):
            // следует системной локали; дефолт движка — английский.
            String lang = appCtx.getResources().getConfiguration().locale.getLanguage();
            libxray.Libxray.setLang("ru".equals(lang) ? "ru" : "en");
        } catch (Throwable ignored) {
        }
    }

    /** Строка ресурса с подстановками (плейсхолдеры только %s — типобезопасно). */
    public static String s(int resId, Object... args) {
        Context c = appCtx;
        if (c == null) {
            return "log#" + Integer.toHexString(resId);
        }
        try {
            return args.length == 0 ? c.getString(resId) : c.getString(resId, args);
        } catch (Exception e) {
            return "log#" + Integer.toHexString(resId);
        }
    }
}
