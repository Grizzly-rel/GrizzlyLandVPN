package com.grizzlyland.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileDescriptor;

/**
 * VPN-сервис. Создаёт виртуальный интерфейс через Android VpnService
 * и применяет per-app фильтрацию (addAllowedApplication) — как в OpenVPN for Android.
 *
 * В полной реализации сюда подключаются Xray (внешний туннель) и OpenVPN
 * (внутренний, cipher none, маршрутизация). Здесь реализован сам каркас
 * VpnService с per-app выбором, который можно проверить на устройстве.
 */
public class GrizzlyLandVpnService extends VpnService {

    public static final String ACTION_CONNECT = "com.grizzlyland.vpn.CONNECT";
    public static final String ACTION_DISCONNECT = "com.grizzlyland.vpn.DISCONNECT";
    public static final String ACTION_RECONNECT = "com.grizzlyland.vpn.RECONNECT";
    public static final String ACTION_STATE_CHANGED = "com.grizzlyland.vpn.STATE_CHANGED";
    /** Живое применение флага «Подробный журнал» — БЕЗ реконнекта VPN. */
    public static final String ACTION_SET_DEBUG = "com.grizzlyland.vpn.SET_DEBUG";

    private static final String TAG = "GrizzlyLandVpnService";
    private static final String CHANNEL_ID = "grizzlylandvpn";
    private static final int NOTIF_ID = 1;

    /** Глобальный флаг: подключён ли VPN (для UI). */
    public static volatile boolean connected = false;

    /** Последняя ошибка подключения (показывается в UI). */
    public static volatile String lastError = "";

    /** Жив ли сервис сейчас (true от onCreate до onDestroy). MainActivity по нему
     *  и connected решает, нужно ли восстанавливать VPN при открытии приложения.
     *  При смерти процесса статик сбрасывается в false вместе с процессом. */
    public static volatile boolean serviceActive = false;

    /** «VPN включён, но сети с интернетом нет»: движки и TUN не подняты, ждём
     *  появления любой сети с работающим интернетом (Wi-Fi/LTE/Ethernet) — тогда
     *  подключаемся автоматически. Честный текст в уведомлении («Жду появления
     *  интернета…»), значка ключа в статус-баре нет (TUN не создан), движки не
     *  тратят батарею на посылку пакетов в никуда. */
    public static volatile boolean waitingNetwork = false;

    private ParcelFileDescriptor vpnInterface;
    private ConfigManager config;
    private XrayRunner xrayRunner = new XrayRunner();
    private OpenVpnRunner openVpnRunner = new OpenVpnRunner();
    /** SSH-туннель для режима openvpn_ssh (живёт, пока работает VPN в этом режиме). */
    private SshTunnel sshTunnel;
    /** WireGuard-движок для режима wireguard (живёт, пока работает VPN в этом режиме). */
    private WgRunner wgRunner;
    /** AmneziaWG-движок для режима amneziawg (живёт, пока работает VPN в этом режиме). */
    private AwgRunner awgRunner;
    /** Сетевой колбэк режима WireGuard: при смене сети пересоздаём туннель
     *  (UDP-сокеты движка перепривязываются). */
    private android.net.ConnectivityManager.NetworkCallback wgNetCallback;
    private android.net.Network wgLastNetwork;
    /** Эпоха старта: инвалидирует асинхронный старт WG-через-Xray при
     *  disconnect/реконнекте (резолв endpoint'а идёт в рабочем потоке). */
    /** Ретраи старта WG (режим 5) при транзиентных ошибках (резолв endpoint'а,
     *  пока сеть пропала/только возвращается). Бэкофф 2→30с, отменяется сменой
     *  startEpoch (disconnect/новый connect). */
    private int wgRetryAttempts = 0;
    private int wgRetryEpoch = -1;
    private final android.os.Handler mainHandler =
            new android.os.Handler(android.os.Looper.getMainLooper());
    private final Runnable wgRetryRunnable = new Runnable() {
        @Override
        public void run() {
            if (startEpoch.get() != wgRetryEpoch) {
                return; // отменено: disconnect или пользовательский connect
            }
            if (!connected && wgRunner == null && awgRunner == null) {
                connect();
            }
        }
    };

    /** Планирует повторный старт WG с бэкоффом (2,4,8,16,30с — далее 30с). */
    private void scheduleWgRetry(String reason) {
        wgRetryEpoch = startEpoch.get();
        long delay = 2000L << Math.min(wgRetryAttempts, 4);
        if (delay > 30000) {
            delay = 30000;
        }
        wgRetryAttempts++;
        LogStore.add("Service", "WG: " + reason
                + " — повторная попытка через " + (delay / 1000) + " с");
        mainHandler.removeCallbacks(wgRetryRunnable);
        mainHandler.postDelayed(wgRetryRunnable, delay);
    }

    /** Ретраи неудачного establish() («VpnService не разрешил TUN»). Типичный
     *  случай — автоподключение при загрузке телефона: BOOT_COMPLETED приходит
     *  ДО первой разблокировки экрана, и система в этот момент не выдаёт
     *  TUN-интерфейс (проверено 23.10: establish()=null сразу после boot).
     *  Ретраим с бэкоффом 5..60с ограниченное число раз — после разблокировки
     *  establish проходит и VPN поднимается сам. Останавливается disconnect'ом
     *  (эпоха-гвард) и при исчерпании попыток. */
    private int tunRetryAttempts = 0;
    private int tunRetryEpoch = -1;
    private static final int TUN_RETRY_MAX = 30;

    private final Runnable tunRetryRunnable = new Runnable() {
        @Override
        public void run() {
            if (startEpoch.get() != tunRetryEpoch) {
                return; // отменено: disconnect или новый connect
            }
            if (connected || vpnInterface != null) {
                return; // пока ждали — уже подключилось
            }
            // Подчистить возможные остатки движков (SOCKS/SSH/openvpn могли
            // частично стартовать до неудачного establish) и пробовать заново.
            xrayRunner.stop();
            openVpnRunner.stop();
            stopSshTunnel();
            stopWgEngine();
            connect();
        }
    };

    private void scheduleTunRetry(String modeTag) {
        tunRetryEpoch = startEpoch.get();
        tunRetryAttempts++;
        long delay = Math.min(5000L * tunRetryAttempts, 60000L);
        LogStore.add("Service", "VpnService не дал TUN (" + modeTag + ") — повтор через "
                + (delay / 1000) + " с (при загрузке телефона: ждём разблокировки экрана)");
        updateNotification("Подключение…");
        mainHandler.removeCallbacks(tunRetryRunnable);
        mainHandler.postDelayed(tunRetryRunnable, delay);
    }

    /** Неудачный establish() во всех режимах: если VPN должен быть подключён
     *  (автоподключение при загрузке/падении/перезапуске) — ретраи; иначе
     *  (ручной запуск, согласие не выдано) — как раньше, фатально. */
    private void handleTunFailure(String modeTag) {
        LogStore.add("Service", "ОШИБКА: VpnService не разрешил TUN (" + modeTag + ")");
        lastError = "VpnService не разрешил TUN";
        broadcastState();
        if (config.getWantConnected() && tunRetryAttempts < TUN_RETRY_MAX) {
            scheduleTunRetry(modeTag);
        } else {
            stopSelf();
        }
    }

    /** Ретраи после внезапной смерти процесса openvpn (management-exit,
     *  убийство системой и т.п.): бэкофф 2→30с, отменяется сменой startEpoch
     *  (disconnect/новый connect). Фатальные ошибки (битый конфиг, отказ auth)
     *  не ретраятся — см. OpenVpnRunner.sawFatalFailure(). */
    private int ovpnRetryAttempts = 0;
    private int ovpnRetryEpoch = -1;
    private final Runnable ovpnRetryRunnable = new Runnable() {
        @Override
        public void run() {
            if (startEpoch.get() != ovpnRetryEpoch) {
                return; // отменено: disconnect или пользовательский connect
            }
            if (connected || vpnInterface != null || openVpnRunner.isRunning()) {
                return; // пока ждали — уже подключилось
            }
            xrayRunner.stop();
            stopSshTunnel();
            connect();
        }
    };

    private void scheduleOvpnRetry(String reason) {
        ovpnRetryEpoch = startEpoch.get();
        long delay = Math.min(2000L << Math.min(ovpnRetryAttempts, 4), 30000L);
        ovpnRetryAttempts++;
        LogStore.add("Service", "OpenVPN: " + reason
                + " — повторная попытка через " + (delay / 1000) + " с");
        updateNotification("Подключение…");
        mainHandler.removeCallbacks(ovpnRetryRunnable);
        mainHandler.postDelayed(ovpnRetryRunnable, delay);
    }

    private final java.util.concurrent.atomic.AtomicInteger startEpoch =
            new java.util.concurrent.atomic.AtomicInteger(0);

    /** Флаг «обработчик падений уже установлен» (по одному на процесс). */
    private static boolean crashHandlerInstalled = false;

    @Override
    public void onCreate() {
        super.onCreate();
        serviceActive = true;
        installCrashRestart();
        registerConnectivityWatch();
    }

    /** При падении процесса (неперехваченное исключение в любом потоке) система
     *  НЕ перезапускает sticky-сервисы упавшего приложения (проверено: AMS
     *  «restarting=false»). Ставим одноразовую будильнику через ~3с — она
     *  переживает смерть процесса и будит BootReceiver, который стартует сервис,
     *  если пользователь хотел подключённый VPN. Нативные падения (SIGABRT в
     *  движках) не ловятся — там Java-стек не выполняется. */
    private void installCrashRestart() {
        if (crashHandlerInstalled) {
            return;
        }
        crashHandlerInstalled = true;
        final android.content.Context ctx = getApplicationContext();
        final Thread.UncaughtExceptionHandler prev = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            try {
                if (new ConfigManager(ctx).getWantConnected()) {
                    android.app.AlarmManager am =
                            (android.app.AlarmManager) ctx.getSystemService(Context.ALARM_SERVICE);
                    android.app.PendingIntent pi = android.app.PendingIntent.getBroadcast(ctx, 1001,
                            new Intent(ctx, BootReceiver.class).setAction(BootReceiver.ACTION_ALARM_RESTART),
                            android.app.PendingIntent.FLAG_UPDATE_CURRENT
                                    | android.app.PendingIntent.FLAG_IMMUTABLE);
                    // setAndAllowWhileIdle: без SCHEDULE_EXACT_ALARM (targetSdk 34),
                    // будит из doze; на интерактивном устройстве срабатывает за секунды.
                    am.setAndAllowWhileIdle(android.app.AlarmManager.ELAPSED_REALTIME_WAKEUP,
                            android.os.SystemClock.elapsedRealtime() + 3000, pi);
                    android.util.Log.w("GrizzlyLog", "Падение процесса — будильник перезапуска VPN через ~3с");
                }
            } catch (Throwable ignored) {
            }
            if (prev != null) {
                prev.uncaughtException(t, e);
            }
        });
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        config = new ConfigManager(this);
        // startForeground ПЕРВЫМ делом (до ветки DISCONNECT тоже): сервис могут
        // запустить через startForegroundService из фона (autoRestore за keyguard,
        // MainActivity.startServiceCompat) — тогда обязаны вызвать startForeground
        // в любом пути, иначе краш «did not then call Service.startForeground()».
        // Явный тип FGS на 29+ (на Android 14+ тип обязателен; на 26-28 обычный
        // вызов — перегрузки с типом не существует, а 24-25 не знают про FGS вовсе).
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIF_ID, buildNotification(),
                    android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        } else {
            startForeground(NOTIF_ID, buildNotification());
        }
        String action = intent != null ? intent.getAction() : null;
        if (ACTION_DISCONNECT.equals(action)) {
            // Явное отключение пользователем — автоподключение при загрузке/падении выключаем.
            config.setWantConnected(false);
            LogStore.add("Service", "Отключение пользователем — восстановление при загрузке/падении выключено");
            disconnect();
            return START_NOT_STICKY;
        }
        // Рестарт сервиса системой после падения процесса (START_STICKY, intent==null):
        // подключаем только если пользователь не отключал VPN сам.
        if (intent == null && !config.getWantConnected()) {
            LogStore.add("Service", "Рестарт после падения: VPN до падения не работал — не подключаю");
            stopSelf();
            return START_NOT_STICKY;
        }
        // Подключение (пользователь, BootReceiver, смена сети, рестарт после падения) —
        // запоминаем «хотел подключён» для восстановления при перезагрузке/падении.
        config.setWantConnected(true);
        // Явный интент (пользователь или смена сети) — новая попытка с нуля.
        wgRetryAttempts = 0;
        tunRetryAttempts = 0;
        ovpnRetryAttempts = 0;
        if (ACTION_SET_DEBUG.equals(action)) {
            // Живое применение «Подробного журнала» — реконнект НЕ делаем.
            applyLogFlagLive();
            return START_STICKY;
        }
        if (ACTION_RECONNECT.equals(action)) {
            // Пересоздать VPN с новыми настройками (применение без перезапуска).
            if (connected) {
                xrayRunner.stop();
                openVpnRunner.stop();
                stopSshTunnel();
                stopWgEngine();
                if (vpnInterface != null) {
                    try {
                        vpnInterface.close();
                    } catch (Exception ignored) {
                    }
                    vpnInterface = null;
                }
                connected = false;
                broadcastState();
            }
        }
        connect();
        return START_STICKY;
    }

    /** Попросить сервис применить новые настройки, если VPN подключён. */
    public static void requestApply(Context context) {
        if (!connected) {
            return;
        }
        Intent i = new Intent(context, GrizzlyLandVpnService.class);
        i.setAction(ACTION_RECONNECT);
        context.startService(i);
    }

    /** Применить флаг «Подробный журнал» к живому VPN без реконнекта. */
    public static void requestSetDebug(Context context) {
        if (!connected) {
            return;
        }
        Intent i = new Intent(context, GrizzlyLandVpnService.class);
        i.setAction(ACTION_SET_DEBUG);
        context.startService(i);
    }

    /**
     * Живое применение флага «Подробный журнал» (кнопка в журнале), без
     * реконнекта: OpenVPN — verb через management на лету; Xray — перезапуск
     * ядра с новым loglevel (TUN/движки переживают, восстановление авто);
     * WireGuard (реж. 5) — фильтр в памяти WgRunner, делать ничего не нужно.
     */
    private void applyLogFlagLive() {
        boolean verbose = config.getLogDebug();
        String mode = config.getMode();
        if (openVpnRunner.isRunning()) {
            int verb = verbose ? 5 : config.getOvpnVerb();
            openVpnRunner.setVerb(verb);
            LogStore.add("Service", "OpenVPN verb → " + verb);
        }
        if (xrayRunner.isRunning()) {
            restartXrayForLogFlag();
        }
        if (wgRunner != null && wgRunner.isRunning()) {
            LogStore.add("Service", verbose
                    ? "WireGuard: подробные строки движка показаны (фильтр снят)"
                    : "WireGuard: подробные строки движка скрыты");
        }
        if (awgRunner != null && awgRunner.isRunning()) {
            LogStore.add("Service", verbose
                    ? "AmneziaWG: подробные строки движка показаны (фильтр снят)"
                    : "AmneziaWG: подробные строки движка скрыты");
        }
    }

    /**
     * Перезапуск ядра Xray с новым loglevel, не трогая TUN и остальные движки.
     * Активные TCP-соединения приложений оборвутся и переустановятся; в режиме
     * Xray+OpenVPN сессия openvpn переподключится сама (SOCKS поднимется заново);
     * WG-движок (реж. «через Xray») поднимет handshake по первому пакету.
     */
    private void restartXrayForLogFlag() {
        String mode = config.getMode();
        try {
            xrayRunner.stop();
            String logDir = getFilesDir().getAbsolutePath();
            if (ConfigManager.MODE_WG_XRAY.equals(mode)) {
                if (vpnInterface != null) {
                    xrayRunner.startTunWg(config, vpnInterface.getFd(), logDir);
                }
            } else if (ConfigManager.MODE_XRAY_OVPN.equals(mode)) {
                xrayRunner.startSocks(config, logDir);
            } else if (vpnInterface != null) {
                // Режим «только Xray»: custom-конфиг или собранный из полей.
                String custom = config.getXrayCustomJson();
                if (custom != null && !custom.trim().isEmpty()) {
                    xrayRunner.startTunCustom(config, vpnInterface.getFd(), logDir);
                } else {
                    xrayRunner.startTun(config, vpnInterface.getFd(), logDir);
                }
            }
            LogStore.add("Service", "Xray перезапущен (loglevel="
                    + (config.getLogDebug() ? "debug" : "info") + "), TUN не пересоздавался");
        } catch (Exception e) {
            Log.e(TAG, "Xray restart (log flag) failed", e);
            LogStore.add("Service", "ОШИБКА перезапуска Xray: " + e);
            lastError = e.getMessage();
            connected = false;
            broadcastState();
            openVpnRunner.stop();
            stopSshTunnel();
            stopWgEngine();
            if (vpnInterface != null) {
                try {
                    vpnInterface.close();
                } catch (Exception ignored) {
                }
                vpnInterface = null;
            }
            stopSelf();
        }
    }

    private void connect() {
        if (vpnInterface != null) {
            LogStore.add("Service", "connect(): интерфейс уже существует — пропуск ("
                    + (openVpnRunner.isRunning() ? "openvpn живой" : "openvpn не запущен") + ")");
            return;
        }
        // Сети с интернетом нет — движки и TUN не поднимаем вовсе: честный статус
        // в уведомлении, значка ключа нет (TUN не создаётся), батарея не тратится.
        // Подключимся автоматически, когда интернет появится (connWatch → connect()).
        // Это закрывает шторм при загрузке без сети (WG-движок + «sendmsg: network
        // is unreachable» + рестарты) для ВСЕХ режимов, не только OpenVPN.
        if (!hasInternetCapableNetwork()) {
            enterWaitingForNetwork("на момент подключения");
            return;
        }
        startEpoch.incrementAndGet();
        try {
            String mode = config.getMode();
            lastError = "";
            LogStore.add("Service", "==== Подключение (режим: " + mode + ") ====");
            if (ConfigManager.MODE_OPENVPN.equals(mode) || ConfigManager.MODE_XRAY_OVPN.equals(mode)
                    || ConfigManager.MODE_OVPN_SSH.equals(mode)) {
                // Режим OpenVPN: TUN-интерфейс создаёт VpnService, но fd отдаётся
                // нативному openvpn через management (команда OPENTUN), поэтому
                // здесь tun НЕ устанавливаем заранее. Устанавливаем провайдер.
                startOpenVpnMode(mode);
            } else if (ConfigManager.MODE_WG.equals(mode)) {
                // Режим WireGuard: TUN создаём сами и отдаём fd движку wireguard-go.
                startWgMode();
            } else if (ConfigManager.MODE_AWG.equals(mode)) {
                // Режим AmneziaWG: TUN создаём сами и отдаём fd движку amneziawg-go
                // (UAPI-конфиг с параметрами обфускации от AwgConfigParser).
                startAwgMode();
            } else if (ConfigManager.MODE_WG_XRAY.equals(mode)) {
                // WireGuard через Xray: TUN как в режиме "только Xray", но дефолтный
                // outbound Xray — wireguard, чей UDP завёрнут в VLESS (dialerProxy).
                startWgXrayMode();
            } else {
                // Режимы "только Xray": устанавливаем TUN и отдаём fd Xray.
                // Если задан пользовательский custom-конфиг — используем его (inbounds
                // подменяются на tun-вход), иначе собираем конфиг из полей.
                vpnInterface = buildBuilder(null, 1400, null, null).establish();
                if (vpnInterface != null) {
                    try {
                        String logDir = getFilesDir().getAbsolutePath();
                        String custom = config.getXrayCustomJson();
                        if (custom != null && !custom.trim().isEmpty()) {
                            xrayRunner.startTunCustom(config, vpnInterface.getFd(), logDir);
                        } else {
                            xrayRunner.startTun(config, vpnInterface.getFd(), logDir);
                        }
                        // connected — только после успешного старта ядра. Раньше флаг
                        // ставился до startTun: при падении Xray UI показывал «подключено»
                        // при мёртвом туннеле.
                        connected = true;
                        tunRetryAttempts = 0;
                        broadcastState();
                        updateNotification("VPN активен");
                    } catch (Exception e) {
                        Log.e(TAG, "Xray TUN start failed", e);
                        LogStore.add("Service", "ОШИБКА запуска Xray TUN: " + e);
                        lastError = e.getMessage();
                        // Туннель без работающего ядра бесполезен — закрываем интерфейс.
                        try {
                            vpnInterface.close();
                        } catch (Exception ignored) {
                        }
                        vpnInterface = null;
                        broadcastState();
                        stopSelf();
                        return;
                    }
                } else {
                    handleTunFailure("Xray");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            lastError = e.getMessage();
            broadcastState();
            stopSelf();
        }
    }

    // ============ Режим ожидания сети («VPN включён, интернета нет») ============
    // Проблема (лог юзера 26.10, загрузка без сети, старая версия): сервис поднимал
    // WG-движок сразу, тот заваливал журнал «sendmsg: network is unreachable»,
    // уведомление врало «VPN активен», значок ключа висел в статус-баре, батарея
    // горела на посылке пакетов в никуда и рестартах движка. Теперь: если интернета
    // нет — TUN/движки не поднимаются вовсе; при ПОЯВЛЕНИИ интернета (любой транспорт)
    // подключаемся автоматически. Если сеть пропала УЖЕ ПОСЛЕ подключения — держим
    // туннель GRACE-паузу (короткие обрывы переживает живой туннель), потом глушим
    // и тоже переходим в ожидание: значок ключа исчезает, уведомление честное.

    /** Грейс-пауза перед глушением туннеля при полной потере сети: короткие
     *  обрывы (роуминг Wi-Fi, переключение Wi-Fi↔LTE) переживает живой туннель
     *  без пересоздания; если сеть не вернулась — глушим всё и ждём. */
    private static final long NET_LOST_GRACE_MS = 10000;
    /** Уведомление «Сеть пропала — жду…» уже показано и грейс-таймер тикает. */
    private boolean netLostNotified = false;
    /** Пассивный колбэк всех сетей с интернетом (весь срок жизни сервиса). */
    private android.net.ConnectivityManager.NetworkCallback connWatchCallback;

    /** Есть ли сеть с РАБОТАЮЩИМ интернетом: не наша VPN (TRANSPORT_VPN),
     *  NET_CAPABILITY_INTERNET + VALIDATED. VALIDATED нужен, чтобы не поднимать
     *  туннель через captive-портал/мёртвый Wi-Fi: «появление интернета» = сеть
     *  реально пропускает трафик (проверка самой Android). При ошибке определения
     *  — true (fail-open, как в hold-шлюзе OpenVPN). */
    private boolean hasInternetCapableNetwork() {
        try {
            android.net.ConnectivityManager cm = (android.net.ConnectivityManager)
                    getSystemService(CONNECTIVITY_SERVICE);
            if (cm == null) {
                return true;
            }
            for (android.net.Network n : cm.getAllNetworks()) {
                android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(n);
                if (caps == null) continue;
                if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) continue;
                if (!caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
                if (!caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)) continue;
                return true;
            }
        } catch (Exception e) {
            return true;
        }
        return false;
    }

    private static String networkLabel(android.net.NetworkCapabilities caps) {
        if (caps == null) return "Сеть";
        if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) return "VPN (наш tun)";
        if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)) return "Wi-Fi";
        if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)) return "мобильная сеть";
        if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET)) return "Ethernet";
        return "сеть";
    }

    /** Перейти в ожидание сети: движки/TUN гарантированно погашены, уведомление —
     *  «Жду появления интернета…». Идемпотентно (повторные вызовы — no-op). */
    private void enterWaitingForNetwork(String reason) {
        if (waitingNetwork) {
            return; // уже ждём — не спамим журналом и уведомлением
        }
        waitingNetwork = true;
        connected = false;
        lastError = "";
        netLostNotified = false;
        mainHandler.removeCallbacks(netLostGraceRunnable);
        broadcastState();
        updateNotification("Жду появления интернета…");
        LogStore.add("Service", "Сети с интернетом нет (" + reason + ") — TUN не поднимаю "
                + "(значка ключа нет), движки выключены; подключусь сам при появлении интернета");
    }

    /** Сеть пропала (или потеряла интернет): если это надолго — через грейс-паузу
     *  глушим туннель и переходим в ожидание; если сеть вернулась в паузу —
     *  тихо возвращаем обычный статус (туннель само восстановился). */
    private void maybeHandleNetworkLoss() {
        if (!connected || waitingNetwork) {
            return;
        }
        if (hasInternetCapableNetwork()) {
            return; // есть другая сеть с интернетом (например, LTE подхватил вместо Wi-Fi)
        }
        if (netLostNotified) {
            return; // грейс-таймер уже тикает
        }
        netLostNotified = true;
        updateNotification("Сеть пропала — жду…");
        LogStore.add("Service", "Сети с интернетом нет — держу туннель ещё "
                + (NET_LOST_GRACE_MS / 1000) + "с (короткий обрыв переживёт), "
                + "потом глушу до появления сети");
        mainHandler.removeCallbacks(netLostGraceRunnable);
        mainHandler.postDelayed(netLostGraceRunnable, NET_LOST_GRACE_MS);
    }

    /** Сеть появилась / получила интернет: из ожидания — подключаемся; во время
     *  грейс-паузы после потери — возвращаем обычный статус. */
    private void maybeHandleNetworkReturn(android.net.NetworkCapabilities caps) {
        if (caps != null && caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) {
            return; // собственный tun
        }
        if (waitingNetwork) {
            if (caps == null || !caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                return;
            }
            if (!caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                LogStore.add("Service", networkLabel(caps)
                        + " появилась, но интернет ещё не проверен — жду валидации");
                return; // валидация придёт отдельным onCapabilitiesChanged
            }
            LogStore.add("Service", networkLabel(caps) + " с интернетом — подключаюсь");
            waitingNetwork = false;
            connect();
        } else if (connected && netLostNotified
                && caps != null
                && caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
            netLostNotified = false;
            mainHandler.removeCallbacks(netLostGraceRunnable);
            updateNotification("VPN активен");
            LogStore.add("Service", networkLabel(caps) + " вернулась — туннель работает");
        }
    }

    private final Runnable netLostGraceRunnable = new Runnable() {
        @Override
        public void run() {
            netLostNotified = false;
            if (!connected || waitingNetwork) {
                return; // уже отключено/уже ждём
            }
            if (hasInternetCapableNetwork()) {
                updateNotification("VPN активен"); // сеть вернулась, пока шла пауза
                return;
            }
            LogStore.add("Service", "Сети нет уже " + (NET_LOST_GRACE_MS / 1000)
                    + "с — глушу туннель и движки до появления интернета "
                    + "(значок ключа исчезнет, батарея не тратится)");
            connected = false;
            broadcastState();
            xrayRunner.stop();
            openVpnRunner.stop();
            stopSshTunnel();
            stopWgEngine();
            if (vpnInterface != null) {
                try {
                    vpnInterface.close();
                } catch (Exception ignored) {
                }
                vpnInterface = null;
            }
            enterWaitingForNetwork("сеть пропала надолго");
        }
    };

    /** Пассивное слежение за сетями (все виды соединений, не только default):
     *  появление интернета → автоподключение из ожидания; потеря → честный
     *  статус и (после грейса) глушение туннеля. Ноль поллинга и будильников —
     *  колбэки приходят только при изменениях сети. */
    private void registerConnectivityWatch() {
        if (connWatchCallback != null) {
            return;
        }
        try {
            android.net.ConnectivityManager cm = (android.net.ConnectivityManager)
                    getSystemService(CONNECTIVITY_SERVICE);
            android.net.NetworkRequest req = new android.net.NetworkRequest.Builder()
                    .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build();
            connWatchCallback = new android.net.ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(android.net.Network network) {
                    android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                    LogStore.add("Service", "Сеть доступна: " + networkLabel(caps)
                            + (caps != null && caps.hasCapability(
                                    android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                                    ? " (есть интернет)" : " (без интернета)"));
                    maybeHandleNetworkReturn(caps);
                }

                @Override
                public void onCapabilitiesChanged(android.net.Network network,
                                                  android.net.NetworkCapabilities caps) {
                    if (caps != null
                            && caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                        maybeHandleNetworkReturn(caps);
                    } else {
                        maybeHandleNetworkLoss();
                    }
                }

                @Override
                public void onLost(android.net.Network network) {
                    android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                    LogStore.add("Service", "Сеть потеряна: "
                            + (caps == null ? "интерфейс исчез" : networkLabel(caps)));
                    maybeHandleNetworkLoss();
                }
            };
            cm.registerNetworkCallback(req, connWatchCallback);
            LogStore.add("Service", "Слежение за сетью включено (интернет появился → автоподключение)");
        } catch (Exception e) {
            LogStore.add("Service", "Слежение за сетью не зарегистрировано: " + e);
        }
    }

    private void unregisterConnectivityWatch() {
        if (connWatchCallback == null) {
            return;
        }
        try {
            android.net.ConnectivityManager cm = (android.net.ConnectivityManager)
                    getSystemService(CONNECTIVITY_SERVICE);
            cm.unregisterNetworkCallback(connWatchCallback);
        } catch (Exception ignored) {
        }
        connWatchCallback = null;
    }

    /** Запуск режимов с OpenVPN (только OpenVPN / Xray+OpenVPN / OpenVPN-через-SSH). */
    private void startOpenVpnMode(String mode) throws Exception {
        String socks = null;
        String logDir = getFilesDir().getAbsolutePath();
        if (ConfigManager.MODE_OVPN_SSH.equals(mode)) {
            // Сначала поднимаем SSH-форвард; openvpn стартует из onSshReady().
            startSshMode();
            return;
        }
        if (ConfigManager.MODE_XRAY_OVPN.equals(mode)) {
            xrayRunner.startSocks(config, logDir);
            socks = "127.0.0.1:" + config.getXraySocksPort();
        }
        openVpnRunner.start(this, config, this::establishTunForOpenVpn, this::protectFd, socks,
                this::onOpenVpnExited);
    }

    /**
     * Режим OpenVPN-через-SSH: подключаемся к SSH-серверу с локальным форвардом
     * (аналог ssh -L 11940:127.0.0.1:1194). OpenVPN стартует только после того,
     * как форвард реально слушает локальный порт. Реконнекты SSH-сессии туннель
     * переживает сам (openvpn в это время просто ретраит подключение).
     */
    private void startSshMode() {
        if (!config.isSshConfigured()) {
            lastError = "SSH: не заданы хост/пользователь (Настройки → Настройки SSH)";
            LogStore.add("Service", "ОШИБКА: " + lastError);
            broadcastState();
            stopSelf();
            return;
        }
        stopSshTunnel();
        sshTunnel = new SshTunnel(config, this::protectFd, new SshTunnel.Listener() {
            @Override
            public void onReady(int localPort) {
                onSshReady(localPort);
            }

            @Override
            public void onFinalFailure(String reason) {
                onSshFailed(reason);
            }
        });
        sshTunnel.start();
    }

    /** SSH-форвард готов: запускаем openvpn с remote=127.0.0.1:<localPort>. */
    private void onSshReady(int localPort) {
        LogStore.add("Service", "SSH-туннель готов, локальный форвард 127.0.0.1:" + localPort);
        if (openVpnRunner.isRunning()) {
            // Реконнект SSH-сессии: openvpn уже ретраит и подцепится сам.
            return;
        }
        openVpnRunner.setSshLocalPort(localPort);
        try {
            openVpnRunner.start(this, config, this::establishTunForOpenVpn, this::protectFd,
                    null, this::onOpenVpnExited);
        } catch (Exception e) {
            Log.e(TAG, "openvpn start failed (ssh mode)", e);
            LogStore.add("Service", "ОШИБКА запуска OpenVPN (SSH-режим): " + e);
            lastError = e.getMessage();
            connected = false;
            broadcastState();
            stopSshTunnel();
            stopSelf();
        }
    }

    /** SSH не смог подключиться после всех попыток — честно останавливаем VPN. */
    private void onSshFailed(String reason) {
        LogStore.add("Service", "ОШИБКА SSH: " + reason);
        lastError = reason;
        connected = false;
        broadcastState();
        openVpnRunner.stop();
        stopSshTunnel();
        stopSelf();
    }

    /** Останавливает SSH-туннель, если он запущен. */
    private void stopSshTunnel() {
        SshTunnel t = sshTunnel;
        sshTunnel = null;
        if (t != null) {
            t.stop();
        }
    }

    // ===== WireGuard (режим wireguard) =====

    /**
     * Режим WireGuard: парсим wg-quick конфиг, создаём TUN VpnService
     * (адреса/DNS/маршруты из конфига) и отдаём fd движку wireguard-go
     * (libwg.aar). UDP-сокеты движка защищаются через protect сразу после
     * подъёма. При смене сети туннель пересоздаётся (NetworkCallback).
     */
    private void startWgMode() {
        WgConfigParser.WgConfig cfg = WgConfigParser.parse(config.getWgRaw());
        if (!cfg.valid) {
            lastError = "WG: конфиг некорректен"
                    + (cfg.parseError.isEmpty() ? "" : (": " + cfg.parseError))
                    + " (Настройки → Настройки WireGuard)";
            LogStore.add("Service", "ОШИБКА: " + lastError);
            broadcastState();
            stopSelf();
            return;
        }
        LogStore.add("Service", "WG-конфиг: адресов=" + cfg.addresses.size()
                + " peer=" + cfg.peers + " endpoint=" + cfg.endpointForLog
                + " mtu=" + (cfg.mtu > 0 ? cfg.mtu : 1420));
        vpnInterface = buildBuilderForWg(cfg).establish();
        if (vpnInterface == null) {
            handleTunFailure("WG");
            return;
        }
        // Владение fd переходит движку: detach, чтобы close() обёртки в
        // disconnect() не закрыл fd, которым владеет wireguard-go.
        final int tunFd = vpnInterface.detachFd();
        stopWgEngine();
        wgRunner = new WgRunner(this::protectFd, config::getLogDebug, new WgRunner.Listener() {
            @Override
            public void onUp() {
                wgRetryAttempts = 0;
                tunRetryAttempts = 0;
                connected = true;
                broadcastState();
                updateNotification("VPN активен");
                LogStore.add("Service", "WireGuard: туннель поднят");
                registerWgNetworkCallback();
            }

            @Override
            public void onError(String message) {
                LogStore.add("Service", "ОШИБКА WG: " + message);
                lastError = message;
                connected = false;
                broadcastState();
                stopWgEngine();
                // Резолв endpoint'а — транзиентная ошибка (сеть пропала или ещё
                // не поднялась после переключения): не гасим VPN, ретраим с
                // бэкоффом, иначе короткий сбой сети убивает туннель навсегда
                // (наблюдалось: «пропал интернет на 5 минут» → VPN мёртв).
                // Прочие ошибки (битый конфиг, TUN) — фатальны.
                if (message != null && message.startsWith("резолв")) {
                    scheduleWgRetry("сеть недоступна (резолв endpoint'а)");
                } else {
                    stopSelf();
                }
            }
        });
        wgRunner.start(tunFd, cfg.ipc);
    }

    /**
     * Режим AmneziaWG: всё то же, что startWgMode, но движок — amneziawg-go,
     * конфиг парсит AwgConfigParser (добавляя UAPI-параметры обфускации
     * jc/jmin/jmax/s1/s2/h1..h4), TUN-билдер общий с WireGuard.
     * Ретраи при транзиентном «резолв endpoint'а» — тот же супервизор,
     * что у WG (scheduleWgRetry).
     */
    private void startAwgMode() {
        AwgConfigParser.AwgConfig cfg = AwgConfigParser.parse(config.getAwgRaw());
        if (!cfg.valid) {
            lastError = "AWG: конфиг некорректен"
                    + (cfg.parseError.isEmpty() ? "" : (": " + cfg.parseError))
                    + " (Настройки → Настройки AmneziaWG)";
            LogStore.add("Service", "ОШИБКА: " + lastError);
            broadcastState();
            stopSelf();
            return;
        }
        LogStore.add("Service", "AWG-конфиг: адресов=" + cfg.addresses.size()
                + " peer=" + cfg.peers + " endpoint=" + cfg.endpointForLog
                + " mtu=" + (cfg.mtu > 0 ? cfg.mtu : 1420)
                + " обфускация jc=" + cfg.jc + " jmin=" + cfg.jmin + " jmax=" + cfg.jmax
                + " s1=" + cfg.s1 + " s2=" + cfg.s2
                + " h1=" + cfg.h1 + " h2=" + cfg.h2 + " h3=" + cfg.h3 + " h4=" + cfg.h4);
        vpnInterface = buildBuilderForAwg(cfg).establish();
        if (vpnInterface == null) {
            handleTunFailure("AWG");
            return;
        }
        // Владение fd переходит движку: detach, чтобы close() обёртки в
        // disconnect() не закрыл fd, которым владеет amneziawg-go.
        final int tunFd = vpnInterface.detachFd();
        stopWgEngine();
        awgRunner = new AwgRunner(this::protectFd, config::getLogDebug, new AwgRunner.Listener() {
            @Override
            public void onUp() {
                wgRetryAttempts = 0;
                tunRetryAttempts = 0;
                connected = true;
                broadcastState();
                updateNotification("VPN активен");
                LogStore.add("Service", "AmneziaWG: туннель поднят");
                registerWgNetworkCallback();
            }

            @Override
            public void onError(String message) {
                LogStore.add("Service", "ОШИБКА AWG: " + message);
                lastError = message;
                connected = false;
                broadcastState();
                stopWgEngine();
                // Резолв endpoint'а — транзиентная ошибка (сеть пропала или ещё
                // не поднялась): не гасим VPN, ретраим с бэкоффом — как у WG.
                // Прочие ошибки (битый конфиг, TUN, параметры обфускации) — фатальны.
                if (message != null && message.startsWith("резолв")) {
                    scheduleWgRetry("сеть недоступна (резолв endpoint'а)");
                } else {
                    stopSelf();
                }
            }
        });
        awgRunner.start(tunFd, cfg.ipc);
    }

    /** Останавливает WG/AWG-движок, сетевой колбэк и (если жив) TUN-обёртку. */
    private void stopWgEngine() {
        unregisterWgNetworkCallback();
        WgRunner r = wgRunner;
        wgRunner = null;
        if (r != null) {
            r.stop();
        }
        AwgRunner a = awgRunner;
        awgRunner = null;
        if (a != null) {
            a.stop();
        }
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {
            }
            vpnInterface = null;
        }
    }

    /**
     * Режим "WireGuard через Xray": шифрование WG выполняет wireguard-outbound
     * самого Xray (userspace WG-клиент + gVisor-стек внутри ядра), а его UDP к
     * WG-серверу идёт через VLESS-туннель (sockopt.dialerProxy → outbound "proxy").
     * TUN создаётся как в режиме "только Xray" (адрес 10.0.0.2, DNS из Xray-настроек);
     * адреса/DNS из wg-конфига живут внутри WG-стека Xray, а не в VpnService.
     */
    private void startWgXrayMode() {
        WgConfigParser.WgConfig cfg = WgConfigParser.parse(config.getWgRaw());
        if (!cfg.valid) {
            lastError = "WG: конфиг некорректен"
                    + (cfg.parseError.isEmpty() ? "" : (": " + cfg.parseError))
                    + " (Настройки → Настройки WireGuard)";
            LogStore.add("Service", "ОШИБКА: " + lastError);
            broadcastState();
            stopSelf();
            return;
        }
        if (cfg.peerList.size() > 1) {
            LogStore.add("Service", "WG-конфиг содержит " + cfg.peerList.size()
                    + " peer — в режиме через Xray используется только первый ("
                    + cfg.endpointForLog + ")");
        }
        LogStore.add("Service", "WG-через-Xray: endpoint=" + cfg.endpointForLog
                + " адресов=" + cfg.addresses.size() + " peer=" + cfg.peers
                + " mtu=" + (cfg.mtu > 0 ? cfg.mtu : 1420));
        // Endpoint резолвит САМ Xray через свой DNS-модуль (лениво, при первом
        // трафике через wg-outbound), а запросы DNS-модуля идут через proxy
        // (VLESS) — правило inboundTag "dns-internal" в buildTunWg. Это «DNS
        // через Xray»: локальный системный DNS не участвует вовсе, поэтому
        // блокировки/отравление локального DNS не мешают резолву endpoint'а.
        // Java-резолв на стороне приложения убран (он зависел от системного DNS).
        final int myEpoch = startEpoch.get();
        final android.os.ParcelFileDescriptor[] holder = new android.os.ParcelFileDescriptor[1];
        new Thread(() -> {
            try {
                if (startEpoch.get() != myEpoch) {
                    LogStore.add("Service", "Старт WG-через-Xray отменён (состояние изменилось)");
                    return;
                }
                ParcelFileDescriptor tun = buildBuilder(null, 1400, null, null).establish();
                if (tun == null) {
                    connected = false;
                    broadcastState();
                    handleTunFailure("WG через Xray");
                    return;
                }
                holder[0] = tun;
                vpnInterface = tun;
                if (startEpoch.get() != myEpoch) {
                    LogStore.add("Service", "Старт WG-через-Xray отменён (состояние изменилось)");
                    closeQuietly(tun);
                    if (vpnInterface == tun) {
                        vpnInterface = null;
                    }
                    return;
                }
                String logDir = getFilesDir().getAbsolutePath();
                xrayRunner.startTunWg(config, tun.getFd(), logDir);
                connected = true;
                tunRetryAttempts = 0;
                broadcastState();
                updateNotification("VPN активен");
                // UDP-сокет WG живёт внутри Xray: при смене сети пересоздаём туннель
                // целиком (тот же NetworkCallback, что у режима WireGuard).
                registerWgNetworkCallback();
            } catch (Exception e) {
                Log.e(TAG, "Xray WG start failed", e);
                LogStore.add("Service", "ОШИБКА запуска Xray (WG через Xray): " + e);
                lastError = e.getMessage();
                connected = false;
                broadcastState();
                ParcelFileDescriptor tun = holder[0];
                if (tun != null) {
                    closeQuietly(tun);
                    if (vpnInterface == tun) {
                        vpnInterface = null;
                    }
                }
                stopSelf();
            }
        }, "wg-xray-start").start();
    }

    /** Закрывает ParcelFileDescriptor, глотая исключения (вспомогательная). */
    private static void closeQuietly(ParcelFileDescriptor p) {
        try {
            p.close();
        } catch (Exception ignored) {
        }
    }

    /**
     * Per-app фильтр TUN-интерфейса, общий для всех режимов.
     * «VPN для всего телефона» (vpnAllApps) — без allowed-фильтра, только
     * исключение собственного пакета (иначе соединение движка с сервером
     * зациклится через собственный туннель). Иначе: allowedApps непусто →
     * только выбранные приложения (свой пакет в список не входит и так
     * отсечён; смешивание addAllowedApplication и addDisallowedApplication
     * на Android 11+ даёт ошибку «Interface rule must specify interface»);
     * пусто → весь трафик + исключение своего пакета.
     */
    private Builder applyAppFilter(Builder builder) {
        if (config.getVpnAllApps()) {
            try {
                builder.addDisallowedApplication(getPackageName());
                LogStore.add("Service", "Приложения: весь телефон (переключатель «VPN для всего телефона»)");
            } catch (Exception e) {
                Log.e(TAG, "addDisallowedApplication failed for own package", e);
                LogStore.add("Service", "addDisallowedApplication(own) failed: " + e);
            }
            return builder;
        }
        for (String pkg : config.getAllowedApps()) {
            try {
                builder.addAllowedApplication(pkg);
            } catch (Exception e) {
                Log.e(TAG, "addAllowedApplication failed for " + pkg, e);
                LogStore.add("Service", "addAllowedApplication(" + pkg + ") failed: " + e);
            }
        }
        if (config.getAllowedApps().isEmpty()) {
            try {
                builder.addDisallowedApplication(getPackageName());
                LogStore.add("Service", "Приложения: весь телефон (per-app список пуст)");
            } catch (Exception e) {
                Log.e(TAG, "addDisallowedApplication failed for own package", e);
                LogStore.add("Service", "addDisallowedApplication(own) failed: " + e);
            }
        } else {
            LogStore.add("Service", "Per-app: выбранных приложений: " + config.getAllowedApps().size());
        }
        return builder;
    }

    /**
     * Билдер TUN для WireGuard: адреса и DNS из конфига, маршруты из
     * AllowedIPs (0.0.0.0/0 → весь трафик), per-app фильтрация как везде.
     * Отдельный метод (не общий buildBuilder), чтобы не трогать рабочий код
     * остальных режимов.
     */
    private Builder buildBuilderForWg(WgConfigParser.WgConfig cfg) {
        return buildBuilderWgStyle(cfg.addresses, cfg.dns, cfg.allowedIps, cfg.mtu);
    }

    /** Билдер TUN для AmneziaWG — тот же, что для WireGuard. */
    private Builder buildBuilderForAwg(AwgConfigParser.AwgConfig cfg) {
        return buildBuilderWgStyle(cfg.addresses, cfg.dns, cfg.allowedIps, cfg.mtu);
    }

    /**
     * Билдер TUN для WG/AWG: адреса и DNS из конфига, маршруты из
     * AllowedIPs (0.0.0.0/0 → весь трафик), per-app фильтрация как везде.
     * Отдельный метод (не общий buildBuilder), чтобы не трогать рабочий код
     * остальных режимов.
     */
    private Builder buildBuilderWgStyle(java.util.List<String> addresses,
                                        java.util.List<String> dns,
                                        java.util.List<String> allowedIps, int mtu) {
        Builder builder = new Builder()
                .setSession(getString(R.string.app_name))
                .setBlocking(true)
                .setMtu(mtu > 0 ? mtu : 1420);
        for (String cidr : addresses) {
            String[] p = cidr.split("/");
            if (p.length < 1 || !isIpv4(p[0])) {
                continue;
            }
            int prefix = 32;
            if (p.length > 1) {
                try {
                    prefix = Integer.parseInt(p[1].trim());
                } catch (NumberFormatException ignored) {
                }
            }
            if (prefix < 0 || prefix > 32) {
                prefix = 32;
            }
            try {
                builder.addAddress(p[0], prefix);
            } catch (Exception e) {
                Log.e(TAG, "WG addAddress failed for " + cidr, e);
            }
        }
        for (String d : dns) {
            if (isIpv4(d)) {
                try {
                    builder.addDnsServer(d);
                } catch (Exception e) {
                    Log.e(TAG, "WG addDnsServer failed for " + d, e);
                }
            }
        }
        boolean defaultRoute = false;
        int routesAdded = 0;
        for (String cidr : allowedIps) {
            String[] p = cidr.split("/");
            if (p.length < 1 || !isIpv4(p[0])) {
                continue;
            }
            int prefix = 32;
            if (p.length > 1) {
                try {
                    prefix = Integer.parseInt(p[1].trim());
                } catch (NumberFormatException ignored) {
                }
            }
            if (p[0].equals("0.0.0.0") && prefix == 0) {
                defaultRoute = true;
                continue;
            }
            try {
                builder.addRoute(p[0], prefix);
                routesAdded++;
                LogStore.add("Service", "маршрут: " + p[0] + "/" + prefix);
            } catch (Exception e) {
                Log.e(TAG, "WG addRoute failed for " + cidr, e);
            }
        }
        if (defaultRoute || routesAdded == 0) {
            builder.addRoute("0.0.0.0", 0);
        }
        return applyAppFilter(builder);
    }

    /**
     * Смена сети на телефоне: UDP-сокеты движка привязаны к умершему интерфейсу.
     * Простейший корректный ответ (как в официальном приложении) — пересоздать
     * туннель целиком через штатный RECONNECT.
     */
    private void registerWgNetworkCallback() {
        if (wgNetCallback != null) {
            return;
        }
        try {
            android.net.ConnectivityManager cm =
                    (android.net.ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            wgNetCallback = new android.net.ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(android.net.Network network) {
                    // Собственная VPN-сеть (tun) тоже приходит в default-callback.
                    // Её игнорируем ПОЛНОСТЬЮ (в т.ч. не трогаем wgLastNetwork):
                    // иначе каждый реконнект VPN порождает «сменилась сеть» →
                    // новый реконнект → бесконечный цикл рестартов (наблюдалось
                    // ~2.5 рестарта/сек: VPN поднялся → default=VPN → событие →
                    // реконнект → default=Wi-Fi → событие → …).
                    android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                    if (caps != null
                            && caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) {
                        return;
                    }
                    // Только дефолтная сеть (registerDefaultNetworkCallback):
                    // перезапуск нужен один раз при реальной смене сети, иначе
                    // колбэк по каждой сети (Wi-Fi + LTE) даёт цикл рестартов.
                    if (wgLastNetwork != null && !network.equals(wgLastNetwork)
                            && connected
                            && (ConfigManager.MODE_WG.equals(config.getMode())
                                || ConfigManager.MODE_WG_XRAY.equals(config.getMode())
                                || ConfigManager.MODE_AWG.equals(config.getMode()))) {
                        LogStore.add("Wg", "сменилась сеть — перезапуск WG-туннеля");
                        Intent i = new Intent(GrizzlyLandVpnService.this,
                                GrizzlyLandVpnService.class);
                        i.setAction(ACTION_RECONNECT);
                        startService(i);
                    }
                    wgLastNetwork = network;
                }
            };
            cm.registerDefaultNetworkCallback(wgNetCallback);
        } catch (Exception e) {
            LogStore.add("Wg", "NetworkCallback не зарегистрирован: " + e);
        }
    }

    private void unregisterWgNetworkCallback() {
        if (wgNetCallback != null) {
            try {
                android.net.ConnectivityManager cm = (android.net.ConnectivityManager)
                        getSystemService(CONNECTIVITY_SERVICE);
                cm.unregisterNetworkCallback(wgNetCallback);
            } catch (Exception ignored) {
            }
            wgNetCallback = null;
        }
        wgLastNetwork = null;
    }

    /**
     * Нативный openvpn завершился сам (плохой конфиг, отказ auth, недоступен сервер).
     * Нельзя оставлять UI в состоянии «подключено» при мёртвом туннеле.
     */
    private void onOpenVpnExited() {
        LogStore.add("Service", "OpenVPN завершился сам — VPN отключён");
        connected = false;
        broadcastState();
        xrayRunner.stop();
        stopSshTunnel();
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {
            }
            vpnInterface = null;
        }
        // Внезапная смерть процесса (management-exit, убийство системой и т.п.).
        // Если VPN должен быть подключён (wantConnected) и это не фатальная
        // ошибка конфига/кредов — перезапускаем с бэкоффом (как ретраи WG);
        // иначе — стоп как раньше.
        if (config.getWantConnected() && !openVpnRunner.sawFatalFailure()) {
            scheduleOvpnRetry("процесс openvpn завершился");
        } else {
            stopSelf();
        }
    }

    /**
     * Провайдер TUN для нативного openvpn: вызывается на команду OPENTUN.
     * Создаёт TUN-интерфейс VpnService с текущими настройками и отдаёт fd.
     */
    /** Исключает сокет openvpn из VPN-маршрутизации (иначе VPN зациклится). */
    private void protectFd(int fd) {
        boolean ok = protect(fd);
        Log.i(TAG, "protect fd " + fd + " -> " + ok);
        LogStore.add("Service", "protect(fd=" + fd + ") -> " + ok);
    }

    private ParcelFileDescriptor establishTunForOpenVpn(String localIp, int mtu,
                                                        java.util.List<String> pushedDns,
                                                        java.util.List<String> pushedRoutes) {
        if (vpnInterface == null) {
            vpnInterface = buildBuilder(localIp, mtu, pushedDns, pushedRoutes).establish();
            if (vpnInterface != null) {
                connected = true;
                tunRetryAttempts = 0;
                ovpnRetryAttempts = 0;
                broadcastState();
                updateNotification("VPN активен");
                LogStore.add("Service", "TUN создан: ip=" + localIp + " mtu=" + mtu
                        + " (fd=" + tunFdNumber(vpnInterface) + ")"
                        + " pushedDNS=" + (pushedDns == null ? 0 : pushedDns.size())
                        + " pushedRoutes=" + (pushedRoutes == null ? 0 : pushedRoutes.size()));
                startTunFdMonitor();
            } else {
                handleTunFailure("OpenVPN ip=" + localIp);
            }
        }
        return vpnInterface;
    }

    /** Номер дескриптора ParcelFileDescriptor (для диагностики SCM_RIGHTS). */
    private static int tunFdNumber(ParcelFileDescriptor pfd) {
        try {
            java.lang.reflect.Method m = FileDescriptor.class.getDeclaredMethod("getInt$");
            m.setAccessible(true);
            return (Integer) m.invoke(pfd.getFileDescriptor());
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Диагностика: раз в 2с опрашивает TUN-fd на читаемость (POLLIN, 0ms).
     * Если POLLIN есть, а openvpn не читает — fd до openvpn не дошёл/не тот.
     */
    private volatile Thread tunFdMonitor;

    private void startTunFdMonitor() {
        stopTunFdMonitor();
        final ParcelFileDescriptor pfd = vpnInterface;
        if (pfd == null) {
            return;
        }
        tunFdMonitor = new Thread(() -> {
            try {
                FileDescriptor fd = pfd.getFileDescriptor();
                boolean lastReadable = false;
                while (connected && !Thread.currentThread().isInterrupted()) {
                    android.system.StructPollfd[] p = new android.system.StructPollfd[1];
                    p[0] = new android.system.StructPollfd();
                    p[0].fd = fd;
                    p[0].events = (short) android.system.OsConstants.POLLIN;
                    try {
                        android.system.Os.poll(p, 0);
                        boolean readable =
                                (p[0].revents & android.system.OsConstants.POLLIN) != 0;
                        boolean err = (p[0].revents
                                & (android.system.OsConstants.POLLERR
                                | android.system.OsConstants.POLLNVAL)) != 0;
                        // Логируем только СМЕНУ состояния (и ошибки): в простое
                        // POLLIN=false — норма (в TUN нет пакетов), и строчка
                        // каждые 2с просто заливала журнал (проверено 26.10).
                        if (readable != lastReadable || err) {
                            LogStore.add("TunMon", "poll(fd=" + tunFdNumber(pfd)
                                    + ") POLLIN=" + readable
                                    + (err ? " POLLERR/NVAL" : " (смена состояния)"));
                            lastReadable = readable;
                        }
                    } catch (Exception e) {
                        LogStore.add("TunMon", "poll failed: " + e);
                        return;
                    }
                    Thread.sleep(2000);
                }
            } catch (InterruptedException ignored) {
            }
        }, "tunfd-monitor");
        tunFdMonitor.setDaemon(true);
        tunFdMonitor.start();
    }

    private void stopTunFdMonitor() {
        Thread t = tunFdMonitor;
        tunFdMonitor = null;
        if (t != null) {
            t.interrupt();
        }
    }

    /** Строит VpnService.Builder с адресами, DNS и per-app фильтрацией. */
    private Builder buildBuilder(String localIp, int mtu,
                                 java.util.List<String> pushedDns,
                                 java.util.List<String> pushedRoutes) {
        String addr = (localIp != null && !localIp.isEmpty()) ? localIp : "10.0.0.2";

        // В режимах OpenVPN учитываем настройки MTU/DNS из OpenVPN-раздела.
        boolean isOvpnMode = ConfigManager.MODE_OPENVPN.equals(config.getMode())
                || ConfigManager.MODE_XRAY_OVPN.equals(config.getMode())
                || ConfigManager.MODE_OVPN_SSH.equals(config.getMode());
        // MTU: в OpenVPN-режимах ПРИОРИТЕТ у mtu, полученного от openvpn
        // (IFCONFIG/PUSH tun-mtu) — нативный openvpn пишет пакеты размером до
        // СВОЕГО tun_mtu; если VpnService-tun меньше, write() в TUN падает
        // EINVAL ("write to TUN/TAP: Invalid argument"). Пользовательская
        // настройка используется только как fallback.
        int vpnMtu = (mtu > 0) ? mtu : 1400;
        String mtuStr = config.getOvpnMtu();
        if (isOvpnMode && !(mtu > 0) && mtuStr != null && !mtuStr.trim().isEmpty()) {
            try {
                int v = Integer.parseInt(mtuStr.trim());
                if (v > 0) {
                    vpnMtu = v;
                }
            } catch (NumberFormatException ignored) {
            }
        }
        // Приоритет DNS в OpenVPN-режимах: явная настройка пользователя →
        // DNS, запушенный сервером (PUSH_REPLY/dhcp-option DNS) → DNS из Xray-настроек.
        String dnsList = config.getXrayDnsPlain();
        if (isOvpnMode) {
            String oDns = config.getOvpnDns();
            if (oDns != null && !oDns.trim().isEmpty()) {
                dnsList = oDns;
            } else if (pushedDns != null && !pushedDns.isEmpty()) {
                // TextUtils.join вместо String.join: тот доступен только с API 26,
                // а minSdk 24 (Android 7) — на 7/7.1 был бы NoSuchMethodError.
                dnsList = android.text.TextUtils.join(",", pushedDns);
            }
        }
        // DNS-серверы берутся ТОЛЬКО из настроек/импортированного конфига (без
        // жёстко зашитых fallback-адресов), чтобы не подменять DNS пользователя.
        // Для Android VpnService addDnsServer нужны чистые IP, поэтому из поля DNS
        // (которое может содержать tcp://, https:// DoH, ip:853 DoT) берём только IP.

        Builder builder = new Builder()
                .setSession(getString(R.string.app_name))
                .addAddress(addr, 32)
                .addRoute("0.0.0.0", 0)
                .setBlocking(true)
                .setMtu(vpnMtu > 0 ? vpnMtu : 1400);

        // DNS-серверы из настроек (через запятую). addDnsServer принимает только
        // числовые IP: DoH/DoT-форматы и прочий мусор отфильтровываем, иначе
        // establish() упадёт с IllegalArgumentException.
        for (String dns : dnsList.split(",")) {
            String d = dns.trim();
            if (!d.isEmpty() && isIpv4(d)) {
                builder.addDnsServer(d);
            }
        }

        // Маршруты: если сервер пушит конкретные (PUSH_REPLY/ROUTE) — уважаем их
        // (split-VPN как в OpenVPN for Android). Иначе — весь трафик (0.0.0.0/0).
        if (pushedRoutes != null && !pushedRoutes.isEmpty()) {
            for (String r : pushedRoutes) {
                String[] p = r.split("\\s+");
                if (p.length < 2) continue;
                int prefix = prefixFromMask(p[1]);
                if (prefix < 0) continue;
                try {
                    builder.addRoute(p[0], prefix);
                    LogStore.add("Service", "Маршрут сервера: " + p[0] + "/" + prefix);
                } catch (Exception e) {
                    Log.e(TAG, "addRoute failed for " + r, e);
                }
            }
        } else {
            builder.addRoute("0.0.0.0", 0);
        }

        // Per-app: маршрутизируем только выбранные приложения (или весь телефон
        // при включённом переключателе «VPN для всего телефона»).
        return applyAppFilter(builder);
    }

    private void disconnect() {
        connected = false;
        lastError = "";
        startEpoch.incrementAndGet(); // отменить асинхронный старт WG-через-Xray и ретраи WG/TUN, если в полёте
        mainHandler.removeCallbacks(wgRetryRunnable);
        mainHandler.removeCallbacks(tunRetryRunnable);
        mainHandler.removeCallbacks(ovpnRetryRunnable);
        mainHandler.removeCallbacks(netLostGraceRunnable);
        waitingNetwork = false;
        netLostNotified = false;
        wgRetryAttempts = 0;
        tunRetryAttempts = 0;
        ovpnRetryAttempts = 0;
        broadcastState();
        LogStore.add("Service", "==== Отключение ====");
        stopTunFdMonitor();
        xrayRunner.stop();
        openVpnRunner.stop();
        stopSshTunnel();
        stopWgEngine();
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {
            }
            vpnInterface = null;
        }
        stopForeground(true);
        stopSelf();
    }

    /** VPN отозван системой: пользователь выключил в настройках Android либо
     *  запущен другой VPN. Считаем это явным отключением — автоподключение
     *  при загрузке/падении выключаем. (Собственные реконнекты сервиса через
     *  establish() onRevoke не вызывают.) */
    @Override
    public void onRevoke() {
        LogStore.add("Service", "VPN отозван системой (onRevoke) — восстановление при загрузке/падении выключено");
        if (config != null) {
            config.setWantConnected(false);
        }
        disconnect();
    }

    @Override
    public void onDestroy() {
        serviceActive = false;
        disconnect();
        unregisterConnectivityWatch();
        super.onDestroy();
    }

    /** Строгая проверка IPv4 (InetAddress.getByName сделал бы DNS-запрос для доменов). */
    private static boolean isIpv4(String s) {
        String[] o = s.split("\\.");
        if (o.length != 4) return false;
        for (String part : o) {
            if (!part.matches("\\d{1,3}")) return false;
            try {
                if (Integer.parseInt(part) > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    /** Маска вида 255.255.255.0 → префикс 24. Некорректная/несмежная маска → -1. */
    private static int prefixFromMask(String mask) {
        if (mask == null) return -1;
        String[] o = mask.split("\\.");
        if (o.length != 4) return -1;
        int bits = 0;
        boolean seenZero = false;
        try {
            for (String part : o) {
                int v = Integer.parseInt(part);
                if (v < 0 || v > 255) return -1;
                for (int i = 7; i >= 0; i--) {
                    if ((v & (1 << i)) != 0) {
                        if (seenZero) return -1;
                        bits++;
                    } else {
                        seenZero = true;
                    }
                }
            }
        } catch (NumberFormatException e) {
            return -1;
        }
        return bits;
    }

    private void broadcastState() {
        Intent i = new Intent(ACTION_STATE_CHANGED);
        i.setPackage(getPackageName());
        sendBroadcast(i);
    }

    /** Обновить текст существующего уведомления (без пересоздания канала). */
    private void updateNotification(String text) {
        try {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            nm.notify(NOTIF_ID, buildNotification(text));
        } catch (Exception ignored) {
        }
    }

    /** Текст по состоянию: раньше при старте сервиса (в т.ч. при загрузке телефона
     *  без сети) уведомление сразу врало «VPN активен». */
    private Notification buildNotification() {
        if (waitingNetwork) {
            return buildNotification("Жду появления интернета…");
        }
        return buildNotification("Подключение…");
    }

    private Notification buildNotification(String contentText) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "GrizzlyLandVPN", NotificationManager.IMPORTANCE_LOW);
            nm.createNotificationChannel(ch);
        }
        Intent disconnectIntent = new Intent(this, GrizzlyLandVpnService.class);
        disconnectIntent.setAction(ACTION_DISCONNECT);
        PendingIntent pi = PendingIntent.getService(
                this, 0, disconnectIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder b = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        return b.setContentTitle("GrizzlyLandVPN")
                .setContentText(contentText)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setOngoing(true)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Отключить", pi)
                .build();
    }
}
