package com.grizzlyland.vpn;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.Matrix;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.media.Image;
import android.media.ImageReader;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.view.Gravity;
import android.view.Surface;
import android.view.TextureView;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.common.HybridBinarizer;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Сканер QR-кодов для импорта конфига WireGuard (как «Scan from QR code» в
 * оригинальном приложении WireGuard). Camera2-превью + ImageReader (YUV_420_888),
 * декодирование — zxing core (PlanarYUVLuminanceSource по Y-плоскости).
 *
 * Результат возвращается в setResult: extra "text" с декодированным текстом.
 * Ориентация захвата: экран заблокирован в portrait, декод делается в двух
 * ориентациях (как есть + поворот на 90°) — покрывает сенсоры любой ориентации.
 */
public class QrScanActivity extends Activity {

    private static final int REQ_CAM_PERM = 2401;
    /** Минимальный интервал между декодами, мс (декод сам по себе быстрый). */
    private static final long DECODE_INTERVAL_MS = 120;

    private CameraManager cameraManager;
    private String cameraId;
    private CameraDevice cameraDevice;
    private CameraCaptureSession session;
    /** Выбранный размер потока (общий для превью и анализа, ландшафтный). */
    private android.util.Size analysisSize;
    /** Ориентация сенсора (90/270): задаёт направление поворота превью. */
    private int sensorOrientation = 90;
    /** Билдер повторяющегося запроса (для переключения фонарика на лету). */
    private CaptureRequest.Builder previewRequest;
    private ImageReader reader;
    private TextureView textureView;
    private HandlerThread cameraThread;
    private Handler cameraHandler;
    private final ExecutorService decodeExecutor = Executors.newSingleThreadExecutor();
    private MultiFormatReader multiFormatReader;
    private Map<DecodeHintType, Object> decodeHints;

    private volatile boolean busy = false;
    private long lastDecodeAt = 0;
    private long frameCounter = 0;
    private boolean torchOn = false;
    private boolean finished = false;
    /** Защита от двойного openCamera (permission-диалог + SurfaceTexture). */
    private boolean cameraOpening = false;
    /** Запрос разрешения на камеру уже висит (защита от двойного requestPermissions). */
    private boolean permissionPending = false;

    @SuppressLint("MissingPermission")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

        cameraManager = (CameraManager) getSystemService(Context.CAMERA_SERVICE);
        multiFormatReader = new MultiFormatReader();
        decodeHints = new EnumMap<>(DecodeHintType.class);
        decodeHints.put(DecodeHintType.POSSIBLE_FORMATS,
                java.util.Collections.singletonList(BarcodeFormat.QR_CODE));
        decodeHints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);

        FrameLayout root = new FrameLayout(this);
        textureView = new TextureView(this);
        root.addView(textureView, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        TextView hint = new TextView(this);
        hint.setText("Наведите камеру на QR-код с конфигом WireGuard");
        hint.setTextSize(14);
        hint.setPadding(24, 32, 24, 0);
        hint.setGravity(Gravity.CENTER_HORIZONTAL);
        root.addView(hint, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.TOP));

        Button torch = new Button(this);
        torch.setText("Фонарик");
        torch.setOnClickListener(v -> toggleTorch());
        FrameLayout.LayoutParams tlp = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        tlp.bottomMargin = 48;
        root.addView(torch, tlp);

        setContentView(root);

        textureView.setSurfaceTextureListener(new TextureView.SurfaceTextureListener() {
            @Override
            public void onSurfaceTextureAvailable(SurfaceTexture st, int w, int h) {
                fitPreviewToFrame(w, h);
                openCameraIfPermitted();
            }
            @Override
            public void onSurfaceTextureSizeChanged(SurfaceTexture st, int w, int h) {
                fitPreviewToFrame(w, h);
            }
            @Override
            public boolean onSurfaceTextureDestroyed(SurfaceTexture st) {
                return true;
            }
            @Override
            public void onSurfaceTextureUpdated(SurfaceTexture st) {
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (textureView.isAvailable()) {
            openCameraIfPermitted();
        } else if (checkSelfPermission(android.Manifest.permission.CAMERA)
                != PackageManager.PERMISSION_GRANTED) {
            requestCameraPermission();
        }
    }

    @Override
    protected void onPause() {
        closeCamera();
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        decodeExecutor.shutdownNow();
        super.onDestroy();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != REQ_CAM_PERM) {
            return;
        }
        permissionPending = false;
        // Пустой результат — запрос был отменён/заменён (например, параллельный
        // запрос из onResume и onSurfaceTextureAvailable). Это НЕ отказ юзера.
        if (grantResults.length == 0) {
            return;
        }
        if (grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            openCameraIfPermitted();
        } else {
            Toast.makeText(this, "Без разрешения на камеру сканирование невозможно",
                    Toast.LENGTH_LONG).show();
            finish();
        }
    }

    /** Однократный запрос разрешения (повторный вызов, пока запрос висит, — no-op). */
    private void requestCameraPermission() {
        if (permissionPending) {
            return;
        }
        permissionPending = true;
        requestPermissions(new String[]{android.Manifest.permission.CAMERA}, REQ_CAM_PERM);
    }

    private void openCameraIfPermitted() {
        if (checkSelfPermission(android.Manifest.permission.CAMERA)
                != PackageManager.PERMISSION_GRANTED) {
            requestCameraPermission();
            return;
        }
        if (cameraDevice != null || cameraOpening || cameraManager == null) {
            return;
        }
        if (!textureView.isAvailable()) {
            return; // откроем из onSurfaceTextureAvailable
        }
        try {
            if (cameraId == null) {
                cameraId = pickBackCamera();
            }
            if (cameraId == null) {
                Toast.makeText(this, "Камера не найдена", Toast.LENGTH_LONG).show();
                finish();
                return;
            }
            CameraCharacteristics cc = cameraManager.getCameraCharacteristics(cameraId);
            android.hardware.camera2.params.StreamConfigurationMap map =
                    cc.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            if (map == null) {
                throw new IllegalStateException("StreamConfigurationMap недоступен");
            }
            android.util.Size analysisSize = pickAnalysisSize(
                    map.getOutputSizes(ImageFormat_YUV()));
            this.analysisSize = analysisSize;
            Integer so = cc.get(CameraCharacteristics.SENSOR_ORIENTATION);
            if (so != null) {
                sensorOrientation = so;
            }
            LogStore.add("QR", "камера " + cameraId + ", кадр анализа "
                    + analysisSize.getWidth() + "x" + analysisSize.getHeight()
                    + ", сенсор " + sensorOrientation + "°");
            // Размер превью из SurfaceTexture берём тот же (упрощает сессию).
            cameraThread = new HandlerThread("qr-cam");
            cameraThread.start();
            cameraHandler = new Handler(cameraThread.getLooper());

            reader = ImageReader.newInstance(analysisSize.getWidth(), analysisSize.getHeight(),
                    ImageFormat_YUV(), 2);
            reader.setOnImageAvailableListener(this::onImageAvailable, cameraHandler);

            cameraOpening = true;
            cameraManager.openCamera(cameraId, new CameraDevice.StateCallback() {
                @Override
                public void onOpened(CameraDevice cam) {
                    cameraOpening = false;
                    cameraDevice = cam;
                    createSession();
                }
                @Override
                public void onDisconnected(CameraDevice cam) {
                    cameraOpening = false;
                    cam.close();
                    if (cameraDevice == cam) {
                        cameraDevice = null;
                    }
                }
                @Override
                public void onError(CameraDevice cam, int error) {
                    cameraOpening = false;
                    cam.close();
                    if (cameraDevice == cam) {
                        cameraDevice = null;
                    }
                    if (!finished) {
                        Toast.makeText(QrScanActivity.this,
                                "Ошибка камеры: " + error, Toast.LENGTH_LONG).show();
                        finish();
                    }
                }
            }, cameraHandler);
        } catch (Exception e) {
            Toast.makeText(this, "Не удалось открыть камеру: " + e.getMessage(),
                    Toast.LENGTH_LONG).show();
            finish();
        }
    }

    /** ImageFormat.YUV_420_888 отдельным методом (константа доступна с API 23). */
    private static int ImageFormat_YUV() {
        return android.graphics.ImageFormat.YUV_420_888;
    }

    private String pickBackCamera() throws Exception {
        String fallback = null;
        for (String id : cameraManager.getCameraIdList()) {
            CameraCharacteristics cc = cameraManager.getCameraCharacteristics(id);
            Integer facing = cc.get(CameraCharacteristics.LENS_FACING);
            if (facing != null && facing == CameraCharacteristics.LENS_FACING_BACK) {
                return id;
            }
            if (fallback == null) {
                fallback = id;
            }
        }
        return fallback;
    }

    /** Размер кадра анализа: ближе всего к 1280x960 (быстро и достаточно для QR). */
    private static android.util.Size pickAnalysisSize(android.util.Size[] sizes) {
        android.util.Size best = sizes[0];
        int bestDiff = Integer.MAX_VALUE;
        for (android.util.Size s : sizes) {
            int diff = Math.abs(s.getWidth() * s.getHeight() - 1280 * 960);
            if (diff < bestDiff) {
                bestDiff = diff;
                best = s;
            }
        }
        return best;
    }

    /**
     * Вписывает поток камеры в экран без растяжения: cover-масштаб + поворот
     * сенсора (буфер кадра ландшафтный, окно портретное). Размеры берутся из
     * реального analysisSize (общего для превью и анализа), а не хардкод 3:4.
     */
    private void fitPreviewToFrame(int frameW, int frameH) {
        if (frameW == 0 || frameH == 0 || analysisSize == null) {
            return; // до открытия камеры вьюха остаётся на весь экран
        }
        int pw = analysisSize.getWidth();   // ландшафтный буфер, напр. 1280x720
        int ph = analysisSize.getHeight();
        // Повёрнутый на 90° кадр занимает ph x pw (портрет); cover — без полей.
        float scale = Math.max(frameW / (float) ph, frameH / (float) pw);
        int w = Math.round(ph * scale);
        int h = Math.round(pw * scale);
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(w, h, Gravity.CENTER);
        textureView.setLayoutParams(lp);
        // Контент: буфер pw x ph масштабируем в h x w (аспект сохранён), затем
        // поворот на 90° вокруг центра — портретная ориентация превью.
        Matrix m = new Matrix();
        m.postScale(h / (float) pw, w / (float) ph);
        m.postRotate(sensorOrientation == 270 ? -90f : 90f, w / 2f, h / 2f);
        textureView.setTransform(m);
    }

    @SuppressLint("MissingPermission")
    private void createSession() {
        try {
            SurfaceTexture st = textureView.getSurfaceTexture();
            if (st == null || cameraDevice == null) {
                return;
            }
            // Без этого буфер SurfaceTexture остаётся размером вьюхи, и камера
            // растягивает сенсорный кадр в него — превью «вытянутое».
            if (analysisSize != null) {
                st.setDefaultBufferSize(analysisSize.getWidth(), analysisSize.getHeight());
            }
            // Геометрия превью считается по фактическому размеру потока.
            runOnUiThread(() -> fitPreviewToFrame(
                    textureView.getWidth(), textureView.getHeight()));
            Surface preview = new Surface(st);
            List<Surface> targets = new ArrayList<>();
            targets.add(preview);
            targets.add(reader.getSurface());
            cameraDevice.createCaptureSession(targets, new CameraCaptureSession.StateCallback() {
                @Override
                public void onConfigured(CameraCaptureSession s) {
                    if (cameraDevice == null) {
                        return;
                    }
                    session = s;
                    LogStore.add("QR", "сессия камеры готова");
                    try {
                        CaptureRequest.Builder req = cameraDevice
                                .createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
                        req.addTarget(preview);
                        req.addTarget(reader.getSurface());
                        req.set(CaptureRequest.CONTROL_AF_MODE,
                                CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);
                        previewRequest = req;
                        s.setRepeatingRequest(req.build(), null, cameraHandler);
                    } catch (Exception e) {
                        if (!finished) {
                            Toast.makeText(QrScanActivity.this,
                                    "Ошибка превью: " + e.getMessage(), Toast.LENGTH_LONG).show();
                            finish();
                        }
                    }
                }
                @Override
                public void onConfigureFailed(CameraCaptureSession s) {
                    LogStore.add("QR", "ОШИБКА: сессия камеры не настроилась");
                    if (!finished) {
                        Toast.makeText(QrScanActivity.this, "Камера не настроилась",
                                Toast.LENGTH_LONG).show();
                        finish();
                    }
                }
            }, cameraHandler);
        } catch (Exception e) {
            if (!finished) {
                Toast.makeText(this, "Ошибка сессии камеры: " + e.getMessage(),
                        Toast.LENGTH_LONG).show();
                finish();
            }
        }
    }

    private void toggleTorch() {
        try {
            torchOn = !torchOn;
            if (session != null && previewRequest != null) {
                // Пока камера открыта нами, setTorchMode на этом устройстве даёт
                // CAMERA_IN_USE — фонарик включаем через FLASH_MODE в запросе.
                previewRequest.set(CaptureRequest.FLASH_MODE, torchOn
                        ? CaptureRequest.FLASH_MODE_TORCH
                        : CaptureRequest.FLASH_MODE_OFF);
                session.setRepeatingRequest(previewRequest.build(), null, cameraHandler);
            } else if (cameraId != null) {
                cameraManager.setTorchMode(cameraId, torchOn);
            }
            LogStore.add("QR", "фонарик: " + (torchOn ? "вкл" : "выкл"));
        } catch (Exception e) {
            torchOn = false;
            LogStore.add("QR", "фонарик недоступен: " + e.getMessage());
            Toast.makeText(this, "Фонарик недоступен: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    private void onImageAvailable(ImageReader r) {
        if (busy || finished) {
            Image skip = r.acquireLatestImage();
            if (skip != null) {
                skip.close();
            }
            return;
        }
        long now = SystemClock.elapsedRealtime();
        if (now - lastDecodeAt < DECODE_INTERVAL_MS) {
            Image skip = r.acquireLatestImage();
            if (skip != null) {
                skip.close();
            }
            return;
        }
        final Image image = r.acquireLatestImage();
        if (image == null) {
            return;
        }
        lastDecodeAt = now;
        busy = true;
        final long frameNo = ++frameCounter;
        decodeExecutor.execute(() -> {
            String result = null;
            try {
                if (frameNo % 50 == 1) {
                    LogStore.add("QR", "кадр #" + frameNo + " "
                            + image.getWidth() + "x" + image.getHeight());
                }
                result = decode(image);
            } catch (Throwable t) {
                LogStore.add("QR", "ошибка декода: " + t);
            } finally {
                image.close();
                busy = false;
            }
            if (result != null && !finished) {
                LogStore.add("QR", "QR распознан (" + result.length() + " симв.)");
                final String decoded = result;
                runOnUiThread(() -> onDecoded(decoded));
            }
        });
    }

    /** Декод одного кадра: Y-плоскость → zxing; пробуем как есть и повёрнутым. */
    private String decode(Image image) {
        Image.Plane plane = image.getPlanes()[0];
        ByteBuffer buf = plane.getBuffer();
        int width = image.getWidth();
        int height = image.getHeight();
        int rowStride = plane.getRowStride();
        int pixelStride = plane.getPixelStride();

        byte[] data;
        int dataWidth;
        if (pixelStride == 1) {
            dataWidth = rowStride;
            data = new byte[rowStride * height];
            int n = Math.min(buf.remaining(), data.length);
            buf.get(data, 0, n);
        } else {
            dataWidth = width;
            data = new byte[width * height];
            for (int row = 0; row < height; row++) {
                int base = row * rowStride;
                for (int col = 0; col < width; col++) {
                    data[row * width + col] = buf.get(base + col * pixelStride);
                }
            }
        }
        PlanarYUVLuminanceSource source = new PlanarYUVLuminanceSource(
                data, dataWidth, height, 0, 0, width, height, false);
        try {
            try {
                return multiFormatReader.decode(new BinaryBitmap(new HybridBinarizer(source)),
                        decodeHints).getText();
            } catch (NotFoundException e) {
                // PlanarYUVLuminanceSource не поддерживает rotate*() — поворачиваем
                // Y-буфер вручную. Пробуем обе стороны: ориентация сенсора бывает
                // 90 и 270 (portrait-фикс не гарантирует сторону).
                try {
                    return multiFormatReader.decode(rotatedBitmap(data, dataWidth,
                            width, height, true), decodeHints).getText();
                } catch (NotFoundException e2) {
                    return multiFormatReader.decode(rotatedBitmap(data, dataWidth,
                            width, height, false), decodeHints).getText();
                }
            }
        } catch (NotFoundException e) {
            return null;
        } finally {
            multiFormatReader.reset();
        }
    }

    /** Поворот Y-буфера на 90° (ccw=true — против часовой) → BinaryBitmap. */
    private static BinaryBitmap rotatedBitmap(byte[] data, int dataWidth,
                                              int w, int h, boolean ccw) {
        byte[] out = new byte[w * h];
        if (ccw) {
            // (x,y) → (y, w-1-x): строка out длиной h
            for (int y = 0; y < h; y++) {
                int base = y * dataWidth;
                for (int x = 0; x < w; x++) {
                    out[(w - 1 - x) * h + y] = data[base + x];
                }
            }
        } else {
            // (x,y) → (h-1-y, x)
            for (int y = 0; y < h; y++) {
                int base = y * dataWidth;
                for (int x = 0; x < w; x++) {
                    out[x * h + (h - 1 - y)] = data[base + x];
                }
            }
        }
        PlanarYUVLuminanceSource src = new PlanarYUVLuminanceSource(
                out, h, w, 0, 0, h, w, false);
        return new BinaryBitmap(new HybridBinarizer(src));
    }

    private void onDecoded(String text) {
        if (finished) {
            return;
        }
        finished = true;
        try {
            Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            if (v != null && v.hasVibrator()) {
                v.vibrate(VibrationEffect.createOneShot(80,
                        VibrationEffect.DEFAULT_AMPLITUDE));
            }
        } catch (Exception ignored) {
        }
        // Убираем возможное mojibake: если сканер вернул не-ASCII (QR без ECI),
        // пробуем трактовать байты как UTF-8 (стандартный случай wg-конфигов —
        // чистый ASCII, где это не срабатывает).
        String out = text;
        if (out != null && hasNonAscii(out)) {
            try {
                String fixed = new String(out.getBytes("ISO-8859-1"), "UTF-8");
                if (!hasNonAscii(fixed) || countHigh(fixed) < countHigh(out)) {
                    out = fixed;
                }
            } catch (Exception ignored) {
            }
        }
        setResult(RESULT_OK, new android.content.Intent().putExtra("text", out == null ? "" : out));
        finish();
    }

    private static boolean hasNonAscii(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) > 127) {
                return true;
            }
        }
        return false;
    }

    private static int countHigh(String s) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) > 127) {
                n++;
            }
        }
        return n;
    }

    private void closeCamera() {
        previewRequest = null;
        try {
            if (session != null) {
                session.close();
                session = null;
            }
        } catch (Exception ignored) {
        }
        try {
            if (cameraDevice != null) {
                cameraDevice.close();
                cameraDevice = null;
            }
        } catch (Exception ignored) {
        }
        try {
            if (reader != null) {
                reader.close();
                reader = null;
            }
        } catch (Exception ignored) {
        }
        if (cameraThread != null) {
            cameraThread.quitSafely();
            cameraThread = null;
            cameraHandler = null;
        }
    }
}
