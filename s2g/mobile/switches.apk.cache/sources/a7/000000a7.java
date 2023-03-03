package com.badlogic.gdx.backends.android;

import android.app.WallpaperColors;
import android.os.Build;
import android.os.Bundle;
import android.service.wallpaper.WallpaperService;
import android.util.Log;
import android.view.MotionEvent;
import android.view.SurfaceHolder;
import android.view.WindowManager;
import com.badlogic.gdx.Application;
import com.badlogic.gdx.ApplicationListener;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.utils.GdxNativesLoader;

/* loaded from: classes.dex */
public abstract class AndroidLiveWallpaperService extends WallpaperService {
    static boolean DEBUG = false;
    static final String TAG = "WallpaperService";
    protected int viewFormat;
    protected int viewHeight;
    protected int viewWidth;
    protected volatile AndroidLiveWallpaper app = null;
    protected SurfaceHolder.Callback view = null;
    protected int engines = 0;
    protected int visibleEngines = 0;
    protected volatile AndroidWallpaperEngine linkedEngine = null;
    protected volatile boolean isPreviewNotified = false;
    protected volatile boolean notifiedPreviewState = false;
    volatile int[] sync = new int[0];

    static {
        GdxNativesLoader.load();
        DEBUG = false;
    }

    protected void setLinkedEngine(AndroidWallpaperEngine linkedEngine) {
        synchronized (this.sync) {
            this.linkedEngine = linkedEngine;
        }
    }

    @Override // android.service.wallpaper.WallpaperService, android.app.Service
    public void onCreate() {
        if (DEBUG) {
            Log.d(TAG, " > AndroidLiveWallpaperService - onCreate() " + hashCode());
        }
        Log.i(TAG, "service created");
        super.onCreate();
    }

    @Override // android.service.wallpaper.WallpaperService
    public WallpaperService.Engine onCreateEngine() {
        if (DEBUG) {
            Log.d(TAG, " > AndroidLiveWallpaperService - onCreateEngine()");
        }
        Log.i(TAG, "engine created");
        return new AndroidWallpaperEngine();
    }

    public void onCreateApplication() {
        if (DEBUG) {
            Log.d(TAG, " > AndroidLiveWallpaperService - onCreateApplication()");
        }
    }

    public void initialize(ApplicationListener listener) {
        AndroidApplicationConfiguration config = new AndroidApplicationConfiguration();
        initialize(listener, config);
    }

    public void initialize(ApplicationListener listener, AndroidApplicationConfiguration config) {
        if (DEBUG) {
            Log.d(TAG, " > AndroidLiveWallpaperService - initialize()");
        }
        this.app.initialize(listener, config);
        if (config.getTouchEventsForLiveWallpaper && Integer.parseInt(Build.VERSION.SDK) >= 7) {
            this.linkedEngine.setTouchEventsEnabled(true);
        }
    }

    public SurfaceHolder getSurfaceHolder() {
        if (DEBUG) {
            Log.d(TAG, " > AndroidLiveWallpaperService - getSurfaceHolder()");
        }
        synchronized (this.sync) {
            if (this.linkedEngine == null) {
                return null;
            }
            return this.linkedEngine.getSurfaceHolder();
        }
    }

    public void onDeepPauseApplication() {
        if (DEBUG) {
            Log.d(TAG, " > AndroidLiveWallpaperService - onDeepPauseApplication()");
        }
        if (this.app != null) {
            this.app.graphics.clearManagedCaches();
        }
    }

    @Override // android.service.wallpaper.WallpaperService, android.app.Service
    public void onDestroy() {
        if (DEBUG) {
            Log.d(TAG, " > AndroidLiveWallpaperService - onDestroy() " + hashCode());
        }
        Log.i(TAG, "service destroyed");
        super.onDestroy();
        if (this.app != null) {
            this.app.onDestroy();
            this.app = null;
            this.view = null;
        }
    }

    protected void finalize() throws Throwable {
        Log.i(TAG, "service finalized");
        super.finalize();
    }

    public AndroidLiveWallpaper getLiveWallpaper() {
        return this.app;
    }

    public WindowManager getWindowManager() {
        return (WindowManager) getSystemService("window");
    }

    /* loaded from: classes.dex */
    public class AndroidWallpaperEngine extends WallpaperService.Engine {
        protected int engineFormat;
        protected int engineHeight;
        protected boolean engineIsVisible;
        protected int engineWidth;
        boolean iconDropConsumed;
        boolean offsetsConsumed;
        int xIconDrop;
        float xOffset;
        float xOffsetStep;
        int xPixelOffset;
        int yIconDrop;
        float yOffset;
        float yOffsetStep;
        int yPixelOffset;

        public AndroidWallpaperEngine() {
            super(AndroidLiveWallpaperService.this);
            this.engineIsVisible = false;
            this.iconDropConsumed = true;
            this.offsetsConsumed = true;
            this.xOffset = 0.0f;
            this.yOffset = 0.0f;
            this.xOffsetStep = 0.0f;
            this.yOffsetStep = 0.0f;
            this.xPixelOffset = 0;
            this.yPixelOffset = 0;
            if (AndroidLiveWallpaperService.DEBUG) {
                Log.d(AndroidLiveWallpaperService.TAG, " > AndroidWallpaperEngine() " + hashCode());
            }
        }

        @Override // android.service.wallpaper.WallpaperService.Engine
        public void onCreate(SurfaceHolder surfaceHolder) {
            if (AndroidLiveWallpaperService.DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append(" > AndroidWallpaperEngine - onCreate() ");
                sb.append(hashCode());
                sb.append(" running: ");
                sb.append(AndroidLiveWallpaperService.this.engines);
                sb.append(", linked: ");
                sb.append(AndroidLiveWallpaperService.this.linkedEngine == this);
                sb.append(", thread: ");
                sb.append(Thread.currentThread().toString());
                Log.d(AndroidLiveWallpaperService.TAG, sb.toString());
            }
            super.onCreate(surfaceHolder);
        }

        @Override // android.service.wallpaper.WallpaperService.Engine
        public void onSurfaceCreated(SurfaceHolder holder) {
            AndroidLiveWallpaperService.this.engines++;
            AndroidLiveWallpaperService.this.setLinkedEngine(this);
            if (AndroidLiveWallpaperService.DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append(" > AndroidWallpaperEngine - onSurfaceCreated() ");
                sb.append(hashCode());
                sb.append(", running: ");
                sb.append(AndroidLiveWallpaperService.this.engines);
                sb.append(", linked: ");
                sb.append(AndroidLiveWallpaperService.this.linkedEngine == this);
                Log.d(AndroidLiveWallpaperService.TAG, sb.toString());
            }
            Log.i(AndroidLiveWallpaperService.TAG, "engine surface created");
            super.onSurfaceCreated(holder);
            if (AndroidLiveWallpaperService.this.engines == 1) {
                AndroidLiveWallpaperService.this.visibleEngines = 0;
            }
            if (AndroidLiveWallpaperService.this.engines == 1 && AndroidLiveWallpaperService.this.app == null) {
                AndroidLiveWallpaperService androidLiveWallpaperService = AndroidLiveWallpaperService.this;
                androidLiveWallpaperService.viewFormat = 0;
                androidLiveWallpaperService.viewWidth = 0;
                androidLiveWallpaperService.viewHeight = 0;
                androidLiveWallpaperService.app = new AndroidLiveWallpaper(androidLiveWallpaperService);
                AndroidLiveWallpaperService.this.onCreateApplication();
                if (AndroidLiveWallpaperService.this.app.graphics == null) {
                    throw new Error("You must override 'AndroidLiveWallpaperService.onCreateApplication' method and call 'initialize' from its body.");
                }
            }
            AndroidLiveWallpaperService androidLiveWallpaperService2 = AndroidLiveWallpaperService.this;
            androidLiveWallpaperService2.view = androidLiveWallpaperService2.app.graphics.view;
            getSurfaceHolder().removeCallback(AndroidLiveWallpaperService.this.view);
            this.engineFormat = AndroidLiveWallpaperService.this.viewFormat;
            this.engineWidth = AndroidLiveWallpaperService.this.viewWidth;
            this.engineHeight = AndroidLiveWallpaperService.this.viewHeight;
            if (AndroidLiveWallpaperService.this.engines == 1) {
                AndroidLiveWallpaperService.this.view.surfaceCreated(holder);
            } else {
                AndroidLiveWallpaperService.this.view.surfaceDestroyed(holder);
                notifySurfaceChanged(this.engineFormat, this.engineWidth, this.engineHeight, false);
                AndroidLiveWallpaperService.this.view.surfaceCreated(holder);
            }
            notifyPreviewState();
            notifyOffsetsChanged();
            if (!Gdx.graphics.isContinuousRendering()) {
                Gdx.graphics.requestRendering();
            }
        }

        @Override // android.service.wallpaper.WallpaperService.Engine
        public void onSurfaceChanged(SurfaceHolder holder, int format, int width, int height) {
            if (AndroidLiveWallpaperService.DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append(" > AndroidWallpaperEngine - onSurfaceChanged() isPreview: ");
                sb.append(isPreview());
                sb.append(", ");
                sb.append(hashCode());
                sb.append(", running: ");
                sb.append(AndroidLiveWallpaperService.this.engines);
                sb.append(", linked: ");
                sb.append(AndroidLiveWallpaperService.this.linkedEngine == this);
                sb.append(", sufcace valid: ");
                sb.append(getSurfaceHolder().getSurface().isValid());
                Log.d(AndroidLiveWallpaperService.TAG, sb.toString());
            }
            Log.i(AndroidLiveWallpaperService.TAG, "engine surface changed");
            super.onSurfaceChanged(holder, format, width, height);
            notifySurfaceChanged(format, width, height, true);
        }

        private void notifySurfaceChanged(int format, int width, int height, boolean forceUpdate) {
            if (!forceUpdate && format == AndroidLiveWallpaperService.this.viewFormat && width == AndroidLiveWallpaperService.this.viewWidth && height == AndroidLiveWallpaperService.this.viewHeight) {
                if (AndroidLiveWallpaperService.DEBUG) {
                    Log.d(AndroidLiveWallpaperService.TAG, " > surface is current, skipping surfaceChanged event");
                    return;
                }
                return;
            }
            this.engineFormat = format;
            this.engineWidth = width;
            this.engineHeight = height;
            if (AndroidLiveWallpaperService.this.linkedEngine == this) {
                AndroidLiveWallpaperService androidLiveWallpaperService = AndroidLiveWallpaperService.this;
                androidLiveWallpaperService.viewFormat = this.engineFormat;
                androidLiveWallpaperService.viewWidth = this.engineWidth;
                androidLiveWallpaperService.viewHeight = this.engineHeight;
                androidLiveWallpaperService.view.surfaceChanged(getSurfaceHolder(), AndroidLiveWallpaperService.this.viewFormat, AndroidLiveWallpaperService.this.viewWidth, AndroidLiveWallpaperService.this.viewHeight);
            } else if (AndroidLiveWallpaperService.DEBUG) {
                Log.d(AndroidLiveWallpaperService.TAG, " > engine is not active, skipping surfaceChanged event");
            }
        }

        @Override // android.service.wallpaper.WallpaperService.Engine
        public void onVisibilityChanged(boolean visible) {
            boolean reportedVisible = isVisible();
            if (AndroidLiveWallpaperService.DEBUG) {
                Log.d(AndroidLiveWallpaperService.TAG, " > AndroidWallpaperEngine - onVisibilityChanged(paramVisible: " + visible + " reportedVisible: " + reportedVisible + ") " + hashCode() + ", sufcace valid: " + getSurfaceHolder().getSurface().isValid());
            }
            super.onVisibilityChanged(visible);
            if (!reportedVisible && visible) {
                if (AndroidLiveWallpaperService.DEBUG) {
                    Log.d(AndroidLiveWallpaperService.TAG, " > fake visibilityChanged event! Android WallpaperService likes do that!");
                    return;
                }
                return;
            }
            notifyVisibilityChanged(visible);
        }

        private void notifyVisibilityChanged(boolean visible) {
            if (this.engineIsVisible != visible) {
                this.engineIsVisible = visible;
                if (this.engineIsVisible) {
                    onResume();
                } else {
                    onPause();
                }
            } else if (AndroidLiveWallpaperService.DEBUG) {
                Log.d(AndroidLiveWallpaperService.TAG, " > visible state is current, skipping visibilityChanged event!");
            }
        }

        public void onResume() {
            AndroidLiveWallpaperService.this.visibleEngines++;
            if (AndroidLiveWallpaperService.DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append(" > AndroidWallpaperEngine - onResume() ");
                sb.append(hashCode());
                sb.append(", running: ");
                sb.append(AndroidLiveWallpaperService.this.engines);
                sb.append(", linked: ");
                sb.append(AndroidLiveWallpaperService.this.linkedEngine == this);
                sb.append(", visible: ");
                sb.append(AndroidLiveWallpaperService.this.visibleEngines);
                Log.d(AndroidLiveWallpaperService.TAG, sb.toString());
            }
            Log.i(AndroidLiveWallpaperService.TAG, "engine resumed");
            if (AndroidLiveWallpaperService.this.linkedEngine != null) {
                if (AndroidLiveWallpaperService.this.linkedEngine != this) {
                    AndroidLiveWallpaperService.this.setLinkedEngine(this);
                    AndroidLiveWallpaperService.this.view.surfaceDestroyed(getSurfaceHolder());
                    notifySurfaceChanged(this.engineFormat, this.engineWidth, this.engineHeight, false);
                    AndroidLiveWallpaperService.this.view.surfaceCreated(getSurfaceHolder());
                } else {
                    notifySurfaceChanged(this.engineFormat, this.engineWidth, this.engineHeight, false);
                }
                if (AndroidLiveWallpaperService.this.visibleEngines == 1) {
                    AndroidLiveWallpaperService.this.app.onResume();
                }
                notifyPreviewState();
                notifyOffsetsChanged();
                if (!Gdx.graphics.isContinuousRendering()) {
                    Gdx.graphics.requestRendering();
                }
            }
        }

        public void onPause() {
            AndroidLiveWallpaperService.this.visibleEngines--;
            if (AndroidLiveWallpaperService.DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append(" > AndroidWallpaperEngine - onPause() ");
                sb.append(hashCode());
                sb.append(", running: ");
                sb.append(AndroidLiveWallpaperService.this.engines);
                sb.append(", linked: ");
                sb.append(AndroidLiveWallpaperService.this.linkedEngine == this);
                sb.append(", visible: ");
                sb.append(AndroidLiveWallpaperService.this.visibleEngines);
                Log.d(AndroidLiveWallpaperService.TAG, sb.toString());
            }
            Log.i(AndroidLiveWallpaperService.TAG, "engine paused");
            if (AndroidLiveWallpaperService.this.visibleEngines >= AndroidLiveWallpaperService.this.engines) {
                Log.e(AndroidLiveWallpaperService.TAG, "wallpaper lifecycle error, counted too many visible engines! repairing..");
                AndroidLiveWallpaperService androidLiveWallpaperService = AndroidLiveWallpaperService.this;
                androidLiveWallpaperService.visibleEngines = Math.max(androidLiveWallpaperService.engines - 1, 0);
            }
            if (AndroidLiveWallpaperService.this.linkedEngine != null && AndroidLiveWallpaperService.this.visibleEngines == 0) {
                AndroidLiveWallpaperService.this.app.onPause();
            }
            if (AndroidLiveWallpaperService.DEBUG) {
                Log.d(AndroidLiveWallpaperService.TAG, " > AndroidWallpaperEngine - onPause() done!");
            }
        }

        @Override // android.service.wallpaper.WallpaperService.Engine
        public void onSurfaceDestroyed(SurfaceHolder holder) {
            AndroidLiveWallpaperService.this.engines--;
            if (AndroidLiveWallpaperService.DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append(" > AndroidWallpaperEngine - onSurfaceDestroyed() ");
                sb.append(hashCode());
                sb.append(", running: ");
                sb.append(AndroidLiveWallpaperService.this.engines);
                sb.append(" ,linked: ");
                sb.append(AndroidLiveWallpaperService.this.linkedEngine == this);
                sb.append(", isVisible: ");
                sb.append(this.engineIsVisible);
                Log.d(AndroidLiveWallpaperService.TAG, sb.toString());
            }
            Log.i(AndroidLiveWallpaperService.TAG, "engine surface destroyed");
            if (AndroidLiveWallpaperService.this.engines == 0) {
                AndroidLiveWallpaperService.this.onDeepPauseApplication();
            }
            if (AndroidLiveWallpaperService.this.linkedEngine == this && AndroidLiveWallpaperService.this.view != null) {
                AndroidLiveWallpaperService.this.view.surfaceDestroyed(holder);
            }
            this.engineFormat = 0;
            this.engineWidth = 0;
            this.engineHeight = 0;
            if (AndroidLiveWallpaperService.this.engines == 0) {
                AndroidLiveWallpaperService.this.linkedEngine = null;
            }
            super.onSurfaceDestroyed(holder);
        }

        @Override // android.service.wallpaper.WallpaperService.Engine
        public void onDestroy() {
            super.onDestroy();
        }

        @Override // android.service.wallpaper.WallpaperService.Engine
        public Bundle onCommand(String pAction, int pX, int pY, int pZ, Bundle pExtras, boolean pResultRequested) {
            if (AndroidLiveWallpaperService.DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append(" > AndroidWallpaperEngine - onCommand(");
                sb.append(pAction);
                sb.append(" ");
                sb.append(pX);
                sb.append(" ");
                sb.append(pY);
                sb.append(" ");
                sb.append(pZ);
                sb.append(" ");
                sb.append(pExtras);
                sb.append(" ");
                sb.append(pResultRequested);
                sb.append("), linked: ");
                sb.append(AndroidLiveWallpaperService.this.linkedEngine == this);
                Log.d(AndroidLiveWallpaperService.TAG, sb.toString());
            }
            if (pAction.equals("android.home.drop")) {
                this.iconDropConsumed = false;
                this.xIconDrop = pX;
                this.yIconDrop = pY;
                notifyIconDropped();
            }
            return super.onCommand(pAction, pX, pY, pZ, pExtras, pResultRequested);
        }

        protected void notifyIconDropped() {
            if (AndroidLiveWallpaperService.this.linkedEngine == this && (AndroidLiveWallpaperService.this.app.listener instanceof AndroidWallpaperListener) && !this.iconDropConsumed) {
                this.iconDropConsumed = true;
                AndroidLiveWallpaperService.this.app.postRunnable(new Runnable() { // from class: com.badlogic.gdx.backends.android.AndroidLiveWallpaperService.AndroidWallpaperEngine.1
                    @Override // java.lang.Runnable
                    public void run() {
                        boolean isCurrent;
                        synchronized (AndroidLiveWallpaperService.this.sync) {
                            isCurrent = AndroidLiveWallpaperService.this.linkedEngine == AndroidWallpaperEngine.this;
                        }
                        if (isCurrent) {
                            ((AndroidWallpaperListener) AndroidLiveWallpaperService.this.app.listener).iconDropped(AndroidWallpaperEngine.this.xIconDrop, AndroidWallpaperEngine.this.yIconDrop);
                        }
                    }
                });
            }
        }

        @Override // android.service.wallpaper.WallpaperService.Engine
        public void onTouchEvent(MotionEvent event) {
            if (AndroidLiveWallpaperService.this.linkedEngine == this) {
                AndroidLiveWallpaperService.this.app.input.onTouch(null, event);
            }
        }

        @Override // android.service.wallpaper.WallpaperService.Engine
        public void onOffsetsChanged(float xOffset, float yOffset, float xOffsetStep, float yOffsetStep, int xPixelOffset, int yPixelOffset) {
            this.offsetsConsumed = false;
            this.xOffset = xOffset;
            this.yOffset = yOffset;
            this.xOffsetStep = xOffsetStep;
            this.yOffsetStep = yOffsetStep;
            this.xPixelOffset = xPixelOffset;
            this.yPixelOffset = yPixelOffset;
            notifyOffsetsChanged();
            if (!Gdx.graphics.isContinuousRendering()) {
                Gdx.graphics.requestRendering();
            }
            super.onOffsetsChanged(xOffset, yOffset, xOffsetStep, yOffsetStep, xPixelOffset, yPixelOffset);
        }

        protected void notifyOffsetsChanged() {
            if (AndroidLiveWallpaperService.this.linkedEngine == this && (AndroidLiveWallpaperService.this.app.listener instanceof AndroidWallpaperListener) && !this.offsetsConsumed) {
                this.offsetsConsumed = true;
                AndroidLiveWallpaperService.this.app.postRunnable(new Runnable() { // from class: com.badlogic.gdx.backends.android.AndroidLiveWallpaperService.AndroidWallpaperEngine.2
                    @Override // java.lang.Runnable
                    public void run() {
                        boolean isCurrent;
                        synchronized (AndroidLiveWallpaperService.this.sync) {
                            isCurrent = AndroidLiveWallpaperService.this.linkedEngine == AndroidWallpaperEngine.this;
                        }
                        if (isCurrent) {
                            ((AndroidWallpaperListener) AndroidLiveWallpaperService.this.app.listener).offsetChange(AndroidWallpaperEngine.this.xOffset, AndroidWallpaperEngine.this.yOffset, AndroidWallpaperEngine.this.xOffsetStep, AndroidWallpaperEngine.this.yOffsetStep, AndroidWallpaperEngine.this.xPixelOffset, AndroidWallpaperEngine.this.yPixelOffset);
                        }
                    }
                });
            }
        }

        protected void notifyPreviewState() {
            if (AndroidLiveWallpaperService.this.linkedEngine == this && (AndroidLiveWallpaperService.this.app.listener instanceof AndroidWallpaperListener)) {
                final boolean currentPreviewState = AndroidLiveWallpaperService.this.linkedEngine.isPreview();
                AndroidLiveWallpaperService.this.app.postRunnable(new Runnable() { // from class: com.badlogic.gdx.backends.android.AndroidLiveWallpaperService.AndroidWallpaperEngine.3
                    @Override // java.lang.Runnable
                    public void run() {
                        AndroidLiveWallpaper currentApp;
                        boolean shouldNotify = false;
                        synchronized (AndroidLiveWallpaperService.this.sync) {
                            if (!AndroidLiveWallpaperService.this.isPreviewNotified || AndroidLiveWallpaperService.this.notifiedPreviewState != currentPreviewState) {
                                AndroidLiveWallpaperService.this.notifiedPreviewState = currentPreviewState;
                                AndroidLiveWallpaperService.this.isPreviewNotified = true;
                                shouldNotify = true;
                            }
                        }
                        if (shouldNotify && (currentApp = AndroidLiveWallpaperService.this.app) != null) {
                            ((AndroidWallpaperListener) currentApp.listener).previewStateChange(currentPreviewState);
                        }
                    }
                });
            }
        }

        @Override // android.service.wallpaper.WallpaperService.Engine
        public WallpaperColors onComputeColors() {
            Application app = Gdx.app;
            if (Build.VERSION.SDK_INT >= 27 && (app instanceof AndroidLiveWallpaper)) {
                AndroidLiveWallpaper liveWallpaper = (AndroidLiveWallpaper) app;
                Color[] colors = liveWallpaper.wallpaperColors;
                if (colors != null) {
                    return new WallpaperColors(android.graphics.Color.valueOf(colors[0].r, colors[0].g, colors[0].b, colors[0].a), android.graphics.Color.valueOf(colors[1].r, colors[1].g, colors[1].b, colors[1].a), android.graphics.Color.valueOf(colors[2].r, colors[2].g, colors[2].b, colors[2].a));
                }
            }
            return super.onComputeColors();
        }
    }
}