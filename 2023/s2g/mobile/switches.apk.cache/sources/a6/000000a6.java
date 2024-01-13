package com.badlogic.gdx.backends.android;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Debug;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.Window;
import android.view.WindowManager;
import com.badlogic.gdx.Application;
import com.badlogic.gdx.ApplicationListener;
import com.badlogic.gdx.ApplicationLogger;
import com.badlogic.gdx.Audio;
import com.badlogic.gdx.Files;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.Graphics;
import com.badlogic.gdx.LifecycleListener;
import com.badlogic.gdx.Net;
import com.badlogic.gdx.Preferences;
import com.badlogic.gdx.backends.android.AndroidLiveWallpaperService;
import com.badlogic.gdx.backends.android.surfaceview.FillResolutionStrategy;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Clipboard;
import com.badlogic.gdx.utils.GdxNativesLoader;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.SnapshotArray;

/* loaded from: classes.dex */
public class AndroidLiveWallpaper implements AndroidApplicationBase {
    protected ApplicationLogger applicationLogger;
    protected AndroidAudio audio;
    protected AndroidClipboard clipboard;
    protected AndroidFiles files;
    protected AndroidGraphicsLiveWallpaper graphics;
    protected AndroidInput input;
    protected ApplicationListener listener;
    protected AndroidNet net;
    protected AndroidLiveWallpaperService service;
    protected boolean firstResume = true;
    protected final Array<Runnable> runnables = new Array<>();
    protected final Array<Runnable> executedRunnables = new Array<>();
    protected final SnapshotArray<LifecycleListener> lifecycleListeners = new SnapshotArray<>(LifecycleListener.class);
    protected int logLevel = 2;
    protected volatile Color[] wallpaperColors = null;

    static {
        GdxNativesLoader.load();
    }

    public AndroidLiveWallpaper(AndroidLiveWallpaperService service) {
        this.service = service;
    }

    public void initialize(ApplicationListener listener, AndroidApplicationConfiguration config) {
        if (getVersion() < 14) {
            throw new GdxRuntimeException("LibGDX requires Android API Level 14 or later.");
        }
        setApplicationLogger(new AndroidApplicationLogger());
        this.graphics = new AndroidGraphicsLiveWallpaper(this, config, config.resolutionStrategy == null ? new FillResolutionStrategy() : config.resolutionStrategy);
        this.input = createInput(this, getService(), this.graphics.view, config);
        this.audio = createAudio(getService(), config);
        this.files = createFiles();
        this.net = new AndroidNet(this, config);
        this.listener = listener;
        this.clipboard = new AndroidClipboard(getService());
        Gdx.app = this;
        Gdx.input = this.input;
        Gdx.audio = this.audio;
        Gdx.files = this.files;
        Gdx.graphics = this.graphics;
        Gdx.net = this.net;
    }

    public void onPause() {
        if (AndroidLiveWallpaperService.DEBUG) {
            Log.d("WallpaperService", " > AndroidLiveWallpaper - onPause()");
        }
        this.audio.pause();
        this.input.onPause();
        AndroidGraphicsLiveWallpaper androidGraphicsLiveWallpaper = this.graphics;
        if (androidGraphicsLiveWallpaper != null) {
            androidGraphicsLiveWallpaper.onPauseGLSurfaceView();
        }
        if (AndroidLiveWallpaperService.DEBUG) {
            Log.d("WallpaperService", " > AndroidLiveWallpaper - onPause() done!");
        }
    }

    public void onResume() {
        Gdx.app = this;
        AndroidInput androidInput = this.input;
        Gdx.input = androidInput;
        Gdx.audio = this.audio;
        Gdx.files = this.files;
        Gdx.graphics = this.graphics;
        Gdx.net = this.net;
        androidInput.onResume();
        AndroidGraphicsLiveWallpaper androidGraphicsLiveWallpaper = this.graphics;
        if (androidGraphicsLiveWallpaper != null) {
            androidGraphicsLiveWallpaper.onResumeGLSurfaceView();
        }
        if (!this.firstResume) {
            this.audio.resume();
            this.graphics.resume();
            return;
        }
        this.firstResume = false;
    }

    public void onDestroy() {
        AndroidGraphicsLiveWallpaper androidGraphicsLiveWallpaper = this.graphics;
        if (androidGraphicsLiveWallpaper != null) {
            androidGraphicsLiveWallpaper.onDestroyGLSurfaceView();
        }
        AndroidAudio androidAudio = this.audio;
        if (androidAudio != null) {
            androidAudio.dispose();
        }
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public WindowManager getWindowManager() {
        return this.service.getWindowManager();
    }

    public AndroidLiveWallpaperService getService() {
        return this.service;
    }

    @Override // com.badlogic.gdx.Application
    public ApplicationListener getApplicationListener() {
        return this.listener;
    }

    @Override // com.badlogic.gdx.Application
    public void postRunnable(Runnable runnable) {
        synchronized (this.runnables) {
            this.runnables.add(runnable);
        }
    }

    @Override // com.badlogic.gdx.Application
    public Audio getAudio() {
        return this.audio;
    }

    @Override // com.badlogic.gdx.Application
    public Files getFiles() {
        return this.files;
    }

    @Override // com.badlogic.gdx.Application
    public Graphics getGraphics() {
        return this.graphics;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase, com.badlogic.gdx.Application
    public AndroidInput getInput() {
        return this.input;
    }

    @Override // com.badlogic.gdx.Application
    public Net getNet() {
        return this.net;
    }

    @Override // com.badlogic.gdx.Application
    public Application.ApplicationType getType() {
        return Application.ApplicationType.Android;
    }

    @Override // com.badlogic.gdx.Application
    public int getVersion() {
        return Build.VERSION.SDK_INT;
    }

    @Override // com.badlogic.gdx.Application
    public long getJavaHeap() {
        return Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
    }

    @Override // com.badlogic.gdx.Application
    public long getNativeHeap() {
        return Debug.getNativeHeapAllocatedSize();
    }

    @Override // com.badlogic.gdx.Application
    public Preferences getPreferences(String name) {
        return new AndroidPreferences(this.service.getSharedPreferences(name, 0));
    }

    @Override // com.badlogic.gdx.Application
    public Clipboard getClipboard() {
        return this.clipboard;
    }

    @Override // com.badlogic.gdx.Application
    public void debug(String tag, String message) {
        if (this.logLevel >= 3) {
            getApplicationLogger().debug(tag, message);
        }
    }

    @Override // com.badlogic.gdx.Application
    public void debug(String tag, String message, Throwable exception) {
        if (this.logLevel >= 3) {
            getApplicationLogger().debug(tag, message, exception);
        }
    }

    @Override // com.badlogic.gdx.Application
    public void log(String tag, String message) {
        if (this.logLevel >= 2) {
            getApplicationLogger().log(tag, message);
        }
    }

    @Override // com.badlogic.gdx.Application
    public void log(String tag, String message, Throwable exception) {
        if (this.logLevel >= 2) {
            getApplicationLogger().log(tag, message, exception);
        }
    }

    @Override // com.badlogic.gdx.Application
    public void error(String tag, String message) {
        if (this.logLevel >= 1) {
            getApplicationLogger().error(tag, message);
        }
    }

    @Override // com.badlogic.gdx.Application
    public void error(String tag, String message, Throwable exception) {
        if (this.logLevel >= 1) {
            getApplicationLogger().error(tag, message, exception);
        }
    }

    @Override // com.badlogic.gdx.Application
    public void setLogLevel(int logLevel) {
        this.logLevel = logLevel;
    }

    @Override // com.badlogic.gdx.Application
    public int getLogLevel() {
        return this.logLevel;
    }

    @Override // com.badlogic.gdx.Application
    public void setApplicationLogger(ApplicationLogger applicationLogger) {
        this.applicationLogger = applicationLogger;
    }

    @Override // com.badlogic.gdx.Application
    public ApplicationLogger getApplicationLogger() {
        return this.applicationLogger;
    }

    @Override // com.badlogic.gdx.Application
    public void exit() {
    }

    @Override // com.badlogic.gdx.Application
    public void addLifecycleListener(LifecycleListener listener) {
        synchronized (this.lifecycleListeners) {
            this.lifecycleListeners.add(listener);
        }
    }

    @Override // com.badlogic.gdx.Application
    public void removeLifecycleListener(LifecycleListener listener) {
        synchronized (this.lifecycleListeners) {
            this.lifecycleListeners.removeValue(listener, true);
        }
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public Context getContext() {
        return this.service;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public Array<Runnable> getRunnables() {
        return this.runnables;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public Array<Runnable> getExecutedRunnables() {
        return this.executedRunnables;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public SnapshotArray<LifecycleListener> getLifecycleListeners() {
        return this.lifecycleListeners;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public void startActivity(Intent intent) {
        this.service.startActivity(intent);
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public Window getApplicationWindow() {
        throw new UnsupportedOperationException();
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public Handler getHandler() {
        throw new UnsupportedOperationException();
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public AndroidAudio createAudio(Context context, AndroidApplicationConfiguration config) {
        return new DefaultAndroidAudio(context, config);
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public AndroidInput createInput(Application activity, Context context, Object view, AndroidApplicationConfiguration config) {
        return new DefaultAndroidInput(this, getService(), this.graphics.view, config);
    }

    protected AndroidFiles createFiles() {
        getService().getFilesDir();
        return new DefaultAndroidFiles(getService().getAssets(), getService(), true);
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public void runOnUiThread(Runnable runnable) {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            new Handler(Looper.getMainLooper()).post(runnable);
        } else {
            runnable.run();
        }
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public void useImmersiveMode(boolean b) {
        throw new UnsupportedOperationException();
    }

    public void notifyColorsChanged(Color primaryColor, Color secondaryColor, Color tertiaryColor) {
        if (Build.VERSION.SDK_INT < 27) {
            return;
        }
        Color[] colors = {new Color(primaryColor), new Color(secondaryColor), new Color(tertiaryColor)};
        this.wallpaperColors = colors;
        AndroidLiveWallpaperService.AndroidWallpaperEngine engine = this.service.linkedEngine;
        if (engine != null) {
            engine.notifyColorsChanged();
        }
    }
}