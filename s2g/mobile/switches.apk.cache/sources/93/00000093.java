package com.badlogic.gdx.backends.android;

import android.content.Context;
import android.content.res.Configuration;
import android.os.Build;
import android.os.Debug;
import android.os.Handler;
import android.os.Looper;
import android.service.dreams.DreamService;
import android.view.View;
import android.view.Window;
import android.widget.FrameLayout;
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
import com.badlogic.gdx.backends.android.surfaceview.FillResolutionStrategy;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Clipboard;
import com.badlogic.gdx.utils.GdxNativesLoader;
import com.badlogic.gdx.utils.SnapshotArray;

/* loaded from: classes.dex */
public class AndroidDaydream extends DreamService implements AndroidApplicationBase {
    protected ApplicationLogger applicationLogger;
    protected AndroidAudio audio;
    protected AndroidClipboard clipboard;
    protected AndroidFiles files;
    protected AndroidGraphics graphics;
    protected Handler handler;
    protected AndroidInput input;
    protected ApplicationListener listener;
    protected AndroidNet net;
    protected boolean firstResume = true;
    protected final Array<Runnable> runnables = new Array<>();
    protected final Array<Runnable> executedRunnables = new Array<>();
    protected final SnapshotArray<LifecycleListener> lifecycleListeners = new SnapshotArray<>(LifecycleListener.class);
    protected int logLevel = 2;

    static {
        GdxNativesLoader.load();
    }

    public void initialize(ApplicationListener listener) {
        AndroidApplicationConfiguration config = new AndroidApplicationConfiguration();
        initialize(listener, config);
    }

    public void initialize(ApplicationListener listener, AndroidApplicationConfiguration config) {
        init(listener, config, false);
    }

    public View initializeForView(ApplicationListener listener) {
        AndroidApplicationConfiguration config = new AndroidApplicationConfiguration();
        return initializeForView(listener, config);
    }

    public View initializeForView(ApplicationListener listener, AndroidApplicationConfiguration config) {
        init(listener, config, true);
        return this.graphics.getView();
    }

    private void init(ApplicationListener listener, AndroidApplicationConfiguration config, boolean isForView) {
        setApplicationLogger(new AndroidApplicationLogger());
        this.graphics = new AndroidGraphics(this, config, config.resolutionStrategy == null ? new FillResolutionStrategy() : config.resolutionStrategy);
        this.input = createInput(this, this, this.graphics.view, config);
        this.audio = createAudio(this, config);
        this.files = createFiles();
        this.net = new AndroidNet(this, config);
        this.listener = listener;
        this.handler = new Handler();
        this.clipboard = new AndroidClipboard(this);
        addLifecycleListener(new LifecycleListener() { // from class: com.badlogic.gdx.backends.android.AndroidDaydream.1
            @Override // com.badlogic.gdx.LifecycleListener
            public void resume() {
                AndroidDaydream.this.audio.resume();
            }

            @Override // com.badlogic.gdx.LifecycleListener
            public void pause() {
                AndroidDaydream.this.audio.pause();
            }

            @Override // com.badlogic.gdx.LifecycleListener
            public void dispose() {
                AndroidDaydream.this.audio.dispose();
                AndroidDaydream.this.audio = null;
            }
        });
        Gdx.app = this;
        Gdx.input = getInput();
        Gdx.audio = getAudio();
        Gdx.files = getFiles();
        Gdx.graphics = getGraphics();
        Gdx.net = getNet();
        if (!isForView) {
            setFullscreen(true);
            setContentView(this.graphics.getView(), createLayoutParams());
        }
        createWakeLock(config.useWakelock);
        hideStatusBar(config);
        if (getResources().getConfiguration().keyboard != 1) {
            this.input.setKeyboardAvailable(true);
        }
    }

    protected FrameLayout.LayoutParams createLayoutParams() {
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, -1);
        layoutParams.gravity = 17;
        return layoutParams;
    }

    protected void createWakeLock(boolean use) {
        if (use) {
            getWindow().addFlags(128);
        }
    }

    protected void hideStatusBar(AndroidApplicationConfiguration config) {
        if (config.hideStatusBar) {
            View rootView = getWindow().getDecorView();
            rootView.setSystemUiVisibility(0);
            rootView.setSystemUiVisibility(1);
        }
    }

    @Override // android.service.dreams.DreamService
    public void onDreamingStopped() {
        boolean isContinuous = this.graphics.isContinuousRendering();
        this.graphics.setContinuousRendering(true);
        this.graphics.pause();
        this.input.onDreamingStopped();
        this.graphics.clearManagedCaches();
        this.graphics.destroy();
        this.graphics.setContinuousRendering(isContinuous);
        this.graphics.onPauseGLSurfaceView();
        super.onDreamingStopped();
    }

    @Override // android.service.dreams.DreamService
    public void onDreamingStarted() {
        Gdx.app = this;
        Gdx.input = getInput();
        Gdx.audio = getAudio();
        Gdx.files = getFiles();
        Gdx.graphics = getGraphics();
        Gdx.net = getNet();
        this.input.onDreamingStarted();
        AndroidGraphics androidGraphics = this.graphics;
        if (androidGraphics != null) {
            androidGraphics.onResumeGLSurfaceView();
        }
        if (!this.firstResume) {
            this.graphics.resume();
        } else {
            this.firstResume = false;
        }
        super.onDreamingStarted();
    }

    @Override // android.service.dreams.DreamService, android.view.Window.Callback
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
    }

    @Override // com.badlogic.gdx.Application
    public ApplicationListener getApplicationListener() {
        return this.listener;
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
        return new AndroidPreferences(getSharedPreferences(name, 0));
    }

    @Override // com.badlogic.gdx.Application
    public Clipboard getClipboard() {
        return this.clipboard;
    }

    @Override // com.badlogic.gdx.Application
    public void postRunnable(Runnable runnable) {
        synchronized (this.runnables) {
            this.runnables.add(runnable);
            Gdx.graphics.requestRendering();
        }
    }

    @Override // android.app.Service, android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration config) {
        super.onConfigurationChanged(config);
        boolean keyboardAvailable = config.hardKeyboardHidden == 1;
        this.input.setKeyboardAvailable(keyboardAvailable);
    }

    @Override // com.badlogic.gdx.Application
    public void exit() {
        this.handler.post(new Runnable() { // from class: com.badlogic.gdx.backends.android.AndroidDaydream.2
            @Override // java.lang.Runnable
            public void run() {
                AndroidDaydream.this.finish();
            }
        });
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
        return this;
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
    public Window getApplicationWindow() {
        return getWindow();
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public Handler getHandler() {
        return this.handler;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public AndroidAudio createAudio(Context context, AndroidApplicationConfiguration config) {
        return new DefaultAndroidAudio(context, config);
    }

    @Override // com.badlogic.gdx.backends.android.AndroidApplicationBase
    public AndroidInput createInput(Application activity, Context context, Object view, AndroidApplicationConfiguration config) {
        return new DefaultAndroidInput(this, this, this.graphics.view, config);
    }

    protected AndroidFiles createFiles() {
        getFilesDir();
        return new DefaultAndroidFiles(getAssets(), this, true);
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
}