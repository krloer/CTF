package com.badlogic.gdx.backends.android;

import android.opengl.GLSurfaceView;
import android.os.Build;
import android.os.Process;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.DisplayCutout;
import android.view.View;
import com.badlogic.gdx.AbstractGraphics;
import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.Graphics;
import com.badlogic.gdx.LifecycleListener;
import com.badlogic.gdx.backends.android.surfaceview.GLSurfaceView20;
import com.badlogic.gdx.backends.android.surfaceview.GdxEglConfigChooser;
import com.badlogic.gdx.backends.android.surfaceview.ResolutionStrategy;
import com.badlogic.gdx.graphics.Cubemap;
import com.badlogic.gdx.graphics.Cursor;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.GL30;
import com.badlogic.gdx.graphics.Mesh;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.TextureArray;
import com.badlogic.gdx.graphics.glutils.FrameBuffer;
import com.badlogic.gdx.graphics.glutils.GLVersion;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.SnapshotArray;
import javax.microedition.khronos.egl.EGL10;
import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.egl.EGLContext;
import javax.microedition.khronos.egl.EGLDisplay;
import javax.microedition.khronos.opengles.GL10;

/* loaded from: classes.dex */
public class AndroidGraphics extends AbstractGraphics implements GLSurfaceView.Renderer {
    private static final String LOG_TAG = "AndroidGraphics";
    static volatile boolean enforceContinuousRendering = false;
    AndroidApplicationBase app;
    private Graphics.BufferFormat bufferFormat;
    protected final AndroidApplicationConfiguration config;
    volatile boolean created;
    protected float deltaTime;
    private float density;
    volatile boolean destroy;
    EGLContext eglContext;
    String extensions;
    protected int fps;
    protected long frameId;
    protected long frameStart;
    protected int frames;
    GL20 gl20;
    GL30 gl30;
    GLVersion glVersion;
    int height;
    private boolean isContinuous;
    protected long lastFrameTime;
    volatile boolean pause;
    private float ppcX;
    private float ppcY;
    private float ppiX;
    private float ppiY;
    volatile boolean resume;
    volatile boolean running;
    int safeInsetBottom;
    int safeInsetLeft;
    int safeInsetRight;
    int safeInsetTop;
    Object synch;
    int[] value;
    final GLSurfaceView20 view;
    int width;

    public AndroidGraphics(AndroidApplicationBase application, AndroidApplicationConfiguration config, ResolutionStrategy resolutionStrategy) {
        this(application, config, resolutionStrategy, true);
    }

    public AndroidGraphics(AndroidApplicationBase application, AndroidApplicationConfiguration config, ResolutionStrategy resolutionStrategy, boolean focusableView) {
        this.lastFrameTime = System.nanoTime();
        this.deltaTime = 0.0f;
        this.frameStart = System.nanoTime();
        this.frameId = -1L;
        this.frames = 0;
        this.created = false;
        this.running = false;
        this.pause = false;
        this.resume = false;
        this.destroy = false;
        this.ppiX = 0.0f;
        this.ppiY = 0.0f;
        this.ppcX = 0.0f;
        this.ppcY = 0.0f;
        this.density = 1.0f;
        this.bufferFormat = new Graphics.BufferFormat(8, 8, 8, 0, 16, 0, 0, false);
        this.isContinuous = true;
        this.value = new int[1];
        this.synch = new Object();
        this.config = config;
        this.app = application;
        this.view = createGLSurfaceView(application, resolutionStrategy);
        preserveEGLContextOnPause();
        if (focusableView) {
            this.view.setFocusable(true);
            this.view.setFocusableInTouchMode(true);
        }
    }

    protected void preserveEGLContextOnPause() {
        this.view.setPreserveEGLContextOnPause(true);
    }

    protected GLSurfaceView20 createGLSurfaceView(AndroidApplicationBase application, ResolutionStrategy resolutionStrategy) {
        if (!checkGL20()) {
            throw new GdxRuntimeException("Libgdx requires OpenGL ES 2.0");
        }
        GLSurfaceView.EGLConfigChooser configChooser = getEglConfigChooser();
        GLSurfaceView20 view = new GLSurfaceView20(application.getContext(), resolutionStrategy, this.config.useGL30 ? 3 : 2);
        if (configChooser != null) {
            view.setEGLConfigChooser(configChooser);
        } else {
            view.setEGLConfigChooser(this.config.r, this.config.g, this.config.b, this.config.a, this.config.depth, this.config.stencil);
        }
        view.setRenderer(this);
        return view;
    }

    public void onPauseGLSurfaceView() {
        GLSurfaceView20 gLSurfaceView20 = this.view;
        if (gLSurfaceView20 != null) {
            gLSurfaceView20.onPause();
        }
    }

    public void onResumeGLSurfaceView() {
        GLSurfaceView20 gLSurfaceView20 = this.view;
        if (gLSurfaceView20 != null) {
            gLSurfaceView20.onResume();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public GLSurfaceView.EGLConfigChooser getEglConfigChooser() {
        return new GdxEglConfigChooser(this.config.r, this.config.g, this.config.b, this.config.a, this.config.depth, this.config.stencil, this.config.numSamples);
    }

    protected void updatePpi() {
        DisplayMetrics metrics = new DisplayMetrics();
        this.app.getWindowManager().getDefaultDisplay().getMetrics(metrics);
        this.ppiX = metrics.xdpi;
        this.ppiY = metrics.ydpi;
        this.ppcX = metrics.xdpi / 2.54f;
        this.ppcY = metrics.ydpi / 2.54f;
        this.density = metrics.density;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public boolean checkGL20() {
        EGL10 egl = (EGL10) EGLContext.getEGL();
        EGLDisplay display = egl.eglGetDisplay(EGL10.EGL_DEFAULT_DISPLAY);
        int[] version = new int[2];
        egl.eglInitialize(display, version);
        int[] configAttribs = {12324, 4, 12323, 4, 12322, 4, 12352, 4, 12344};
        EGLConfig[] configs = new EGLConfig[10];
        int[] num_config = new int[1];
        egl.eglChooseConfig(display, configAttribs, configs, 10, num_config);
        egl.eglTerminate(display);
        return num_config[0] > 0;
    }

    @Override // com.badlogic.gdx.Graphics
    public GL20 getGL20() {
        return this.gl20;
    }

    @Override // com.badlogic.gdx.Graphics
    public void setGL20(GL20 gl20) {
        this.gl20 = gl20;
        if (this.gl30 == null) {
            Gdx.gl = gl20;
            Gdx.gl20 = gl20;
        }
    }

    @Override // com.badlogic.gdx.Graphics
    public boolean isGL30Available() {
        return this.gl30 != null;
    }

    @Override // com.badlogic.gdx.Graphics
    public GL30 getGL30() {
        return this.gl30;
    }

    @Override // com.badlogic.gdx.Graphics
    public void setGL30(GL30 gl30) {
        this.gl30 = gl30;
        if (gl30 != null) {
            this.gl20 = gl30;
            GL20 gl20 = this.gl20;
            Gdx.gl = gl20;
            Gdx.gl20 = gl20;
            Gdx.gl30 = gl30;
        }
    }

    @Override // com.badlogic.gdx.Graphics
    public int getHeight() {
        return this.height;
    }

    @Override // com.badlogic.gdx.Graphics
    public int getWidth() {
        return this.width;
    }

    @Override // com.badlogic.gdx.Graphics
    public int getBackBufferWidth() {
        return this.width;
    }

    @Override // com.badlogic.gdx.Graphics
    public int getBackBufferHeight() {
        return this.height;
    }

    protected void setupGL(GL10 gl) {
        String versionString = gl.glGetString(GL20.GL_VERSION);
        String vendorString = gl.glGetString(GL20.GL_VENDOR);
        String rendererString = gl.glGetString(GL20.GL_RENDERER);
        this.glVersion = new GLVersion(Application.ApplicationType.Android, versionString, vendorString, rendererString);
        if (this.config.useGL30 && this.glVersion.getMajorVersion() > 2) {
            if (this.gl30 != null) {
                return;
            }
            AndroidGL30 androidGL30 = new AndroidGL30();
            this.gl30 = androidGL30;
            this.gl20 = androidGL30;
            GL30 gl30 = this.gl30;
            Gdx.gl = gl30;
            Gdx.gl20 = gl30;
            Gdx.gl30 = gl30;
        } else if (this.gl20 != null) {
            return;
        } else {
            this.gl20 = new AndroidGL20();
            GL20 gl20 = this.gl20;
            Gdx.gl = gl20;
            Gdx.gl20 = gl20;
        }
        Application application = Gdx.app;
        application.log(LOG_TAG, "OGL renderer: " + gl.glGetString(GL20.GL_RENDERER));
        Application application2 = Gdx.app;
        application2.log(LOG_TAG, "OGL vendor: " + gl.glGetString(GL20.GL_VENDOR));
        Application application3 = Gdx.app;
        application3.log(LOG_TAG, "OGL version: " + gl.glGetString(GL20.GL_VERSION));
        Application application4 = Gdx.app;
        application4.log(LOG_TAG, "OGL extensions: " + gl.glGetString(GL20.GL_EXTENSIONS));
    }

    @Override // android.opengl.GLSurfaceView.Renderer
    public void onSurfaceChanged(GL10 gl, int width, int height) {
        this.width = width;
        this.height = height;
        updatePpi();
        updateSafeAreaInsets();
        gl.glViewport(0, 0, this.width, this.height);
        if (!this.created) {
            this.app.getApplicationListener().create();
            this.created = true;
            synchronized (this) {
                this.running = true;
            }
        }
        this.app.getApplicationListener().resize(width, height);
    }

    @Override // android.opengl.GLSurfaceView.Renderer
    public void onSurfaceCreated(GL10 gl, EGLConfig config) {
        this.eglContext = ((EGL10) EGLContext.getEGL()).eglGetCurrentContext();
        setupGL(gl);
        logConfig(config);
        updatePpi();
        updateSafeAreaInsets();
        Mesh.invalidateAllMeshes(this.app);
        Texture.invalidateAllTextures(this.app);
        Cubemap.invalidateAllCubemaps(this.app);
        TextureArray.invalidateAllTextureArrays(this.app);
        ShaderProgram.invalidateAllShaderPrograms(this.app);
        FrameBuffer.invalidateAllFrameBuffers(this.app);
        logManagedCachesStatus();
        Display display = this.app.getWindowManager().getDefaultDisplay();
        this.width = display.getWidth();
        this.height = display.getHeight();
        this.lastFrameTime = System.nanoTime();
        gl.glViewport(0, 0, this.width, this.height);
    }

    protected void logConfig(EGLConfig config) {
        EGL10 egl = (EGL10) EGLContext.getEGL();
        EGLDisplay display = egl.eglGetDisplay(EGL10.EGL_DEFAULT_DISPLAY);
        int r = getAttrib(egl, display, config, 12324, 0);
        int g = getAttrib(egl, display, config, 12323, 0);
        int b = getAttrib(egl, display, config, 12322, 0);
        int a = getAttrib(egl, display, config, 12321, 0);
        int d = getAttrib(egl, display, config, 12325, 0);
        int s = getAttrib(egl, display, config, 12326, 0);
        int samples = Math.max(getAttrib(egl, display, config, 12337, 0), getAttrib(egl, display, config, GdxEglConfigChooser.EGL_COVERAGE_SAMPLES_NV, 0));
        boolean coverageSample = getAttrib(egl, display, config, GdxEglConfigChooser.EGL_COVERAGE_SAMPLES_NV, 0) != 0;
        Application application = Gdx.app;
        application.log(LOG_TAG, "framebuffer: (" + r + ", " + g + ", " + b + ", " + a + ")");
        Application application2 = Gdx.app;
        StringBuilder sb = new StringBuilder();
        sb.append("depthbuffer: (");
        sb.append(d);
        sb.append(")");
        application2.log(LOG_TAG, sb.toString());
        Application application3 = Gdx.app;
        application3.log(LOG_TAG, "stencilbuffer: (" + s + ")");
        Application application4 = Gdx.app;
        application4.log(LOG_TAG, "samples: (" + samples + ")");
        Application application5 = Gdx.app;
        application5.log(LOG_TAG, "coverage sampling: (" + coverageSample + ")");
        this.bufferFormat = new Graphics.BufferFormat(r, g, b, a, d, s, samples, coverageSample);
    }

    private int getAttrib(EGL10 egl, EGLDisplay display, EGLConfig config, int attrib, int defValue) {
        if (egl.eglGetConfigAttrib(display, config, attrib, this.value)) {
            return this.value[0];
        }
        return defValue;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void resume() {
        synchronized (this.synch) {
            this.running = true;
            this.resume = true;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void pause() {
        synchronized (this.synch) {
            if (this.running) {
                this.running = false;
                this.pause = true;
                this.view.queueEvent(new Runnable() { // from class: com.badlogic.gdx.backends.android.AndroidGraphics.1
                    @Override // java.lang.Runnable
                    public void run() {
                        if (!AndroidGraphics.this.pause) {
                            return;
                        }
                        AndroidGraphics.this.onDrawFrame(null);
                    }
                });
                while (this.pause) {
                    try {
                        this.synch.wait(4000L);
                        if (this.pause) {
                            Gdx.app.error(LOG_TAG, "waiting for pause synchronization took too long; assuming deadlock and killing");
                            Process.killProcess(Process.myPid());
                        }
                    } catch (InterruptedException e) {
                        Gdx.app.log(LOG_TAG, "waiting for pause synchronization failed!");
                    }
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void destroy() {
        synchronized (this.synch) {
            this.running = false;
            this.destroy = true;
            while (this.destroy) {
                try {
                    this.synch.wait();
                } catch (InterruptedException e) {
                    Gdx.app.log(LOG_TAG, "waiting for destroy synchronization failed!");
                }
            }
        }
    }

    @Override // android.opengl.GLSurfaceView.Renderer
    public void onDrawFrame(GL10 gl) {
        boolean lrunning;
        boolean lpause;
        boolean ldestroy;
        boolean lresume;
        long time = System.nanoTime();
        if (!this.resume) {
            this.deltaTime = ((float) (time - this.lastFrameTime)) / 1.0E9f;
        } else {
            this.deltaTime = 0.0f;
        }
        this.lastFrameTime = time;
        synchronized (this.synch) {
            lrunning = this.running;
            lpause = this.pause;
            ldestroy = this.destroy;
            lresume = this.resume;
            if (this.resume) {
                this.resume = false;
            }
            if (this.pause) {
                this.pause = false;
                this.synch.notifyAll();
            }
            if (this.destroy) {
                this.destroy = false;
                this.synch.notifyAll();
            }
        }
        if (lresume) {
            SnapshotArray<LifecycleListener> lifecycleListeners = this.app.getLifecycleListeners();
            synchronized (lifecycleListeners) {
                LifecycleListener[] listeners = lifecycleListeners.begin();
                int n = lifecycleListeners.size;
                for (int i = 0; i < n; i++) {
                    listeners[i].resume();
                }
                lifecycleListeners.end();
            }
            this.app.getApplicationListener().resume();
            Gdx.app.log(LOG_TAG, "resumed");
        }
        if (lrunning) {
            synchronized (this.app.getRunnables()) {
                this.app.getExecutedRunnables().clear();
                this.app.getExecutedRunnables().addAll(this.app.getRunnables());
                this.app.getRunnables().clear();
            }
            for (int i2 = 0; i2 < this.app.getExecutedRunnables().size; i2++) {
                try {
                    this.app.getExecutedRunnables().get(i2).run();
                } catch (Throwable t) {
                    t.printStackTrace();
                }
            }
            this.app.getInput().processEvents();
            this.frameId++;
            this.app.getApplicationListener().render();
        }
        if (lpause) {
            SnapshotArray<LifecycleListener> lifecycleListeners2 = this.app.getLifecycleListeners();
            synchronized (lifecycleListeners2) {
                LifecycleListener[] listeners2 = lifecycleListeners2.begin();
                int n2 = lifecycleListeners2.size;
                for (int i3 = 0; i3 < n2; i3++) {
                    listeners2[i3].pause();
                }
            }
            this.app.getApplicationListener().pause();
            Gdx.app.log(LOG_TAG, "paused");
        }
        if (ldestroy) {
            SnapshotArray<LifecycleListener> lifecycleListeners3 = this.app.getLifecycleListeners();
            synchronized (lifecycleListeners3) {
                LifecycleListener[] listeners3 = lifecycleListeners3.begin();
                int n3 = lifecycleListeners3.size;
                for (int i4 = 0; i4 < n3; i4++) {
                    listeners3[i4].dispose();
                }
            }
            this.app.getApplicationListener().dispose();
            Gdx.app.log(LOG_TAG, "destroyed");
        }
        if (time - this.frameStart > 1000000000) {
            this.fps = this.frames;
            this.frames = 0;
            this.frameStart = time;
        }
        this.frames++;
    }

    @Override // com.badlogic.gdx.Graphics
    public long getFrameId() {
        return this.frameId;
    }

    @Override // com.badlogic.gdx.Graphics
    public float getDeltaTime() {
        return this.deltaTime;
    }

    @Override // com.badlogic.gdx.Graphics
    public Graphics.GraphicsType getType() {
        return Graphics.GraphicsType.AndroidGL;
    }

    @Override // com.badlogic.gdx.Graphics
    public GLVersion getGLVersion() {
        return this.glVersion;
    }

    @Override // com.badlogic.gdx.Graphics
    public int getFramesPerSecond() {
        return this.fps;
    }

    public void clearManagedCaches() {
        Mesh.clearAllMeshes(this.app);
        Texture.clearAllTextures(this.app);
        Cubemap.clearAllCubemaps(this.app);
        TextureArray.clearAllTextureArrays(this.app);
        ShaderProgram.clearAllShaderPrograms(this.app);
        FrameBuffer.clearAllFrameBuffers(this.app);
        logManagedCachesStatus();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void logManagedCachesStatus() {
        Gdx.app.log(LOG_TAG, Mesh.getManagedStatus());
        Gdx.app.log(LOG_TAG, Texture.getManagedStatus());
        Gdx.app.log(LOG_TAG, Cubemap.getManagedStatus());
        Gdx.app.log(LOG_TAG, ShaderProgram.getManagedStatus());
        Gdx.app.log(LOG_TAG, FrameBuffer.getManagedStatus());
    }

    public View getView() {
        return this.view;
    }

    @Override // com.badlogic.gdx.Graphics
    public float getPpiX() {
        return this.ppiX;
    }

    @Override // com.badlogic.gdx.Graphics
    public float getPpiY() {
        return this.ppiY;
    }

    @Override // com.badlogic.gdx.Graphics
    public float getPpcX() {
        return this.ppcX;
    }

    @Override // com.badlogic.gdx.Graphics
    public float getPpcY() {
        return this.ppcY;
    }

    @Override // com.badlogic.gdx.AbstractGraphics, com.badlogic.gdx.Graphics
    public float getDensity() {
        return this.density;
    }

    @Override // com.badlogic.gdx.Graphics
    public boolean supportsDisplayModeChange() {
        return false;
    }

    @Override // com.badlogic.gdx.Graphics
    public boolean setFullscreenMode(Graphics.DisplayMode displayMode) {
        return false;
    }

    @Override // com.badlogic.gdx.Graphics
    public Graphics.Monitor getPrimaryMonitor() {
        return new AndroidMonitor(0, 0, "Primary Monitor");
    }

    @Override // com.badlogic.gdx.Graphics
    public Graphics.Monitor getMonitor() {
        return getPrimaryMonitor();
    }

    @Override // com.badlogic.gdx.Graphics
    public Graphics.Monitor[] getMonitors() {
        return new Graphics.Monitor[]{getPrimaryMonitor()};
    }

    @Override // com.badlogic.gdx.Graphics
    public Graphics.DisplayMode[] getDisplayModes(Graphics.Monitor monitor) {
        return getDisplayModes();
    }

    @Override // com.badlogic.gdx.Graphics
    public Graphics.DisplayMode getDisplayMode(Graphics.Monitor monitor) {
        return getDisplayMode();
    }

    @Override // com.badlogic.gdx.Graphics
    public Graphics.DisplayMode[] getDisplayModes() {
        return new Graphics.DisplayMode[]{getDisplayMode()};
    }

    protected void updateSafeAreaInsets() {
        this.safeInsetLeft = 0;
        this.safeInsetTop = 0;
        this.safeInsetRight = 0;
        this.safeInsetBottom = 0;
        if (Build.VERSION.SDK_INT >= 28) {
            try {
                DisplayCutout displayCutout = this.app.getApplicationWindow().getDecorView().getRootWindowInsets().getDisplayCutout();
                if (displayCutout != null) {
                    this.safeInsetRight = displayCutout.getSafeInsetRight();
                    this.safeInsetBottom = displayCutout.getSafeInsetBottom();
                    this.safeInsetTop = displayCutout.getSafeInsetTop();
                    this.safeInsetLeft = displayCutout.getSafeInsetLeft();
                }
            } catch (UnsupportedOperationException e) {
                Gdx.app.log(LOG_TAG, "Unable to get safe area insets");
            }
        }
    }

    @Override // com.badlogic.gdx.Graphics
    public int getSafeInsetLeft() {
        return this.safeInsetLeft;
    }

    @Override // com.badlogic.gdx.Graphics
    public int getSafeInsetTop() {
        return this.safeInsetTop;
    }

    @Override // com.badlogic.gdx.Graphics
    public int getSafeInsetBottom() {
        return this.safeInsetBottom;
    }

    @Override // com.badlogic.gdx.Graphics
    public int getSafeInsetRight() {
        return this.safeInsetRight;
    }

    @Override // com.badlogic.gdx.Graphics
    public boolean setWindowedMode(int width, int height) {
        return false;
    }

    @Override // com.badlogic.gdx.Graphics
    public void setTitle(String title) {
    }

    @Override // com.badlogic.gdx.Graphics
    public void setUndecorated(boolean undecorated) {
        this.app.getApplicationWindow().setFlags(GL20.GL_STENCIL_BUFFER_BIT, undecorated ? 1 : 0);
    }

    @Override // com.badlogic.gdx.Graphics
    public void setResizable(boolean resizable) {
    }

    @Override // com.badlogic.gdx.Graphics
    public Graphics.DisplayMode getDisplayMode() {
        DisplayMetrics metrics = new DisplayMetrics();
        this.app.getWindowManager().getDefaultDisplay().getMetrics(metrics);
        return new AndroidDisplayMode(metrics.widthPixels, metrics.heightPixels, 0, 0);
    }

    @Override // com.badlogic.gdx.Graphics
    public Graphics.BufferFormat getBufferFormat() {
        return this.bufferFormat;
    }

    @Override // com.badlogic.gdx.Graphics
    public void setVSync(boolean vsync) {
    }

    @Override // com.badlogic.gdx.Graphics
    public void setForegroundFPS(int fps) {
    }

    @Override // com.badlogic.gdx.Graphics
    public boolean supportsExtension(String extension) {
        if (this.extensions == null) {
            this.extensions = Gdx.gl.glGetString(GL20.GL_EXTENSIONS);
        }
        return this.extensions.contains(extension);
    }

    @Override // com.badlogic.gdx.Graphics
    public void setContinuousRendering(boolean isContinuous) {
        if (this.view != null) {
            this.isContinuous = enforceContinuousRendering || isContinuous;
            boolean z = this.isContinuous;
            GLSurfaceView20 gLSurfaceView20 = this.view;
            int renderMode = z ? 1 : 0;
            gLSurfaceView20.setRenderMode(renderMode);
        }
    }

    @Override // com.badlogic.gdx.Graphics
    public boolean isContinuousRendering() {
        return this.isContinuous;
    }

    @Override // com.badlogic.gdx.Graphics
    public void requestRendering() {
        GLSurfaceView20 gLSurfaceView20 = this.view;
        if (gLSurfaceView20 != null) {
            gLSurfaceView20.requestRender();
        }
    }

    @Override // com.badlogic.gdx.Graphics
    public boolean isFullscreen() {
        return true;
    }

    @Override // com.badlogic.gdx.Graphics
    public Cursor newCursor(Pixmap pixmap, int xHotspot, int yHotspot) {
        return null;
    }

    @Override // com.badlogic.gdx.Graphics
    public void setCursor(Cursor cursor) {
    }

    @Override // com.badlogic.gdx.Graphics
    public void setSystemCursor(Cursor.SystemCursor systemCursor) {
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class AndroidDisplayMode extends Graphics.DisplayMode {
        protected AndroidDisplayMode(int width, int height, int refreshRate, int bitsPerPixel) {
            super(width, height, refreshRate, bitsPerPixel);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class AndroidMonitor extends Graphics.Monitor {
        public AndroidMonitor(int virtualX, int virtualY, String name) {
            super(virtualX, virtualY, name);
        }
    }
}