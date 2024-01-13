package com.badlogic.gdx.backends.android.surfaceview;

import android.content.Context;
import android.opengl.GLSurfaceView;
import android.os.Build;
import android.os.SystemClock;
import android.util.Log;
import android.view.KeyEvent;
import android.view.inputmethod.BaseInputConnection;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import com.badlogic.gdx.Input;
import com.badlogic.gdx.backends.android.DefaultAndroidInput;
import com.badlogic.gdx.backends.android.surfaceview.ResolutionStrategy;
import javax.microedition.khronos.egl.EGL10;
import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.egl.EGLContext;
import javax.microedition.khronos.egl.EGLDisplay;

/* loaded from: classes.dex */
public class GLSurfaceView20 extends GLSurfaceView {
    private static final boolean DEBUG = false;
    static String TAG = "GL2JNIView";
    static int targetGLESVersion;
    public Input.OnscreenKeyboardType onscreenKeyboardType;
    final ResolutionStrategy resolutionStrategy;

    public GLSurfaceView20(Context context, ResolutionStrategy resolutionStrategy, int targetGLESVersion2) {
        super(context);
        this.onscreenKeyboardType = Input.OnscreenKeyboardType.Default;
        targetGLESVersion = targetGLESVersion2;
        this.resolutionStrategy = resolutionStrategy;
        init(false, 16, 0);
    }

    public GLSurfaceView20(Context context, ResolutionStrategy resolutionStrategy) {
        this(context, resolutionStrategy, 2);
    }

    public GLSurfaceView20(Context context, boolean translucent, int depth, int stencil, ResolutionStrategy resolutionStrategy) {
        super(context);
        this.onscreenKeyboardType = Input.OnscreenKeyboardType.Default;
        this.resolutionStrategy = resolutionStrategy;
        init(translucent, depth, stencil);
    }

    @Override // android.view.SurfaceView, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        ResolutionStrategy.MeasuredDimension measures = this.resolutionStrategy.calcMeasures(widthMeasureSpec, heightMeasureSpec);
        setMeasuredDimension(measures.width, measures.height);
    }

    @Override // android.view.View
    public InputConnection onCreateInputConnection(EditorInfo outAttrs) {
        if (outAttrs != null) {
            outAttrs.imeOptions |= 268435456;
            outAttrs.inputType = DefaultAndroidInput.getAndroidInputType(this.onscreenKeyboardType);
        }
        BaseInputConnection connection = new BaseInputConnection(this, false) { // from class: com.badlogic.gdx.backends.android.surfaceview.GLSurfaceView20.1
            @Override // android.view.inputmethod.BaseInputConnection, android.view.inputmethod.InputConnection
            public boolean deleteSurroundingText(int beforeLength, int afterLength) {
                int sdkVersion = Build.VERSION.SDK_INT;
                if (sdkVersion >= 16 && beforeLength == 1 && afterLength == 0) {
                    sendDownUpKeyEventForBackwardCompatibility(67);
                    return true;
                }
                return super.deleteSurroundingText(beforeLength, afterLength);
            }

            private void sendDownUpKeyEventForBackwardCompatibility(int code) {
                long eventTime = SystemClock.uptimeMillis();
                super.sendKeyEvent(new KeyEvent(eventTime, eventTime, 0, code, 0, 0, -1, 0, 6));
                super.sendKeyEvent(new KeyEvent(SystemClock.uptimeMillis(), eventTime, 1, code, 0, 0, -1, 0, 6));
            }
        };
        return connection;
    }

    @Override // android.opengl.GLSurfaceView, android.view.SurfaceView, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
    }

    private void init(boolean translucent, int depth, int stencil) {
        if (translucent) {
            getHolder().setFormat(-3);
        }
        setEGLContextFactory(new ContextFactory());
        setEGLConfigChooser(translucent ? new ConfigChooser(8, 8, 8, 8, depth, stencil) : new ConfigChooser(8, 8, 8, 0, depth, stencil));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class ContextFactory implements GLSurfaceView.EGLContextFactory {
        private static int EGL_CONTEXT_CLIENT_VERSION = 12440;

        ContextFactory() {
        }

        @Override // android.opengl.GLSurfaceView.EGLContextFactory
        public EGLContext createContext(EGL10 egl, EGLDisplay display, EGLConfig eglConfig) {
            String str = GLSurfaceView20.TAG;
            Log.w(str, "creating OpenGL ES " + GLSurfaceView20.targetGLESVersion + ".0 context");
            StringBuilder sb = new StringBuilder();
            sb.append("Before eglCreateContext ");
            sb.append(GLSurfaceView20.targetGLESVersion);
            GLSurfaceView20.checkEglError(sb.toString(), egl);
            int[] attrib_list = {EGL_CONTEXT_CLIENT_VERSION, GLSurfaceView20.targetGLESVersion, 12344};
            EGLContext context = egl.eglCreateContext(display, eglConfig, EGL10.EGL_NO_CONTEXT, attrib_list);
            boolean success = GLSurfaceView20.checkEglError("After eglCreateContext " + GLSurfaceView20.targetGLESVersion, egl);
            if ((!success || context == null) && GLSurfaceView20.targetGLESVersion > 2) {
                Log.w(GLSurfaceView20.TAG, "Falling back to GLES 2");
                GLSurfaceView20.targetGLESVersion = 2;
                return createContext(egl, display, eglConfig);
            }
            String str2 = GLSurfaceView20.TAG;
            Log.w(str2, "Returning a GLES " + GLSurfaceView20.targetGLESVersion + " context");
            return context;
        }

        @Override // android.opengl.GLSurfaceView.EGLContextFactory
        public void destroyContext(EGL10 egl, EGLDisplay display, EGLContext context) {
            egl.eglDestroyContext(display, context);
        }
    }

    static boolean checkEglError(String prompt, EGL10 egl) {
        boolean result = true;
        while (true) {
            int error = egl.eglGetError();
            if (error != 12288) {
                result = false;
                Log.e(TAG, String.format("%s: EGL error: 0x%x", prompt, Integer.valueOf(error)));
            } else {
                return result;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class ConfigChooser implements GLSurfaceView.EGLConfigChooser {
        private static int EGL_OPENGL_ES2_BIT = 4;
        private static int[] s_configAttribs2 = {12324, 4, 12323, 4, 12322, 4, 12352, EGL_OPENGL_ES2_BIT, 12344};
        protected int mAlphaSize;
        protected int mBlueSize;
        protected int mDepthSize;
        protected int mGreenSize;
        protected int mRedSize;
        protected int mStencilSize;
        private int[] mValue = new int[1];

        public ConfigChooser(int r, int g, int b, int a, int depth, int stencil) {
            this.mRedSize = r;
            this.mGreenSize = g;
            this.mBlueSize = b;
            this.mAlphaSize = a;
            this.mDepthSize = depth;
            this.mStencilSize = stencil;
        }

        @Override // android.opengl.GLSurfaceView.EGLConfigChooser
        public EGLConfig chooseConfig(EGL10 egl, EGLDisplay display) {
            int[] num_config = new int[1];
            egl.eglChooseConfig(display, s_configAttribs2, null, 0, num_config);
            int numConfigs = num_config[0];
            if (numConfigs <= 0) {
                throw new IllegalArgumentException("No configs match configSpec");
            }
            EGLConfig[] configs = new EGLConfig[numConfigs];
            egl.eglChooseConfig(display, s_configAttribs2, configs, numConfigs, num_config);
            return chooseConfig(egl, display, configs);
        }

        public EGLConfig chooseConfig(EGL10 egl, EGLDisplay display, EGLConfig[] configs) {
            for (EGLConfig config : configs) {
                int d = findConfigAttrib(egl, display, config, 12325, 0);
                int s = findConfigAttrib(egl, display, config, 12326, 0);
                if (d >= this.mDepthSize && s >= this.mStencilSize) {
                    int r = findConfigAttrib(egl, display, config, 12324, 0);
                    int g = findConfigAttrib(egl, display, config, 12323, 0);
                    int b = findConfigAttrib(egl, display, config, 12322, 0);
                    int a = findConfigAttrib(egl, display, config, 12321, 0);
                    if (r == this.mRedSize && g == this.mGreenSize && b == this.mBlueSize && a == this.mAlphaSize) {
                        return config;
                    }
                }
            }
            return null;
        }

        private int findConfigAttrib(EGL10 egl, EGLDisplay display, EGLConfig config, int attribute, int defaultValue) {
            if (egl.eglGetConfigAttrib(display, config, attribute, this.mValue)) {
                return this.mValue[0];
            }
            return defaultValue;
        }

        private void printConfigs(EGL10 egl, EGLDisplay display, EGLConfig[] configs) {
            int numConfigs = configs.length;
            Log.w(GLSurfaceView20.TAG, String.format("%d configurations", Integer.valueOf(numConfigs)));
            for (int i = 0; i < numConfigs; i++) {
                Log.w(GLSurfaceView20.TAG, String.format("Configuration %d:\n", Integer.valueOf(i)));
                printConfig(egl, display, configs[i]);
            }
        }

        private void printConfig(EGL10 egl, EGLDisplay display, EGLConfig config) {
            int[] attributes = {12320, 12321, 12322, 12323, 12324, 12325, 12326, 12327, 12328, 12329, 12330, 12331, 12332, 12333, 12334, 12335, 12336, 12337, 12338, 12339, 12340, 12343, 12342, 12341, 12345, 12346, 12347, 12348, 12349, 12350, 12351, 12352, 12354};
            String[] names = {"EGL_BUFFER_SIZE", "EGL_ALPHA_SIZE", "EGL_BLUE_SIZE", "EGL_GREEN_SIZE", "EGL_RED_SIZE", "EGL_DEPTH_SIZE", "EGL_STENCIL_SIZE", "EGL_CONFIG_CAVEAT", "EGL_CONFIG_ID", "EGL_LEVEL", "EGL_MAX_PBUFFER_HEIGHT", "EGL_MAX_PBUFFER_PIXELS", "EGL_MAX_PBUFFER_WIDTH", "EGL_NATIVE_RENDERABLE", "EGL_NATIVE_VISUAL_ID", "EGL_NATIVE_VISUAL_TYPE", "EGL_PRESERVED_RESOURCES", "EGL_SAMPLES", "EGL_SAMPLE_BUFFERS", "EGL_SURFACE_TYPE", "EGL_TRANSPARENT_TYPE", "EGL_TRANSPARENT_RED_VALUE", "EGL_TRANSPARENT_GREEN_VALUE", "EGL_TRANSPARENT_BLUE_VALUE", "EGL_BIND_TO_TEXTURE_RGB", "EGL_BIND_TO_TEXTURE_RGBA", "EGL_MIN_SWAP_INTERVAL", "EGL_MAX_SWAP_INTERVAL", "EGL_LUMINANCE_SIZE", "EGL_ALPHA_MASK_SIZE", "EGL_COLOR_BUFFER_TYPE", "EGL_RENDERABLE_TYPE", "EGL_CONFORMANT"};
            int[] value = new int[1];
            for (int i = 0; i < attributes.length; i++) {
                int attribute = attributes[i];
                String name = names[i];
                if (egl.eglGetConfigAttrib(display, config, attribute, value)) {
                    Log.w(GLSurfaceView20.TAG, String.format("  %s: %d\n", name, Integer.valueOf(value[0])));
                } else {
                    do {
                    } while (egl.eglGetError() != 12288);
                }
            }
        }
    }
}