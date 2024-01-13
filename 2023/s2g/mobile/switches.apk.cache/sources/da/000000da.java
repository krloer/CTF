package com.badlogic.gdx.backends.android.surfaceview;

import android.opengl.GLSurfaceView;
import android.util.Log;
import javax.microedition.khronos.egl.EGL10;
import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.egl.EGLDisplay;

/* loaded from: classes.dex */
public class GdxEglConfigChooser implements GLSurfaceView.EGLConfigChooser {
    public static final int EGL_COVERAGE_BUFFERS_NV = 12512;
    public static final int EGL_COVERAGE_SAMPLES_NV = 12513;
    private static final int EGL_OPENGL_ES2_BIT = 4;
    private static final String TAG = "GdxEglConfigChooser";
    protected int mAlphaSize;
    protected int mBlueSize;
    protected int mDepthSize;
    protected int mGreenSize;
    protected int mNumSamples;
    protected int mRedSize;
    protected int mStencilSize;
    private int[] mValue = new int[1];
    protected final int[] mConfigAttribs = {12324, 4, 12323, 4, 12322, 4, 12352, 4, 12344};

    public GdxEglConfigChooser(int r, int g, int b, int a, int depth, int stencil, int numSamples) {
        this.mRedSize = r;
        this.mGreenSize = g;
        this.mBlueSize = b;
        this.mAlphaSize = a;
        this.mDepthSize = depth;
        this.mStencilSize = stencil;
        this.mNumSamples = numSamples;
    }

    @Override // android.opengl.GLSurfaceView.EGLConfigChooser
    public EGLConfig chooseConfig(EGL10 egl, EGLDisplay display) {
        int[] num_config = new int[1];
        egl.eglChooseConfig(display, this.mConfigAttribs, null, 0, num_config);
        int numConfigs = num_config[0];
        if (numConfigs <= 0) {
            throw new IllegalArgumentException("No configs match configSpec");
        }
        EGLConfig[] configs = new EGLConfig[numConfigs];
        egl.eglChooseConfig(display, this.mConfigAttribs, configs, numConfigs, num_config);
        EGLConfig config = chooseConfig(egl, display, configs);
        return config;
    }

    public EGLConfig chooseConfig(EGL10 egl, EGLDisplay display, EGLConfig[] configs) {
        int i;
        EGLConfig[] eGLConfigArr = configs;
        int length = eGLConfigArr.length;
        EGLConfig best = null;
        EGLConfig bestAA = null;
        EGLConfig safe = null;
        int i2 = 0;
        while (i2 < length) {
            EGLConfig config = eGLConfigArr[i2];
            int d = findConfigAttrib(egl, display, config, 12325, 0);
            int s = findConfigAttrib(egl, display, config, 12326, 0);
            if (d >= this.mDepthSize) {
                if (s < this.mStencilSize) {
                    i = length;
                } else {
                    int r = findConfigAttrib(egl, display, config, 12324, 0);
                    int g = findConfigAttrib(egl, display, config, 12323, 0);
                    i = length;
                    int b = findConfigAttrib(egl, display, config, 12322, 0);
                    int a = findConfigAttrib(egl, display, config, 12321, 0);
                    if (safe == null && r == 5 && g == 6 && b == 5 && a == 0) {
                        safe = config;
                    }
                    if (best == null && r == this.mRedSize && g == this.mGreenSize && b == this.mBlueSize && a == this.mAlphaSize) {
                        best = config;
                        if (this.mNumSamples == 0) {
                            break;
                        }
                    }
                    EGLConfig safe2 = safe;
                    int hasSampleBuffers = findConfigAttrib(egl, display, config, 12338, 0);
                    EGLConfig best2 = best;
                    int numSamples = findConfigAttrib(egl, display, config, 12337, 0);
                    if (bestAA == null && hasSampleBuffers == 1 && numSamples >= this.mNumSamples && r == this.mRedSize && g == this.mGreenSize && b == this.mBlueSize && a == this.mAlphaSize) {
                        bestAA = config;
                        safe = safe2;
                        best = best2;
                    } else {
                        int hasSampleBuffers2 = findConfigAttrib(egl, display, config, EGL_COVERAGE_BUFFERS_NV, 0);
                        int numSamples2 = findConfigAttrib(egl, display, config, EGL_COVERAGE_SAMPLES_NV, 0);
                        if (bestAA != null || hasSampleBuffers2 != 1 || numSamples2 < this.mNumSamples || r != this.mRedSize || g != this.mGreenSize || b != this.mBlueSize || a != this.mAlphaSize) {
                            safe = safe2;
                            best = best2;
                        } else {
                            bestAA = config;
                            safe = safe2;
                            best = best2;
                        }
                    }
                }
            } else {
                i = length;
            }
            i2++;
            eGLConfigArr = configs;
            length = i;
        }
        if (bestAA != null) {
            return bestAA;
        }
        if (best != null) {
            return best;
        }
        return safe;
    }

    private int findConfigAttrib(EGL10 egl, EGLDisplay display, EGLConfig config, int attribute, int defaultValue) {
        if (egl.eglGetConfigAttrib(display, config, attribute, this.mValue)) {
            return this.mValue[0];
        }
        return defaultValue;
    }

    private void printConfigs(EGL10 egl, EGLDisplay display, EGLConfig[] configs) {
        int numConfigs = configs.length;
        Log.w(TAG, String.format("%d configurations", Integer.valueOf(numConfigs)));
        for (int i = 0; i < numConfigs; i++) {
            Log.w(TAG, String.format("Configuration %d:\n", Integer.valueOf(i)));
            printConfig(egl, display, configs[i]);
        }
    }

    private void printConfig(EGL10 egl, EGLDisplay display, EGLConfig config) {
        int[] attributes = {12320, 12321, 12322, 12323, 12324, 12325, 12326, 12327, 12328, 12329, 12330, 12331, 12332, 12333, 12334, 12335, 12336, 12337, 12338, 12339, 12340, 12343, 12342, 12341, 12345, 12346, 12347, 12348, 12349, 12350, 12351, 12352, 12354, EGL_COVERAGE_BUFFERS_NV, EGL_COVERAGE_SAMPLES_NV};
        String[] names = {"EGL_BUFFER_SIZE", "EGL_ALPHA_SIZE", "EGL_BLUE_SIZE", "EGL_GREEN_SIZE", "EGL_RED_SIZE", "EGL_DEPTH_SIZE", "EGL_STENCIL_SIZE", "EGL_CONFIG_CAVEAT", "EGL_CONFIG_ID", "EGL_LEVEL", "EGL_MAX_PBUFFER_HEIGHT", "EGL_MAX_PBUFFER_PIXELS", "EGL_MAX_PBUFFER_WIDTH", "EGL_NATIVE_RENDERABLE", "EGL_NATIVE_VISUAL_ID", "EGL_NATIVE_VISUAL_TYPE", "EGL_PRESERVED_RESOURCES", "EGL_SAMPLES", "EGL_SAMPLE_BUFFERS", "EGL_SURFACE_TYPE", "EGL_TRANSPARENT_TYPE", "EGL_TRANSPARENT_RED_VALUE", "EGL_TRANSPARENT_GREEN_VALUE", "EGL_TRANSPARENT_BLUE_VALUE", "EGL_BIND_TO_TEXTURE_RGB", "EGL_BIND_TO_TEXTURE_RGBA", "EGL_MIN_SWAP_INTERVAL", "EGL_MAX_SWAP_INTERVAL", "EGL_LUMINANCE_SIZE", "EGL_ALPHA_MASK_SIZE", "EGL_COLOR_BUFFER_TYPE", "EGL_RENDERABLE_TYPE", "EGL_CONFORMANT", "EGL_COVERAGE_BUFFERS_NV", "EGL_COVERAGE_SAMPLES_NV"};
        int[] value = new int[1];
        for (int i = 0; i < attributes.length; i++) {
            int attribute = attributes[i];
            String name = names[i];
            if (egl.eglGetConfigAttrib(display, config, attribute, value)) {
                Log.w(TAG, String.format("  %s: %d\n", name, Integer.valueOf(value[0])));
            } else {
                egl.eglGetError();
            }
        }
    }
}