package com.badlogic.gdx.graphics.profiling;

import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.math.FloatCounter;

/* loaded from: classes.dex */
public abstract class GLInterceptor implements GL20 {
    protected int calls;
    protected int drawCalls;
    protected GLProfiler glProfiler;
    protected int shaderSwitches;
    protected int textureBindings;
    protected final FloatCounter vertexCount = new FloatCounter(0);

    /* JADX INFO: Access modifiers changed from: protected */
    public GLInterceptor(GLProfiler profiler) {
        this.glProfiler = profiler;
    }

    public static String resolveErrorNumber(int error) {
        switch (error) {
            case GL20.GL_INVALID_ENUM /* 1280 */:
                return "GL_INVALID_ENUM";
            case GL20.GL_INVALID_VALUE /* 1281 */:
                return "GL_INVALID_VALUE";
            case GL20.GL_INVALID_OPERATION /* 1282 */:
                return "GL_INVALID_OPERATION";
            case 1283:
            case 1284:
            default:
                return "number " + error;
            case GL20.GL_OUT_OF_MEMORY /* 1285 */:
                return "GL_OUT_OF_MEMORY";
            case GL20.GL_INVALID_FRAMEBUFFER_OPERATION /* 1286 */:
                return "GL_INVALID_FRAMEBUFFER_OPERATION";
        }
    }

    public int getCalls() {
        return this.calls;
    }

    public int getTextureBindings() {
        return this.textureBindings;
    }

    public int getDrawCalls() {
        return this.drawCalls;
    }

    public int getShaderSwitches() {
        return this.shaderSwitches;
    }

    public FloatCounter getVertexCount() {
        return this.vertexCount;
    }

    public void reset() {
        this.calls = 0;
        this.textureBindings = 0;
        this.drawCalls = 0;
        this.shaderSwitches = 0;
        this.vertexCount.reset();
    }
}