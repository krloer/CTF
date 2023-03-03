package com.badlogic.gdx.graphics.profiling;

import com.badlogic.gdx.graphics.GL20;
import java.nio.Buffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;

/* loaded from: classes.dex */
public class GL20Interceptor extends GLInterceptor implements GL20 {
    protected final GL20 gl20;

    /* JADX INFO: Access modifiers changed from: protected */
    public GL20Interceptor(GLProfiler glProfiler, GL20 gl20) {
        super(glProfiler);
        this.gl20 = gl20;
    }

    private void check() {
        int error = this.gl20.glGetError();
        while (error != 0) {
            this.glProfiler.getListener().onError(error);
            error = this.gl20.glGetError();
        }
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glActiveTexture(int texture) {
        this.calls++;
        this.gl20.glActiveTexture(texture);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindTexture(int target, int texture) {
        this.textureBindings++;
        this.calls++;
        this.gl20.glBindTexture(target, texture);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendFunc(int sfactor, int dfactor) {
        this.calls++;
        this.gl20.glBlendFunc(sfactor, dfactor);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glClear(int mask) {
        this.calls++;
        this.gl20.glClear(mask);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glClearColor(float red, float green, float blue, float alpha) {
        this.calls++;
        this.gl20.glClearColor(red, green, blue, alpha);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glClearDepthf(float depth) {
        this.calls++;
        this.gl20.glClearDepthf(depth);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glClearStencil(int s) {
        this.calls++;
        this.gl20.glClearStencil(s);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glColorMask(boolean red, boolean green, boolean blue, boolean alpha) {
        this.calls++;
        this.gl20.glColorMask(red, green, blue, alpha);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCompressedTexImage2D(int target, int level, int internalformat, int width, int height, int border, int imageSize, Buffer data) {
        this.calls++;
        this.gl20.glCompressedTexImage2D(target, level, internalformat, width, height, border, imageSize, data);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCompressedTexSubImage2D(int target, int level, int xoffset, int yoffset, int width, int height, int format, int imageSize, Buffer data) {
        this.calls++;
        this.gl20.glCompressedTexSubImage2D(target, level, xoffset, yoffset, width, height, format, imageSize, data);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCopyTexImage2D(int target, int level, int internalformat, int x, int y, int width, int height, int border) {
        this.calls++;
        this.gl20.glCopyTexImage2D(target, level, internalformat, x, y, width, height, border);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCopyTexSubImage2D(int target, int level, int xoffset, int yoffset, int x, int y, int width, int height) {
        this.calls++;
        this.gl20.glCopyTexSubImage2D(target, level, xoffset, yoffset, x, y, width, height);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCullFace(int mode) {
        this.calls++;
        this.gl20.glCullFace(mode);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteTextures(int n, IntBuffer textures) {
        this.calls++;
        this.gl20.glDeleteTextures(n, textures);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteTexture(int texture) {
        this.calls++;
        this.gl20.glDeleteTexture(texture);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDepthFunc(int func) {
        this.calls++;
        this.gl20.glDepthFunc(func);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDepthMask(boolean flag) {
        this.calls++;
        this.gl20.glDepthMask(flag);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDepthRangef(float zNear, float zFar) {
        this.calls++;
        this.gl20.glDepthRangef(zNear, zFar);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDisable(int cap) {
        this.calls++;
        this.gl20.glDisable(cap);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDrawArrays(int mode, int first, int count) {
        this.vertexCount.put(count);
        this.drawCalls++;
        this.calls++;
        this.gl20.glDrawArrays(mode, first, count);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDrawElements(int mode, int count, int type, Buffer indices) {
        this.vertexCount.put(count);
        this.drawCalls++;
        this.calls++;
        this.gl20.glDrawElements(mode, count, type, indices);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glEnable(int cap) {
        this.calls++;
        this.gl20.glEnable(cap);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFinish() {
        this.calls++;
        this.gl20.glFinish();
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFlush() {
        this.calls++;
        this.gl20.glFlush();
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFrontFace(int mode) {
        this.calls++;
        this.gl20.glFrontFace(mode);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenTextures(int n, IntBuffer textures) {
        this.calls++;
        this.gl20.glGenTextures(n, textures);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGenTexture() {
        this.calls++;
        int result = this.gl20.glGenTexture();
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGetError() {
        this.calls++;
        return this.gl20.glGetError();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetIntegerv(int pname, IntBuffer params) {
        this.calls++;
        this.gl20.glGetIntegerv(pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetString(int name) {
        this.calls++;
        String result = this.gl20.glGetString(name);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glHint(int target, int mode) {
        this.calls++;
        this.gl20.glHint(target, mode);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glLineWidth(float width) {
        this.calls++;
        this.gl20.glLineWidth(width);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glPixelStorei(int pname, int param) {
        this.calls++;
        this.gl20.glPixelStorei(pname, param);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glPolygonOffset(float factor, float units) {
        this.calls++;
        this.gl20.glPolygonOffset(factor, units);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glReadPixels(int x, int y, int width, int height, int format, int type, Buffer pixels) {
        this.calls++;
        this.gl20.glReadPixels(x, y, width, height, format, type, pixels);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glScissor(int x, int y, int width, int height) {
        this.calls++;
        this.gl20.glScissor(x, y, width, height);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilFunc(int func, int ref, int mask) {
        this.calls++;
        this.gl20.glStencilFunc(func, ref, mask);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilMask(int mask) {
        this.calls++;
        this.gl20.glStencilMask(mask);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilOp(int fail, int zfail, int zpass) {
        this.calls++;
        this.gl20.glStencilOp(fail, zfail, zpass);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexImage2D(int target, int level, int internalformat, int width, int height, int border, int format, int type, Buffer pixels) {
        this.calls++;
        this.gl20.glTexImage2D(target, level, internalformat, width, height, border, format, type, pixels);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexParameterf(int target, int pname, float param) {
        this.calls++;
        this.gl20.glTexParameterf(target, pname, param);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexSubImage2D(int target, int level, int xoffset, int yoffset, int width, int height, int format, int type, Buffer pixels) {
        this.calls++;
        this.gl20.glTexSubImage2D(target, level, xoffset, yoffset, width, height, format, type, pixels);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glViewport(int x, int y, int width, int height) {
        this.calls++;
        this.gl20.glViewport(x, y, width, height);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glAttachShader(int program, int shader) {
        this.calls++;
        this.gl20.glAttachShader(program, shader);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindAttribLocation(int program, int index, String name) {
        this.calls++;
        this.gl20.glBindAttribLocation(program, index, name);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindBuffer(int target, int buffer) {
        this.calls++;
        this.gl20.glBindBuffer(target, buffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindFramebuffer(int target, int framebuffer) {
        this.calls++;
        this.gl20.glBindFramebuffer(target, framebuffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindRenderbuffer(int target, int renderbuffer) {
        this.calls++;
        this.gl20.glBindRenderbuffer(target, renderbuffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendColor(float red, float green, float blue, float alpha) {
        this.calls++;
        this.gl20.glBlendColor(red, green, blue, alpha);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendEquation(int mode) {
        this.calls++;
        this.gl20.glBlendEquation(mode);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendEquationSeparate(int modeRGB, int modeAlpha) {
        this.calls++;
        this.gl20.glBlendEquationSeparate(modeRGB, modeAlpha);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendFuncSeparate(int srcRGB, int dstRGB, int srcAlpha, int dstAlpha) {
        this.calls++;
        this.gl20.glBlendFuncSeparate(srcRGB, dstRGB, srcAlpha, dstAlpha);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBufferData(int target, int size, Buffer data, int usage) {
        this.calls++;
        this.gl20.glBufferData(target, size, data, usage);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBufferSubData(int target, int offset, int size, Buffer data) {
        this.calls++;
        this.gl20.glBufferSubData(target, offset, size, data);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glCheckFramebufferStatus(int target) {
        this.calls++;
        int result = this.gl20.glCheckFramebufferStatus(target);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCompileShader(int shader) {
        this.calls++;
        this.gl20.glCompileShader(shader);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glCreateProgram() {
        this.calls++;
        int result = this.gl20.glCreateProgram();
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glCreateShader(int type) {
        this.calls++;
        int result = this.gl20.glCreateShader(type);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteBuffer(int buffer) {
        this.calls++;
        this.gl20.glDeleteBuffer(buffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteBuffers(int n, IntBuffer buffers) {
        this.calls++;
        this.gl20.glDeleteBuffers(n, buffers);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteFramebuffer(int framebuffer) {
        this.calls++;
        this.gl20.glDeleteFramebuffer(framebuffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteFramebuffers(int n, IntBuffer framebuffers) {
        this.calls++;
        this.gl20.glDeleteFramebuffers(n, framebuffers);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteProgram(int program) {
        this.calls++;
        this.gl20.glDeleteProgram(program);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteRenderbuffer(int renderbuffer) {
        this.calls++;
        this.gl20.glDeleteRenderbuffer(renderbuffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteRenderbuffers(int n, IntBuffer renderbuffers) {
        this.calls++;
        this.gl20.glDeleteRenderbuffers(n, renderbuffers);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteShader(int shader) {
        this.calls++;
        this.gl20.glDeleteShader(shader);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDetachShader(int program, int shader) {
        this.calls++;
        this.gl20.glDetachShader(program, shader);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDisableVertexAttribArray(int index) {
        this.calls++;
        this.gl20.glDisableVertexAttribArray(index);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDrawElements(int mode, int count, int type, int indices) {
        this.vertexCount.put(count);
        this.drawCalls++;
        this.calls++;
        this.gl20.glDrawElements(mode, count, type, indices);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glEnableVertexAttribArray(int index) {
        this.calls++;
        this.gl20.glEnableVertexAttribArray(index);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFramebufferRenderbuffer(int target, int attachment, int renderbuffertarget, int renderbuffer) {
        this.calls++;
        this.gl20.glFramebufferRenderbuffer(target, attachment, renderbuffertarget, renderbuffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFramebufferTexture2D(int target, int attachment, int textarget, int texture, int level) {
        this.calls++;
        this.gl20.glFramebufferTexture2D(target, attachment, textarget, texture, level);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGenBuffer() {
        this.calls++;
        int result = this.gl20.glGenBuffer();
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenBuffers(int n, IntBuffer buffers) {
        this.calls++;
        this.gl20.glGenBuffers(n, buffers);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenerateMipmap(int target) {
        this.calls++;
        this.gl20.glGenerateMipmap(target);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGenFramebuffer() {
        this.calls++;
        int result = this.gl20.glGenFramebuffer();
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenFramebuffers(int n, IntBuffer framebuffers) {
        this.calls++;
        this.gl20.glGenFramebuffers(n, framebuffers);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGenRenderbuffer() {
        this.calls++;
        int result = this.gl20.glGenRenderbuffer();
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenRenderbuffers(int n, IntBuffer renderbuffers) {
        this.calls++;
        this.gl20.glGenRenderbuffers(n, renderbuffers);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetActiveAttrib(int program, int index, IntBuffer size, IntBuffer type) {
        this.calls++;
        String result = this.gl20.glGetActiveAttrib(program, index, size, type);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetActiveUniform(int program, int index, IntBuffer size, IntBuffer type) {
        this.calls++;
        String result = this.gl20.glGetActiveUniform(program, index, size, type);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetAttachedShaders(int program, int maxcount, Buffer count, IntBuffer shaders) {
        this.calls++;
        this.gl20.glGetAttachedShaders(program, maxcount, count, shaders);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGetAttribLocation(int program, String name) {
        this.calls++;
        int result = this.gl20.glGetAttribLocation(program, name);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetBooleanv(int pname, Buffer params) {
        this.calls++;
        this.gl20.glGetBooleanv(pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetBufferParameteriv(int target, int pname, IntBuffer params) {
        this.calls++;
        this.gl20.glGetBufferParameteriv(target, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetFloatv(int pname, FloatBuffer params) {
        this.calls++;
        this.gl20.glGetFloatv(pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetFramebufferAttachmentParameteriv(int target, int attachment, int pname, IntBuffer params) {
        this.calls++;
        this.gl20.glGetFramebufferAttachmentParameteriv(target, attachment, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetProgramiv(int program, int pname, IntBuffer params) {
        this.calls++;
        this.gl20.glGetProgramiv(program, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetProgramInfoLog(int program) {
        this.calls++;
        String result = this.gl20.glGetProgramInfoLog(program);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetRenderbufferParameteriv(int target, int pname, IntBuffer params) {
        this.calls++;
        this.gl20.glGetRenderbufferParameteriv(target, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetShaderiv(int shader, int pname, IntBuffer params) {
        this.calls++;
        this.gl20.glGetShaderiv(shader, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetShaderInfoLog(int shader) {
        this.calls++;
        String result = this.gl20.glGetShaderInfoLog(shader);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetShaderPrecisionFormat(int shadertype, int precisiontype, IntBuffer range, IntBuffer precision) {
        this.calls++;
        this.gl20.glGetShaderPrecisionFormat(shadertype, precisiontype, range, precision);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetTexParameterfv(int target, int pname, FloatBuffer params) {
        this.calls++;
        this.gl20.glGetTexParameterfv(target, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetTexParameteriv(int target, int pname, IntBuffer params) {
        this.calls++;
        this.gl20.glGetTexParameteriv(target, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetUniformfv(int program, int location, FloatBuffer params) {
        this.calls++;
        this.gl20.glGetUniformfv(program, location, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetUniformiv(int program, int location, IntBuffer params) {
        this.calls++;
        this.gl20.glGetUniformiv(program, location, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGetUniformLocation(int program, String name) {
        this.calls++;
        int result = this.gl20.glGetUniformLocation(program, name);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetVertexAttribfv(int index, int pname, FloatBuffer params) {
        this.calls++;
        this.gl20.glGetVertexAttribfv(index, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetVertexAttribiv(int index, int pname, IntBuffer params) {
        this.calls++;
        this.gl20.glGetVertexAttribiv(index, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetVertexAttribPointerv(int index, int pname, Buffer pointer) {
        this.calls++;
        this.gl20.glGetVertexAttribPointerv(index, pname, pointer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsBuffer(int buffer) {
        this.calls++;
        boolean result = this.gl20.glIsBuffer(buffer);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsEnabled(int cap) {
        this.calls++;
        boolean result = this.gl20.glIsEnabled(cap);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsFramebuffer(int framebuffer) {
        this.calls++;
        boolean result = this.gl20.glIsFramebuffer(framebuffer);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsProgram(int program) {
        this.calls++;
        boolean result = this.gl20.glIsProgram(program);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsRenderbuffer(int renderbuffer) {
        this.calls++;
        boolean result = this.gl20.glIsRenderbuffer(renderbuffer);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsShader(int shader) {
        this.calls++;
        boolean result = this.gl20.glIsShader(shader);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsTexture(int texture) {
        this.calls++;
        boolean result = this.gl20.glIsTexture(texture);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glLinkProgram(int program) {
        this.calls++;
        this.gl20.glLinkProgram(program);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glReleaseShaderCompiler() {
        this.calls++;
        this.gl20.glReleaseShaderCompiler();
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glRenderbufferStorage(int target, int internalformat, int width, int height) {
        this.calls++;
        this.gl20.glRenderbufferStorage(target, internalformat, width, height);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glSampleCoverage(float value, boolean invert) {
        this.calls++;
        this.gl20.glSampleCoverage(value, invert);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glShaderBinary(int n, IntBuffer shaders, int binaryformat, Buffer binary, int length) {
        this.calls++;
        this.gl20.glShaderBinary(n, shaders, binaryformat, binary, length);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glShaderSource(int shader, String string) {
        this.calls++;
        this.gl20.glShaderSource(shader, string);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilFuncSeparate(int face, int func, int ref, int mask) {
        this.calls++;
        this.gl20.glStencilFuncSeparate(face, func, ref, mask);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilMaskSeparate(int face, int mask) {
        this.calls++;
        this.gl20.glStencilMaskSeparate(face, mask);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilOpSeparate(int face, int fail, int zfail, int zpass) {
        this.calls++;
        this.gl20.glStencilOpSeparate(face, fail, zfail, zpass);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexParameterfv(int target, int pname, FloatBuffer params) {
        this.calls++;
        this.gl20.glTexParameterfv(target, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexParameteri(int target, int pname, int param) {
        this.calls++;
        this.gl20.glTexParameteri(target, pname, param);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexParameteriv(int target, int pname, IntBuffer params) {
        this.calls++;
        this.gl20.glTexParameteriv(target, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1f(int location, float x) {
        this.calls++;
        this.gl20.glUniform1f(location, x);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1fv(int location, int count, FloatBuffer v) {
        this.calls++;
        this.gl20.glUniform1fv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1fv(int location, int count, float[] v, int offset) {
        this.calls++;
        this.gl20.glUniform1fv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1i(int location, int x) {
        this.calls++;
        this.gl20.glUniform1i(location, x);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1iv(int location, int count, IntBuffer v) {
        this.calls++;
        this.gl20.glUniform1iv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1iv(int location, int count, int[] v, int offset) {
        this.calls++;
        this.gl20.glUniform1iv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2f(int location, float x, float y) {
        this.calls++;
        this.gl20.glUniform2f(location, x, y);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2fv(int location, int count, FloatBuffer v) {
        this.calls++;
        this.gl20.glUniform2fv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2fv(int location, int count, float[] v, int offset) {
        this.calls++;
        this.gl20.glUniform2fv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2i(int location, int x, int y) {
        this.calls++;
        this.gl20.glUniform2i(location, x, y);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2iv(int location, int count, IntBuffer v) {
        this.calls++;
        this.gl20.glUniform2iv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2iv(int location, int count, int[] v, int offset) {
        this.calls++;
        this.gl20.glUniform2iv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3f(int location, float x, float y, float z) {
        this.calls++;
        this.gl20.glUniform3f(location, x, y, z);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3fv(int location, int count, FloatBuffer v) {
        this.calls++;
        this.gl20.glUniform3fv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3fv(int location, int count, float[] v, int offset) {
        this.calls++;
        this.gl20.glUniform3fv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3i(int location, int x, int y, int z) {
        this.calls++;
        this.gl20.glUniform3i(location, x, y, z);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3iv(int location, int count, IntBuffer v) {
        this.calls++;
        this.gl20.glUniform3iv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3iv(int location, int count, int[] v, int offset) {
        this.calls++;
        this.gl20.glUniform3iv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4f(int location, float x, float y, float z, float w) {
        this.calls++;
        this.gl20.glUniform4f(location, x, y, z, w);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4fv(int location, int count, FloatBuffer v) {
        this.calls++;
        this.gl20.glUniform4fv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4fv(int location, int count, float[] v, int offset) {
        this.calls++;
        this.gl20.glUniform4fv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4i(int location, int x, int y, int z, int w) {
        this.calls++;
        this.gl20.glUniform4i(location, x, y, z, w);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4iv(int location, int count, IntBuffer v) {
        this.calls++;
        this.gl20.glUniform4iv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4iv(int location, int count, int[] v, int offset) {
        this.calls++;
        this.gl20.glUniform4iv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix2fv(int location, int count, boolean transpose, FloatBuffer value) {
        this.calls++;
        this.gl20.glUniformMatrix2fv(location, count, transpose, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix2fv(int location, int count, boolean transpose, float[] value, int offset) {
        this.calls++;
        this.gl20.glUniformMatrix2fv(location, count, transpose, value, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix3fv(int location, int count, boolean transpose, FloatBuffer value) {
        this.calls++;
        this.gl20.glUniformMatrix3fv(location, count, transpose, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix3fv(int location, int count, boolean transpose, float[] value, int offset) {
        this.calls++;
        this.gl20.glUniformMatrix3fv(location, count, transpose, value, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix4fv(int location, int count, boolean transpose, FloatBuffer value) {
        this.calls++;
        this.gl20.glUniformMatrix4fv(location, count, transpose, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix4fv(int location, int count, boolean transpose, float[] value, int offset) {
        this.calls++;
        this.gl20.glUniformMatrix4fv(location, count, transpose, value, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUseProgram(int program) {
        this.shaderSwitches++;
        this.calls++;
        this.gl20.glUseProgram(program);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glValidateProgram(int program) {
        this.calls++;
        this.gl20.glValidateProgram(program);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib1f(int indx, float x) {
        this.calls++;
        this.gl20.glVertexAttrib1f(indx, x);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib1fv(int indx, FloatBuffer values) {
        this.calls++;
        this.gl20.glVertexAttrib1fv(indx, values);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib2f(int indx, float x, float y) {
        this.calls++;
        this.gl20.glVertexAttrib2f(indx, x, y);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib2fv(int indx, FloatBuffer values) {
        this.calls++;
        this.gl20.glVertexAttrib2fv(indx, values);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib3f(int indx, float x, float y, float z) {
        this.calls++;
        this.gl20.glVertexAttrib3f(indx, x, y, z);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib3fv(int indx, FloatBuffer values) {
        this.calls++;
        this.gl20.glVertexAttrib3fv(indx, values);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib4f(int indx, float x, float y, float z, float w) {
        this.calls++;
        this.gl20.glVertexAttrib4f(indx, x, y, z, w);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib4fv(int indx, FloatBuffer values) {
        this.calls++;
        this.gl20.glVertexAttrib4fv(indx, values);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttribPointer(int indx, int size, int type, boolean normalized, int stride, Buffer ptr) {
        this.calls++;
        this.gl20.glVertexAttribPointer(indx, size, type, normalized, stride, ptr);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttribPointer(int indx, int size, int type, boolean normalized, int stride, int ptr) {
        this.calls++;
        this.gl20.glVertexAttribPointer(indx, size, type, normalized, stride, ptr);
        check();
    }
}