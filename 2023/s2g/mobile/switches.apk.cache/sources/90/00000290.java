package com.badlogic.gdx.graphics.profiling;

import com.badlogic.gdx.graphics.GL30;
import java.nio.Buffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;

/* loaded from: classes.dex */
public class GL30Interceptor extends GLInterceptor implements GL30 {
    protected final GL30 gl30;

    /* JADX INFO: Access modifiers changed from: protected */
    public GL30Interceptor(GLProfiler glProfiler, GL30 gl30) {
        super(glProfiler);
        this.gl30 = gl30;
    }

    private void check() {
        int error = this.gl30.glGetError();
        while (error != 0) {
            this.glProfiler.getListener().onError(error);
            error = this.gl30.glGetError();
        }
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glActiveTexture(int texture) {
        this.calls++;
        this.gl30.glActiveTexture(texture);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindTexture(int target, int texture) {
        this.textureBindings++;
        this.calls++;
        this.gl30.glBindTexture(target, texture);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendFunc(int sfactor, int dfactor) {
        this.calls++;
        this.gl30.glBlendFunc(sfactor, dfactor);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glClear(int mask) {
        this.calls++;
        this.gl30.glClear(mask);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glClearColor(float red, float green, float blue, float alpha) {
        this.calls++;
        this.gl30.glClearColor(red, green, blue, alpha);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glClearDepthf(float depth) {
        this.calls++;
        this.gl30.glClearDepthf(depth);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glClearStencil(int s) {
        this.calls++;
        this.gl30.glClearStencil(s);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glColorMask(boolean red, boolean green, boolean blue, boolean alpha) {
        this.calls++;
        this.gl30.glColorMask(red, green, blue, alpha);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCompressedTexImage2D(int target, int level, int internalformat, int width, int height, int border, int imageSize, Buffer data) {
        this.calls++;
        this.gl30.glCompressedTexImage2D(target, level, internalformat, width, height, border, imageSize, data);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCompressedTexSubImage2D(int target, int level, int xoffset, int yoffset, int width, int height, int format, int imageSize, Buffer data) {
        this.calls++;
        this.gl30.glCompressedTexSubImage2D(target, level, xoffset, yoffset, width, height, format, imageSize, data);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCopyTexImage2D(int target, int level, int internalformat, int x, int y, int width, int height, int border) {
        this.calls++;
        this.gl30.glCopyTexImage2D(target, level, internalformat, x, y, width, height, border);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCopyTexSubImage2D(int target, int level, int xoffset, int yoffset, int x, int y, int width, int height) {
        this.calls++;
        this.gl30.glCopyTexSubImage2D(target, level, xoffset, yoffset, x, y, width, height);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCullFace(int mode) {
        this.calls++;
        this.gl30.glCullFace(mode);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteTextures(int n, IntBuffer textures) {
        this.calls++;
        this.gl30.glDeleteTextures(n, textures);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteTexture(int texture) {
        this.calls++;
        this.gl30.glDeleteTexture(texture);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDepthFunc(int func) {
        this.calls++;
        this.gl30.glDepthFunc(func);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDepthMask(boolean flag) {
        this.calls++;
        this.gl30.glDepthMask(flag);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDepthRangef(float zNear, float zFar) {
        this.calls++;
        this.gl30.glDepthRangef(zNear, zFar);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDisable(int cap) {
        this.calls++;
        this.gl30.glDisable(cap);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDrawArrays(int mode, int first, int count) {
        this.vertexCount.put(count);
        this.drawCalls++;
        this.calls++;
        this.gl30.glDrawArrays(mode, first, count);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDrawElements(int mode, int count, int type, Buffer indices) {
        this.vertexCount.put(count);
        this.drawCalls++;
        this.calls++;
        this.gl30.glDrawElements(mode, count, type, indices);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glEnable(int cap) {
        this.calls++;
        this.gl30.glEnable(cap);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFinish() {
        this.calls++;
        this.gl30.glFinish();
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFlush() {
        this.calls++;
        this.gl30.glFlush();
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFrontFace(int mode) {
        this.calls++;
        this.gl30.glFrontFace(mode);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenTextures(int n, IntBuffer textures) {
        this.calls++;
        this.gl30.glGenTextures(n, textures);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGenTexture() {
        this.calls++;
        int result = this.gl30.glGenTexture();
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGetError() {
        this.calls++;
        return this.gl30.glGetError();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetIntegerv(int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetIntegerv(pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetString(int name) {
        this.calls++;
        String result = this.gl30.glGetString(name);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glHint(int target, int mode) {
        this.calls++;
        this.gl30.glHint(target, mode);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glLineWidth(float width) {
        this.calls++;
        this.gl30.glLineWidth(width);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glPixelStorei(int pname, int param) {
        this.calls++;
        this.gl30.glPixelStorei(pname, param);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glPolygonOffset(float factor, float units) {
        this.calls++;
        this.gl30.glPolygonOffset(factor, units);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glReadPixels(int x, int y, int width, int height, int format, int type, Buffer pixels) {
        this.calls++;
        this.gl30.glReadPixels(x, y, width, height, format, type, pixels);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glScissor(int x, int y, int width, int height) {
        this.calls++;
        this.gl30.glScissor(x, y, width, height);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilFunc(int func, int ref, int mask) {
        this.calls++;
        this.gl30.glStencilFunc(func, ref, mask);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilMask(int mask) {
        this.calls++;
        this.gl30.glStencilMask(mask);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilOp(int fail, int zfail, int zpass) {
        this.calls++;
        this.gl30.glStencilOp(fail, zfail, zpass);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexImage2D(int target, int level, int internalformat, int width, int height, int border, int format, int type, Buffer pixels) {
        this.calls++;
        this.gl30.glTexImage2D(target, level, internalformat, width, height, border, format, type, pixels);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexParameterf(int target, int pname, float param) {
        this.calls++;
        this.gl30.glTexParameterf(target, pname, param);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexSubImage2D(int target, int level, int xoffset, int yoffset, int width, int height, int format, int type, Buffer pixels) {
        this.calls++;
        this.gl30.glTexSubImage2D(target, level, xoffset, yoffset, width, height, format, type, pixels);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glViewport(int x, int y, int width, int height) {
        this.calls++;
        this.gl30.glViewport(x, y, width, height);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glAttachShader(int program, int shader) {
        this.calls++;
        this.gl30.glAttachShader(program, shader);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindAttribLocation(int program, int index, String name) {
        this.calls++;
        this.gl30.glBindAttribLocation(program, index, name);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindBuffer(int target, int buffer) {
        this.calls++;
        this.gl30.glBindBuffer(target, buffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindFramebuffer(int target, int framebuffer) {
        this.calls++;
        this.gl30.glBindFramebuffer(target, framebuffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindRenderbuffer(int target, int renderbuffer) {
        this.calls++;
        this.gl30.glBindRenderbuffer(target, renderbuffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendColor(float red, float green, float blue, float alpha) {
        this.calls++;
        this.gl30.glBlendColor(red, green, blue, alpha);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendEquation(int mode) {
        this.calls++;
        this.gl30.glBlendEquation(mode);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendEquationSeparate(int modeRGB, int modeAlpha) {
        this.calls++;
        this.gl30.glBlendEquationSeparate(modeRGB, modeAlpha);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendFuncSeparate(int srcRGB, int dstRGB, int srcAlpha, int dstAlpha) {
        this.calls++;
        this.gl30.glBlendFuncSeparate(srcRGB, dstRGB, srcAlpha, dstAlpha);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBufferData(int target, int size, Buffer data, int usage) {
        this.calls++;
        this.gl30.glBufferData(target, size, data, usage);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBufferSubData(int target, int offset, int size, Buffer data) {
        this.calls++;
        this.gl30.glBufferSubData(target, offset, size, data);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glCheckFramebufferStatus(int target) {
        this.calls++;
        int result = this.gl30.glCheckFramebufferStatus(target);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCompileShader(int shader) {
        this.calls++;
        this.gl30.glCompileShader(shader);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glCreateProgram() {
        this.calls++;
        int result = this.gl30.glCreateProgram();
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glCreateShader(int type) {
        this.calls++;
        int result = this.gl30.glCreateShader(type);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteBuffer(int buffer) {
        this.calls++;
        this.gl30.glDeleteBuffer(buffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteBuffers(int n, IntBuffer buffers) {
        this.calls++;
        this.gl30.glDeleteBuffers(n, buffers);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteFramebuffer(int framebuffer) {
        this.calls++;
        this.gl30.glDeleteFramebuffer(framebuffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteFramebuffers(int n, IntBuffer framebuffers) {
        this.calls++;
        this.gl30.glDeleteFramebuffers(n, framebuffers);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteProgram(int program) {
        this.calls++;
        this.gl30.glDeleteProgram(program);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteRenderbuffer(int renderbuffer) {
        this.calls++;
        this.gl30.glDeleteRenderbuffer(renderbuffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteRenderbuffers(int n, IntBuffer renderbuffers) {
        this.calls++;
        this.gl30.glDeleteRenderbuffers(n, renderbuffers);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteShader(int shader) {
        this.calls++;
        this.gl30.glDeleteShader(shader);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDetachShader(int program, int shader) {
        this.calls++;
        this.gl30.glDetachShader(program, shader);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDisableVertexAttribArray(int index) {
        this.calls++;
        this.gl30.glDisableVertexAttribArray(index);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDrawElements(int mode, int count, int type, int indices) {
        this.vertexCount.put(count);
        this.drawCalls++;
        this.calls++;
        this.gl30.glDrawElements(mode, count, type, indices);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glEnableVertexAttribArray(int index) {
        this.calls++;
        this.gl30.glEnableVertexAttribArray(index);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFramebufferRenderbuffer(int target, int attachment, int renderbuffertarget, int renderbuffer) {
        this.calls++;
        this.gl30.glFramebufferRenderbuffer(target, attachment, renderbuffertarget, renderbuffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFramebufferTexture2D(int target, int attachment, int textarget, int texture, int level) {
        this.calls++;
        this.gl30.glFramebufferTexture2D(target, attachment, textarget, texture, level);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGenBuffer() {
        this.calls++;
        int result = this.gl30.glGenBuffer();
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenBuffers(int n, IntBuffer buffers) {
        this.calls++;
        this.gl30.glGenBuffers(n, buffers);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenerateMipmap(int target) {
        this.calls++;
        this.gl30.glGenerateMipmap(target);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGenFramebuffer() {
        this.calls++;
        int result = this.gl30.glGenFramebuffer();
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenFramebuffers(int n, IntBuffer framebuffers) {
        this.calls++;
        this.gl30.glGenFramebuffers(n, framebuffers);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGenRenderbuffer() {
        this.calls++;
        int result = this.gl30.glGenRenderbuffer();
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenRenderbuffers(int n, IntBuffer renderbuffers) {
        this.calls++;
        this.gl30.glGenRenderbuffers(n, renderbuffers);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetActiveAttrib(int program, int index, IntBuffer size, IntBuffer type) {
        this.calls++;
        String result = this.gl30.glGetActiveAttrib(program, index, size, type);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetActiveUniform(int program, int index, IntBuffer size, IntBuffer type) {
        this.calls++;
        String result = this.gl30.glGetActiveUniform(program, index, size, type);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetAttachedShaders(int program, int maxcount, Buffer count, IntBuffer shaders) {
        this.calls++;
        this.gl30.glGetAttachedShaders(program, maxcount, count, shaders);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGetAttribLocation(int program, String name) {
        this.calls++;
        int result = this.gl30.glGetAttribLocation(program, name);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetBooleanv(int pname, Buffer params) {
        this.calls++;
        this.gl30.glGetBooleanv(pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetBufferParameteriv(int target, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetBufferParameteriv(target, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetFloatv(int pname, FloatBuffer params) {
        this.calls++;
        this.gl30.glGetFloatv(pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetFramebufferAttachmentParameteriv(int target, int attachment, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetFramebufferAttachmentParameteriv(target, attachment, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetProgramiv(int program, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetProgramiv(program, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetProgramInfoLog(int program) {
        this.calls++;
        String result = this.gl30.glGetProgramInfoLog(program);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetRenderbufferParameteriv(int target, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetRenderbufferParameteriv(target, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetShaderiv(int shader, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetShaderiv(shader, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetShaderInfoLog(int shader) {
        this.calls++;
        String result = this.gl30.glGetShaderInfoLog(shader);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetShaderPrecisionFormat(int shadertype, int precisiontype, IntBuffer range, IntBuffer precision) {
        this.calls++;
        this.gl30.glGetShaderPrecisionFormat(shadertype, precisiontype, range, precision);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetTexParameterfv(int target, int pname, FloatBuffer params) {
        this.calls++;
        this.gl30.glGetTexParameterfv(target, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetTexParameteriv(int target, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetTexParameteriv(target, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetUniformfv(int program, int location, FloatBuffer params) {
        this.calls++;
        this.gl30.glGetUniformfv(program, location, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetUniformiv(int program, int location, IntBuffer params) {
        this.calls++;
        this.gl30.glGetUniformiv(program, location, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGetUniformLocation(int program, String name) {
        this.calls++;
        int result = this.gl30.glGetUniformLocation(program, name);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetVertexAttribfv(int index, int pname, FloatBuffer params) {
        this.calls++;
        this.gl30.glGetVertexAttribfv(index, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetVertexAttribiv(int index, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetVertexAttribiv(index, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetVertexAttribPointerv(int index, int pname, Buffer pointer) {
        this.calls++;
        this.gl30.glGetVertexAttribPointerv(index, pname, pointer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsBuffer(int buffer) {
        this.calls++;
        boolean result = this.gl30.glIsBuffer(buffer);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsEnabled(int cap) {
        this.calls++;
        boolean result = this.gl30.glIsEnabled(cap);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsFramebuffer(int framebuffer) {
        this.calls++;
        boolean result = this.gl30.glIsFramebuffer(framebuffer);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsProgram(int program) {
        this.calls++;
        boolean result = this.gl30.glIsProgram(program);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsRenderbuffer(int renderbuffer) {
        this.calls++;
        boolean result = this.gl30.glIsRenderbuffer(renderbuffer);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsShader(int shader) {
        this.calls++;
        boolean result = this.gl30.glIsShader(shader);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsTexture(int texture) {
        this.calls++;
        boolean result = this.gl30.glIsTexture(texture);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glLinkProgram(int program) {
        this.calls++;
        this.gl30.glLinkProgram(program);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glReleaseShaderCompiler() {
        this.calls++;
        this.gl30.glReleaseShaderCompiler();
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glRenderbufferStorage(int target, int internalformat, int width, int height) {
        this.calls++;
        this.gl30.glRenderbufferStorage(target, internalformat, width, height);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glSampleCoverage(float value, boolean invert) {
        this.calls++;
        this.gl30.glSampleCoverage(value, invert);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glShaderBinary(int n, IntBuffer shaders, int binaryformat, Buffer binary, int length) {
        this.calls++;
        this.gl30.glShaderBinary(n, shaders, binaryformat, binary, length);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glShaderSource(int shader, String string) {
        this.calls++;
        this.gl30.glShaderSource(shader, string);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilFuncSeparate(int face, int func, int ref, int mask) {
        this.calls++;
        this.gl30.glStencilFuncSeparate(face, func, ref, mask);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilMaskSeparate(int face, int mask) {
        this.calls++;
        this.gl30.glStencilMaskSeparate(face, mask);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilOpSeparate(int face, int fail, int zfail, int zpass) {
        this.calls++;
        this.gl30.glStencilOpSeparate(face, fail, zfail, zpass);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexParameterfv(int target, int pname, FloatBuffer params) {
        this.calls++;
        this.gl30.glTexParameterfv(target, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexParameteri(int target, int pname, int param) {
        this.calls++;
        this.gl30.glTexParameteri(target, pname, param);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexParameteriv(int target, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glTexParameteriv(target, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1f(int location, float x) {
        this.calls++;
        this.gl30.glUniform1f(location, x);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1fv(int location, int count, FloatBuffer v) {
        this.calls++;
        this.gl30.glUniform1fv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1fv(int location, int count, float[] v, int offset) {
        this.calls++;
        this.gl30.glUniform1fv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1i(int location, int x) {
        this.calls++;
        this.gl30.glUniform1i(location, x);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1iv(int location, int count, IntBuffer v) {
        this.calls++;
        this.gl30.glUniform1iv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1iv(int location, int count, int[] v, int offset) {
        this.calls++;
        this.gl30.glUniform1iv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2f(int location, float x, float y) {
        this.calls++;
        this.gl30.glUniform2f(location, x, y);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2fv(int location, int count, FloatBuffer v) {
        this.calls++;
        this.gl30.glUniform2fv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2fv(int location, int count, float[] v, int offset) {
        this.calls++;
        this.gl30.glUniform2fv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2i(int location, int x, int y) {
        this.calls++;
        this.gl30.glUniform2i(location, x, y);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2iv(int location, int count, IntBuffer v) {
        this.calls++;
        this.gl30.glUniform2iv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2iv(int location, int count, int[] v, int offset) {
        this.calls++;
        this.gl30.glUniform2iv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3f(int location, float x, float y, float z) {
        this.calls++;
        this.gl30.glUniform3f(location, x, y, z);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3fv(int location, int count, FloatBuffer v) {
        this.calls++;
        this.gl30.glUniform3fv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3fv(int location, int count, float[] v, int offset) {
        this.calls++;
        this.gl30.glUniform3fv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3i(int location, int x, int y, int z) {
        this.calls++;
        this.gl30.glUniform3i(location, x, y, z);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3iv(int location, int count, IntBuffer v) {
        this.calls++;
        this.gl30.glUniform3iv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3iv(int location, int count, int[] v, int offset) {
        this.calls++;
        this.gl30.glUniform3iv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4f(int location, float x, float y, float z, float w) {
        this.calls++;
        this.gl30.glUniform4f(location, x, y, z, w);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4fv(int location, int count, FloatBuffer v) {
        this.calls++;
        this.gl30.glUniform4fv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4fv(int location, int count, float[] v, int offset) {
        this.calls++;
        this.gl30.glUniform4fv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4i(int location, int x, int y, int z, int w) {
        this.calls++;
        this.gl30.glUniform4i(location, x, y, z, w);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4iv(int location, int count, IntBuffer v) {
        this.calls++;
        this.gl30.glUniform4iv(location, count, v);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4iv(int location, int count, int[] v, int offset) {
        this.calls++;
        this.gl30.glUniform4iv(location, count, v, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix2fv(int location, int count, boolean transpose, FloatBuffer value) {
        this.calls++;
        this.gl30.glUniformMatrix2fv(location, count, transpose, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix2fv(int location, int count, boolean transpose, float[] value, int offset) {
        this.calls++;
        this.gl30.glUniformMatrix2fv(location, count, transpose, value, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix3fv(int location, int count, boolean transpose, FloatBuffer value) {
        this.calls++;
        this.gl30.glUniformMatrix3fv(location, count, transpose, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix3fv(int location, int count, boolean transpose, float[] value, int offset) {
        this.calls++;
        this.gl30.glUniformMatrix3fv(location, count, transpose, value, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix4fv(int location, int count, boolean transpose, FloatBuffer value) {
        this.calls++;
        this.gl30.glUniformMatrix4fv(location, count, transpose, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix4fv(int location, int count, boolean transpose, float[] value, int offset) {
        this.calls++;
        this.gl30.glUniformMatrix4fv(location, count, transpose, value, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUseProgram(int program) {
        this.shaderSwitches++;
        this.calls++;
        this.gl30.glUseProgram(program);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glValidateProgram(int program) {
        this.calls++;
        this.gl30.glValidateProgram(program);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib1f(int indx, float x) {
        this.calls++;
        this.gl30.glVertexAttrib1f(indx, x);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib1fv(int indx, FloatBuffer values) {
        this.calls++;
        this.gl30.glVertexAttrib1fv(indx, values);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib2f(int indx, float x, float y) {
        this.calls++;
        this.gl30.glVertexAttrib2f(indx, x, y);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib2fv(int indx, FloatBuffer values) {
        this.calls++;
        this.gl30.glVertexAttrib2fv(indx, values);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib3f(int indx, float x, float y, float z) {
        this.calls++;
        this.gl30.glVertexAttrib3f(indx, x, y, z);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib3fv(int indx, FloatBuffer values) {
        this.calls++;
        this.gl30.glVertexAttrib3fv(indx, values);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib4f(int indx, float x, float y, float z, float w) {
        this.calls++;
        this.gl30.glVertexAttrib4f(indx, x, y, z, w);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib4fv(int indx, FloatBuffer values) {
        this.calls++;
        this.gl30.glVertexAttrib4fv(indx, values);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttribPointer(int indx, int size, int type, boolean normalized, int stride, Buffer ptr) {
        this.calls++;
        this.gl30.glVertexAttribPointer(indx, size, type, normalized, stride, ptr);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttribPointer(int indx, int size, int type, boolean normalized, int stride, int ptr) {
        this.calls++;
        this.gl30.glVertexAttribPointer(indx, size, type, normalized, stride, ptr);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glReadBuffer(int mode) {
        this.calls++;
        this.gl30.glReadBuffer(mode);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDrawRangeElements(int mode, int start, int end, int count, int type, Buffer indices) {
        this.vertexCount.put(count);
        this.drawCalls++;
        this.calls++;
        this.gl30.glDrawRangeElements(mode, start, end, count, type, indices);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDrawRangeElements(int mode, int start, int end, int count, int type, int offset) {
        this.vertexCount.put(count);
        this.drawCalls++;
        this.calls++;
        this.gl30.glDrawRangeElements(mode, start, end, count, type, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glTexImage3D(int target, int level, int internalformat, int width, int height, int depth, int border, int format, int type, Buffer pixels) {
        this.calls++;
        this.gl30.glTexImage3D(target, level, internalformat, width, height, depth, border, format, type, pixels);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glTexImage3D(int target, int level, int internalformat, int width, int height, int depth, int border, int format, int type, int offset) {
        this.calls++;
        this.gl30.glTexImage3D(target, level, internalformat, width, height, depth, border, format, type, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glTexSubImage3D(int target, int level, int xoffset, int yoffset, int zoffset, int width, int height, int depth, int format, int type, Buffer pixels) {
        this.calls++;
        this.gl30.glTexSubImage3D(target, level, xoffset, yoffset, zoffset, width, height, depth, format, type, pixels);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glTexSubImage3D(int target, int level, int xoffset, int yoffset, int zoffset, int width, int height, int depth, int format, int type, int offset) {
        this.calls++;
        this.gl30.glTexSubImage3D(target, level, xoffset, yoffset, zoffset, width, height, depth, format, type, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glCopyTexSubImage3D(int target, int level, int xoffset, int yoffset, int zoffset, int x, int y, int width, int height) {
        this.calls++;
        this.gl30.glCopyTexSubImage3D(target, level, xoffset, yoffset, zoffset, x, y, width, height);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenQueries(int n, int[] ids, int offset) {
        this.calls++;
        this.gl30.glGenQueries(n, ids, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenQueries(int n, IntBuffer ids) {
        this.calls++;
        this.gl30.glGenQueries(n, ids);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteQueries(int n, int[] ids, int offset) {
        this.calls++;
        this.gl30.glDeleteQueries(n, ids, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteQueries(int n, IntBuffer ids) {
        this.calls++;
        this.gl30.glDeleteQueries(n, ids);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public boolean glIsQuery(int id) {
        this.calls++;
        boolean result = this.gl30.glIsQuery(id);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBeginQuery(int target, int id) {
        this.calls++;
        this.gl30.glBeginQuery(target, id);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glEndQuery(int target) {
        this.calls++;
        this.gl30.glEndQuery(target);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetQueryiv(int target, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetQueryiv(target, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetQueryObjectuiv(int id, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetQueryObjectuiv(id, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public boolean glUnmapBuffer(int target) {
        this.calls++;
        boolean result = this.gl30.glUnmapBuffer(target);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public Buffer glGetBufferPointerv(int target, int pname) {
        this.calls++;
        Buffer result = this.gl30.glGetBufferPointerv(target, pname);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDrawBuffers(int n, IntBuffer bufs) {
        this.drawCalls++;
        this.calls++;
        this.gl30.glDrawBuffers(n, bufs);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniformMatrix2x3fv(int location, int count, boolean transpose, FloatBuffer value) {
        this.calls++;
        this.gl30.glUniformMatrix2x3fv(location, count, transpose, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniformMatrix3x2fv(int location, int count, boolean transpose, FloatBuffer value) {
        this.calls++;
        this.gl30.glUniformMatrix3x2fv(location, count, transpose, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniformMatrix2x4fv(int location, int count, boolean transpose, FloatBuffer value) {
        this.calls++;
        this.gl30.glUniformMatrix2x4fv(location, count, transpose, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniformMatrix4x2fv(int location, int count, boolean transpose, FloatBuffer value) {
        this.calls++;
        this.gl30.glUniformMatrix4x2fv(location, count, transpose, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniformMatrix3x4fv(int location, int count, boolean transpose, FloatBuffer value) {
        this.calls++;
        this.gl30.glUniformMatrix3x4fv(location, count, transpose, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniformMatrix4x3fv(int location, int count, boolean transpose, FloatBuffer value) {
        this.calls++;
        this.gl30.glUniformMatrix4x3fv(location, count, transpose, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBlitFramebuffer(int srcX0, int srcY0, int srcX1, int srcY1, int dstX0, int dstY0, int dstX1, int dstY1, int mask, int filter) {
        this.calls++;
        this.gl30.glBlitFramebuffer(srcX0, srcY0, srcX1, srcY1, dstX0, dstY0, dstX1, dstY1, mask, filter);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glRenderbufferStorageMultisample(int target, int samples, int internalformat, int width, int height) {
        this.calls++;
        this.gl30.glRenderbufferStorageMultisample(target, samples, internalformat, width, height);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glFramebufferTextureLayer(int target, int attachment, int texture, int level, int layer) {
        this.calls++;
        this.gl30.glFramebufferTextureLayer(target, attachment, texture, level, layer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public Buffer glMapBufferRange(int target, int offset, int length, int access) {
        this.calls++;
        Buffer result = this.gl30.glMapBufferRange(target, offset, length, access);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glFlushMappedBufferRange(int target, int offset, int length) {
        this.calls++;
        this.gl30.glFlushMappedBufferRange(target, offset, length);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBindVertexArray(int array) {
        this.calls++;
        this.gl30.glBindVertexArray(array);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteVertexArrays(int n, int[] arrays, int offset) {
        this.calls++;
        this.gl30.glDeleteVertexArrays(n, arrays, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteVertexArrays(int n, IntBuffer arrays) {
        this.calls++;
        this.gl30.glDeleteVertexArrays(n, arrays);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenVertexArrays(int n, int[] arrays, int offset) {
        this.calls++;
        this.gl30.glGenVertexArrays(n, arrays, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenVertexArrays(int n, IntBuffer arrays) {
        this.calls++;
        this.gl30.glGenVertexArrays(n, arrays);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public boolean glIsVertexArray(int array) {
        this.calls++;
        boolean result = this.gl30.glIsVertexArray(array);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBeginTransformFeedback(int primitiveMode) {
        this.calls++;
        this.gl30.glBeginTransformFeedback(primitiveMode);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glEndTransformFeedback() {
        this.calls++;
        this.gl30.glEndTransformFeedback();
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBindBufferRange(int target, int index, int buffer, int offset, int size) {
        this.calls++;
        this.gl30.glBindBufferRange(target, index, buffer, offset, size);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBindBufferBase(int target, int index, int buffer) {
        this.calls++;
        this.gl30.glBindBufferBase(target, index, buffer);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glTransformFeedbackVaryings(int program, String[] varyings, int bufferMode) {
        this.calls++;
        this.gl30.glTransformFeedbackVaryings(program, varyings, bufferMode);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glVertexAttribIPointer(int index, int size, int type, int stride, int offset) {
        this.calls++;
        this.gl30.glVertexAttribIPointer(index, size, type, stride, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetVertexAttribIiv(int index, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetVertexAttribIiv(index, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetVertexAttribIuiv(int index, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetVertexAttribIuiv(index, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glVertexAttribI4i(int index, int x, int y, int z, int w) {
        this.calls++;
        this.gl30.glVertexAttribI4i(index, x, y, z, w);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glVertexAttribI4ui(int index, int x, int y, int z, int w) {
        this.calls++;
        this.gl30.glVertexAttribI4ui(index, x, y, z, w);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetUniformuiv(int program, int location, IntBuffer params) {
        this.calls++;
        this.gl30.glGetUniformuiv(program, location, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public int glGetFragDataLocation(int program, String name) {
        this.calls++;
        int result = this.gl30.glGetFragDataLocation(program, name);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniform1uiv(int location, int count, IntBuffer value) {
        this.calls++;
        this.gl30.glUniform1uiv(location, count, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniform3uiv(int location, int count, IntBuffer value) {
        this.calls++;
        this.gl30.glUniform3uiv(location, count, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniform4uiv(int location, int count, IntBuffer value) {
        this.calls++;
        this.gl30.glUniform4uiv(location, count, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glClearBufferiv(int buffer, int drawbuffer, IntBuffer value) {
        this.calls++;
        this.gl30.glClearBufferiv(buffer, drawbuffer, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glClearBufferuiv(int buffer, int drawbuffer, IntBuffer value) {
        this.calls++;
        this.gl30.glClearBufferuiv(buffer, drawbuffer, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glClearBufferfv(int buffer, int drawbuffer, FloatBuffer value) {
        this.calls++;
        this.gl30.glClearBufferfv(buffer, drawbuffer, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glClearBufferfi(int buffer, int drawbuffer, float depth, int stencil) {
        this.calls++;
        this.gl30.glClearBufferfi(buffer, drawbuffer, depth, stencil);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public String glGetStringi(int name, int index) {
        this.calls++;
        String result = this.gl30.glGetStringi(name, index);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glCopyBufferSubData(int readTarget, int writeTarget, int readOffset, int writeOffset, int size) {
        this.calls++;
        this.gl30.glCopyBufferSubData(readTarget, writeTarget, readOffset, writeOffset, size);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetUniformIndices(int program, String[] uniformNames, IntBuffer uniformIndices) {
        this.calls++;
        this.gl30.glGetUniformIndices(program, uniformNames, uniformIndices);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetActiveUniformsiv(int program, int uniformCount, IntBuffer uniformIndices, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetActiveUniformsiv(program, uniformCount, uniformIndices, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public int glGetUniformBlockIndex(int program, String uniformBlockName) {
        this.calls++;
        int result = this.gl30.glGetUniformBlockIndex(program, uniformBlockName);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetActiveUniformBlockiv(int program, int uniformBlockIndex, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetActiveUniformBlockiv(program, uniformBlockIndex, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetActiveUniformBlockName(int program, int uniformBlockIndex, Buffer length, Buffer uniformBlockName) {
        this.calls++;
        this.gl30.glGetActiveUniformBlockName(program, uniformBlockIndex, length, uniformBlockName);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public String glGetActiveUniformBlockName(int program, int uniformBlockIndex) {
        this.calls++;
        String result = this.gl30.glGetActiveUniformBlockName(program, uniformBlockIndex);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniformBlockBinding(int program, int uniformBlockIndex, int uniformBlockBinding) {
        this.calls++;
        this.gl30.glUniformBlockBinding(program, uniformBlockIndex, uniformBlockBinding);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDrawArraysInstanced(int mode, int first, int count, int instanceCount) {
        this.vertexCount.put(count);
        this.drawCalls++;
        this.calls++;
        this.gl30.glDrawArraysInstanced(mode, first, count, instanceCount);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDrawElementsInstanced(int mode, int count, int type, int indicesOffset, int instanceCount) {
        this.vertexCount.put(count);
        this.drawCalls++;
        this.calls++;
        this.gl30.glDrawElementsInstanced(mode, count, type, indicesOffset, instanceCount);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetInteger64v(int pname, LongBuffer params) {
        this.calls++;
        this.gl30.glGetInteger64v(pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetBufferParameteri64v(int target, int pname, LongBuffer params) {
        this.calls++;
        this.gl30.glGetBufferParameteri64v(target, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenSamplers(int count, int[] samplers, int offset) {
        this.calls++;
        this.gl30.glGenSamplers(count, samplers, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenSamplers(int count, IntBuffer samplers) {
        this.calls++;
        this.gl30.glGenSamplers(count, samplers);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteSamplers(int count, int[] samplers, int offset) {
        this.calls++;
        this.gl30.glDeleteSamplers(count, samplers, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteSamplers(int count, IntBuffer samplers) {
        this.calls++;
        this.gl30.glDeleteSamplers(count, samplers);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public boolean glIsSampler(int sampler) {
        this.calls++;
        boolean result = this.gl30.glIsSampler(sampler);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBindSampler(int unit, int sampler) {
        this.calls++;
        this.gl30.glBindSampler(unit, sampler);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glSamplerParameteri(int sampler, int pname, int param) {
        this.calls++;
        this.gl30.glSamplerParameteri(sampler, pname, param);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glSamplerParameteriv(int sampler, int pname, IntBuffer param) {
        this.calls++;
        this.gl30.glSamplerParameteriv(sampler, pname, param);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glSamplerParameterf(int sampler, int pname, float param) {
        this.calls++;
        this.gl30.glSamplerParameterf(sampler, pname, param);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glSamplerParameterfv(int sampler, int pname, FloatBuffer param) {
        this.calls++;
        this.gl30.glSamplerParameterfv(sampler, pname, param);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetSamplerParameteriv(int sampler, int pname, IntBuffer params) {
        this.calls++;
        this.gl30.glGetSamplerParameteriv(sampler, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetSamplerParameterfv(int sampler, int pname, FloatBuffer params) {
        this.calls++;
        this.gl30.glGetSamplerParameterfv(sampler, pname, params);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glVertexAttribDivisor(int index, int divisor) {
        this.calls++;
        this.gl30.glVertexAttribDivisor(index, divisor);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBindTransformFeedback(int target, int id) {
        this.calls++;
        this.gl30.glBindTransformFeedback(target, id);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteTransformFeedbacks(int n, int[] ids, int offset) {
        this.calls++;
        this.gl30.glDeleteTransformFeedbacks(n, ids, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteTransformFeedbacks(int n, IntBuffer ids) {
        this.calls++;
        this.gl30.glDeleteTransformFeedbacks(n, ids);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenTransformFeedbacks(int n, int[] ids, int offset) {
        this.calls++;
        this.gl30.glGenTransformFeedbacks(n, ids, offset);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenTransformFeedbacks(int n, IntBuffer ids) {
        this.calls++;
        this.gl30.glGenTransformFeedbacks(n, ids);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public boolean glIsTransformFeedback(int id) {
        this.calls++;
        boolean result = this.gl30.glIsTransformFeedback(id);
        check();
        return result;
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glPauseTransformFeedback() {
        this.calls++;
        this.gl30.glPauseTransformFeedback();
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glResumeTransformFeedback() {
        this.calls++;
        this.gl30.glResumeTransformFeedback();
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glProgramParameteri(int program, int pname, int value) {
        this.calls++;
        this.gl30.glProgramParameteri(program, pname, value);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glInvalidateFramebuffer(int target, int numAttachments, IntBuffer attachments) {
        this.calls++;
        this.gl30.glInvalidateFramebuffer(target, numAttachments, attachments);
        check();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glInvalidateSubFramebuffer(int target, int numAttachments, IntBuffer attachments, int x, int y, int width, int height) {
        this.calls++;
        this.gl30.glInvalidateSubFramebuffer(target, numAttachments, attachments, x, y, width, height);
        check();
    }
}