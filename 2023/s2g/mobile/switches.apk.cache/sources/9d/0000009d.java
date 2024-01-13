package com.badlogic.gdx.backends.android;

import android.opengl.GLES20;
import com.badlogic.gdx.graphics.GL20;
import java.nio.Buffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;

/* loaded from: classes.dex */
public class AndroidGL20 implements GL20 {
    private int[] ints = new int[1];
    private int[] ints2 = new int[1];
    private int[] ints3 = new int[1];
    private byte[] buffer = new byte[512];

    @Override // com.badlogic.gdx.graphics.GL20
    public void glActiveTexture(int texture) {
        GLES20.glActiveTexture(texture);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glAttachShader(int program, int shader) {
        GLES20.glAttachShader(program, shader);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindAttribLocation(int program, int index, String name) {
        GLES20.glBindAttribLocation(program, index, name);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindBuffer(int target, int buffer) {
        GLES20.glBindBuffer(target, buffer);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindFramebuffer(int target, int framebuffer) {
        GLES20.glBindFramebuffer(target, framebuffer);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindRenderbuffer(int target, int renderbuffer) {
        GLES20.glBindRenderbuffer(target, renderbuffer);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBindTexture(int target, int texture) {
        GLES20.glBindTexture(target, texture);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendColor(float red, float green, float blue, float alpha) {
        GLES20.glBlendColor(red, green, blue, alpha);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendEquation(int mode) {
        GLES20.glBlendEquation(mode);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendEquationSeparate(int modeRGB, int modeAlpha) {
        GLES20.glBlendEquationSeparate(modeRGB, modeAlpha);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendFunc(int sfactor, int dfactor) {
        GLES20.glBlendFunc(sfactor, dfactor);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBlendFuncSeparate(int srcRGB, int dstRGB, int srcAlpha, int dstAlpha) {
        GLES20.glBlendFuncSeparate(srcRGB, dstRGB, srcAlpha, dstAlpha);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBufferData(int target, int size, Buffer data, int usage) {
        GLES20.glBufferData(target, size, data, usage);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glBufferSubData(int target, int offset, int size, Buffer data) {
        GLES20.glBufferSubData(target, offset, size, data);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glCheckFramebufferStatus(int target) {
        return GLES20.glCheckFramebufferStatus(target);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glClear(int mask) {
        GLES20.glClear(mask);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glClearColor(float red, float green, float blue, float alpha) {
        GLES20.glClearColor(red, green, blue, alpha);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glClearDepthf(float depth) {
        GLES20.glClearDepthf(depth);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glClearStencil(int s) {
        GLES20.glClearStencil(s);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glColorMask(boolean red, boolean green, boolean blue, boolean alpha) {
        GLES20.glColorMask(red, green, blue, alpha);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCompileShader(int shader) {
        GLES20.glCompileShader(shader);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCompressedTexImage2D(int target, int level, int internalformat, int width, int height, int border, int imageSize, Buffer data) {
        GLES20.glCompressedTexImage2D(target, level, internalformat, width, height, border, imageSize, data);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCompressedTexSubImage2D(int target, int level, int xoffset, int yoffset, int width, int height, int format, int imageSize, Buffer data) {
        GLES20.glCompressedTexSubImage2D(target, level, xoffset, yoffset, width, height, format, imageSize, data);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCopyTexImage2D(int target, int level, int internalformat, int x, int y, int width, int height, int border) {
        GLES20.glCopyTexImage2D(target, level, internalformat, x, y, width, height, border);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCopyTexSubImage2D(int target, int level, int xoffset, int yoffset, int x, int y, int width, int height) {
        GLES20.glCopyTexSubImage2D(target, level, xoffset, yoffset, x, y, width, height);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glCreateProgram() {
        return GLES20.glCreateProgram();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glCreateShader(int type) {
        return GLES20.glCreateShader(type);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glCullFace(int mode) {
        GLES20.glCullFace(mode);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteBuffers(int n, IntBuffer buffers) {
        GLES20.glDeleteBuffers(n, buffers);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteBuffer(int buffer) {
        int[] iArr = this.ints;
        iArr[0] = buffer;
        GLES20.glDeleteBuffers(1, iArr, 0);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteFramebuffers(int n, IntBuffer framebuffers) {
        GLES20.glDeleteFramebuffers(n, framebuffers);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteFramebuffer(int framebuffer) {
        int[] iArr = this.ints;
        iArr[0] = framebuffer;
        GLES20.glDeleteFramebuffers(1, iArr, 0);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteProgram(int program) {
        GLES20.glDeleteProgram(program);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteRenderbuffers(int n, IntBuffer renderbuffers) {
        GLES20.glDeleteRenderbuffers(n, renderbuffers);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteRenderbuffer(int renderbuffer) {
        int[] iArr = this.ints;
        iArr[0] = renderbuffer;
        GLES20.glDeleteRenderbuffers(1, iArr, 0);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteShader(int shader) {
        GLES20.glDeleteShader(shader);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteTextures(int n, IntBuffer textures) {
        GLES20.glDeleteTextures(n, textures);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDeleteTexture(int texture) {
        int[] iArr = this.ints;
        iArr[0] = texture;
        GLES20.glDeleteTextures(1, iArr, 0);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDepthFunc(int func) {
        GLES20.glDepthFunc(func);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDepthMask(boolean flag) {
        GLES20.glDepthMask(flag);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDepthRangef(float zNear, float zFar) {
        GLES20.glDepthRangef(zNear, zFar);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDetachShader(int program, int shader) {
        GLES20.glDetachShader(program, shader);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDisable(int cap) {
        GLES20.glDisable(cap);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDisableVertexAttribArray(int index) {
        GLES20.glDisableVertexAttribArray(index);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDrawArrays(int mode, int first, int count) {
        GLES20.glDrawArrays(mode, first, count);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDrawElements(int mode, int count, int type, Buffer indices) {
        GLES20.glDrawElements(mode, count, type, indices);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glDrawElements(int mode, int count, int type, int indices) {
        GLES20.glDrawElements(mode, count, type, indices);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glEnable(int cap) {
        GLES20.glEnable(cap);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glEnableVertexAttribArray(int index) {
        GLES20.glEnableVertexAttribArray(index);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFinish() {
        GLES20.glFinish();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFlush() {
        GLES20.glFlush();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFramebufferRenderbuffer(int target, int attachment, int renderbuffertarget, int renderbuffer) {
        GLES20.glFramebufferRenderbuffer(target, attachment, renderbuffertarget, renderbuffer);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFramebufferTexture2D(int target, int attachment, int textarget, int texture, int level) {
        GLES20.glFramebufferTexture2D(target, attachment, textarget, texture, level);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glFrontFace(int mode) {
        GLES20.glFrontFace(mode);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenBuffers(int n, IntBuffer buffers) {
        GLES20.glGenBuffers(n, buffers);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGenBuffer() {
        GLES20.glGenBuffers(1, this.ints, 0);
        return this.ints[0];
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenerateMipmap(int target) {
        GLES20.glGenerateMipmap(target);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenFramebuffers(int n, IntBuffer framebuffers) {
        GLES20.glGenFramebuffers(n, framebuffers);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGenFramebuffer() {
        GLES20.glGenFramebuffers(1, this.ints, 0);
        return this.ints[0];
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenRenderbuffers(int n, IntBuffer renderbuffers) {
        GLES20.glGenRenderbuffers(n, renderbuffers);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGenRenderbuffer() {
        GLES20.glGenRenderbuffers(1, this.ints, 0);
        return this.ints[0];
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGenTextures(int n, IntBuffer textures) {
        GLES20.glGenTextures(n, textures);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGenTexture() {
        GLES20.glGenTextures(1, this.ints, 0);
        return this.ints[0];
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetActiveAttrib(int program, int index, IntBuffer size, IntBuffer type) {
        byte[] bArr = this.buffer;
        GLES20.glGetActiveAttrib(program, index, bArr.length, this.ints, 0, this.ints2, 0, this.ints3, 0, bArr, 0);
        size.put(this.ints2[0]);
        type.put(this.ints3[0]);
        return new String(this.buffer, 0, this.ints[0]);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetActiveUniform(int program, int index, IntBuffer size, IntBuffer type) {
        byte[] bArr = this.buffer;
        GLES20.glGetActiveUniform(program, index, bArr.length, this.ints, 0, this.ints2, 0, this.ints3, 0, bArr, 0);
        size.put(this.ints2[0]);
        type.put(this.ints3[0]);
        return new String(this.buffer, 0, this.ints[0]);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetAttachedShaders(int program, int maxcount, Buffer count, IntBuffer shaders) {
        GLES20.glGetAttachedShaders(program, maxcount, (IntBuffer) count, shaders);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGetAttribLocation(int program, String name) {
        return GLES20.glGetAttribLocation(program, name);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetBooleanv(int pname, Buffer params) {
        GLES20.glGetBooleanv(pname, (IntBuffer) params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetBufferParameteriv(int target, int pname, IntBuffer params) {
        GLES20.glGetBufferParameteriv(target, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGetError() {
        return GLES20.glGetError();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetFloatv(int pname, FloatBuffer params) {
        GLES20.glGetFloatv(pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetFramebufferAttachmentParameteriv(int target, int attachment, int pname, IntBuffer params) {
        GLES20.glGetFramebufferAttachmentParameteriv(target, attachment, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetIntegerv(int pname, IntBuffer params) {
        GLES20.glGetIntegerv(pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetProgramiv(int program, int pname, IntBuffer params) {
        GLES20.glGetProgramiv(program, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetProgramInfoLog(int program) {
        return GLES20.glGetProgramInfoLog(program);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetRenderbufferParameteriv(int target, int pname, IntBuffer params) {
        GLES20.glGetRenderbufferParameteriv(target, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetShaderiv(int shader, int pname, IntBuffer params) {
        GLES20.glGetShaderiv(shader, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetShaderInfoLog(int shader) {
        return GLES20.glGetShaderInfoLog(shader);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetShaderPrecisionFormat(int shadertype, int precisiontype, IntBuffer range, IntBuffer precision) {
        GLES20.glGetShaderPrecisionFormat(shadertype, precisiontype, range, precision);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public String glGetString(int name) {
        return GLES20.glGetString(name);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetTexParameterfv(int target, int pname, FloatBuffer params) {
        GLES20.glGetTexParameterfv(target, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetTexParameteriv(int target, int pname, IntBuffer params) {
        GLES20.glGetTexParameteriv(target, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetUniformfv(int program, int location, FloatBuffer params) {
        GLES20.glGetUniformfv(program, location, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetUniformiv(int program, int location, IntBuffer params) {
        GLES20.glGetUniformiv(program, location, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public int glGetUniformLocation(int program, String name) {
        return GLES20.glGetUniformLocation(program, name);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetVertexAttribfv(int index, int pname, FloatBuffer params) {
        GLES20.glGetVertexAttribfv(index, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetVertexAttribiv(int index, int pname, IntBuffer params) {
        GLES20.glGetVertexAttribiv(index, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glGetVertexAttribPointerv(int index, int pname, Buffer pointer) {
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glHint(int target, int mode) {
        GLES20.glHint(target, mode);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsBuffer(int buffer) {
        return GLES20.glIsBuffer(buffer);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsEnabled(int cap) {
        return GLES20.glIsEnabled(cap);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsFramebuffer(int framebuffer) {
        return GLES20.glIsFramebuffer(framebuffer);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsProgram(int program) {
        return GLES20.glIsProgram(program);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsRenderbuffer(int renderbuffer) {
        return GLES20.glIsRenderbuffer(renderbuffer);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsShader(int shader) {
        return GLES20.glIsShader(shader);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public boolean glIsTexture(int texture) {
        return GLES20.glIsTexture(texture);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glLineWidth(float width) {
        GLES20.glLineWidth(width);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glLinkProgram(int program) {
        GLES20.glLinkProgram(program);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glPixelStorei(int pname, int param) {
        GLES20.glPixelStorei(pname, param);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glPolygonOffset(float factor, float units) {
        GLES20.glPolygonOffset(factor, units);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glReadPixels(int x, int y, int width, int height, int format, int type, Buffer pixels) {
        GLES20.glReadPixels(x, y, width, height, format, type, pixels);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glReleaseShaderCompiler() {
        GLES20.glReleaseShaderCompiler();
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glRenderbufferStorage(int target, int internalformat, int width, int height) {
        GLES20.glRenderbufferStorage(target, internalformat, width, height);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glSampleCoverage(float value, boolean invert) {
        GLES20.glSampleCoverage(value, invert);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glScissor(int x, int y, int width, int height) {
        GLES20.glScissor(x, y, width, height);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glShaderBinary(int n, IntBuffer shaders, int binaryformat, Buffer binary, int length) {
        GLES20.glShaderBinary(n, shaders, binaryformat, binary, length);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glShaderSource(int shader, String string) {
        GLES20.glShaderSource(shader, string);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilFunc(int func, int ref, int mask) {
        GLES20.glStencilFunc(func, ref, mask);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilFuncSeparate(int face, int func, int ref, int mask) {
        GLES20.glStencilFuncSeparate(face, func, ref, mask);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilMask(int mask) {
        GLES20.glStencilMask(mask);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilMaskSeparate(int face, int mask) {
        GLES20.glStencilMaskSeparate(face, mask);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilOp(int fail, int zfail, int zpass) {
        GLES20.glStencilOp(fail, zfail, zpass);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glStencilOpSeparate(int face, int fail, int zfail, int zpass) {
        GLES20.glStencilOpSeparate(face, fail, zfail, zpass);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexImage2D(int target, int level, int internalformat, int width, int height, int border, int format, int type, Buffer pixels) {
        GLES20.glTexImage2D(target, level, internalformat, width, height, border, format, type, pixels);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexParameterf(int target, int pname, float param) {
        GLES20.glTexParameterf(target, pname, param);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexParameterfv(int target, int pname, FloatBuffer params) {
        GLES20.glTexParameterfv(target, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexParameteri(int target, int pname, int param) {
        GLES20.glTexParameteri(target, pname, param);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexParameteriv(int target, int pname, IntBuffer params) {
        GLES20.glTexParameteriv(target, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glTexSubImage2D(int target, int level, int xoffset, int yoffset, int width, int height, int format, int type, Buffer pixels) {
        GLES20.glTexSubImage2D(target, level, xoffset, yoffset, width, height, format, type, pixels);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1f(int location, float x) {
        GLES20.glUniform1f(location, x);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1fv(int location, int count, FloatBuffer v) {
        GLES20.glUniform1fv(location, count, v);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1fv(int location, int count, float[] v, int offset) {
        GLES20.glUniform1fv(location, count, v, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1i(int location, int x) {
        GLES20.glUniform1i(location, x);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1iv(int location, int count, IntBuffer v) {
        GLES20.glUniform1iv(location, count, v);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform1iv(int location, int count, int[] v, int offset) {
        GLES20.glUniform1iv(location, count, v, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2f(int location, float x, float y) {
        GLES20.glUniform2f(location, x, y);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2fv(int location, int count, FloatBuffer v) {
        GLES20.glUniform2fv(location, count, v);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2fv(int location, int count, float[] v, int offset) {
        GLES20.glUniform2fv(location, count, v, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2i(int location, int x, int y) {
        GLES20.glUniform2i(location, x, y);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2iv(int location, int count, IntBuffer v) {
        GLES20.glUniform2iv(location, count, v);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform2iv(int location, int count, int[] v, int offset) {
        GLES20.glUniform2iv(location, count, v, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3f(int location, float x, float y, float z) {
        GLES20.glUniform3f(location, x, y, z);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3fv(int location, int count, FloatBuffer v) {
        GLES20.glUniform3fv(location, count, v);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3fv(int location, int count, float[] v, int offset) {
        GLES20.glUniform3fv(location, count, v, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3i(int location, int x, int y, int z) {
        GLES20.glUniform3i(location, x, y, z);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3iv(int location, int count, IntBuffer v) {
        GLES20.glUniform3iv(location, count, v);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform3iv(int location, int count, int[] v, int offset) {
        GLES20.glUniform3iv(location, count, v, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4f(int location, float x, float y, float z, float w) {
        GLES20.glUniform4f(location, x, y, z, w);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4fv(int location, int count, FloatBuffer v) {
        GLES20.glUniform4fv(location, count, v);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4fv(int location, int count, float[] v, int offset) {
        GLES20.glUniform4fv(location, count, v, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4i(int location, int x, int y, int z, int w) {
        GLES20.glUniform4i(location, x, y, z, w);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4iv(int location, int count, IntBuffer v) {
        GLES20.glUniform4iv(location, count, v);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniform4iv(int location, int count, int[] v, int offset) {
        GLES20.glUniform4iv(location, count, v, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix2fv(int location, int count, boolean transpose, FloatBuffer value) {
        GLES20.glUniformMatrix2fv(location, count, transpose, value);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix2fv(int location, int count, boolean transpose, float[] value, int offset) {
        GLES20.glUniformMatrix2fv(location, count, transpose, value, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix3fv(int location, int count, boolean transpose, FloatBuffer value) {
        GLES20.glUniformMatrix3fv(location, count, transpose, value);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix3fv(int location, int count, boolean transpose, float[] value, int offset) {
        GLES20.glUniformMatrix3fv(location, count, transpose, value, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix4fv(int location, int count, boolean transpose, FloatBuffer value) {
        GLES20.glUniformMatrix4fv(location, count, transpose, value);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUniformMatrix4fv(int location, int count, boolean transpose, float[] value, int offset) {
        GLES20.glUniformMatrix4fv(location, count, transpose, value, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glUseProgram(int program) {
        GLES20.glUseProgram(program);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glValidateProgram(int program) {
        GLES20.glValidateProgram(program);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib1f(int indx, float x) {
        GLES20.glVertexAttrib1f(indx, x);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib1fv(int indx, FloatBuffer values) {
        GLES20.glVertexAttrib1fv(indx, values);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib2f(int indx, float x, float y) {
        GLES20.glVertexAttrib2f(indx, x, y);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib2fv(int indx, FloatBuffer values) {
        GLES20.glVertexAttrib2fv(indx, values);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib3f(int indx, float x, float y, float z) {
        GLES20.glVertexAttrib3f(indx, x, y, z);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib3fv(int indx, FloatBuffer values) {
        GLES20.glVertexAttrib3fv(indx, values);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib4f(int indx, float x, float y, float z, float w) {
        GLES20.glVertexAttrib4f(indx, x, y, z, w);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttrib4fv(int indx, FloatBuffer values) {
        GLES20.glVertexAttrib4fv(indx, values);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttribPointer(int indx, int size, int type, boolean normalized, int stride, Buffer ptr) {
        GLES20.glVertexAttribPointer(indx, size, type, normalized, stride, ptr);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glVertexAttribPointer(int indx, int size, int type, boolean normalized, int stride, int ptr) {
        GLES20.glVertexAttribPointer(indx, size, type, normalized, stride, ptr);
    }

    @Override // com.badlogic.gdx.graphics.GL20
    public void glViewport(int x, int y, int width, int height) {
        GLES20.glViewport(x, y, width, height);
    }
}