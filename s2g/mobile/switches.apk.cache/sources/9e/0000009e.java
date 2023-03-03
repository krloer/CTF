package com.badlogic.gdx.backends.android;

import android.opengl.GLES30;
import com.badlogic.gdx.graphics.GL30;
import java.nio.Buffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;

/* loaded from: classes.dex */
public class AndroidGL30 extends AndroidGL20 implements GL30 {
    @Override // com.badlogic.gdx.graphics.GL30
    public void glReadBuffer(int mode) {
        GLES30.glReadBuffer(mode);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDrawRangeElements(int mode, int start, int end, int count, int type, Buffer indices) {
        GLES30.glDrawRangeElements(mode, start, end, count, type, indices);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDrawRangeElements(int mode, int start, int end, int count, int type, int offset) {
        GLES30.glDrawRangeElements(mode, start, end, count, type, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glTexImage3D(int target, int level, int internalformat, int width, int height, int depth, int border, int format, int type, Buffer pixels) {
        if (pixels != null) {
            GLES30.glTexImage3D(target, level, internalformat, width, height, depth, border, format, type, pixels);
        } else {
            GLES30.glTexImage3D(target, level, internalformat, width, height, depth, border, format, type, 0);
        }
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glTexImage3D(int target, int level, int internalformat, int width, int height, int depth, int border, int format, int type, int offset) {
        GLES30.glTexImage3D(target, level, internalformat, width, height, depth, border, format, type, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glTexSubImage3D(int target, int level, int xoffset, int yoffset, int zoffset, int width, int height, int depth, int format, int type, Buffer pixels) {
        GLES30.glTexSubImage3D(target, level, xoffset, yoffset, zoffset, width, height, depth, format, type, pixels);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glTexSubImage3D(int target, int level, int xoffset, int yoffset, int zoffset, int width, int height, int depth, int format, int type, int offset) {
        GLES30.glTexSubImage3D(target, level, xoffset, yoffset, zoffset, width, height, depth, format, type, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glCopyTexSubImage3D(int target, int level, int xoffset, int yoffset, int zoffset, int x, int y, int width, int height) {
        GLES30.glCopyTexSubImage3D(target, level, xoffset, yoffset, zoffset, x, y, width, height);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenQueries(int n, int[] ids, int offset) {
        GLES30.glGenQueries(n, ids, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenQueries(int n, IntBuffer ids) {
        GLES30.glGenQueries(n, ids);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteQueries(int n, int[] ids, int offset) {
        GLES30.glDeleteQueries(n, ids, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteQueries(int n, IntBuffer ids) {
        GLES30.glDeleteQueries(n, ids);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public boolean glIsQuery(int id) {
        return GLES30.glIsQuery(id);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBeginQuery(int target, int id) {
        GLES30.glBeginQuery(target, id);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glEndQuery(int target) {
        GLES30.glEndQuery(target);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetQueryiv(int target, int pname, IntBuffer params) {
        GLES30.glGetQueryiv(target, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetQueryObjectuiv(int id, int pname, IntBuffer params) {
        GLES30.glGetQueryObjectuiv(id, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public boolean glUnmapBuffer(int target) {
        return GLES30.glUnmapBuffer(target);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public Buffer glGetBufferPointerv(int target, int pname) {
        return GLES30.glGetBufferPointerv(target, pname);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDrawBuffers(int n, IntBuffer bufs) {
        GLES30.glDrawBuffers(n, bufs);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniformMatrix2x3fv(int location, int count, boolean transpose, FloatBuffer value) {
        GLES30.glUniformMatrix2x3fv(location, count, transpose, value);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniformMatrix3x2fv(int location, int count, boolean transpose, FloatBuffer value) {
        GLES30.glUniformMatrix3x2fv(location, count, transpose, value);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniformMatrix2x4fv(int location, int count, boolean transpose, FloatBuffer value) {
        GLES30.glUniformMatrix2x4fv(location, count, transpose, value);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniformMatrix4x2fv(int location, int count, boolean transpose, FloatBuffer value) {
        GLES30.glUniformMatrix4x2fv(location, count, transpose, value);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniformMatrix3x4fv(int location, int count, boolean transpose, FloatBuffer value) {
        GLES30.glUniformMatrix3x4fv(location, count, transpose, value);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniformMatrix4x3fv(int location, int count, boolean transpose, FloatBuffer value) {
        GLES30.glUniformMatrix4x3fv(location, count, transpose, value);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBlitFramebuffer(int srcX0, int srcY0, int srcX1, int srcY1, int dstX0, int dstY0, int dstX1, int dstY1, int mask, int filter) {
        GLES30.glBlitFramebuffer(srcX0, srcY0, srcX1, srcY1, dstX0, dstY0, dstX1, dstY1, mask, filter);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glRenderbufferStorageMultisample(int target, int samples, int internalformat, int width, int height) {
        GLES30.glRenderbufferStorageMultisample(target, samples, internalformat, width, height);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glFramebufferTextureLayer(int target, int attachment, int texture, int level, int layer) {
        GLES30.glFramebufferTextureLayer(target, attachment, texture, level, layer);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public Buffer glMapBufferRange(int target, int offset, int length, int access) {
        return GLES30.glMapBufferRange(target, offset, length, access);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glFlushMappedBufferRange(int target, int offset, int length) {
        GLES30.glFlushMappedBufferRange(target, offset, length);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBindVertexArray(int array) {
        GLES30.glBindVertexArray(array);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteVertexArrays(int n, int[] arrays, int offset) {
        GLES30.glDeleteVertexArrays(n, arrays, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteVertexArrays(int n, IntBuffer arrays) {
        GLES30.glDeleteVertexArrays(n, arrays);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenVertexArrays(int n, int[] arrays, int offset) {
        GLES30.glGenVertexArrays(n, arrays, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenVertexArrays(int n, IntBuffer arrays) {
        GLES30.glGenVertexArrays(n, arrays);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public boolean glIsVertexArray(int array) {
        return GLES30.glIsVertexArray(array);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBeginTransformFeedback(int primitiveMode) {
        GLES30.glBeginTransformFeedback(primitiveMode);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glEndTransformFeedback() {
        GLES30.glEndTransformFeedback();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBindBufferRange(int target, int index, int buffer, int offset, int size) {
        GLES30.glBindBufferRange(target, index, buffer, offset, size);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBindBufferBase(int target, int index, int buffer) {
        GLES30.glBindBufferBase(target, index, buffer);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glTransformFeedbackVaryings(int program, String[] varyings, int bufferMode) {
        GLES30.glTransformFeedbackVaryings(program, varyings, bufferMode);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glVertexAttribIPointer(int index, int size, int type, int stride, int offset) {
        GLES30.glVertexAttribIPointer(index, size, type, stride, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetVertexAttribIiv(int index, int pname, IntBuffer params) {
        GLES30.glGetVertexAttribIiv(index, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetVertexAttribIuiv(int index, int pname, IntBuffer params) {
        GLES30.glGetVertexAttribIuiv(index, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glVertexAttribI4i(int index, int x, int y, int z, int w) {
        GLES30.glVertexAttribI4i(index, x, y, z, w);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glVertexAttribI4ui(int index, int x, int y, int z, int w) {
        GLES30.glVertexAttribI4ui(index, x, y, z, w);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetUniformuiv(int program, int location, IntBuffer params) {
        GLES30.glGetUniformuiv(program, location, params);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public int glGetFragDataLocation(int program, String name) {
        return GLES30.glGetFragDataLocation(program, name);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniform1uiv(int location, int count, IntBuffer value) {
        GLES30.glUniform1uiv(location, count, value);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniform3uiv(int location, int count, IntBuffer value) {
        GLES30.glUniform3uiv(location, count, value);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniform4uiv(int location, int count, IntBuffer value) {
        GLES30.glUniform4uiv(location, count, value);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glClearBufferiv(int buffer, int drawbuffer, IntBuffer value) {
        GLES30.glClearBufferiv(buffer, drawbuffer, value);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glClearBufferuiv(int buffer, int drawbuffer, IntBuffer value) {
        GLES30.glClearBufferuiv(buffer, drawbuffer, value);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glClearBufferfv(int buffer, int drawbuffer, FloatBuffer value) {
        GLES30.glClearBufferfv(buffer, drawbuffer, value);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glClearBufferfi(int buffer, int drawbuffer, float depth, int stencil) {
        GLES30.glClearBufferfi(buffer, drawbuffer, depth, stencil);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public String glGetStringi(int name, int index) {
        return GLES30.glGetStringi(name, index);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glCopyBufferSubData(int readTarget, int writeTarget, int readOffset, int writeOffset, int size) {
        GLES30.glCopyBufferSubData(readTarget, writeTarget, readOffset, writeOffset, size);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetUniformIndices(int program, String[] uniformNames, IntBuffer uniformIndices) {
        GLES30.glGetUniformIndices(program, uniformNames, uniformIndices);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetActiveUniformsiv(int program, int uniformCount, IntBuffer uniformIndices, int pname, IntBuffer params) {
        GLES30.glGetActiveUniformsiv(program, uniformCount, uniformIndices, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public int glGetUniformBlockIndex(int program, String uniformBlockName) {
        return GLES30.glGetUniformBlockIndex(program, uniformBlockName);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetActiveUniformBlockiv(int program, int uniformBlockIndex, int pname, IntBuffer params) {
        GLES30.glGetActiveUniformBlockiv(program, uniformBlockIndex, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetActiveUniformBlockName(int program, int uniformBlockIndex, Buffer length, Buffer uniformBlockName) {
        GLES30.glGetActiveUniformBlockName(program, uniformBlockIndex, length, uniformBlockName);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public String glGetActiveUniformBlockName(int program, int uniformBlockIndex) {
        return GLES30.glGetActiveUniformBlockName(program, uniformBlockIndex);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glUniformBlockBinding(int program, int uniformBlockIndex, int uniformBlockBinding) {
        GLES30.glUniformBlockBinding(program, uniformBlockIndex, uniformBlockBinding);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDrawArraysInstanced(int mode, int first, int count, int instanceCount) {
        GLES30.glDrawArraysInstanced(mode, first, count, instanceCount);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDrawElementsInstanced(int mode, int count, int type, int indicesOffset, int instanceCount) {
        GLES30.glDrawElementsInstanced(mode, count, type, indicesOffset, instanceCount);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetInteger64v(int pname, LongBuffer params) {
        GLES30.glGetInteger64v(pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetBufferParameteri64v(int target, int pname, LongBuffer params) {
        GLES30.glGetBufferParameteri64v(target, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenSamplers(int count, int[] samplers, int offset) {
        GLES30.glGenSamplers(count, samplers, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenSamplers(int count, IntBuffer samplers) {
        GLES30.glGenSamplers(count, samplers);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteSamplers(int count, int[] samplers, int offset) {
        GLES30.glDeleteSamplers(count, samplers, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteSamplers(int count, IntBuffer samplers) {
        GLES30.glDeleteSamplers(count, samplers);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public boolean glIsSampler(int sampler) {
        return GLES30.glIsSampler(sampler);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBindSampler(int unit, int sampler) {
        GLES30.glBindSampler(unit, sampler);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glSamplerParameteri(int sampler, int pname, int param) {
        GLES30.glSamplerParameteri(sampler, pname, param);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glSamplerParameteriv(int sampler, int pname, IntBuffer param) {
        GLES30.glSamplerParameteriv(sampler, pname, param);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glSamplerParameterf(int sampler, int pname, float param) {
        GLES30.glSamplerParameterf(sampler, pname, param);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glSamplerParameterfv(int sampler, int pname, FloatBuffer param) {
        GLES30.glSamplerParameterfv(sampler, pname, param);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetSamplerParameteriv(int sampler, int pname, IntBuffer params) {
        GLES30.glGetSamplerParameteriv(sampler, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGetSamplerParameterfv(int sampler, int pname, FloatBuffer params) {
        GLES30.glGetSamplerParameterfv(sampler, pname, params);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glVertexAttribDivisor(int index, int divisor) {
        GLES30.glVertexAttribDivisor(index, divisor);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glBindTransformFeedback(int target, int id) {
        GLES30.glBindTransformFeedback(target, id);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteTransformFeedbacks(int n, int[] ids, int offset) {
        GLES30.glDeleteTransformFeedbacks(n, ids, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glDeleteTransformFeedbacks(int n, IntBuffer ids) {
        GLES30.glDeleteTransformFeedbacks(n, ids);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenTransformFeedbacks(int n, int[] ids, int offset) {
        GLES30.glGenTransformFeedbacks(n, ids, offset);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glGenTransformFeedbacks(int n, IntBuffer ids) {
        GLES30.glGenTransformFeedbacks(n, ids);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public boolean glIsTransformFeedback(int id) {
        return GLES30.glIsTransformFeedback(id);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glPauseTransformFeedback() {
        GLES30.glPauseTransformFeedback();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glResumeTransformFeedback() {
        GLES30.glResumeTransformFeedback();
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glProgramParameteri(int program, int pname, int value) {
        GLES30.glProgramParameteri(program, pname, value);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glInvalidateFramebuffer(int target, int numAttachments, IntBuffer attachments) {
        GLES30.glInvalidateFramebuffer(target, numAttachments, attachments);
    }

    @Override // com.badlogic.gdx.graphics.GL30
    public void glInvalidateSubFramebuffer(int target, int numAttachments, IntBuffer attachments, int x, int y, int width, int height) {
        GLES30.glInvalidateSubFramebuffer(target, numAttachments, attachments, x, y, width, height);
    }
}