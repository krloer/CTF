package com.badlogic.gdx.graphics.glutils;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.GL30;
import com.badlogic.gdx.graphics.GLTexture;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.BufferUtils;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.GdxRuntimeException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes.dex */
public abstract class GLFrameBuffer<T extends GLTexture> implements Disposable {
    protected static final int GL_DEPTH24_STENCIL8_OES = 35056;
    protected static int defaultFramebufferHandle;
    protected GLFrameBufferBuilder<? extends GLFrameBuffer<T>> bufferBuilder;
    protected int depthStencilPackedBufferHandle;
    protected int depthbufferHandle;
    protected int framebufferHandle;
    protected boolean hasDepthStencilPackedBuffer;
    protected boolean isMRT;
    protected int stencilbufferHandle;
    protected Array<T> textureAttachments = new Array<>();
    protected static final Map<Application, Array<GLFrameBuffer>> buffers = new HashMap();
    protected static boolean defaultFramebufferHandleInitialized = false;

    protected abstract void attachFrameBufferColorTexture(T t);

    protected abstract T createTexture(FrameBufferTextureAttachmentSpec frameBufferTextureAttachmentSpec);

    protected abstract void disposeColorTexture(T t);

    /* JADX INFO: Access modifiers changed from: package-private */
    public GLFrameBuffer() {
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public GLFrameBuffer(GLFrameBufferBuilder<? extends GLFrameBuffer<T>> bufferBuilder) {
        this.bufferBuilder = bufferBuilder;
        build();
    }

    public T getColorBufferTexture() {
        return this.textureAttachments.first();
    }

    public Array<T> getTextureAttachments() {
        return this.textureAttachments;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void build() {
        GL20 gl = Gdx.gl20;
        checkValidBuilder();
        if (!defaultFramebufferHandleInitialized) {
            defaultFramebufferHandleInitialized = true;
            if (Gdx.app.getType() == Application.ApplicationType.iOS) {
                IntBuffer intbuf = ByteBuffer.allocateDirect(64).order(ByteOrder.nativeOrder()).asIntBuffer();
                gl.glGetIntegerv(36006, intbuf);
                defaultFramebufferHandle = intbuf.get(0);
            } else {
                defaultFramebufferHandle = 0;
            }
        }
        this.framebufferHandle = gl.glGenFramebuffer();
        gl.glBindFramebuffer(GL20.GL_FRAMEBUFFER, this.framebufferHandle);
        int width = this.bufferBuilder.width;
        int height = this.bufferBuilder.height;
        if (this.bufferBuilder.hasDepthRenderBuffer) {
            this.depthbufferHandle = gl.glGenRenderbuffer();
            gl.glBindRenderbuffer(GL20.GL_RENDERBUFFER, this.depthbufferHandle);
            gl.glRenderbufferStorage(GL20.GL_RENDERBUFFER, this.bufferBuilder.depthRenderBufferSpec.internalFormat, width, height);
        }
        if (this.bufferBuilder.hasStencilRenderBuffer) {
            this.stencilbufferHandle = gl.glGenRenderbuffer();
            gl.glBindRenderbuffer(GL20.GL_RENDERBUFFER, this.stencilbufferHandle);
            gl.glRenderbufferStorage(GL20.GL_RENDERBUFFER, this.bufferBuilder.stencilRenderBufferSpec.internalFormat, width, height);
        }
        if (this.bufferBuilder.hasPackedStencilDepthRenderBuffer) {
            this.depthStencilPackedBufferHandle = gl.glGenRenderbuffer();
            gl.glBindRenderbuffer(GL20.GL_RENDERBUFFER, this.depthStencilPackedBufferHandle);
            gl.glRenderbufferStorage(GL20.GL_RENDERBUFFER, this.bufferBuilder.packedStencilDepthRenderBufferSpec.internalFormat, width, height);
        }
        this.isMRT = this.bufferBuilder.textureAttachmentSpecs.size > 1;
        int colorTextureCounter = 0;
        if (!this.isMRT) {
            T texture = createTexture(this.bufferBuilder.textureAttachmentSpecs.first());
            this.textureAttachments.add(texture);
            gl.glBindTexture(texture.glTarget, texture.getTextureObjectHandle());
        } else {
            Array.ArrayIterator<FrameBufferTextureAttachmentSpec> it = this.bufferBuilder.textureAttachmentSpecs.iterator();
            int colorTextureCounter2 = 0;
            while (it.hasNext()) {
                FrameBufferTextureAttachmentSpec attachmentSpec = it.next();
                T texture2 = createTexture(attachmentSpec);
                this.textureAttachments.add(texture2);
                if (attachmentSpec.isColorTexture()) {
                    gl.glFramebufferTexture2D(GL20.GL_FRAMEBUFFER, colorTextureCounter2 + GL20.GL_COLOR_ATTACHMENT0, GL20.GL_TEXTURE_2D, texture2.getTextureObjectHandle(), 0);
                    colorTextureCounter2++;
                } else if (attachmentSpec.isDepth) {
                    gl.glFramebufferTexture2D(GL20.GL_FRAMEBUFFER, GL20.GL_DEPTH_ATTACHMENT, GL20.GL_TEXTURE_2D, texture2.getTextureObjectHandle(), 0);
                } else if (attachmentSpec.isStencil) {
                    gl.glFramebufferTexture2D(GL20.GL_FRAMEBUFFER, GL20.GL_STENCIL_ATTACHMENT, GL20.GL_TEXTURE_2D, texture2.getTextureObjectHandle(), 0);
                }
            }
            colorTextureCounter = colorTextureCounter2;
        }
        if (!this.isMRT) {
            attachFrameBufferColorTexture(this.textureAttachments.first());
        } else {
            IntBuffer buffer = BufferUtils.newIntBuffer(colorTextureCounter);
            for (int i = 0; i < colorTextureCounter; i++) {
                buffer.put(i + GL20.GL_COLOR_ATTACHMENT0);
            }
            buffer.position(0);
            Gdx.gl30.glDrawBuffers(colorTextureCounter, buffer);
        }
        if (this.bufferBuilder.hasDepthRenderBuffer) {
            gl.glFramebufferRenderbuffer(GL20.GL_FRAMEBUFFER, GL20.GL_DEPTH_ATTACHMENT, GL20.GL_RENDERBUFFER, this.depthbufferHandle);
        }
        if (this.bufferBuilder.hasStencilRenderBuffer) {
            gl.glFramebufferRenderbuffer(GL20.GL_FRAMEBUFFER, GL20.GL_STENCIL_ATTACHMENT, GL20.GL_RENDERBUFFER, this.stencilbufferHandle);
        }
        if (this.bufferBuilder.hasPackedStencilDepthRenderBuffer) {
            gl.glFramebufferRenderbuffer(GL20.GL_FRAMEBUFFER, GL30.GL_DEPTH_STENCIL_ATTACHMENT, GL20.GL_RENDERBUFFER, this.depthStencilPackedBufferHandle);
        }
        gl.glBindRenderbuffer(GL20.GL_RENDERBUFFER, 0);
        Array.ArrayIterator<T> it2 = this.textureAttachments.iterator();
        while (it2.hasNext()) {
            gl.glBindTexture(it2.next().glTarget, 0);
        }
        int result = gl.glCheckFramebufferStatus(GL20.GL_FRAMEBUFFER);
        if (result == 36061 && this.bufferBuilder.hasDepthRenderBuffer && this.bufferBuilder.hasStencilRenderBuffer && (Gdx.graphics.supportsExtension("GL_OES_packed_depth_stencil") || Gdx.graphics.supportsExtension("GL_EXT_packed_depth_stencil"))) {
            if (this.bufferBuilder.hasDepthRenderBuffer) {
                gl.glDeleteRenderbuffer(this.depthbufferHandle);
                this.depthbufferHandle = 0;
            }
            if (this.bufferBuilder.hasStencilRenderBuffer) {
                gl.glDeleteRenderbuffer(this.stencilbufferHandle);
                this.stencilbufferHandle = 0;
            }
            if (this.bufferBuilder.hasPackedStencilDepthRenderBuffer) {
                gl.glDeleteRenderbuffer(this.depthStencilPackedBufferHandle);
                this.depthStencilPackedBufferHandle = 0;
            }
            this.depthStencilPackedBufferHandle = gl.glGenRenderbuffer();
            this.hasDepthStencilPackedBuffer = true;
            gl.glBindRenderbuffer(GL20.GL_RENDERBUFFER, this.depthStencilPackedBufferHandle);
            gl.glRenderbufferStorage(GL20.GL_RENDERBUFFER, 35056, width, height);
            gl.glBindRenderbuffer(GL20.GL_RENDERBUFFER, 0);
            gl.glFramebufferRenderbuffer(GL20.GL_FRAMEBUFFER, GL20.GL_DEPTH_ATTACHMENT, GL20.GL_RENDERBUFFER, this.depthStencilPackedBufferHandle);
            gl.glFramebufferRenderbuffer(GL20.GL_FRAMEBUFFER, GL20.GL_STENCIL_ATTACHMENT, GL20.GL_RENDERBUFFER, this.depthStencilPackedBufferHandle);
            result = gl.glCheckFramebufferStatus(GL20.GL_FRAMEBUFFER);
        }
        gl.glBindFramebuffer(GL20.GL_FRAMEBUFFER, defaultFramebufferHandle);
        if (result == 36053) {
            addManagedFrameBuffer(Gdx.app, this);
            return;
        }
        Array.ArrayIterator<T> it3 = this.textureAttachments.iterator();
        while (it3.hasNext()) {
            disposeColorTexture(it3.next());
        }
        if (this.hasDepthStencilPackedBuffer) {
            gl.glDeleteBuffer(this.depthStencilPackedBufferHandle);
        } else {
            if (this.bufferBuilder.hasDepthRenderBuffer) {
                gl.glDeleteRenderbuffer(this.depthbufferHandle);
            }
            if (this.bufferBuilder.hasStencilRenderBuffer) {
                gl.glDeleteRenderbuffer(this.stencilbufferHandle);
            }
        }
        gl.glDeleteFramebuffer(this.framebufferHandle);
        if (result == 36054) {
            throw new IllegalStateException("Frame buffer couldn't be constructed: incomplete attachment");
        }
        if (result == 36057) {
            throw new IllegalStateException("Frame buffer couldn't be constructed: incomplete dimensions");
        }
        if (result == 36055) {
            throw new IllegalStateException("Frame buffer couldn't be constructed: missing attachment");
        }
        if (result == 36061) {
            throw new IllegalStateException("Frame buffer couldn't be constructed: unsupported combination of formats");
        }
        throw new IllegalStateException("Frame buffer couldn't be constructed: unknown error " + result);
    }

    private void checkValidBuilder() {
        boolean runningGL30 = Gdx.graphics.isGL30Available();
        if (!runningGL30) {
            if (this.bufferBuilder.hasPackedStencilDepthRenderBuffer) {
                throw new GdxRuntimeException("Packed Stencil/Render render buffers are not available on GLES 2.0");
            }
            if (this.bufferBuilder.textureAttachmentSpecs.size > 1) {
                throw new GdxRuntimeException("Multiple render targets not available on GLES 2.0");
            }
            Array.ArrayIterator<FrameBufferTextureAttachmentSpec> it = this.bufferBuilder.textureAttachmentSpecs.iterator();
            while (it.hasNext()) {
                FrameBufferTextureAttachmentSpec spec = it.next();
                if (spec.isDepth) {
                    throw new GdxRuntimeException("Depth texture FrameBuffer Attachment not available on GLES 2.0");
                }
                if (spec.isStencil) {
                    throw new GdxRuntimeException("Stencil texture FrameBuffer Attachment not available on GLES 2.0");
                }
                if (spec.isFloat && !Gdx.graphics.supportsExtension("OES_texture_float")) {
                    throw new GdxRuntimeException("Float texture FrameBuffer Attachment not available on GLES 2.0");
                }
            }
        }
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        GL20 gl = Gdx.gl20;
        Array.ArrayIterator<T> it = this.textureAttachments.iterator();
        while (it.hasNext()) {
            T texture = it.next();
            disposeColorTexture(texture);
        }
        if (this.hasDepthStencilPackedBuffer) {
            gl.glDeleteRenderbuffer(this.depthStencilPackedBufferHandle);
        } else {
            if (this.bufferBuilder.hasDepthRenderBuffer) {
                gl.glDeleteRenderbuffer(this.depthbufferHandle);
            }
            if (this.bufferBuilder.hasStencilRenderBuffer) {
                gl.glDeleteRenderbuffer(this.stencilbufferHandle);
            }
        }
        gl.glDeleteFramebuffer(this.framebufferHandle);
        if (buffers.get(Gdx.app) != null) {
            buffers.get(Gdx.app).removeValue(this, true);
        }
    }

    public void bind() {
        Gdx.gl20.glBindFramebuffer(GL20.GL_FRAMEBUFFER, this.framebufferHandle);
    }

    public static void unbind() {
        Gdx.gl20.glBindFramebuffer(GL20.GL_FRAMEBUFFER, defaultFramebufferHandle);
    }

    public void begin() {
        bind();
        setFrameBufferViewport();
    }

    protected void setFrameBufferViewport() {
        Gdx.gl20.glViewport(0, 0, this.bufferBuilder.width, this.bufferBuilder.height);
    }

    public void end() {
        end(0, 0, Gdx.graphics.getBackBufferWidth(), Gdx.graphics.getBackBufferHeight());
    }

    public void end(int x, int y, int width, int height) {
        unbind();
        Gdx.gl20.glViewport(x, y, width, height);
    }

    public int getFramebufferHandle() {
        return this.framebufferHandle;
    }

    public int getDepthBufferHandle() {
        return this.depthbufferHandle;
    }

    public int getStencilBufferHandle() {
        return this.stencilbufferHandle;
    }

    protected int getDepthStencilPackedBuffer() {
        return this.depthStencilPackedBufferHandle;
    }

    public int getHeight() {
        return this.bufferBuilder.height;
    }

    public int getWidth() {
        return this.bufferBuilder.width;
    }

    private static void addManagedFrameBuffer(Application app, GLFrameBuffer frameBuffer) {
        Array<GLFrameBuffer> managedResources = buffers.get(app);
        if (managedResources == null) {
            managedResources = new Array<>();
        }
        managedResources.add(frameBuffer);
        buffers.put(app, managedResources);
    }

    public static void invalidateAllFrameBuffers(Application app) {
        Array<GLFrameBuffer> bufferArray;
        if (Gdx.gl20 == null || (bufferArray = buffers.get(app)) == null) {
            return;
        }
        for (int i = 0; i < bufferArray.size; i++) {
            bufferArray.get(i).build();
        }
    }

    public static void clearAllFrameBuffers(Application app) {
        buffers.remove(app);
    }

    public static StringBuilder getManagedStatus(StringBuilder builder) {
        builder.append("Managed buffers/app: { ");
        for (Application app : buffers.keySet()) {
            builder.append(buffers.get(app).size);
            builder.append(" ");
        }
        builder.append("}");
        return builder;
    }

    public static String getManagedStatus() {
        return getManagedStatus(new StringBuilder()).toString();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: classes.dex */
    public static class FrameBufferTextureAttachmentSpec {
        int format;
        int internalFormat;
        boolean isDepth;
        boolean isFloat;
        boolean isGpuOnly;
        boolean isStencil;
        int type;

        public FrameBufferTextureAttachmentSpec(int internalformat, int format, int type) {
            this.internalFormat = internalformat;
            this.format = format;
            this.type = type;
        }

        public boolean isColorTexture() {
            return (this.isDepth || this.isStencil) ? false : true;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: classes.dex */
    public static class FrameBufferRenderBufferAttachmentSpec {
        int internalFormat;

        public FrameBufferRenderBufferAttachmentSpec(int internalFormat) {
            this.internalFormat = internalFormat;
        }
    }

    /* loaded from: classes.dex */
    public static abstract class GLFrameBufferBuilder<U extends GLFrameBuffer<? extends GLTexture>> {
        protected FrameBufferRenderBufferAttachmentSpec depthRenderBufferSpec;
        protected boolean hasDepthRenderBuffer;
        protected boolean hasPackedStencilDepthRenderBuffer;
        protected boolean hasStencilRenderBuffer;
        protected int height;
        protected FrameBufferRenderBufferAttachmentSpec packedStencilDepthRenderBufferSpec;
        protected FrameBufferRenderBufferAttachmentSpec stencilRenderBufferSpec;
        protected Array<FrameBufferTextureAttachmentSpec> textureAttachmentSpecs = new Array<>();
        protected int width;

        public abstract U build();

        public GLFrameBufferBuilder(int width, int height) {
            this.width = width;
            this.height = height;
        }

        public GLFrameBufferBuilder<U> addColorTextureAttachment(int internalFormat, int format, int type) {
            this.textureAttachmentSpecs.add(new FrameBufferTextureAttachmentSpec(internalFormat, format, type));
            return this;
        }

        public GLFrameBufferBuilder<U> addBasicColorTextureAttachment(Pixmap.Format format) {
            int glFormat = Pixmap.Format.toGlFormat(format);
            int glType = Pixmap.Format.toGlType(format);
            return addColorTextureAttachment(glFormat, glFormat, glType);
        }

        public GLFrameBufferBuilder<U> addFloatAttachment(int internalFormat, int format, int type, boolean gpuOnly) {
            FrameBufferTextureAttachmentSpec spec = new FrameBufferTextureAttachmentSpec(internalFormat, format, type);
            spec.isFloat = true;
            spec.isGpuOnly = gpuOnly;
            this.textureAttachmentSpecs.add(spec);
            return this;
        }

        public GLFrameBufferBuilder<U> addDepthTextureAttachment(int internalFormat, int type) {
            FrameBufferTextureAttachmentSpec spec = new FrameBufferTextureAttachmentSpec(internalFormat, GL20.GL_DEPTH_COMPONENT, type);
            spec.isDepth = true;
            this.textureAttachmentSpecs.add(spec);
            return this;
        }

        public GLFrameBufferBuilder<U> addStencilTextureAttachment(int internalFormat, int type) {
            FrameBufferTextureAttachmentSpec spec = new FrameBufferTextureAttachmentSpec(internalFormat, GL20.GL_STENCIL_ATTACHMENT, type);
            spec.isStencil = true;
            this.textureAttachmentSpecs.add(spec);
            return this;
        }

        public GLFrameBufferBuilder<U> addDepthRenderBuffer(int internalFormat) {
            this.depthRenderBufferSpec = new FrameBufferRenderBufferAttachmentSpec(internalFormat);
            this.hasDepthRenderBuffer = true;
            return this;
        }

        public GLFrameBufferBuilder<U> addStencilRenderBuffer(int internalFormat) {
            this.stencilRenderBufferSpec = new FrameBufferRenderBufferAttachmentSpec(internalFormat);
            this.hasStencilRenderBuffer = true;
            return this;
        }

        public GLFrameBufferBuilder<U> addStencilDepthPackedRenderBuffer(int internalFormat) {
            this.packedStencilDepthRenderBufferSpec = new FrameBufferRenderBufferAttachmentSpec(internalFormat);
            this.hasPackedStencilDepthRenderBuffer = true;
            return this;
        }

        public GLFrameBufferBuilder<U> addBasicDepthRenderBuffer() {
            return addDepthRenderBuffer(GL20.GL_DEPTH_COMPONENT16);
        }

        public GLFrameBufferBuilder<U> addBasicStencilRenderBuffer() {
            return addStencilRenderBuffer(GL20.GL_STENCIL_INDEX8);
        }

        public GLFrameBufferBuilder<U> addBasicStencilDepthPackedRenderBuffer() {
            return addStencilDepthPackedRenderBuffer(35056);
        }
    }

    /* loaded from: classes.dex */
    public static class FrameBufferBuilder extends GLFrameBufferBuilder<FrameBuffer> {
        public FrameBufferBuilder(int width, int height) {
            super(width, height);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // com.badlogic.gdx.graphics.glutils.GLFrameBuffer.GLFrameBufferBuilder
        public FrameBuffer build() {
            return new FrameBuffer(this);
        }
    }

    /* loaded from: classes.dex */
    public static class FloatFrameBufferBuilder extends GLFrameBufferBuilder<FloatFrameBuffer> {
        public FloatFrameBufferBuilder(int width, int height) {
            super(width, height);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // com.badlogic.gdx.graphics.glutils.GLFrameBuffer.GLFrameBufferBuilder
        public FloatFrameBuffer build() {
            return new FloatFrameBuffer(this);
        }
    }

    /* loaded from: classes.dex */
    public static class FrameBufferCubemapBuilder extends GLFrameBufferBuilder<FrameBufferCubemap> {
        public FrameBufferCubemapBuilder(int width, int height) {
            super(width, height);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // com.badlogic.gdx.graphics.glutils.GLFrameBuffer.GLFrameBufferBuilder
        public FrameBufferCubemap build() {
            return new FrameBufferCubemap(this);
        }
    }
}