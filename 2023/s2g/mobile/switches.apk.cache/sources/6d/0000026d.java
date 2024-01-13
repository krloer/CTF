package com.badlogic.gdx.graphics.glutils;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Cubemap;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.glutils.GLFrameBuffer;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class FrameBufferCubemap extends GLFrameBuffer<Cubemap> {
    private static final Cubemap.CubemapSide[] cubemapSides = Cubemap.CubemapSide.values();
    private int currentSide;

    FrameBufferCubemap() {
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public FrameBufferCubemap(GLFrameBuffer.GLFrameBufferBuilder<? extends GLFrameBuffer<Cubemap>> bufferBuilder) {
        super(bufferBuilder);
    }

    public FrameBufferCubemap(Pixmap.Format format, int width, int height, boolean hasDepth) {
        this(format, width, height, hasDepth, false);
    }

    public FrameBufferCubemap(Pixmap.Format format, int width, int height, boolean hasDepth, boolean hasStencil) {
        GLFrameBuffer.FrameBufferCubemapBuilder frameBufferBuilder = new GLFrameBuffer.FrameBufferCubemapBuilder(width, height);
        frameBufferBuilder.addBasicColorTextureAttachment(format);
        if (hasDepth) {
            frameBufferBuilder.addBasicDepthRenderBuffer();
        }
        if (hasStencil) {
            frameBufferBuilder.addBasicStencilRenderBuffer();
        }
        this.bufferBuilder = frameBufferBuilder;
        build();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.badlogic.gdx.graphics.glutils.GLFrameBuffer
    public Cubemap createTexture(GLFrameBuffer.FrameBufferTextureAttachmentSpec attachmentSpec) {
        GLOnlyTextureData data = new GLOnlyTextureData(this.bufferBuilder.width, this.bufferBuilder.height, 0, attachmentSpec.internalFormat, attachmentSpec.format, attachmentSpec.type);
        Cubemap result = new Cubemap(data, data, data, data, data, data);
        result.setFilter(Texture.TextureFilter.Linear, Texture.TextureFilter.Linear);
        result.setWrap(Texture.TextureWrap.ClampToEdge, Texture.TextureWrap.ClampToEdge);
        return result;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.graphics.glutils.GLFrameBuffer
    public void disposeColorTexture(Cubemap colorTexture) {
        colorTexture.dispose();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.graphics.glutils.GLFrameBuffer
    public void attachFrameBufferColorTexture(Cubemap texture) {
        GL20 gl = Gdx.gl20;
        int glHandle = texture.getTextureObjectHandle();
        Cubemap.CubemapSide[] sides = Cubemap.CubemapSide.values();
        for (Cubemap.CubemapSide side : sides) {
            gl.glFramebufferTexture2D(GL20.GL_FRAMEBUFFER, GL20.GL_COLOR_ATTACHMENT0, side.glEnum, glHandle, 0);
        }
    }

    @Override // com.badlogic.gdx.graphics.glutils.GLFrameBuffer
    public void bind() {
        this.currentSide = -1;
        super.bind();
    }

    public boolean nextSide() {
        int i = this.currentSide;
        if (i > 5) {
            throw new GdxRuntimeException("No remaining sides.");
        }
        if (i == 5) {
            return false;
        }
        this.currentSide = i + 1;
        bindSide(getSide());
        return true;
    }

    protected void bindSide(Cubemap.CubemapSide side) {
        Gdx.gl20.glFramebufferTexture2D(GL20.GL_FRAMEBUFFER, GL20.GL_COLOR_ATTACHMENT0, side.glEnum, getColorBufferTexture().getTextureObjectHandle(), 0);
    }

    public Cubemap.CubemapSide getSide() {
        int i = this.currentSide;
        if (i < 0) {
            return null;
        }
        return cubemapSides[i];
    }
}