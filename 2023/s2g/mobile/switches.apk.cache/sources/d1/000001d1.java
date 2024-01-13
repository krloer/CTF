package com.badlogic.gdx.graphics.g3d.particles.batches;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.Mesh;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.VertexAttribute;
import com.badlogic.gdx.graphics.VertexAttributes;
import com.badlogic.gdx.graphics.g3d.Material;
import com.badlogic.gdx.graphics.g3d.Renderable;
import com.badlogic.gdx.graphics.g3d.attributes.BlendingAttribute;
import com.badlogic.gdx.graphics.g3d.attributes.DepthTestAttribute;
import com.badlogic.gdx.graphics.g3d.attributes.TextureAttribute;
import com.badlogic.gdx.graphics.g3d.particles.ParallelArray;
import com.badlogic.gdx.graphics.g3d.particles.ParticleShader;
import com.badlogic.gdx.graphics.g3d.particles.ResourceData;
import com.badlogic.gdx.graphics.g3d.particles.renderers.PointSpriteControllerRenderData;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Pool;

/* loaded from: classes.dex */
public class PointSpriteParticleBatch extends BufferedParticleBatch<PointSpriteControllerRenderData> {
    protected static final int sizeAndRotationUsage = 512;
    Renderable renderable;
    private float[] vertices;
    private static boolean pointSpritesEnabled = false;
    protected static final Vector3 TMP_V1 = new Vector3();
    protected static final VertexAttributes CPU_ATTRIBUTES = new VertexAttributes(new VertexAttribute(1, 3, ShaderProgram.POSITION_ATTRIBUTE), new VertexAttribute(2, 4, ShaderProgram.COLOR_ATTRIBUTE), new VertexAttribute(16, 4, "a_region"), new VertexAttribute(512, 3, "a_sizeAndRotation"));
    protected static final int CPU_VERTEX_SIZE = (short) (CPU_ATTRIBUTES.vertexSize / 4);
    protected static final int CPU_POSITION_OFFSET = (short) (CPU_ATTRIBUTES.findByUsage(1).offset / 4);
    protected static final int CPU_COLOR_OFFSET = (short) (CPU_ATTRIBUTES.findByUsage(2).offset / 4);
    protected static final int CPU_REGION_OFFSET = (short) (CPU_ATTRIBUTES.findByUsage(16).offset / 4);
    protected static final int CPU_SIZE_AND_ROTATION_OFFSET = (short) (CPU_ATTRIBUTES.findByUsage(512).offset / 4);

    private static void enablePointSprites() {
        Gdx.gl.glEnable(GL20.GL_VERTEX_PROGRAM_POINT_SIZE);
        if (Gdx.app.getType() == Application.ApplicationType.Desktop) {
            Gdx.gl.glEnable(34913);
        }
        pointSpritesEnabled = true;
    }

    public PointSpriteParticleBatch() {
        this(1000);
    }

    public PointSpriteParticleBatch(int capacity) {
        this(capacity, new ParticleShader.Config(ParticleShader.ParticleType.Point));
    }

    public PointSpriteParticleBatch(int capacity, ParticleShader.Config shaderConfig) {
        super(PointSpriteControllerRenderData.class);
        if (!pointSpritesEnabled) {
            enablePointSprites();
        }
        allocRenderable();
        ensureCapacity(capacity);
        Renderable renderable = this.renderable;
        renderable.shader = new ParticleShader(renderable, shaderConfig);
        this.renderable.shader.init();
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.batches.BufferedParticleBatch
    protected void allocParticlesData(int capacity) {
        this.vertices = new float[CPU_VERTEX_SIZE * capacity];
        if (this.renderable.meshPart.mesh != null) {
            this.renderable.meshPart.mesh.dispose();
        }
        this.renderable.meshPart.mesh = new Mesh(false, capacity, 0, CPU_ATTRIBUTES);
    }

    protected void allocRenderable() {
        this.renderable = new Renderable();
        this.renderable.meshPart.primitiveType = 0;
        this.renderable.meshPart.offset = 0;
        this.renderable.material = new Material(new BlendingAttribute(1, GL20.GL_ONE_MINUS_SRC_ALPHA, 1.0f), new DepthTestAttribute(GL20.GL_LEQUAL, false), TextureAttribute.createDiffuse((Texture) null));
    }

    public void setTexture(Texture texture) {
        TextureAttribute attribute = (TextureAttribute) this.renderable.material.get(TextureAttribute.Diffuse);
        attribute.textureDescription.texture = texture;
    }

    public Texture getTexture() {
        TextureAttribute attribute = (TextureAttribute) this.renderable.material.get(TextureAttribute.Diffuse);
        return attribute.textureDescription.texture;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.batches.BufferedParticleBatch
    protected void flush(int[] offsets) {
        int tp = 0;
        Array.ArrayIterator it = this.renderData.iterator();
        while (it.hasNext()) {
            PointSpriteControllerRenderData data = (PointSpriteControllerRenderData) it.next();
            ParallelArray.FloatChannel scaleChannel = data.scaleChannel;
            ParallelArray.FloatChannel regionChannel = data.regionChannel;
            ParallelArray.FloatChannel positionChannel = data.positionChannel;
            ParallelArray.FloatChannel colorChannel = data.colorChannel;
            ParallelArray.FloatChannel rotationChannel = data.rotationChannel;
            int p = 0;
            while (p < data.controller.particles.size) {
                int offset = offsets[tp] * CPU_VERTEX_SIZE;
                int regionOffset = regionChannel.strideSize * p;
                int positionOffset = positionChannel.strideSize * p;
                int colorOffset = colorChannel.strideSize * p;
                int rotationOffset = rotationChannel.strideSize * p;
                this.vertices[offset + CPU_POSITION_OFFSET] = positionChannel.data[positionOffset + 0];
                this.vertices[CPU_POSITION_OFFSET + offset + 1] = positionChannel.data[positionOffset + 1];
                this.vertices[CPU_POSITION_OFFSET + offset + 2] = positionChannel.data[positionOffset + 2];
                this.vertices[CPU_COLOR_OFFSET + offset] = colorChannel.data[colorOffset + 0];
                this.vertices[CPU_COLOR_OFFSET + offset + 1] = colorChannel.data[colorOffset + 1];
                this.vertices[CPU_COLOR_OFFSET + offset + 2] = colorChannel.data[colorOffset + 2];
                this.vertices[CPU_COLOR_OFFSET + offset + 3] = colorChannel.data[colorOffset + 3];
                this.vertices[CPU_SIZE_AND_ROTATION_OFFSET + offset] = scaleChannel.data[scaleChannel.strideSize * p];
                this.vertices[CPU_SIZE_AND_ROTATION_OFFSET + offset + 1] = rotationChannel.data[rotationOffset + 0];
                this.vertices[CPU_SIZE_AND_ROTATION_OFFSET + offset + 2] = rotationChannel.data[rotationOffset + 1];
                this.vertices[CPU_REGION_OFFSET + offset] = regionChannel.data[regionOffset + 0];
                this.vertices[CPU_REGION_OFFSET + offset + 1] = regionChannel.data[regionOffset + 1];
                this.vertices[CPU_REGION_OFFSET + offset + 2] = regionChannel.data[regionOffset + 2];
                this.vertices[CPU_REGION_OFFSET + offset + 3] = regionChannel.data[regionOffset + 3];
                p++;
                tp++;
                data = data;
                it = it;
                positionChannel = positionChannel;
            }
        }
        this.renderable.meshPart.size = this.bufferedParticlesCount;
        this.renderable.meshPart.mesh.setVertices(this.vertices, 0, this.bufferedParticlesCount * CPU_VERTEX_SIZE);
        this.renderable.meshPart.update();
    }

    @Override // com.badlogic.gdx.graphics.g3d.RenderableProvider
    public void getRenderables(Array<Renderable> renderables, Pool<Renderable> pool) {
        if (this.bufferedParticlesCount > 0) {
            renderables.add(pool.obtain().set(this.renderable));
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch, com.badlogic.gdx.graphics.g3d.particles.ResourceData.Configurable
    public void save(AssetManager manager, ResourceData resources) {
        ResourceData.SaveData data = resources.createSaveData("pointSpriteBatch");
        data.saveAsset(manager.getAssetFileName(getTexture()), Texture.class);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch, com.badlogic.gdx.graphics.g3d.particles.ResourceData.Configurable
    public void load(AssetManager manager, ResourceData resources) {
        ResourceData.SaveData data = resources.getSaveData("pointSpriteBatch");
        if (data != null) {
            setTexture((Texture) manager.get(data.loadAsset()));
        }
    }
}