package com.badlogic.gdx.graphics.g3d.shaders;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.VertexAttribute;
import com.badlogic.gdx.graphics.g3d.Attributes;
import com.badlogic.gdx.graphics.g3d.Renderable;
import com.badlogic.gdx.graphics.g3d.attributes.BlendingAttribute;
import com.badlogic.gdx.graphics.g3d.attributes.FloatAttribute;
import com.badlogic.gdx.graphics.g3d.attributes.TextureAttribute;
import com.badlogic.gdx.graphics.g3d.shaders.DefaultShader;
import com.badlogic.gdx.graphics.g3d.utils.RenderContext;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class DepthShader extends DefaultShader {
    private final FloatAttribute alphaTestAttribute;
    public final int numBones;
    public final int weights;
    private static String defaultVertexShader = null;
    private static String defaultFragmentShader = null;
    private static final Attributes tmpAttributes = new Attributes();

    /* loaded from: classes.dex */
    public static class Config extends DefaultShader.Config {
        public float defaultAlphaTest;
        public boolean depthBufferOnly;

        public Config() {
            this.depthBufferOnly = false;
            this.defaultAlphaTest = 0.5f;
            this.defaultCullFace = GL20.GL_FRONT;
        }

        public Config(String vertexShader, String fragmentShader) {
            super(vertexShader, fragmentShader);
            this.depthBufferOnly = false;
            this.defaultAlphaTest = 0.5f;
        }
    }

    public static final String getDefaultVertexShader() {
        if (defaultVertexShader == null) {
            defaultVertexShader = Gdx.files.classpath("com/badlogic/gdx/graphics/g3d/shaders/depth.vertex.glsl").readString();
        }
        return defaultVertexShader;
    }

    public static final String getDefaultFragmentShader() {
        if (defaultFragmentShader == null) {
            defaultFragmentShader = Gdx.files.classpath("com/badlogic/gdx/graphics/g3d/shaders/depth.fragment.glsl").readString();
        }
        return defaultFragmentShader;
    }

    public static String createPrefix(Renderable renderable, Config config) {
        String prefix = DefaultShader.createPrefix(renderable, config);
        if (config.depthBufferOnly) {
            return prefix;
        }
        return prefix + "#define PackedDepthFlag\n";
    }

    public DepthShader(Renderable renderable) {
        this(renderable, new Config());
    }

    public DepthShader(Renderable renderable, Config config) {
        this(renderable, config, createPrefix(renderable, config));
    }

    public DepthShader(Renderable renderable, Config config, String prefix) {
        this(renderable, config, prefix, config.vertexShader != null ? config.vertexShader : getDefaultVertexShader(), config.fragmentShader != null ? config.fragmentShader : getDefaultFragmentShader());
    }

    public DepthShader(Renderable renderable, Config config, String prefix, String vertexShader, String fragmentShader) {
        this(renderable, config, new ShaderProgram(prefix + vertexShader, prefix + fragmentShader));
    }

    public DepthShader(Renderable renderable, Config config, ShaderProgram shaderProgram) {
        super(renderable, config, shaderProgram);
        combineAttributes(renderable);
        if (renderable.bones != null && renderable.bones.length > config.numBones) {
            throw new GdxRuntimeException("too many bones: " + renderable.bones.length + ", max configured: " + config.numBones);
        }
        this.numBones = renderable.bones == null ? 0 : config.numBones;
        int w = 0;
        int n = renderable.meshPart.mesh.getVertexAttributes().size();
        for (int i = 0; i < n; i++) {
            VertexAttribute attr = renderable.meshPart.mesh.getVertexAttributes().get(i);
            if (attr.usage == 64) {
                w |= 1 << attr.unit;
            }
        }
        this.weights = w;
        this.alphaTestAttribute = new FloatAttribute(FloatAttribute.AlphaTest, config.defaultAlphaTest);
    }

    @Override // com.badlogic.gdx.graphics.g3d.shaders.DefaultShader, com.badlogic.gdx.graphics.g3d.shaders.BaseShader, com.badlogic.gdx.graphics.g3d.Shader
    public void begin(Camera camera, RenderContext context) {
        super.begin(camera, context);
    }

    @Override // com.badlogic.gdx.graphics.g3d.shaders.DefaultShader, com.badlogic.gdx.graphics.g3d.shaders.BaseShader, com.badlogic.gdx.graphics.g3d.Shader
    public void end() {
        super.end();
    }

    @Override // com.badlogic.gdx.graphics.g3d.shaders.DefaultShader, com.badlogic.gdx.graphics.g3d.Shader
    public boolean canRender(Renderable renderable) {
        if (renderable.bones == null || renderable.bones.length <= this.numBones) {
            Attributes attributes = combineAttributes(renderable);
            if (attributes.has(BlendingAttribute.Type)) {
                if ((this.attributesMask & BlendingAttribute.Type) != BlendingAttribute.Type) {
                    return false;
                }
                if (attributes.has(TextureAttribute.Diffuse) != ((this.attributesMask & TextureAttribute.Diffuse) == TextureAttribute.Diffuse)) {
                    return false;
                }
            }
            boolean skinned = (renderable.meshPart.mesh.getVertexAttributes().getMask() & 64) == 64;
            return skinned == (this.weights > 0);
        }
        return false;
    }

    @Override // com.badlogic.gdx.graphics.g3d.shaders.DefaultShader, com.badlogic.gdx.graphics.g3d.shaders.BaseShader
    public void render(Renderable renderable, Attributes combinedAttributes) {
        if (combinedAttributes.has(BlendingAttribute.Type)) {
            BlendingAttribute blending = (BlendingAttribute) combinedAttributes.get(BlendingAttribute.Type);
            combinedAttributes.remove(BlendingAttribute.Type);
            boolean hasAlphaTest = combinedAttributes.has(FloatAttribute.AlphaTest);
            if (!hasAlphaTest) {
                combinedAttributes.set(this.alphaTestAttribute);
            }
            if (blending.opacity >= ((FloatAttribute) combinedAttributes.get(FloatAttribute.AlphaTest)).value) {
                super.render(renderable, combinedAttributes);
            }
            if (!hasAlphaTest) {
                combinedAttributes.remove(FloatAttribute.AlphaTest);
            }
            combinedAttributes.set(blending);
            return;
        }
        super.render(renderable, combinedAttributes);
    }

    private static final Attributes combineAttributes(Renderable renderable) {
        tmpAttributes.clear();
        if (renderable.environment != null) {
            tmpAttributes.set(renderable.environment);
        }
        if (renderable.material != null) {
            tmpAttributes.set(renderable.material);
        }
        return tmpAttributes;
    }
}