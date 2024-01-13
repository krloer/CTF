package com.badlogic.gdx.graphics.g3d.particles;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.g3d.Attribute;
import com.badlogic.gdx.graphics.g3d.Attributes;
import com.badlogic.gdx.graphics.g3d.Material;
import com.badlogic.gdx.graphics.g3d.Renderable;
import com.badlogic.gdx.graphics.g3d.Shader;
import com.badlogic.gdx.graphics.g3d.attributes.BlendingAttribute;
import com.badlogic.gdx.graphics.g3d.attributes.DepthTestAttribute;
import com.badlogic.gdx.graphics.g3d.attributes.IntAttribute;
import com.badlogic.gdx.graphics.g3d.attributes.TextureAttribute;
import com.badlogic.gdx.graphics.g3d.shaders.BaseShader;
import com.badlogic.gdx.graphics.g3d.shaders.DefaultShader;
import com.badlogic.gdx.graphics.g3d.utils.RenderContext;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.GdxRuntimeException;
import java.util.Iterator;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class ParticleShader extends BaseShader {
    protected final Config config;
    Material currentMaterial;
    private long materialMask;
    private Renderable renderable;
    private long vertexMask;
    private static String defaultVertexShader = null;
    private static String defaultFragmentShader = null;
    protected static long implementedFlags = BlendingAttribute.Type | TextureAttribute.Diffuse;
    static final Vector3 TMP_VECTOR3 = new Vector3();
    private static final long optionalAttributes = IntAttribute.CullFace | DepthTestAttribute.Type;

    /* loaded from: classes.dex */
    public enum AlignMode {
        Screen,
        ViewPoint
    }

    /* loaded from: classes.dex */
    public static class Inputs {
        public static final BaseShader.Uniform cameraRight = new BaseShader.Uniform("u_cameraRight");
        public static final BaseShader.Uniform cameraInvDirection = new BaseShader.Uniform("u_cameraInvDirection");
        public static final BaseShader.Uniform screenWidth = new BaseShader.Uniform("u_screenWidth");
        public static final BaseShader.Uniform regionSize = new BaseShader.Uniform("u_regionSize");
    }

    /* loaded from: classes.dex */
    public enum ParticleType {
        Billboard,
        Point
    }

    /* loaded from: classes.dex */
    public static class Setters {
        public static final BaseShader.Setter cameraRight = new BaseShader.Setter() { // from class: com.badlogic.gdx.graphics.g3d.particles.ParticleShader.Setters.1
            @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader.Setter
            public boolean isGlobal(BaseShader shader, int inputID) {
                return true;
            }

            @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader.Setter
            public void set(BaseShader shader, int inputID, Renderable renderable, Attributes combinedAttributes) {
                shader.set(inputID, ParticleShader.TMP_VECTOR3.set(shader.camera.direction).crs(shader.camera.up).nor());
            }
        };
        public static final BaseShader.Setter cameraUp = new BaseShader.Setter() { // from class: com.badlogic.gdx.graphics.g3d.particles.ParticleShader.Setters.2
            @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader.Setter
            public boolean isGlobal(BaseShader shader, int inputID) {
                return true;
            }

            @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader.Setter
            public void set(BaseShader shader, int inputID, Renderable renderable, Attributes combinedAttributes) {
                shader.set(inputID, ParticleShader.TMP_VECTOR3.set(shader.camera.up).nor());
            }
        };
        public static final BaseShader.Setter cameraInvDirection = new BaseShader.Setter() { // from class: com.badlogic.gdx.graphics.g3d.particles.ParticleShader.Setters.3
            @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader.Setter
            public boolean isGlobal(BaseShader shader, int inputID) {
                return true;
            }

            @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader.Setter
            public void set(BaseShader shader, int inputID, Renderable renderable, Attributes combinedAttributes) {
                shader.set(inputID, ParticleShader.TMP_VECTOR3.set(-shader.camera.direction.x, -shader.camera.direction.y, -shader.camera.direction.z).nor());
            }
        };
        public static final BaseShader.Setter cameraPosition = new BaseShader.Setter() { // from class: com.badlogic.gdx.graphics.g3d.particles.ParticleShader.Setters.4
            @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader.Setter
            public boolean isGlobal(BaseShader shader, int inputID) {
                return true;
            }

            @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader.Setter
            public void set(BaseShader shader, int inputID, Renderable renderable, Attributes combinedAttributes) {
                shader.set(inputID, shader.camera.position);
            }
        };
        public static final BaseShader.Setter screenWidth = new BaseShader.Setter() { // from class: com.badlogic.gdx.graphics.g3d.particles.ParticleShader.Setters.5
            @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader.Setter
            public boolean isGlobal(BaseShader shader, int inputID) {
                return true;
            }

            @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader.Setter
            public void set(BaseShader shader, int inputID, Renderable renderable, Attributes combinedAttributes) {
                shader.set(inputID, Gdx.graphics.getWidth());
            }
        };
        public static final BaseShader.Setter worldViewTrans = new BaseShader.Setter() { // from class: com.badlogic.gdx.graphics.g3d.particles.ParticleShader.Setters.6
            final Matrix4 temp = new Matrix4();

            @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader.Setter
            public boolean isGlobal(BaseShader shader, int inputID) {
                return false;
            }

            @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader.Setter
            public void set(BaseShader shader, int inputID, Renderable renderable, Attributes combinedAttributes) {
                shader.set(inputID, this.temp.set(shader.camera.view).mul(renderable.worldTransform));
            }
        };
    }

    /* loaded from: classes.dex */
    public static class Config {
        public AlignMode align;
        public int defaultCullFace;
        public int defaultDepthFunc;
        public String fragmentShader;
        public boolean ignoreUnimplemented;
        public ParticleType type;
        public String vertexShader;

        public Config() {
            this.vertexShader = null;
            this.fragmentShader = null;
            this.ignoreUnimplemented = true;
            this.defaultCullFace = -1;
            this.defaultDepthFunc = -1;
            this.align = AlignMode.Screen;
            this.type = ParticleType.Billboard;
        }

        public Config(AlignMode align, ParticleType type) {
            this.vertexShader = null;
            this.fragmentShader = null;
            this.ignoreUnimplemented = true;
            this.defaultCullFace = -1;
            this.defaultDepthFunc = -1;
            this.align = AlignMode.Screen;
            this.type = ParticleType.Billboard;
            this.align = align;
            this.type = type;
        }

        public Config(AlignMode align) {
            this.vertexShader = null;
            this.fragmentShader = null;
            this.ignoreUnimplemented = true;
            this.defaultCullFace = -1;
            this.defaultDepthFunc = -1;
            this.align = AlignMode.Screen;
            this.type = ParticleType.Billboard;
            this.align = align;
        }

        public Config(ParticleType type) {
            this.vertexShader = null;
            this.fragmentShader = null;
            this.ignoreUnimplemented = true;
            this.defaultCullFace = -1;
            this.defaultDepthFunc = -1;
            this.align = AlignMode.Screen;
            this.type = ParticleType.Billboard;
            this.type = type;
        }

        public Config(String vertexShader, String fragmentShader) {
            this.vertexShader = null;
            this.fragmentShader = null;
            this.ignoreUnimplemented = true;
            this.defaultCullFace = -1;
            this.defaultDepthFunc = -1;
            this.align = AlignMode.Screen;
            this.type = ParticleType.Billboard;
            this.vertexShader = vertexShader;
            this.fragmentShader = fragmentShader;
        }
    }

    public static String getDefaultVertexShader() {
        if (defaultVertexShader == null) {
            defaultVertexShader = Gdx.files.classpath("com/badlogic/gdx/graphics/g3d/particles/particles.vertex.glsl").readString();
        }
        return defaultVertexShader;
    }

    public static String getDefaultFragmentShader() {
        if (defaultFragmentShader == null) {
            defaultFragmentShader = Gdx.files.classpath("com/badlogic/gdx/graphics/g3d/particles/particles.fragment.glsl").readString();
        }
        return defaultFragmentShader;
    }

    public ParticleShader(Renderable renderable) {
        this(renderable, new Config());
    }

    public ParticleShader(Renderable renderable, Config config) {
        this(renderable, config, createPrefix(renderable, config));
    }

    public ParticleShader(Renderable renderable, Config config, String prefix) {
        this(renderable, config, prefix, config.vertexShader != null ? config.vertexShader : getDefaultVertexShader(), config.fragmentShader != null ? config.fragmentShader : getDefaultFragmentShader());
    }

    public ParticleShader(Renderable renderable, Config config, String prefix, String vertexShader, String fragmentShader) {
        this(renderable, config, new ShaderProgram(prefix + vertexShader, prefix + fragmentShader));
    }

    public ParticleShader(Renderable renderable, Config config, ShaderProgram shaderProgram) {
        this.config = config;
        this.program = shaderProgram;
        this.renderable = renderable;
        this.materialMask = renderable.material.getMask() | optionalAttributes;
        this.vertexMask = renderable.meshPart.mesh.getVertexAttributes().getMask();
        if (!config.ignoreUnimplemented) {
            long j = implementedFlags;
            long j2 = this.materialMask;
            if ((j & j2) != j2) {
                throw new GdxRuntimeException("Some attributes not implemented yet (" + this.materialMask + ")");
            }
        }
        register(DefaultShader.Inputs.viewTrans, DefaultShader.Setters.viewTrans);
        register(DefaultShader.Inputs.projViewTrans, DefaultShader.Setters.projViewTrans);
        register(DefaultShader.Inputs.projTrans, DefaultShader.Setters.projTrans);
        register(Inputs.screenWidth, Setters.screenWidth);
        register(DefaultShader.Inputs.cameraUp, Setters.cameraUp);
        register(Inputs.cameraRight, Setters.cameraRight);
        register(Inputs.cameraInvDirection, Setters.cameraInvDirection);
        register(DefaultShader.Inputs.cameraPosition, Setters.cameraPosition);
        register(DefaultShader.Inputs.diffuseTexture, DefaultShader.Setters.diffuseTexture);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Shader
    public void init() {
        ShaderProgram program = this.program;
        this.program = null;
        init(program, this.renderable);
        this.renderable = null;
    }

    public static String createPrefix(Renderable renderable, Config config) {
        String prefix;
        if (Gdx.app.getType() == Application.ApplicationType.Desktop) {
            prefix = BuildConfig.FLAVOR + "#version 120\n";
        } else {
            prefix = BuildConfig.FLAVOR + "#version 100\n";
        }
        if (config.type == ParticleType.Billboard) {
            String prefix2 = prefix + "#define billboard\n";
            if (config.align == AlignMode.Screen) {
                return prefix2 + "#define screenFacing\n";
            } else if (config.align == AlignMode.ViewPoint) {
                return prefix2 + "#define viewPointFacing\n";
            } else {
                return prefix2;
            }
        }
        return prefix;
    }

    @Override // com.badlogic.gdx.graphics.g3d.Shader
    public boolean canRender(Renderable renderable) {
        return this.materialMask == (renderable.material.getMask() | optionalAttributes) && this.vertexMask == renderable.meshPart.mesh.getVertexAttributes().getMask();
    }

    @Override // com.badlogic.gdx.graphics.g3d.Shader
    public int compareTo(Shader other) {
        if (other == null) {
            return -1;
        }
        return other == this ? 0 : 0;
    }

    public boolean equals(Object obj) {
        return (obj instanceof ParticleShader) && equals((ParticleShader) obj);
    }

    public boolean equals(ParticleShader obj) {
        return obj == this;
    }

    @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader, com.badlogic.gdx.graphics.g3d.Shader
    public void begin(Camera camera, RenderContext context) {
        super.begin(camera, context);
    }

    @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader, com.badlogic.gdx.graphics.g3d.Shader
    public void render(Renderable renderable) {
        if (!renderable.material.has(BlendingAttribute.Type)) {
            this.context.setBlending(false, GL20.GL_SRC_ALPHA, GL20.GL_ONE_MINUS_SRC_ALPHA);
        }
        bindMaterial(renderable);
        super.render(renderable);
    }

    @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader, com.badlogic.gdx.graphics.g3d.Shader
    public void end() {
        this.currentMaterial = null;
        super.end();
    }

    protected void bindMaterial(Renderable renderable) {
        if (this.currentMaterial == renderable.material) {
            return;
        }
        int cullFace = this.config.defaultCullFace == -1 ? GL20.GL_BACK : this.config.defaultCullFace;
        int depthFunc = this.config.defaultDepthFunc == -1 ? GL20.GL_LEQUAL : this.config.defaultDepthFunc;
        float depthRangeNear = 0.0f;
        float depthRangeFar = 1.0f;
        boolean depthMask = true;
        this.currentMaterial = renderable.material;
        Iterator<Attribute> it = this.currentMaterial.iterator();
        while (it.hasNext()) {
            Attribute attr = it.next();
            long t = attr.type;
            if (BlendingAttribute.is(t)) {
                this.context.setBlending(true, ((BlendingAttribute) attr).sourceFunction, ((BlendingAttribute) attr).destFunction);
            } else if ((DepthTestAttribute.Type & t) == DepthTestAttribute.Type) {
                DepthTestAttribute dta = (DepthTestAttribute) attr;
                depthFunc = dta.depthFunc;
                depthRangeNear = dta.depthRangeNear;
                depthRangeFar = dta.depthRangeFar;
                depthMask = dta.depthMask;
            } else if (!this.config.ignoreUnimplemented) {
                throw new GdxRuntimeException("Unknown material attribute: " + attr.toString());
            }
        }
        this.context.setCullFace(cullFace);
        this.context.setDepthTest(depthFunc, depthRangeNear, depthRangeFar);
        this.context.setDepthMask(depthMask);
    }

    @Override // com.badlogic.gdx.graphics.g3d.shaders.BaseShader, com.badlogic.gdx.utils.Disposable
    public void dispose() {
        this.program.dispose();
        super.dispose();
    }

    public int getDefaultCullFace() {
        return this.config.defaultCullFace == -1 ? GL20.GL_BACK : this.config.defaultCullFace;
    }

    public void setDefaultCullFace(int cullFace) {
        this.config.defaultCullFace = cullFace;
    }

    public int getDefaultDepthFunc() {
        return this.config.defaultDepthFunc == -1 ? GL20.GL_LEQUAL : this.config.defaultDepthFunc;
    }

    public void setDefaultDepthFunc(int depthFunc) {
        this.config.defaultDepthFunc = depthFunc;
    }
}