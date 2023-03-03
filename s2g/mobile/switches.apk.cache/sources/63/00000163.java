package com.badlogic.gdx.graphics.g3d;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.graphics.g3d.utils.DefaultRenderableSorter;
import com.badlogic.gdx.graphics.g3d.utils.DefaultShaderProvider;
import com.badlogic.gdx.graphics.g3d.utils.DefaultTextureBinder;
import com.badlogic.gdx.graphics.g3d.utils.RenderContext;
import com.badlogic.gdx.graphics.g3d.utils.RenderableSorter;
import com.badlogic.gdx.graphics.g3d.utils.ShaderProvider;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.FlushablePool;
import com.badlogic.gdx.utils.GdxRuntimeException;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class ModelBatch implements Disposable {
    protected Camera camera;
    protected final RenderContext context;
    private final boolean ownContext;
    protected final Array<Renderable> renderables;
    protected final RenderablePool renderablesPool;
    protected final ShaderProvider shaderProvider;
    protected final RenderableSorter sorter;

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: classes.dex */
    public static class RenderablePool extends FlushablePool<Renderable> {
        protected RenderablePool() {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.badlogic.gdx.utils.Pool
        public Renderable newObject() {
            return new Renderable();
        }

        @Override // com.badlogic.gdx.utils.FlushablePool, com.badlogic.gdx.utils.Pool
        public Renderable obtain() {
            Renderable renderable = (Renderable) super.obtain();
            renderable.environment = null;
            renderable.material = null;
            renderable.meshPart.set(BuildConfig.FLAVOR, null, 0, 0, 0);
            renderable.shader = null;
            renderable.userData = null;
            return renderable;
        }
    }

    public ModelBatch(RenderContext context, ShaderProvider shaderProvider, RenderableSorter sorter) {
        this.renderablesPool = new RenderablePool();
        this.renderables = new Array<>();
        this.sorter = sorter == null ? new DefaultRenderableSorter() : sorter;
        this.ownContext = context == null;
        this.context = context == null ? new RenderContext(new DefaultTextureBinder(1, 1)) : context;
        this.shaderProvider = shaderProvider == null ? new DefaultShaderProvider() : shaderProvider;
    }

    public ModelBatch(RenderContext context, ShaderProvider shaderProvider) {
        this(context, shaderProvider, null);
    }

    public ModelBatch(RenderContext context, RenderableSorter sorter) {
        this(context, null, sorter);
    }

    public ModelBatch(RenderContext context) {
        this(context, null, null);
    }

    public ModelBatch(ShaderProvider shaderProvider, RenderableSorter sorter) {
        this(null, shaderProvider, sorter);
    }

    public ModelBatch(RenderableSorter sorter) {
        this(null, null, sorter);
    }

    public ModelBatch(ShaderProvider shaderProvider) {
        this(null, shaderProvider, null);
    }

    public ModelBatch(FileHandle vertexShader, FileHandle fragmentShader) {
        this(null, new DefaultShaderProvider(vertexShader, fragmentShader), null);
    }

    public ModelBatch(String vertexShader, String fragmentShader) {
        this(null, new DefaultShaderProvider(vertexShader, fragmentShader), null);
    }

    public ModelBatch() {
        this(null, null, null);
    }

    public void begin(Camera cam) {
        if (this.camera != null) {
            throw new GdxRuntimeException("Call end() first.");
        }
        this.camera = cam;
        if (this.ownContext) {
            this.context.begin();
        }
    }

    public void setCamera(Camera cam) {
        if (this.camera == null) {
            throw new GdxRuntimeException("Call begin() first.");
        }
        if (this.renderables.size > 0) {
            flush();
        }
        this.camera = cam;
    }

    public Camera getCamera() {
        return this.camera;
    }

    public boolean ownsRenderContext() {
        return this.ownContext;
    }

    public RenderContext getRenderContext() {
        return this.context;
    }

    public ShaderProvider getShaderProvider() {
        return this.shaderProvider;
    }

    public RenderableSorter getRenderableSorter() {
        return this.sorter;
    }

    public void flush() {
        this.sorter.sort(this.camera, this.renderables);
        Shader currentShader = null;
        for (int i = 0; i < this.renderables.size; i++) {
            Renderable renderable = this.renderables.get(i);
            if (currentShader != renderable.shader) {
                if (currentShader != null) {
                    currentShader.end();
                }
                currentShader = renderable.shader;
                currentShader.begin(this.camera, this.context);
            }
            currentShader.render(renderable);
        }
        if (currentShader != null) {
            currentShader.end();
        }
        this.renderablesPool.flush();
        this.renderables.clear();
    }

    public void end() {
        flush();
        if (this.ownContext) {
            this.context.end();
        }
        this.camera = null;
    }

    public void render(Renderable renderable) {
        renderable.shader = this.shaderProvider.getShader(renderable);
        this.renderables.add(renderable);
    }

    public void render(RenderableProvider renderableProvider) {
        int offset = this.renderables.size;
        renderableProvider.getRenderables(this.renderables, this.renderablesPool);
        for (int i = offset; i < this.renderables.size; i++) {
            Renderable renderable = this.renderables.get(i);
            renderable.shader = this.shaderProvider.getShader(renderable);
        }
    }

    public <T extends RenderableProvider> void render(Iterable<T> renderableProviders) {
        for (RenderableProvider renderableProvider : renderableProviders) {
            render(renderableProvider);
        }
    }

    public void render(RenderableProvider renderableProvider, Environment environment) {
        int offset = this.renderables.size;
        renderableProvider.getRenderables(this.renderables, this.renderablesPool);
        for (int i = offset; i < this.renderables.size; i++) {
            Renderable renderable = this.renderables.get(i);
            renderable.environment = environment;
            renderable.shader = this.shaderProvider.getShader(renderable);
        }
    }

    public <T extends RenderableProvider> void render(Iterable<T> renderableProviders, Environment environment) {
        for (RenderableProvider renderableProvider : renderableProviders) {
            render(renderableProvider, environment);
        }
    }

    public void render(RenderableProvider renderableProvider, Shader shader) {
        int offset = this.renderables.size;
        renderableProvider.getRenderables(this.renderables, this.renderablesPool);
        for (int i = offset; i < this.renderables.size; i++) {
            Renderable renderable = this.renderables.get(i);
            renderable.shader = shader;
            renderable.shader = this.shaderProvider.getShader(renderable);
        }
    }

    public <T extends RenderableProvider> void render(Iterable<T> renderableProviders, Shader shader) {
        for (RenderableProvider renderableProvider : renderableProviders) {
            render(renderableProvider, shader);
        }
    }

    public void render(RenderableProvider renderableProvider, Environment environment, Shader shader) {
        int offset = this.renderables.size;
        renderableProvider.getRenderables(this.renderables, this.renderablesPool);
        for (int i = offset; i < this.renderables.size; i++) {
            Renderable renderable = this.renderables.get(i);
            renderable.environment = environment;
            renderable.shader = shader;
            renderable.shader = this.shaderProvider.getShader(renderable);
        }
    }

    public <T extends RenderableProvider> void render(Iterable<T> renderableProviders, Environment environment, Shader shader) {
        for (RenderableProvider renderableProvider : renderableProviders) {
            render(renderableProvider, environment, shader);
        }
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        this.shaderProvider.dispose();
    }
}