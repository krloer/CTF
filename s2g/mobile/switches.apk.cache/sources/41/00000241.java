package com.badlogic.gdx.graphics.g3d.utils;

import com.badlogic.gdx.graphics.g3d.Renderable;
import com.badlogic.gdx.graphics.g3d.Shader;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public abstract class BaseShaderProvider implements ShaderProvider {
    protected Array<Shader> shaders = new Array<>();

    protected abstract Shader createShader(Renderable renderable);

    @Override // com.badlogic.gdx.graphics.g3d.utils.ShaderProvider
    public Shader getShader(Renderable renderable) {
        Shader suggestedShader = renderable.shader;
        if (suggestedShader == null || !suggestedShader.canRender(renderable)) {
            Array.ArrayIterator<Shader> it = this.shaders.iterator();
            while (it.hasNext()) {
                Shader shader = it.next();
                if (shader.canRender(renderable)) {
                    return shader;
                }
            }
            Shader shader2 = createShader(renderable);
            if (!shader2.canRender(renderable)) {
                throw new GdxRuntimeException("unable to provide a shader for this renderable");
            }
            shader2.init();
            this.shaders.add(shader2);
            return shader2;
        }
        return suggestedShader;
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        Array.ArrayIterator<Shader> it = this.shaders.iterator();
        while (it.hasNext()) {
            Shader shader = it.next();
            shader.dispose();
        }
        this.shaders.clear();
    }
}