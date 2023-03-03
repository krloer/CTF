package com.badlogic.gdx.graphics.g3d.utils;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.g3d.Renderable;
import com.badlogic.gdx.graphics.g3d.Shader;
import com.badlogic.gdx.graphics.g3d.shaders.DefaultShader;

/* loaded from: classes.dex */
public class DefaultShaderProvider extends BaseShaderProvider {
    public final DefaultShader.Config config;

    public DefaultShaderProvider(DefaultShader.Config config) {
        this.config = config == null ? new DefaultShader.Config() : config;
    }

    public DefaultShaderProvider(String vertexShader, String fragmentShader) {
        this(new DefaultShader.Config(vertexShader, fragmentShader));
    }

    public DefaultShaderProvider(FileHandle vertexShader, FileHandle fragmentShader) {
        this(vertexShader.readString(), fragmentShader.readString());
    }

    public DefaultShaderProvider() {
        this(null);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.BaseShaderProvider
    protected Shader createShader(Renderable renderable) {
        return new DefaultShader(renderable, this.config);
    }
}