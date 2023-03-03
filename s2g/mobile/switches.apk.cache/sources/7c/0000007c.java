package com.badlogic.gdx.assets.loaders.resolvers;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.assets.loaders.FileHandleResolver;
import com.badlogic.gdx.files.FileHandle;

/* loaded from: classes.dex */
public class ClasspathFileHandleResolver implements FileHandleResolver {
    @Override // com.badlogic.gdx.assets.loaders.FileHandleResolver
    public FileHandle resolve(String fileName) {
        return Gdx.files.classpath(fileName);
    }
}