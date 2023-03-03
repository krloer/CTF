package com.badlogic.gdx.assets.loaders.resolvers;

import com.badlogic.gdx.assets.loaders.FileHandleResolver;
import com.badlogic.gdx.files.FileHandle;

/* loaded from: classes.dex */
public class PrefixFileHandleResolver implements FileHandleResolver {
    private FileHandleResolver baseResolver;
    private String prefix;

    public PrefixFileHandleResolver(FileHandleResolver baseResolver, String prefix) {
        this.baseResolver = baseResolver;
        this.prefix = prefix;
    }

    public void setBaseResolver(FileHandleResolver baseResolver) {
        this.baseResolver = baseResolver;
    }

    public FileHandleResolver getBaseResolver() {
        return this.baseResolver;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    public String getPrefix() {
        return this.prefix;
    }

    @Override // com.badlogic.gdx.assets.loaders.FileHandleResolver
    public FileHandle resolve(String fileName) {
        FileHandleResolver fileHandleResolver = this.baseResolver;
        return fileHandleResolver.resolve(this.prefix + fileName);
    }
}