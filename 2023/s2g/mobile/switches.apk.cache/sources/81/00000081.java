package com.badlogic.gdx.assets.loaders.resolvers;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.assets.loaders.FileHandleResolver;
import com.badlogic.gdx.files.FileHandle;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class ResolutionFileResolver implements FileHandleResolver {
    protected final FileHandleResolver baseResolver;
    protected final Resolution[] descriptors;

    /* loaded from: classes.dex */
    public static class Resolution {
        public final String folder;
        public final int portraitHeight;
        public final int portraitWidth;

        public Resolution(int portraitWidth, int portraitHeight, String folder) {
            this.portraitWidth = portraitWidth;
            this.portraitHeight = portraitHeight;
            this.folder = folder;
        }
    }

    public ResolutionFileResolver(FileHandleResolver baseResolver, Resolution... descriptors) {
        if (descriptors.length == 0) {
            throw new IllegalArgumentException("At least one Resolution needs to be supplied.");
        }
        this.baseResolver = baseResolver;
        this.descriptors = descriptors;
    }

    @Override // com.badlogic.gdx.assets.loaders.FileHandleResolver
    public FileHandle resolve(String fileName) {
        Resolution bestResolution = choose(this.descriptors);
        FileHandle originalHandle = new FileHandle(fileName);
        FileHandle handle = this.baseResolver.resolve(resolve(originalHandle, bestResolution.folder));
        return !handle.exists() ? this.baseResolver.resolve(fileName) : handle;
    }

    protected String resolve(FileHandle originalHandle, String suffix) {
        String parentString = BuildConfig.FLAVOR;
        FileHandle parent = originalHandle.parent();
        if (parent != null && !parent.name().equals(BuildConfig.FLAVOR)) {
            parentString = parent + "/";
        }
        return parentString + suffix + "/" + originalHandle.name();
    }

    public static Resolution choose(Resolution... descriptors) {
        int w = Gdx.graphics.getBackBufferWidth();
        int h = Gdx.graphics.getBackBufferHeight();
        Resolution best = descriptors[0];
        if (w < h) {
            int n = descriptors.length;
            for (int i = 0; i < n; i++) {
                Resolution other = descriptors[i];
                if (w >= other.portraitWidth && other.portraitWidth >= best.portraitWidth && h >= other.portraitHeight && other.portraitHeight >= best.portraitHeight) {
                    best = descriptors[i];
                }
            }
        } else {
            int n2 = descriptors.length;
            for (int i2 = 0; i2 < n2; i2++) {
                Resolution other2 = descriptors[i2];
                if (w >= other2.portraitHeight && other2.portraitHeight >= best.portraitHeight && h >= other2.portraitWidth && other2.portraitWidth >= best.portraitWidth) {
                    best = descriptors[i2];
                }
            }
        }
        return best;
    }
}