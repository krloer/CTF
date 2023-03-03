package com.badlogic.gdx.assets.loaders;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.I18NBundle;
import java.util.Locale;

/* loaded from: classes.dex */
public class I18NBundleLoader extends AsynchronousAssetLoader<I18NBundle, I18NBundleParameter> {
    I18NBundle bundle;

    public I18NBundleLoader(FileHandleResolver resolver) {
        super(resolver);
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public void loadAsync(AssetManager manager, String fileName, FileHandle file, I18NBundleParameter parameter) {
        Locale locale;
        String encoding;
        this.bundle = null;
        if (parameter == null) {
            locale = Locale.getDefault();
            encoding = null;
        } else {
            Locale locale2 = parameter.locale;
            locale = locale2 == null ? Locale.getDefault() : parameter.locale;
            encoding = parameter.encoding;
        }
        if (encoding == null) {
            this.bundle = I18NBundle.createBundle(file, locale);
        } else {
            this.bundle = I18NBundle.createBundle(file, locale, encoding);
        }
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public I18NBundle loadSync(AssetManager manager, String fileName, FileHandle file, I18NBundleParameter parameter) {
        I18NBundle bundle = this.bundle;
        this.bundle = null;
        return bundle;
    }

    @Override // com.badlogic.gdx.assets.loaders.AssetLoader
    public Array<AssetDescriptor> getDependencies(String fileName, FileHandle file, I18NBundleParameter parameter) {
        return null;
    }

    /* loaded from: classes.dex */
    public static class I18NBundleParameter extends AssetLoaderParameters<I18NBundle> {
        public final String encoding;
        public final Locale locale;

        public I18NBundleParameter() {
            this(null, null);
        }

        public I18NBundleParameter(Locale locale) {
            this(locale, null);
        }

        public I18NBundleParameter(Locale locale, String encoding) {
            this.locale = locale;
            this.encoding = encoding;
        }
    }
}