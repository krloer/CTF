package com.badlogic.gdx.utils;

/* loaded from: classes.dex */
public class GdxNativesLoader {
    public static boolean disableNativesLoading = false;
    private static boolean nativesLoaded;

    public static synchronized void load() {
        synchronized (GdxNativesLoader.class) {
            if (nativesLoaded) {
                return;
            }
            nativesLoaded = true;
            if (disableNativesLoading) {
                return;
            }
            new SharedLibraryLoader().load("gdx");
        }
    }
}