package com.badlogic.gdx.physics.box2d;

import com.badlogic.gdx.utils.SharedLibraryLoader;

/* loaded from: classes.dex */
public final class Box2D {
    private Box2D() {
    }

    public static void init() {
        new SharedLibraryLoader().load("gdx-box2d");
    }
}