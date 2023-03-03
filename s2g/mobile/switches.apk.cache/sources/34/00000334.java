package com.badlogic.gdx.physics.box2d;

/* loaded from: classes.dex */
public class Filter {
    public short categoryBits = 1;
    public short maskBits = -1;
    public short groupIndex = 0;

    public void set(Filter filter) {
        this.categoryBits = filter.categoryBits;
        this.maskBits = filter.maskBits;
        this.groupIndex = filter.groupIndex;
    }
}