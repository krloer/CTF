package com.badlogic.gdx;

import com.badlogic.gdx.utils.IntSet;

/* loaded from: classes.dex */
public abstract class AbstractInput implements Input {
    protected boolean keyJustPressed;
    protected int pressedKeyCount;
    private final IntSet keysToCatch = new IntSet();
    protected final boolean[] pressedKeys = new boolean[256];
    protected final boolean[] justPressedKeys = new boolean[256];

    @Override // com.badlogic.gdx.Input
    public boolean isKeyPressed(int key) {
        if (key == -1) {
            return this.pressedKeyCount > 0;
        } else if (key < 0 || key > 255) {
            return false;
        } else {
            return this.pressedKeys[key];
        }
    }

    @Override // com.badlogic.gdx.Input
    public boolean isKeyJustPressed(int key) {
        if (key == -1) {
            return this.keyJustPressed;
        }
        if (key < 0 || key > 255) {
            return false;
        }
        return this.justPressedKeys[key];
    }

    @Override // com.badlogic.gdx.Input
    public boolean isCatchBackKey() {
        return this.keysToCatch.contains(4);
    }

    @Override // com.badlogic.gdx.Input
    public void setCatchBackKey(boolean catchBack) {
        setCatchKey(4, catchBack);
    }

    @Override // com.badlogic.gdx.Input
    public boolean isCatchMenuKey() {
        return this.keysToCatch.contains(82);
    }

    @Override // com.badlogic.gdx.Input
    public void setCatchMenuKey(boolean catchMenu) {
        setCatchKey(82, catchMenu);
    }

    @Override // com.badlogic.gdx.Input
    public void setCatchKey(int keycode, boolean catchKey) {
        if (!catchKey) {
            this.keysToCatch.remove(keycode);
        } else {
            this.keysToCatch.add(keycode);
        }
    }

    @Override // com.badlogic.gdx.Input
    public boolean isCatchKey(int keycode) {
        return this.keysToCatch.contains(keycode);
    }
}