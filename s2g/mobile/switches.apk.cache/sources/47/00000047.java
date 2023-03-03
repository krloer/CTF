package com.badlogic.gdx;

/* loaded from: classes.dex */
public class InputAdapter implements InputProcessor {
    @Override // com.badlogic.gdx.InputProcessor
    public boolean keyDown(int keycode) {
        return false;
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean keyUp(int keycode) {
        return false;
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean keyTyped(char character) {
        return false;
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean touchDown(int screenX, int screenY, int pointer, int button) {
        return false;
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean touchUp(int screenX, int screenY, int pointer, int button) {
        return false;
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean touchDragged(int screenX, int screenY, int pointer) {
        return false;
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean mouseMoved(int screenX, int screenY) {
        return false;
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean scrolled(float amountX, float amountY) {
        return false;
    }
}