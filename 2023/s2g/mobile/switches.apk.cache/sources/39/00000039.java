package com.badlogic.gdx;

/* loaded from: classes.dex */
public abstract class Game implements ApplicationListener {
    protected Screen screen;

    @Override // com.badlogic.gdx.ApplicationListener
    public void dispose() {
        Screen screen = this.screen;
        if (screen != null) {
            screen.hide();
        }
    }

    @Override // com.badlogic.gdx.ApplicationListener
    public void pause() {
        Screen screen = this.screen;
        if (screen != null) {
            screen.pause();
        }
    }

    @Override // com.badlogic.gdx.ApplicationListener
    public void resume() {
        Screen screen = this.screen;
        if (screen != null) {
            screen.resume();
        }
    }

    @Override // com.badlogic.gdx.ApplicationListener
    public void render() {
        Screen screen = this.screen;
        if (screen != null) {
            screen.render(Gdx.graphics.getDeltaTime());
        }
    }

    @Override // com.badlogic.gdx.ApplicationListener
    public void resize(int width, int height) {
        Screen screen = this.screen;
        if (screen != null) {
            screen.resize(width, height);
        }
    }

    public void setScreen(Screen screen) {
        Screen screen2 = this.screen;
        if (screen2 != null) {
            screen2.hide();
        }
        this.screen = screen;
        Screen screen3 = this.screen;
        if (screen3 != null) {
            screen3.show();
            this.screen.resize(Gdx.graphics.getWidth(), Gdx.graphics.getHeight());
        }
    }

    public Screen getScreen() {
        return this.screen;
    }
}