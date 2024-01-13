package com.badlogic.gdx.graphics.g3d.utils;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.InputAdapter;
import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.IntIntMap;

/* loaded from: classes.dex */
public class FirstPersonCameraController extends InputAdapter {
    private final Camera camera;
    private final IntIntMap keys = new IntIntMap();
    private int STRAFE_LEFT = 29;
    private int STRAFE_RIGHT = 32;
    private int FORWARD = 51;
    private int BACKWARD = 47;
    private int UP = 45;
    private int DOWN = 33;
    private float velocity = 5.0f;
    private float degreesPerPixel = 0.5f;
    private final Vector3 tmp = new Vector3();

    public FirstPersonCameraController(Camera camera) {
        this.camera = camera;
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean keyDown(int keycode) {
        this.keys.put(keycode, keycode);
        return true;
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean keyUp(int keycode) {
        this.keys.remove(keycode, 0);
        return true;
    }

    public void setVelocity(float velocity) {
        this.velocity = velocity;
    }

    public void setDegreesPerPixel(float degreesPerPixel) {
        this.degreesPerPixel = degreesPerPixel;
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean touchDragged(int screenX, int screenY, int pointer) {
        float deltaX = (-Gdx.input.getDeltaX()) * this.degreesPerPixel;
        float deltaY = (-Gdx.input.getDeltaY()) * this.degreesPerPixel;
        this.camera.direction.rotate(this.camera.up, deltaX);
        this.tmp.set(this.camera.direction).crs(this.camera.up).nor();
        this.camera.direction.rotate(this.tmp, deltaY);
        return true;
    }

    public void update() {
        update(Gdx.graphics.getDeltaTime());
    }

    public void update(float deltaTime) {
        if (this.keys.containsKey(this.FORWARD)) {
            this.tmp.set(this.camera.direction).nor().scl(this.velocity * deltaTime);
            this.camera.position.add(this.tmp);
        }
        if (this.keys.containsKey(this.BACKWARD)) {
            this.tmp.set(this.camera.direction).nor().scl((-deltaTime) * this.velocity);
            this.camera.position.add(this.tmp);
        }
        if (this.keys.containsKey(this.STRAFE_LEFT)) {
            this.tmp.set(this.camera.direction).crs(this.camera.up).nor().scl((-deltaTime) * this.velocity);
            this.camera.position.add(this.tmp);
        }
        if (this.keys.containsKey(this.STRAFE_RIGHT)) {
            this.tmp.set(this.camera.direction).crs(this.camera.up).nor().scl(this.velocity * deltaTime);
            this.camera.position.add(this.tmp);
        }
        if (this.keys.containsKey(this.UP)) {
            this.tmp.set(this.camera.up).nor().scl(this.velocity * deltaTime);
            this.camera.position.add(this.tmp);
        }
        if (this.keys.containsKey(this.DOWN)) {
            this.tmp.set(this.camera.up).nor().scl((-deltaTime) * this.velocity);
            this.camera.position.add(this.tmp);
        }
        this.camera.update(true);
    }
}