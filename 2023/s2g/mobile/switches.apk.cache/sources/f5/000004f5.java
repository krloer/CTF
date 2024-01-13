package com.badlogic.gdx.utils.viewport;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.graphics.glutils.HdpiUtils;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.math.collision.Ray;
import com.badlogic.gdx.scenes.scene2d.utils.ScissorStack;

/* loaded from: classes.dex */
public abstract class Viewport {
    private Camera camera;
    private int screenHeight;
    private int screenWidth;
    private int screenX;
    private int screenY;
    private final Vector3 tmp = new Vector3();
    private float worldHeight;
    private float worldWidth;

    public void apply() {
        apply(false);
    }

    public void apply(boolean centerCamera) {
        HdpiUtils.glViewport(this.screenX, this.screenY, this.screenWidth, this.screenHeight);
        Camera camera = this.camera;
        camera.viewportWidth = this.worldWidth;
        camera.viewportHeight = this.worldHeight;
        if (centerCamera) {
            camera.position.set(this.worldWidth / 2.0f, this.worldHeight / 2.0f, 0.0f);
        }
        this.camera.update();
    }

    public final void update(int screenWidth, int screenHeight) {
        update(screenWidth, screenHeight, false);
    }

    public void update(int screenWidth, int screenHeight, boolean centerCamera) {
        apply(centerCamera);
    }

    public Vector2 unproject(Vector2 screenCoords) {
        this.tmp.set(screenCoords.x, screenCoords.y, 1.0f);
        this.camera.unproject(this.tmp, this.screenX, this.screenY, this.screenWidth, this.screenHeight);
        screenCoords.set(this.tmp.x, this.tmp.y);
        return screenCoords;
    }

    public Vector2 project(Vector2 worldCoords) {
        this.tmp.set(worldCoords.x, worldCoords.y, 1.0f);
        this.camera.project(this.tmp, this.screenX, this.screenY, this.screenWidth, this.screenHeight);
        worldCoords.set(this.tmp.x, this.tmp.y);
        return worldCoords;
    }

    public Vector3 unproject(Vector3 screenCoords) {
        this.camera.unproject(screenCoords, this.screenX, this.screenY, this.screenWidth, this.screenHeight);
        return screenCoords;
    }

    public Vector3 project(Vector3 worldCoords) {
        this.camera.project(worldCoords, this.screenX, this.screenY, this.screenWidth, this.screenHeight);
        return worldCoords;
    }

    public Ray getPickRay(float screenX, float screenY) {
        return this.camera.getPickRay(screenX, screenY, this.screenX, this.screenY, this.screenWidth, this.screenHeight);
    }

    public void calculateScissors(Matrix4 batchTransform, Rectangle area, Rectangle scissor) {
        ScissorStack.calculateScissors(this.camera, this.screenX, this.screenY, this.screenWidth, this.screenHeight, batchTransform, area, scissor);
    }

    public Vector2 toScreenCoordinates(Vector2 worldCoords, Matrix4 transformMatrix) {
        this.tmp.set(worldCoords.x, worldCoords.y, 0.0f);
        this.tmp.mul(transformMatrix);
        this.camera.project(this.tmp, this.screenX, this.screenY, this.screenWidth, this.screenHeight);
        this.tmp.y = Gdx.graphics.getHeight() - this.tmp.y;
        worldCoords.x = this.tmp.x;
        worldCoords.y = this.tmp.y;
        return worldCoords;
    }

    public Camera getCamera() {
        return this.camera;
    }

    public void setCamera(Camera camera) {
        this.camera = camera;
    }

    public float getWorldWidth() {
        return this.worldWidth;
    }

    public void setWorldWidth(float worldWidth) {
        this.worldWidth = worldWidth;
    }

    public float getWorldHeight() {
        return this.worldHeight;
    }

    public void setWorldHeight(float worldHeight) {
        this.worldHeight = worldHeight;
    }

    public void setWorldSize(float worldWidth, float worldHeight) {
        this.worldWidth = worldWidth;
        this.worldHeight = worldHeight;
    }

    public int getScreenX() {
        return this.screenX;
    }

    public void setScreenX(int screenX) {
        this.screenX = screenX;
    }

    public int getScreenY() {
        return this.screenY;
    }

    public void setScreenY(int screenY) {
        this.screenY = screenY;
    }

    public int getScreenWidth() {
        return this.screenWidth;
    }

    public void setScreenWidth(int screenWidth) {
        this.screenWidth = screenWidth;
    }

    public int getScreenHeight() {
        return this.screenHeight;
    }

    public void setScreenHeight(int screenHeight) {
        this.screenHeight = screenHeight;
    }

    public void setScreenPosition(int screenX, int screenY) {
        this.screenX = screenX;
        this.screenY = screenY;
    }

    public void setScreenSize(int screenWidth, int screenHeight) {
        this.screenWidth = screenWidth;
        this.screenHeight = screenHeight;
    }

    public void setScreenBounds(int screenX, int screenY, int screenWidth, int screenHeight) {
        this.screenX = screenX;
        this.screenY = screenY;
        this.screenWidth = screenWidth;
        this.screenHeight = screenHeight;
    }

    public int getLeftGutterWidth() {
        return this.screenX;
    }

    public int getRightGutterX() {
        return this.screenX + this.screenWidth;
    }

    public int getRightGutterWidth() {
        return Gdx.graphics.getWidth() - (this.screenX + this.screenWidth);
    }

    public int getBottomGutterHeight() {
        return this.screenY;
    }

    public int getTopGutterY() {
        return this.screenY + this.screenHeight;
    }

    public int getTopGutterHeight() {
        return Gdx.graphics.getHeight() - (this.screenY + this.screenHeight);
    }
}