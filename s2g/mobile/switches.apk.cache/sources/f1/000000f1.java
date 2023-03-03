package com.badlogic.gdx.graphics;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.math.Vector3;

/* loaded from: classes.dex */
public class OrthographicCamera extends Camera {
    public float zoom = 1.0f;
    private final Vector3 tmp = new Vector3();

    public OrthographicCamera() {
        this.near = 0.0f;
    }

    public OrthographicCamera(float viewportWidth, float viewportHeight) {
        this.viewportWidth = viewportWidth;
        this.viewportHeight = viewportHeight;
        this.near = 0.0f;
        update();
    }

    @Override // com.badlogic.gdx.graphics.Camera
    public void update() {
        update(true);
    }

    @Override // com.badlogic.gdx.graphics.Camera
    public void update(boolean updateFrustum) {
        this.projection.setToOrtho((this.zoom * (-this.viewportWidth)) / 2.0f, this.zoom * (this.viewportWidth / 2.0f), this.zoom * (-(this.viewportHeight / 2.0f)), (this.zoom * this.viewportHeight) / 2.0f, this.near, this.far);
        this.view.setToLookAt(this.position, this.tmp.set(this.position).add(this.direction), this.up);
        this.combined.set(this.projection);
        Matrix4.mul(this.combined.val, this.view.val);
        if (updateFrustum) {
            this.invProjectionView.set(this.combined);
            Matrix4.inv(this.invProjectionView.val);
            this.frustum.update(this.invProjectionView);
        }
    }

    public void setToOrtho(boolean yDown) {
        setToOrtho(yDown, Gdx.graphics.getWidth(), Gdx.graphics.getHeight());
    }

    public void setToOrtho(boolean yDown, float viewportWidth, float viewportHeight) {
        if (yDown) {
            this.up.set(0.0f, -1.0f, 0.0f);
            this.direction.set(0.0f, 0.0f, 1.0f);
        } else {
            this.up.set(0.0f, 1.0f, 0.0f);
            this.direction.set(0.0f, 0.0f, -1.0f);
        }
        Vector3 vector3 = this.position;
        float f = this.zoom;
        vector3.set((f * viewportWidth) / 2.0f, (f * viewportHeight) / 2.0f, 0.0f);
        this.viewportWidth = viewportWidth;
        this.viewportHeight = viewportHeight;
        update();
    }

    public void rotate(float angle) {
        rotate(this.direction, angle);
    }

    public void translate(float x, float y) {
        translate(x, y, 0.0f);
    }

    public void translate(Vector2 vec) {
        translate(vec.x, vec.y, 0.0f);
    }
}