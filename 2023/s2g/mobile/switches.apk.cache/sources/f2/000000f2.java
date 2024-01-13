package com.badlogic.gdx.graphics;

import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Vector3;

/* loaded from: classes.dex */
public class PerspectiveCamera extends Camera {
    public float fieldOfView;
    final Vector3 tmp;

    public PerspectiveCamera() {
        this.fieldOfView = 67.0f;
        this.tmp = new Vector3();
    }

    public PerspectiveCamera(float fieldOfViewY, float viewportWidth, float viewportHeight) {
        this.fieldOfView = 67.0f;
        this.tmp = new Vector3();
        this.fieldOfView = fieldOfViewY;
        this.viewportWidth = viewportWidth;
        this.viewportHeight = viewportHeight;
        update();
    }

    @Override // com.badlogic.gdx.graphics.Camera
    public void update() {
        update(true);
    }

    @Override // com.badlogic.gdx.graphics.Camera
    public void update(boolean updateFrustum) {
        float aspect = this.viewportWidth / this.viewportHeight;
        this.projection.setToProjection(Math.abs(this.near), Math.abs(this.far), this.fieldOfView, aspect);
        this.view.setToLookAt(this.position, this.tmp.set(this.position).add(this.direction), this.up);
        this.combined.set(this.projection);
        Matrix4.mul(this.combined.val, this.view.val);
        if (updateFrustum) {
            this.invProjectionView.set(this.combined);
            Matrix4.inv(this.invProjectionView.val);
            this.frustum.update(this.invProjectionView);
        }
    }
}