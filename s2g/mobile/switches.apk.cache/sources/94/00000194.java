package com.badlogic.gdx.graphics.g3d.model;

import com.badlogic.gdx.graphics.Mesh;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.math.collision.BoundingBox;

/* loaded from: classes.dex */
public class MeshPart {
    private static final BoundingBox bounds = new BoundingBox();
    public String id;
    public Mesh mesh;
    public int offset;
    public int primitiveType;
    public int size;
    public final Vector3 center = new Vector3();
    public final Vector3 halfExtents = new Vector3();
    public float radius = -1.0f;

    public MeshPart() {
    }

    public MeshPart(String id, Mesh mesh, int offset, int size, int type) {
        set(id, mesh, offset, size, type);
    }

    public MeshPart(MeshPart copyFrom) {
        set(copyFrom);
    }

    public MeshPart set(MeshPart other) {
        this.id = other.id;
        this.mesh = other.mesh;
        this.offset = other.offset;
        this.size = other.size;
        this.primitiveType = other.primitiveType;
        this.center.set(other.center);
        this.halfExtents.set(other.halfExtents);
        this.radius = other.radius;
        return this;
    }

    public MeshPart set(String id, Mesh mesh, int offset, int size, int type) {
        this.id = id;
        this.mesh = mesh;
        this.offset = offset;
        this.size = size;
        this.primitiveType = type;
        this.center.set(0.0f, 0.0f, 0.0f);
        this.halfExtents.set(0.0f, 0.0f, 0.0f);
        this.radius = -1.0f;
        return this;
    }

    public void update() {
        this.mesh.calculateBoundingBox(bounds, this.offset, this.size);
        bounds.getCenter(this.center);
        bounds.getDimensions(this.halfExtents).scl(0.5f);
        this.radius = this.halfExtents.len();
    }

    public boolean equals(MeshPart other) {
        return other == this || (other != null && other.mesh == this.mesh && other.primitiveType == this.primitiveType && other.offset == this.offset && other.size == this.size);
    }

    public boolean equals(Object arg0) {
        if (arg0 == null) {
            return false;
        }
        if (arg0 == this) {
            return true;
        }
        if (!(arg0 instanceof MeshPart)) {
            return false;
        }
        return equals((MeshPart) arg0);
    }

    public void render(ShaderProgram shader, boolean autoBind) {
        this.mesh.render(shader, this.primitiveType, this.offset, this.size, autoBind);
    }

    public void render(ShaderProgram shader) {
        this.mesh.render(shader, this.primitiveType, this.offset, this.size);
    }
}