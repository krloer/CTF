package com.badlogic.gdx.graphics.g3d.model;

import com.badlogic.gdx.graphics.g3d.Material;
import com.badlogic.gdx.graphics.g3d.Renderable;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.utils.ArrayMap;

/* loaded from: classes.dex */
public class NodePart {
    public Matrix4[] bones;
    public boolean enabled = true;
    public ArrayMap<Node, Matrix4> invBoneBindTransforms;
    public Material material;
    public MeshPart meshPart;

    public NodePart() {
    }

    public NodePart(MeshPart meshPart, Material material) {
        this.meshPart = meshPart;
        this.material = material;
    }

    public Renderable setRenderable(Renderable out) {
        out.material = this.material;
        out.meshPart.set(this.meshPart);
        out.bones = this.bones;
        return out;
    }

    public NodePart copy() {
        return new NodePart().set(this);
    }

    protected NodePart set(NodePart other) {
        this.meshPart = new MeshPart(other.meshPart);
        this.material = other.material;
        this.enabled = other.enabled;
        ArrayMap<Node, Matrix4> arrayMap = other.invBoneBindTransforms;
        if (arrayMap == null) {
            this.invBoneBindTransforms = null;
            this.bones = null;
        } else {
            ArrayMap<Node, Matrix4> arrayMap2 = this.invBoneBindTransforms;
            if (arrayMap2 == null) {
                this.invBoneBindTransforms = new ArrayMap<>(true, arrayMap.size, Node.class, Matrix4.class);
            } else {
                arrayMap2.clear();
            }
            this.invBoneBindTransforms.putAll(other.invBoneBindTransforms);
            Matrix4[] matrix4Arr = this.bones;
            if (matrix4Arr == null || matrix4Arr.length != this.invBoneBindTransforms.size) {
                this.bones = new Matrix4[this.invBoneBindTransforms.size];
            }
            int i = 0;
            while (true) {
                Matrix4[] matrix4Arr2 = this.bones;
                if (i >= matrix4Arr2.length) {
                    break;
                }
                if (matrix4Arr2[i] == null) {
                    matrix4Arr2[i] = new Matrix4();
                }
                i++;
            }
        }
        return this;
    }
}