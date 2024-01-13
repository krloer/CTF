package com.badlogic.gdx.graphics.g3d.model.data;

import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class ModelData {
    public String id;
    public final short[] version = new short[2];
    public final Array<ModelMesh> meshes = new Array<>();
    public final Array<ModelMaterial> materials = new Array<>();
    public final Array<ModelNode> nodes = new Array<>();
    public final Array<ModelAnimation> animations = new Array<>();

    public void addMesh(ModelMesh mesh) {
        Array.ArrayIterator<ModelMesh> it = this.meshes.iterator();
        while (it.hasNext()) {
            ModelMesh other = it.next();
            if (other.id.equals(mesh.id)) {
                throw new GdxRuntimeException("Mesh with id '" + other.id + "' already in model");
            }
        }
        this.meshes.add(mesh);
    }
}