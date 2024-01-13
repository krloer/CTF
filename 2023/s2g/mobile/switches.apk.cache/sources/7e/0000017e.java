package com.badlogic.gdx.graphics.g3d.decals;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Mesh;
import com.badlogic.gdx.graphics.VertexAttribute;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.Pool;
import com.badlogic.gdx.utils.SortedIntList;
import java.util.Iterator;

/* loaded from: classes.dex */
public class DecalBatch implements Disposable {
    private static final int DEFAULT_SIZE = 1000;
    private final SortedIntList<Array<Decal>> groupList;
    private final Pool<Array<Decal>> groupPool;
    private GroupStrategy groupStrategy;
    private Mesh mesh;
    private final Array<Array<Decal>> usedGroups;
    private float[] vertices;

    public DecalBatch(GroupStrategy groupStrategy) {
        this(DEFAULT_SIZE, groupStrategy);
    }

    public DecalBatch(int size, GroupStrategy groupStrategy) {
        this.groupList = new SortedIntList<>();
        this.groupPool = new Pool<Array<Decal>>(16) { // from class: com.badlogic.gdx.graphics.g3d.decals.DecalBatch.1
            /* JADX INFO: Access modifiers changed from: protected */
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // com.badlogic.gdx.utils.Pool
            public Array<Decal> newObject() {
                return new Array<>(false, 100);
            }
        };
        this.usedGroups = new Array<>(16);
        initialize(size);
        setGroupStrategy(groupStrategy);
    }

    public void setGroupStrategy(GroupStrategy groupStrategy) {
        this.groupStrategy = groupStrategy;
    }

    public void initialize(int size) {
        this.vertices = new float[size * 24];
        Mesh.VertexDataType vertexDataType = Mesh.VertexDataType.VertexArray;
        if (Gdx.gl30 != null) {
            vertexDataType = Mesh.VertexDataType.VertexBufferObjectWithVAO;
        }
        this.mesh = new Mesh(vertexDataType, false, size * 4, size * 6, new VertexAttribute(1, 3, ShaderProgram.POSITION_ATTRIBUTE), new VertexAttribute(4, 4, ShaderProgram.COLOR_ATTRIBUTE), new VertexAttribute(16, 2, "a_texCoord0"));
        short[] indices = new short[size * 6];
        int v = 0;
        int i = 0;
        while (i < indices.length) {
            indices[i] = (short) v;
            indices[i + 1] = (short) (v + 2);
            indices[i + 2] = (short) (v + 1);
            indices[i + 3] = (short) (v + 1);
            indices[i + 4] = (short) (v + 2);
            indices[i + 5] = (short) (v + 3);
            i += 6;
            v += 4;
        }
        this.mesh.setIndices(indices);
    }

    public int getSize() {
        return this.vertices.length / 24;
    }

    public void add(Decal decal) {
        int groupIndex = this.groupStrategy.decideGroup(decal);
        Array<Decal> targetGroup = this.groupList.get(groupIndex);
        if (targetGroup == null) {
            targetGroup = this.groupPool.obtain();
            targetGroup.clear();
            this.usedGroups.add(targetGroup);
            this.groupList.insert(groupIndex, targetGroup);
        }
        targetGroup.add(decal);
    }

    public void flush() {
        render();
        clear();
    }

    protected void render() {
        this.groupStrategy.beforeGroups();
        Iterator<SortedIntList.Node<Array<Decal>>> it = this.groupList.iterator();
        while (it.hasNext()) {
            SortedIntList.Node<Array<Decal>> group = it.next();
            this.groupStrategy.beforeGroup(group.index, group.value);
            ShaderProgram shader = this.groupStrategy.getGroupShader(group.index);
            render(shader, group.value);
            this.groupStrategy.afterGroup(group.index);
        }
        this.groupStrategy.afterGroups();
    }

    private void render(ShaderProgram shader, Array<Decal> decals) {
        DecalMaterial lastMaterial = null;
        int idx = 0;
        Array.ArrayIterator<Decal> it = decals.iterator();
        while (it.hasNext()) {
            Decal decal = it.next();
            if (lastMaterial == null || !lastMaterial.equals(decal.getMaterial())) {
                if (idx > 0) {
                    flush(shader, idx);
                    idx = 0;
                }
                decal.material.set();
                lastMaterial = decal.material;
            }
            decal.update();
            System.arraycopy(decal.vertices, 0, this.vertices, idx, decal.vertices.length);
            idx += decal.vertices.length;
            if (idx == this.vertices.length) {
                flush(shader, idx);
                idx = 0;
            }
        }
        if (idx > 0) {
            flush(shader, idx);
        }
    }

    protected void flush(ShaderProgram shader, int verticesPosition) {
        this.mesh.setVertices(this.vertices, 0, verticesPosition);
        this.mesh.render(shader, 4, 0, verticesPosition / 4);
    }

    protected void clear() {
        this.groupList.clear();
        this.groupPool.freeAll(this.usedGroups);
        this.usedGroups.clear();
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        clear();
        this.vertices = null;
        this.mesh.dispose();
    }
}