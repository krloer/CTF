package com.badlogic.gdx.graphics.g3d.decals;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.ObjectMap;
import com.badlogic.gdx.utils.Pool;
import java.util.Comparator;

/* loaded from: classes.dex */
public class CameraGroupStrategy implements GroupStrategy, Disposable {
    private static final int GROUP_BLEND = 1;
    private static final int GROUP_OPAQUE = 0;
    Pool<Array<Decal>> arrayPool;
    Camera camera;
    private final Comparator<Decal> cameraSorter;
    ObjectMap<DecalMaterial, Array<Decal>> materialGroups;
    ShaderProgram shader;
    Array<Array<Decal>> usedArrays;

    public CameraGroupStrategy(final Camera camera) {
        this(camera, new Comparator<Decal>() { // from class: com.badlogic.gdx.graphics.g3d.decals.CameraGroupStrategy.2
            @Override // java.util.Comparator
            public int compare(Decal o1, Decal o2) {
                float dist1 = Camera.this.position.dst(o1.position);
                float dist2 = Camera.this.position.dst(o2.position);
                return (int) Math.signum(dist2 - dist1);
            }
        });
    }

    public CameraGroupStrategy(Camera camera, Comparator<Decal> sorter) {
        this.arrayPool = new Pool<Array<Decal>>(16) { // from class: com.badlogic.gdx.graphics.g3d.decals.CameraGroupStrategy.1
            /* JADX INFO: Access modifiers changed from: protected */
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // com.badlogic.gdx.utils.Pool
            public Array<Decal> newObject() {
                return new Array<>();
            }
        };
        this.usedArrays = new Array<>();
        this.materialGroups = new ObjectMap<>();
        this.camera = camera;
        this.cameraSorter = sorter;
        createDefaultShader();
    }

    public void setCamera(Camera camera) {
        this.camera = camera;
    }

    public Camera getCamera() {
        return this.camera;
    }

    @Override // com.badlogic.gdx.graphics.g3d.decals.GroupStrategy
    public int decideGroup(Decal decal) {
        return !decal.getMaterial().isOpaque();
    }

    @Override // com.badlogic.gdx.graphics.g3d.decals.GroupStrategy
    public void beforeGroup(int group, Array<Decal> contents) {
        if (group == 1) {
            Gdx.gl.glEnable(GL20.GL_BLEND);
            contents.sort(this.cameraSorter);
            return;
        }
        int n = contents.size;
        for (int i = 0; i < n; i++) {
            Decal decal = contents.get(i);
            Array<Decal> materialGroup = this.materialGroups.get(decal.material);
            if (materialGroup == null) {
                materialGroup = this.arrayPool.obtain();
                materialGroup.clear();
                this.usedArrays.add(materialGroup);
                this.materialGroups.put(decal.material, materialGroup);
            }
            materialGroup.add(decal);
        }
        contents.clear();
        ObjectMap.Values<Array<Decal>> it = this.materialGroups.values().iterator();
        while (it.hasNext()) {
            contents.addAll(it.next());
        }
        this.materialGroups.clear();
        this.arrayPool.freeAll(this.usedArrays);
        this.usedArrays.clear();
    }

    @Override // com.badlogic.gdx.graphics.g3d.decals.GroupStrategy
    public void afterGroup(int group) {
        if (group == 1) {
            Gdx.gl.glDisable(GL20.GL_BLEND);
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.decals.GroupStrategy
    public void beforeGroups() {
        Gdx.gl.glEnable(GL20.GL_DEPTH_TEST);
        this.shader.bind();
        this.shader.setUniformMatrix("u_projectionViewMatrix", this.camera.combined);
        this.shader.setUniformi("u_texture", 0);
    }

    @Override // com.badlogic.gdx.graphics.g3d.decals.GroupStrategy
    public void afterGroups() {
        Gdx.gl.glDisable(GL20.GL_DEPTH_TEST);
    }

    private void createDefaultShader() {
        this.shader = new ShaderProgram("attribute vec4 a_position;\nattribute vec4 a_color;\nattribute vec2 a_texCoord0;\nuniform mat4 u_projectionViewMatrix;\nvarying vec4 v_color;\nvarying vec2 v_texCoords;\n\nvoid main()\n{\n   v_color = a_color;\n   v_color.a = v_color.a * (255.0/254.0);\n   v_texCoords = a_texCoord0;\n   gl_Position =  u_projectionViewMatrix * a_position;\n}\n", "#ifdef GL_ES\nprecision mediump float;\n#endif\nvarying vec4 v_color;\nvarying vec2 v_texCoords;\nuniform sampler2D u_texture;\nvoid main()\n{\n  gl_FragColor = v_color * texture2D(u_texture, v_texCoords);\n}");
        if (!this.shader.isCompiled()) {
            throw new IllegalArgumentException("couldn't compile shader: " + this.shader.getLog());
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.decals.GroupStrategy
    public ShaderProgram getGroupShader(int group) {
        return this.shader;
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        ShaderProgram shaderProgram = this.shader;
        if (shaderProgram != null) {
            shaderProgram.dispose();
        }
    }
}