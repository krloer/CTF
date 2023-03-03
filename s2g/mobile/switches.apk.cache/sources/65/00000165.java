package com.badlogic.gdx.graphics.g3d;

import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.graphics.Mesh;
import com.badlogic.gdx.graphics.VertexAttributes;
import com.badlogic.gdx.graphics.g3d.model.MeshPart;
import com.badlogic.gdx.graphics.g3d.utils.MeshBuilder;
import com.badlogic.gdx.graphics.g3d.utils.RenderableSorter;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.FlushablePool;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.Pool;
import java.util.Comparator;

/* loaded from: classes.dex */
public class ModelCache implements Disposable, RenderableProvider {
    private boolean building;
    private Camera camera;
    private Array<Renderable> items;
    private MeshBuilder meshBuilder;
    private FlushablePool<MeshPart> meshPartPool;
    private MeshPool meshPool;
    private Array<Renderable> renderables;
    private FlushablePool<Renderable> renderablesPool;
    private RenderableSorter sorter;
    private Array<Renderable> tmp;

    /* loaded from: classes.dex */
    public interface MeshPool extends Disposable {
        void flush();

        Mesh obtain(VertexAttributes vertexAttributes, int i, int i2);
    }

    /* loaded from: classes.dex */
    public static class SimpleMeshPool implements MeshPool {
        private Array<Mesh> freeMeshes = new Array<>();
        private Array<Mesh> usedMeshes = new Array<>();

        @Override // com.badlogic.gdx.graphics.g3d.ModelCache.MeshPool
        public void flush() {
            this.freeMeshes.addAll(this.usedMeshes);
            this.usedMeshes.clear();
        }

        @Override // com.badlogic.gdx.graphics.g3d.ModelCache.MeshPool
        public Mesh obtain(VertexAttributes vertexAttributes, int vertexCount, int indexCount) {
            int n = this.freeMeshes.size;
            for (int i = 0; i < n; i++) {
                Mesh mesh = this.freeMeshes.get(i);
                if (mesh.getVertexAttributes().equals(vertexAttributes) && mesh.getMaxVertices() >= vertexCount && mesh.getMaxIndices() >= indexCount) {
                    this.freeMeshes.removeIndex(i);
                    this.usedMeshes.add(mesh);
                    return mesh;
                }
            }
            Mesh result = new Mesh(false, (int) MeshBuilder.MAX_VERTICES, Math.max((int) MeshBuilder.MAX_VERTICES, 1 << (32 - Integer.numberOfLeadingZeros(indexCount - 1))), vertexAttributes);
            this.usedMeshes.add(result);
            return result;
        }

        @Override // com.badlogic.gdx.utils.Disposable
        public void dispose() {
            Array.ArrayIterator<Mesh> it = this.usedMeshes.iterator();
            while (it.hasNext()) {
                Mesh m = it.next();
                m.dispose();
            }
            this.usedMeshes.clear();
            Array.ArrayIterator<Mesh> it2 = this.freeMeshes.iterator();
            while (it2.hasNext()) {
                Mesh m2 = it2.next();
                m2.dispose();
            }
            this.freeMeshes.clear();
        }
    }

    /* loaded from: classes.dex */
    public static class TightMeshPool implements MeshPool {
        private Array<Mesh> freeMeshes = new Array<>();
        private Array<Mesh> usedMeshes = new Array<>();

        @Override // com.badlogic.gdx.graphics.g3d.ModelCache.MeshPool
        public void flush() {
            this.freeMeshes.addAll(this.usedMeshes);
            this.usedMeshes.clear();
        }

        @Override // com.badlogic.gdx.graphics.g3d.ModelCache.MeshPool
        public Mesh obtain(VertexAttributes vertexAttributes, int vertexCount, int indexCount) {
            int n = this.freeMeshes.size;
            for (int i = 0; i < n; i++) {
                Mesh mesh = this.freeMeshes.get(i);
                if (mesh.getVertexAttributes().equals(vertexAttributes) && mesh.getMaxVertices() == vertexCount && mesh.getMaxIndices() == indexCount) {
                    this.freeMeshes.removeIndex(i);
                    this.usedMeshes.add(mesh);
                    return mesh;
                }
            }
            Mesh result = new Mesh(true, vertexCount, indexCount, vertexAttributes);
            this.usedMeshes.add(result);
            return result;
        }

        @Override // com.badlogic.gdx.utils.Disposable
        public void dispose() {
            Array.ArrayIterator<Mesh> it = this.usedMeshes.iterator();
            while (it.hasNext()) {
                Mesh m = it.next();
                m.dispose();
            }
            this.usedMeshes.clear();
            Array.ArrayIterator<Mesh> it2 = this.freeMeshes.iterator();
            while (it2.hasNext()) {
                Mesh m2 = it2.next();
                m2.dispose();
            }
            this.freeMeshes.clear();
        }
    }

    /* loaded from: classes.dex */
    public static class Sorter implements RenderableSorter, Comparator<Renderable> {
        @Override // com.badlogic.gdx.graphics.g3d.utils.RenderableSorter
        public void sort(Camera camera, Array<Renderable> renderables) {
            renderables.sort(this);
        }

        @Override // java.util.Comparator
        public int compare(Renderable arg0, Renderable arg1) {
            VertexAttributes va0 = arg0.meshPart.mesh.getVertexAttributes();
            VertexAttributes va1 = arg1.meshPart.mesh.getVertexAttributes();
            int vc = va0.compareTo(va1);
            if (vc == 0) {
                int mc = arg0.material.compareTo((Attributes) arg1.material);
                if (mc == 0) {
                    return arg0.meshPart.primitiveType - arg1.meshPart.primitiveType;
                }
                return mc;
            }
            return vc;
        }
    }

    public ModelCache() {
        this(new Sorter(), new SimpleMeshPool());
    }

    public ModelCache(RenderableSorter sorter, MeshPool meshPool) {
        this.renderables = new Array<>();
        this.renderablesPool = new FlushablePool<Renderable>() { // from class: com.badlogic.gdx.graphics.g3d.ModelCache.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.badlogic.gdx.utils.Pool
            public Renderable newObject() {
                return new Renderable();
            }
        };
        this.meshPartPool = new FlushablePool<MeshPart>() { // from class: com.badlogic.gdx.graphics.g3d.ModelCache.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.badlogic.gdx.utils.Pool
            public MeshPart newObject() {
                return new MeshPart();
            }
        };
        this.items = new Array<>();
        this.tmp = new Array<>();
        this.sorter = sorter;
        this.meshPool = meshPool;
        this.meshBuilder = new MeshBuilder();
    }

    public void begin() {
        begin(null);
    }

    public void begin(Camera camera) {
        if (this.building) {
            throw new GdxRuntimeException("Call end() after calling begin()");
        }
        this.building = true;
        this.camera = camera;
        this.renderablesPool.flush();
        this.renderables.clear();
        this.items.clear();
        this.meshPartPool.flush();
        this.meshPool.flush();
    }

    private Renderable obtainRenderable(Material material, int primitiveType) {
        Renderable result = this.renderablesPool.obtain();
        result.bones = null;
        result.environment = null;
        result.material = material;
        result.meshPart.mesh = null;
        result.meshPart.offset = 0;
        result.meshPart.size = 0;
        result.meshPart.primitiveType = primitiveType;
        result.meshPart.center.set(0.0f, 0.0f, 0.0f);
        result.meshPart.halfExtents.set(0.0f, 0.0f, 0.0f);
        result.meshPart.radius = -1.0f;
        result.shader = null;
        result.userData = null;
        result.worldTransform.idt();
        return result;
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0145  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public void end() {
        /*
            Method dump skipped, instructions count: 457
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.graphics.g3d.ModelCache.end():void");
    }

    public void add(Renderable renderable) {
        if (!this.building) {
            throw new GdxRuntimeException("Can only add items to the ModelCache in between .begin() and .end()");
        }
        if (renderable.bones == null) {
            this.items.add(renderable);
        } else {
            this.renderables.add(renderable);
        }
    }

    public void add(RenderableProvider renderableProvider) {
        renderableProvider.getRenderables(this.tmp, this.renderablesPool);
        int n = this.tmp.size;
        for (int i = 0; i < n; i++) {
            add(this.tmp.get(i));
        }
        this.tmp.clear();
    }

    public <T extends RenderableProvider> void add(Iterable<T> renderableProviders) {
        for (RenderableProvider renderableProvider : renderableProviders) {
            add(renderableProvider);
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.RenderableProvider
    public void getRenderables(Array<Renderable> renderables, Pool<Renderable> pool) {
        if (this.building) {
            throw new GdxRuntimeException("Cannot render a ModelCache in between .begin() and .end()");
        }
        Array.ArrayIterator<Renderable> it = this.renderables.iterator();
        while (it.hasNext()) {
            Renderable r = it.next();
            r.shader = null;
            r.environment = null;
        }
        renderables.addAll(this.renderables);
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        if (this.building) {
            throw new GdxRuntimeException("Cannot dispose a ModelCache in between .begin() and .end()");
        }
        this.meshPool.dispose();
    }
}