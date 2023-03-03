package com.badlogic.gdx.graphics.g3d.utils;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Mesh;
import com.badlogic.gdx.graphics.VertexAttributes;
import com.badlogic.gdx.graphics.g3d.Material;
import com.badlogic.gdx.graphics.g3d.Model;
import com.badlogic.gdx.graphics.g3d.model.MeshPart;
import com.badlogic.gdx.graphics.g3d.model.Node;
import com.badlogic.gdx.graphics.g3d.model.NodePart;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class ModelBuilder {
    private Model model;
    private Node node;
    private Array<MeshBuilder> builders = new Array<>();
    private Matrix4 tmpTransform = new Matrix4();

    private MeshBuilder getBuilder(VertexAttributes attributes) {
        Array.ArrayIterator<MeshBuilder> it = this.builders.iterator();
        while (it.hasNext()) {
            MeshBuilder mb = it.next();
            if (mb.getAttributes().equals(attributes) && mb.lastIndex() < 16383) {
                return mb;
            }
        }
        MeshBuilder result = new MeshBuilder();
        result.begin(attributes);
        this.builders.add(result);
        return result;
    }

    public void begin() {
        if (this.model != null) {
            throw new GdxRuntimeException("Call end() first");
        }
        this.node = null;
        this.model = new Model();
        this.builders.clear();
    }

    public Model end() {
        if (this.model == null) {
            throw new GdxRuntimeException("Call begin() first");
        }
        Model result = this.model;
        endnode();
        this.model = null;
        Array.ArrayIterator<MeshBuilder> it = this.builders.iterator();
        while (it.hasNext()) {
            MeshBuilder mb = it.next();
            mb.end();
        }
        this.builders.clear();
        rebuildReferences(result);
        return result;
    }

    private void endnode() {
        if (this.node != null) {
            this.node = null;
        }
    }

    protected Node node(Node node) {
        if (this.model == null) {
            throw new GdxRuntimeException("Call begin() first");
        }
        endnode();
        this.model.nodes.add(node);
        this.node = node;
        return node;
    }

    public Node node() {
        Node node = new Node();
        node(node);
        node.id = "node" + this.model.nodes.size;
        return node;
    }

    public Node node(String id, Model model) {
        Node node = new Node();
        node.id = id;
        node.addChildren(model.nodes);
        node(node);
        for (Disposable disposable : model.getManagedDisposables()) {
            manage(disposable);
        }
        return node;
    }

    public void manage(Disposable disposable) {
        Model model = this.model;
        if (model == null) {
            throw new GdxRuntimeException("Call begin() first");
        }
        model.manageDisposable(disposable);
    }

    public void part(MeshPart meshpart, Material material) {
        if (this.node == null) {
            node();
        }
        this.node.parts.add(new NodePart(meshpart, material));
    }

    public MeshPart part(String id, Mesh mesh, int primitiveType, int offset, int size, Material material) {
        MeshPart meshPart = new MeshPart();
        meshPart.id = id;
        meshPart.primitiveType = primitiveType;
        meshPart.mesh = mesh;
        meshPart.offset = offset;
        meshPart.size = size;
        part(meshPart, material);
        return meshPart;
    }

    public MeshPart part(String id, Mesh mesh, int primitiveType, Material material) {
        return part(id, mesh, primitiveType, 0, mesh.getNumIndices(), material);
    }

    public MeshPartBuilder part(String id, int primitiveType, VertexAttributes attributes, Material material) {
        MeshBuilder builder = getBuilder(attributes);
        part(builder.part(id, primitiveType), material);
        return builder;
    }

    public MeshPartBuilder part(String id, int primitiveType, long attributes, Material material) {
        return part(id, primitiveType, MeshBuilder.createAttributes(attributes), material);
    }

    public Model createBox(float width, float height, float depth, Material material, long attributes) {
        return createBox(width, height, depth, 4, material, attributes);
    }

    public Model createBox(float width, float height, float depth, int primitiveType, Material material, long attributes) {
        begin();
        part("box", primitiveType, attributes, material).box(width, height, depth);
        return end();
    }

    public Model createRect(float x00, float y00, float z00, float x10, float y10, float z10, float x11, float y11, float z11, float x01, float y01, float z01, float normalX, float normalY, float normalZ, Material material, long attributes) {
        return createRect(x00, y00, z00, x10, y10, z10, x11, y11, z11, x01, y01, z01, normalX, normalY, normalZ, 4, material, attributes);
    }

    public Model createRect(float x00, float y00, float z00, float x10, float y10, float z10, float x11, float y11, float z11, float x01, float y01, float z01, float normalX, float normalY, float normalZ, int primitiveType, Material material, long attributes) {
        begin();
        part("rect", primitiveType, attributes, material).rect(x00, y00, z00, x10, y10, z10, x11, y11, z11, x01, y01, z01, normalX, normalY, normalZ);
        return end();
    }

    public Model createCylinder(float width, float height, float depth, int divisions, Material material, long attributes) {
        return createCylinder(width, height, depth, divisions, 4, material, attributes);
    }

    public Model createCylinder(float width, float height, float depth, int divisions, int primitiveType, Material material, long attributes) {
        return createCylinder(width, height, depth, divisions, primitiveType, material, attributes, 0.0f, 360.0f);
    }

    public Model createCylinder(float width, float height, float depth, int divisions, Material material, long attributes, float angleFrom, float angleTo) {
        return createCylinder(width, height, depth, divisions, 4, material, attributes, angleFrom, angleTo);
    }

    public Model createCylinder(float width, float height, float depth, int divisions, int primitiveType, Material material, long attributes, float angleFrom, float angleTo) {
        begin();
        part("cylinder", primitiveType, attributes, material).cylinder(width, height, depth, divisions, angleFrom, angleTo);
        return end();
    }

    public Model createCone(float width, float height, float depth, int divisions, Material material, long attributes) {
        return createCone(width, height, depth, divisions, 4, material, attributes);
    }

    public Model createCone(float width, float height, float depth, int divisions, int primitiveType, Material material, long attributes) {
        return createCone(width, height, depth, divisions, primitiveType, material, attributes, 0.0f, 360.0f);
    }

    public Model createCone(float width, float height, float depth, int divisions, Material material, long attributes, float angleFrom, float angleTo) {
        return createCone(width, height, depth, divisions, 4, material, attributes, angleFrom, angleTo);
    }

    public Model createCone(float width, float height, float depth, int divisions, int primitiveType, Material material, long attributes, float angleFrom, float angleTo) {
        begin();
        part("cone", primitiveType, attributes, material).cone(width, height, depth, divisions, angleFrom, angleTo);
        return end();
    }

    public Model createSphere(float width, float height, float depth, int divisionsU, int divisionsV, Material material, long attributes) {
        return createSphere(width, height, depth, divisionsU, divisionsV, 4, material, attributes);
    }

    public Model createSphere(float width, float height, float depth, int divisionsU, int divisionsV, int primitiveType, Material material, long attributes) {
        return createSphere(width, height, depth, divisionsU, divisionsV, primitiveType, material, attributes, 0.0f, 360.0f, 0.0f, 180.0f);
    }

    public Model createSphere(float width, float height, float depth, int divisionsU, int divisionsV, Material material, long attributes, float angleUFrom, float angleUTo, float angleVFrom, float angleVTo) {
        return createSphere(width, height, depth, divisionsU, divisionsV, 4, material, attributes, angleUFrom, angleUTo, angleVFrom, angleVTo);
    }

    public Model createSphere(float width, float height, float depth, int divisionsU, int divisionsV, int primitiveType, Material material, long attributes, float angleUFrom, float angleUTo, float angleVFrom, float angleVTo) {
        begin();
        part("sphere", primitiveType, attributes, material).sphere(width, height, depth, divisionsU, divisionsV, angleUFrom, angleUTo, angleVFrom, angleVTo);
        return end();
    }

    public Model createCapsule(float radius, float height, int divisions, Material material, long attributes) {
        return createCapsule(radius, height, divisions, 4, material, attributes);
    }

    public Model createCapsule(float radius, float height, int divisions, int primitiveType, Material material, long attributes) {
        begin();
        part("capsule", primitiveType, attributes, material).capsule(radius, height, divisions);
        return end();
    }

    public static void rebuildReferences(Model model) {
        model.materials.clear();
        model.meshes.clear();
        model.meshParts.clear();
        Array.ArrayIterator<Node> it = model.nodes.iterator();
        while (it.hasNext()) {
            Node node = it.next();
            rebuildReferences(model, node);
        }
    }

    private static void rebuildReferences(Model model, Node node) {
        Array.ArrayIterator<NodePart> it = node.parts.iterator();
        while (it.hasNext()) {
            NodePart mpm = it.next();
            if (!model.materials.contains(mpm.material, true)) {
                model.materials.add(mpm.material);
            }
            if (!model.meshParts.contains(mpm.meshPart, true)) {
                model.meshParts.add(mpm.meshPart);
                if (!model.meshes.contains(mpm.meshPart.mesh, true)) {
                    model.meshes.add(mpm.meshPart.mesh);
                }
                model.manageDisposable(mpm.meshPart.mesh);
            }
        }
        for (Node child : node.getChildren()) {
            rebuildReferences(model, child);
        }
    }

    public Model createXYZCoordinates(float axisLength, float capLength, float stemThickness, int divisions, int primitiveType, Material material, long attributes) {
        begin();
        node();
        MeshPartBuilder partBuilder = part("xyz", primitiveType, attributes, material);
        partBuilder.setColor(Color.RED);
        partBuilder.arrow(0.0f, 0.0f, 0.0f, axisLength, 0.0f, 0.0f, capLength, stemThickness, divisions);
        partBuilder.setColor(Color.GREEN);
        partBuilder.arrow(0.0f, 0.0f, 0.0f, 0.0f, axisLength, 0.0f, capLength, stemThickness, divisions);
        partBuilder.setColor(Color.BLUE);
        partBuilder.arrow(0.0f, 0.0f, 0.0f, 0.0f, 0.0f, axisLength, capLength, stemThickness, divisions);
        return end();
    }

    public Model createXYZCoordinates(float axisLength, Material material, long attributes) {
        return createXYZCoordinates(axisLength, 0.1f, 0.1f, 5, 4, material, attributes);
    }

    public Model createArrow(float x1, float y1, float z1, float x2, float y2, float z2, float capLength, float stemThickness, int divisions, int primitiveType, Material material, long attributes) {
        begin();
        part("arrow", primitiveType, attributes, material).arrow(x1, y1, z1, x2, y2, z2, capLength, stemThickness, divisions);
        return end();
    }

    public Model createArrow(Vector3 from, Vector3 to, Material material, long attributes) {
        return createArrow(from.x, from.y, from.z, to.x, to.y, to.z, 0.1f, 0.1f, 5, 4, material, attributes);
    }

    public Model createLineGrid(int xDivisions, int zDivisions, float xSize, float zSize, Material material, long attributes) {
        begin();
        MeshPartBuilder partBuilder = part("lines", 1, attributes, material);
        float xlength = xDivisions * xSize;
        float zlength = zDivisions * zSize;
        float hxlength = xlength / 2.0f;
        float hzlength = zlength / 2.0f;
        float x1 = -hxlength;
        float x2 = -hxlength;
        float z2 = -hzlength;
        float x12 = x1;
        float x22 = x2;
        for (int i = 0; i <= xDivisions; i++) {
            partBuilder.line(x12, 0.0f, hzlength, x22, 0.0f, z2);
            x12 += xSize;
            x22 += xSize;
        }
        float x13 = -hxlength;
        float z1 = -hzlength;
        float z22 = -hzlength;
        float z12 = z1;
        float z23 = z22;
        int j = 0;
        while (j <= zDivisions) {
            float x14 = x13;
            float x15 = z23;
            partBuilder.line(x13, 0.0f, z12, hxlength, 0.0f, x15);
            z12 += zSize;
            z23 += zSize;
            j++;
            x13 = x14;
        }
        return end();
    }
}