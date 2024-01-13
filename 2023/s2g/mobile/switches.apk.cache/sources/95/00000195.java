package com.badlogic.gdx.graphics.g3d.model;

import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Quaternion;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.math.collision.BoundingBox;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class Node {
    public String id;
    public boolean isAnimated;
    protected Node parent;
    public boolean inheritTransform = true;
    public final Vector3 translation = new Vector3();
    public final Quaternion rotation = new Quaternion(0.0f, 0.0f, 0.0f, 1.0f);
    public final Vector3 scale = new Vector3(1.0f, 1.0f, 1.0f);
    public final Matrix4 localTransform = new Matrix4();
    public final Matrix4 globalTransform = new Matrix4();
    public Array<NodePart> parts = new Array<>(2);
    private final Array<Node> children = new Array<>(2);

    public Matrix4 calculateLocalTransform() {
        if (!this.isAnimated) {
            this.localTransform.set(this.translation, this.rotation, this.scale);
        }
        return this.localTransform;
    }

    public Matrix4 calculateWorldTransform() {
        Node node;
        if (this.inheritTransform && (node = this.parent) != null) {
            this.globalTransform.set(node.globalTransform).mul(this.localTransform);
        } else {
            this.globalTransform.set(this.localTransform);
        }
        return this.globalTransform;
    }

    public void calculateTransforms(boolean recursive) {
        calculateLocalTransform();
        calculateWorldTransform();
        if (recursive) {
            Array.ArrayIterator<Node> it = this.children.iterator();
            while (it.hasNext()) {
                Node child = it.next();
                child.calculateTransforms(true);
            }
        }
    }

    public void calculateBoneTransforms(boolean recursive) {
        Array.ArrayIterator<NodePart> it = this.parts.iterator();
        while (it.hasNext()) {
            NodePart part = it.next();
            if (part.invBoneBindTransforms != null && part.bones != null && part.invBoneBindTransforms.size == part.bones.length) {
                int n = part.invBoneBindTransforms.size;
                for (int i = 0; i < n; i++) {
                    part.bones[i].set(part.invBoneBindTransforms.keys[i].globalTransform).mul(part.invBoneBindTransforms.values[i]);
                }
            }
        }
        if (recursive) {
            Array.ArrayIterator<Node> it2 = this.children.iterator();
            while (it2.hasNext()) {
                Node child = it2.next();
                child.calculateBoneTransforms(true);
            }
        }
    }

    public BoundingBox calculateBoundingBox(BoundingBox out) {
        out.inf();
        return extendBoundingBox(out);
    }

    public BoundingBox calculateBoundingBox(BoundingBox out, boolean transform) {
        out.inf();
        return extendBoundingBox(out, transform);
    }

    public BoundingBox extendBoundingBox(BoundingBox out) {
        return extendBoundingBox(out, true);
    }

    public BoundingBox extendBoundingBox(BoundingBox out, boolean transform) {
        int partCount = this.parts.size;
        for (int i = 0; i < partCount; i++) {
            NodePart part = this.parts.get(i);
            if (part.enabled) {
                MeshPart meshPart = part.meshPart;
                if (transform) {
                    meshPart.mesh.extendBoundingBox(out, meshPart.offset, meshPart.size, this.globalTransform);
                } else {
                    meshPart.mesh.extendBoundingBox(out, meshPart.offset, meshPart.size);
                }
            }
        }
        int childCount = this.children.size;
        for (int i2 = 0; i2 < childCount; i2++) {
            this.children.get(i2).extendBoundingBox(out);
        }
        return out;
    }

    public <T extends Node> void attachTo(T parent) {
        parent.addChild(this);
    }

    public void detach() {
        Node node = this.parent;
        if (node != null) {
            node.removeChild(this);
            this.parent = null;
        }
    }

    public boolean hasChildren() {
        Array<Node> array = this.children;
        return array != null && array.size > 0;
    }

    public int getChildCount() {
        return this.children.size;
    }

    public Node getChild(int index) {
        return this.children.get(index);
    }

    public Node getChild(String id, boolean recursive, boolean ignoreCase) {
        return getNode(this.children, id, recursive, ignoreCase);
    }

    public <T extends Node> int addChild(T child) {
        return insertChild(-1, child);
    }

    public <T extends Node> int addChildren(Iterable<T> nodes) {
        return insertChildren(-1, nodes);
    }

    public <T extends Node> int insertChild(int index, T child) {
        for (Node p = this; p != null; p = p.getParent()) {
            if (p == child) {
                throw new GdxRuntimeException("Cannot add a parent as a child");
            }
        }
        Node p2 = child.getParent();
        if (p2 == null || p2.removeChild(child)) {
            if (index < 0 || index >= this.children.size) {
                index = this.children.size;
                this.children.add(child);
            } else {
                this.children.insert(index, child);
            }
            child.parent = this;
            return index;
        }
        throw new GdxRuntimeException("Could not remove child from its current parent");
    }

    public <T extends Node> int insertChildren(int index, Iterable<T> nodes) {
        if (index < 0 || index > this.children.size) {
            index = this.children.size;
        }
        int i = index;
        for (T child : nodes) {
            insertChild(i, child);
            i++;
        }
        return index;
    }

    public <T extends Node> boolean removeChild(T child) {
        if (this.children.removeValue(child, true)) {
            child.parent = null;
            return true;
        }
        return false;
    }

    public Iterable<Node> getChildren() {
        return this.children;
    }

    public Node getParent() {
        return this.parent;
    }

    public boolean hasParent() {
        return this.parent != null;
    }

    public Node copy() {
        return new Node().set(this);
    }

    protected Node set(Node other) {
        detach();
        this.id = other.id;
        this.isAnimated = other.isAnimated;
        this.inheritTransform = other.inheritTransform;
        this.translation.set(other.translation);
        this.rotation.set(other.rotation);
        this.scale.set(other.scale);
        this.localTransform.set(other.localTransform);
        this.globalTransform.set(other.globalTransform);
        this.parts.clear();
        Array.ArrayIterator<NodePart> it = other.parts.iterator();
        while (it.hasNext()) {
            NodePart nodePart = it.next();
            this.parts.add(nodePart.copy());
        }
        this.children.clear();
        for (Node child : other.getChildren()) {
            addChild(child.copy());
        }
        return this;
    }

    public static Node getNode(Array<Node> nodes, String id, boolean recursive, boolean ignoreCase) {
        int n = nodes.size;
        if (ignoreCase) {
            for (int i = 0; i < n; i++) {
                Node node = nodes.get(i);
                if (node.id.equalsIgnoreCase(id)) {
                    return node;
                }
            }
        } else {
            for (int i2 = 0; i2 < n; i2++) {
                Node node2 = nodes.get(i2);
                if (node2.id.equals(id)) {
                    return node2;
                }
            }
        }
        if (recursive) {
            for (int i3 = 0; i3 < n; i3++) {
                Node node3 = getNode(nodes.get(i3).children, id, true, ignoreCase);
                if (node3 != null) {
                    return node3;
                }
            }
            return null;
        }
        return null;
    }
}