package com.badlogic.gdx.graphics.g3d;

import com.badlogic.gdx.graphics.g3d.model.Animation;
import com.badlogic.gdx.graphics.g3d.model.Node;
import com.badlogic.gdx.graphics.g3d.model.NodeAnimation;
import com.badlogic.gdx.graphics.g3d.model.NodeKeyframe;
import com.badlogic.gdx.graphics.g3d.model.NodePart;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Quaternion;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.math.collision.BoundingBox;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.ArrayMap;
import com.badlogic.gdx.utils.Pool;

/* loaded from: classes.dex */
public class ModelInstance implements RenderableProvider {
    public static boolean defaultShareKeyframes = true;
    public final Array<Animation> animations;
    public final Array<Material> materials;
    public final Model model;
    public final Array<Node> nodes;
    public Matrix4 transform;
    public Object userData;

    public ModelInstance(Model model) {
        this(model, (String[]) null);
    }

    public ModelInstance(Model model, String nodeId, boolean mergeTransform) {
        this(model, null, nodeId, false, false, mergeTransform);
    }

    public ModelInstance(Model model, Matrix4 transform, String nodeId, boolean mergeTransform) {
        this(model, transform, nodeId, false, false, mergeTransform);
    }

    public ModelInstance(Model model, String nodeId, boolean parentTransform, boolean mergeTransform) {
        this(model, null, nodeId, true, parentTransform, mergeTransform);
    }

    public ModelInstance(Model model, Matrix4 transform, String nodeId, boolean parentTransform, boolean mergeTransform) {
        this(model, transform, nodeId, true, parentTransform, mergeTransform);
    }

    public ModelInstance(Model model, String nodeId, boolean recursive, boolean parentTransform, boolean mergeTransform) {
        this(model, null, nodeId, recursive, parentTransform, mergeTransform);
    }

    public ModelInstance(Model model, Matrix4 transform, String nodeId, boolean recursive, boolean parentTransform, boolean mergeTransform) {
        this(model, transform, nodeId, recursive, parentTransform, mergeTransform, defaultShareKeyframes);
    }

    public ModelInstance(Model model, Matrix4 transform, String nodeId, boolean recursive, boolean parentTransform, boolean mergeTransform, boolean shareKeyframes) {
        this.materials = new Array<>();
        this.nodes = new Array<>();
        this.animations = new Array<>();
        this.model = model;
        this.transform = transform == null ? new Matrix4() : transform;
        Node node = model.getNode(nodeId, recursive);
        Array<Node> array = this.nodes;
        Node copy = node.copy();
        array.add(copy);
        if (mergeTransform) {
            this.transform.mul(parentTransform ? node.globalTransform : node.localTransform);
            copy.translation.set(0.0f, 0.0f, 0.0f);
            copy.rotation.idt();
            copy.scale.set(1.0f, 1.0f, 1.0f);
        } else if (parentTransform && copy.hasParent()) {
            this.transform.mul(node.getParent().globalTransform);
        }
        invalidate();
        copyAnimations(model.animations, shareKeyframes);
        calculateTransforms();
    }

    public ModelInstance(Model model, String... rootNodeIds) {
        this(model, (Matrix4) null, rootNodeIds);
    }

    public ModelInstance(Model model, Matrix4 transform, String... rootNodeIds) {
        this.materials = new Array<>();
        this.nodes = new Array<>();
        this.animations = new Array<>();
        this.model = model;
        this.transform = transform == null ? new Matrix4() : transform;
        if (rootNodeIds == null) {
            copyNodes(model.nodes);
        } else {
            copyNodes(model.nodes, rootNodeIds);
        }
        copyAnimations(model.animations, defaultShareKeyframes);
        calculateTransforms();
    }

    public ModelInstance(Model model, Array<String> rootNodeIds) {
        this(model, (Matrix4) null, rootNodeIds);
    }

    public ModelInstance(Model model, Matrix4 transform, Array<String> rootNodeIds) {
        this(model, transform, rootNodeIds, defaultShareKeyframes);
    }

    public ModelInstance(Model model, Matrix4 transform, Array<String> rootNodeIds, boolean shareKeyframes) {
        this.materials = new Array<>();
        this.nodes = new Array<>();
        this.animations = new Array<>();
        this.model = model;
        this.transform = transform == null ? new Matrix4() : transform;
        copyNodes(model.nodes, rootNodeIds);
        copyAnimations(model.animations, shareKeyframes);
        calculateTransforms();
    }

    public ModelInstance(Model model, Vector3 position) {
        this(model);
        this.transform.setToTranslation(position);
    }

    public ModelInstance(Model model, float x, float y, float z) {
        this(model);
        this.transform.setToTranslation(x, y, z);
    }

    public ModelInstance(Model model, Matrix4 transform) {
        this(model, transform, (String[]) null);
    }

    public ModelInstance(ModelInstance copyFrom) {
        this(copyFrom, copyFrom.transform.cpy());
    }

    public ModelInstance(ModelInstance copyFrom, Matrix4 transform) {
        this(copyFrom, transform, defaultShareKeyframes);
    }

    public ModelInstance(ModelInstance copyFrom, Matrix4 transform, boolean shareKeyframes) {
        this.materials = new Array<>();
        this.nodes = new Array<>();
        this.animations = new Array<>();
        this.model = copyFrom.model;
        this.transform = transform == null ? new Matrix4() : transform;
        copyNodes(copyFrom.nodes);
        copyAnimations(copyFrom.animations, shareKeyframes);
        calculateTransforms();
    }

    public ModelInstance copy() {
        return new ModelInstance(this);
    }

    private void copyNodes(Array<Node> nodes) {
        int n = nodes.size;
        for (int i = 0; i < n; i++) {
            Node node = nodes.get(i);
            this.nodes.add(node.copy());
        }
        invalidate();
    }

    private void copyNodes(Array<Node> nodes, String... nodeIds) {
        int n = nodes.size;
        for (int i = 0; i < n; i++) {
            Node node = nodes.get(i);
            int length = nodeIds.length;
            int i2 = 0;
            while (true) {
                if (i2 < length) {
                    String nodeId = nodeIds[i2];
                    if (!nodeId.equals(node.id)) {
                        i2++;
                    } else {
                        this.nodes.add(node.copy());
                        break;
                    }
                }
            }
        }
        invalidate();
    }

    private void copyNodes(Array<Node> nodes, Array<String> nodeIds) {
        int n = nodes.size;
        for (int i = 0; i < n; i++) {
            Node node = nodes.get(i);
            Array.ArrayIterator<String> it = nodeIds.iterator();
            while (true) {
                if (it.hasNext()) {
                    String nodeId = it.next();
                    if (nodeId.equals(node.id)) {
                        this.nodes.add(node.copy());
                        break;
                    }
                }
            }
        }
        invalidate();
    }

    private void invalidate(Node node) {
        int n = node.parts.size;
        for (int i = 0; i < n; i++) {
            NodePart part = node.parts.get(i);
            ArrayMap<Node, Matrix4> bindPose = part.invBoneBindTransforms;
            if (bindPose != null) {
                for (int j = 0; j < bindPose.size; j++) {
                    bindPose.keys[j] = getNode(bindPose.keys[j].id);
                }
            }
            if (!this.materials.contains(part.material, true)) {
                int midx = this.materials.indexOf(part.material, false);
                if (midx < 0) {
                    Array<Material> array = this.materials;
                    Material copy = part.material.copy();
                    part.material = copy;
                    array.add(copy);
                } else {
                    part.material = this.materials.get(midx);
                }
            }
        }
        int n2 = node.getChildCount();
        for (int i2 = 0; i2 < n2; i2++) {
            invalidate(node.getChild(i2));
        }
    }

    private void invalidate() {
        int n = this.nodes.size;
        for (int i = 0; i < n; i++) {
            invalidate(this.nodes.get(i));
        }
    }

    public void copyAnimations(Iterable<Animation> source) {
        for (Animation anim : source) {
            copyAnimation(anim, defaultShareKeyframes);
        }
    }

    public void copyAnimations(Iterable<Animation> source, boolean shareKeyframes) {
        for (Animation anim : source) {
            copyAnimation(anim, shareKeyframes);
        }
    }

    public void copyAnimation(Animation sourceAnim) {
        copyAnimation(sourceAnim, defaultShareKeyframes);
    }

    public void copyAnimation(Animation sourceAnim, boolean shareKeyframes) {
        Animation animation = new Animation();
        animation.id = sourceAnim.id;
        animation.duration = sourceAnim.duration;
        Array.ArrayIterator<NodeAnimation> it = sourceAnim.nodeAnimations.iterator();
        while (it.hasNext()) {
            NodeAnimation nanim = it.next();
            Node node = getNode(nanim.node.id);
            if (node != null) {
                NodeAnimation nodeAnim = new NodeAnimation();
                nodeAnim.node = node;
                if (shareKeyframes) {
                    nodeAnim.translation = nanim.translation;
                    nodeAnim.rotation = nanim.rotation;
                    nodeAnim.scaling = nanim.scaling;
                } else {
                    if (nanim.translation != null) {
                        nodeAnim.translation = new Array<>();
                        Array.ArrayIterator<NodeKeyframe<Vector3>> it2 = nanim.translation.iterator();
                        while (it2.hasNext()) {
                            NodeKeyframe<Vector3> kf = it2.next();
                            nodeAnim.translation.add(new NodeKeyframe<>(kf.keytime, kf.value));
                        }
                    }
                    if (nanim.rotation != null) {
                        nodeAnim.rotation = new Array<>();
                        Array.ArrayIterator<NodeKeyframe<Quaternion>> it3 = nanim.rotation.iterator();
                        while (it3.hasNext()) {
                            NodeKeyframe<Quaternion> kf2 = it3.next();
                            nodeAnim.rotation.add(new NodeKeyframe<>(kf2.keytime, kf2.value));
                        }
                    }
                    if (nanim.scaling != null) {
                        nodeAnim.scaling = new Array<>();
                        Array.ArrayIterator<NodeKeyframe<Vector3>> it4 = nanim.scaling.iterator();
                        while (it4.hasNext()) {
                            NodeKeyframe<Vector3> kf3 = it4.next();
                            nodeAnim.scaling.add(new NodeKeyframe<>(kf3.keytime, kf3.value));
                        }
                    }
                }
                if (nodeAnim.translation != null || nodeAnim.rotation != null || nodeAnim.scaling != null) {
                    animation.nodeAnimations.add(nodeAnim);
                }
            }
        }
        if (animation.nodeAnimations.size > 0) {
            this.animations.add(animation);
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.RenderableProvider
    public void getRenderables(Array<Renderable> renderables, Pool<Renderable> pool) {
        Array.ArrayIterator<Node> it = this.nodes.iterator();
        while (it.hasNext()) {
            Node node = it.next();
            getRenderables(node, renderables, pool);
        }
    }

    public Renderable getRenderable(Renderable out) {
        return getRenderable(out, this.nodes.get(0));
    }

    public Renderable getRenderable(Renderable out, Node node) {
        return getRenderable(out, node, node.parts.get(0));
    }

    public Renderable getRenderable(Renderable out, Node node, NodePart nodePart) {
        nodePart.setRenderable(out);
        if (nodePart.bones == null && this.transform != null) {
            out.worldTransform.set(this.transform).mul(node.globalTransform);
        } else if (this.transform != null) {
            out.worldTransform.set(this.transform);
        } else {
            out.worldTransform.idt();
        }
        out.userData = this.userData;
        return out;
    }

    protected void getRenderables(Node node, Array<Renderable> renderables, Pool<Renderable> pool) {
        if (node.parts.size > 0) {
            Array.ArrayIterator<NodePart> it = node.parts.iterator();
            while (it.hasNext()) {
                NodePart nodePart = it.next();
                if (nodePart.enabled) {
                    renderables.add(getRenderable(pool.obtain(), node, nodePart));
                }
            }
        }
        for (Node child : node.getChildren()) {
            getRenderables(child, renderables, pool);
        }
    }

    public void calculateTransforms() {
        int n = this.nodes.size;
        for (int i = 0; i < n; i++) {
            this.nodes.get(i).calculateTransforms(true);
        }
        for (int i2 = 0; i2 < n; i2++) {
            this.nodes.get(i2).calculateBoneTransforms(true);
        }
    }

    public BoundingBox calculateBoundingBox(BoundingBox out) {
        out.inf();
        return extendBoundingBox(out);
    }

    public BoundingBox extendBoundingBox(BoundingBox out) {
        int n = this.nodes.size;
        for (int i = 0; i < n; i++) {
            this.nodes.get(i).extendBoundingBox(out);
        }
        return out;
    }

    public Animation getAnimation(String id) {
        return getAnimation(id, false);
    }

    public Animation getAnimation(String id, boolean ignoreCase) {
        int n = this.animations.size;
        if (ignoreCase) {
            for (int i = 0; i < n; i++) {
                Animation animation = this.animations.get(i);
                if (animation.id.equalsIgnoreCase(id)) {
                    return animation;
                }
            }
            return null;
        }
        for (int i2 = 0; i2 < n; i2++) {
            Animation animation2 = this.animations.get(i2);
            if (animation2.id.equals(id)) {
                return animation2;
            }
        }
        return null;
    }

    public Material getMaterial(String id) {
        return getMaterial(id, true);
    }

    public Material getMaterial(String id, boolean ignoreCase) {
        int n = this.materials.size;
        if (ignoreCase) {
            for (int i = 0; i < n; i++) {
                Material material = this.materials.get(i);
                if (material.id.equalsIgnoreCase(id)) {
                    return material;
                }
            }
            return null;
        }
        for (int i2 = 0; i2 < n; i2++) {
            Material material2 = this.materials.get(i2);
            if (material2.id.equals(id)) {
                return material2;
            }
        }
        return null;
    }

    public Node getNode(String id) {
        return getNode(id, true);
    }

    public Node getNode(String id, boolean recursive) {
        return getNode(id, recursive, false);
    }

    public Node getNode(String id, boolean recursive, boolean ignoreCase) {
        return Node.getNode(this.nodes, id, recursive, ignoreCase);
    }
}