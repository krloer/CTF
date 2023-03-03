package com.badlogic.gdx.graphics.g3d.loader;

import com.badlogic.gdx.assets.loaders.FileHandleResolver;
import com.badlogic.gdx.assets.loaders.ModelLoader;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.VertexAttribute;
import com.badlogic.gdx.graphics.g3d.attributes.FloatAttribute;
import com.badlogic.gdx.graphics.g3d.model.data.ModelAnimation;
import com.badlogic.gdx.graphics.g3d.model.data.ModelData;
import com.badlogic.gdx.graphics.g3d.model.data.ModelMaterial;
import com.badlogic.gdx.graphics.g3d.model.data.ModelMesh;
import com.badlogic.gdx.graphics.g3d.model.data.ModelMeshPart;
import com.badlogic.gdx.graphics.g3d.model.data.ModelNode;
import com.badlogic.gdx.graphics.g3d.model.data.ModelNodeAnimation;
import com.badlogic.gdx.graphics.g3d.model.data.ModelNodeKeyframe;
import com.badlogic.gdx.graphics.g3d.model.data.ModelNodePart;
import com.badlogic.gdx.graphics.g3d.model.data.ModelTexture;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Quaternion;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.ArrayMap;
import com.badlogic.gdx.utils.BaseJsonReader;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.JsonValue;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class G3dModelLoader extends ModelLoader<ModelLoader.ModelParameters> {
    public static final short VERSION_HI = 0;
    public static final short VERSION_LO = 1;
    protected final BaseJsonReader reader;
    protected final Quaternion tempQ;

    public G3dModelLoader(BaseJsonReader reader) {
        this(reader, null);
    }

    public G3dModelLoader(BaseJsonReader reader, FileHandleResolver resolver) {
        super(resolver);
        this.tempQ = new Quaternion();
        this.reader = reader;
    }

    @Override // com.badlogic.gdx.assets.loaders.ModelLoader
    public ModelData loadModelData(FileHandle fileHandle, ModelLoader.ModelParameters parameters) {
        return parseModel(fileHandle);
    }

    public ModelData parseModel(FileHandle handle) {
        JsonValue json = this.reader.parse(handle);
        ModelData model = new ModelData();
        JsonValue version = json.require("version");
        model.version[0] = version.getShort(0);
        model.version[1] = version.getShort(1);
        if (model.version[0] != 0 || model.version[1] != 1) {
            throw new GdxRuntimeException("Model version not supported");
        }
        model.id = json.getString("id", BuildConfig.FLAVOR);
        parseMeshes(model, json);
        parseMaterials(model, json, handle.parent().path());
        parseNodes(model, json);
        parseAnimations(model, json);
        return model;
    }

    protected void parseMeshes(ModelData model, JsonValue json) {
        JsonValue meshes = json.get("meshes");
        if (meshes != null) {
            model.meshes.ensureCapacity(meshes.size);
            JsonValue mesh = meshes.child;
            while (mesh != null) {
                ModelMesh jsonMesh = new ModelMesh();
                String id = mesh.getString("id", BuildConfig.FLAVOR);
                jsonMesh.id = id;
                JsonValue attributes = mesh.require("attributes");
                jsonMesh.attributes = parseAttributes(attributes);
                jsonMesh.vertices = mesh.require("vertices").asFloatArray();
                JsonValue meshParts = mesh.require("parts");
                Array<ModelMeshPart> parts = new Array<>();
                JsonValue meshPart = meshParts.child;
                while (meshPart != null) {
                    ModelMeshPart jsonPart = new ModelMeshPart();
                    String partId = meshPart.getString("id", null);
                    if (partId == null) {
                        throw new GdxRuntimeException("Not id given for mesh part");
                    }
                    Array.ArrayIterator<ModelMeshPart> it = parts.iterator();
                    while (it.hasNext()) {
                        ModelMeshPart other = (ModelMeshPart) it.next();
                        JsonValue meshes2 = meshes;
                        if (other.id.equals(partId)) {
                            throw new GdxRuntimeException("Mesh part with id '" + partId + "' already in defined");
                        }
                        meshes = meshes2;
                    }
                    JsonValue meshes3 = meshes;
                    jsonPart.id = partId;
                    String type = meshPart.getString("type", null);
                    if (type == null) {
                        throw new GdxRuntimeException("No primitive type given for mesh part '" + partId + "'");
                    }
                    jsonPart.primitiveType = parseType(type);
                    jsonPart.indices = meshPart.require("indices").asShortArray();
                    parts.add(jsonPart);
                    meshPart = meshPart.next;
                    meshes = meshes3;
                }
                jsonMesh.parts = (ModelMeshPart[]) parts.toArray(ModelMeshPart.class);
                model.meshes.add(jsonMesh);
                mesh = mesh.next;
                meshes = meshes;
            }
        }
    }

    protected int parseType(String type) {
        if (type.equals("TRIANGLES")) {
            return 4;
        }
        if (type.equals("LINES")) {
            return 1;
        }
        if (type.equals("POINTS")) {
            return 0;
        }
        if (type.equals("TRIANGLE_STRIP")) {
            return 5;
        }
        if (type.equals("LINE_STRIP")) {
            return 3;
        }
        throw new GdxRuntimeException("Unknown primitive type '" + type + "', should be one of triangle, trianglestrip, line, linestrip, lineloop or point");
    }

    protected VertexAttribute[] parseAttributes(JsonValue attributes) {
        Array<VertexAttribute> vertexAttributes = new Array<>();
        int unit = 0;
        int blendWeightCount = 0;
        for (JsonValue value = attributes.child; value != null; value = value.next) {
            String attribute = value.asString();
            if (!attribute.equals("POSITION")) {
                if (!attribute.equals("NORMAL")) {
                    if (!attribute.equals("COLOR")) {
                        if (!attribute.equals("COLORPACKED")) {
                            if (!attribute.equals("TANGENT")) {
                                if (!attribute.equals("BINORMAL")) {
                                    if (!attribute.startsWith("TEXCOORD")) {
                                        if (!attribute.startsWith("BLENDWEIGHT")) {
                                            throw new GdxRuntimeException("Unknown vertex attribute '" + attribute + "', should be one of position, normal, uv, tangent or binormal");
                                        }
                                        vertexAttributes.add(VertexAttribute.BoneWeight(blendWeightCount));
                                        blendWeightCount++;
                                    } else {
                                        vertexAttributes.add(VertexAttribute.TexCoords(unit));
                                        unit++;
                                    }
                                } else {
                                    vertexAttributes.add(VertexAttribute.Binormal());
                                }
                            } else {
                                vertexAttributes.add(VertexAttribute.Tangent());
                            }
                        } else {
                            vertexAttributes.add(VertexAttribute.ColorPacked());
                        }
                    } else {
                        vertexAttributes.add(VertexAttribute.ColorUnpacked());
                    }
                } else {
                    vertexAttributes.add(VertexAttribute.Normal());
                }
            } else {
                vertexAttributes.add(VertexAttribute.Position());
            }
        }
        return (VertexAttribute[]) vertexAttributes.toArray(VertexAttribute.class);
    }

    protected void parseMaterials(ModelData model, JsonValue json, String materialDir) {
        G3dModelLoader g3dModelLoader = this;
        JsonValue materials = json.get("materials");
        if (materials != null) {
            model.materials.ensureCapacity(materials.size);
            JsonValue material = materials.child;
            while (material != null) {
                ModelMaterial jsonMaterial = new ModelMaterial();
                String str = "id";
                String id = material.getString("id", null);
                if (id == null) {
                    throw new GdxRuntimeException("Material needs an id.");
                }
                jsonMaterial.id = id;
                JsonValue diffuse = material.get("diffuse");
                if (diffuse != null) {
                    jsonMaterial.diffuse = g3dModelLoader.parseColor(diffuse);
                }
                JsonValue ambient = material.get("ambient");
                if (ambient != null) {
                    jsonMaterial.ambient = g3dModelLoader.parseColor(ambient);
                }
                JsonValue emissive = material.get("emissive");
                if (emissive != null) {
                    jsonMaterial.emissive = g3dModelLoader.parseColor(emissive);
                }
                JsonValue specular = material.get("specular");
                if (specular != null) {
                    jsonMaterial.specular = g3dModelLoader.parseColor(specular);
                }
                JsonValue reflection = material.get("reflection");
                if (reflection != null) {
                    jsonMaterial.reflection = g3dModelLoader.parseColor(reflection);
                }
                jsonMaterial.shininess = material.getFloat(FloatAttribute.ShininessAlias, 0.0f);
                jsonMaterial.opacity = material.getFloat("opacity", 1.0f);
                JsonValue textures = material.get("textures");
                if (textures != null) {
                    JsonValue texture = textures.child;
                    while (texture != null) {
                        ModelTexture jsonTexture = new ModelTexture();
                        JsonValue materials2 = materials;
                        String textureId = texture.getString(str, null);
                        if (textureId == null) {
                            throw new GdxRuntimeException("Texture has no id.");
                        }
                        jsonTexture.id = textureId;
                        String str2 = str;
                        String fileName = texture.getString("filename", null);
                        if (fileName == null) {
                            throw new GdxRuntimeException("Texture needs filename.");
                        }
                        StringBuilder sb = new StringBuilder();
                        sb.append(materialDir);
                        String id2 = id;
                        String id3 = "/";
                        if (materialDir.length() == 0 || materialDir.endsWith("/")) {
                            id3 = BuildConfig.FLAVOR;
                        }
                        sb.append(id3);
                        sb.append(fileName);
                        jsonTexture.fileName = sb.toString();
                        jsonTexture.uvTranslation = g3dModelLoader.readVector2(texture.get("uvTranslation"), 0.0f, 0.0f);
                        jsonTexture.uvScaling = g3dModelLoader.readVector2(texture.get("uvScaling"), 1.0f, 1.0f);
                        String textureType = texture.getString("type", null);
                        if (textureType != null) {
                            jsonTexture.usage = g3dModelLoader.parseTextureUsage(textureType);
                            if (jsonMaterial.textures == null) {
                                jsonMaterial.textures = new Array<>();
                            }
                            jsonMaterial.textures.add(jsonTexture);
                            texture = texture.next;
                            materials = materials2;
                            str = str2;
                            id = id2;
                        } else {
                            throw new GdxRuntimeException("Texture needs type.");
                        }
                    }
                    continue;
                }
                model.materials.add(jsonMaterial);
                material = material.next;
                g3dModelLoader = this;
                materials = materials;
            }
        }
    }

    protected int parseTextureUsage(String value) {
        if (value.equalsIgnoreCase("AMBIENT")) {
            return 4;
        }
        if (value.equalsIgnoreCase("BUMP")) {
            return 8;
        }
        if (value.equalsIgnoreCase("DIFFUSE")) {
            return 2;
        }
        if (value.equalsIgnoreCase("EMISSIVE")) {
            return 3;
        }
        if (value.equalsIgnoreCase("NONE")) {
            return 1;
        }
        if (value.equalsIgnoreCase("NORMAL")) {
            return 7;
        }
        if (value.equalsIgnoreCase("REFLECTION")) {
            return 10;
        }
        if (value.equalsIgnoreCase("SHININESS")) {
            return 6;
        }
        if (value.equalsIgnoreCase("SPECULAR")) {
            return 5;
        }
        return value.equalsIgnoreCase("TRANSPARENCY") ? 9 : 0;
    }

    protected Color parseColor(JsonValue colorArray) {
        if (colorArray.size >= 3) {
            return new Color(colorArray.getFloat(0), colorArray.getFloat(1), colorArray.getFloat(2), 1.0f);
        }
        throw new GdxRuntimeException("Expected Color values <> than three.");
    }

    protected Vector2 readVector2(JsonValue vectorArray, float x, float y) {
        if (vectorArray == null) {
            return new Vector2(x, y);
        }
        if (vectorArray.size == 2) {
            return new Vector2(vectorArray.getFloat(0), vectorArray.getFloat(1));
        }
        throw new GdxRuntimeException("Expected Vector2 values <> than two.");
    }

    protected Array<ModelNode> parseNodes(ModelData model, JsonValue json) {
        JsonValue nodes = json.get("nodes");
        if (nodes != null) {
            model.nodes.ensureCapacity(nodes.size);
            for (JsonValue node = nodes.child; node != null; node = node.next) {
                model.nodes.add(parseNodesRecursively(node));
            }
        }
        return model.nodes;
    }

    protected ModelNode parseNodesRecursively(JsonValue json) {
        Vector3 vector3;
        Quaternion quaternion;
        String id;
        String str;
        JsonValue scale;
        JsonValue materials;
        String str2;
        JsonValue rotation;
        String id2;
        String str3;
        JsonValue bones;
        String str4;
        G3dModelLoader g3dModelLoader = this;
        ModelNode jsonNode = new ModelNode();
        String id3 = json.getString("id", null);
        if (id3 != null) {
            jsonNode.id = id3;
            String str5 = "translation";
            JsonValue translation = json.get("translation");
            if (translation == null || translation.size == 3) {
                if (translation == null) {
                    vector3 = null;
                } else {
                    vector3 = new Vector3(translation.getFloat(0), translation.getFloat(1), translation.getFloat(2));
                }
                jsonNode.translation = vector3;
                String str6 = "rotation";
                JsonValue rotation2 = json.get("rotation");
                if (rotation2 == null || rotation2.size == 4) {
                    if (rotation2 == null) {
                        quaternion = null;
                    } else {
                        quaternion = new Quaternion(rotation2.getFloat(0), rotation2.getFloat(1), rotation2.getFloat(2), rotation2.getFloat(3));
                    }
                    jsonNode.rotation = quaternion;
                    JsonValue scale2 = json.get("scale");
                    if (scale2 == null || scale2.size == 3) {
                        jsonNode.scale = scale2 == null ? null : new Vector3(scale2.getFloat(0), scale2.getFloat(1), scale2.getFloat(2));
                        String meshId = json.getString("mesh", null);
                        if (meshId != null) {
                            jsonNode.meshId = meshId;
                        }
                        JsonValue materials2 = json.get("parts");
                        if (materials2 != null) {
                            jsonNode.parts = new ModelNodePart[materials2.size];
                            int i = 0;
                            JsonValue material = materials2.child;
                            while (material != null) {
                                ModelNodePart nodePart = new ModelNodePart();
                                JsonValue translation2 = translation;
                                String meshPartId = material.getString("meshpartid", null);
                                String meshId2 = meshId;
                                String materialId = material.getString("materialid", null);
                                if (meshPartId == null || materialId == null) {
                                    throw new GdxRuntimeException("Node " + id3 + " part is missing meshPartId or materialId");
                                }
                                nodePart.materialId = materialId;
                                nodePart.meshPartId = meshPartId;
                                JsonValue bones2 = material.get("bones");
                                if (bones2 == null) {
                                    id = id3;
                                    str = str5;
                                    scale = scale2;
                                    materials = materials2;
                                    str2 = str6;
                                    rotation = rotation2;
                                } else {
                                    scale = scale2;
                                    materials = materials2;
                                    rotation = rotation2;
                                    nodePart.bones = new ArrayMap<>(true, bones2.size, String.class, Matrix4.class);
                                    int j = 0;
                                    JsonValue bone = bones2.child;
                                    while (bone != null) {
                                        String nodeId = bone.getString("node", null);
                                        if (nodeId == null) {
                                            throw new GdxRuntimeException("Bone node ID missing");
                                        }
                                        Matrix4 transform = new Matrix4();
                                        JsonValue val = bone.get(str5);
                                        if (val != null) {
                                            str3 = str5;
                                            bones = bones2;
                                            if (val.size >= 3) {
                                                id2 = id3;
                                                transform.translate(val.getFloat(0), val.getFloat(1), val.getFloat(2));
                                            } else {
                                                id2 = id3;
                                            }
                                        } else {
                                            id2 = id3;
                                            str3 = str5;
                                            bones = bones2;
                                        }
                                        JsonValue val2 = bone.get(str6);
                                        if (val2 == null || val2.size < 4) {
                                            str4 = str6;
                                        } else {
                                            str4 = str6;
                                            transform.rotate(g3dModelLoader.tempQ.set(val2.getFloat(0), val2.getFloat(1), val2.getFloat(2), val2.getFloat(3)));
                                        }
                                        JsonValue val3 = bone.get("scale");
                                        if (val3 != null && val3.size >= 3) {
                                            transform.scale(val3.getFloat(0), val3.getFloat(1), val3.getFloat(2));
                                            nodePart.bones.put(nodeId, transform);
                                            bone = bone.next;
                                            j++;
                                            g3dModelLoader = this;
                                            str5 = str3;
                                            bones2 = bones;
                                            id3 = id2;
                                            str6 = str4;
                                        }
                                        nodePart.bones.put(nodeId, transform);
                                        bone = bone.next;
                                        j++;
                                        g3dModelLoader = this;
                                        str5 = str3;
                                        bones2 = bones;
                                        id3 = id2;
                                        str6 = str4;
                                    }
                                    id = id3;
                                    str = str5;
                                    str2 = str6;
                                }
                                jsonNode.parts[i] = nodePart;
                                material = material.next;
                                i++;
                                g3dModelLoader = this;
                                translation = translation2;
                                meshId = meshId2;
                                scale2 = scale;
                                materials2 = materials;
                                rotation2 = rotation;
                                str5 = str;
                                id3 = id;
                                str6 = str2;
                            }
                        }
                        JsonValue children = json.get("children");
                        if (children != null) {
                            jsonNode.children = new ModelNode[children.size];
                            int i2 = 0;
                            JsonValue child = children.child;
                            while (child != null) {
                                jsonNode.children[i2] = parseNodesRecursively(child);
                                child = child.next;
                                i2++;
                            }
                        }
                        return jsonNode;
                    }
                    throw new GdxRuntimeException("Node scale incomplete");
                }
                throw new GdxRuntimeException("Node rotation incomplete");
            }
            throw new GdxRuntimeException("Node translation incomplete");
        }
        throw new GdxRuntimeException("Node id missing.");
    }

    /* JADX WARN: Type inference failed for: r12v2, types: [com.badlogic.gdx.math.Vector3, T] */
    /* JADX WARN: Type inference failed for: r2v15, types: [T, com.badlogic.gdx.math.Quaternion] */
    /* JADX WARN: Type inference failed for: r4v18, types: [com.badlogic.gdx.math.Vector3, T] */
    /* JADX WARN: Type inference failed for: r8v14, types: [com.badlogic.gdx.math.Vector3, T] */
    /* JADX WARN: Type inference failed for: r9v16, types: [com.badlogic.gdx.math.Vector3, T] */
    /* JADX WARN: Type inference failed for: r9v7, types: [T, com.badlogic.gdx.math.Quaternion] */
    protected void parseAnimations(ModelData model, JsonValue json) {
        JsonValue animations;
        JsonValue animations2;
        JsonValue nodes;
        ModelAnimation animation;
        JsonValue animations3;
        JsonValue nodes2;
        ModelAnimation animation2;
        JsonValue keyframes;
        ModelData modelData = model;
        JsonValue animations4 = json.get("animations");
        if (animations4 == null) {
            return;
        }
        modelData.animations.ensureCapacity(animations4.size);
        JsonValue anim = animations4.child;
        while (anim != null) {
            JsonValue nodes3 = anim.get("bones");
            if (nodes3 == null) {
                animations = animations4;
            } else {
                ModelAnimation animation3 = new ModelAnimation();
                modelData.animations.add(animation3);
                animation3.nodeAnimations.ensureCapacity(nodes3.size);
                animation3.id = anim.getString("id");
                JsonValue node = nodes3.child;
                while (node != null) {
                    ModelNodeAnimation nodeAnim = new ModelNodeAnimation();
                    animation3.nodeAnimations.add(nodeAnim);
                    nodeAnim.nodeId = node.getString("boneId");
                    JsonValue keyframes2 = node.get("keyframes");
                    float f = 1000.0f;
                    float f2 = 0.0f;
                    int i = 3;
                    if (keyframes2 == null || !keyframes2.isArray()) {
                        animations2 = animations4;
                        nodes = nodes3;
                        animation = animation3;
                        JsonValue translationKF = node.get("translation");
                        if (translationKF != null && translationKF.isArray()) {
                            nodeAnim.translation = new Array<>();
                            nodeAnim.translation.ensureCapacity(translationKF.size);
                            for (JsonValue keyframe = translationKF.child; keyframe != null; keyframe = keyframe.next) {
                                ModelNodeKeyframe<Vector3> kf = new ModelNodeKeyframe<>();
                                nodeAnim.translation.add(kf);
                                kf.keytime = keyframe.getFloat("keytime", 0.0f) / 1000.0f;
                                JsonValue translation = keyframe.get("value");
                                if (translation != null && translation.size >= 3) {
                                    kf.value = new Vector3(translation.getFloat(0), translation.getFloat(1), translation.getFloat(2));
                                }
                            }
                        }
                        JsonValue rotationKF = node.get("rotation");
                        if (rotationKF != null && rotationKF.isArray()) {
                            nodeAnim.rotation = new Array<>();
                            nodeAnim.rotation.ensureCapacity(rotationKF.size);
                            for (JsonValue keyframe2 = rotationKF.child; keyframe2 != null; keyframe2 = keyframe2.next) {
                                ModelNodeKeyframe<Quaternion> kf2 = new ModelNodeKeyframe<>();
                                nodeAnim.rotation.add(kf2);
                                kf2.keytime = keyframe2.getFloat("keytime", 0.0f) / 1000.0f;
                                JsonValue rotation = keyframe2.get("value");
                                if (rotation != null && rotation.size >= 4) {
                                    kf2.value = new Quaternion(rotation.getFloat(0), rotation.getFloat(1), rotation.getFloat(2), rotation.getFloat(3));
                                }
                            }
                        }
                        JsonValue scalingKF = node.get("scaling");
                        if (scalingKF != null && scalingKF.isArray()) {
                            nodeAnim.scaling = new Array<>();
                            nodeAnim.scaling.ensureCapacity(scalingKF.size);
                            for (JsonValue keyframe3 = scalingKF.child; keyframe3 != null; keyframe3 = keyframe3.next) {
                                ModelNodeKeyframe<Vector3> kf3 = new ModelNodeKeyframe<>();
                                nodeAnim.scaling.add(kf3);
                                kf3.keytime = keyframe3.getFloat("keytime", 0.0f) / 1000.0f;
                                JsonValue scaling = keyframe3.get("value");
                                if (scaling != null && scaling.size >= 3) {
                                    kf3.value = new Vector3(scaling.getFloat(0), scaling.getFloat(1), scaling.getFloat(2));
                                }
                            }
                        }
                    } else {
                        JsonValue keyframe4 = keyframes2.child;
                        while (keyframe4 != null) {
                            float keytime = keyframe4.getFloat("keytime", f2) / f;
                            JsonValue translation2 = keyframe4.get("translation");
                            if (translation2 == null || translation2.size != i) {
                                animations3 = animations4;
                                nodes2 = nodes3;
                                animation2 = animation3;
                            } else {
                                if (nodeAnim.translation == null) {
                                    nodeAnim.translation = new Array<>();
                                }
                                ModelNodeKeyframe<Vector3> tkf = new ModelNodeKeyframe<>();
                                tkf.keytime = keytime;
                                animations3 = animations4;
                                nodes2 = nodes3;
                                animation2 = animation3;
                                tkf.value = new Vector3(translation2.getFloat(0), translation2.getFloat(1), translation2.getFloat(2));
                                nodeAnim.translation.add(tkf);
                            }
                            JsonValue rotation2 = keyframe4.get("rotation");
                            if (rotation2 == null || rotation2.size != 4) {
                                keyframes = keyframes2;
                            } else {
                                if (nodeAnim.rotation == null) {
                                    nodeAnim.rotation = new Array<>();
                                }
                                ModelNodeKeyframe<Quaternion> rkf = new ModelNodeKeyframe<>();
                                rkf.keytime = keytime;
                                keyframes = keyframes2;
                                rkf.value = new Quaternion(rotation2.getFloat(0), rotation2.getFloat(1), rotation2.getFloat(2), rotation2.getFloat(3));
                                nodeAnim.rotation.add(rkf);
                            }
                            JsonValue scale = keyframe4.get("scale");
                            if (scale != null && scale.size == 3) {
                                if (nodeAnim.scaling == null) {
                                    nodeAnim.scaling = new Array<>();
                                }
                                ModelNodeKeyframe<Vector3> skf = new ModelNodeKeyframe<>();
                                skf.keytime = keytime;
                                skf.value = new Vector3(scale.getFloat(0), scale.getFloat(1), scale.getFloat(2));
                                nodeAnim.scaling.add(skf);
                            }
                            keyframe4 = keyframe4.next;
                            animations4 = animations3;
                            nodes3 = nodes2;
                            animation3 = animation2;
                            keyframes2 = keyframes;
                            i = 3;
                            f = 1000.0f;
                            f2 = 0.0f;
                        }
                        animations2 = animations4;
                        nodes = nodes3;
                        animation = animation3;
                    }
                    node = node.next;
                    animations4 = animations2;
                    nodes3 = nodes;
                    animation3 = animation;
                }
                animations = animations4;
            }
            anim = anim.next;
            modelData = model;
            animations4 = animations;
        }
    }
}