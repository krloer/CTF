package com.badlogic.gdx.graphics.g3d.decals;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.math.Quaternion;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.NumberUtils;

/* loaded from: classes.dex */
public class Decal {
    public static final int C1 = 3;
    public static final int C2 = 9;
    public static final int C3 = 15;
    public static final int C4 = 21;
    public static final int SIZE = 24;
    public static final int U1 = 4;
    public static final int U2 = 10;
    public static final int U3 = 16;
    public static final int U4 = 22;
    public static final int V1 = 5;
    public static final int V2 = 11;
    public static final int V3 = 17;
    public static final int V4 = 23;
    private static final int VERTEX_SIZE = 6;
    public static final int X1 = 0;
    public static final int X2 = 6;
    public static final int X3 = 12;
    public static final int X4 = 18;
    public static final int Y1 = 1;
    public static final int Y2 = 7;
    public static final int Y3 = 13;
    public static final int Y4 = 19;
    public static final int Z1 = 2;
    public static final int Z2 = 8;
    public static final int Z3 = 14;
    public static final int Z4 = 20;
    protected Color color;
    protected Vector2 dimensions;
    protected DecalMaterial material;
    protected Vector3 position;
    protected Quaternion rotation;
    protected Vector2 scale;
    public Vector2 transformationOffset;
    protected boolean updated;
    public int value;
    protected float[] vertices;
    private static Vector3 tmp = new Vector3();
    private static Vector3 tmp2 = new Vector3();
    static final Vector3 dir = new Vector3();
    protected static Quaternion rotator = new Quaternion(0.0f, 0.0f, 0.0f, 0.0f);

    public Decal() {
        this.vertices = new float[24];
        this.position = new Vector3();
        this.rotation = new Quaternion();
        this.scale = new Vector2(1.0f, 1.0f);
        this.color = new Color();
        this.transformationOffset = null;
        this.dimensions = new Vector2();
        this.updated = false;
        this.material = new DecalMaterial();
    }

    public Decal(DecalMaterial material) {
        this.vertices = new float[24];
        this.position = new Vector3();
        this.rotation = new Quaternion();
        this.scale = new Vector2(1.0f, 1.0f);
        this.color = new Color();
        this.transformationOffset = null;
        this.dimensions = new Vector2();
        this.updated = false;
        this.material = material;
    }

    public void setColor(float r, float g, float b, float a) {
        this.color.set(r, g, b, a);
        int intBits = ((int) (255.0f * r)) | (((int) (a * 255.0f)) << 24) | (((int) (b * 255.0f)) << 16) | (((int) (g * 255.0f)) << 8);
        float color = NumberUtils.intToFloatColor(intBits);
        float[] fArr = this.vertices;
        fArr[3] = color;
        fArr[9] = color;
        fArr[15] = color;
        fArr[21] = color;
    }

    public void setColor(Color tint) {
        this.color.set(tint);
        float color = tint.toFloatBits();
        float[] fArr = this.vertices;
        fArr[3] = color;
        fArr[9] = color;
        fArr[15] = color;
        fArr[21] = color;
    }

    public void setPackedColor(float color) {
        Color.abgr8888ToColor(this.color, color);
        float[] fArr = this.vertices;
        fArr[3] = color;
        fArr[9] = color;
        fArr[15] = color;
        fArr[21] = color;
    }

    public void setRotationX(float angle) {
        this.rotation.set(Vector3.X, angle);
        this.updated = false;
    }

    public void setRotationY(float angle) {
        this.rotation.set(Vector3.Y, angle);
        this.updated = false;
    }

    public void setRotationZ(float angle) {
        this.rotation.set(Vector3.Z, angle);
        this.updated = false;
    }

    public void rotateX(float angle) {
        rotator.set(Vector3.X, angle);
        this.rotation.mul(rotator);
        this.updated = false;
    }

    public void rotateY(float angle) {
        rotator.set(Vector3.Y, angle);
        this.rotation.mul(rotator);
        this.updated = false;
    }

    public void rotateZ(float angle) {
        rotator.set(Vector3.Z, angle);
        this.rotation.mul(rotator);
        this.updated = false;
    }

    public void setRotation(float yaw, float pitch, float roll) {
        this.rotation.setEulerAngles(yaw, pitch, roll);
        this.updated = false;
    }

    public void setRotation(Vector3 dir2, Vector3 up) {
        tmp.set(up).crs(dir2).nor();
        tmp2.set(dir2).crs(tmp).nor();
        this.rotation.setFromAxes(tmp.x, tmp2.x, dir2.x, tmp.y, tmp2.y, dir2.y, tmp.z, tmp2.z, dir2.z);
        this.updated = false;
    }

    public void setRotation(Quaternion q) {
        this.rotation.set(q);
        this.updated = false;
    }

    public Quaternion getRotation() {
        return this.rotation;
    }

    public void translateX(float units) {
        this.position.x += units;
        this.updated = false;
    }

    public void setX(float x) {
        this.position.x = x;
        this.updated = false;
    }

    public float getX() {
        return this.position.x;
    }

    public void translateY(float units) {
        this.position.y += units;
        this.updated = false;
    }

    public void setY(float y) {
        this.position.y = y;
        this.updated = false;
    }

    public float getY() {
        return this.position.y;
    }

    public void translateZ(float units) {
        this.position.z += units;
        this.updated = false;
    }

    public void setZ(float z) {
        this.position.z = z;
        this.updated = false;
    }

    public float getZ() {
        return this.position.z;
    }

    public void translate(float x, float y, float z) {
        this.position.add(x, y, z);
        this.updated = false;
    }

    public void translate(Vector3 trans) {
        this.position.add(trans);
        this.updated = false;
    }

    public void setPosition(float x, float y, float z) {
        this.position.set(x, y, z);
        this.updated = false;
    }

    public void setPosition(Vector3 pos) {
        this.position.set(pos);
        this.updated = false;
    }

    public Color getColor() {
        return this.color;
    }

    public Vector3 getPosition() {
        return this.position;
    }

    public void setScaleX(float scale) {
        this.scale.x = scale;
        this.updated = false;
    }

    public float getScaleX() {
        return this.scale.x;
    }

    public void setScaleY(float scale) {
        this.scale.y = scale;
        this.updated = false;
    }

    public float getScaleY() {
        return this.scale.y;
    }

    public void setScale(float scaleX, float scaleY) {
        this.scale.set(scaleX, scaleY);
        this.updated = false;
    }

    public void setScale(float scale) {
        this.scale.set(scale, scale);
        this.updated = false;
    }

    public void setWidth(float width) {
        this.dimensions.x = width;
        this.updated = false;
    }

    public float getWidth() {
        return this.dimensions.x;
    }

    public void setHeight(float height) {
        this.dimensions.y = height;
        this.updated = false;
    }

    public float getHeight() {
        return this.dimensions.y;
    }

    public void setDimensions(float width, float height) {
        this.dimensions.set(width, height);
        this.updated = false;
    }

    public float[] getVertices() {
        update();
        return this.vertices;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void update() {
        if (!this.updated) {
            resetVertices();
            transformVertices();
        }
    }

    protected void transformVertices() {
        float tx;
        float ty;
        Vector2 vector2 = this.transformationOffset;
        if (vector2 != null) {
            tx = -vector2.x;
            ty = -this.transformationOffset.y;
        } else {
            tx = 0.0f;
            ty = 0.0f;
        }
        float x = (this.vertices[0] + tx) * this.scale.x;
        float y = (this.vertices[1] + ty) * this.scale.y;
        float[] fArr = this.vertices;
        float z = fArr[2];
        fArr[0] = ((this.rotation.w * x) + (this.rotation.y * z)) - (this.rotation.z * y);
        this.vertices[1] = ((this.rotation.w * y) + (this.rotation.z * x)) - (this.rotation.x * z);
        this.vertices[2] = ((this.rotation.w * z) + (this.rotation.x * y)) - (this.rotation.y * x);
        float w = (((-this.rotation.x) * x) - (this.rotation.y * y)) - (this.rotation.z * z);
        this.rotation.conjugate();
        float[] fArr2 = this.vertices;
        float x2 = fArr2[0];
        float y2 = fArr2[1];
        float z2 = fArr2[2];
        fArr2[0] = (((this.rotation.x * w) + (this.rotation.w * x2)) + (this.rotation.z * y2)) - (this.rotation.y * z2);
        this.vertices[1] = (((this.rotation.y * w) + (this.rotation.w * y2)) + (this.rotation.x * z2)) - (this.rotation.z * x2);
        this.vertices[2] = (((this.rotation.z * w) + (this.rotation.w * z2)) + (this.rotation.y * x2)) - (this.rotation.x * y2);
        this.rotation.conjugate();
        float[] fArr3 = this.vertices;
        fArr3[0] = fArr3[0] + (this.position.x - tx);
        float[] fArr4 = this.vertices;
        fArr4[1] = fArr4[1] + (this.position.y - ty);
        float[] fArr5 = this.vertices;
        fArr5[2] = fArr5[2] + this.position.z;
        float x3 = (this.vertices[6] + tx) * this.scale.x;
        float y3 = (this.vertices[7] + ty) * this.scale.y;
        float[] fArr6 = this.vertices;
        float z3 = fArr6[8];
        fArr6[6] = ((this.rotation.w * x3) + (this.rotation.y * z3)) - (this.rotation.z * y3);
        this.vertices[7] = ((this.rotation.w * y3) + (this.rotation.z * x3)) - (this.rotation.x * z3);
        this.vertices[8] = ((this.rotation.w * z3) + (this.rotation.x * y3)) - (this.rotation.y * x3);
        float w2 = (((-this.rotation.x) * x3) - (this.rotation.y * y3)) - (this.rotation.z * z3);
        this.rotation.conjugate();
        float[] fArr7 = this.vertices;
        float x4 = fArr7[6];
        float y4 = fArr7[7];
        float z4 = fArr7[8];
        fArr7[6] = (((this.rotation.x * w2) + (this.rotation.w * x4)) + (this.rotation.z * y4)) - (this.rotation.y * z4);
        this.vertices[7] = (((this.rotation.y * w2) + (this.rotation.w * y4)) + (this.rotation.x * z4)) - (this.rotation.z * x4);
        this.vertices[8] = (((this.rotation.z * w2) + (this.rotation.w * z4)) + (this.rotation.y * x4)) - (this.rotation.x * y4);
        this.rotation.conjugate();
        float[] fArr8 = this.vertices;
        fArr8[6] = fArr8[6] + (this.position.x - tx);
        float[] fArr9 = this.vertices;
        fArr9[7] = fArr9[7] + (this.position.y - ty);
        float[] fArr10 = this.vertices;
        fArr10[8] = fArr10[8] + this.position.z;
        float x5 = (this.vertices[12] + tx) * this.scale.x;
        float y5 = (this.vertices[13] + ty) * this.scale.y;
        float[] fArr11 = this.vertices;
        float z5 = fArr11[14];
        fArr11[12] = ((this.rotation.w * x5) + (this.rotation.y * z5)) - (this.rotation.z * y5);
        this.vertices[13] = ((this.rotation.w * y5) + (this.rotation.z * x5)) - (this.rotation.x * z5);
        this.vertices[14] = ((this.rotation.w * z5) + (this.rotation.x * y5)) - (this.rotation.y * x5);
        float w3 = (((-this.rotation.x) * x5) - (this.rotation.y * y5)) - (this.rotation.z * z5);
        this.rotation.conjugate();
        float[] fArr12 = this.vertices;
        float x6 = fArr12[12];
        float y6 = fArr12[13];
        float z6 = fArr12[14];
        fArr12[12] = (((this.rotation.x * w3) + (this.rotation.w * x6)) + (this.rotation.z * y6)) - (this.rotation.y * z6);
        this.vertices[13] = (((this.rotation.y * w3) + (this.rotation.w * y6)) + (this.rotation.x * z6)) - (this.rotation.z * x6);
        this.vertices[14] = (((this.rotation.z * w3) + (this.rotation.w * z6)) + (this.rotation.y * x6)) - (this.rotation.x * y6);
        this.rotation.conjugate();
        float[] fArr13 = this.vertices;
        fArr13[12] = fArr13[12] + (this.position.x - tx);
        float[] fArr14 = this.vertices;
        fArr14[13] = fArr14[13] + (this.position.y - ty);
        float[] fArr15 = this.vertices;
        fArr15[14] = fArr15[14] + this.position.z;
        float x7 = (this.vertices[18] + tx) * this.scale.x;
        float y7 = (this.vertices[19] + ty) * this.scale.y;
        float[] fArr16 = this.vertices;
        float z7 = fArr16[20];
        fArr16[18] = ((this.rotation.w * x7) + (this.rotation.y * z7)) - (this.rotation.z * y7);
        this.vertices[19] = ((this.rotation.w * y7) + (this.rotation.z * x7)) - (this.rotation.x * z7);
        this.vertices[20] = ((this.rotation.w * z7) + (this.rotation.x * y7)) - (this.rotation.y * x7);
        float w4 = (((-this.rotation.x) * x7) - (this.rotation.y * y7)) - (this.rotation.z * z7);
        this.rotation.conjugate();
        float[] fArr17 = this.vertices;
        float x8 = fArr17[18];
        float y8 = fArr17[19];
        float z8 = fArr17[20];
        fArr17[18] = (((this.rotation.x * w4) + (this.rotation.w * x8)) + (this.rotation.z * y8)) - (this.rotation.y * z8);
        this.vertices[19] = (((this.rotation.y * w4) + (this.rotation.w * y8)) + (this.rotation.x * z8)) - (this.rotation.z * x8);
        this.vertices[20] = (((this.rotation.z * w4) + (this.rotation.w * z8)) + (this.rotation.y * x8)) - (this.rotation.x * y8);
        this.rotation.conjugate();
        float[] fArr18 = this.vertices;
        fArr18[18] = fArr18[18] + (this.position.x - tx);
        float[] fArr19 = this.vertices;
        fArr19[19] = fArr19[19] + (this.position.y - ty);
        float[] fArr20 = this.vertices;
        fArr20[20] = fArr20[20] + this.position.z;
        this.updated = true;
    }

    protected void resetVertices() {
        float left = (-this.dimensions.x) / 2.0f;
        float right = this.dimensions.x + left;
        float top = this.dimensions.y / 2.0f;
        float bottom = top - this.dimensions.y;
        float[] fArr = this.vertices;
        fArr[0] = left;
        fArr[1] = top;
        fArr[2] = 0.0f;
        fArr[6] = right;
        fArr[7] = top;
        fArr[8] = 0.0f;
        fArr[12] = left;
        fArr[13] = bottom;
        fArr[14] = 0.0f;
        fArr[18] = right;
        fArr[19] = bottom;
        fArr[20] = 0.0f;
        this.updated = false;
    }

    protected void updateUVs() {
        TextureRegion tr = this.material.textureRegion;
        this.vertices[4] = tr.getU();
        this.vertices[5] = tr.getV();
        this.vertices[10] = tr.getU2();
        this.vertices[11] = tr.getV();
        this.vertices[16] = tr.getU();
        this.vertices[17] = tr.getV2();
        this.vertices[22] = tr.getU2();
        this.vertices[23] = tr.getV2();
    }

    public void setTextureRegion(TextureRegion textureRegion) {
        this.material.textureRegion = textureRegion;
        updateUVs();
    }

    public TextureRegion getTextureRegion() {
        return this.material.textureRegion;
    }

    public void setBlending(int srcBlendFactor, int dstBlendFactor) {
        DecalMaterial decalMaterial = this.material;
        decalMaterial.srcBlendFactor = srcBlendFactor;
        decalMaterial.dstBlendFactor = dstBlendFactor;
    }

    public DecalMaterial getMaterial() {
        return this.material;
    }

    public void setMaterial(DecalMaterial material) {
        this.material = material;
    }

    public void lookAt(Vector3 position, Vector3 up) {
        dir.set(position).sub(this.position).nor();
        setRotation(dir, up);
    }

    public static Decal newDecal(TextureRegion textureRegion) {
        return newDecal(textureRegion.getRegionWidth(), textureRegion.getRegionHeight(), textureRegion, -1, -1);
    }

    public static Decal newDecal(TextureRegion textureRegion, boolean hasTransparency) {
        return newDecal(textureRegion.getRegionWidth(), textureRegion.getRegionHeight(), textureRegion, hasTransparency ? GL20.GL_SRC_ALPHA : -1, hasTransparency ? GL20.GL_ONE_MINUS_SRC_ALPHA : -1);
    }

    public static Decal newDecal(float width, float height, TextureRegion textureRegion) {
        return newDecal(width, height, textureRegion, -1, -1);
    }

    public static Decal newDecal(float width, float height, TextureRegion textureRegion, boolean hasTransparency) {
        return newDecal(width, height, textureRegion, hasTransparency ? GL20.GL_SRC_ALPHA : -1, hasTransparency ? GL20.GL_ONE_MINUS_SRC_ALPHA : -1);
    }

    public static Decal newDecal(float width, float height, TextureRegion textureRegion, int srcBlendFactor, int dstBlendFactor) {
        Decal decal = new Decal();
        decal.setTextureRegion(textureRegion);
        decal.setBlending(srcBlendFactor, dstBlendFactor);
        Vector2 vector2 = decal.dimensions;
        vector2.x = width;
        vector2.y = height;
        decal.setColor(1.0f, 1.0f, 1.0f, 1.0f);
        return decal;
    }

    public static Decal newDecal(float width, float height, TextureRegion textureRegion, int srcBlendFactor, int dstBlendFactor, DecalMaterial material) {
        Decal decal = new Decal(material);
        decal.setTextureRegion(textureRegion);
        decal.setBlending(srcBlendFactor, dstBlendFactor);
        Vector2 vector2 = decal.dimensions;
        vector2.x = width;
        vector2.y = height;
        decal.setColor(1.0f, 1.0f, 1.0f, 1.0f);
        return decal;
    }
}