package com.badlogic.gdx.math;

import java.io.Serializable;

/* loaded from: classes.dex */
public class Matrix4 implements Serializable {
    public static final int M00 = 0;
    public static final int M01 = 4;
    public static final int M02 = 8;
    public static final int M03 = 12;
    public static final int M10 = 1;
    public static final int M11 = 5;
    public static final int M12 = 9;
    public static final int M13 = 13;
    public static final int M20 = 2;
    public static final int M21 = 6;
    public static final int M22 = 10;
    public static final int M23 = 14;
    public static final int M30 = 3;
    public static final int M31 = 7;
    public static final int M32 = 11;
    public static final int M33 = 15;
    private static final long serialVersionUID = -2717655254359579617L;
    public final float[] val;
    static final Quaternion quat = new Quaternion();
    static final Quaternion quat2 = new Quaternion();
    static final Vector3 l_vez = new Vector3();
    static final Vector3 l_vex = new Vector3();
    static final Vector3 l_vey = new Vector3();
    static final Vector3 tmpVec = new Vector3();
    static final Matrix4 tmpMat = new Matrix4();
    static final Vector3 right = new Vector3();
    static final Vector3 tmpForward = new Vector3();
    static final Vector3 tmpUp = new Vector3();

    public static native void mulVec(float[] fArr, float[] fArr2, int i, int i2, int i3);

    public static native void prj(float[] fArr, float[] fArr2, int i, int i2, int i3);

    public static native void rot(float[] fArr, float[] fArr2, int i, int i2, int i3);

    public Matrix4() {
        this.val = new float[16];
        float[] fArr = this.val;
        fArr[0] = 1.0f;
        fArr[5] = 1.0f;
        fArr[10] = 1.0f;
        fArr[15] = 1.0f;
    }

    public Matrix4(Matrix4 matrix) {
        this.val = new float[16];
        set(matrix);
    }

    public Matrix4(float[] values) {
        this.val = new float[16];
        set(values);
    }

    public Matrix4(Quaternion quaternion) {
        this.val = new float[16];
        set(quaternion);
    }

    public Matrix4(Vector3 position, Quaternion rotation, Vector3 scale) {
        this.val = new float[16];
        set(position, rotation, scale);
    }

    public Matrix4 set(Matrix4 matrix) {
        return set(matrix.val);
    }

    public Matrix4 set(float[] values) {
        float[] fArr = this.val;
        System.arraycopy(values, 0, fArr, 0, fArr.length);
        return this;
    }

    public Matrix4 set(Quaternion quaternion) {
        return set(quaternion.x, quaternion.y, quaternion.z, quaternion.w);
    }

    public Matrix4 set(float quaternionX, float quaternionY, float quaternionZ, float quaternionW) {
        return set(0.0f, 0.0f, 0.0f, quaternionX, quaternionY, quaternionZ, quaternionW);
    }

    public Matrix4 set(Vector3 position, Quaternion orientation) {
        return set(position.x, position.y, position.z, orientation.x, orientation.y, orientation.z, orientation.w);
    }

    public Matrix4 set(float translationX, float translationY, float translationZ, float quaternionX, float quaternionY, float quaternionZ, float quaternionW) {
        float xs = quaternionX * 2.0f;
        float ys = quaternionY * 2.0f;
        float zs = 2.0f * quaternionZ;
        float wx = quaternionW * xs;
        float wy = quaternionW * ys;
        float wz = quaternionW * zs;
        float xx = quaternionX * xs;
        float xy = quaternionX * ys;
        float xz = quaternionX * zs;
        float yy = quaternionY * ys;
        float yz = quaternionY * zs;
        float zz = quaternionZ * zs;
        float[] fArr = this.val;
        fArr[0] = 1.0f - (yy + zz);
        fArr[4] = xy - wz;
        fArr[8] = xz + wy;
        fArr[12] = translationX;
        fArr[1] = xy + wz;
        fArr[5] = 1.0f - (xx + zz);
        fArr[9] = yz - wx;
        fArr[13] = translationY;
        fArr[2] = xz - wy;
        fArr[6] = yz + wx;
        fArr[10] = 1.0f - (xx + yy);
        fArr[14] = translationZ;
        fArr[3] = 0.0f;
        fArr[7] = 0.0f;
        fArr[11] = 0.0f;
        fArr[15] = 1.0f;
        return this;
    }

    public Matrix4 set(Vector3 position, Quaternion orientation, Vector3 scale) {
        return set(position.x, position.y, position.z, orientation.x, orientation.y, orientation.z, orientation.w, scale.x, scale.y, scale.z);
    }

    public Matrix4 set(float translationX, float translationY, float translationZ, float quaternionX, float quaternionY, float quaternionZ, float quaternionW, float scaleX, float scaleY, float scaleZ) {
        float xs = quaternionX * 2.0f;
        float ys = quaternionY * 2.0f;
        float zs = 2.0f * quaternionZ;
        float wx = quaternionW * xs;
        float wy = quaternionW * ys;
        float wz = quaternionW * zs;
        float xx = quaternionX * xs;
        float xy = quaternionX * ys;
        float xz = quaternionX * zs;
        float yy = quaternionY * ys;
        float yz = quaternionY * zs;
        float zz = quaternionZ * zs;
        float[] fArr = this.val;
        fArr[0] = (1.0f - (yy + zz)) * scaleX;
        fArr[4] = (xy - wz) * scaleY;
        fArr[8] = (xz + wy) * scaleZ;
        fArr[12] = translationX;
        fArr[1] = (xy + wz) * scaleX;
        fArr[5] = (1.0f - (xx + zz)) * scaleY;
        fArr[9] = (yz - wx) * scaleZ;
        fArr[13] = translationY;
        fArr[2] = (xz - wy) * scaleX;
        fArr[6] = (yz + wx) * scaleY;
        fArr[10] = (1.0f - (xx + yy)) * scaleZ;
        fArr[14] = translationZ;
        fArr[3] = 0.0f;
        fArr[7] = 0.0f;
        fArr[11] = 0.0f;
        fArr[15] = 1.0f;
        return this;
    }

    public Matrix4 set(Vector3 xAxis, Vector3 yAxis, Vector3 zAxis, Vector3 pos) {
        this.val[0] = xAxis.x;
        this.val[4] = xAxis.y;
        this.val[8] = xAxis.z;
        this.val[1] = yAxis.x;
        this.val[5] = yAxis.y;
        this.val[9] = yAxis.z;
        this.val[2] = zAxis.x;
        this.val[6] = zAxis.y;
        this.val[10] = zAxis.z;
        this.val[12] = pos.x;
        this.val[13] = pos.y;
        this.val[14] = pos.z;
        float[] fArr = this.val;
        fArr[3] = 0.0f;
        fArr[7] = 0.0f;
        fArr[11] = 0.0f;
        fArr[15] = 1.0f;
        return this;
    }

    public Matrix4 cpy() {
        return new Matrix4(this);
    }

    public Matrix4 trn(Vector3 vector) {
        float[] fArr = this.val;
        fArr[12] = fArr[12] + vector.x;
        float[] fArr2 = this.val;
        fArr2[13] = fArr2[13] + vector.y;
        float[] fArr3 = this.val;
        fArr3[14] = fArr3[14] + vector.z;
        return this;
    }

    public Matrix4 trn(float x, float y, float z) {
        float[] fArr = this.val;
        fArr[12] = fArr[12] + x;
        fArr[13] = fArr[13] + y;
        fArr[14] = fArr[14] + z;
        return this;
    }

    public float[] getValues() {
        return this.val;
    }

    public Matrix4 mul(Matrix4 matrix) {
        mul(this.val, matrix.val);
        return this;
    }

    public Matrix4 mulLeft(Matrix4 matrix) {
        tmpMat.set(matrix);
        mul(tmpMat.val, this.val);
        return set(tmpMat);
    }

    public Matrix4 tra() {
        float[] fArr = this.val;
        float m01 = fArr[4];
        float m02 = fArr[8];
        float m03 = fArr[12];
        float m12 = fArr[9];
        float m13 = fArr[13];
        float m23 = fArr[14];
        fArr[4] = fArr[1];
        fArr[8] = fArr[2];
        fArr[12] = fArr[3];
        fArr[1] = m01;
        fArr[9] = fArr[6];
        fArr[13] = fArr[7];
        fArr[2] = m02;
        fArr[6] = m12;
        fArr[14] = fArr[11];
        fArr[3] = m03;
        fArr[7] = m13;
        fArr[11] = m23;
        return this;
    }

    public Matrix4 idt() {
        float[] fArr = this.val;
        fArr[0] = 1.0f;
        fArr[4] = 0.0f;
        fArr[8] = 0.0f;
        fArr[12] = 0.0f;
        fArr[1] = 0.0f;
        fArr[5] = 1.0f;
        fArr[9] = 0.0f;
        fArr[13] = 0.0f;
        fArr[2] = 0.0f;
        fArr[6] = 0.0f;
        fArr[10] = 1.0f;
        fArr[14] = 0.0f;
        fArr[3] = 0.0f;
        fArr[7] = 0.0f;
        fArr[11] = 0.0f;
        fArr[15] = 1.0f;
        return this;
    }

    /*  JADX ERROR: Type inference failed with exception
        jadx.core.utils.exceptions.JadxOverflowException: Type update terminated with stack overflow, arg: (r23v27 ?? I:float)
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:56)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:30)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:18)
        	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:114)
        */
    public com.badlogic.gdx.math.Matrix4 inv() {
        /*
            Method dump skipped, instructions count: 1654
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.math.Matrix4.inv():com.badlogic.gdx.math.Matrix4");
    }

    public float det() {
        float[] fArr = this.val;
        return (((((((((((((((((((((((((fArr[3] * fArr[6]) * fArr[9]) * fArr[12]) - (((fArr[2] * fArr[7]) * fArr[9]) * fArr[12])) - (((fArr[3] * fArr[5]) * fArr[10]) * fArr[12])) + (((fArr[1] * fArr[7]) * fArr[10]) * fArr[12])) + (((fArr[2] * fArr[5]) * fArr[11]) * fArr[12])) - (((fArr[1] * fArr[6]) * fArr[11]) * fArr[12])) - (((fArr[3] * fArr[6]) * fArr[8]) * fArr[13])) + (((fArr[2] * fArr[7]) * fArr[8]) * fArr[13])) + (((fArr[3] * fArr[4]) * fArr[10]) * fArr[13])) - (((fArr[0] * fArr[7]) * fArr[10]) * fArr[13])) - (((fArr[2] * fArr[4]) * fArr[11]) * fArr[13])) + (((fArr[0] * fArr[6]) * fArr[11]) * fArr[13])) + (((fArr[3] * fArr[5]) * fArr[8]) * fArr[14])) - (((fArr[1] * fArr[7]) * fArr[8]) * fArr[14])) - (((fArr[3] * fArr[4]) * fArr[9]) * fArr[14])) + (((fArr[0] * fArr[7]) * fArr[9]) * fArr[14])) + (((fArr[1] * fArr[4]) * fArr[11]) * fArr[14])) - (((fArr[0] * fArr[5]) * fArr[11]) * fArr[14])) - (((fArr[2] * fArr[5]) * fArr[8]) * fArr[15])) + (((fArr[1] * fArr[6]) * fArr[8]) * fArr[15])) + (((fArr[2] * fArr[4]) * fArr[9]) * fArr[15])) - (((fArr[0] * fArr[6]) * fArr[9]) * fArr[15])) - (((fArr[1] * fArr[4]) * fArr[10]) * fArr[15])) + (fArr[0] * fArr[5] * fArr[10] * fArr[15]);
    }

    public float det3x3() {
        float[] fArr = this.val;
        return ((((((fArr[0] * fArr[5]) * fArr[10]) + ((fArr[4] * fArr[9]) * fArr[2])) + ((fArr[8] * fArr[1]) * fArr[6])) - ((fArr[0] * fArr[9]) * fArr[6])) - ((fArr[4] * fArr[1]) * fArr[10])) - ((fArr[8] * fArr[5]) * fArr[2]);
    }

    public Matrix4 setToProjection(float near, float far, float fovy, float aspectRatio) {
        idt();
        double d = fovy;
        Double.isNaN(d);
        float l_fd = (float) (1.0d / Math.tan((d * 0.017453292519943295d) / 2.0d));
        float l_a1 = (far + near) / (near - far);
        float l_a2 = ((2.0f * far) * near) / (near - far);
        float[] fArr = this.val;
        fArr[0] = l_fd / aspectRatio;
        fArr[1] = 0.0f;
        fArr[2] = 0.0f;
        fArr[3] = 0.0f;
        fArr[4] = 0.0f;
        fArr[5] = l_fd;
        fArr[6] = 0.0f;
        fArr[7] = 0.0f;
        fArr[8] = 0.0f;
        fArr[9] = 0.0f;
        fArr[10] = l_a1;
        fArr[11] = -1.0f;
        fArr[12] = 0.0f;
        fArr[13] = 0.0f;
        fArr[14] = l_a2;
        fArr[15] = 0.0f;
        return this;
    }

    public Matrix4 setToProjection(float left, float right2, float bottom, float top, float near, float far) {
        float x = (near * 2.0f) / (right2 - left);
        float y = (near * 2.0f) / (top - bottom);
        float a = (right2 + left) / (right2 - left);
        float b = (top + bottom) / (top - bottom);
        float l_a1 = (far + near) / (near - far);
        float l_a2 = ((2.0f * far) * near) / (near - far);
        float[] fArr = this.val;
        fArr[0] = x;
        fArr[1] = 0.0f;
        fArr[2] = 0.0f;
        fArr[3] = 0.0f;
        fArr[4] = 0.0f;
        fArr[5] = y;
        fArr[6] = 0.0f;
        fArr[7] = 0.0f;
        fArr[8] = a;
        fArr[9] = b;
        fArr[10] = l_a1;
        fArr[11] = -1.0f;
        fArr[12] = 0.0f;
        fArr[13] = 0.0f;
        fArr[14] = l_a2;
        fArr[15] = 0.0f;
        return this;
    }

    public Matrix4 setToOrtho2D(float x, float y, float width, float height) {
        setToOrtho(x, x + width, y, y + height, 0.0f, 1.0f);
        return this;
    }

    public Matrix4 setToOrtho2D(float x, float y, float width, float height, float near, float far) {
        setToOrtho(x, x + width, y, y + height, near, far);
        return this;
    }

    public Matrix4 setToOrtho(float left, float right2, float bottom, float top, float near, float far) {
        float x_orth = 2.0f / (right2 - left);
        float y_orth = 2.0f / (top - bottom);
        float z_orth = (-2.0f) / (far - near);
        float tx = (-(right2 + left)) / (right2 - left);
        float ty = (-(top + bottom)) / (top - bottom);
        float tz = (-(far + near)) / (far - near);
        float[] fArr = this.val;
        fArr[0] = x_orth;
        fArr[1] = 0.0f;
        fArr[2] = 0.0f;
        fArr[3] = 0.0f;
        fArr[4] = 0.0f;
        fArr[5] = y_orth;
        fArr[6] = 0.0f;
        fArr[7] = 0.0f;
        fArr[8] = 0.0f;
        fArr[9] = 0.0f;
        fArr[10] = z_orth;
        fArr[11] = 0.0f;
        fArr[12] = tx;
        fArr[13] = ty;
        fArr[14] = tz;
        fArr[15] = 1.0f;
        return this;
    }

    public Matrix4 setTranslation(Vector3 vector) {
        this.val[12] = vector.x;
        this.val[13] = vector.y;
        this.val[14] = vector.z;
        return this;
    }

    public Matrix4 setTranslation(float x, float y, float z) {
        float[] fArr = this.val;
        fArr[12] = x;
        fArr[13] = y;
        fArr[14] = z;
        return this;
    }

    public Matrix4 setToTranslation(Vector3 vector) {
        idt();
        this.val[12] = vector.x;
        this.val[13] = vector.y;
        this.val[14] = vector.z;
        return this;
    }

    public Matrix4 setToTranslation(float x, float y, float z) {
        idt();
        float[] fArr = this.val;
        fArr[12] = x;
        fArr[13] = y;
        fArr[14] = z;
        return this;
    }

    public Matrix4 setToTranslationAndScaling(Vector3 translation, Vector3 scaling) {
        idt();
        this.val[12] = translation.x;
        this.val[13] = translation.y;
        this.val[14] = translation.z;
        this.val[0] = scaling.x;
        this.val[5] = scaling.y;
        this.val[10] = scaling.z;
        return this;
    }

    public Matrix4 setToTranslationAndScaling(float translationX, float translationY, float translationZ, float scalingX, float scalingY, float scalingZ) {
        idt();
        float[] fArr = this.val;
        fArr[12] = translationX;
        fArr[13] = translationY;
        fArr[14] = translationZ;
        fArr[0] = scalingX;
        fArr[5] = scalingY;
        fArr[10] = scalingZ;
        return this;
    }

    public Matrix4 setToRotation(Vector3 axis, float degrees) {
        if (degrees == 0.0f) {
            idt();
            return this;
        }
        return set(quat.set(axis, degrees));
    }

    public Matrix4 setToRotationRad(Vector3 axis, float radians) {
        if (radians == 0.0f) {
            idt();
            return this;
        }
        return set(quat.setFromAxisRad(axis, radians));
    }

    public Matrix4 setToRotation(float axisX, float axisY, float axisZ, float degrees) {
        if (degrees == 0.0f) {
            idt();
            return this;
        }
        return set(quat.setFromAxis(axisX, axisY, axisZ, degrees));
    }

    public Matrix4 setToRotationRad(float axisX, float axisY, float axisZ, float radians) {
        if (radians == 0.0f) {
            idt();
            return this;
        }
        return set(quat.setFromAxisRad(axisX, axisY, axisZ, radians));
    }

    public Matrix4 setToRotation(Vector3 v1, Vector3 v2) {
        return set(quat.setFromCross(v1, v2));
    }

    public Matrix4 setToRotation(float x1, float y1, float z1, float x2, float y2, float z2) {
        return set(quat.setFromCross(x1, y1, z1, x2, y2, z2));
    }

    public Matrix4 setFromEulerAngles(float yaw, float pitch, float roll) {
        quat.setEulerAngles(yaw, pitch, roll);
        return set(quat);
    }

    public Matrix4 setFromEulerAnglesRad(float yaw, float pitch, float roll) {
        quat.setEulerAnglesRad(yaw, pitch, roll);
        return set(quat);
    }

    public Matrix4 setToScaling(Vector3 vector) {
        idt();
        this.val[0] = vector.x;
        this.val[5] = vector.y;
        this.val[10] = vector.z;
        return this;
    }

    public Matrix4 setToScaling(float x, float y, float z) {
        idt();
        float[] fArr = this.val;
        fArr[0] = x;
        fArr[5] = y;
        fArr[10] = z;
        return this;
    }

    public Matrix4 setToLookAt(Vector3 direction, Vector3 up) {
        l_vez.set(direction).nor();
        l_vex.set(direction).crs(up).nor();
        l_vey.set(l_vex).crs(l_vez).nor();
        idt();
        this.val[0] = l_vex.x;
        this.val[4] = l_vex.y;
        this.val[8] = l_vex.z;
        this.val[1] = l_vey.x;
        this.val[5] = l_vey.y;
        this.val[9] = l_vey.z;
        this.val[2] = -l_vez.x;
        this.val[6] = -l_vez.y;
        this.val[10] = -l_vez.z;
        return this;
    }

    public Matrix4 setToLookAt(Vector3 position, Vector3 target, Vector3 up) {
        tmpVec.set(target).sub(position);
        setToLookAt(tmpVec, up);
        mul(tmpMat.setToTranslation(-position.x, -position.y, -position.z));
        return this;
    }

    public Matrix4 setToWorld(Vector3 position, Vector3 forward, Vector3 up) {
        tmpForward.set(forward).nor();
        right.set(tmpForward).crs(up).nor();
        tmpUp.set(right).crs(tmpForward).nor();
        set(right, tmpUp, tmpForward.scl(-1.0f), position);
        return this;
    }

    public Matrix4 lerp(Matrix4 matrix, float alpha) {
        for (int i = 0; i < 16; i++) {
            float[] fArr = this.val;
            fArr[i] = (fArr[i] * (1.0f - alpha)) + (matrix.val[i] * alpha);
        }
        return this;
    }

    public Matrix4 avg(Matrix4 other, float w) {
        getScale(tmpVec);
        other.getScale(tmpForward);
        getRotation(quat);
        other.getRotation(quat2);
        getTranslation(tmpUp);
        other.getTranslation(right);
        setToScaling(tmpVec.scl(w).add(tmpForward.scl(1.0f - w)));
        rotate(quat.slerp(quat2, 1.0f - w));
        setTranslation(tmpUp.scl(w).add(right.scl(1.0f - w)));
        return this;
    }

    public Matrix4 avg(Matrix4[] t) {
        float w = 1.0f / t.length;
        tmpVec.set(t[0].getScale(tmpUp).scl(w));
        quat.set(t[0].getRotation(quat2).exp(w));
        tmpForward.set(t[0].getTranslation(tmpUp).scl(w));
        for (int i = 1; i < t.length; i++) {
            tmpVec.add(t[i].getScale(tmpUp).scl(w));
            quat.mul(t[i].getRotation(quat2).exp(w));
            tmpForward.add(t[i].getTranslation(tmpUp).scl(w));
        }
        quat.nor();
        setToScaling(tmpVec);
        rotate(quat);
        setTranslation(tmpForward);
        return this;
    }

    public Matrix4 avg(Matrix4[] t, float[] w) {
        tmpVec.set(t[0].getScale(tmpUp).scl(w[0]));
        quat.set(t[0].getRotation(quat2).exp(w[0]));
        tmpForward.set(t[0].getTranslation(tmpUp).scl(w[0]));
        for (int i = 1; i < t.length; i++) {
            tmpVec.add(t[i].getScale(tmpUp).scl(w[i]));
            quat.mul(t[i].getRotation(quat2).exp(w[i]));
            tmpForward.add(t[i].getTranslation(tmpUp).scl(w[i]));
        }
        quat.nor();
        setToScaling(tmpVec);
        rotate(quat);
        setTranslation(tmpForward);
        return this;
    }

    public Matrix4 set(Matrix3 mat) {
        this.val[0] = mat.val[0];
        this.val[1] = mat.val[1];
        this.val[2] = mat.val[2];
        float[] fArr = this.val;
        fArr[3] = 0.0f;
        fArr[4] = mat.val[3];
        this.val[5] = mat.val[4];
        this.val[6] = mat.val[5];
        float[] fArr2 = this.val;
        fArr2[7] = 0.0f;
        fArr2[8] = 0.0f;
        fArr2[9] = 0.0f;
        fArr2[10] = 1.0f;
        fArr2[11] = 0.0f;
        fArr2[12] = mat.val[6];
        this.val[13] = mat.val[7];
        float[] fArr3 = this.val;
        fArr3[14] = 0.0f;
        fArr3[15] = mat.val[8];
        return this;
    }

    public Matrix4 set(Affine2 affine) {
        this.val[0] = affine.m00;
        this.val[1] = affine.m10;
        float[] fArr = this.val;
        fArr[2] = 0.0f;
        fArr[3] = 0.0f;
        fArr[4] = affine.m01;
        this.val[5] = affine.m11;
        float[] fArr2 = this.val;
        fArr2[6] = 0.0f;
        fArr2[7] = 0.0f;
        fArr2[8] = 0.0f;
        fArr2[9] = 0.0f;
        fArr2[10] = 1.0f;
        fArr2[11] = 0.0f;
        fArr2[12] = affine.m02;
        this.val[13] = affine.m12;
        float[] fArr3 = this.val;
        fArr3[14] = 0.0f;
        fArr3[15] = 1.0f;
        return this;
    }

    public Matrix4 setAsAffine(Affine2 affine) {
        this.val[0] = affine.m00;
        this.val[1] = affine.m10;
        this.val[4] = affine.m01;
        this.val[5] = affine.m11;
        this.val[12] = affine.m02;
        this.val[13] = affine.m12;
        return this;
    }

    public Matrix4 setAsAffine(Matrix4 mat) {
        float[] fArr = this.val;
        float[] fArr2 = mat.val;
        fArr[0] = fArr2[0];
        fArr[1] = fArr2[1];
        fArr[4] = fArr2[4];
        fArr[5] = fArr2[5];
        fArr[12] = fArr2[12];
        fArr[13] = fArr2[13];
        return this;
    }

    public Matrix4 scl(Vector3 scale) {
        float[] fArr = this.val;
        fArr[0] = fArr[0] * scale.x;
        float[] fArr2 = this.val;
        fArr2[5] = fArr2[5] * scale.y;
        float[] fArr3 = this.val;
        fArr3[10] = fArr3[10] * scale.z;
        return this;
    }

    public Matrix4 scl(float x, float y, float z) {
        float[] fArr = this.val;
        fArr[0] = fArr[0] * x;
        fArr[5] = fArr[5] * y;
        fArr[10] = fArr[10] * z;
        return this;
    }

    public Matrix4 scl(float scale) {
        float[] fArr = this.val;
        fArr[0] = fArr[0] * scale;
        fArr[5] = fArr[5] * scale;
        fArr[10] = fArr[10] * scale;
        return this;
    }

    public Vector3 getTranslation(Vector3 position) {
        float[] fArr = this.val;
        position.x = fArr[12];
        position.y = fArr[13];
        position.z = fArr[14];
        return position;
    }

    public Quaternion getRotation(Quaternion rotation, boolean normalizeAxes) {
        return rotation.setFromMatrix(normalizeAxes, this);
    }

    public Quaternion getRotation(Quaternion rotation) {
        return rotation.setFromMatrix(this);
    }

    public float getScaleXSquared() {
        float[] fArr = this.val;
        return (fArr[0] * fArr[0]) + (fArr[4] * fArr[4]) + (fArr[8] * fArr[8]);
    }

    public float getScaleYSquared() {
        float[] fArr = this.val;
        return (fArr[1] * fArr[1]) + (fArr[5] * fArr[5]) + (fArr[9] * fArr[9]);
    }

    public float getScaleZSquared() {
        float[] fArr = this.val;
        return (fArr[2] * fArr[2]) + (fArr[6] * fArr[6]) + (fArr[10] * fArr[10]);
    }

    public float getScaleX() {
        return (MathUtils.isZero(this.val[4]) && MathUtils.isZero(this.val[8])) ? Math.abs(this.val[0]) : (float) Math.sqrt(getScaleXSquared());
    }

    public float getScaleY() {
        return (MathUtils.isZero(this.val[1]) && MathUtils.isZero(this.val[9])) ? Math.abs(this.val[5]) : (float) Math.sqrt(getScaleYSquared());
    }

    public float getScaleZ() {
        return (MathUtils.isZero(this.val[2]) && MathUtils.isZero(this.val[6])) ? Math.abs(this.val[10]) : (float) Math.sqrt(getScaleZSquared());
    }

    public Vector3 getScale(Vector3 scale) {
        return scale.set(getScaleX(), getScaleY(), getScaleZ());
    }

    public Matrix4 toNormalMatrix() {
        float[] fArr = this.val;
        fArr[12] = 0.0f;
        fArr[13] = 0.0f;
        fArr[14] = 0.0f;
        return inv().tra();
    }

    public String toString() {
        return "[" + this.val[0] + "|" + this.val[4] + "|" + this.val[8] + "|" + this.val[12] + "]\n[" + this.val[1] + "|" + this.val[5] + "|" + this.val[9] + "|" + this.val[13] + "]\n[" + this.val[2] + "|" + this.val[6] + "|" + this.val[10] + "|" + this.val[14] + "]\n[" + this.val[3] + "|" + this.val[7] + "|" + this.val[11] + "|" + this.val[15] + "]\n";
    }

    public static void mul(float[] mata, float[] matb) {
        float m00 = (mata[0] * matb[0]) + (mata[4] * matb[1]) + (mata[8] * matb[2]) + (mata[12] * matb[3]);
        float m01 = (mata[0] * matb[4]) + (mata[4] * matb[5]) + (mata[8] * matb[6]) + (mata[12] * matb[7]);
        float m02 = (mata[0] * matb[8]) + (mata[4] * matb[9]) + (mata[8] * matb[10]) + (mata[12] * matb[11]);
        float m03 = (mata[0] * matb[12]) + (mata[4] * matb[13]) + (mata[8] * matb[14]) + (mata[12] * matb[15]);
        float m10 = (mata[1] * matb[0]) + (mata[5] * matb[1]) + (mata[9] * matb[2]) + (mata[13] * matb[3]);
        float m11 = (mata[1] * matb[4]) + (mata[5] * matb[5]) + (mata[9] * matb[6]) + (mata[13] * matb[7]);
        float m12 = (mata[1] * matb[8]) + (mata[5] * matb[9]) + (mata[9] * matb[10]) + (mata[13] * matb[11]);
        float m13 = (mata[1] * matb[12]) + (mata[5] * matb[13]) + (mata[9] * matb[14]) + (mata[13] * matb[15]);
        float m20 = (mata[2] * matb[0]) + (mata[6] * matb[1]) + (mata[10] * matb[2]) + (mata[14] * matb[3]);
        float m21 = (mata[2] * matb[4]) + (mata[6] * matb[5]) + (mata[10] * matb[6]) + (mata[14] * matb[7]);
        float m22 = (mata[2] * matb[8]) + (mata[6] * matb[9]) + (mata[10] * matb[10]) + (mata[14] * matb[11]);
        float m23 = (mata[2] * matb[12]) + (mata[6] * matb[13]) + (mata[10] * matb[14]) + (mata[14] * matb[15]);
        float m30 = (mata[3] * matb[0]) + (mata[7] * matb[1]) + (mata[11] * matb[2]) + (mata[15] * matb[3]);
        float m31 = (mata[3] * matb[4]) + (mata[7] * matb[5]) + (mata[11] * matb[6]) + (mata[15] * matb[7]);
        float m32 = (mata[3] * matb[8]) + (mata[7] * matb[9]) + (mata[11] * matb[10]) + (mata[15] * matb[11]);
        float m33 = (mata[3] * matb[12]) + (mata[7] * matb[13]) + (mata[11] * matb[14]) + (mata[15] * matb[15]);
        mata[0] = m00;
        mata[1] = m10;
        mata[2] = m20;
        mata[3] = m30;
        mata[4] = m01;
        mata[5] = m11;
        mata[6] = m21;
        mata[7] = m31;
        mata[8] = m02;
        mata[9] = m12;
        mata[10] = m22;
        mata[11] = m32;
        mata[12] = m03;
        mata[13] = m13;
        mata[14] = m23;
        mata[15] = m33;
    }

    public static void mulVec(float[] mat, float[] vec) {
        float x = (vec[0] * mat[0]) + (vec[1] * mat[4]) + (vec[2] * mat[8]) + mat[12];
        float y = (vec[0] * mat[1]) + (vec[1] * mat[5]) + (vec[2] * mat[9]) + mat[13];
        float z = (vec[0] * mat[2]) + (vec[1] * mat[6]) + (vec[2] * mat[10]) + mat[14];
        vec[0] = x;
        vec[1] = y;
        vec[2] = z;
    }

    public static void prj(float[] mat, float[] vec) {
        float inv_w = 1.0f / ((((vec[0] * mat[3]) + (vec[1] * mat[7])) + (vec[2] * mat[11])) + mat[15]);
        float x = ((vec[0] * mat[0]) + (vec[1] * mat[4]) + (vec[2] * mat[8]) + mat[12]) * inv_w;
        float y = ((vec[0] * mat[1]) + (vec[1] * mat[5]) + (vec[2] * mat[9]) + mat[13]) * inv_w;
        float z = ((vec[0] * mat[2]) + (vec[1] * mat[6]) + (vec[2] * mat[10]) + mat[14]) * inv_w;
        vec[0] = x;
        vec[1] = y;
        vec[2] = z;
    }

    public static void rot(float[] mat, float[] vec) {
        float x = (vec[0] * mat[0]) + (vec[1] * mat[4]) + (vec[2] * mat[8]);
        float y = (vec[0] * mat[1]) + (vec[1] * mat[5]) + (vec[2] * mat[9]);
        float z = (vec[0] * mat[2]) + (vec[1] * mat[6]) + (vec[2] * mat[10]);
        vec[0] = x;
        vec[1] = y;
        vec[2] = z;
    }

    public static boolean inv(float[] values) {
        float l_det = det(values);
        if (l_det == 0.0f) {
            return false;
        }
        float m00 = ((((((values[9] * values[14]) * values[7]) - ((values[13] * values[10]) * values[7])) + ((values[13] * values[6]) * values[11])) - ((values[5] * values[14]) * values[11])) - ((values[9] * values[6]) * values[15])) + (values[5] * values[10] * values[15]);
        float m01 = ((((((values[12] * values[10]) * values[7]) - ((values[8] * values[14]) * values[7])) - ((values[12] * values[6]) * values[11])) + ((values[4] * values[14]) * values[11])) + ((values[8] * values[6]) * values[15])) - ((values[4] * values[10]) * values[15]);
        float m02 = ((((((values[8] * values[13]) * values[7]) - ((values[12] * values[9]) * values[7])) + ((values[12] * values[5]) * values[11])) - ((values[4] * values[13]) * values[11])) - ((values[8] * values[5]) * values[15])) + (values[4] * values[9] * values[15]);
        float m03 = ((((((values[12] * values[9]) * values[6]) - ((values[8] * values[13]) * values[6])) - ((values[12] * values[5]) * values[10])) + ((values[4] * values[13]) * values[10])) + ((values[8] * values[5]) * values[14])) - ((values[4] * values[9]) * values[14]);
        float m10 = ((((((values[13] * values[10]) * values[3]) - ((values[9] * values[14]) * values[3])) - ((values[13] * values[2]) * values[11])) + ((values[1] * values[14]) * values[11])) + ((values[9] * values[2]) * values[15])) - ((values[1] * values[10]) * values[15]);
        float m11 = ((((((values[8] * values[14]) * values[3]) - ((values[12] * values[10]) * values[3])) + ((values[12] * values[2]) * values[11])) - ((values[0] * values[14]) * values[11])) - ((values[8] * values[2]) * values[15])) + (values[0] * values[10] * values[15]);
        float m12 = ((((((values[12] * values[9]) * values[3]) - ((values[8] * values[13]) * values[3])) - ((values[12] * values[1]) * values[11])) + ((values[0] * values[13]) * values[11])) + ((values[8] * values[1]) * values[15])) - ((values[0] * values[9]) * values[15]);
        float m13 = ((((((values[8] * values[13]) * values[2]) - ((values[12] * values[9]) * values[2])) + ((values[12] * values[1]) * values[10])) - ((values[0] * values[13]) * values[10])) - ((values[8] * values[1]) * values[14])) + (values[0] * values[9] * values[14]);
        float m20 = ((((((values[5] * values[14]) * values[3]) - ((values[13] * values[6]) * values[3])) + ((values[13] * values[2]) * values[7])) - ((values[1] * values[14]) * values[7])) - ((values[5] * values[2]) * values[15])) + (values[1] * values[6] * values[15]);
        float m21 = ((((((values[12] * values[6]) * values[3]) - ((values[4] * values[14]) * values[3])) - ((values[12] * values[2]) * values[7])) + ((values[0] * values[14]) * values[7])) + ((values[4] * values[2]) * values[15])) - ((values[0] * values[6]) * values[15]);
        float m22 = ((((((values[4] * values[13]) * values[3]) - ((values[12] * values[5]) * values[3])) + ((values[12] * values[1]) * values[7])) - ((values[0] * values[13]) * values[7])) - ((values[4] * values[1]) * values[15])) + (values[0] * values[5] * values[15]);
        float m23 = ((((((values[12] * values[5]) * values[2]) - ((values[4] * values[13]) * values[2])) - ((values[12] * values[1]) * values[6])) + ((values[0] * values[13]) * values[6])) + ((values[4] * values[1]) * values[14])) - ((values[0] * values[5]) * values[14]);
        float m30 = ((((((values[9] * values[6]) * values[3]) - ((values[5] * values[10]) * values[3])) - ((values[9] * values[2]) * values[7])) + ((values[1] * values[10]) * values[7])) + ((values[5] * values[2]) * values[11])) - ((values[1] * values[6]) * values[11]);
        float m31 = ((((((values[4] * values[10]) * values[3]) - ((values[8] * values[6]) * values[3])) + ((values[8] * values[2]) * values[7])) - ((values[0] * values[10]) * values[7])) - ((values[4] * values[2]) * values[11])) + (values[0] * values[6] * values[11]);
        float m32 = ((((((values[8] * values[5]) * values[3]) - ((values[4] * values[9]) * values[3])) - ((values[8] * values[1]) * values[7])) + ((values[0] * values[9]) * values[7])) + ((values[4] * values[1]) * values[11])) - ((values[0] * values[5]) * values[11]);
        float m33 = ((((((values[4] * values[9]) * values[2]) - ((values[8] * values[5]) * values[2])) + ((values[8] * values[1]) * values[6])) - ((values[0] * values[9]) * values[6])) - ((values[4] * values[1]) * values[10])) + (values[0] * values[5] * values[10]);
        float inv_det = 1.0f / l_det;
        values[0] = m00 * inv_det;
        values[1] = m10 * inv_det;
        values[2] = m20 * inv_det;
        values[3] = m30 * inv_det;
        values[4] = m01 * inv_det;
        values[5] = m11 * inv_det;
        values[6] = m21 * inv_det;
        values[7] = m31 * inv_det;
        values[8] = m02 * inv_det;
        values[9] = m12 * inv_det;
        values[10] = m22 * inv_det;
        values[11] = m32 * inv_det;
        values[12] = m03 * inv_det;
        values[13] = m13 * inv_det;
        values[14] = m23 * inv_det;
        values[15] = m33 * inv_det;
        return true;
    }

    public static float det(float[] values) {
        return (((((((((((((((((((((((((values[3] * values[6]) * values[9]) * values[12]) - (((values[2] * values[7]) * values[9]) * values[12])) - (((values[3] * values[5]) * values[10]) * values[12])) + (((values[1] * values[7]) * values[10]) * values[12])) + (((values[2] * values[5]) * values[11]) * values[12])) - (((values[1] * values[6]) * values[11]) * values[12])) - (((values[3] * values[6]) * values[8]) * values[13])) + (((values[2] * values[7]) * values[8]) * values[13])) + (((values[3] * values[4]) * values[10]) * values[13])) - (((values[0] * values[7]) * values[10]) * values[13])) - (((values[2] * values[4]) * values[11]) * values[13])) + (((values[0] * values[6]) * values[11]) * values[13])) + (((values[3] * values[5]) * values[8]) * values[14])) - (((values[1] * values[7]) * values[8]) * values[14])) - (((values[3] * values[4]) * values[9]) * values[14])) + (((values[0] * values[7]) * values[9]) * values[14])) + (((values[1] * values[4]) * values[11]) * values[14])) - (((values[0] * values[5]) * values[11]) * values[14])) - (((values[2] * values[5]) * values[8]) * values[15])) + (((values[1] * values[6]) * values[8]) * values[15])) + (((values[2] * values[4]) * values[9]) * values[15])) - (((values[0] * values[6]) * values[9]) * values[15])) - (((values[1] * values[4]) * values[10]) * values[15])) + (values[0] * values[5] * values[10] * values[15]);
    }

    public Matrix4 translate(Vector3 translation) {
        return translate(translation.x, translation.y, translation.z);
    }

    public Matrix4 translate(float x, float y, float z) {
        float[] fArr = this.val;
        fArr[12] = fArr[12] + (fArr[0] * x) + (fArr[4] * y) + (fArr[8] * z);
        fArr[13] = fArr[13] + (fArr[1] * x) + (fArr[5] * y) + (fArr[9] * z);
        fArr[14] = fArr[14] + (fArr[2] * x) + (fArr[6] * y) + (fArr[10] * z);
        fArr[15] = fArr[15] + (fArr[3] * x) + (fArr[7] * y) + (fArr[11] * z);
        return this;
    }

    public Matrix4 rotate(Vector3 axis, float degrees) {
        if (degrees == 0.0f) {
            return this;
        }
        quat.set(axis, degrees);
        return rotate(quat);
    }

    public Matrix4 rotateRad(Vector3 axis, float radians) {
        if (radians == 0.0f) {
            return this;
        }
        quat.setFromAxisRad(axis, radians);
        return rotate(quat);
    }

    public Matrix4 rotate(float axisX, float axisY, float axisZ, float degrees) {
        if (degrees == 0.0f) {
            return this;
        }
        quat.setFromAxis(axisX, axisY, axisZ, degrees);
        return rotate(quat);
    }

    public Matrix4 rotateRad(float axisX, float axisY, float axisZ, float radians) {
        if (radians == 0.0f) {
            return this;
        }
        quat.setFromAxisRad(axisX, axisY, axisZ, radians);
        return rotate(quat);
    }

    public Matrix4 rotate(Quaternion rotation) {
        float x = rotation.x;
        float y = rotation.y;
        float z = rotation.z;
        float w = rotation.w;
        float xx = x * x;
        float xy = x * y;
        float xz = x * z;
        float xw = x * w;
        float yy = y * y;
        float yz = y * z;
        float yw = y * w;
        float zz = z * z;
        float zw = z * w;
        float r00 = 1.0f - ((yy + zz) * 2.0f);
        float r01 = (xy - zw) * 2.0f;
        float r02 = (xz + yw) * 2.0f;
        float r10 = (xy + zw) * 2.0f;
        float r11 = 1.0f - ((xx + zz) * 2.0f);
        float r12 = (yz - xw) * 2.0f;
        float r20 = (xz - yw) * 2.0f;
        float r21 = (yz + xw) * 2.0f;
        float r22 = 1.0f - ((xx + yy) * 2.0f);
        float[] fArr = this.val;
        float m00 = (fArr[0] * r00) + (fArr[4] * r10) + (fArr[8] * r20);
        float m01 = (fArr[0] * r01) + (fArr[4] * r11) + (fArr[8] * r21);
        float m02 = (fArr[0] * r02) + (fArr[4] * r12) + (fArr[8] * r22);
        float m10 = (fArr[1] * r00) + (fArr[5] * r10) + (fArr[9] * r20);
        float m11 = (fArr[1] * r01) + (fArr[5] * r11) + (fArr[9] * r21);
        float m12 = (fArr[1] * r02) + (fArr[5] * r12) + (fArr[9] * r22);
        float m20 = (fArr[2] * r00) + (fArr[6] * r10) + (fArr[10] * r20);
        float m21 = (fArr[2] * r01) + (fArr[6] * r11) + (fArr[10] * r21);
        float m22 = (fArr[2] * r02) + (fArr[6] * r12) + (fArr[10] * r22);
        float m30 = (fArr[3] * r00) + (fArr[7] * r10) + (fArr[11] * r20);
        float m31 = (fArr[3] * r01) + (fArr[7] * r11) + (fArr[11] * r21);
        float m32 = (fArr[3] * r02) + (fArr[7] * r12) + (fArr[11] * r22);
        fArr[0] = m00;
        fArr[1] = m10;
        fArr[2] = m20;
        fArr[3] = m30;
        fArr[4] = m01;
        fArr[5] = m11;
        fArr[6] = m21;
        fArr[7] = m31;
        fArr[8] = m02;
        fArr[9] = m12;
        fArr[10] = m22;
        fArr[11] = m32;
        return this;
    }

    public Matrix4 rotate(Vector3 v1, Vector3 v2) {
        return rotate(quat.setFromCross(v1, v2));
    }

    public Matrix4 rotateTowardDirection(Vector3 direction, Vector3 up) {
        l_vez.set(direction).nor();
        l_vex.set(direction).crs(up).nor();
        l_vey.set(l_vex).crs(l_vez).nor();
        float m00 = (this.val[0] * l_vex.x) + (this.val[4] * l_vex.y) + (this.val[8] * l_vex.z);
        float m01 = (this.val[0] * l_vey.x) + (this.val[4] * l_vey.y) + (this.val[8] * l_vey.z);
        float m02 = (this.val[0] * (-l_vez.x)) + (this.val[4] * (-l_vez.y)) + (this.val[8] * (-l_vez.z));
        float m10 = (this.val[1] * l_vex.x) + (this.val[5] * l_vex.y) + (this.val[9] * l_vex.z);
        float m11 = (this.val[1] * l_vey.x) + (this.val[5] * l_vey.y) + (this.val[9] * l_vey.z);
        float m12 = (this.val[1] * (-l_vez.x)) + (this.val[5] * (-l_vez.y)) + (this.val[9] * (-l_vez.z));
        float m20 = (this.val[2] * l_vex.x) + (this.val[6] * l_vex.y) + (this.val[10] * l_vex.z);
        float m21 = (this.val[2] * l_vey.x) + (this.val[6] * l_vey.y) + (this.val[10] * l_vey.z);
        float m22 = (this.val[2] * (-l_vez.x)) + (this.val[6] * (-l_vez.y)) + (this.val[10] * (-l_vez.z));
        float m30 = (this.val[3] * l_vex.x) + (this.val[7] * l_vex.y) + (this.val[11] * l_vex.z);
        float m31 = (this.val[3] * l_vey.x) + (this.val[7] * l_vey.y) + (this.val[11] * l_vey.z);
        float m32 = (this.val[3] * (-l_vez.x)) + (this.val[7] * (-l_vez.y)) + (this.val[11] * (-l_vez.z));
        float[] fArr = this.val;
        fArr[0] = m00;
        fArr[1] = m10;
        fArr[2] = m20;
        fArr[3] = m30;
        fArr[4] = m01;
        fArr[5] = m11;
        fArr[6] = m21;
        fArr[7] = m31;
        fArr[8] = m02;
        fArr[9] = m12;
        fArr[10] = m22;
        fArr[11] = m32;
        return this;
    }

    public Matrix4 rotateTowardTarget(Vector3 target, Vector3 up) {
        tmpVec.set(target.x - this.val[12], target.y - this.val[13], target.z - this.val[14]);
        return rotateTowardDirection(tmpVec, up);
    }

    public Matrix4 scale(float scaleX, float scaleY, float scaleZ) {
        float[] fArr = this.val;
        fArr[0] = fArr[0] * scaleX;
        fArr[4] = fArr[4] * scaleY;
        fArr[8] = fArr[8] * scaleZ;
        fArr[1] = fArr[1] * scaleX;
        fArr[5] = fArr[5] * scaleY;
        fArr[9] = fArr[9] * scaleZ;
        fArr[2] = fArr[2] * scaleX;
        fArr[6] = fArr[6] * scaleY;
        fArr[10] = fArr[10] * scaleZ;
        fArr[3] = fArr[3] * scaleX;
        fArr[7] = fArr[7] * scaleY;
        fArr[11] = fArr[11] * scaleZ;
        return this;
    }

    public void extract4x3Matrix(float[] dst) {
        float[] fArr = this.val;
        dst[0] = fArr[0];
        dst[1] = fArr[1];
        dst[2] = fArr[2];
        dst[3] = fArr[4];
        dst[4] = fArr[5];
        dst[5] = fArr[6];
        dst[6] = fArr[8];
        dst[7] = fArr[9];
        dst[8] = fArr[10];
        dst[9] = fArr[12];
        dst[10] = fArr[13];
        dst[11] = fArr[14];
    }

    public boolean hasRotationOrScaling() {
        return (MathUtils.isEqual(this.val[0], 1.0f) && MathUtils.isEqual(this.val[5], 1.0f) && MathUtils.isEqual(this.val[10], 1.0f) && MathUtils.isZero(this.val[4]) && MathUtils.isZero(this.val[8]) && MathUtils.isZero(this.val[1]) && MathUtils.isZero(this.val[9]) && MathUtils.isZero(this.val[2]) && MathUtils.isZero(this.val[6])) ? false : true;
    }
}