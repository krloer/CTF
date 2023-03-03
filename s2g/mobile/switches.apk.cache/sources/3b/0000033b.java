package com.badlogic.gdx.physics.box2d;

import com.badlogic.gdx.math.Vector2;

/* loaded from: classes.dex */
public class Manifold {
    long addr;
    final ManifoldPoint[] points = {new ManifoldPoint(), new ManifoldPoint()};
    final Vector2 localNormal = new Vector2();
    final Vector2 localPoint = new Vector2();
    final int[] tmpInt = new int[2];
    final float[] tmpFloat = new float[4];

    /* loaded from: classes.dex */
    public enum ManifoldType {
        Circle,
        FaceA,
        FaceB
    }

    private native void jniGetLocalNormal(long j, float[] fArr);

    private native void jniGetLocalPoint(long j, float[] fArr);

    private native int jniGetPoint(long j, float[] fArr, int i);

    private native int jniGetPointCount(long j);

    private native int jniGetType(long j);

    /* JADX INFO: Access modifiers changed from: protected */
    public Manifold(long addr) {
        this.addr = addr;
    }

    public ManifoldType getType() {
        int type = jniGetType(this.addr);
        return type == 0 ? ManifoldType.Circle : type == 1 ? ManifoldType.FaceA : type == 2 ? ManifoldType.FaceB : ManifoldType.Circle;
    }

    public int getPointCount() {
        return jniGetPointCount(this.addr);
    }

    public Vector2 getLocalNormal() {
        jniGetLocalNormal(this.addr, this.tmpFloat);
        Vector2 vector2 = this.localNormal;
        float[] fArr = this.tmpFloat;
        vector2.set(fArr[0], fArr[1]);
        return this.localNormal;
    }

    public Vector2 getLocalPoint() {
        jniGetLocalPoint(this.addr, this.tmpFloat);
        Vector2 vector2 = this.localPoint;
        float[] fArr = this.tmpFloat;
        vector2.set(fArr[0], fArr[1]);
        return this.localPoint;
    }

    public ManifoldPoint[] getPoints() {
        int count = jniGetPointCount(this.addr);
        for (int i = 0; i < count; i++) {
            int contactID = jniGetPoint(this.addr, this.tmpFloat, i);
            ManifoldPoint point = this.points[i];
            point.contactID = contactID;
            Vector2 vector2 = point.localPoint;
            float[] fArr = this.tmpFloat;
            vector2.set(fArr[0], fArr[1]);
            float[] fArr2 = this.tmpFloat;
            point.normalImpulse = fArr2[2];
            point.tangentImpulse = fArr2[3];
        }
        return this.points;
    }

    /* loaded from: classes.dex */
    public class ManifoldPoint {
        public float normalImpulse;
        public float tangentImpulse;
        public final Vector2 localPoint = new Vector2();
        public int contactID = 0;

        public ManifoldPoint() {
        }

        public String toString() {
            return "id: " + this.contactID + ", " + this.localPoint + ", " + this.normalImpulse + ", " + this.tangentImpulse;
        }
    }
}