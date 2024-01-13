package com.badlogic.gdx.math;

import com.badlogic.gdx.math.Plane;
import com.badlogic.gdx.math.collision.BoundingBox;

/* loaded from: classes.dex */
public class Frustum {
    protected static final Vector3[] clipSpacePlanePoints = {new Vector3(-1.0f, -1.0f, -1.0f), new Vector3(1.0f, -1.0f, -1.0f), new Vector3(1.0f, 1.0f, -1.0f), new Vector3(-1.0f, 1.0f, -1.0f), new Vector3(-1.0f, -1.0f, 1.0f), new Vector3(1.0f, -1.0f, 1.0f), new Vector3(1.0f, 1.0f, 1.0f), new Vector3(-1.0f, 1.0f, 1.0f)};
    protected static final float[] clipSpacePlanePointsArray = new float[24];
    private static final Vector3 tmpV;
    public final Plane[] planes = new Plane[6];
    public final Vector3[] planePoints = {new Vector3(), new Vector3(), new Vector3(), new Vector3(), new Vector3(), new Vector3(), new Vector3(), new Vector3()};
    protected final float[] planePointsArray = new float[24];

    static {
        int i = 0;
        int j = 0;
        Vector3[] vector3Arr = clipSpacePlanePoints;
        int length = vector3Arr.length;
        while (i < length) {
            Vector3 v = vector3Arr[i];
            int j2 = j + 1;
            clipSpacePlanePointsArray[j] = v.x;
            int j3 = j2 + 1;
            clipSpacePlanePointsArray[j2] = v.y;
            clipSpacePlanePointsArray[j3] = v.z;
            i++;
            j = j3 + 1;
        }
        tmpV = new Vector3();
    }

    public Frustum() {
        for (int i = 0; i < 6; i++) {
            this.planes[i] = new Plane(new Vector3(), 0.0f);
        }
    }

    public void update(Matrix4 inverseProjectionView) {
        float[] fArr = clipSpacePlanePointsArray;
        System.arraycopy(fArr, 0, this.planePointsArray, 0, fArr.length);
        Matrix4.prj(inverseProjectionView.val, this.planePointsArray, 0, 8, 3);
        int i = 0;
        int j = 0;
        while (i < 8) {
            Vector3 v = this.planePoints[i];
            float[] fArr2 = this.planePointsArray;
            int j2 = j + 1;
            v.x = fArr2[j];
            int j3 = j2 + 1;
            v.y = fArr2[j2];
            v.z = fArr2[j3];
            i++;
            j = j3 + 1;
        }
        Plane plane = this.planes[0];
        Vector3[] vector3Arr = this.planePoints;
        plane.set(vector3Arr[1], vector3Arr[0], vector3Arr[2]);
        Plane plane2 = this.planes[1];
        Vector3[] vector3Arr2 = this.planePoints;
        plane2.set(vector3Arr2[4], vector3Arr2[5], vector3Arr2[7]);
        Plane plane3 = this.planes[2];
        Vector3[] vector3Arr3 = this.planePoints;
        plane3.set(vector3Arr3[0], vector3Arr3[4], vector3Arr3[3]);
        Plane plane4 = this.planes[3];
        Vector3[] vector3Arr4 = this.planePoints;
        plane4.set(vector3Arr4[5], vector3Arr4[1], vector3Arr4[6]);
        Plane plane5 = this.planes[4];
        Vector3[] vector3Arr5 = this.planePoints;
        plane5.set(vector3Arr5[2], vector3Arr5[3], vector3Arr5[6]);
        Plane plane6 = this.planes[5];
        Vector3[] vector3Arr6 = this.planePoints;
        plane6.set(vector3Arr6[4], vector3Arr6[0], vector3Arr6[1]);
    }

    public boolean pointInFrustum(Vector3 point) {
        int i = 0;
        while (true) {
            Plane[] planeArr = this.planes;
            if (i < planeArr.length) {
                Plane.PlaneSide result = planeArr[i].testPoint(point);
                if (result == Plane.PlaneSide.Back) {
                    return false;
                }
                i++;
            } else {
                return true;
            }
        }
    }

    public boolean pointInFrustum(float x, float y, float z) {
        int i = 0;
        while (true) {
            Plane[] planeArr = this.planes;
            if (i < planeArr.length) {
                Plane.PlaneSide result = planeArr[i].testPoint(x, y, z);
                if (result == Plane.PlaneSide.Back) {
                    return false;
                }
                i++;
            } else {
                return true;
            }
        }
    }

    public boolean sphereInFrustum(Vector3 center, float radius) {
        for (int i = 0; i < 6; i++) {
            if ((this.planes[i].normal.x * center.x) + (this.planes[i].normal.y * center.y) + (this.planes[i].normal.z * center.z) < (-radius) - this.planes[i].d) {
                return false;
            }
        }
        return true;
    }

    public boolean sphereInFrustum(float x, float y, float z, float radius) {
        for (int i = 0; i < 6; i++) {
            if ((this.planes[i].normal.x * x) + (this.planes[i].normal.y * y) + (this.planes[i].normal.z * z) < (-radius) - this.planes[i].d) {
                return false;
            }
        }
        return true;
    }

    public boolean sphereInFrustumWithoutNearFar(Vector3 center, float radius) {
        for (int i = 2; i < 6; i++) {
            if ((this.planes[i].normal.x * center.x) + (this.planes[i].normal.y * center.y) + (this.planes[i].normal.z * center.z) < (-radius) - this.planes[i].d) {
                return false;
            }
        }
        return true;
    }

    public boolean sphereInFrustumWithoutNearFar(float x, float y, float z, float radius) {
        for (int i = 2; i < 6; i++) {
            if ((this.planes[i].normal.x * x) + (this.planes[i].normal.y * y) + (this.planes[i].normal.z * z) < (-radius) - this.planes[i].d) {
                return false;
            }
        }
        return true;
    }

    public boolean boundsInFrustum(BoundingBox bounds) {
        int len2 = this.planes.length;
        for (int i = 0; i < len2; i++) {
            if (this.planes[i].testPoint(bounds.getCorner000(tmpV)) == Plane.PlaneSide.Back && this.planes[i].testPoint(bounds.getCorner001(tmpV)) == Plane.PlaneSide.Back && this.planes[i].testPoint(bounds.getCorner010(tmpV)) == Plane.PlaneSide.Back && this.planes[i].testPoint(bounds.getCorner011(tmpV)) == Plane.PlaneSide.Back && this.planes[i].testPoint(bounds.getCorner100(tmpV)) == Plane.PlaneSide.Back && this.planes[i].testPoint(bounds.getCorner101(tmpV)) == Plane.PlaneSide.Back && this.planes[i].testPoint(bounds.getCorner110(tmpV)) == Plane.PlaneSide.Back && this.planes[i].testPoint(bounds.getCorner111(tmpV)) == Plane.PlaneSide.Back) {
                return false;
            }
        }
        return true;
    }

    public boolean boundsInFrustum(Vector3 center, Vector3 dimensions) {
        return boundsInFrustum(center.x, center.y, center.z, dimensions.x / 2.0f, dimensions.y / 2.0f, dimensions.z / 2.0f);
    }

    public boolean boundsInFrustum(float x, float y, float z, float halfWidth, float halfHeight, float halfDepth) {
        int len2 = this.planes.length;
        for (int i = 0; i < len2; i++) {
            if (this.planes[i].testPoint(x + halfWidth, y + halfHeight, z + halfDepth) == Plane.PlaneSide.Back && this.planes[i].testPoint(x + halfWidth, y + halfHeight, z - halfDepth) == Plane.PlaneSide.Back && this.planes[i].testPoint(x + halfWidth, y - halfHeight, z + halfDepth) == Plane.PlaneSide.Back && this.planes[i].testPoint(x + halfWidth, y - halfHeight, z - halfDepth) == Plane.PlaneSide.Back && this.planes[i].testPoint(x - halfWidth, y + halfHeight, z + halfDepth) == Plane.PlaneSide.Back && this.planes[i].testPoint(x - halfWidth, y + halfHeight, z - halfDepth) == Plane.PlaneSide.Back && this.planes[i].testPoint(x - halfWidth, y - halfHeight, z + halfDepth) == Plane.PlaneSide.Back && this.planes[i].testPoint(x - halfWidth, y - halfHeight, z - halfDepth) == Plane.PlaneSide.Back) {
                return false;
            }
        }
        return true;
    }
}