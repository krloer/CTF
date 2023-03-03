package com.badlogic.gdx.math;

/* loaded from: classes.dex */
public final class GeometryUtils {
    private static final Vector2 tmp1 = new Vector2();
    private static final Vector2 tmp2 = new Vector2();
    private static final Vector2 tmp3 = new Vector2();

    private GeometryUtils() {
    }

    public static Vector2 toBarycoord(Vector2 p, Vector2 a, Vector2 b, Vector2 c, Vector2 barycentricOut) {
        Vector2 v0 = tmp1.set(b).sub(a);
        Vector2 v1 = tmp2.set(c).sub(a);
        Vector2 v2 = tmp3.set(p).sub(a);
        float d00 = v0.dot(v0);
        float d01 = v0.dot(v1);
        float d11 = v1.dot(v1);
        float d20 = v2.dot(v0);
        float d21 = v2.dot(v1);
        float denom = (d00 * d11) - (d01 * d01);
        barycentricOut.x = ((d11 * d20) - (d01 * d21)) / denom;
        barycentricOut.y = ((d00 * d21) - (d01 * d20)) / denom;
        return barycentricOut;
    }

    public static boolean barycoordInsideTriangle(Vector2 barycentric) {
        return barycentric.x >= 0.0f && barycentric.y >= 0.0f && barycentric.x + barycentric.y <= 1.0f;
    }

    public static Vector2 fromBarycoord(Vector2 barycentric, Vector2 a, Vector2 b, Vector2 c, Vector2 interpolatedOut) {
        float u = (1.0f - barycentric.x) - barycentric.y;
        interpolatedOut.x = (a.x * u) + (barycentric.x * b.x) + (barycentric.y * c.x);
        interpolatedOut.y = (a.y * u) + (barycentric.x * b.y) + (barycentric.y * c.y);
        return interpolatedOut;
    }

    public static float fromBarycoord(Vector2 barycentric, float a, float b, float c) {
        float u = (1.0f - barycentric.x) - barycentric.y;
        return (u * a) + (barycentric.x * b) + (barycentric.y * c);
    }

    public static float lowestPositiveRoot(float a, float b, float c) {
        float det = (b * b) - ((4.0f * a) * c);
        if (det < 0.0f) {
            return Float.NaN;
        }
        float sqrtD = (float) Math.sqrt(det);
        float invA = 1.0f / (2.0f * a);
        float r1 = ((-b) - sqrtD) * invA;
        float r2 = ((-b) + sqrtD) * invA;
        if (r1 > r2) {
            r2 = r1;
            r1 = r2;
        }
        if (r1 > 0.0f) {
            return r1;
        }
        if (r2 > 0.0f) {
            return r2;
        }
        return Float.NaN;
    }

    public static boolean colinear(float x1, float y1, float x2, float y2, float x3, float y3) {
        float dx21 = x2 - x1;
        float dy21 = y2 - y1;
        float dx32 = x3 - x2;
        float dy32 = y3 - y2;
        float det = (dx32 * dy21) - (dx21 * dy32);
        return Math.abs(det) < 1.0E-6f;
    }

    public static Vector2 triangleCentroid(float x1, float y1, float x2, float y2, float x3, float y3, Vector2 centroid) {
        centroid.x = ((x1 + x2) + x3) / 3.0f;
        centroid.y = ((y1 + y2) + y3) / 3.0f;
        return centroid;
    }

    public static Vector2 triangleCircumcenter(float x1, float y1, float x2, float y2, float x3, float y3, Vector2 circumcenter) {
        float dx21 = x2 - x1;
        float dy21 = y2 - y1;
        float dx32 = x3 - x2;
        float dy32 = y3 - y2;
        float dx13 = x1 - x3;
        float dy13 = y1 - y3;
        float det = (dx32 * dy21) - (dx21 * dy32);
        if (Math.abs(det) < 1.0E-6f) {
            throw new IllegalArgumentException("Triangle points must not be colinear.");
        }
        float det2 = det * 2.0f;
        float sqr1 = (x1 * x1) + (y1 * y1);
        float sqr2 = (x2 * x2) + (y2 * y2);
        float sqr3 = (x3 * x3) + (y3 * y3);
        circumcenter.set((((sqr1 * dy32) + (sqr2 * dy13)) + (sqr3 * dy21)) / det2, (-(((sqr1 * dx32) + (sqr2 * dx13)) + (sqr3 * dx21))) / det2);
        return circumcenter;
    }

    public static float triangleCircumradius(float x1, float y1, float x2, float y2, float x3, float y3) {
        float x;
        float x4;
        if (Math.abs(y2 - y1) < 1.0E-6f) {
            float mx2 = (x2 + x3) / 2.0f;
            float my2 = (y2 + y3) / 2.0f;
            x = (x2 + x1) / 2.0f;
            x4 = ((x - mx2) * ((-(x3 - x2)) / (y3 - y2))) + my2;
        } else if (Math.abs(y3 - y2) < 1.0E-6f) {
            x = (x3 + x2) / 2.0f;
            x4 = ((x - ((x1 + x2) / 2.0f)) * ((-(x2 - x1)) / (y2 - y1))) + ((y1 + y2) / 2.0f);
        } else {
            float m1 = (-(x2 - x1)) / (y2 - y1);
            float m2 = (-(x3 - x2)) / (y3 - y2);
            float mx1 = (x1 + x2) / 2.0f;
            float mx22 = (x2 + x3) / 2.0f;
            float my1 = (y1 + y2) / 2.0f;
            float my22 = (y2 + y3) / 2.0f;
            float x5 = ((((m1 * mx1) - (m2 * mx22)) + my22) - my1) / (m1 - m2);
            x = x5;
            x4 = ((x5 - mx1) * m1) + my1;
        }
        float m12 = x1 - x;
        float dy = y1 - x4;
        return (float) Math.sqrt((m12 * m12) + (dy * dy));
    }

    public static float triangleQuality(float x1, float y1, float x2, float y2, float x3, float y3) {
        float length1 = (float) Math.sqrt((x1 * x1) + (y1 * y1));
        float length2 = (float) Math.sqrt((x2 * x2) + (y2 * y2));
        float length3 = (float) Math.sqrt((x3 * x3) + (y3 * y3));
        return Math.min(length1, Math.min(length2, length3)) / triangleCircumradius(x1, y1, x2, y2, x3, y3);
    }

    public static float triangleArea(float x1, float y1, float x2, float y2, float x3, float y3) {
        return Math.abs(((x1 - x3) * (y2 - y1)) - ((x1 - x2) * (y3 - y1))) * 0.5f;
    }

    public static Vector2 quadrilateralCentroid(float x1, float y1, float x2, float y2, float x3, float y3, float x4, float y4, Vector2 centroid) {
        float avgX1 = ((x1 + x2) + x3) / 3.0f;
        float avgY1 = ((y1 + y2) + y3) / 3.0f;
        float avgX2 = ((x1 + x4) + x3) / 3.0f;
        float avgY2 = ((y1 + y4) + y3) / 3.0f;
        centroid.x = avgX1 - ((avgX1 - avgX2) / 2.0f);
        centroid.y = avgY1 - ((avgY1 - avgY2) / 2.0f);
        return centroid;
    }

    public static Vector2 polygonCentroid(float[] polygon, int offset, int count, Vector2 centroid) {
        if (count < 6) {
            throw new IllegalArgumentException("A polygon must have 3 or more coordinate pairs.");
        }
        float area = 0.0f;
        float x = 0.0f;
        float y = 0.0f;
        int last = (offset + count) - 2;
        float x1 = polygon[last];
        float y1 = polygon[last + 1];
        for (int i = offset; i <= last; i += 2) {
            float x2 = polygon[i];
            float y2 = polygon[i + 1];
            float a = (x1 * y2) - (x2 * y1);
            area += a;
            x += (x1 + x2) * a;
            y += (y1 + y2) * a;
            x1 = x2;
            y1 = y2;
        }
        if (area == 0.0f) {
            centroid.x = 0.0f;
            centroid.y = 0.0f;
        } else {
            float area2 = area * 0.5f;
            centroid.x = x / (area2 * 6.0f);
            centroid.y = y / (6.0f * area2);
        }
        return centroid;
    }

    public static float polygonArea(float[] polygon, int offset, int count) {
        float area = 0.0f;
        int last = (offset + count) - 2;
        float x1 = polygon[last];
        float y1 = polygon[last + 1];
        for (int i = offset; i <= last; i += 2) {
            float x2 = polygon[i];
            float y2 = polygon[i + 1];
            area += (x1 * y2) - (x2 * y1);
            x1 = x2;
            y1 = y2;
        }
        return 0.5f * area;
    }

    public static void ensureCCW(float[] polygon) {
        ensureCCW(polygon, 0, polygon.length);
    }

    public static void ensureCCW(float[] polygon, int offset, int count) {
        if (isClockwise(polygon, offset, count)) {
            int lastX = (offset + count) - 2;
            int n = (count / 2) + offset;
            for (int i = offset; i < n; i += 2) {
                int other = lastX - i;
                float x = polygon[i];
                float y = polygon[i + 1];
                polygon[i] = polygon[other];
                polygon[i + 1] = polygon[other + 1];
                polygon[other] = x;
                polygon[other + 1] = y;
            }
        }
    }

    public static boolean isClockwise(float[] polygon, int offset, int count) {
        if (count <= 2) {
            return false;
        }
        float area = 0.0f;
        int last = (offset + count) - 2;
        float x1 = polygon[last];
        float y1 = polygon[last + 1];
        for (int i = offset; i <= last; i += 2) {
            float x2 = polygon[i];
            float y2 = polygon[i + 1];
            area += (x1 * y2) - (x2 * y1);
            x1 = x2;
            y1 = y2;
        }
        return area < 0.0f;
    }
}