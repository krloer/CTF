package com.badlogic.gdx.math;

import com.badlogic.gdx.utils.BooleanArray;
import com.badlogic.gdx.utils.FloatArray;
import com.badlogic.gdx.utils.IntArray;
import com.badlogic.gdx.utils.ShortArray;

/* loaded from: classes.dex */
public class DelaunayTriangulator {
    private static final int COMPLETE = 1;
    private static final float EPSILON = 1.0E-6f;
    private static final int INCOMPLETE = 2;
    private static final int INSIDE = 0;
    private float[] sortedPoints;
    private final IntArray quicksortStack = new IntArray();
    private final ShortArray triangles = new ShortArray(false, 16);
    private final ShortArray originalIndices = new ShortArray(false, 0);
    private final IntArray edges = new IntArray();
    private final BooleanArray complete = new BooleanArray(false, 16);
    private final float[] superTriangle = new float[6];
    private final Vector2 centroid = new Vector2();

    public ShortArray computeTriangles(FloatArray points, boolean sorted) {
        return computeTriangles(points.items, 0, points.size, sorted);
    }

    public ShortArray computeTriangles(float[] polygon, boolean sorted) {
        return computeTriangles(polygon, 0, polygon.length, sorted);
    }

    public ShortArray computeTriangles(float[] points, int offset, int count, boolean sorted) {
        float[] points2;
        int offset2;
        int pointIndex;
        int offset3;
        float y1;
        float x1;
        float y2;
        float x2;
        float y3;
        float x3;
        float[] points3;
        int triangleIndex;
        boolean[] completeArray;
        short[] trianglesArray;
        int end;
        int pointIndex2;
        IntArray edges;
        float[] superTriangle;
        ShortArray triangles;
        BooleanArray complete;
        if (count <= 32767) {
            ShortArray triangles2 = this.triangles;
            triangles2.clear();
            if (count < 6) {
                return triangles2;
            }
            triangles2.ensureCapacity(count);
            if (sorted) {
                points2 = points;
                offset2 = offset;
            } else {
                float[] fArr = this.sortedPoints;
                if (fArr == null || fArr.length < count) {
                    this.sortedPoints = new float[count];
                }
                System.arraycopy(points, offset, this.sortedPoints, 0, count);
                float[] points4 = this.sortedPoints;
                sort(points4, count);
                points2 = points4;
                offset2 = 0;
            }
            int end2 = offset2 + count;
            float xmin = points2[0];
            int i = 1;
            float ymin = points2[1];
            int i2 = offset2 + 2;
            float xmin2 = xmin;
            float ymin2 = ymin;
            float xmax = xmin;
            float ymax = ymin;
            while (i2 < end2) {
                float value = points2[i2];
                if (value < xmin2) {
                    xmin2 = value;
                }
                if (value > xmax) {
                    xmax = value;
                }
                int i3 = i2 + 1;
                float value2 = points2[i3];
                if (value2 < ymin2) {
                    ymin2 = value2;
                }
                if (value2 > ymax) {
                    ymax = value2;
                }
                i2 = i3 + 1;
            }
            float dx = xmax - xmin2;
            float dy = ymax - ymin2;
            float dmax = (dx > dy ? dx : dy) * 20.0f;
            float xmid = (xmax + xmin2) / 2.0f;
            float ymid = (ymax + ymin2) / 2.0f;
            float[] superTriangle2 = this.superTriangle;
            superTriangle2[0] = xmid - dmax;
            superTriangle2[1] = ymid - dmax;
            superTriangle2[2] = xmid;
            superTriangle2[3] = ymid + dmax;
            superTriangle2[4] = xmid + dmax;
            superTriangle2[5] = ymid - dmax;
            IntArray edges2 = this.edges;
            edges2.ensureCapacity(count / 2);
            BooleanArray complete2 = this.complete;
            complete2.clear();
            complete2.ensureCapacity(count);
            triangles2.add(end2);
            triangles2.add(end2 + 2);
            triangles2.add(end2 + 4);
            complete2.add(false);
            int pointIndex3 = offset2;
            while (pointIndex3 < end2) {
                float x = points2[pointIndex3];
                float y = points2[pointIndex3 + 1];
                short[] trianglesArray2 = triangles2.items;
                boolean[] completeArray2 = complete2.items;
                int triangleIndex2 = triangles2.size - i;
                while (triangleIndex2 >= 0) {
                    int completeIndex = triangleIndex2 / 3;
                    if (completeArray2[completeIndex]) {
                        triangleIndex = triangleIndex2;
                        completeArray = completeArray2;
                        trianglesArray = trianglesArray2;
                        pointIndex2 = pointIndex3;
                        complete = complete2;
                        superTriangle = superTriangle2;
                        triangles = triangles2;
                        offset3 = offset2;
                        points3 = points2;
                        end = end2;
                        edges = edges2;
                    } else {
                        short s = trianglesArray2[triangleIndex2 - 2];
                        short s2 = trianglesArray2[triangleIndex2 - 1];
                        offset3 = offset2;
                        short s3 = trianglesArray2[triangleIndex2];
                        if (s >= end2) {
                            int i4 = s - end2;
                            float x12 = superTriangle2[i4];
                            float y12 = superTriangle2[i4 + 1];
                            x1 = y12;
                            y1 = x12;
                        } else {
                            y1 = points2[s];
                            x1 = points2[s + 1];
                        }
                        if (s2 >= end2) {
                            int i5 = s2 - end2;
                            float x22 = superTriangle2[i5];
                            float y22 = superTriangle2[i5 + 1];
                            x2 = y22;
                            y2 = x22;
                        } else {
                            y2 = points2[s2];
                            x2 = points2[s2 + 1];
                        }
                        if (s3 >= end2) {
                            int i6 = s3 - end2;
                            float x32 = superTriangle2[i6];
                            float y32 = superTriangle2[i6 + 1];
                            x3 = y32;
                            y3 = x32;
                        } else {
                            y3 = points2[s3];
                            x3 = points2[s3 + 1];
                        }
                        points3 = points2;
                        triangleIndex = triangleIndex2;
                        completeArray = completeArray2;
                        trianglesArray = trianglesArray2;
                        end = end2;
                        pointIndex2 = pointIndex3;
                        BooleanArray complete3 = complete2;
                        edges = edges2;
                        superTriangle = superTriangle2;
                        ShortArray triangles3 = triangles2;
                        int circumCircle = circumCircle(x, y, y1, x1, y2, x2, y3, x3);
                        if (circumCircle == 0) {
                            edges.add(s, s2, s2, s3);
                            edges.add(s3, s);
                            triangles = triangles3;
                            triangles.removeRange(triangleIndex - 2, triangleIndex);
                            complete = complete3;
                            complete.removeIndex(completeIndex);
                        } else if (circumCircle != 1) {
                            complete = complete3;
                            triangles = triangles3;
                        } else {
                            completeArray[completeIndex] = true;
                            complete = complete3;
                            triangles = triangles3;
                        }
                    }
                    offset2 = offset3;
                    points2 = points3;
                    triangles2 = triangles;
                    complete2 = complete;
                    triangleIndex2 = triangleIndex - 3;
                    edges2 = edges;
                    completeArray2 = completeArray;
                    trianglesArray2 = trianglesArray;
                    end2 = end;
                    pointIndex3 = pointIndex2;
                    superTriangle2 = superTriangle;
                }
                int pointIndex4 = pointIndex3;
                BooleanArray complete4 = complete2;
                float[] superTriangle3 = superTriangle2;
                ShortArray triangles4 = triangles2;
                int offset4 = offset2;
                float[] points5 = points2;
                int end3 = end2;
                IntArray edges3 = edges2;
                int[] edgesArray = edges3.items;
                int i7 = 0;
                int n = edges3.size;
                while (i7 < n) {
                    int p1 = edgesArray[i7];
                    if (p1 == -1) {
                        pointIndex = pointIndex4;
                    } else {
                        int p2 = edgesArray[i7 + 1];
                        boolean skip = false;
                        for (int ii = i7 + 2; ii < n; ii += 2) {
                            if (p1 == edgesArray[ii + 1] && p2 == edgesArray[ii]) {
                                skip = true;
                                edgesArray[ii] = -1;
                            }
                        }
                        if (skip) {
                            pointIndex = pointIndex4;
                        } else {
                            triangles4.add(p1);
                            triangles4.add(edgesArray[i7 + 1]);
                            pointIndex = pointIndex4;
                            triangles4.add(pointIndex);
                            complete4.add(false);
                        }
                    }
                    i7 += 2;
                    pointIndex4 = pointIndex;
                }
                edges3.clear();
                pointIndex3 = pointIndex4 + 2;
                offset2 = offset4;
                points2 = points5;
                triangles2 = triangles4;
                complete2 = complete4;
                edges2 = edges3;
                end2 = end3;
                superTriangle2 = superTriangle3;
                i = 1;
            }
            ShortArray triangles5 = triangles2;
            int offset5 = offset2;
            int end4 = end2;
            short[] trianglesArray3 = triangles5.items;
            int i8 = triangles5.size - 1;
            while (i8 >= 0) {
                int end5 = end4;
                if (trianglesArray3[i8] >= end5 || trianglesArray3[i8 - 1] >= end5 || trianglesArray3[i8 - 2] >= end5) {
                    triangles5.removeIndex(i8);
                    triangles5.removeIndex(i8 - 1);
                    triangles5.removeIndex(i8 - 2);
                }
                i8 -= 3;
                end4 = end5;
            }
            if (!sorted) {
                short[] originalIndicesArray = this.originalIndices.items;
                int n2 = triangles5.size;
                for (int i9 = 0; i9 < n2; i9++) {
                    trianglesArray3[i9] = (short) (originalIndicesArray[trianglesArray3[i9] / 2] * 2);
                }
            }
            if (offset5 == 0) {
                int n3 = triangles5.size;
                for (int i10 = 0; i10 < n3; i10++) {
                    trianglesArray3[i10] = (short) (trianglesArray3[i10] / 2);
                }
            } else {
                int n4 = triangles5.size;
                for (int i11 = 0; i11 < n4; i11++) {
                    trianglesArray3[i11] = (short) ((trianglesArray3[i11] - offset5) / 2);
                }
            }
            return triangles5;
        }
        throw new IllegalArgumentException("count must be <= 32767");
    }

    private int circumCircle(float xp, float yp, float x1, float y1, float x2, float y2, float x3, float y3) {
        float xc;
        float xc2;
        float y1y2 = Math.abs(y1 - y2);
        float y2y3 = Math.abs(y2 - y3);
        if (y1y2 < 1.0E-6f) {
            if (y2y3 < 1.0E-6f) {
                return 2;
            }
            float mx2 = (x2 + x3) / 2.0f;
            float my2 = (y2 + y3) / 2.0f;
            xc = (x2 + x1) / 2.0f;
            xc2 = ((xc - mx2) * ((-(x3 - x2)) / (y3 - y2))) + my2;
        } else {
            float m1 = (-(x2 - x1)) / (y2 - y1);
            float mx1 = (x1 + x2) / 2.0f;
            float my1 = (y1 + y2) / 2.0f;
            if (y2y3 < 1.0E-6f) {
                xc = (x3 + x2) / 2.0f;
                xc2 = ((xc - mx1) * m1) + my1;
            } else {
                float m2 = (-(x3 - x2)) / (y3 - y2);
                float mx22 = (x2 + x3) / 2.0f;
                float my22 = (y2 + y3) / 2.0f;
                float xc3 = ((((m1 * mx1) - (m2 * mx22)) + my22) - my1) / (m1 - m2);
                xc = xc3;
                xc2 = ((xc3 - mx1) * m1) + my1;
            }
        }
        float m12 = x2 - xc;
        float dy = y2 - xc2;
        float rsqr = (m12 * m12) + (dy * dy);
        float dx = xp - xc;
        float dx2 = dx * dx;
        float dy2 = yp - xc2;
        if (((dy2 * dy2) + dx2) - rsqr <= 1.0E-6f) {
            return 0;
        }
        return (xp <= xc || dx2 <= rsqr) ? 2 : 1;
    }

    private void sort(float[] values, int count) {
        int pointCount = count / 2;
        this.originalIndices.clear();
        this.originalIndices.ensureCapacity(pointCount);
        short[] originalIndicesArray = this.originalIndices.items;
        for (short i = 0; i < pointCount; i = (short) (i + 1)) {
            originalIndicesArray[i] = i;
        }
        IntArray stack = this.quicksortStack;
        stack.add(0);
        stack.add((count - 1) - 1);
        while (stack.size > 0) {
            int upper = stack.pop();
            int lower = stack.pop();
            if (upper > lower) {
                int i2 = quicksortPartition(values, lower, upper, originalIndicesArray);
                if (i2 - lower > upper - i2) {
                    stack.add(lower);
                    stack.add(i2 - 2);
                }
                stack.add(i2 + 2);
                stack.add(upper);
                if (upper - i2 >= i2 - lower) {
                    stack.add(lower);
                    stack.add(i2 - 2);
                }
            }
        }
    }

    private int quicksortPartition(float[] values, int lower, int upper, short[] originalIndices) {
        float value = values[lower];
        int up = upper;
        int down = lower + 2;
        while (down < up) {
            while (down < up && values[down] <= value) {
                down += 2;
            }
            while (values[up] > value) {
                up -= 2;
            }
            if (down < up) {
                float tempValue = values[down];
                values[down] = values[up];
                values[up] = tempValue;
                float tempValue2 = values[down + 1];
                values[down + 1] = values[up + 1];
                values[up + 1] = tempValue2;
                short tempIndex = originalIndices[down / 2];
                originalIndices[down / 2] = originalIndices[up / 2];
                originalIndices[up / 2] = tempIndex;
            }
        }
        float tempValue3 = values[up];
        if (value > tempValue3) {
            values[lower] = values[up];
            values[up] = value;
            float tempValue4 = values[lower + 1];
            values[lower + 1] = values[up + 1];
            values[up + 1] = tempValue4;
            short tempIndex2 = originalIndices[lower / 2];
            originalIndices[lower / 2] = originalIndices[up / 2];
            originalIndices[up / 2] = tempIndex2;
        }
        return up;
    }

    public void trim(ShortArray triangles, float[] points, float[] hull, int offset, int count) {
        short[] trianglesArray = triangles.items;
        for (int i = triangles.size - 1; i >= 0; i -= 3) {
            int p1 = trianglesArray[i - 2] * 2;
            int p2 = trianglesArray[i - 1] * 2;
            int p3 = trianglesArray[i] * 2;
            GeometryUtils.triangleCentroid(points[p1], points[p1 + 1], points[p2], points[p2 + 1], points[p3], points[p3 + 1], this.centroid);
            if (!Intersector.isPointInPolygon(hull, offset, count, this.centroid.x, this.centroid.y)) {
                triangles.removeIndex(i);
                triangles.removeIndex(i - 1);
                triangles.removeIndex(i - 2);
            }
        }
    }
}