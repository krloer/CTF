package com.badlogic.gdx.math;

import com.badlogic.gdx.math.Plane;
import com.badlogic.gdx.math.collision.BoundingBox;
import com.badlogic.gdx.math.collision.Ray;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.FloatArray;
import java.util.Arrays;
import java.util.List;

/* loaded from: classes.dex */
public final class Intersector {
    private static final Vector3 v0 = new Vector3();
    private static final Vector3 v1 = new Vector3();
    private static final Vector3 v2 = new Vector3();
    private static final FloatArray floatArray = new FloatArray();
    private static final FloatArray floatArray2 = new FloatArray();
    private static final Vector2 ip = new Vector2();
    private static final Vector2 ep1 = new Vector2();
    private static final Vector2 ep2 = new Vector2();
    private static final Vector2 s = new Vector2();
    private static final Vector2 e = new Vector2();
    static Vector2 v2a = new Vector2();
    static Vector2 v2b = new Vector2();
    static Vector2 v2c = new Vector2();
    static Vector2 v2d = new Vector2();
    private static final Plane p = new Plane(new Vector3(), 0.0f);
    private static final Vector3 i = new Vector3();
    private static final Vector3 dir = new Vector3();
    private static final Vector3 start = new Vector3();
    static Vector3 best = new Vector3();
    static Vector3 tmp = new Vector3();
    static Vector3 tmp1 = new Vector3();
    static Vector3 tmp2 = new Vector3();
    static Vector3 tmp3 = new Vector3();
    static Vector3 intersection = new Vector3();

    /* loaded from: classes.dex */
    public static class MinimumTranslationVector {
        public Vector2 normal = new Vector2();
        public float depth = 0.0f;
    }

    private Intersector() {
    }

    public static boolean isPointInTriangle(Vector3 point, Vector3 t1, Vector3 t2, Vector3 t3) {
        v0.set(t1).sub(point);
        v1.set(t2).sub(point);
        v2.set(t3).sub(point);
        float ab = v0.dot(v1);
        float ac = v0.dot(v2);
        float bc = v1.dot(v2);
        Vector3 vector3 = v2;
        float cc = vector3.dot(vector3);
        if ((bc * ac) - (cc * ab) < 0.0f) {
            return false;
        }
        Vector3 vector32 = v1;
        float bb = vector32.dot(vector32);
        return (ab * bc) - (ac * bb) >= 0.0f;
    }

    public static boolean isPointInTriangle(Vector2 p2, Vector2 a, Vector2 b, Vector2 c) {
        float px1 = p2.x - a.x;
        float py1 = p2.y - a.y;
        boolean side12 = ((b.x - a.x) * py1) - ((b.y - a.y) * px1) > 0.0f;
        if ((((c.x - a.x) * py1) - ((c.y - a.y) * px1) > 0.0f) == side12) {
            return false;
        }
        return (((((c.x - b.x) * (p2.y - b.y)) - ((c.y - b.y) * (p2.x - b.x))) > 0.0f ? 1 : ((((c.x - b.x) * (p2.y - b.y)) - ((c.y - b.y) * (p2.x - b.x))) == 0.0f ? 0 : -1)) > 0) == side12;
    }

    public static boolean isPointInTriangle(float px, float py, float ax, float ay, float bx, float by, float cx, float cy) {
        float px1 = px - ax;
        float py1 = py - ay;
        boolean side12 = ((bx - ax) * py1) - ((by - ay) * px1) > 0.0f;
        if ((((cx - ax) * py1) - ((cy - ay) * px1) > 0.0f) == side12) {
            return false;
        }
        return (((((cx - bx) * (py - by)) - ((cy - by) * (px - bx))) > 0.0f ? 1 : ((((cx - bx) * (py - by)) - ((cy - by) * (px - bx))) == 0.0f ? 0 : -1)) > 0) == side12;
    }

    public static boolean intersectSegmentPlane(Vector3 start2, Vector3 end, Plane plane, Vector3 intersection2) {
        Vector3 dir2 = v0.set(end).sub(start2);
        float denom = dir2.dot(plane.getNormal());
        if (denom == 0.0f) {
            return false;
        }
        float t = (-(start2.dot(plane.getNormal()) + plane.getD())) / denom;
        if (t < 0.0f || t > 1.0f) {
            return false;
        }
        intersection2.set(start2).add(dir2.scl(t));
        return true;
    }

    public static int pointLineSide(Vector2 linePoint1, Vector2 linePoint2, Vector2 point) {
        return (int) Math.signum(((linePoint2.x - linePoint1.x) * (point.y - linePoint1.y)) - ((linePoint2.y - linePoint1.y) * (point.x - linePoint1.x)));
    }

    public static int pointLineSide(float linePoint1X, float linePoint1Y, float linePoint2X, float linePoint2Y, float pointX, float pointY) {
        return (int) Math.signum(((linePoint2X - linePoint1X) * (pointY - linePoint1Y)) - ((linePoint2Y - linePoint1Y) * (pointX - linePoint1X)));
    }

    public static boolean isPointInPolygon(Array<Vector2> polygon, Vector2 point) {
        Vector2 last = polygon.peek();
        float x = point.x;
        float y = point.y;
        boolean oddNodes = false;
        for (int i2 = 0; i2 < polygon.size; i2++) {
            Vector2 vertex = polygon.get(i2);
            if (((vertex.y < y && last.y >= y) || (last.y < y && vertex.y >= y)) && vertex.x + (((y - vertex.y) / (last.y - vertex.y)) * (last.x - vertex.x)) < x) {
                oddNodes = !oddNodes;
            }
            last = vertex;
        }
        return oddNodes;
    }

    public static boolean isPointInPolygon(float[] polygon, int offset, int count, float x, float y) {
        boolean oddNodes = false;
        float sx = polygon[offset];
        float sy = polygon[offset + 1];
        float y1 = sy;
        int yi = offset + 3;
        int n = offset + count;
        while (true) {
            if (yi >= n) {
                break;
            }
            float y2 = polygon[yi];
            if ((y2 < y && y1 >= y) || (y1 < y && y2 >= y)) {
                float x2 = polygon[yi - 1];
                if ((((y - y2) / (y1 - y2)) * (polygon[yi - 3] - x2)) + x2 < x) {
                    oddNodes = oddNodes ? false : true;
                }
            }
            y1 = y2;
            yi += 2;
        }
        int n2 = (sy > y ? 1 : (sy == y ? 0 : -1));
        if (((n2 >= 0 || y1 < y) && (y1 >= y || sy < y)) || (((y - sy) / (y1 - sy)) * (polygon[yi - 3] - sx)) + sx >= x) {
            return oddNodes;
        }
        boolean oddNodes2 = oddNodes ? false : true;
        return oddNodes2;
    }

    /* JADX WARN: Type inference failed for: r2v0 */
    /* JADX WARN: Type inference failed for: r2v1, types: [boolean] */
    /* JADX WARN: Type inference failed for: r2v7 */
    public static boolean intersectPolygons(Polygon p1, Polygon p2, Polygon overlap) {
        ?? r2 = 0;
        if (p1.getVertices().length == 0 || p2.getVertices().length == 0) {
            return false;
        }
        Vector2 ip2 = ip;
        Vector2 ep12 = ep1;
        Vector2 ep22 = ep2;
        Vector2 s2 = s;
        Vector2 e2 = e;
        FloatArray floatArray3 = floatArray;
        FloatArray floatArray22 = floatArray2;
        floatArray3.clear();
        floatArray22.clear();
        floatArray22.addAll(p1.getTransformedVertices());
        float[] vertices2 = p2.getTransformedVertices();
        int i2 = 0;
        int i3 = 2;
        int last = vertices2.length - 2;
        while (i2 <= last) {
            ep12.set(vertices2[i2], vertices2[i2 + 1]);
            if (i2 < last) {
                ep22.set(vertices2[i2 + 2], vertices2[i2 + 3]);
            } else {
                ep22.set(vertices2[r2], vertices2[1]);
            }
            if (floatArray22.size == 0) {
                return r2;
            }
            s2.set(floatArray22.get(floatArray22.size - i3), floatArray22.get(floatArray22.size - 1));
            int j = 0;
            while (j < floatArray22.size) {
                e2.set(floatArray22.get(j), floatArray22.get(j + 1));
                boolean side = pointLineSide(ep22, ep12, s2) > 0;
                if (pointLineSide(ep22, ep12, e2) > 0) {
                    if (!side) {
                        intersectLines(s2, e2, ep12, ep22, ip2);
                        if (floatArray3.size < i3 || floatArray3.get(floatArray3.size - i3) != ip2.x || floatArray3.get(floatArray3.size - 1) != ip2.y) {
                            floatArray3.add(ip2.x);
                            floatArray3.add(ip2.y);
                        }
                    }
                    floatArray3.add(e2.x);
                    floatArray3.add(e2.y);
                } else if (side) {
                    intersectLines(s2, e2, ep12, ep22, ip2);
                    floatArray3.add(ip2.x);
                    floatArray3.add(ip2.y);
                }
                s2.set(e2.x, e2.y);
                j += 2;
                i3 = 2;
            }
            floatArray22.clear();
            floatArray22.addAll(floatArray3);
            floatArray3.clear();
            i2 += 2;
            r2 = 0;
            i3 = 2;
        }
        if (floatArray22.size != 0) {
            if (overlap != null) {
                if (overlap.getVertices().length != floatArray22.size) {
                    overlap.setVertices(floatArray22.toArray());
                } else {
                    System.arraycopy(floatArray22.items, 0, overlap.getVertices(), 0, floatArray22.size);
                }
            }
            return true;
        }
        return false;
    }

    public static boolean intersectPolygons(FloatArray polygon1, FloatArray polygon2) {
        if (isPointInPolygon(polygon1.items, 0, polygon1.size, polygon2.items[0], polygon2.items[1]) || isPointInPolygon(polygon2.items, 0, polygon2.size, polygon1.items[0], polygon1.items[1])) {
            return true;
        }
        return intersectPolygonEdges(polygon1, polygon2);
    }

    public static boolean intersectPolygonEdges(FloatArray polygon1, FloatArray polygon2) {
        int last1 = polygon1.size - 2;
        int last2 = polygon2.size - 2;
        float[] p1 = polygon1.items;
        float[] p2 = polygon2.items;
        float x1 = p1[last1];
        float y1 = p1[last1 + 1];
        for (int i2 = 0; i2 <= last1; i2 += 2) {
            float x2 = p1[i2];
            float y2 = p1[i2 + 1];
            float x3 = p2[last2];
            float y3 = p2[last2 + 1];
            float x32 = x3;
            float y32 = y3;
            int j = 0;
            while (j <= last2) {
                float x4 = p2[j];
                float y4 = p2[j + 1];
                int j2 = j;
                if (intersectSegments(x1, y1, x2, y2, x32, y32, x4, y4, null)) {
                    return true;
                }
                x32 = x4;
                y32 = y4;
                j = j2 + 2;
            }
            x1 = x2;
            y1 = y2;
        }
        return false;
    }

    public static float distanceLinePoint(float startX, float startY, float endX, float endY, float pointX, float pointY) {
        float normalLength = (float) Math.sqrt(((endX - startX) * (endX - startX)) + ((endY - startY) * (endY - startY)));
        return Math.abs(((pointX - startX) * (endY - startY)) - ((pointY - startY) * (endX - startX))) / normalLength;
    }

    public static float distanceSegmentPoint(float startX, float startY, float endX, float endY, float pointX, float pointY) {
        return nearestSegmentPoint(startX, startY, endX, endY, pointX, pointY, v2a).dst(pointX, pointY);
    }

    public static float distanceSegmentPoint(Vector2 start2, Vector2 end, Vector2 point) {
        return nearestSegmentPoint(start2, end, point, v2a).dst(point);
    }

    public static Vector2 nearestSegmentPoint(Vector2 start2, Vector2 end, Vector2 point, Vector2 nearest) {
        float length2 = start2.dst2(end);
        if (length2 == 0.0f) {
            return nearest.set(start2);
        }
        float t = (((point.x - start2.x) * (end.x - start2.x)) + ((point.y - start2.y) * (end.y - start2.y))) / length2;
        return t < 0.0f ? nearest.set(start2) : t > 1.0f ? nearest.set(end) : nearest.set(start2.x + ((end.x - start2.x) * t), start2.y + ((end.y - start2.y) * t));
    }

    public static Vector2 nearestSegmentPoint(float startX, float startY, float endX, float endY, float pointX, float pointY, Vector2 nearest) {
        float xDiff = endX - startX;
        float yDiff = endY - startY;
        float length2 = (xDiff * xDiff) + (yDiff * yDiff);
        if (length2 == 0.0f) {
            return nearest.set(startX, startY);
        }
        float t = (((pointX - startX) * (endX - startX)) + ((pointY - startY) * (endY - startY))) / length2;
        return t < 0.0f ? nearest.set(startX, startY) : t > 1.0f ? nearest.set(endX, endY) : nearest.set(((endX - startX) * t) + startX, ((endY - startY) * t) + startY);
    }

    public static boolean intersectSegmentCircle(Vector2 start2, Vector2 end, Vector2 center, float squareRadius) {
        tmp.set(end.x - start2.x, end.y - start2.y, 0.0f);
        tmp1.set(center.x - start2.x, center.y - start2.y, 0.0f);
        float l = tmp.len();
        float u = tmp1.dot(tmp.nor());
        if (u <= 0.0f) {
            tmp2.set(start2.x, start2.y, 0.0f);
        } else if (u >= l) {
            tmp2.set(end.x, end.y, 0.0f);
        } else {
            tmp3.set(tmp.scl(u));
            tmp2.set(tmp3.x + start2.x, tmp3.y + start2.y, 0.0f);
        }
        float x = center.x - tmp2.x;
        float y = center.y - tmp2.y;
        return (x * x) + (y * y) <= squareRadius;
    }

    public static boolean intersectSegmentCircle(Vector2 start2, Vector2 end, Circle circle, MinimumTranslationVector mtv) {
        v2a.set(end).sub(start2);
        v2b.set(circle.x - start2.x, circle.y - start2.y);
        float len = v2a.len();
        float u = v2b.dot(v2a.nor());
        if (u <= 0.0f) {
            v2c.set(start2);
        } else if (u >= len) {
            v2c.set(end);
        } else {
            v2d.set(v2a.scl(u));
            v2c.set(v2d).add(start2);
        }
        v2a.set(v2c.x - circle.x, v2c.y - circle.y);
        if (mtv != null) {
            if (v2a.equals(Vector2.Zero)) {
                v2d.set(end.y - start2.y, start2.x - end.x);
                mtv.normal.set(v2d).nor();
                mtv.depth = circle.radius;
            } else {
                mtv.normal.set(v2a).nor();
                mtv.depth = circle.radius - v2a.len();
            }
        }
        return v2a.len2() <= circle.radius * circle.radius;
    }

    public static float intersectRayRay(Vector2 start1, Vector2 direction1, Vector2 start2, Vector2 direction2) {
        float difx = start2.x - start1.x;
        float dify = start2.y - start1.y;
        float d1xd2 = (direction1.x * direction2.y) - (direction1.y * direction2.x);
        if (d1xd2 == 0.0f) {
            return Float.POSITIVE_INFINITY;
        }
        float d2sx = direction2.x / d1xd2;
        float d2sy = direction2.y / d1xd2;
        return (difx * d2sy) - (dify * d2sx);
    }

    public static boolean intersectRayPlane(Ray ray, Plane plane, Vector3 intersection2) {
        float denom = ray.direction.dot(plane.getNormal());
        if (denom != 0.0f) {
            float t = (-(ray.origin.dot(plane.getNormal()) + plane.getD())) / denom;
            if (t < 0.0f) {
                return false;
            }
            if (intersection2 != null) {
                intersection2.set(ray.origin).add(v0.set(ray.direction).scl(t));
            }
            return true;
        } else if (plane.testPoint(ray.origin) == Plane.PlaneSide.OnPlane) {
            if (intersection2 != null) {
                intersection2.set(ray.origin);
            }
            return true;
        } else {
            return false;
        }
    }

    public static float intersectLinePlane(float x, float y, float z, float x2, float y2, float z2, Plane plane, Vector3 intersection2) {
        Vector3 direction = tmp.set(x2, y2, z2).sub(x, y, z);
        Vector3 origin = tmp2.set(x, y, z);
        float denom = direction.dot(plane.getNormal());
        if (denom != 0.0f) {
            float t = (-(origin.dot(plane.getNormal()) + plane.getD())) / denom;
            if (intersection2 != null) {
                intersection2.set(origin).add(direction.scl(t));
            }
            return t;
        } else if (plane.testPoint(origin) == Plane.PlaneSide.OnPlane) {
            if (intersection2 != null) {
                intersection2.set(origin);
            }
            return 0.0f;
        } else {
            return -1.0f;
        }
    }

    public static boolean intersectPlanes(Plane a, Plane b, Plane c, Vector3 intersection2) {
        tmp1.set(a.normal).crs(b.normal);
        tmp2.set(b.normal).crs(c.normal);
        tmp3.set(c.normal).crs(a.normal);
        float f = -a.normal.dot(tmp2);
        if (Math.abs(f) < 1.0E-6f) {
            return false;
        }
        tmp1.scl(c.d);
        tmp2.scl(a.d);
        tmp3.scl(b.d);
        intersection2.set(tmp1.x + tmp2.x + tmp3.x, tmp1.y + tmp2.y + tmp3.y, tmp1.z + tmp2.z + tmp3.z);
        intersection2.scl(1.0f / f);
        return true;
    }

    public static boolean intersectRayTriangle(Ray ray, Vector3 t1, Vector3 t2, Vector3 t3, Vector3 intersection2) {
        Vector3 edge1 = v0.set(t2).sub(t1);
        Vector3 edge2 = v1.set(t3).sub(t1);
        Vector3 pvec = v2.set(ray.direction).crs(edge2);
        float det = edge1.dot(pvec);
        if (MathUtils.isZero(det)) {
            p.set(t1, t2, t3);
            if (p.testPoint(ray.origin) == Plane.PlaneSide.OnPlane && isPointInTriangle(ray.origin, t1, t2, t3)) {
                if (intersection2 != null) {
                    intersection2.set(ray.origin);
                }
                return true;
            }
            return false;
        }
        float det2 = 1.0f / det;
        Vector3 tvec = i.set(ray.origin).sub(t1);
        float u = tvec.dot(pvec) * det2;
        if (u < 0.0f || u > 1.0f) {
            return false;
        }
        Vector3 qvec = tvec.crs(edge1);
        float v = ray.direction.dot(qvec) * det2;
        if (v < 0.0f || u + v > 1.0f) {
            return false;
        }
        float t = edge2.dot(qvec) * det2;
        if (t < 0.0f) {
            return false;
        }
        if (intersection2 != null) {
            if (t <= 1.0E-6f) {
                intersection2.set(ray.origin);
                return true;
            }
            ray.getEndPoint(intersection2, t);
            return true;
        }
        return true;
    }

    public static boolean intersectRaySphere(Ray ray, Vector3 center, float radius, Vector3 intersection2) {
        float len = ray.direction.dot(center.x - ray.origin.x, center.y - ray.origin.y, center.z - ray.origin.z);
        if (len < 0.0f) {
            return false;
        }
        float dst2 = center.dst2(ray.origin.x + (ray.direction.x * len), ray.origin.y + (ray.direction.y * len), ray.origin.z + (ray.direction.z * len));
        float r2 = radius * radius;
        if (dst2 > r2) {
            return false;
        }
        if (intersection2 != null) {
            intersection2.set(ray.direction).scl(len - ((float) Math.sqrt(r2 - dst2))).add(ray.origin);
            return true;
        }
        return true;
    }

    public static boolean intersectRayBounds(Ray ray, BoundingBox box, Vector3 intersection2) {
        if (box.contains(ray.origin)) {
            if (intersection2 != null) {
                intersection2.set(ray.origin);
                return true;
            }
            return true;
        }
        float lowest = 0.0f;
        boolean hit = false;
        if (ray.origin.x <= box.min.x && ray.direction.x > 0.0f) {
            float t = (box.min.x - ray.origin.x) / ray.direction.x;
            if (t >= 0.0f) {
                v2.set(ray.direction).scl(t).add(ray.origin);
                if (v2.y >= box.min.y && v2.y <= box.max.y && v2.z >= box.min.z && v2.z <= box.max.z && (0 == 0 || t < 0.0f)) {
                    hit = true;
                    lowest = t;
                }
            }
        }
        if (ray.origin.x >= box.max.x && ray.direction.x < 0.0f) {
            float t2 = (box.max.x - ray.origin.x) / ray.direction.x;
            if (t2 >= 0.0f) {
                v2.set(ray.direction).scl(t2).add(ray.origin);
                if (v2.y >= box.min.y && v2.y <= box.max.y && v2.z >= box.min.z && v2.z <= box.max.z && (!hit || t2 < lowest)) {
                    hit = true;
                    lowest = t2;
                }
            }
        }
        if (ray.origin.y <= box.min.y && ray.direction.y > 0.0f) {
            float t3 = (box.min.y - ray.origin.y) / ray.direction.y;
            if (t3 >= 0.0f) {
                v2.set(ray.direction).scl(t3).add(ray.origin);
                if (v2.x >= box.min.x && v2.x <= box.max.x && v2.z >= box.min.z && v2.z <= box.max.z && (!hit || t3 < lowest)) {
                    hit = true;
                    lowest = t3;
                }
            }
        }
        if (ray.origin.y >= box.max.y && ray.direction.y < 0.0f) {
            float t4 = (box.max.y - ray.origin.y) / ray.direction.y;
            if (t4 >= 0.0f) {
                v2.set(ray.direction).scl(t4).add(ray.origin);
                if (v2.x >= box.min.x && v2.x <= box.max.x && v2.z >= box.min.z && v2.z <= box.max.z && (!hit || t4 < lowest)) {
                    hit = true;
                    lowest = t4;
                }
            }
        }
        if (ray.origin.z <= box.min.z && ray.direction.z > 0.0f) {
            float t5 = (box.min.z - ray.origin.z) / ray.direction.z;
            if (t5 >= 0.0f) {
                v2.set(ray.direction).scl(t5).add(ray.origin);
                if (v2.x >= box.min.x && v2.x <= box.max.x && v2.y >= box.min.y && v2.y <= box.max.y && (!hit || t5 < lowest)) {
                    hit = true;
                    lowest = t5;
                }
            }
        }
        if (ray.origin.z >= box.max.z && ray.direction.z < 0.0f) {
            float t6 = (box.max.z - ray.origin.z) / ray.direction.z;
            if (t6 >= 0.0f) {
                v2.set(ray.direction).scl(t6).add(ray.origin);
                if (v2.x >= box.min.x && v2.x <= box.max.x && v2.y >= box.min.y && v2.y <= box.max.y && (!hit || t6 < lowest)) {
                    hit = true;
                    lowest = t6;
                }
            }
        }
        if (hit && intersection2 != null) {
            intersection2.set(ray.direction).scl(lowest).add(ray.origin);
            if (intersection2.x < box.min.x) {
                intersection2.x = box.min.x;
            } else if (intersection2.x > box.max.x) {
                intersection2.x = box.max.x;
            }
            if (intersection2.y < box.min.y) {
                intersection2.y = box.min.y;
            } else if (intersection2.y > box.max.y) {
                intersection2.y = box.max.y;
            }
            if (intersection2.z < box.min.z) {
                intersection2.z = box.min.z;
            } else if (intersection2.z > box.max.z) {
                intersection2.z = box.max.z;
            }
        }
        return hit;
    }

    public static boolean intersectRayBoundsFast(Ray ray, BoundingBox box) {
        return intersectRayBoundsFast(ray, box.getCenter(tmp1), box.getDimensions(tmp2));
    }

    public static boolean intersectRayBoundsFast(Ray ray, Vector3 center, Vector3 dimensions) {
        float divX = 1.0f / ray.direction.x;
        float divY = 1.0f / ray.direction.y;
        float divZ = 1.0f / ray.direction.z;
        float minx = ((center.x - (dimensions.x * 0.5f)) - ray.origin.x) * divX;
        float maxx = ((center.x + (dimensions.x * 0.5f)) - ray.origin.x) * divX;
        if (minx > maxx) {
            minx = maxx;
            maxx = minx;
        }
        float t = center.y;
        float miny = ((t - (dimensions.y * 0.5f)) - ray.origin.y) * divY;
        float maxy = ((center.y + (dimensions.y * 0.5f)) - ray.origin.y) * divY;
        if (miny > maxy) {
            miny = maxy;
            maxy = miny;
        }
        float t2 = center.z;
        float minz = ((t2 - (dimensions.z * 0.5f)) - ray.origin.z) * divZ;
        float maxz = ((center.z + (dimensions.z * 0.5f)) - ray.origin.z) * divZ;
        if (minz > maxz) {
            minz = maxz;
            maxz = minz;
        }
        float t3 = Math.max(minx, miny);
        float min = Math.max(t3, minz);
        float max = Math.min(Math.min(maxx, maxy), maxz);
        return max >= 0.0f && max >= min;
    }

    public static boolean intersectRayOrientedBoundsFast(Ray ray, BoundingBox bounds, Matrix4 matrix) {
        float tMax = Float.MAX_VALUE;
        Vector3 oBBposition = matrix.getTranslation(tmp);
        Vector3 delta = oBBposition.sub(ray.origin);
        Vector3 xaxis = tmp1;
        tmp1.set(matrix.val[0], matrix.val[1], matrix.val[2]);
        float e2 = xaxis.dot(delta);
        float f = ray.direction.dot(xaxis);
        if (Math.abs(f) > 1.0E-6f) {
            float t1 = (bounds.min.x + e2) / f;
            float t2 = (bounds.max.x + e2) / f;
            if (t1 > t2) {
                t1 = t2;
                t2 = t1;
            }
            if (t2 < Float.MAX_VALUE) {
                tMax = t2;
            }
            tMin = t1 > 0.0f ? t1 : 0.0f;
            if (tMax < tMin) {
                return false;
            }
        } else {
            float t12 = -e2;
            if (t12 + bounds.min.x > 0.0f || (-e2) + bounds.max.x < 0.0f) {
                return false;
            }
        }
        Vector3 yaxis = tmp2;
        tmp2.set(matrix.val[4], matrix.val[5], matrix.val[6]);
        float e3 = yaxis.dot(delta);
        float f2 = ray.direction.dot(yaxis);
        if (Math.abs(f2) > 1.0E-6f) {
            float t13 = (bounds.min.y + e3) / f2;
            float t22 = (bounds.max.y + e3) / f2;
            if (t13 > t22) {
                t13 = t22;
                t22 = t13;
            }
            if (t22 < tMax) {
                tMax = t22;
            }
            if (t13 > tMin) {
                tMin = t13;
            }
            if (tMin > tMax) {
                return false;
            }
        } else {
            float t14 = -e3;
            if (t14 + bounds.min.y > 0.0f || (-e3) + bounds.max.y < 0.0f) {
                return false;
            }
        }
        Vector3 zaxis = tmp3;
        tmp3.set(matrix.val[8], matrix.val[9], matrix.val[10]);
        float e4 = zaxis.dot(delta);
        float f3 = ray.direction.dot(zaxis);
        if (Math.abs(f3) > 1.0E-6f) {
            float t15 = (bounds.min.z + e4) / f3;
            float t23 = (bounds.max.z + e4) / f3;
            if (t15 > t23) {
                t15 = t23;
                t23 = t15;
            }
            if (t23 < tMax) {
                tMax = t23;
            }
            if (t15 > tMin) {
                tMin = t15;
            }
            if (tMin > tMax) {
                return false;
            }
            return true;
        }
        float t16 = -e4;
        if (t16 + bounds.min.z > 0.0f || (-e4) + bounds.max.z < 0.0f) {
            return false;
        }
        return true;
    }

    public static boolean intersectRayTriangles(Ray ray, float[] triangles, Vector3 intersection2) {
        float min_dist = Float.MAX_VALUE;
        boolean hit = false;
        if (triangles.length % 9 != 0) {
            throw new RuntimeException("triangles array size is not a multiple of 9");
        }
        for (int i2 = 0; i2 < triangles.length; i2 += 9) {
            boolean result = intersectRayTriangle(ray, tmp1.set(triangles[i2], triangles[i2 + 1], triangles[i2 + 2]), tmp2.set(triangles[i2 + 3], triangles[i2 + 4], triangles[i2 + 5]), tmp3.set(triangles[i2 + 6], triangles[i2 + 7], triangles[i2 + 8]), tmp);
            if (result) {
                float dist = ray.origin.dst2(tmp);
                if (dist < min_dist) {
                    min_dist = dist;
                    best.set(tmp);
                    hit = true;
                }
            }
        }
        if (!hit) {
            return false;
        }
        if (intersection2 != null) {
            intersection2.set(best);
            return true;
        }
        return true;
    }

    public static boolean intersectRayTriangles(Ray ray, float[] vertices, short[] indices, int vertexSize, Vector3 intersection2) {
        float min_dist = Float.MAX_VALUE;
        boolean hit = false;
        if (indices.length % 3 != 0) {
            throw new RuntimeException("triangle list size is not a multiple of 3");
        }
        for (int i2 = 0; i2 < indices.length; i2 += 3) {
            int i1 = indices[i2] * vertexSize;
            int i22 = indices[i2 + 1] * vertexSize;
            int i3 = indices[i2 + 2] * vertexSize;
            boolean result = intersectRayTriangle(ray, tmp1.set(vertices[i1], vertices[i1 + 1], vertices[i1 + 2]), tmp2.set(vertices[i22], vertices[i22 + 1], vertices[i22 + 2]), tmp3.set(vertices[i3], vertices[i3 + 1], vertices[i3 + 2]), tmp);
            if (result) {
                float dist = ray.origin.dst2(tmp);
                if (dist < min_dist) {
                    min_dist = dist;
                    best.set(tmp);
                    hit = true;
                }
            }
        }
        if (!hit) {
            return false;
        }
        if (intersection2 != null) {
            intersection2.set(best);
            return true;
        }
        return true;
    }

    public static boolean intersectRayTriangles(Ray ray, List<Vector3> triangles, Vector3 intersection2) {
        float min_dist = Float.MAX_VALUE;
        boolean hit = false;
        if (triangles.size() % 3 != 0) {
            throw new RuntimeException("triangle list size is not a multiple of 3");
        }
        for (int i2 = 0; i2 < triangles.size(); i2 += 3) {
            boolean result = intersectRayTriangle(ray, triangles.get(i2), triangles.get(i2 + 1), triangles.get(i2 + 2), tmp);
            if (result) {
                float dist = ray.origin.dst2(tmp);
                if (dist < min_dist) {
                    min_dist = dist;
                    best.set(tmp);
                    hit = true;
                }
            }
        }
        if (!hit) {
            return false;
        }
        if (intersection2 != null) {
            intersection2.set(best);
            return true;
        }
        return true;
    }

    public static boolean intersectBoundsPlaneFast(BoundingBox box, Plane plane) {
        return intersectBoundsPlaneFast(box.getCenter(tmp1), box.getDimensions(tmp2).scl(0.5f), plane.normal, plane.d);
    }

    public static boolean intersectBoundsPlaneFast(Vector3 center, Vector3 halfDimensions, Vector3 normal, float distance) {
        float radius = (halfDimensions.x * Math.abs(normal.x)) + (halfDimensions.y * Math.abs(normal.y)) + (halfDimensions.z * Math.abs(normal.z));
        float s2 = normal.dot(center) - distance;
        return Math.abs(s2) <= radius;
    }

    public static boolean intersectLines(Vector2 p1, Vector2 p2, Vector2 p3, Vector2 p4, Vector2 intersection2) {
        float x1 = p1.x;
        float y1 = p1.y;
        float x2 = p2.x;
        float y2 = p2.y;
        float x3 = p3.x;
        float y3 = p3.y;
        float x4 = p4.x;
        float y4 = p4.y;
        float d = ((y4 - y3) * (x2 - x1)) - ((x4 - x3) * (y2 - y1));
        if (d == 0.0f) {
            return false;
        }
        if (intersection2 != null) {
            float ua = (((x4 - x3) * (y1 - y3)) - ((y4 - y3) * (x1 - x3))) / d;
            intersection2.set(((x2 - x1) * ua) + x1, y1 + ((y2 - y1) * ua));
            return true;
        }
        return true;
    }

    public static boolean intersectLines(float x1, float y1, float x2, float y2, float x3, float y3, float x4, float y4, Vector2 intersection2) {
        float d = ((y4 - y3) * (x2 - x1)) - ((x4 - x3) * (y2 - y1));
        if (d == 0.0f) {
            return false;
        }
        if (intersection2 != null) {
            float ua = (((x4 - x3) * (y1 - y3)) - ((y4 - y3) * (x1 - x3))) / d;
            intersection2.set(((x2 - x1) * ua) + x1, ((y2 - y1) * ua) + y1);
            return true;
        }
        return true;
    }

    public static boolean intersectLinePolygon(Vector2 p1, Vector2 p2, Polygon polygon) {
        float[] vertices = polygon.getTransformedVertices();
        float x1 = p1.x;
        float y1 = p1.y;
        float x2 = p2.x;
        float y2 = p2.y;
        int n = vertices.length;
        float x3 = vertices[n - 2];
        float y3 = vertices[n - 1];
        for (int i2 = 0; i2 < n; i2 += 2) {
            float x4 = vertices[i2];
            float y4 = vertices[i2 + 1];
            float d = ((y4 - y3) * (x2 - x1)) - ((x4 - x3) * (y2 - y1));
            if (d != 0.0f) {
                float yd = y1 - y3;
                float xd = x1 - x3;
                float ua = (((x4 - x3) * yd) - ((y4 - y3) * xd)) / d;
                if (ua >= 0.0f && ua <= 1.0f) {
                    return true;
                }
            }
            x3 = x4;
            y3 = y4;
        }
        return false;
    }

    public static boolean intersectRectangles(Rectangle rectangle1, Rectangle rectangle2, Rectangle intersection2) {
        if (rectangle1.overlaps(rectangle2)) {
            intersection2.x = Math.max(rectangle1.x, rectangle2.x);
            intersection2.width = Math.min(rectangle1.x + rectangle1.width, rectangle2.x + rectangle2.width) - intersection2.x;
            intersection2.y = Math.max(rectangle1.y, rectangle2.y);
            intersection2.height = Math.min(rectangle1.y + rectangle1.height, rectangle2.y + rectangle2.height) - intersection2.y;
            return true;
        }
        return false;
    }

    public static boolean intersectSegmentRectangle(float startX, float startY, float endX, float endY, Rectangle rectangle) {
        float rectangleEndX = rectangle.x + rectangle.width;
        float rectangleEndY = rectangle.y + rectangle.height;
        if (intersectSegments(startX, startY, endX, endY, rectangle.x, rectangle.y, rectangle.x, rectangleEndY, null) || intersectSegments(startX, startY, endX, endY, rectangle.x, rectangle.y, rectangleEndX, rectangle.y, null) || intersectSegments(startX, startY, endX, endY, rectangleEndX, rectangle.y, rectangleEndX, rectangleEndY, null) || intersectSegments(startX, startY, endX, endY, rectangle.x, rectangleEndY, rectangleEndX, rectangleEndY, null)) {
            return true;
        }
        return rectangle.contains(startX, startY);
    }

    public static boolean intersectSegmentRectangle(Vector2 start2, Vector2 end, Rectangle rectangle) {
        return intersectSegmentRectangle(start2.x, start2.y, end.x, end.y, rectangle);
    }

    public static boolean intersectSegmentPolygon(Vector2 p1, Vector2 p2, Polygon polygon) {
        float[] vertices = polygon.getTransformedVertices();
        float x1 = p1.x;
        float y1 = p1.y;
        float x2 = p2.x;
        float y2 = p2.y;
        int n = vertices.length;
        float x3 = vertices[n - 2];
        float y3 = vertices[n - 1];
        for (int i2 = 0; i2 < n; i2 += 2) {
            float x4 = vertices[i2];
            float y4 = vertices[i2 + 1];
            float d = ((y4 - y3) * (x2 - x1)) - ((x4 - x3) * (y2 - y1));
            if (d != 0.0f) {
                float yd = y1 - y3;
                float xd = x1 - x3;
                float ua = (((x4 - x3) * yd) - ((y4 - y3) * xd)) / d;
                if (ua >= 0.0f && ua <= 1.0f) {
                    float ub = (((x2 - x1) * yd) - ((y2 - y1) * xd)) / d;
                    if (ub >= 0.0f && ub <= 1.0f) {
                        return true;
                    }
                }
            }
            x3 = x4;
            y3 = y4;
        }
        return false;
    }

    public static boolean intersectSegments(Vector2 p1, Vector2 p2, Vector2 p3, Vector2 p4, Vector2 intersection2) {
        float x1 = p1.x;
        float y1 = p1.y;
        float x2 = p2.x;
        float y2 = p2.y;
        float x3 = p3.x;
        float y3 = p3.y;
        float x4 = p4.x;
        float y4 = p4.y;
        float d = ((y4 - y3) * (x2 - x1)) - ((x4 - x3) * (y2 - y1));
        if (d == 0.0f) {
            return false;
        }
        float yd = y1 - y3;
        float xd = x1 - x3;
        float ua = (((x4 - x3) * yd) - ((y4 - y3) * xd)) / d;
        if (ua < 0.0f || ua > 1.0f) {
            return false;
        }
        float ub = (((x2 - x1) * yd) - ((y2 - y1) * xd)) / d;
        if (ub < 0.0f || ub > 1.0f) {
            return false;
        }
        if (intersection2 != null) {
            intersection2.set(((x2 - x1) * ua) + x1, ((y2 - y1) * ua) + y1);
            return true;
        }
        return true;
    }

    public static boolean intersectSegments(float x1, float y1, float x2, float y2, float x3, float y3, float x4, float y4, Vector2 intersection2) {
        float d = ((y4 - y3) * (x2 - x1)) - ((x4 - x3) * (y2 - y1));
        if (d == 0.0f) {
            return false;
        }
        float yd = y1 - y3;
        float xd = x1 - x3;
        float ua = (((x4 - x3) * yd) - ((y4 - y3) * xd)) / d;
        if (ua < 0.0f || ua > 1.0f) {
            return false;
        }
        float ub = (((x2 - x1) * yd) - ((y2 - y1) * xd)) / d;
        if (ub < 0.0f || ub > 1.0f) {
            return false;
        }
        if (intersection2 != null) {
            intersection2.set(((x2 - x1) * ua) + x1, ((y2 - y1) * ua) + y1);
            return true;
        }
        return true;
    }

    static float det(float a, float b, float c, float d) {
        return (a * d) - (b * c);
    }

    static double detd(double a, double b, double c, double d) {
        return (a * d) - (b * c);
    }

    public static boolean overlaps(Circle c1, Circle c2) {
        return c1.overlaps(c2);
    }

    public static boolean overlaps(Rectangle r1, Rectangle r2) {
        return r1.overlaps(r2);
    }

    public static boolean overlaps(Circle c, Rectangle r) {
        float closestX = c.x;
        float closestY = c.y;
        if (c.x < r.x) {
            closestX = r.x;
        } else if (c.x > r.x + r.width) {
            closestX = r.x + r.width;
        }
        if (c.y < r.y) {
            closestY = r.y;
        } else if (c.y > r.y + r.height) {
            closestY = r.y + r.height;
        }
        float closestX2 = closestX - c.x;
        float closestY2 = closestY - c.y;
        return (closestX2 * closestX2) + (closestY2 * closestY2) < c.radius * c.radius;
    }

    public static boolean overlapConvexPolygons(Polygon p1, Polygon p2) {
        return overlapConvexPolygons(p1, p2, (MinimumTranslationVector) null);
    }

    public static boolean overlapConvexPolygons(Polygon p1, Polygon p2, MinimumTranslationVector mtv) {
        return overlapConvexPolygons(p1.getTransformedVertices(), p2.getTransformedVertices(), mtv);
    }

    public static boolean overlapConvexPolygons(float[] verts1, float[] verts2, MinimumTranslationVector mtv) {
        return overlapConvexPolygons(verts1, 0, verts1.length, verts2, 0, verts2.length, mtv);
    }

    public static boolean overlapConvexPolygons(float[] verts1, int offset1, int count1, float[] verts2, int offset2, int count2, MinimumTranslationVector mtv) {
        if (mtv != null) {
            mtv.depth = Float.MAX_VALUE;
            mtv.normal.setZero();
        }
        boolean overlaps = overlapsOnAxisOfShape(verts2, offset2, count2, verts1, offset1, count1, mtv, true);
        if (overlaps) {
            overlaps = overlapsOnAxisOfShape(verts1, offset1, count1, verts2, offset2, count2, mtv, false);
        }
        if (!overlaps) {
            if (mtv != null) {
                mtv.depth = 0.0f;
                mtv.normal.setZero();
                return false;
            }
            return false;
        }
        return true;
    }

    private static boolean overlapsOnAxisOfShape(float[] verts1, int offset1, int count1, float[] verts2, int offset2, int count2, MinimumTranslationVector mtv, boolean shapesShifted) {
        float axisX;
        float axisY;
        int endB;
        float mins;
        float maxs;
        float x1;
        float axisY2;
        int endA = offset1 + count1;
        int endB2 = offset2 + count2;
        int i2 = offset1;
        while (i2 < endA) {
            float x12 = verts1[i2];
            float y1 = verts1[i2 + 1];
            float x2 = verts1[(i2 + 2) % count1];
            float y2 = verts1[(i2 + 3) % count1];
            float len = (float) Math.sqrt((axisX * axisX) + (axisY * axisY));
            float axisX2 = (y1 - y2) / len;
            float axisY3 = (-(x12 - x2)) / len;
            float minA = Float.MAX_VALUE;
            float maxA = -3.4028235E38f;
            for (int v = offset1; v < endA; v += 2) {
                float p2 = (verts1[v] * axisX2) + (verts1[v + 1] * axisY3);
                minA = Math.min(minA, p2);
                maxA = Math.max(maxA, p2);
            }
            float maxB = -3.4028235E38f;
            float minB = Float.MAX_VALUE;
            int v3 = offset2;
            while (v3 < endB2) {
                int endA2 = endA;
                float p3 = (verts2[v3] * axisX2) + (verts2[v3 + 1] * axisY3);
                minB = Math.min(minB, p3);
                maxB = Math.max(maxB, p3);
                v3 += 2;
                endA = endA2;
            }
            int endA3 = endA;
            int v4 = (maxA > minB ? 1 : (maxA == minB ? 0 : -1));
            if (v4 >= 0 && maxB >= minA) {
                if (mtv == null) {
                    endB = endB2;
                } else {
                    float o = Math.min(maxA, maxB) - Math.max(minA, minB);
                    boolean aContainsB = minA < minB && maxA > maxB;
                    boolean bContainsA = minB < minA && maxB > maxA;
                    if (!aContainsB && !bContainsA) {
                        endB = endB2;
                        mins = 0.0f;
                        maxs = 0.0f;
                    } else {
                        mins = Math.abs(minA - minB);
                        endB = endB2;
                        maxs = Math.abs(maxA - maxB);
                        o += Math.min(mins, maxs);
                    }
                    float maxB2 = mtv.depth;
                    if (maxB2 > o) {
                        mtv.depth = o;
                        if (shapesShifted) {
                            boolean condition = minA < minB;
                            x1 = condition ? axisX2 : -axisX2;
                            axisY2 = condition ? axisY3 : -axisY3;
                        } else {
                            boolean condition2 = minA > minB;
                            x1 = condition2 ? axisX2 : -axisX2;
                            axisY2 = condition2 ? axisY3 : -axisY3;
                        }
                        if (aContainsB || bContainsA) {
                            boolean condition3 = mins > maxs;
                            x1 = condition3 ? x1 : -x1;
                            axisY2 = condition3 ? axisY2 : -axisY2;
                        }
                        mtv.normal.set(x1, axisY2);
                    }
                }
                i2 += 2;
                endA = endA3;
                endB2 = endB;
            }
            return false;
        }
        return true;
    }

    public static void splitTriangle(float[] triangle, Plane plane, SplitTriangle split) {
        boolean r3;
        boolean r32;
        int stride = triangle.length / 3;
        boolean r1 = plane.testPoint(triangle[0], triangle[1], triangle[2]) == Plane.PlaneSide.Back;
        boolean r2 = plane.testPoint(triangle[stride + 0], triangle[stride + 1], triangle[stride + 2]) == Plane.PlaneSide.Back;
        boolean r33 = plane.testPoint(triangle[(stride * 2) + 0], triangle[(stride * 2) + 1], triangle[(stride * 2) + 2]) == Plane.PlaneSide.Back;
        split.reset();
        if (r1 == r2 && r2 == r33) {
            split.total = 1;
            if (r1) {
                split.numBack = 1;
                System.arraycopy(triangle, 0, split.back, 0, triangle.length);
                return;
            }
            split.numFront = 1;
            System.arraycopy(triangle, 0, split.front, 0, triangle.length);
            return;
        }
        split.total = 3;
        split.numFront = (r1 ? 0 : 1) + (r2 ? 0 : 1) + (r33 ? 0 : 1);
        split.numBack = split.total - split.numFront;
        split.setSide(!r1);
        if (r1 == r2) {
            r3 = r33;
            split.add(triangle, 0, stride);
        } else {
            r3 = r33;
            splitEdge(triangle, 0, stride, stride, plane, split.edgeSplit, 0);
            split.add(triangle, 0, stride);
            split.add(split.edgeSplit, 0, stride);
            split.setSide(!split.getSide());
            split.add(split.edgeSplit, 0, stride);
        }
        int second = stride + stride;
        boolean r34 = r3;
        if (r2 != r34) {
            r32 = r34;
            splitEdge(triangle, stride, second, stride, plane, split.edgeSplit, 0);
            split.add(triangle, stride, stride);
            split.add(split.edgeSplit, 0, stride);
            split.setSide(!split.getSide());
            split.add(split.edgeSplit, 0, stride);
        } else {
            r32 = r34;
            split.add(triangle, stride, stride);
        }
        int first = stride + stride;
        if (r32 == r1) {
            split.add(triangle, first, stride);
        } else {
            splitEdge(triangle, first, 0, stride, plane, split.edgeSplit, 0);
            split.add(triangle, first, stride);
            split.add(split.edgeSplit, 0, stride);
            split.setSide(!split.getSide());
            split.add(split.edgeSplit, 0, stride);
        }
        if (split.numFront == 2) {
            System.arraycopy(split.front, stride * 2, split.front, stride * 3, stride * 2);
            System.arraycopy(split.front, 0, split.front, stride * 5, stride);
            return;
        }
        System.arraycopy(split.back, stride * 2, split.back, stride * 3, stride * 2);
        System.arraycopy(split.back, 0, split.back, stride * 5, stride);
    }

    private static void splitEdge(float[] vertices, int s2, int e2, int stride, Plane plane, float[] split, int offset) {
        float t = intersectLinePlane(vertices[s2], vertices[s2 + 1], vertices[s2 + 2], vertices[e2], vertices[e2 + 1], vertices[e2 + 2], plane, intersection);
        split[offset + 0] = intersection.x;
        split[offset + 1] = intersection.y;
        split[offset + 2] = intersection.z;
        for (int i2 = 3; i2 < stride; i2++) {
            float a = vertices[s2 + i2];
            float b = vertices[e2 + i2];
            split[offset + i2] = ((b - a) * t) + a;
        }
    }

    /* loaded from: classes.dex */
    public static class SplitTriangle {
        public float[] back;
        float[] edgeSplit;
        public float[] front;
        public int numBack;
        public int numFront;
        public int total;
        boolean frontCurrent = false;
        int frontOffset = 0;
        int backOffset = 0;

        public SplitTriangle(int numAttributes) {
            this.front = new float[numAttributes * 3 * 2];
            this.back = new float[numAttributes * 3 * 2];
            this.edgeSplit = new float[numAttributes];
        }

        public String toString() {
            return "SplitTriangle [front=" + Arrays.toString(this.front) + ", back=" + Arrays.toString(this.back) + ", numFront=" + this.numFront + ", numBack=" + this.numBack + ", total=" + this.total + "]";
        }

        void setSide(boolean front) {
            this.frontCurrent = front;
        }

        boolean getSide() {
            return this.frontCurrent;
        }

        void add(float[] vertex, int offset, int stride) {
            if (this.frontCurrent) {
                System.arraycopy(vertex, offset, this.front, this.frontOffset, stride);
                this.frontOffset += stride;
                return;
            }
            System.arraycopy(vertex, offset, this.back, this.backOffset, stride);
            this.backOffset += stride;
        }

        void reset() {
            this.frontCurrent = false;
            this.frontOffset = 0;
            this.backOffset = 0;
            this.numFront = 0;
            this.numBack = 0;
            this.total = 0;
        }
    }
}