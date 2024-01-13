package com.badlogic.gdx.math;

import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Pool;

/* loaded from: classes.dex */
public class Bresenham2 {
    private final Array<GridPoint2> points = new Array<>();
    private final Pool<GridPoint2> pool = new Pool<GridPoint2>() { // from class: com.badlogic.gdx.math.Bresenham2.1
        /* JADX INFO: Access modifiers changed from: protected */
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // com.badlogic.gdx.utils.Pool
        public GridPoint2 newObject() {
            return new GridPoint2();
        }
    };

    public Array<GridPoint2> line(GridPoint2 start, GridPoint2 end) {
        return line(start.x, start.y, end.x, end.y);
    }

    public Array<GridPoint2> line(int startX, int startY, int endX, int endY) {
        this.pool.freeAll(this.points);
        this.points.clear();
        return line(startX, startY, endX, endY, this.pool, this.points);
    }

    public Array<GridPoint2> line(int startX, int startY, int endX, int endY, Pool<GridPoint2> pool, Array<GridPoint2> output) {
        int w = endX - startX;
        int h = endY - startY;
        int dx1 = 0;
        int dy1 = 0;
        int dx2 = 0;
        int dy2 = 0;
        if (w < 0) {
            dx1 = -1;
            dx2 = -1;
        } else if (w > 0) {
            dx1 = 1;
            dx2 = 1;
        }
        if (h < 0) {
            dy1 = -1;
        } else if (h > 0) {
            dy1 = 1;
        }
        int longest = Math.abs(w);
        int shortest = Math.abs(h);
        if (longest < shortest) {
            longest = Math.abs(h);
            shortest = Math.abs(w);
            if (h < 0) {
                dy2 = -1;
            } else if (h > 0) {
                dy2 = 1;
            }
            dx2 = 0;
        }
        int shortest2 = shortest << 1;
        int longest2 = longest << 1;
        int startY2 = startY;
        int numerator = 0;
        int startX2 = startX;
        for (int i = 0; i <= longest; i++) {
            GridPoint2 point = pool.obtain();
            point.set(startX2, startY2);
            output.add(point);
            numerator += shortest2;
            if (numerator > longest) {
                numerator -= longest2;
                startX2 += dx1;
                startY2 += dy1;
            } else {
                startX2 += dx2;
                startY2 += dy2;
            }
        }
        return output;
    }
}