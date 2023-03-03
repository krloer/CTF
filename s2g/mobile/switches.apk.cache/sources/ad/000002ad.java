package com.badlogic.gdx.maps.objects;

import com.badlogic.gdx.maps.MapObject;
import com.badlogic.gdx.math.Circle;

/* loaded from: classes.dex */
public class CircleMapObject extends MapObject {
    private Circle circle;

    public Circle getCircle() {
        return this.circle;
    }

    public CircleMapObject() {
        this(0.0f, 0.0f, 1.0f);
    }

    public CircleMapObject(float x, float y, float radius) {
        this.circle = new Circle(x, y, radius);
    }
}