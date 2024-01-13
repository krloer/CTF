package com.badlogic.gdx.maps.objects;

import com.badlogic.gdx.maps.MapObject;
import com.badlogic.gdx.math.Polygon;

/* loaded from: classes.dex */
public class PolygonMapObject extends MapObject {
    private Polygon polygon;

    public Polygon getPolygon() {
        return this.polygon;
    }

    public void setPolygon(Polygon polygon) {
        this.polygon = polygon;
    }

    public PolygonMapObject() {
        this(new float[0]);
    }

    public PolygonMapObject(float[] vertices) {
        this.polygon = new Polygon(vertices);
    }

    public PolygonMapObject(Polygon polygon) {
        this.polygon = polygon;
    }
}