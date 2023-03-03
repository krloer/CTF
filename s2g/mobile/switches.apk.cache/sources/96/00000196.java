package com.badlogic.gdx.graphics.g3d.model;

import com.badlogic.gdx.math.Quaternion;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class NodeAnimation {
    public Node node;
    public Array<NodeKeyframe<Vector3>> translation = null;
    public Array<NodeKeyframe<Quaternion>> rotation = null;
    public Array<NodeKeyframe<Vector3>> scaling = null;
}