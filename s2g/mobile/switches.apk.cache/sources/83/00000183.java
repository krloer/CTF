package com.badlogic.gdx.graphics.g3d.decals;

import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.IntMap;

/* loaded from: classes.dex */
public abstract class PluggableGroupStrategy implements GroupStrategy {
    private IntMap<GroupPlug> plugs = new IntMap<>();

    @Override // com.badlogic.gdx.graphics.g3d.decals.GroupStrategy
    public void beforeGroup(int group, Array<Decal> contents) {
        this.plugs.get(group).beforeGroup(contents);
    }

    @Override // com.badlogic.gdx.graphics.g3d.decals.GroupStrategy
    public void afterGroup(int group) {
        this.plugs.get(group).afterGroup();
    }

    public void plugIn(GroupPlug plug, int group) {
        this.plugs.put(group, plug);
    }

    public GroupPlug unPlug(int group) {
        return this.plugs.remove(group);
    }
}