package com.kotcrab.vis.ui.util.adapter;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.utils.ObjectMap;

/* loaded from: classes.dex */
public abstract class CachedItemAdapter<ItemT, ViewT extends Actor> implements ItemAdapter<ItemT> {
    private ObjectMap<ItemT, ViewT> views = new ObjectMap<>();

    protected abstract ViewT createView(ItemT itemt);

    protected abstract void updateView(ViewT viewt, ItemT itemt);

    @Override // com.kotcrab.vis.ui.util.adapter.ItemAdapter
    public final ViewT getView(ItemT item) {
        ViewT view = this.views.get(item);
        if (view == null) {
            view = createView(item);
            if (view == null) {
                throw new IllegalStateException("Returned view view can't be null");
            }
            this.views.put(item, view);
        } else {
            updateView(view, item);
        }
        return view;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ObjectMap<ItemT, ViewT> getViews() {
        return this.views;
    }
}