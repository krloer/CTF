package com.kotcrab.vis.ui.util.adapter;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.widget.VisLabel;
import com.kotcrab.vis.ui.widget.VisTable;

/* loaded from: classes.dex */
public class SimpleListAdapter<ItemT> extends ArrayAdapter<ItemT, VisTable> {
    private final SimpleListAdapterStyle style;

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.kotcrab.vis.ui.util.adapter.CachedItemAdapter
    protected /* bridge */ /* synthetic */ Actor createView(Object obj) {
        return createView((SimpleListAdapter<ItemT>) obj);
    }

    public SimpleListAdapter(Array<ItemT> array) {
        this(array, "default");
    }

    public SimpleListAdapter(Array<ItemT> array, String styleName) {
        this(array, (SimpleListAdapterStyle) VisUI.getSkin().get(styleName, SimpleListAdapterStyle.class));
    }

    public SimpleListAdapter(Array<ItemT> array, SimpleListAdapterStyle style) {
        super(array);
        this.style = style;
    }

    @Override // com.kotcrab.vis.ui.util.adapter.CachedItemAdapter
    protected VisTable createView(ItemT item) {
        VisTable table = new VisTable();
        table.left();
        table.add((VisTable) new VisLabel(item.toString()));
        return table;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.kotcrab.vis.ui.util.adapter.AbstractListAdapter
    public void selectView(VisTable view) {
        view.setBackground(this.style.selection);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.kotcrab.vis.ui.util.adapter.AbstractListAdapter
    public void deselectView(VisTable view) {
        view.setBackground(this.style.background);
    }

    /* loaded from: classes.dex */
    public static class SimpleListAdapterStyle {
        public Drawable background;
        public Drawable selection;

        public SimpleListAdapterStyle() {
        }

        public SimpleListAdapterStyle(Drawable background, Drawable selection) {
            this.background = background;
            this.selection = selection;
        }

        public SimpleListAdapterStyle(SimpleListAdapterStyle style) {
            this.background = style.background;
            this.selection = style.selection;
        }
    }
}