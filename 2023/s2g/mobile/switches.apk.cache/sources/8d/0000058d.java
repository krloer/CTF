package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.adapter.ListAdapter;

/* loaded from: classes.dex */
public class ListView<ItemT> {
    private ListAdapter<ItemT> adapter;
    private ItemClickListener<ItemT> clickListener;
    private boolean dataInvalidated;
    private Actor footer;
    private Actor header;
    private VisTable itemsTable;
    private ListViewTable<ItemT> mainTable;
    private VisScrollPane scrollPane;
    private VisTable scrollTable;
    private UpdatePolicy updatePolicy;

    /* loaded from: classes.dex */
    public interface ItemClickListener<ItemT> {
        void clicked(ItemT itemt);
    }

    /* loaded from: classes.dex */
    public enum UpdatePolicy {
        ON_DRAW,
        IMMEDIATELY,
        MANUAL
    }

    public ListView(ListAdapter<ItemT> adapter) {
        this(adapter, "default");
    }

    public ListView(ListAdapter<ItemT> adapter, String styleName) {
        this(adapter, (ListViewStyle) VisUI.getSkin().get(styleName, ListViewStyle.class));
    }

    public ListView(ListAdapter<ItemT> adapter, ListViewStyle style) {
        this.updatePolicy = UpdatePolicy.IMMEDIATELY;
        this.dataInvalidated = false;
        if (style == null) {
            throw new IllegalArgumentException("style can't be null");
        }
        if (adapter == null) {
            throw new IllegalArgumentException("adapter can't be null");
        }
        this.adapter = adapter;
        this.mainTable = new ListViewTable<>();
        this.scrollTable = new VisTable();
        this.itemsTable = new VisTable();
        this.scrollPane = new VisScrollPane(this.scrollTable, style.scrollPaneStyle);
        this.scrollPane.setOverscroll(false, true);
        this.scrollPane.setFlickScroll(false);
        this.scrollPane.setFadeScrollBars(false);
        this.mainTable.add((ListViewTable<ItemT>) this.scrollPane).grow();
        adapter.setListView(this, new ListAdapterListener());
        rebuildView(true);
    }

    public void rebuildView() {
        rebuildView(true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void rebuildView(boolean full) {
        this.scrollTable.clearChildren();
        this.scrollTable.top();
        Actor actor = this.header;
        if (actor != null) {
            this.scrollTable.add((VisTable) actor).growX();
            this.scrollTable.row();
        }
        if (full) {
            this.itemsTable.clearChildren();
            this.adapter.fillTable(this.itemsTable);
        }
        this.scrollTable.add(this.itemsTable).growX();
        this.scrollTable.row();
        Actor actor2 = this.footer;
        if (actor2 != null) {
            this.scrollTable.add((VisTable) actor2).growX();
            this.scrollTable.row();
        }
    }

    public ListAdapter<ItemT> getAdapter() {
        return this.adapter;
    }

    public ListViewTable<ItemT> getMainTable() {
        return this.mainTable;
    }

    public VisScrollPane getScrollPane() {
        return this.scrollPane;
    }

    public void setItemClickListener(ItemClickListener<ItemT> listener) {
        this.clickListener = listener;
        this.adapter.setItemClickListener(listener);
    }

    public ItemClickListener<ItemT> getClickListener() {
        return this.clickListener;
    }

    public Actor getHeader() {
        return this.header;
    }

    public void setHeader(Actor header) {
        this.header = header;
        rebuildView(false);
    }

    public Actor getFooter() {
        return this.footer;
    }

    public void setFooter(Actor footer) {
        this.footer = footer;
        rebuildView(false);
    }

    public void setUpdatePolicy(UpdatePolicy updatePolicy) {
        this.updatePolicy = updatePolicy;
    }

    public UpdatePolicy getUpdatePolicy() {
        return this.updatePolicy;
    }

    /* loaded from: classes.dex */
    public class ListAdapterListener {
        public ListAdapterListener() {
        }

        public void invalidateDataSet() {
            if (ListView.this.updatePolicy == UpdatePolicy.IMMEDIATELY) {
                ListView.this.rebuildView(true);
            }
            if (ListView.this.updatePolicy == UpdatePolicy.ON_DRAW) {
                ListView.this.dataInvalidated = true;
            }
        }
    }

    /* loaded from: classes.dex */
    public static class ListViewTable<ItemT> extends VisTable {
        private ListView<ItemT> listView;

        private ListViewTable(ListView<ItemT> listView) {
            this.listView = listView;
        }

        @Override // com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
        public void draw(Batch batch, float parentAlpha) {
            if (((ListView) this.listView).updatePolicy == UpdatePolicy.ON_DRAW && ((ListView) this.listView).dataInvalidated) {
                this.listView.rebuildView(true);
            }
            super.draw(batch, parentAlpha);
        }

        public ListView<ItemT> getListView() {
            return this.listView;
        }
    }
}