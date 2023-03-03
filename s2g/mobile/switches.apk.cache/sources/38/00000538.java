package com.kotcrab.vis.ui.util.adapter;

import com.kotcrab.vis.ui.widget.ListView;
import com.kotcrab.vis.ui.widget.VisTable;

/* loaded from: classes.dex */
public interface ListAdapter<ItemT> {
    void add(ItemT itemt);

    void fillTable(VisTable visTable);

    ItemT get(int i);

    int indexOf(ItemT itemt);

    Iterable<ItemT> iterable();

    void setItemClickListener(ListView.ItemClickListener<ItemT> itemClickListener);

    void setListView(ListView<ItemT> listView, ListView.ListAdapterListener listAdapterListener);

    int size();
}