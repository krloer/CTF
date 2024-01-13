package com.kotcrab.vis.ui.util.adapter;

import com.badlogic.gdx.scenes.scene2d.Actor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;

/* loaded from: classes.dex */
public abstract class ArrayListAdapter<ItemT, ViewT extends Actor> extends AbstractListAdapter<ItemT, ViewT> {
    private ArrayList<ItemT> array;

    public ArrayListAdapter(ArrayList<ItemT> array) {
        this.array = array;
    }

    @Override // com.kotcrab.vis.ui.util.adapter.ListAdapter
    public Iterable<ItemT> iterable() {
        return this.array;
    }

    @Override // com.kotcrab.vis.ui.util.adapter.ListAdapter
    public int size() {
        return this.array.size();
    }

    @Override // com.kotcrab.vis.ui.util.adapter.ListAdapter
    public int indexOf(ItemT item) {
        return this.array.indexOf(item);
    }

    @Override // com.kotcrab.vis.ui.util.adapter.ListAdapter
    public void add(ItemT element) {
        this.array.add(element);
        itemAdded(element);
    }

    @Override // com.kotcrab.vis.ui.util.adapter.ListAdapter
    public ItemT get(int index) {
        return this.array.get(index);
    }

    @Override // com.kotcrab.vis.ui.util.adapter.AbstractListAdapter
    protected void sort(Comparator<ItemT> comparator) {
        Collections.sort(this.array, comparator);
    }

    public ItemT set(int index, ItemT element) {
        ItemT res = this.array.set(index, element);
        itemsChanged();
        return res;
    }

    public void add(int index, ItemT element) {
        this.array.add(index, element);
        itemAdded(element);
    }

    public ItemT remove(int index) {
        ItemT res = this.array.remove(index);
        if (res != null) {
            itemRemoved(res);
        }
        return res;
    }

    public boolean remove(ItemT item) {
        boolean res = this.array.remove(item);
        if (res) {
            itemRemoved(item);
        }
        return res;
    }

    public void clear() {
        this.array.clear();
        itemsChanged();
    }

    public boolean addAll(Collection<? extends ItemT> c) {
        boolean res = this.array.addAll(c);
        itemsChanged();
        return res;
    }

    public boolean addAll(int index, Collection<? extends ItemT> c) {
        boolean res = this.array.addAll(index, c);
        itemsChanged();
        return res;
    }

    public boolean removeAll(Collection<?> c) {
        boolean res = this.array.removeAll(c);
        itemsChanged();
        return res;
    }
}