package com.kotcrab.vis.ui.util.adapter;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.utils.Array;
import java.util.Comparator;

/* loaded from: classes.dex */
public abstract class ArrayAdapter<ItemT, ViewT extends Actor> extends AbstractListAdapter<ItemT, ViewT> {
    private Array<ItemT> array;

    public ArrayAdapter(Array<ItemT> array) {
        this.array = array;
    }

    @Override // com.kotcrab.vis.ui.util.adapter.ListAdapter
    public int indexOf(ItemT item) {
        return this.array.indexOf(item, true);
    }

    @Override // com.kotcrab.vis.ui.util.adapter.ListAdapter
    public int size() {
        return this.array.size;
    }

    @Override // com.kotcrab.vis.ui.util.adapter.ListAdapter
    public ItemT get(int index) {
        return this.array.get(index);
    }

    @Override // com.kotcrab.vis.ui.util.adapter.ListAdapter
    public void add(ItemT element) {
        this.array.add(element);
        itemAdded(element);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.kotcrab.vis.ui.util.adapter.AbstractListAdapter
    public void sort(Comparator<ItemT> comparator) {
        this.array.sort(comparator);
    }

    @Override // com.kotcrab.vis.ui.util.adapter.ListAdapter
    public Iterable<ItemT> iterable() {
        return this.array;
    }

    public void addAll(Array<? extends ItemT> array) {
        this.array.addAll(array);
        itemsChanged();
    }

    public void addAll(Array<? extends ItemT> array, int start, int count) {
        this.array.addAll(array, start, count);
        itemsChanged();
    }

    public void addAll(ItemT... array) {
        this.array.addAll(array);
        itemsChanged();
    }

    public void addAll(ItemT[] array, int start, int count) {
        this.array.addAll(array, start, count);
        itemsChanged();
    }

    public void set(int index, ItemT value) {
        this.array.set(index, value);
        itemsChanged();
    }

    public void insert(int index, ItemT value) {
        this.array.insert(index, value);
        itemsChanged();
    }

    public void swap(int first, int second) {
        this.array.swap(first, second);
        itemsChanged();
    }

    public boolean removeValue(ItemT value, boolean identity) {
        boolean res = this.array.removeValue(value, identity);
        if (res) {
            itemRemoved(value);
        }
        return res;
    }

    public ItemT removeIndex(int index) {
        ItemT item = this.array.removeIndex(index);
        if (item != null) {
            itemRemoved(item);
        }
        return item;
    }

    public void removeRange(int start, int end) {
        this.array.removeRange(start, end);
        itemsChanged();
    }

    public boolean removeAll(Array<? extends ItemT> array, boolean identity) {
        boolean res = this.array.removeAll(array, identity);
        itemsChanged();
        return res;
    }

    public void clear() {
        this.array.clear();
        itemsChanged();
    }

    public void shuffle() {
        this.array.shuffle();
        itemsChanged();
    }

    public void reverse() {
        this.array.reverse();
        itemsChanged();
    }

    public ItemT pop() {
        ItemT item = this.array.pop();
        itemsChanged();
        return item;
    }
}