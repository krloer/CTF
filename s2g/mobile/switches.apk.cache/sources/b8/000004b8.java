package com.badlogic.gdx.utils;

import java.util.Comparator;

/* loaded from: classes.dex */
public class Sort {
    private static Sort instance;
    private ComparableTimSort comparableTimSort;
    private TimSort timSort;

    public <T extends Comparable> void sort(Array<T> a) {
        if (this.comparableTimSort == null) {
            this.comparableTimSort = new ComparableTimSort();
        }
        this.comparableTimSort.doSort(a.items, 0, a.size);
    }

    public void sort(Object[] a) {
        if (this.comparableTimSort == null) {
            this.comparableTimSort = new ComparableTimSort();
        }
        this.comparableTimSort.doSort(a, 0, a.length);
    }

    public void sort(Object[] a, int fromIndex, int toIndex) {
        if (this.comparableTimSort == null) {
            this.comparableTimSort = new ComparableTimSort();
        }
        this.comparableTimSort.doSort(a, fromIndex, toIndex);
    }

    public <T> void sort(Array<T> a, Comparator<? super T> c) {
        if (this.timSort == null) {
            this.timSort = new TimSort();
        }
        this.timSort.doSort(a.items, c, 0, a.size);
    }

    public <T> void sort(T[] a, Comparator<? super T> c) {
        if (this.timSort == null) {
            this.timSort = new TimSort();
        }
        this.timSort.doSort(a, c, 0, a.length);
    }

    public <T> void sort(T[] a, Comparator<? super T> c, int fromIndex, int toIndex) {
        if (this.timSort == null) {
            this.timSort = new TimSort();
        }
        this.timSort.doSort(a, c, fromIndex, toIndex);
    }

    public static Sort instance() {
        if (instance == null) {
            instance = new Sort();
        }
        return instance;
    }
}