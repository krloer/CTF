package com.badlogic.gdx.utils;

import java.util.Comparator;

/* loaded from: classes.dex */
public class Select {
    private static Select instance;
    private QuickSelect quickSelect;

    public static Select instance() {
        if (instance == null) {
            instance = new Select();
        }
        return instance;
    }

    public <T> T select(T[] items, Comparator<T> comp, int kthLowest, int size) {
        int idx = selectIndex(items, comp, kthLowest, size);
        return items[idx];
    }

    public <T> int selectIndex(T[] items, Comparator<T> comp, int kthLowest, int size) {
        if (size < 1) {
            throw new GdxRuntimeException("cannot select from empty array (size < 1)");
        }
        if (kthLowest > size) {
            throw new GdxRuntimeException("Kth rank is larger than size. k: " + kthLowest + ", size: " + size);
        } else if (kthLowest == 1) {
            int idx = fastMin(items, comp, size);
            return idx;
        } else if (kthLowest == size) {
            int idx2 = fastMax(items, comp, size);
            return idx2;
        } else {
            if (this.quickSelect == null) {
                this.quickSelect = new QuickSelect();
            }
            int idx3 = this.quickSelect.select(items, comp, kthLowest, size);
            return idx3;
        }
    }

    private <T> int fastMin(T[] items, Comparator<T> comp, int size) {
        int lowestIdx = 0;
        for (int i = 1; i < size; i++) {
            int comparison = comp.compare(items[i], items[lowestIdx]);
            if (comparison < 0) {
                lowestIdx = i;
            }
        }
        return lowestIdx;
    }

    private <T> int fastMax(T[] items, Comparator<T> comp, int size) {
        int highestIdx = 0;
        for (int i = 1; i < size; i++) {
            int comparison = comp.compare(items[i], items[highestIdx]);
            if (comparison > 0) {
                highestIdx = i;
            }
        }
        return highestIdx;
    }
}