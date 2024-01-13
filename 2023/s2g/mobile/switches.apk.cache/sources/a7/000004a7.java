package com.badlogic.gdx.utils;

import java.util.Comparator;

/* loaded from: classes.dex */
public class QuickSelect<T> {
    private T[] array;
    private Comparator<? super T> comp;

    /* JADX WARN: Multi-variable type inference failed */
    public int select(T[] items, Comparator<T> comp, int n, int size) {
        this.array = items;
        this.comp = comp;
        return recursiveSelect(0, size - 1, n);
    }

    private int partition(int left, int right, int pivot) {
        T pivotValue = this.array[pivot];
        swap(right, pivot);
        int storage = left;
        for (int i = left; i < right; i++) {
            if (this.comp.compare((Object) this.array[i], pivotValue) < 0) {
                swap(storage, i);
                storage++;
            }
        }
        swap(right, storage);
        return storage;
    }

    private int recursiveSelect(int left, int right, int k) {
        if (left == right) {
            return left;
        }
        int pivotIndex = medianOfThreePivot(left, right);
        int pivotNewIndex = partition(left, right, pivotIndex);
        int pivotDist = (pivotNewIndex - left) + 1;
        if (pivotDist == k) {
            return pivotNewIndex;
        }
        if (k < pivotDist) {
            int result = recursiveSelect(left, pivotNewIndex - 1, k);
            return result;
        }
        int result2 = pivotNewIndex + 1;
        return recursiveSelect(result2, right, k - pivotDist);
    }

    private int medianOfThreePivot(int leftIdx, int rightIdx) {
        T[] tArr = this.array;
        T left = tArr[leftIdx];
        int midIdx = (leftIdx + rightIdx) / 2;
        T mid = tArr[midIdx];
        T right = tArr[rightIdx];
        if (this.comp.compare(left, mid) > 0) {
            if (this.comp.compare(mid, right) > 0) {
                return midIdx;
            }
            if (this.comp.compare(left, right) > 0) {
                return rightIdx;
            }
            return leftIdx;
        } else if (this.comp.compare(left, right) > 0) {
            return leftIdx;
        } else {
            if (this.comp.compare(mid, right) > 0) {
                return rightIdx;
            }
            return midIdx;
        }
    }

    private void swap(int left, int right) {
        T[] tArr = this.array;
        T tmp = tArr[left];
        tArr[left] = tArr[right];
        tArr[right] = tmp;
    }
}