package com.badlogic.gdx.utils;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class ComparableTimSort {
    private static final boolean DEBUG = false;
    private static final int INITIAL_TMP_STORAGE_LENGTH = 256;
    private static final int MIN_GALLOP = 7;
    private static final int MIN_MERGE = 32;
    private Object[] a;
    private int minGallop;
    private final int[] runBase;
    private final int[] runLen;
    private int stackSize;
    private Object[] tmp;
    private int tmpCount;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ComparableTimSort() {
        this.minGallop = 7;
        this.stackSize = 0;
        this.tmp = new Object[256];
        this.runBase = new int[40];
        this.runLen = new int[40];
    }

    public void doSort(Object[] a, int lo, int hi) {
        this.stackSize = 0;
        rangeCheck(a.length, lo, hi);
        int nRemaining = hi - lo;
        if (nRemaining < 2) {
            return;
        }
        if (nRemaining < 32) {
            int initRunLen = countRunAndMakeAscending(a, lo, hi);
            binarySort(a, lo, hi, lo + initRunLen);
            return;
        }
        this.a = a;
        this.tmpCount = 0;
        int minRun = minRunLength(nRemaining);
        do {
            int runLen = countRunAndMakeAscending(a, lo, hi);
            if (runLen < minRun) {
                int force = nRemaining <= minRun ? nRemaining : minRun;
                binarySort(a, lo, lo + force, lo + runLen);
                runLen = force;
            }
            pushRun(lo, runLen);
            mergeCollapse();
            lo += runLen;
            nRemaining -= runLen;
        } while (nRemaining != 0);
        mergeForceCollapse();
        this.a = null;
        Object[] tmp = this.tmp;
        int n = this.tmpCount;
        for (int i = 0; i < n; i++) {
            tmp[i] = null;
        }
    }

    private ComparableTimSort(Object[] a) {
        this.minGallop = 7;
        this.stackSize = 0;
        this.a = a;
        int len = a.length;
        Object[] newArray = new Object[len < 512 ? len >>> 1 : 256];
        this.tmp = newArray;
        int stackLen = len < 120 ? 5 : len < 1542 ? 10 : len < 119151 ? 19 : 40;
        this.runBase = new int[stackLen];
        this.runLen = new int[stackLen];
    }

    static void sort(Object[] a) {
        sort(a, 0, a.length);
    }

    static void sort(Object[] a, int lo, int hi) {
        rangeCheck(a.length, lo, hi);
        int nRemaining = hi - lo;
        if (nRemaining < 2) {
            return;
        }
        if (nRemaining < 32) {
            int initRunLen = countRunAndMakeAscending(a, lo, hi);
            binarySort(a, lo, hi, lo + initRunLen);
            return;
        }
        ComparableTimSort ts = new ComparableTimSort(a);
        int minRun = minRunLength(nRemaining);
        do {
            int runLen = countRunAndMakeAscending(a, lo, hi);
            if (runLen < minRun) {
                int force = nRemaining <= minRun ? nRemaining : minRun;
                binarySort(a, lo, lo + force, lo + runLen);
                runLen = force;
            }
            ts.pushRun(lo, runLen);
            ts.mergeCollapse();
            lo += runLen;
            nRemaining -= runLen;
        } while (nRemaining != 0);
        ts.mergeForceCollapse();
    }

    private static void binarySort(Object[] a, int lo, int hi, int start) {
        if (start == lo) {
            start++;
        }
        while (start < hi) {
            Comparable<Object> pivot = (Comparable) a[start];
            int left = lo;
            int right = start;
            while (left < right) {
                int mid = (left + right) >>> 1;
                if (pivot.compareTo(a[mid]) < 0) {
                    right = mid;
                } else {
                    left = mid + 1;
                }
            }
            int n = start - left;
            if (n != 1) {
                if (n == 2) {
                    a[left + 2] = a[left + 1];
                } else {
                    System.arraycopy(a, left, a, left + 1, n);
                    a[left] = pivot;
                    start++;
                }
            }
            a[left + 1] = a[left];
            a[left] = pivot;
            start++;
        }
    }

    private static int countRunAndMakeAscending(Object[] a, int lo, int hi) {
        int runHi = lo + 1;
        if (runHi == hi) {
            return 1;
        }
        int runHi2 = runHi + 1;
        if (((Comparable) a[runHi]).compareTo(a[lo]) < 0) {
            while (runHi2 < hi && ((Comparable) a[runHi2]).compareTo(a[runHi2 - 1]) < 0) {
                runHi2++;
            }
            reverseRange(a, lo, runHi2);
        } else {
            while (runHi2 < hi && ((Comparable) a[runHi2]).compareTo(a[runHi2 - 1]) >= 0) {
                runHi2++;
            }
        }
        return runHi2 - lo;
    }

    private static void reverseRange(Object[] a, int hi, int hi2) {
        int hi3 = hi2 - 1;
        while (hi < hi3) {
            Object t = a[hi];
            int lo = hi + 1;
            a[hi] = a[hi3];
            a[hi3] = t;
            hi3--;
            hi = lo;
        }
    }

    private static int minRunLength(int n) {
        int r = 0;
        while (n >= 32) {
            r |= n & 1;
            n >>= 1;
        }
        return n + r;
    }

    private void pushRun(int runBase, int runLen) {
        int[] iArr = this.runBase;
        int i = this.stackSize;
        iArr[i] = runBase;
        this.runLen[i] = runLen;
        this.stackSize = i + 1;
    }

    private void mergeCollapse() {
        while (true) {
            int i = this.stackSize;
            if (i > 1) {
                int n = i - 2;
                if (n > 0) {
                    int[] iArr = this.runLen;
                    if (iArr[n - 1] <= iArr[n] + iArr[n + 1]) {
                        if (iArr[n - 1] < iArr[n + 1]) {
                            n--;
                        }
                        mergeAt(n);
                    }
                }
                int[] iArr2 = this.runLen;
                if (iArr2[n] <= iArr2[n + 1]) {
                    mergeAt(n);
                } else {
                    return;
                }
            } else {
                return;
            }
        }
    }

    private void mergeForceCollapse() {
        while (true) {
            int i = this.stackSize;
            if (i > 1) {
                int n = i - 2;
                if (n > 0) {
                    int[] iArr = this.runLen;
                    if (iArr[n - 1] < iArr[n + 1]) {
                        n--;
                    }
                }
                mergeAt(n);
            } else {
                return;
            }
        }
    }

    private void mergeAt(int i) {
        int[] iArr = this.runBase;
        int base1 = iArr[i];
        int[] iArr2 = this.runLen;
        int len1 = iArr2[i];
        int base2 = iArr[i + 1];
        int len2 = iArr2[i + 1];
        iArr2[i] = len1 + len2;
        if (i == this.stackSize - 3) {
            iArr[i + 1] = iArr[i + 2];
            iArr2[i + 1] = iArr2[i + 2];
        }
        this.stackSize--;
        Object[] objArr = this.a;
        int k = gallopRight((Comparable) objArr[base2], objArr, base1, len1, 0);
        int base12 = base1 + k;
        int len12 = len1 - k;
        if (len12 == 0) {
            return;
        }
        Object[] objArr2 = this.a;
        int len22 = gallopLeft((Comparable) objArr2[(base12 + len12) - 1], objArr2, base2, len2, len2 - 1);
        if (len22 == 0) {
            return;
        }
        if (len12 <= len22) {
            mergeLo(base12, len12, base2, len22);
        } else {
            mergeHi(base12, len12, base2, len22);
        }
    }

    private static int gallopLeft(Comparable<Object> key, Object[] a, int base, int len, int hint) {
        int lastOfs;
        int ofs;
        int lastOfs2 = 0;
        int ofs2 = 1;
        if (key.compareTo(a[base + hint]) > 0) {
            int maxOfs = len - hint;
            while (ofs2 < maxOfs && key.compareTo(a[base + hint + ofs2]) > 0) {
                lastOfs2 = ofs2;
                ofs2 = (ofs2 << 1) + 1;
                if (ofs2 <= 0) {
                    ofs2 = maxOfs;
                }
            }
            if (ofs2 > maxOfs) {
                ofs2 = maxOfs;
            }
            lastOfs = lastOfs2 + hint;
            ofs = ofs2 + hint;
        } else {
            int maxOfs2 = hint + 1;
            while (ofs2 < maxOfs2 && key.compareTo(a[(base + hint) - ofs2]) <= 0) {
                lastOfs2 = ofs2;
                ofs2 = (ofs2 << 1) + 1;
                if (ofs2 <= 0) {
                    ofs2 = maxOfs2;
                }
            }
            if (ofs2 > maxOfs2) {
                ofs2 = maxOfs2;
            }
            int tmp = lastOfs2;
            lastOfs = hint - ofs2;
            ofs = hint - tmp;
        }
        int lastOfs3 = lastOfs + 1;
        while (lastOfs3 < ofs) {
            int m = ((ofs - lastOfs3) >>> 1) + lastOfs3;
            if (key.compareTo(a[base + m]) > 0) {
                lastOfs3 = m + 1;
            } else {
                ofs = m;
            }
        }
        return ofs;
    }

    private static int gallopRight(Comparable<Object> key, Object[] a, int base, int len, int hint) {
        int lastOfs;
        int ofs;
        int ofs2 = 1;
        int lastOfs2 = 0;
        if (key.compareTo(a[base + hint]) < 0) {
            int maxOfs = hint + 1;
            while (ofs2 < maxOfs && key.compareTo(a[(base + hint) - ofs2]) < 0) {
                lastOfs2 = ofs2;
                ofs2 = (ofs2 << 1) + 1;
                if (ofs2 <= 0) {
                    ofs2 = maxOfs;
                }
            }
            if (ofs2 > maxOfs) {
                ofs2 = maxOfs;
            }
            int tmp = lastOfs2;
            lastOfs = hint - ofs2;
            ofs = hint - tmp;
        } else {
            int maxOfs2 = len - hint;
            while (ofs2 < maxOfs2 && key.compareTo(a[base + hint + ofs2]) >= 0) {
                lastOfs2 = ofs2;
                ofs2 = (ofs2 << 1) + 1;
                if (ofs2 <= 0) {
                    ofs2 = maxOfs2;
                }
            }
            if (ofs2 > maxOfs2) {
                ofs2 = maxOfs2;
            }
            lastOfs = lastOfs2 + hint;
            ofs = ofs2 + hint;
        }
        int lastOfs3 = lastOfs + 1;
        while (lastOfs3 < ofs) {
            int m = ((ofs - lastOfs3) >>> 1) + lastOfs3;
            if (key.compareTo(a[base + m]) < 0) {
                ofs = m;
            } else {
                lastOfs3 = m + 1;
            }
        }
        return ofs;
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:0x0070, code lost:
        r12 = gallopRight((java.lang.Comparable) r2[r10], r3, r6, r1, 0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x0078, code lost:
        if (r12 == 0) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x007a, code lost:
        java.lang.System.arraycopy(r3, r6, r2, r9, r12);
        r14 = r9 + r12;
        r6 = r6 + r12;
        r1 = r1 - r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0081, code lost:
        if (r1 > 1) goto L24;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x0084, code lost:
        r14 = r9;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x0085, code lost:
        r9 = r14 + 1;
        r15 = r10 + 1;
        r2[r14] = r2[r10];
        r7 = r7 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x008f, code lost:
        if (r7 != 0) goto L26;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x0091, code lost:
        r14 = r9;
        r10 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0094, code lost:
        r13 = gallopLeft((java.lang.Comparable) r3[r6], r2, r15, r7, 0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x009c, code lost:
        if (r13 == 0) goto L63;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x009e, code lost:
        java.lang.System.arraycopy(r2, r15, r2, r9, r13);
        r14 = r9 + r13;
        r10 = r15 + r13;
        r7 = r7 - r13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00a6, code lost:
        if (r7 != 0) goto L30;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x00a9, code lost:
        r14 = r9;
        r10 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x00ab, code lost:
        r9 = r14 + 1;
        r15 = r6 + 1;
        r2[r14] = r3[r6];
        r1 = r1 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00b5, code lost:
        if (r1 != 1) goto L32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x00b7, code lost:
        r14 = r9;
        r6 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x00da, code lost:
        r11 = r11 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00dd, code lost:
        if (r12 < 7) goto L47;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x00df, code lost:
        r14 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x00e1, code lost:
        r14 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x00e2, code lost:
        if (r13 < 7) goto L46;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x00e4, code lost:
        r6 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x00e6, code lost:
        r6 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x00e8, code lost:
        if ((r6 | r14) != false) goto L39;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x00ea, code lost:
        if (r11 >= 0) goto L45;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x00ec, code lost:
        r11 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x00f3, code lost:
        r6 = r15;
     */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0070 A[EDGE_INSN: B:74:0x0070->B:24:0x0070 ?: BREAK  , SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private void mergeLo(int r17, int r18, int r19, int r20) {
        /*
            Method dump skipped, instructions count: 246
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.ComparableTimSort.mergeLo(int, int, int, int):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0080, code lost:
        r13 = r7 - gallopRight((java.lang.Comparable) r5[r9], r4, r18, r7, r7 - 1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x008c, code lost:
        if (r13 == 0) goto L40;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x008e, code lost:
        r6 = r11 - r13;
        r12 = r12 - r13;
        r7 = r7 - r13;
        java.lang.System.arraycopy(r4, r12 + 1, r4, r6 + 1, r13);
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x0099, code lost:
        if (r7 != 0) goto L24;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x009b, code lost:
        r8 = r10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x009d, code lost:
        r11 = r6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x009e, code lost:
        r6 = r11 - 1;
        r15 = r9 - 1;
        r4[r11] = r5[r9];
        r3 = r3 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x00a8, code lost:
        if (r3 != r8) goto L42;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x00aa, code lost:
        r8 = r10;
        r9 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x00ad, code lost:
        r14 = r3 - gallopLeft((java.lang.Comparable) r4[r12], r5, 0, r3, r3 - 1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00ba, code lost:
        if (r14 == 0) goto L68;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x00bc, code lost:
        r6 = r6 - r14;
        r9 = r15 - r14;
        r3 = r3 - r14;
        java.lang.System.arraycopy(r5, r9 + 1, r4, r6 + 1, r14);
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00c8, code lost:
        if (r3 > 1) goto L46;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00ca, code lost:
        r8 = r10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x00cc, code lost:
        r9 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x00cd, code lost:
        r11 = r6 - 1;
        r8 = r12 - 1;
        r4[r6] = r4[r12];
        r7 = r7 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x00d7, code lost:
        if (r7 != 0) goto L48;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00d9, code lost:
        r12 = r8;
        r8 = r10;
        r6 = r11;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x0107, code lost:
        r10 = r10 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x010c, code lost:
        if (r13 < 7) goto L63;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x010e, code lost:
        r16 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0111, code lost:
        r16 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x0113, code lost:
        if (r14 < 7) goto L62;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x0115, code lost:
        r12 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x0117, code lost:
        r12 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x011a, code lost:
        if ((r16 | r12) != false) goto L55;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x011c, code lost:
        if (r10 >= 0) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x011e, code lost:
        r10 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x0126, code lost:
        r12 = r8;
        r8 = 1;
     */
    /* JADX WARN: Removed duplicated region for block: B:66:0x012a A[LOOP:1: B:11:0x0043->B:66:0x012a, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0080 A[EDGE_INSN: B:75:0x0080->B:23:0x0080 ?: BREAK  , SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private void mergeHi(int r18, int r19, int r20, int r21) {
        /*
            Method dump skipped, instructions count: 303
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.ComparableTimSort.mergeHi(int, int, int, int):void");
    }

    private Object[] ensureCapacity(int minCapacity) {
        int newSize;
        this.tmpCount = Math.max(this.tmpCount, minCapacity);
        if (this.tmp.length < minCapacity) {
            int newSize2 = minCapacity | (minCapacity >> 1);
            int newSize3 = newSize2 | (newSize2 >> 2);
            int newSize4 = newSize3 | (newSize3 >> 4);
            int newSize5 = newSize4 | (newSize4 >> 8);
            int newSize6 = (newSize5 | (newSize5 >> 16)) + 1;
            if (newSize6 < 0) {
                newSize = minCapacity;
            } else {
                newSize = Math.min(newSize6, this.a.length >>> 1);
            }
            Object[] newArray = new Object[newSize];
            this.tmp = newArray;
        }
        return this.tmp;
    }

    private static void rangeCheck(int arrayLen, int fromIndex, int toIndex) {
        if (fromIndex > toIndex) {
            throw new IllegalArgumentException("fromIndex(" + fromIndex + ") > toIndex(" + toIndex + ")");
        } else if (fromIndex < 0) {
            throw new ArrayIndexOutOfBoundsException(fromIndex);
        } else {
            if (toIndex > arrayLen) {
                throw new ArrayIndexOutOfBoundsException(toIndex);
            }
        }
    }
}