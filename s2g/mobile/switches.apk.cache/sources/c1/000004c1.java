package com.badlogic.gdx.utils;

import java.util.Arrays;
import java.util.Comparator;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class TimSort<T> {
    private static final boolean DEBUG = false;
    private static final int INITIAL_TMP_STORAGE_LENGTH = 256;
    private static final int MIN_GALLOP = 7;
    private static final int MIN_MERGE = 32;
    private T[] a;
    private Comparator<? super T> c;
    private int minGallop;
    private final int[] runBase;
    private final int[] runLen;
    private int stackSize;
    private T[] tmp;
    private int tmpCount;

    /* JADX INFO: Access modifiers changed from: package-private */
    public TimSort() {
        this.minGallop = 7;
        this.stackSize = 0;
        this.tmp = (T[]) new Object[256];
        this.runBase = new int[40];
        this.runLen = new int[40];
    }

    /* JADX WARN: Multi-variable type inference failed */
    public void doSort(T[] a, Comparator<T> c, int lo, int hi) {
        this.stackSize = 0;
        rangeCheck(a.length, lo, hi);
        int nRemaining = hi - lo;
        if (nRemaining < 2) {
            return;
        }
        if (nRemaining < 32) {
            int initRunLen = countRunAndMakeAscending(a, lo, hi, c);
            binarySort(a, lo, hi, lo + initRunLen, c);
            return;
        }
        this.a = a;
        this.c = c;
        this.tmpCount = 0;
        int minRun = minRunLength(nRemaining);
        do {
            int runLen = countRunAndMakeAscending(a, lo, hi, c);
            if (runLen < minRun) {
                int force = nRemaining <= minRun ? nRemaining : minRun;
                binarySort(a, lo, lo + force, lo + runLen, c);
                runLen = force;
            }
            pushRun(lo, runLen);
            mergeCollapse();
            lo += runLen;
            nRemaining -= runLen;
        } while (nRemaining != 0);
        mergeForceCollapse();
        this.a = null;
        this.c = null;
        T[] tmp = this.tmp;
        int n = this.tmpCount;
        for (int i = 0; i < n; i++) {
            tmp[i] = null;
        }
    }

    private TimSort(T[] a, Comparator<? super T> c) {
        this.minGallop = 7;
        this.stackSize = 0;
        this.a = a;
        this.c = c;
        int len = a.length;
        T[] newArray = (T[]) new Object[len < 512 ? len >>> 1 : 256];
        this.tmp = newArray;
        int stackLen = len < 120 ? 5 : len < 1542 ? 10 : len < 119151 ? 19 : 40;
        this.runBase = new int[stackLen];
        this.runLen = new int[stackLen];
    }

    static <T> void sort(T[] a, Comparator<? super T> c) {
        sort(a, 0, a.length, c);
    }

    static <T> void sort(T[] a, int lo, int hi, Comparator<? super T> c) {
        if (c == null) {
            Arrays.sort(a, lo, hi);
            return;
        }
        rangeCheck(a.length, lo, hi);
        int nRemaining = hi - lo;
        if (nRemaining < 2) {
            return;
        }
        if (nRemaining < 32) {
            int initRunLen = countRunAndMakeAscending(a, lo, hi, c);
            binarySort(a, lo, hi, lo + initRunLen, c);
            return;
        }
        TimSort<T> ts = new TimSort<>(a, c);
        int minRun = minRunLength(nRemaining);
        do {
            int runLen = countRunAndMakeAscending(a, lo, hi, c);
            if (runLen < minRun) {
                int force = nRemaining <= minRun ? nRemaining : minRun;
                binarySort(a, lo, lo + force, lo + runLen, c);
                runLen = force;
            }
            ts.pushRun(lo, runLen);
            ts.mergeCollapse();
            lo += runLen;
            nRemaining -= runLen;
        } while (nRemaining != 0);
        ts.mergeForceCollapse();
    }

    private static <T> void binarySort(T[] a, int lo, int hi, int start, Comparator<? super T> c) {
        if (start == lo) {
            start++;
        }
        while (start < hi) {
            T pivot = a[start];
            int left = lo;
            int right = start;
            while (left < right) {
                int mid = (left + right) >>> 1;
                if (c.compare(pivot, a[mid]) < 0) {
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

    private static <T> int countRunAndMakeAscending(T[] a, int lo, int hi, Comparator<? super T> c) {
        int runHi = lo + 1;
        if (runHi == hi) {
            return 1;
        }
        int runHi2 = runHi + 1;
        if (c.compare(a[runHi], a[lo]) < 0) {
            while (runHi2 < hi && c.compare(a[runHi2], a[runHi2 - 1]) < 0) {
                runHi2++;
            }
            reverseRange(a, lo, runHi2);
        } else {
            while (runHi2 < hi && c.compare(a[runHi2], a[runHi2 - 1]) >= 0) {
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

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0028, code lost:
        if (r1[r0 - 2] <= (r1[r0] + r1[r0 - 1])) goto L7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x002a, code lost:
        r1 = r5.runLen;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0034, code lost:
        if (r1[r0 - 1] >= r1[r0 + 1]) goto L12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:14:0x0036, code lost:
        r0 = r0 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:7:0x0016, code lost:
        if (r1[r0 - 1] > (r1[r0] + r1[r0 + 1])) goto L13;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private void mergeCollapse() {
        /*
            r5 = this;
        L0:
            int r0 = r5.stackSize
            r1 = 1
            if (r0 <= r1) goto L48
            int r0 = r0 + (-2)
            if (r0 < r1) goto L18
            int[] r1 = r5.runLen
            int r2 = r0 + (-1)
            r2 = r1[r2]
            r3 = r1[r0]
            int r4 = r0 + 1
            r1 = r1[r4]
            int r3 = r3 + r1
            if (r2 <= r3) goto L2a
        L18:
            r1 = 2
            if (r0 < r1) goto L39
            int[] r1 = r5.runLen
            int r2 = r0 + (-2)
            r2 = r1[r2]
            r3 = r1[r0]
            int r4 = r0 + (-1)
            r1 = r1[r4]
            int r3 = r3 + r1
            if (r2 > r3) goto L39
        L2a:
            int[] r1 = r5.runLen
            int r2 = r0 + (-1)
            r2 = r1[r2]
            int r3 = r0 + 1
            r1 = r1[r3]
            if (r2 >= r1) goto L44
            int r0 = r0 + (-1)
            goto L44
        L39:
            int[] r1 = r5.runLen
            r2 = r1[r0]
            int r3 = r0 + 1
            r1 = r1[r3]
            if (r2 <= r1) goto L44
            goto L48
        L44:
            r5.mergeAt(r0)
            goto L0
        L48:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.TimSort.mergeCollapse():void");
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
        T[] tArr = this.a;
        int k = gallopRight(tArr[base2], tArr, base1, len1, 0, this.c);
        int base12 = base1 + k;
        int len12 = len1 - k;
        if (len12 == 0) {
            return;
        }
        T[] tArr2 = this.a;
        int len22 = gallopLeft(tArr2[(base12 + len12) - 1], tArr2, base2, len2, len2 - 1, this.c);
        if (len22 == 0) {
            return;
        }
        if (len12 <= len22) {
            mergeLo(base12, len12, base2, len22);
        } else {
            mergeHi(base12, len12, base2, len22);
        }
    }

    private static <T> int gallopLeft(T key, T[] a, int base, int len, int hint, Comparator<? super T> c) {
        int lastOfs;
        int ofs;
        int lastOfs2 = 0;
        int ofs2 = 1;
        if (c.compare(key, a[base + hint]) > 0) {
            int maxOfs = len - hint;
            while (ofs2 < maxOfs && c.compare(key, a[base + hint + ofs2]) > 0) {
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
            while (ofs2 < maxOfs2 && c.compare(key, a[(base + hint) - ofs2]) <= 0) {
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
            if (c.compare(key, a[base + m]) > 0) {
                lastOfs3 = m + 1;
            } else {
                ofs = m;
            }
        }
        return ofs;
    }

    private static <T> int gallopRight(T key, T[] a, int base, int len, int hint, Comparator<? super T> c) {
        int lastOfs;
        int ofs;
        int ofs2 = 1;
        int lastOfs2 = 0;
        if (c.compare(key, a[base + hint]) < 0) {
            int maxOfs = hint + 1;
            while (ofs2 < maxOfs && c.compare(key, a[(base + hint) - ofs2]) < 0) {
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
            while (ofs2 < maxOfs2 && c.compare(key, a[base + hint + ofs2]) >= 0) {
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
            if (c.compare(key, a[base + m]) < 0) {
                ofs = m;
            } else {
                lastOfs3 = m + 1;
            }
        }
        return ofs;
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:0x0077, code lost:
        r16 = r3;
        r18 = r4;
        r9 = r6;
        r14 = r1;
        r13 = r2;
        r6 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x0082, code lost:
        r11 = r6;
        r15 = gallopRight(r7[r9], r8, r13, r14, 0, r12);
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x008e, code lost:
        if (r15 == 0) goto L41;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0090, code lost:
        java.lang.System.arraycopy(r8, r13, r7, r11, r15);
        r1 = r11 + r15;
        r2 = r13 + r15;
        r3 = r14 - r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x009a, code lost:
        if (r3 > 1) goto L26;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x009c, code lost:
        r14 = r3;
        r6 = r9;
        r3 = r16;
        r11 = r18;
        r10 = 1;
        r9 = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x00a6, code lost:
        r11 = r1;
        r13 = r2;
        r14 = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x00a9, code lost:
        r6 = r11 + 1;
        r5 = r9 + 1;
        r7[r11] = r7[r9];
        r9 = r16 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x00b3, code lost:
        if (r9 != 0) goto L43;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00b5, code lost:
        r3 = r9;
        r2 = r13;
        r11 = r18;
        r10 = 1;
        r9 = r6;
        r6 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x00bd, code lost:
        r11 = r6;
        r1 = gallopLeft(r8[r13], r7, r5, r9, 0, r12);
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00cb, code lost:
        if (r1 == 0) goto L70;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00cd, code lost:
        java.lang.System.arraycopy(r7, r5, r7, r11, r1);
        r2 = r11 + r1;
        r6 = r5 + r1;
        r3 = r9 - r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x00d6, code lost:
        if (r3 != 0) goto L47;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x00d8, code lost:
        r9 = r2;
        r2 = r13;
        r11 = r18;
        r10 = 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x00de, code lost:
        r11 = r2;
        r16 = r3;
        r9 = r6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00e3, code lost:
        r16 = r9;
        r9 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x00e6, code lost:
        r6 = r11 + 1;
        r2 = r13 + 1;
        r7[r11] = r8[r13];
        r14 = r14 - 1;
        r10 = 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x00f1, code lost:
        if (r14 != 1) goto L50;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x00f3, code lost:
        r3 = r16;
        r11 = r18;
        r19 = r9;
        r9 = r6;
        r6 = r19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x011d, code lost:
        r18 = r18 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0120, code lost:
        if (r15 < 7) goto L65;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x0122, code lost:
        r4 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x0124, code lost:
        r4 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x0125, code lost:
        if (r1 < 7) goto L64;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x0127, code lost:
        r3 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x0129, code lost:
        r3 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x012b, code lost:
        if ((r3 | r4) != false) goto L57;
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x012d, code lost:
        if (r18 >= 0) goto L63;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x012f, code lost:
        r18 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x013f, code lost:
        r13 = r2;
     */
    /* JADX WARN: Removed duplicated region for block: B:68:0x0147 A[LOOP:1: B:12:0x0038->B:68:0x0147, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0077 A[EDGE_INSN: B:77:0x0077->B:24:0x0077 ?: BREAK  , SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private void mergeLo(int r21, int r22, int r23, int r24) {
        /*
            Method dump skipped, instructions count: 334
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.TimSort.mergeLo(int, int, int, int):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0080, code lost:
        r17 = r2;
        r10 = r3;
        r19 = r5;
        r15 = r6;
        r16 = r7;
        r13 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x008c, code lost:
        r14 = r10 - gallopRight(r9[r13], r8, r24, r10, r10 - 1, r12);
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x009b, code lost:
        if (r14 == 0) goto L40;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x009d, code lost:
        r2 = r15 - r14;
        r7 = r16 - r14;
        r3 = r10 - r14;
        java.lang.System.arraycopy(r8, r7 + 1, r8, r2 + 1, r14);
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x00aa, code lost:
        if (r3 != 0) goto L25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x00ac, code lost:
        r10 = r2;
        r16 = r7;
        r2 = r17;
        r5 = r19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x00b5, code lost:
        r15 = r2;
        r10 = r3;
        r16 = r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x00b9, code lost:
        r20 = r15 - 1;
        r21 = r13 - 1;
        r8[r15] = r9[r13];
        r13 = r17 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x00c3, code lost:
        if (r13 != 1) goto L42;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x00c5, code lost:
        r3 = r10;
        r2 = r13;
        r5 = r19;
        r10 = r20;
        r13 = r21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00ce, code lost:
        r2 = r13 - gallopLeft(r8[r16], r9, 0, r13, r13 - 1, r12);
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x00dc, code lost:
        if (r2 == 0) goto L69;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00de, code lost:
        r3 = r20 - r2;
        r4 = r21 - r2;
        r5 = r13 - r2;
        java.lang.System.arraycopy(r9, r4 + 1, r8, r3 + 1, r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00eb, code lost:
        if (r5 > 1) goto L46;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x00ed, code lost:
        r13 = r4;
        r2 = r5;
        r5 = r19;
        r22 = r10;
        r10 = r3;
        r3 = r22;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x00f7, code lost:
        r13 = r4;
        r17 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x00fb, code lost:
        r17 = r13;
        r3 = r20;
        r13 = r21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x0101, code lost:
        r15 = r3 - 1;
        r4 = r16 - 1;
        r8[r3] = r8[r16];
        r10 = r10 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x010b, code lost:
        if (r10 != 0) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x010d, code lost:
        r16 = r4;
        r3 = r10;
        r10 = r15;
        r2 = r17;
        r5 = r19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x0140, code lost:
        r19 = r19 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x0144, code lost:
        if (r14 < 7) goto L64;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0146, code lost:
        r5 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x0148, code lost:
        r5 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x0149, code lost:
        if (r2 < 7) goto L63;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x014b, code lost:
        r3 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x014d, code lost:
        r3 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x014f, code lost:
        if ((r3 | r5) != false) goto L56;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x0151, code lost:
        if (r19 >= 0) goto L62;
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x0153, code lost:
        r19 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x0161, code lost:
        r16 = r4;
     */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0167 A[LOOP:1: B:11:0x0043->B:67:0x0167, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0080 A[EDGE_INSN: B:76:0x0080->B:23:0x0080 ?: BREAK  , SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private void mergeHi(int r24, int r25, int r26, int r27) {
        /*
            Method dump skipped, instructions count: 362
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.TimSort.mergeHi(int, int, int, int):void");
    }

    private T[] ensureCapacity(int minCapacity) {
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
            T[] newArray = (T[]) new Object[newSize];
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