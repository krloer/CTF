package com.badlogic.gdx.graphics.g3d;

import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public abstract class Attribute implements Comparable<Attribute> {
    private static final Array<String> types = new Array<>();
    public final long type;
    private final int typeBit;

    public abstract Attribute copy();

    public static final long getAttributeType(String alias) {
        for (int i = 0; i < types.size; i++) {
            if (types.get(i).compareTo(alias) == 0) {
                return 1 << i;
            }
        }
        return 0L;
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x001d, code lost:
        if (r0 >= com.badlogic.gdx.graphics.g3d.Attribute.types.size) goto L15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:?, code lost:
        return com.badlogic.gdx.graphics.g3d.Attribute.types.get(r0);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static final java.lang.String getAttributeAlias(long r7) {
        /*
            r0 = -1
        L1:
            r1 = 0
            int r3 = (r7 > r1 ? 1 : (r7 == r1 ? 0 : -1))
            if (r3 == 0) goto L17
            int r0 = r0 + 1
            r3 = 63
            if (r0 >= r3) goto L17
            long r3 = r7 >> r0
            r5 = 1
            long r3 = r3 & r5
            int r5 = (r3 > r1 ? 1 : (r3 == r1 ? 0 : -1))
            if (r5 != 0) goto L17
            goto L1
        L17:
            if (r0 < 0) goto L28
            com.badlogic.gdx.utils.Array<java.lang.String> r1 = com.badlogic.gdx.graphics.g3d.Attribute.types
            int r1 = r1.size
            if (r0 >= r1) goto L28
            com.badlogic.gdx.utils.Array<java.lang.String> r1 = com.badlogic.gdx.graphics.g3d.Attribute.types
            java.lang.Object r1 = r1.get(r0)
            java.lang.String r1 = (java.lang.String) r1
            goto L29
        L28:
            r1 = 0
        L29:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.graphics.g3d.Attribute.getAttributeAlias(long):java.lang.String");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static final long register(String alias) {
        long result = getAttributeType(alias);
        if (result > 0) {
            return result;
        }
        types.add(alias);
        return 1 << (types.size - 1);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public Attribute(long type) {
        this.type = type;
        this.typeBit = Long.numberOfTrailingZeros(type);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public boolean equals(Attribute other) {
        return other.hashCode() == hashCode();
    }

    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof Attribute)) {
            return false;
        }
        Attribute other = (Attribute) obj;
        if (this.type != other.type) {
            return false;
        }
        return equals(other);
    }

    public String toString() {
        return getAttributeAlias(this.type);
    }

    public int hashCode() {
        return this.typeBit * 7489;
    }
}