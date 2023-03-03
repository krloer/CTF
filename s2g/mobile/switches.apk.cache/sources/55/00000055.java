package com.badlogic.gdx;

import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class Version {
    public static final int MAJOR;
    public static final int MINOR;
    public static final int REVISION;
    public static final String VERSION = "1.10.0";

    static {
        try {
            String[] v = VERSION.split("\\.");
            MAJOR = v.length < 1 ? 0 : Integer.valueOf(v[0]).intValue();
            MINOR = v.length < 2 ? 0 : Integer.valueOf(v[1]).intValue();
            REVISION = v.length >= 3 ? Integer.valueOf(v[2]).intValue() : 0;
        } catch (Throwable t) {
            throw new GdxRuntimeException("Invalid version 1.10.0", t);
        }
    }

    public static boolean isHigher(int major, int minor, int revision) {
        return isHigherEqual(major, minor, revision + 1);
    }

    public static boolean isHigherEqual(int major, int minor, int revision) {
        int i = MAJOR;
        if (i != major) {
            return i > major;
        }
        int i2 = MINOR;
        return i2 != minor ? i2 > minor : REVISION >= revision;
    }

    public static boolean isLower(int major, int minor, int revision) {
        return isLowerEqual(major, minor, revision - 1);
    }

    public static boolean isLowerEqual(int major, int minor, int revision) {
        int i = MAJOR;
        if (i != major) {
            return i < major;
        }
        int i2 = MINOR;
        return i2 != minor ? i2 < minor : REVISION <= revision;
    }
}