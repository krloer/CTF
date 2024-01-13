package com.kotcrab.vis.ui.building.utilities;

/* loaded from: classes.dex */
public class Nullables {
    private Nullables() {
    }

    public static boolean isNull(Object nullable) {
        return nullable == null;
    }

    public static boolean isNotNull(Object nullable) {
        return nullable != null;
    }

    public static <Type> Type getOrElse(Type nullable, Type alternative) {
        return nullable == null ? alternative : nullable;
    }

    public static void executeIfNotNull(Object nullable, Runnable command) {
        if (nullable != null) {
            command.run();
        }
    }

    public static boolean areEqual(Object first, Object second) {
        return first == second || (first != null && first.equals(second));
    }

    public static boolean isAnyNull(Object... nullables) {
        for (Object object : nullables) {
            if (object == null) {
                return true;
            }
        }
        return false;
    }

    public static boolean areAllNull(Object... nullables) {
        for (Object object : nullables) {
            if (object != null) {
                return false;
            }
        }
        return true;
    }

    public static boolean isAnyNotNull(Object... nullables) {
        for (Object object : nullables) {
            if (object != null) {
                return true;
            }
        }
        return false;
    }

    public static boolean areAllNotNull(Object... nullables) {
        for (Object object : nullables) {
            if (object == null) {
                return false;
            }
        }
        return true;
    }
}