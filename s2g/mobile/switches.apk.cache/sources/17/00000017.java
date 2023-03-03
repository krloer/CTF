package com.badlogic.ashley.core;

import com.badlogic.gdx.utils.Bits;
import com.badlogic.gdx.utils.ObjectMap;

/* loaded from: classes.dex */
public class Family {
    private final Bits all;
    private final Bits exclude;
    private final int index;
    private final Bits one;
    private static ObjectMap<String, Family> families = new ObjectMap<>();
    private static int familyIndex = 0;
    private static final Builder builder = new Builder();
    private static final Bits zeroBits = new Bits();

    private Family(Bits all, Bits any, Bits exclude) {
        this.all = all;
        this.one = any;
        this.exclude = exclude;
        int i = familyIndex;
        familyIndex = i + 1;
        this.index = i;
    }

    public int getIndex() {
        return this.index;
    }

    public boolean matches(Entity entity) {
        Bits entityComponentBits = entity.getComponentBits();
        if (entityComponentBits.containsAll(this.all)) {
            if (this.one.isEmpty() || this.one.intersects(entityComponentBits)) {
                return this.exclude.isEmpty() || !this.exclude.intersects(entityComponentBits);
            }
            return false;
        }
        return false;
    }

    @SafeVarargs
    public static final Builder all(Class<? extends Component>... componentTypes) {
        return builder.reset().all(componentTypes);
    }

    @SafeVarargs
    public static final Builder one(Class<? extends Component>... componentTypes) {
        return builder.reset().one(componentTypes);
    }

    @SafeVarargs
    public static final Builder exclude(Class<? extends Component>... componentTypes) {
        return builder.reset().exclude(componentTypes);
    }

    /* loaded from: classes.dex */
    public static class Builder {
        private Bits all = Family.zeroBits;
        private Bits one = Family.zeroBits;
        private Bits exclude = Family.zeroBits;

        Builder() {
        }

        public Builder reset() {
            this.all = Family.zeroBits;
            this.one = Family.zeroBits;
            this.exclude = Family.zeroBits;
            return this;
        }

        @SafeVarargs
        public final Builder all(Class<? extends Component>... componentTypes) {
            this.all = ComponentType.getBitsFor(componentTypes);
            return this;
        }

        @SafeVarargs
        public final Builder one(Class<? extends Component>... componentTypes) {
            this.one = ComponentType.getBitsFor(componentTypes);
            return this;
        }

        @SafeVarargs
        public final Builder exclude(Class<? extends Component>... componentTypes) {
            this.exclude = ComponentType.getBitsFor(componentTypes);
            return this;
        }

        public Family get() {
            String hash = Family.getFamilyHash(this.all, this.one, this.exclude);
            Family family = (Family) Family.families.get(hash, null);
            if (family == null) {
                Family family2 = new Family(this.all, this.one, this.exclude);
                Family.families.put(hash, family2);
                return family2;
            }
            return family;
        }
    }

    public int hashCode() {
        return this.index;
    }

    public boolean equals(Object obj) {
        return this == obj;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static String getFamilyHash(Bits all, Bits one, Bits exclude) {
        StringBuilder stringBuilder = new StringBuilder();
        if (!all.isEmpty()) {
            stringBuilder.append("{all:");
            stringBuilder.append(getBitsString(all));
            stringBuilder.append("}");
        }
        if (!one.isEmpty()) {
            stringBuilder.append("{one:");
            stringBuilder.append(getBitsString(one));
            stringBuilder.append("}");
        }
        if (!exclude.isEmpty()) {
            stringBuilder.append("{exclude:");
            stringBuilder.append(getBitsString(exclude));
            stringBuilder.append("}");
        }
        return stringBuilder.toString();
    }

    private static String getBitsString(Bits bits) {
        StringBuilder stringBuilder = new StringBuilder();
        int numBits = bits.length();
        for (int i = 0; i < numBits; i++) {
            stringBuilder.append(bits.get(i) ? "1" : "0");
        }
        return stringBuilder.toString();
    }
}