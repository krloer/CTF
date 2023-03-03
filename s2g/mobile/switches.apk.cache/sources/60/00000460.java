package com.badlogic.gdx.utils;

import com.badlogic.gdx.utils.JsonWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.Iterator;
import java.util.NoSuchElementException;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class JsonValue implements Iterable<JsonValue> {
    public JsonValue child;
    private double doubleValue;
    private long longValue;
    public String name;
    public JsonValue next;
    public JsonValue parent;
    public JsonValue prev;
    public int size;
    private String stringValue;
    private ValueType type;

    /* loaded from: classes.dex */
    public static class PrettyPrintSettings {
        public JsonWriter.OutputType outputType;
        public int singleLineColumns;
        public boolean wrapNumericArrays;
    }

    /* loaded from: classes.dex */
    public enum ValueType {
        object,
        array,
        stringValue,
        doubleValue,
        longValue,
        booleanValue,
        nullValue
    }

    public JsonValue(ValueType type) {
        this.type = type;
    }

    public JsonValue(String value) {
        set(value);
    }

    public JsonValue(double value) {
        set(value, (String) null);
    }

    public JsonValue(long value) {
        set(value, (String) null);
    }

    public JsonValue(double value, String stringValue) {
        set(value, stringValue);
    }

    public JsonValue(long value, String stringValue) {
        set(value, stringValue);
    }

    public JsonValue(boolean value) {
        set(value);
    }

    public JsonValue get(int index) {
        JsonValue current = this.child;
        while (current != null && index > 0) {
            index--;
            current = current.next;
        }
        return current;
    }

    public JsonValue get(String name) {
        JsonValue current = this.child;
        while (current != null) {
            String str = current.name;
            if (str != null && str.equalsIgnoreCase(name)) {
                break;
            }
            current = current.next;
        }
        return current;
    }

    public boolean has(String name) {
        return get(name) != null;
    }

    public JsonValue require(int index) {
        JsonValue current = this.child;
        while (current != null && index > 0) {
            index--;
            current = current.next;
        }
        if (current == null) {
            throw new IllegalArgumentException("Child not found with index: " + index);
        }
        return current;
    }

    public JsonValue require(String name) {
        JsonValue current = this.child;
        while (current != null) {
            String str = current.name;
            if (str != null && str.equalsIgnoreCase(name)) {
                break;
            }
            current = current.next;
        }
        if (current == null) {
            throw new IllegalArgumentException("Child not found with name: " + name);
        }
        return current;
    }

    public JsonValue remove(int index) {
        JsonValue child = get(index);
        if (child == null) {
            return null;
        }
        JsonValue jsonValue = child.prev;
        if (jsonValue == null) {
            this.child = child.next;
            JsonValue jsonValue2 = this.child;
            if (jsonValue2 != null) {
                jsonValue2.prev = null;
            }
        } else {
            jsonValue.next = child.next;
            JsonValue jsonValue3 = child.next;
            if (jsonValue3 != null) {
                jsonValue3.prev = jsonValue;
            }
        }
        this.size--;
        return child;
    }

    public JsonValue remove(String name) {
        JsonValue child = get(name);
        if (child == null) {
            return null;
        }
        JsonValue jsonValue = child.prev;
        if (jsonValue == null) {
            this.child = child.next;
            JsonValue jsonValue2 = this.child;
            if (jsonValue2 != null) {
                jsonValue2.prev = null;
            }
        } else {
            jsonValue.next = child.next;
            JsonValue jsonValue3 = child.next;
            if (jsonValue3 != null) {
                jsonValue3.prev = jsonValue;
            }
        }
        this.size--;
        return child;
    }

    public void remove() {
        JsonValue jsonValue = this.parent;
        if (jsonValue == null) {
            throw new IllegalStateException();
        }
        JsonValue jsonValue2 = this.prev;
        if (jsonValue2 == null) {
            jsonValue.child = this.next;
            JsonValue jsonValue3 = jsonValue.child;
            if (jsonValue3 != null) {
                jsonValue3.prev = null;
            }
        } else {
            jsonValue2.next = this.next;
            JsonValue jsonValue4 = this.next;
            if (jsonValue4 != null) {
                jsonValue4.prev = jsonValue2;
            }
        }
        JsonValue jsonValue5 = this.parent;
        jsonValue5.size--;
    }

    public boolean notEmpty() {
        return this.size > 0;
    }

    public boolean isEmpty() {
        return this.size == 0;
    }

    @Deprecated
    public int size() {
        return this.size;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: com.badlogic.gdx.utils.JsonValue$1  reason: invalid class name */
    /* loaded from: classes.dex */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType = new int[ValueType.values().length];

        static {
            try {
                $SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[ValueType.stringValue.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[ValueType.doubleValue.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[ValueType.longValue.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[ValueType.booleanValue.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[ValueType.nullValue.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
        }
    }

    public String asString() {
        int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[this.type.ordinal()];
        if (i != 1) {
            if (i == 2) {
                String str = this.stringValue;
                return str != null ? str : Double.toString(this.doubleValue);
            } else if (i == 3) {
                String str2 = this.stringValue;
                return str2 != null ? str2 : Long.toString(this.longValue);
            } else if (i == 4) {
                return this.longValue != 0 ? "true" : "false";
            } else if (i == 5) {
                return null;
            } else {
                throw new IllegalStateException("Value cannot be converted to string: " + this.type);
            }
        }
        return this.stringValue;
    }

    public float asFloat() {
        int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[this.type.ordinal()];
        if (i != 1) {
            if (i != 2) {
                if (i != 3) {
                    if (i == 4) {
                        return this.longValue != 0 ? 1.0f : 0.0f;
                    }
                    throw new IllegalStateException("Value cannot be converted to float: " + this.type);
                }
                return (float) this.longValue;
            }
            return (float) this.doubleValue;
        }
        return Float.parseFloat(this.stringValue);
    }

    public double asDouble() {
        int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[this.type.ordinal()];
        if (i != 1) {
            if (i != 2) {
                if (i != 3) {
                    if (i == 4) {
                        return this.longValue != 0 ? 1.0d : 0.0d;
                    }
                    throw new IllegalStateException("Value cannot be converted to double: " + this.type);
                }
                return this.longValue;
            }
            return this.doubleValue;
        }
        return Double.parseDouble(this.stringValue);
    }

    public long asLong() {
        int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[this.type.ordinal()];
        if (i != 1) {
            if (i != 2) {
                if (i != 3) {
                    if (i == 4) {
                        return this.longValue != 0 ? 1L : 0L;
                    }
                    throw new IllegalStateException("Value cannot be converted to long: " + this.type);
                }
                return this.longValue;
            }
            return (long) this.doubleValue;
        }
        return Long.parseLong(this.stringValue);
    }

    public int asInt() {
        int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[this.type.ordinal()];
        if (i != 1) {
            if (i != 2) {
                if (i != 3) {
                    if (i == 4) {
                        return this.longValue != 0 ? 1 : 0;
                    }
                    throw new IllegalStateException("Value cannot be converted to int: " + this.type);
                }
                return (int) this.longValue;
            }
            return (int) this.doubleValue;
        }
        return Integer.parseInt(this.stringValue);
    }

    public boolean asBoolean() {
        int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[this.type.ordinal()];
        if (i != 1) {
            if (i == 2) {
                return this.doubleValue != 0.0d;
            } else if (i == 3) {
                return this.longValue != 0;
            } else if (i == 4) {
                return this.longValue != 0;
            } else {
                throw new IllegalStateException("Value cannot be converted to boolean: " + this.type);
            }
        }
        return this.stringValue.equalsIgnoreCase("true");
    }

    public byte asByte() {
        int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[this.type.ordinal()];
        if (i != 1) {
            if (i != 2) {
                if (i != 3) {
                    if (i == 4) {
                        return this.longValue != 0 ? (byte) 1 : (byte) 0;
                    }
                    throw new IllegalStateException("Value cannot be converted to byte: " + this.type);
                }
                return (byte) this.longValue;
            }
            return (byte) this.doubleValue;
        }
        return Byte.parseByte(this.stringValue);
    }

    public short asShort() {
        int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[this.type.ordinal()];
        if (i != 1) {
            if (i != 2) {
                if (i != 3) {
                    if (i == 4) {
                        return this.longValue != 0 ? (short) 1 : (short) 0;
                    }
                    throw new IllegalStateException("Value cannot be converted to short: " + this.type);
                }
                return (short) this.longValue;
            }
            return (short) this.doubleValue;
        }
        return Short.parseShort(this.stringValue);
    }

    public char asChar() {
        int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[this.type.ordinal()];
        if (i == 1) {
            if (this.stringValue.length() == 0) {
                return (char) 0;
            }
            return this.stringValue.charAt(0);
        } else if (i != 2) {
            if (i != 3) {
                if (i == 4) {
                    return this.longValue != 0 ? (char) 1 : (char) 0;
                }
                throw new IllegalStateException("Value cannot be converted to char: " + this.type);
            }
            return (char) this.longValue;
        } else {
            return (char) this.doubleValue;
        }
    }

    public String[] asStringArray() {
        String v;
        if (this.type != ValueType.array) {
            throw new IllegalStateException("Value is not an array: " + this.type);
        }
        String[] array = new String[this.size];
        int i = 0;
        JsonValue value = this.child;
        while (value != null) {
            int i2 = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[value.type.ordinal()];
            if (i2 == 1) {
                v = value.stringValue;
            } else if (i2 == 2) {
                v = this.stringValue;
                if (v == null) {
                    v = Double.toString(value.doubleValue);
                }
            } else if (i2 == 3) {
                v = this.stringValue;
                if (v == null) {
                    v = Long.toString(value.longValue);
                }
            } else if (i2 == 4) {
                v = value.longValue != 0 ? "true" : "false";
            } else if (i2 == 5) {
                v = null;
            } else {
                throw new IllegalStateException("Value cannot be converted to string: " + value.type);
            }
            array[i] = v;
            value = value.next;
            i++;
        }
        return array;
    }

    public float[] asFloatArray() {
        float v;
        if (this.type != ValueType.array) {
            throw new IllegalStateException("Value is not an array: " + this.type);
        }
        float[] array = new float[this.size];
        int i = 0;
        JsonValue value = this.child;
        while (value != null) {
            int i2 = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[value.type.ordinal()];
            if (i2 == 1) {
                v = Float.parseFloat(value.stringValue);
            } else if (i2 == 2) {
                v = (float) value.doubleValue;
            } else if (i2 == 3) {
                v = (float) value.longValue;
            } else if (i2 == 4) {
                v = value.longValue != 0 ? 1.0f : 0.0f;
            } else {
                throw new IllegalStateException("Value cannot be converted to float: " + value.type);
            }
            array[i] = v;
            value = value.next;
            i++;
        }
        return array;
    }

    public double[] asDoubleArray() {
        double v;
        if (this.type != ValueType.array) {
            throw new IllegalStateException("Value is not an array: " + this.type);
        }
        double[] array = new double[this.size];
        int i = 0;
        JsonValue value = this.child;
        while (value != null) {
            int i2 = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[value.type.ordinal()];
            if (i2 == 1) {
                v = Double.parseDouble(value.stringValue);
            } else if (i2 == 2) {
                v = value.doubleValue;
            } else if (i2 == 3) {
                v = value.longValue;
            } else if (i2 == 4) {
                v = value.longValue != 0 ? 1.0d : 0.0d;
            } else {
                throw new IllegalStateException("Value cannot be converted to double: " + value.type);
            }
            array[i] = v;
            value = value.next;
            i++;
        }
        return array;
    }

    public long[] asLongArray() {
        long v;
        if (this.type != ValueType.array) {
            throw new IllegalStateException("Value is not an array: " + this.type);
        }
        long[] array = new long[this.size];
        int i = 0;
        JsonValue value = this.child;
        while (value != null) {
            int i2 = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[value.type.ordinal()];
            if (i2 == 1) {
                v = Long.parseLong(value.stringValue);
            } else if (i2 == 2) {
                v = (long) value.doubleValue;
            } else if (i2 == 3) {
                v = value.longValue;
            } else if (i2 == 4) {
                v = value.longValue != 0 ? 1L : 0L;
            } else {
                throw new IllegalStateException("Value cannot be converted to long: " + value.type);
            }
            array[i] = v;
            value = value.next;
            i++;
        }
        return array;
    }

    public int[] asIntArray() {
        int v;
        if (this.type != ValueType.array) {
            throw new IllegalStateException("Value is not an array: " + this.type);
        }
        int[] array = new int[this.size];
        int i = 0;
        JsonValue value = this.child;
        while (value != null) {
            int i2 = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[value.type.ordinal()];
            if (i2 == 1) {
                v = Integer.parseInt(value.stringValue);
            } else if (i2 == 2) {
                v = (int) value.doubleValue;
            } else if (i2 == 3) {
                v = (int) value.longValue;
            } else if (i2 == 4) {
                v = value.longValue == 0 ? 0 : 1;
            } else {
                throw new IllegalStateException("Value cannot be converted to int: " + value.type);
            }
            array[i] = v;
            value = value.next;
            i++;
        }
        return array;
    }

    public boolean[] asBooleanArray() {
        boolean v;
        if (this.type != ValueType.array) {
            throw new IllegalStateException("Value is not an array: " + this.type);
        }
        boolean[] array = new boolean[this.size];
        int i = 0;
        JsonValue value = this.child;
        while (value != null) {
            int i2 = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[value.type.ordinal()];
            if (i2 == 1) {
                v = Boolean.parseBoolean(value.stringValue);
            } else if (i2 == 2) {
                v = value.doubleValue == 0.0d;
            } else if (i2 == 3) {
                v = value.longValue == 0;
            } else if (i2 == 4) {
                v = value.longValue != 0;
            } else {
                throw new IllegalStateException("Value cannot be converted to boolean: " + value.type);
            }
            array[i] = v;
            value = value.next;
            i++;
        }
        return array;
    }

    public byte[] asByteArray() {
        byte v;
        if (this.type != ValueType.array) {
            throw new IllegalStateException("Value is not an array: " + this.type);
        }
        byte[] array = new byte[this.size];
        int i = 0;
        JsonValue value = this.child;
        while (value != null) {
            int i2 = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[value.type.ordinal()];
            if (i2 == 1) {
                v = Byte.parseByte(value.stringValue);
            } else if (i2 == 2) {
                v = (byte) value.doubleValue;
            } else if (i2 == 3) {
                v = (byte) value.longValue;
            } else if (i2 == 4) {
                v = value.longValue == 0 ? (byte) 0 : (byte) 1;
            } else {
                throw new IllegalStateException("Value cannot be converted to byte: " + value.type);
            }
            array[i] = v;
            value = value.next;
            i++;
        }
        return array;
    }

    public short[] asShortArray() {
        short v;
        if (this.type != ValueType.array) {
            throw new IllegalStateException("Value is not an array: " + this.type);
        }
        short[] array = new short[this.size];
        int i = 0;
        JsonValue value = this.child;
        while (value != null) {
            int i2 = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[value.type.ordinal()];
            if (i2 == 1) {
                v = Short.parseShort(value.stringValue);
            } else if (i2 == 2) {
                v = (short) value.doubleValue;
            } else if (i2 == 3) {
                v = (short) value.longValue;
            } else if (i2 == 4) {
                v = value.longValue == 0 ? (short) 0 : (short) 1;
            } else {
                throw new IllegalStateException("Value cannot be converted to short: " + value.type);
            }
            array[i] = v;
            value = value.next;
            i++;
        }
        return array;
    }

    public char[] asCharArray() {
        char v;
        if (this.type != ValueType.array) {
            throw new IllegalStateException("Value is not an array: " + this.type);
        }
        char[] array = new char[this.size];
        int i = 0;
        JsonValue value = this.child;
        while (value != null) {
            int i2 = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[value.type.ordinal()];
            if (i2 == 1) {
                v = value.stringValue.length() != 0 ? value.stringValue.charAt(0) : (char) 0;
            } else if (i2 == 2) {
                v = (char) value.doubleValue;
            } else if (i2 == 3) {
                v = (char) value.longValue;
            } else if (i2 == 4) {
                v = value.longValue != 0 ? (char) 1 : (char) 0;
            } else {
                throw new IllegalStateException("Value cannot be converted to char: " + value.type);
            }
            array[i] = v;
            value = value.next;
            i++;
        }
        return array;
    }

    public boolean hasChild(String name) {
        return getChild(name) != null;
    }

    public JsonValue getChild(String name) {
        JsonValue child = get(name);
        if (child == null) {
            return null;
        }
        return child.child;
    }

    public String getString(String name, String defaultValue) {
        JsonValue child = get(name);
        return (child == null || !child.isValue() || child.isNull()) ? defaultValue : child.asString();
    }

    public float getFloat(String name, float defaultValue) {
        JsonValue child = get(name);
        return (child == null || !child.isValue() || child.isNull()) ? defaultValue : child.asFloat();
    }

    public double getDouble(String name, double defaultValue) {
        JsonValue child = get(name);
        return (child == null || !child.isValue() || child.isNull()) ? defaultValue : child.asDouble();
    }

    public long getLong(String name, long defaultValue) {
        JsonValue child = get(name);
        return (child == null || !child.isValue() || child.isNull()) ? defaultValue : child.asLong();
    }

    public int getInt(String name, int defaultValue) {
        JsonValue child = get(name);
        return (child == null || !child.isValue() || child.isNull()) ? defaultValue : child.asInt();
    }

    public boolean getBoolean(String name, boolean defaultValue) {
        JsonValue child = get(name);
        return (child == null || !child.isValue() || child.isNull()) ? defaultValue : child.asBoolean();
    }

    public byte getByte(String name, byte defaultValue) {
        JsonValue child = get(name);
        return (child == null || !child.isValue() || child.isNull()) ? defaultValue : child.asByte();
    }

    public short getShort(String name, short defaultValue) {
        JsonValue child = get(name);
        return (child == null || !child.isValue() || child.isNull()) ? defaultValue : child.asShort();
    }

    public char getChar(String name, char defaultValue) {
        JsonValue child = get(name);
        return (child == null || !child.isValue() || child.isNull()) ? defaultValue : child.asChar();
    }

    public String getString(String name) {
        JsonValue child = get(name);
        if (child == null) {
            throw new IllegalArgumentException("Named value not found: " + name);
        }
        return child.asString();
    }

    public float getFloat(String name) {
        JsonValue child = get(name);
        if (child == null) {
            throw new IllegalArgumentException("Named value not found: " + name);
        }
        return child.asFloat();
    }

    public double getDouble(String name) {
        JsonValue child = get(name);
        if (child == null) {
            throw new IllegalArgumentException("Named value not found: " + name);
        }
        return child.asDouble();
    }

    public long getLong(String name) {
        JsonValue child = get(name);
        if (child == null) {
            throw new IllegalArgumentException("Named value not found: " + name);
        }
        return child.asLong();
    }

    public int getInt(String name) {
        JsonValue child = get(name);
        if (child == null) {
            throw new IllegalArgumentException("Named value not found: " + name);
        }
        return child.asInt();
    }

    public boolean getBoolean(String name) {
        JsonValue child = get(name);
        if (child == null) {
            throw new IllegalArgumentException("Named value not found: " + name);
        }
        return child.asBoolean();
    }

    public byte getByte(String name) {
        JsonValue child = get(name);
        if (child == null) {
            throw new IllegalArgumentException("Named value not found: " + name);
        }
        return child.asByte();
    }

    public short getShort(String name) {
        JsonValue child = get(name);
        if (child == null) {
            throw new IllegalArgumentException("Named value not found: " + name);
        }
        return child.asShort();
    }

    public char getChar(String name) {
        JsonValue child = get(name);
        if (child == null) {
            throw new IllegalArgumentException("Named value not found: " + name);
        }
        return child.asChar();
    }

    public String getString(int index) {
        JsonValue child = get(index);
        if (child == null) {
            throw new IllegalArgumentException("Indexed value not found: " + this.name);
        }
        return child.asString();
    }

    public float getFloat(int index) {
        JsonValue child = get(index);
        if (child == null) {
            throw new IllegalArgumentException("Indexed value not found: " + this.name);
        }
        return child.asFloat();
    }

    public double getDouble(int index) {
        JsonValue child = get(index);
        if (child == null) {
            throw new IllegalArgumentException("Indexed value not found: " + this.name);
        }
        return child.asDouble();
    }

    public long getLong(int index) {
        JsonValue child = get(index);
        if (child == null) {
            throw new IllegalArgumentException("Indexed value not found: " + this.name);
        }
        return child.asLong();
    }

    public int getInt(int index) {
        JsonValue child = get(index);
        if (child == null) {
            throw new IllegalArgumentException("Indexed value not found: " + this.name);
        }
        return child.asInt();
    }

    public boolean getBoolean(int index) {
        JsonValue child = get(index);
        if (child == null) {
            throw new IllegalArgumentException("Indexed value not found: " + this.name);
        }
        return child.asBoolean();
    }

    public byte getByte(int index) {
        JsonValue child = get(index);
        if (child == null) {
            throw new IllegalArgumentException("Indexed value not found: " + this.name);
        }
        return child.asByte();
    }

    public short getShort(int index) {
        JsonValue child = get(index);
        if (child == null) {
            throw new IllegalArgumentException("Indexed value not found: " + this.name);
        }
        return child.asShort();
    }

    public char getChar(int index) {
        JsonValue child = get(index);
        if (child == null) {
            throw new IllegalArgumentException("Indexed value not found: " + this.name);
        }
        return child.asChar();
    }

    public ValueType type() {
        return this.type;
    }

    public void setType(ValueType type) {
        if (type == null) {
            throw new IllegalArgumentException("type cannot be null.");
        }
        this.type = type;
    }

    public boolean isArray() {
        return this.type == ValueType.array;
    }

    public boolean isObject() {
        return this.type == ValueType.object;
    }

    public boolean isString() {
        return this.type == ValueType.stringValue;
    }

    public boolean isNumber() {
        return this.type == ValueType.doubleValue || this.type == ValueType.longValue;
    }

    public boolean isDouble() {
        return this.type == ValueType.doubleValue;
    }

    public boolean isLong() {
        return this.type == ValueType.longValue;
    }

    public boolean isBoolean() {
        return this.type == ValueType.booleanValue;
    }

    public boolean isNull() {
        return this.type == ValueType.nullValue;
    }

    public boolean isValue() {
        int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonValue$ValueType[this.type.ordinal()];
        return i == 1 || i == 2 || i == 3 || i == 4 || i == 5;
    }

    public String name() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public JsonValue parent() {
        return this.parent;
    }

    public JsonValue child() {
        return this.child;
    }

    public void addChild(String name, JsonValue value) {
        if (name == null) {
            throw new IllegalArgumentException("name cannot be null.");
        }
        value.name = name;
        addChild(value);
    }

    public void addChild(JsonValue value) {
        value.parent = this;
        this.size++;
        JsonValue current = this.child;
        if (current == null) {
            this.child = value;
            return;
        }
        while (current.next != null) {
            current = current.next;
        }
        current.next = value;
        value.prev = current;
    }

    public JsonValue next() {
        return this.next;
    }

    public void setNext(JsonValue next) {
        this.next = next;
    }

    public JsonValue prev() {
        return this.prev;
    }

    public void setPrev(JsonValue prev) {
        this.prev = prev;
    }

    public void set(String value) {
        this.stringValue = value;
        this.type = value == null ? ValueType.nullValue : ValueType.stringValue;
    }

    public void set(double value, String stringValue) {
        this.doubleValue = value;
        this.longValue = (long) value;
        this.stringValue = stringValue;
        this.type = ValueType.doubleValue;
    }

    public void set(long value, String stringValue) {
        this.longValue = value;
        this.doubleValue = value;
        this.stringValue = stringValue;
        this.type = ValueType.longValue;
    }

    public void set(boolean value) {
        this.longValue = value ? 1L : 0L;
        this.type = ValueType.booleanValue;
    }

    public String toJson(JsonWriter.OutputType outputType) {
        if (isValue()) {
            return asString();
        }
        StringBuilder buffer = new StringBuilder(512);
        json(this, buffer, outputType);
        return buffer.toString();
    }

    private void json(JsonValue object, StringBuilder buffer, JsonWriter.OutputType outputType) {
        if (object.isObject()) {
            if (object.child == null) {
                buffer.append("{}");
                return;
            }
            buffer.length();
            buffer.append('{');
            for (JsonValue child = object.child; child != null; child = child.next) {
                buffer.append(outputType.quoteName(child.name));
                buffer.append(':');
                json(child, buffer, outputType);
                if (child.next != null) {
                    buffer.append(',');
                }
            }
            buffer.append('}');
        } else if (object.isArray()) {
            if (object.child == null) {
                buffer.append("[]");
                return;
            }
            buffer.length();
            buffer.append('[');
            for (JsonValue child2 = object.child; child2 != null; child2 = child2.next) {
                json(child2, buffer, outputType);
                if (child2.next != null) {
                    buffer.append(',');
                }
            }
            buffer.append(']');
        } else if (object.isString()) {
            buffer.append(outputType.quoteValue(object.asString()));
        } else if (object.isDouble()) {
            double doubleValue = object.asDouble();
            long longValue = object.asLong();
            buffer.append(doubleValue == ((double) longValue) ? longValue : doubleValue);
        } else if (object.isLong()) {
            buffer.append(object.asLong());
        } else if (object.isBoolean()) {
            buffer.append(object.asBoolean());
        } else if (object.isNull()) {
            buffer.append("null");
        } else {
            throw new SerializationException("Unknown object type: " + object);
        }
    }

    @Override // java.lang.Iterable
    /* renamed from: iterator */
    public Iterator<JsonValue> iterator2() {
        return new JsonIterator();
    }

    public String toString() {
        String str;
        if (isValue()) {
            if (this.name == null) {
                return asString();
            }
            return this.name + ": " + asString();
        }
        java.lang.StringBuilder sb = new java.lang.StringBuilder();
        if (this.name == null) {
            str = BuildConfig.FLAVOR;
        } else {
            str = this.name + ": ";
        }
        sb.append(str);
        sb.append(prettyPrint(JsonWriter.OutputType.minimal, 0));
        return sb.toString();
    }

    public String trace() {
        String trace;
        JsonValue jsonValue = this.parent;
        if (jsonValue == null) {
            return this.type == ValueType.array ? "[]" : this.type == ValueType.object ? "{}" : BuildConfig.FLAVOR;
        }
        if (jsonValue.type == ValueType.array) {
            trace = "[]";
            int i = 0;
            JsonValue child = this.parent.child;
            while (true) {
                if (child == null) {
                    break;
                } else if (child != this) {
                    child = child.next;
                    i++;
                } else {
                    trace = "[" + i + "]";
                    break;
                }
            }
        } else {
            String trace2 = this.name;
            if (trace2.indexOf(46) != -1) {
                trace = ".\"" + this.name.replace("\"", "\\\"") + "\"";
            } else {
                trace = '.' + this.name;
            }
        }
        return this.parent.trace() + trace;
    }

    public String prettyPrint(JsonWriter.OutputType outputType, int singleLineColumns) {
        PrettyPrintSettings settings = new PrettyPrintSettings();
        settings.outputType = outputType;
        settings.singleLineColumns = singleLineColumns;
        return prettyPrint(settings);
    }

    public String prettyPrint(PrettyPrintSettings settings) {
        StringBuilder buffer = new StringBuilder(512);
        prettyPrint(this, buffer, 0, settings);
        return buffer.toString();
    }

    private void prettyPrint(JsonValue object, StringBuilder buffer, int indent, PrettyPrintSettings settings) {
        JsonWriter.OutputType outputType = settings.outputType;
        boolean wrap = true;
        if (object.isObject()) {
            if (object.child == null) {
                buffer.append("{}");
                return;
            }
            boolean newLines = !isFlat(object);
            int start = buffer.length();
            loop0: while (true) {
                buffer.append(newLines ? "{\n" : "{ ");
                for (JsonValue child = object.child; child != null; child = child.next) {
                    if (newLines) {
                        indent(indent, buffer);
                    }
                    buffer.append(outputType.quoteName(child.name));
                    buffer.append(": ");
                    prettyPrint(child, buffer, indent + 1, settings);
                    if ((!newLines || outputType != JsonWriter.OutputType.minimal) && child.next != null) {
                        buffer.append(',');
                    }
                    buffer.append(newLines ? '\n' : ' ');
                    if (newLines || buffer.length() - start <= settings.singleLineColumns) {
                    }
                }
                buffer.setLength(start);
                newLines = true;
            }
            if (newLines) {
                indent(indent - 1, buffer);
            }
            buffer.append('}');
        } else if (object.isArray()) {
            if (object.child == null) {
                buffer.append("[]");
                return;
            }
            boolean newLines2 = !isFlat(object);
            if (!settings.wrapNumericArrays && isNumeric(object)) {
                wrap = false;
            }
            int start2 = buffer.length();
            loop2: while (true) {
                buffer.append(newLines2 ? "[\n" : "[ ");
                for (JsonValue child2 = object.child; child2 != null; child2 = child2.next) {
                    if (newLines2) {
                        indent(indent, buffer);
                    }
                    prettyPrint(child2, buffer, indent + 1, settings);
                    if ((!newLines2 || outputType != JsonWriter.OutputType.minimal) && child2.next != null) {
                        buffer.append(',');
                    }
                    buffer.append(newLines2 ? '\n' : ' ');
                    if (!wrap || newLines2 || buffer.length() - start2 <= settings.singleLineColumns) {
                    }
                }
                buffer.setLength(start2);
                newLines2 = true;
            }
            if (newLines2) {
                indent(indent - 1, buffer);
            }
            buffer.append(']');
        } else if (object.isString()) {
            buffer.append(outputType.quoteValue(object.asString()));
        } else if (object.isDouble()) {
            double doubleValue = object.asDouble();
            long longValue = object.asLong();
            buffer.append(doubleValue == ((double) longValue) ? longValue : doubleValue);
        } else if (object.isLong()) {
            buffer.append(object.asLong());
        } else if (object.isBoolean()) {
            buffer.append(object.asBoolean());
        } else if (object.isNull()) {
            buffer.append("null");
        } else {
            throw new SerializationException("Unknown object type: " + object);
        }
    }

    public void prettyPrint(JsonWriter.OutputType outputType, Writer writer) throws IOException {
        PrettyPrintSettings settings = new PrettyPrintSettings();
        settings.outputType = outputType;
        prettyPrint(this, writer, 0, settings);
    }

    private void prettyPrint(JsonValue object, Writer writer, int indent, PrettyPrintSettings settings) throws IOException {
        JsonWriter.OutputType outputType = settings.outputType;
        boolean z = true;
        if (object.isObject()) {
            if (object.child == null) {
                writer.append("{}");
                return;
            }
            if (isFlat(object) && object.size <= 6) {
                z = false;
            }
            boolean newLines = z;
            writer.append((CharSequence) (newLines ? "{\n" : "{ "));
            for (JsonValue child = object.child; child != null; child = child.next) {
                if (newLines) {
                    indent(indent, writer);
                }
                writer.append((CharSequence) outputType.quoteName(child.name));
                writer.append(": ");
                prettyPrint(child, writer, indent + 1, settings);
                if ((!newLines || outputType != JsonWriter.OutputType.minimal) && child.next != null) {
                    writer.append(',');
                }
                writer.append(newLines ? '\n' : ' ');
            }
            if (newLines) {
                indent(indent - 1, writer);
            }
            writer.append('}');
        } else if (object.isArray()) {
            if (object.child == null) {
                writer.append("[]");
                return;
            }
            boolean newLines2 = !isFlat(object);
            writer.append((CharSequence) (newLines2 ? "[\n" : "[ "));
            for (JsonValue child2 = object.child; child2 != null; child2 = child2.next) {
                if (newLines2) {
                    indent(indent, writer);
                }
                prettyPrint(child2, writer, indent + 1, settings);
                if ((!newLines2 || outputType != JsonWriter.OutputType.minimal) && child2.next != null) {
                    writer.append(',');
                }
                writer.append(newLines2 ? '\n' : ' ');
            }
            if (newLines2) {
                indent(indent - 1, writer);
            }
            writer.append(']');
        } else if (object.isString()) {
            writer.append((CharSequence) outputType.quoteValue(object.asString()));
        } else if (object.isDouble()) {
            double doubleValue = object.asDouble();
            long longValue = object.asLong();
            writer.append((CharSequence) Double.toString(doubleValue == ((double) longValue) ? longValue : doubleValue));
        } else if (object.isLong()) {
            writer.append((CharSequence) Long.toString(object.asLong()));
        } else if (object.isBoolean()) {
            writer.append((CharSequence) Boolean.toString(object.asBoolean()));
        } else if (object.isNull()) {
            writer.append("null");
        } else {
            throw new SerializationException("Unknown object type: " + object);
        }
    }

    private static boolean isFlat(JsonValue object) {
        for (JsonValue child = object.child; child != null; child = child.next) {
            if (child.isObject() || child.isArray()) {
                return false;
            }
        }
        return true;
    }

    private static boolean isNumeric(JsonValue object) {
        for (JsonValue child = object.child; child != null; child = child.next) {
            if (!child.isNumber()) {
                return false;
            }
        }
        return true;
    }

    private static void indent(int count, StringBuilder buffer) {
        for (int i = 0; i < count; i++) {
            buffer.append('\t');
        }
    }

    private static void indent(int count, Writer buffer) throws IOException {
        for (int i = 0; i < count; i++) {
            buffer.append('\t');
        }
    }

    /* loaded from: classes.dex */
    public class JsonIterator implements Iterator<JsonValue>, Iterable<JsonValue> {
        JsonValue current;
        JsonValue entry;

        public JsonIterator() {
            this.entry = JsonValue.this.child;
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            return this.entry != null;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // java.util.Iterator
        public JsonValue next() {
            this.current = this.entry;
            JsonValue jsonValue = this.current;
            if (jsonValue == null) {
                throw new NoSuchElementException();
            }
            this.entry = jsonValue.next;
            return this.current;
        }

        @Override // java.util.Iterator
        public void remove() {
            if (this.current.prev == null) {
                JsonValue.this.child = this.current.next;
                if (JsonValue.this.child != null) {
                    JsonValue.this.child.prev = null;
                }
            } else {
                this.current.prev.next = this.current.next;
                if (this.current.next != null) {
                    this.current.next.prev = this.current.prev;
                }
            }
            JsonValue jsonValue = JsonValue.this;
            jsonValue.size--;
        }

        @Override // java.lang.Iterable
        public Iterator<JsonValue> iterator() {
            return this;
        }
    }
}