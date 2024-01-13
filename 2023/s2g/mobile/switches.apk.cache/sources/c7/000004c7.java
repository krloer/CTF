package com.badlogic.gdx.utils;

import com.badlogic.gdx.Input;
import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/* loaded from: classes.dex */
public class UBJsonWriter implements Closeable {
    private JsonObject current;
    private boolean named;
    final DataOutputStream out;
    private final Array<JsonObject> stack = new Array<>();

    public UBJsonWriter(OutputStream out) {
        this.out = (DataOutputStream) (out instanceof DataOutputStream ? out : new DataOutputStream(out));
    }

    public UBJsonWriter object() throws IOException {
        JsonObject jsonObject = this.current;
        if (jsonObject != null && !jsonObject.array) {
            if (!this.named) {
                throw new IllegalStateException("Name must be set.");
            }
            this.named = false;
        }
        Array<JsonObject> array = this.stack;
        JsonObject jsonObject2 = new JsonObject(false);
        this.current = jsonObject2;
        array.add(jsonObject2);
        return this;
    }

    public UBJsonWriter object(String name) throws IOException {
        name(name).object();
        return this;
    }

    public UBJsonWriter array() throws IOException {
        JsonObject jsonObject = this.current;
        if (jsonObject != null && !jsonObject.array) {
            if (!this.named) {
                throw new IllegalStateException("Name must be set.");
            }
            this.named = false;
        }
        Array<JsonObject> array = this.stack;
        JsonObject jsonObject2 = new JsonObject(true);
        this.current = jsonObject2;
        array.add(jsonObject2);
        return this;
    }

    public UBJsonWriter array(String name) throws IOException {
        name(name).array();
        return this;
    }

    public UBJsonWriter name(String name) throws IOException {
        JsonObject jsonObject = this.current;
        if (jsonObject == null || jsonObject.array) {
            throw new IllegalStateException("Current item must be an object.");
        }
        byte[] bytes = name.getBytes("UTF-8");
        if (bytes.length <= 127) {
            this.out.writeByte(Input.Keys.BUTTON_R2);
            this.out.writeByte(bytes.length);
        } else if (bytes.length <= 32767) {
            this.out.writeByte(73);
            this.out.writeShort(bytes.length);
        } else {
            this.out.writeByte(Input.Keys.BUTTON_START);
            this.out.writeInt(bytes.length);
        }
        this.out.write(bytes);
        this.named = true;
        return this;
    }

    public UBJsonWriter value(byte value) throws IOException {
        checkName();
        this.out.writeByte(Input.Keys.BUTTON_R2);
        this.out.writeByte(value);
        return this;
    }

    public UBJsonWriter value(short value) throws IOException {
        checkName();
        this.out.writeByte(73);
        this.out.writeShort(value);
        return this;
    }

    public UBJsonWriter value(int value) throws IOException {
        checkName();
        this.out.writeByte(Input.Keys.BUTTON_START);
        this.out.writeInt(value);
        return this;
    }

    public UBJsonWriter value(long value) throws IOException {
        checkName();
        this.out.writeByte(76);
        this.out.writeLong(value);
        return this;
    }

    public UBJsonWriter value(float value) throws IOException {
        checkName();
        this.out.writeByte(100);
        this.out.writeFloat(value);
        return this;
    }

    public UBJsonWriter value(double value) throws IOException {
        checkName();
        this.out.writeByte(68);
        this.out.writeDouble(value);
        return this;
    }

    public UBJsonWriter value(boolean value) throws IOException {
        checkName();
        this.out.writeByte(value ? 84 : 70);
        return this;
    }

    public UBJsonWriter value(char value) throws IOException {
        checkName();
        this.out.writeByte(73);
        this.out.writeChar(value);
        return this;
    }

    public UBJsonWriter value(String value) throws IOException {
        checkName();
        byte[] bytes = value.getBytes("UTF-8");
        this.out.writeByte(83);
        if (bytes.length <= 127) {
            this.out.writeByte(Input.Keys.BUTTON_R2);
            this.out.writeByte(bytes.length);
        } else if (bytes.length <= 32767) {
            this.out.writeByte(73);
            this.out.writeShort(bytes.length);
        } else {
            this.out.writeByte(Input.Keys.BUTTON_START);
            this.out.writeInt(bytes.length);
        }
        this.out.write(bytes);
        return this;
    }

    public UBJsonWriter value(byte[] values) throws IOException {
        array();
        this.out.writeByte(36);
        this.out.writeByte(Input.Keys.BUTTON_R2);
        this.out.writeByte(35);
        value(values.length);
        for (byte b : values) {
            this.out.writeByte(b);
        }
        pop(true);
        return this;
    }

    public UBJsonWriter value(short[] values) throws IOException {
        array();
        this.out.writeByte(36);
        this.out.writeByte(73);
        this.out.writeByte(35);
        value(values.length);
        for (short s : values) {
            this.out.writeShort(s);
        }
        pop(true);
        return this;
    }

    public UBJsonWriter value(int[] values) throws IOException {
        array();
        this.out.writeByte(36);
        this.out.writeByte(Input.Keys.BUTTON_START);
        this.out.writeByte(35);
        value(values.length);
        for (int i : values) {
            this.out.writeInt(i);
        }
        pop(true);
        return this;
    }

    public UBJsonWriter value(long[] values) throws IOException {
        array();
        this.out.writeByte(36);
        this.out.writeByte(76);
        this.out.writeByte(35);
        value(values.length);
        for (long j : values) {
            this.out.writeLong(j);
        }
        pop(true);
        return this;
    }

    public UBJsonWriter value(float[] values) throws IOException {
        array();
        this.out.writeByte(36);
        this.out.writeByte(100);
        this.out.writeByte(35);
        value(values.length);
        for (float f : values) {
            this.out.writeFloat(f);
        }
        pop(true);
        return this;
    }

    public UBJsonWriter value(double[] values) throws IOException {
        array();
        this.out.writeByte(36);
        this.out.writeByte(68);
        this.out.writeByte(35);
        value(values.length);
        for (double d : values) {
            this.out.writeDouble(d);
        }
        pop(true);
        return this;
    }

    public UBJsonWriter value(boolean[] values) throws IOException {
        array();
        for (boolean z : values) {
            this.out.writeByte(z ? 84 : 70);
        }
        pop();
        return this;
    }

    public UBJsonWriter value(char[] values) throws IOException {
        array();
        this.out.writeByte(36);
        this.out.writeByte(67);
        this.out.writeByte(35);
        value(values.length);
        for (char c : values) {
            this.out.writeChar(c);
        }
        pop(true);
        return this;
    }

    public UBJsonWriter value(String[] values) throws IOException {
        array();
        this.out.writeByte(36);
        this.out.writeByte(83);
        this.out.writeByte(35);
        value(values.length);
        for (String str : values) {
            byte[] bytes = str.getBytes("UTF-8");
            if (bytes.length <= 127) {
                this.out.writeByte(Input.Keys.BUTTON_R2);
                this.out.writeByte(bytes.length);
            } else if (bytes.length <= 32767) {
                this.out.writeByte(73);
                this.out.writeShort(bytes.length);
            } else {
                this.out.writeByte(Input.Keys.BUTTON_START);
                this.out.writeInt(bytes.length);
            }
            this.out.write(bytes);
        }
        pop(true);
        return this;
    }

    public UBJsonWriter value(JsonValue value) throws IOException {
        if (value.isObject()) {
            if (value.name != null) {
                object(value.name);
            } else {
                object();
            }
            for (JsonValue child = value.child; child != null; child = child.next) {
                value(child);
            }
            pop();
        } else if (value.isArray()) {
            if (value.name != null) {
                array(value.name);
            } else {
                array();
            }
            for (JsonValue child2 = value.child; child2 != null; child2 = child2.next) {
                value(child2);
            }
            pop();
        } else if (value.isBoolean()) {
            if (value.name != null) {
                name(value.name);
            }
            value(value.asBoolean());
        } else if (value.isDouble()) {
            if (value.name != null) {
                name(value.name);
            }
            value(value.asDouble());
        } else if (value.isLong()) {
            if (value.name != null) {
                name(value.name);
            }
            value(value.asLong());
        } else if (value.isString()) {
            if (value.name != null) {
                name(value.name);
            }
            value(value.asString());
        } else if (value.isNull()) {
            if (value.name != null) {
                name(value.name);
            }
            value();
        } else {
            throw new IOException("Unhandled JsonValue type");
        }
        return this;
    }

    public UBJsonWriter value(Object object) throws IOException {
        if (object == null) {
            return value();
        }
        if (object instanceof Number) {
            Number number = (Number) object;
            return object instanceof Byte ? value(number.byteValue()) : object instanceof Short ? value(number.shortValue()) : object instanceof Integer ? value(number.intValue()) : object instanceof Long ? value(number.longValue()) : object instanceof Float ? value(number.floatValue()) : object instanceof Double ? value(number.doubleValue()) : this;
        } else if (object instanceof Character) {
            return value(((Character) object).charValue());
        } else {
            if (object instanceof CharSequence) {
                return value(object.toString());
            }
            throw new IOException("Unknown object type.");
        }
    }

    public UBJsonWriter value() throws IOException {
        checkName();
        this.out.writeByte(90);
        return this;
    }

    public UBJsonWriter set(String name, byte value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, short value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, int value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, long value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, float value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, double value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, boolean value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, char value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, String value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, byte[] value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, short[] value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, int[] value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, long[] value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, float[] value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, double[] value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, boolean[] value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, char[] value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name, String[] value) throws IOException {
        return name(name).value(value);
    }

    public UBJsonWriter set(String name) throws IOException {
        return name(name).value();
    }

    private void checkName() {
        JsonObject jsonObject = this.current;
        if (jsonObject != null && !jsonObject.array) {
            if (!this.named) {
                throw new IllegalStateException("Name must be set.");
            }
            this.named = false;
        }
    }

    public UBJsonWriter pop() throws IOException {
        return pop(false);
    }

    protected UBJsonWriter pop(boolean silent) throws IOException {
        if (this.named) {
            throw new IllegalStateException("Expected an object, array, or value since a name was set.");
        }
        if (silent) {
            this.stack.pop();
        } else {
            this.stack.pop().close();
        }
        this.current = this.stack.size == 0 ? null : this.stack.peek();
        return this;
    }

    public void flush() throws IOException {
        this.out.flush();
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        while (this.stack.size > 0) {
            pop();
        }
        this.out.close();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class JsonObject {
        final boolean array;

        JsonObject(boolean array) throws IOException {
            this.array = array;
            UBJsonWriter.this.out.writeByte(array ? 91 : Input.Keys.END);
        }

        void close() throws IOException {
            UBJsonWriter.this.out.writeByte(this.array ? 93 : 125);
        }
    }
}