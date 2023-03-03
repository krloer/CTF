package com.badlogic.gdx.utils;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.utils.JsonValue;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import kotlin.text.Typography;

/* loaded from: classes.dex */
public class JsonReader implements BaseJsonReader {
    static final int json_en_array = 23;
    static final int json_en_main = 1;
    static final int json_en_object = 5;
    static final int json_error = 0;
    static final int json_first_final = 35;
    static final int json_start = 1;
    private JsonValue current;
    private final Array<JsonValue> elements = new Array<>(8);
    private final Array<JsonValue> lastChild = new Array<>(8);
    private JsonValue root;
    private static final byte[] _json_actions = init__json_actions_0();
    private static final short[] _json_key_offsets = init__json_key_offsets_0();
    private static final char[] _json_trans_keys = init__json_trans_keys_0();
    private static final byte[] _json_single_lengths = init__json_single_lengths_0();
    private static final byte[] _json_range_lengths = init__json_range_lengths_0();
    private static final short[] _json_index_offsets = init__json_index_offsets_0();
    private static final byte[] _json_indicies = init__json_indicies_0();
    private static final byte[] _json_trans_targs = init__json_trans_targs_0();
    private static final byte[] _json_trans_actions = init__json_trans_actions_0();
    private static final byte[] _json_eof_actions = init__json_eof_actions_0();

    public JsonValue parse(String json) {
        char[] data = json.toCharArray();
        return parse(data, 0, data.length);
    }

    public JsonValue parse(Reader reader) {
        char[] data = new char[GL20.GL_STENCIL_BUFFER_BIT];
        int offset = 0;
        while (true) {
            try {
                try {
                    int length = reader.read(data, offset, data.length - offset);
                    if (length != -1) {
                        if (length == 0) {
                            char[] newData = new char[data.length * 2];
                            System.arraycopy(data, 0, newData, 0, data.length);
                            data = newData;
                        } else {
                            offset += length;
                        }
                    } else {
                        StreamUtils.closeQuietly(reader);
                        return parse(data, 0, offset);
                    }
                } catch (IOException ex) {
                    throw new SerializationException("Error reading input.", ex);
                }
            } catch (Throwable th) {
                StreamUtils.closeQuietly(reader);
                throw th;
            }
        }
    }

    @Override // com.badlogic.gdx.utils.BaseJsonReader
    public JsonValue parse(InputStream input) {
        try {
            Reader reader = new InputStreamReader(input, "UTF-8");
            return parse(reader);
        } catch (Exception ex) {
            throw new SerializationException("Error reading stream.", ex);
        }
    }

    @Override // com.badlogic.gdx.utils.BaseJsonReader
    public JsonValue parse(FileHandle file) {
        try {
            Reader reader = file.reader("UTF-8");
            try {
                return parse(reader);
            } catch (Exception ex) {
                throw new SerializationException("Error parsing file: " + file, ex);
            }
        } catch (Exception ex2) {
            throw new SerializationException("Error reading file: " + file, ex2);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:119:0x0263  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x026b A[LOOP:5: B:577:0x0204->B:123:0x026b, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:162:0x02f7  */
    /* JADX WARN: Removed duplicated region for block: B:166:0x02fe A[LOOP:7: B:565:0x0292->B:166:0x02fe, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:352:0x06bb A[Catch: RuntimeException -> 0x06de, TRY_ENTER, TryCatch #16 {RuntimeException -> 0x06de, blocks: (B:325:0x0623, B:336:0x065e, B:352:0x06bb, B:353:0x06d7, B:343:0x0677, B:344:0x0695), top: B:545:0x0623 }] */
    /* JADX WARN: Removed duplicated region for block: B:492:0x09f4  */
    /* JADX WARN: Removed duplicated region for block: B:500:0x0a49  */
    /* JADX WARN: Removed duplicated region for block: B:521:0x0234 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:533:0x0169 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:539:0x02c8 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:592:0x0784 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:597:0x0774 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:600:0x075a A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:634:0x0306 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:645:0x02fd A[SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r3v26, types: [java.lang.Object, int[]] */
    /* JADX WARN: Type inference failed for: r3v35, types: [java.lang.Object, int[]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public com.badlogic.gdx.utils.JsonValue parse(char[] r38, int r39, int r40) {
        /*
            Method dump skipped, instructions count: 2782
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.JsonReader.parse(char[], int, int):com.badlogic.gdx.utils.JsonValue");
    }

    private static byte[] init__json_actions_0() {
        return new byte[]{0, 1, 1, 1, 2, 1, 3, 1, 4, 1, 5, 1, 6, 1, 7, 1, 8, 2, 0, 7, 2, 0, 8, 2, 1, 3, 2, 1, 5};
    }

    private static short[] init__json_key_offsets_0() {
        return new short[]{0, 0, 11, 13, 14, 16, 25, 31, 37, 39, 50, 57, 64, 73, 74, 83, 85, 87, 96, 98, 100, 101, 103, 105, 116, 123, 130, 141, 142, 153, 155, 157, 168, 170, 172, 174, 179, 184, 184};
    }

    private static char[] init__json_trans_keys_0() {
        return new char[]{'\r', ' ', Typography.quote, ',', '/', ':', '[', ']', '{', '\t', '\n', '*', '/', Typography.quote, '*', '/', '\r', ' ', Typography.quote, ',', '/', ':', '}', '\t', '\n', '\r', ' ', '/', ':', '\t', '\n', '\r', ' ', '/', ':', '\t', '\n', '*', '/', '\r', ' ', Typography.quote, ',', '/', ':', '[', ']', '{', '\t', '\n', '\t', '\n', '\r', ' ', ',', '/', '}', '\t', '\n', '\r', ' ', ',', '/', '}', '\r', ' ', Typography.quote, ',', '/', ':', '}', '\t', '\n', Typography.quote, '\r', ' ', Typography.quote, ',', '/', ':', '}', '\t', '\n', '*', '/', '*', '/', '\r', ' ', Typography.quote, ',', '/', ':', '}', '\t', '\n', '*', '/', '*', '/', Typography.quote, '*', '/', '*', '/', '\r', ' ', Typography.quote, ',', '/', ':', '[', ']', '{', '\t', '\n', '\t', '\n', '\r', ' ', ',', '/', ']', '\t', '\n', '\r', ' ', ',', '/', ']', '\r', ' ', Typography.quote, ',', '/', ':', '[', ']', '{', '\t', '\n', Typography.quote, '\r', ' ', Typography.quote, ',', '/', ':', '[', ']', '{', '\t', '\n', '*', '/', '*', '/', '\r', ' ', Typography.quote, ',', '/', ':', '[', ']', '{', '\t', '\n', '*', '/', '*', '/', '*', '/', '\r', ' ', '/', '\t', '\n', '\r', ' ', '/', '\t', '\n', 0};
    }

    private static byte[] init__json_single_lengths_0() {
        return new byte[]{0, 9, 2, 1, 2, 7, 4, 4, 2, 9, 7, 7, 7, 1, 7, 2, 2, 7, 2, 2, 1, 2, 2, 9, 7, 7, 9, 1, 9, 2, 2, 9, 2, 2, 2, 3, 3, 0, 0};
    }

    private static byte[] init__json_range_lengths_0() {
        return new byte[]{0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0};
    }

    private static short[] init__json_index_offsets_0() {
        return new short[]{0, 0, 11, 14, 16, 19, 28, 34, 40, 43, 54, 62, 70, 79, 81, 90, 93, 96, 105, 108, 111, 113, 116, 119, 130, 138, 146, 157, 159, 170, 173, 176, 187, 190, 193, 196, 201, 206, 207};
    }

    private static byte[] init__json_indicies_0() {
        return new byte[]{1, 1, 2, 3, 4, 3, 5, 3, 6, 1, 0, 7, 7, 3, 8, 3, 9, 9, 3, 11, 11, 12, 13, 14, 3, 15, 11, 10, 16, 16, 17, 18, 16, 3, 19, 19, 20, 21, 19, 3, 22, 22, 3, 21, 21, 24, 3, 25, 3, 26, 3, 27, 21, 23, 28, 29, 29, 28, 30, 31, 32, 3, 33, 34, 34, 33, 13, 35, 15, 3, 34, 34, 12, 36, 37, 3, 15, 34, 10, 16, 3, 36, 36, 12, 3, 38, 3, 3, 36, 10, 39, 39, 3, 40, 40, 3, 13, 13, 12, 3, 41, 3, 15, 13, 10, 42, 42, 3, 43, 43, 3, 28, 3, 44, 44, 3, 45, 45, 3, 47, 47, 48, 49, 50, 3, 51, 52, 53, 47, 46, 54, 55, 55, 54, 56, 57, 58, 3, 59, 60, 60, 59, 49, 61, 52, 3, 60, 60, 48, 62, 63, 3, 51, 52, 53, 60, 46, 54, 3, 62, 62, 48, 3, 64, 3, 51, 3, 53, 62, 46, 65, 65, 3, 66, 66, 3, 49, 49, 48, 3, 67, 3, 51, 52, 53, 49, 46, 68, 68, 3, 69, 69, 3, 70, 70, 3, 8, 8, 71, 8, 3, 72, 72, 73, 72, 3, 3, 3, 0};
    }

    private static byte[] init__json_trans_targs_0() {
        return new byte[]{35, 1, 3, 0, 4, 36, 36, 36, 36, 1, 6, 5, 13, 17, 22, 37, 7, 8, 9, 7, 8, 9, 7, 10, 20, 21, 11, 11, 11, 12, 17, 19, 37, 11, 12, 19, 14, 16, 15, 14, 12, 18, 17, 11, 9, 5, 24, 23, 27, 31, 34, 25, 38, 25, 25, 26, 31, 33, 38, 25, 26, 33, 28, 30, 29, 28, 26, 32, 31, 25, 23, 2, 36, 2};
    }

    private static byte[] init__json_trans_actions_0() {
        return new byte[]{13, 0, 15, 0, 0, 7, 3, 11, 1, 11, 17, 0, 20, 0, 0, 5, 1, 1, 1, 0, 0, 0, 11, 13, 15, 0, 7, 3, 1, 1, 1, 1, 23, 0, 0, 0, 0, 0, 0, 11, 11, 0, 11, 11, 11, 11, 13, 0, 15, 0, 0, 7, 9, 3, 1, 1, 1, 1, 26, 0, 0, 0, 0, 0, 0, 11, 11, 0, 11, 11, 11, 1, 0, 0};
    }

    private static byte[] init__json_eof_actions_0() {
        return new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0};
    }

    private void addChild(String name, JsonValue child) {
        child.setName(name);
        JsonValue jsonValue = this.current;
        if (jsonValue == null) {
            this.current = child;
            this.root = child;
        } else if (jsonValue.isArray() || this.current.isObject()) {
            JsonValue jsonValue2 = this.current;
            child.parent = jsonValue2;
            if (jsonValue2.size == 0) {
                this.current.child = child;
            } else {
                JsonValue last = this.lastChild.pop();
                last.next = child;
                child.prev = last;
            }
            this.lastChild.add(child);
            this.current.size++;
        } else {
            this.root = this.current;
        }
    }

    protected void startObject(String name) {
        JsonValue value = new JsonValue(JsonValue.ValueType.object);
        if (this.current != null) {
            addChild(name, value);
        }
        this.elements.add(value);
        this.current = value;
    }

    protected void startArray(String name) {
        JsonValue value = new JsonValue(JsonValue.ValueType.array);
        if (this.current != null) {
            addChild(name, value);
        }
        this.elements.add(value);
        this.current = value;
    }

    protected void pop() {
        this.root = this.elements.pop();
        if (this.current.size > 0) {
            this.lastChild.pop();
        }
        this.current = this.elements.size > 0 ? this.elements.peek() : null;
    }

    protected void string(String name, String value) {
        addChild(name, new JsonValue(value));
    }

    protected void number(String name, double value, String stringValue) {
        addChild(name, new JsonValue(value, stringValue));
    }

    protected void number(String name, long value, String stringValue) {
        addChild(name, new JsonValue(value, stringValue));
    }

    protected void bool(String name, boolean value) {
        addChild(name, new JsonValue(value));
    }

    private String unescape(String value) {
        int length = value.length();
        StringBuilder buffer = new StringBuilder(length + 16);
        int i = 0;
        while (i < length) {
            int i2 = i + 1;
            char c = value.charAt(i);
            if (c != '\\') {
                buffer.append(c);
                i = i2;
            } else if (i2 == length) {
                break;
            } else {
                int i3 = i2 + 1;
                char c2 = value.charAt(i2);
                if (c2 == 'u') {
                    buffer.append(Character.toChars(Integer.parseInt(value.substring(i3, i3 + 4), 16)));
                    i = i3 + 4;
                } else {
                    if (c2 != '\"' && c2 != '/' && c2 != '\\') {
                        if (c2 == 'b') {
                            c2 = '\b';
                        } else if (c2 == 'f') {
                            c2 = '\f';
                        } else if (c2 == 'n') {
                            c2 = '\n';
                        } else if (c2 == 'r') {
                            c2 = '\r';
                        } else if (c2 == 't') {
                            c2 = '\t';
                        } else {
                            throw new SerializationException("Illegal escaped character: \\" + c2);
                        }
                    }
                    buffer.append(c2);
                    i = i3;
                }
            }
        }
        return buffer.toString();
    }
}