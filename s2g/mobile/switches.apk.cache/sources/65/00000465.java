package com.badlogic.gdx.utils;

import com.badlogic.gdx.Input;
import java.io.IOException;
import java.io.Writer;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.regex.Pattern;
import kotlin.text.Typography;

/* loaded from: classes.dex */
public class JsonWriter extends Writer {
    private JsonObject current;
    private boolean named;
    final Writer writer;
    private final Array<JsonObject> stack = new Array<>();
    private OutputType outputType = OutputType.json;
    private boolean quoteLongValues = false;

    public JsonWriter(Writer writer) {
        this.writer = writer;
    }

    public Writer getWriter() {
        return this.writer;
    }

    public void setOutputType(OutputType outputType) {
        this.outputType = outputType;
    }

    public void setQuoteLongValues(boolean quoteLongValues) {
        this.quoteLongValues = quoteLongValues;
    }

    public JsonWriter name(String name) throws IOException {
        JsonObject jsonObject = this.current;
        if (jsonObject == null || jsonObject.array) {
            throw new IllegalStateException("Current item must be an object.");
        }
        if (!this.current.needsComma) {
            this.current.needsComma = true;
        } else {
            this.writer.write(44);
        }
        this.writer.write(this.outputType.quoteName(name));
        this.writer.write(58);
        this.named = true;
        return this;
    }

    public JsonWriter object() throws IOException {
        requireCommaOrName();
        Array<JsonObject> array = this.stack;
        JsonObject jsonObject = new JsonObject(false);
        this.current = jsonObject;
        array.add(jsonObject);
        return this;
    }

    public JsonWriter array() throws IOException {
        requireCommaOrName();
        Array<JsonObject> array = this.stack;
        JsonObject jsonObject = new JsonObject(true);
        this.current = jsonObject;
        array.add(jsonObject);
        return this;
    }

    public JsonWriter value(Object value) throws IOException {
        if (this.quoteLongValues && ((value instanceof Long) || (value instanceof Double) || (value instanceof BigDecimal) || (value instanceof BigInteger))) {
            value = value.toString();
        } else if (value instanceof Number) {
            Number number = (Number) value;
            long longValue = number.longValue();
            if (number.doubleValue() == longValue) {
                value = Long.valueOf(longValue);
            }
        }
        requireCommaOrName();
        this.writer.write(this.outputType.quoteValue(value));
        return this;
    }

    public JsonWriter json(String json) throws IOException {
        requireCommaOrName();
        this.writer.write(json);
        return this;
    }

    private void requireCommaOrName() throws IOException {
        JsonObject jsonObject = this.current;
        if (jsonObject == null) {
            return;
        }
        if (jsonObject.array) {
            if (!this.current.needsComma) {
                this.current.needsComma = true;
            } else {
                this.writer.write(44);
            }
        } else if (!this.named) {
            throw new IllegalStateException("Name must be set.");
        } else {
            this.named = false;
        }
    }

    public JsonWriter object(String name) throws IOException {
        return name(name).object();
    }

    public JsonWriter array(String name) throws IOException {
        return name(name).array();
    }

    public JsonWriter set(String name, Object value) throws IOException {
        return name(name).value(value);
    }

    public JsonWriter json(String name, String json) throws IOException {
        return name(name).json(json);
    }

    public JsonWriter pop() throws IOException {
        if (this.named) {
            throw new IllegalStateException("Expected an object, array, or value since a name was set.");
        }
        this.stack.pop().close();
        this.current = this.stack.size == 0 ? null : this.stack.peek();
        return this;
    }

    @Override // java.io.Writer
    public void write(char[] cbuf, int off, int len) throws IOException {
        this.writer.write(cbuf, off, len);
    }

    @Override // java.io.Writer, java.io.Flushable
    public void flush() throws IOException {
        this.writer.flush();
    }

    @Override // java.io.Writer, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        while (this.stack.size > 0) {
            pop();
        }
        this.writer.close();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class JsonObject {
        final boolean array;
        boolean needsComma;

        JsonObject(boolean array) throws IOException {
            this.array = array;
            JsonWriter.this.writer.write(array ? 91 : Input.Keys.END);
        }

        void close() throws IOException {
            JsonWriter.this.writer.write(this.array ? 93 : 125);
        }
    }

    /* loaded from: classes.dex */
    public enum OutputType {
        json,
        javascript,
        minimal;
        
        private static Pattern javascriptPattern = Pattern.compile("^[a-zA-Z_$][a-zA-Z_$0-9]*$");
        private static Pattern minimalNamePattern = Pattern.compile("^[^\":,}/ ][^:]*$");
        private static Pattern minimalValuePattern = Pattern.compile("^[^\":,{\\[\\]/ ][^}\\],]*$");

        public String quoteValue(Object value) {
            int length;
            if (value == null) {
                return "null";
            }
            String string = value.toString();
            if ((value instanceof Number) || (value instanceof Boolean)) {
                return string;
            }
            StringBuilder buffer = new StringBuilder(string);
            buffer.replace('\\', "\\\\").replace('\r', "\\r").replace('\n', "\\n").replace('\t', "\\t");
            if (this == minimal && !string.equals("true") && !string.equals("false") && !string.equals("null") && !string.contains("//") && !string.contains("/*") && (length = buffer.length()) > 0 && buffer.charAt(length - 1) != ' ' && minimalValuePattern.matcher(buffer).matches()) {
                return buffer.toString();
            }
            return Typography.quote + buffer.replace(Typography.quote, "\\\"").toString() + Typography.quote;
        }

        /* JADX WARN: Code restructure failed: missing block: B:5:0x0030, code lost:
            if (r1 != 2) goto L10;
         */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct code enable 'Show inconsistent code' option in preferences
        */
        public java.lang.String quoteName(java.lang.String r5) {
            /*
                r4 = this;
                com.badlogic.gdx.utils.StringBuilder r0 = new com.badlogic.gdx.utils.StringBuilder
                r0.<init>(r5)
                r1 = 92
                java.lang.String r2 = "\\\\"
                com.badlogic.gdx.utils.StringBuilder r1 = r0.replace(r1, r2)
                r2 = 13
                java.lang.String r3 = "\\r"
                com.badlogic.gdx.utils.StringBuilder r1 = r1.replace(r2, r3)
                r2 = 10
                java.lang.String r3 = "\\n"
                com.badlogic.gdx.utils.StringBuilder r1 = r1.replace(r2, r3)
                r2 = 9
                java.lang.String r3 = "\\t"
                r1.replace(r2, r3)
                int[] r1 = com.badlogic.gdx.utils.JsonWriter.AnonymousClass1.$SwitchMap$com$badlogic$gdx$utils$JsonWriter$OutputType
                int r2 = r4.ordinal()
                r1 = r1[r2]
                r2 = 1
                if (r1 == r2) goto L33
                r2 = 2
                if (r1 == r2) goto L54
                goto L65
            L33:
                java.lang.String r1 = "//"
                boolean r1 = r5.contains(r1)
                if (r1 != 0) goto L54
                java.lang.String r1 = "/*"
                boolean r1 = r5.contains(r1)
                if (r1 != 0) goto L54
                java.util.regex.Pattern r1 = com.badlogic.gdx.utils.JsonWriter.OutputType.minimalNamePattern
                java.util.regex.Matcher r1 = r1.matcher(r0)
                boolean r1 = r1.matches()
                if (r1 == 0) goto L54
                java.lang.String r1 = r0.toString()
                return r1
            L54:
                java.util.regex.Pattern r1 = com.badlogic.gdx.utils.JsonWriter.OutputType.javascriptPattern
                java.util.regex.Matcher r1 = r1.matcher(r0)
                boolean r1 = r1.matches()
                if (r1 == 0) goto L65
                java.lang.String r1 = r0.toString()
                return r1
            L65:
                java.lang.StringBuilder r1 = new java.lang.StringBuilder
                r1.<init>()
                r2 = 34
                r1.append(r2)
                java.lang.String r3 = "\\\""
                com.badlogic.gdx.utils.StringBuilder r3 = r0.replace(r2, r3)
                java.lang.String r3 = r3.toString()
                r1.append(r3)
                r1.append(r2)
                java.lang.String r1 = r1.toString()
                return r1
            */
            throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.JsonWriter.OutputType.quoteName(java.lang.String):java.lang.String");
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: com.badlogic.gdx.utils.JsonWriter$1  reason: invalid class name */
    /* loaded from: classes.dex */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$badlogic$gdx$utils$JsonWriter$OutputType = new int[OutputType.values().length];

        static {
            try {
                $SwitchMap$com$badlogic$gdx$utils$JsonWriter$OutputType[OutputType.minimal.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$utils$JsonWriter$OutputType[OutputType.javascript.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
        }
    }
}