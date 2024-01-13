package com.badlogic.gdx.utils;

import java.io.IOException;
import java.io.Writer;

/* loaded from: classes.dex */
public class XmlWriter extends Writer {
    private String currentElement;
    public int indent;
    private boolean indentNextClose;
    private final Array<String> stack = new Array<>();
    private final Writer writer;

    public XmlWriter(Writer writer) {
        this.writer = writer;
    }

    private void indent() throws IOException {
        int count = this.indent;
        if (this.currentElement != null) {
            count++;
        }
        for (int i = 0; i < count; i++) {
            this.writer.write(9);
        }
    }

    public XmlWriter element(String name) throws IOException {
        if (startElementContent()) {
            this.writer.write(10);
        }
        indent();
        this.writer.write(60);
        this.writer.write(name);
        this.currentElement = name;
        return this;
    }

    public XmlWriter element(String name, Object text) throws IOException {
        return element(name).text(text).pop();
    }

    private boolean startElementContent() throws IOException {
        String str = this.currentElement;
        if (str == null) {
            return false;
        }
        this.indent++;
        this.stack.add(str);
        this.currentElement = null;
        this.writer.write(">");
        return true;
    }

    public XmlWriter attribute(String name, Object value) throws IOException {
        if (this.currentElement == null) {
            throw new IllegalStateException();
        }
        this.writer.write(32);
        this.writer.write(name);
        this.writer.write("=\"");
        this.writer.write(value == null ? "null" : value.toString());
        this.writer.write(34);
        return this;
    }

    public XmlWriter text(Object text) throws IOException {
        startElementContent();
        String string = text == null ? "null" : text.toString();
        this.indentNextClose = string.length() > 64;
        if (this.indentNextClose) {
            this.writer.write(10);
            indent();
        }
        this.writer.write(string);
        if (this.indentNextClose) {
            this.writer.write(10);
        }
        return this;
    }

    public XmlWriter pop() throws IOException {
        if (this.currentElement != null) {
            this.writer.write("/>\n");
            this.currentElement = null;
        } else {
            this.indent = Math.max(this.indent - 1, 0);
            if (this.indentNextClose) {
                indent();
            }
            this.writer.write("</");
            this.writer.write(this.stack.pop());
            this.writer.write(">\n");
        }
        this.indentNextClose = true;
        return this;
    }

    @Override // java.io.Writer, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        while (this.stack.size != 0) {
            pop();
        }
        this.writer.close();
    }

    @Override // java.io.Writer
    public void write(char[] cbuf, int off, int len) throws IOException {
        startElementContent();
        this.writer.write(cbuf, off, len);
    }

    @Override // java.io.Writer, java.io.Flushable
    public void flush() throws IOException {
        this.writer.flush();
    }
}