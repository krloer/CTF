package com.badlogic.gdx.utils;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.ObjectMap;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import kotlin.text.Typography;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class XmlReader {
    static final int xml_en_elementBody = 15;
    static final int xml_en_main = 1;
    static final int xml_error = 0;
    static final int xml_first_final = 34;
    static final int xml_start = 1;
    private Element current;
    private Element root;
    private static final byte[] _xml_actions = init__xml_actions_0();
    private static final byte[] _xml_key_offsets = init__xml_key_offsets_0();
    private static final char[] _xml_trans_keys = init__xml_trans_keys_0();
    private static final byte[] _xml_single_lengths = init__xml_single_lengths_0();
    private static final byte[] _xml_range_lengths = init__xml_range_lengths_0();
    private static final short[] _xml_index_offsets = init__xml_index_offsets_0();
    private static final byte[] _xml_indicies = init__xml_indicies_0();
    private static final byte[] _xml_trans_targs = init__xml_trans_targs_0();
    private static final byte[] _xml_trans_actions = init__xml_trans_actions_0();
    private final Array<Element> elements = new Array<>(8);
    private final StringBuilder textBuffer = new StringBuilder(64);

    public Element parse(String xml) {
        char[] data = xml.toCharArray();
        return parse(data, 0, data.length);
    }

    public Element parse(Reader reader) {
        try {
            try {
                char[] data = new char[GL20.GL_STENCIL_BUFFER_BIT];
                int offset = 0;
                while (true) {
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
                        return parse(data, 0, offset);
                    }
                }
            } catch (IOException ex) {
                throw new SerializationException(ex);
            }
        } finally {
            StreamUtils.closeQuietly(reader);
        }
    }

    public Element parse(InputStream input) {
        try {
            try {
                return parse(new InputStreamReader(input, "UTF-8"));
            } catch (IOException ex) {
                throw new SerializationException(ex);
            }
        } finally {
            StreamUtils.closeQuietly(input);
        }
    }

    public Element parse(FileHandle file) {
        try {
            return parse(file.reader("UTF-8"));
        } catch (Exception ex) {
            throw new SerializationException("Error parsing file: " + file, ex);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:172:0x02d0 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:175:0x02cd A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:178:0x02c1 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00ae  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public com.badlogic.gdx.utils.XmlReader.Element parse(char[] r26, int r27, int r28) {
        /*
            Method dump skipped, instructions count: 864
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.XmlReader.parse(char[], int, int):com.badlogic.gdx.utils.XmlReader$Element");
    }

    private static byte[] init__xml_actions_0() {
        return new byte[]{0, 1, 0, 1, 1, 1, 2, 1, 3, 1, 4, 1, 5, 1, 6, 1, 7, 2, 0, 6, 2, 1, 4, 2, 2, 4};
    }

    private static byte[] init__xml_key_offsets_0() {
        return new byte[]{0, 0, 4, 9, 14, 20, 26, 30, 35, 36, 37, 42, 46, 50, 51, 52, 56, 57, 62, 67, 73, 79, 83, 88, 89, 90, 95, 99, 103, 104, 108, 109, 110, 111, 112, 115};
    }

    private static char[] init__xml_trans_keys_0() {
        return new char[]{' ', Typography.less, '\t', '\r', ' ', '/', Typography.greater, '\t', '\r', ' ', '/', Typography.greater, '\t', '\r', ' ', '/', '=', Typography.greater, '\t', '\r', ' ', '/', '=', Typography.greater, '\t', '\r', ' ', '=', '\t', '\r', ' ', Typography.quote, '\'', '\t', '\r', Typography.quote, Typography.quote, ' ', '/', Typography.greater, '\t', '\r', ' ', Typography.greater, '\t', '\r', ' ', Typography.greater, '\t', '\r', '\'', '\'', ' ', Typography.less, '\t', '\r', Typography.less, ' ', '/', Typography.greater, '\t', '\r', ' ', '/', Typography.greater, '\t', '\r', ' ', '/', '=', Typography.greater, '\t', '\r', ' ', '/', '=', Typography.greater, '\t', '\r', ' ', '=', '\t', '\r', ' ', Typography.quote, '\'', '\t', '\r', Typography.quote, Typography.quote, ' ', '/', Typography.greater, '\t', '\r', ' ', Typography.greater, '\t', '\r', ' ', Typography.greater, '\t', '\r', Typography.less, ' ', '/', '\t', '\r', Typography.greater, Typography.greater, '\'', '\'', ' ', '\t', '\r', 0};
    }

    private static byte[] init__xml_single_lengths_0() {
        return new byte[]{0, 2, 3, 3, 4, 4, 2, 3, 1, 1, 3, 2, 2, 1, 1, 2, 1, 3, 3, 4, 4, 2, 3, 1, 1, 3, 2, 2, 1, 2, 1, 1, 1, 1, 1, 0};
    }

    private static byte[] init__xml_range_lengths_0() {
        return new byte[]{0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0};
    }

    private static short[] init__xml_index_offsets_0() {
        return new short[]{0, 0, 4, 9, 14, 20, 26, 30, 35, 37, 39, 44, 48, 52, 54, 56, 60, 62, 67, 72, 78, 84, 88, 93, 95, 97, 102, 106, 110, 112, 116, 118, 120, 122, 124, 127};
    }

    private static byte[] init__xml_indicies_0() {
        return new byte[]{0, 2, 0, 1, 2, 1, 1, 2, 3, 5, 6, 7, 5, 4, 9, 10, 1, 11, 9, 8, 13, 1, 14, 1, 13, 12, 15, 16, 15, 1, 16, 17, 18, 16, 1, 20, 19, 22, 21, 9, 10, 11, 9, 1, 23, 24, 23, 1, 25, 11, 25, 1, 20, 26, 22, 27, 29, 30, 29, 28, 32, 31, 30, 34, 1, 30, 33, 36, 37, 38, 36, 35, 40, 41, 1, 42, 40, 39, 44, 1, 45, 1, 44, 43, 46, 47, 46, 1, 47, 48, 49, 47, 1, 51, 50, 53, 52, 40, 41, 42, 40, 1, 54, 55, 54, 1, 56, 42, 56, 1, 57, 1, 57, 34, 57, 1, 1, 58, 59, 58, 51, 60, 53, 61, 62, 62, 1, 1, 0};
    }

    private static byte[] init__xml_trans_targs_0() {
        return new byte[]{1, 0, 2, 3, 3, 4, 11, 34, 5, 4, 11, 34, 5, 6, 7, 6, 7, 8, 13, 9, 10, 9, 10, 12, 34, 12, 14, 14, 16, 15, 17, 16, 17, 18, 30, 18, 19, 26, 28, 20, 19, 26, 28, 20, 21, 22, 21, 22, 23, 32, 24, 25, 24, 25, 27, 28, 27, 29, 31, 35, 33, 33, 34};
    }

    private static byte[] init__xml_trans_actions_0() {
        return new byte[]{0, 0, 0, 1, 0, 3, 3, 20, 1, 0, 0, 9, 0, 11, 11, 0, 0, 0, 0, 1, 17, 0, 13, 5, 23, 0, 1, 0, 1, 0, 0, 0, 15, 1, 0, 0, 3, 3, 20, 1, 0, 0, 9, 0, 11, 11, 0, 0, 0, 0, 1, 17, 0, 13, 5, 23, 0, 0, 0, 7, 1, 0, 0};
    }

    protected void open(String name) {
        Element child = new Element(name, this.current);
        Element parent = this.current;
        if (parent != null) {
            parent.addChild(child);
        }
        this.elements.add(child);
        this.current = child;
    }

    protected void attribute(String name, String value) {
        this.current.setAttribute(name, value);
    }

    protected String entity(String name) {
        if (name.equals("lt")) {
            return "<";
        }
        if (name.equals("gt")) {
            return ">";
        }
        if (name.equals("amp")) {
            return "&";
        }
        if (name.equals("apos")) {
            return "'";
        }
        if (name.equals("quot")) {
            return "\"";
        }
        if (name.startsWith("#x")) {
            return Character.toString((char) Integer.parseInt(name.substring(2), 16));
        }
        return null;
    }

    protected void text(String text) {
        String str;
        String existing = this.current.getText();
        Element element = this.current;
        if (existing != null) {
            str = existing + text;
        } else {
            str = text;
        }
        element.setText(str);
    }

    protected void close() {
        this.root = this.elements.pop();
        this.current = this.elements.size > 0 ? this.elements.peek() : null;
    }

    /* loaded from: classes.dex */
    public static class Element {
        private ObjectMap<String, String> attributes;
        private Array<Element> children;
        private final String name;
        private Element parent;
        private String text;

        public Element(String name, Element parent) {
            this.name = name;
            this.parent = parent;
        }

        public String getName() {
            return this.name;
        }

        public ObjectMap<String, String> getAttributes() {
            return this.attributes;
        }

        public String getAttribute(String name) {
            ObjectMap<String, String> objectMap = this.attributes;
            if (objectMap == null) {
                throw new GdxRuntimeException("Element " + this.name + " doesn't have attribute: " + name);
            }
            String value = objectMap.get(name);
            if (value == null) {
                throw new GdxRuntimeException("Element " + this.name + " doesn't have attribute: " + name);
            }
            return value;
        }

        public String getAttribute(String name, String defaultValue) {
            String value;
            ObjectMap<String, String> objectMap = this.attributes;
            return (objectMap == null || (value = objectMap.get(name)) == null) ? defaultValue : value;
        }

        public boolean hasAttribute(String name) {
            ObjectMap<String, String> objectMap = this.attributes;
            if (objectMap == null) {
                return false;
            }
            return objectMap.containsKey(name);
        }

        public void setAttribute(String name, String value) {
            if (this.attributes == null) {
                this.attributes = new ObjectMap<>(8);
            }
            this.attributes.put(name, value);
        }

        public int getChildCount() {
            Array<Element> array = this.children;
            if (array == null) {
                return 0;
            }
            return array.size;
        }

        public Element getChild(int index) {
            Array<Element> array = this.children;
            if (array == null) {
                throw new GdxRuntimeException("Element has no children: " + this.name);
            }
            return array.get(index);
        }

        public void addChild(Element element) {
            if (this.children == null) {
                this.children = new Array<>(8);
            }
            this.children.add(element);
        }

        public String getText() {
            return this.text;
        }

        public void setText(String text) {
            this.text = text;
        }

        public void removeChild(int index) {
            Array<Element> array = this.children;
            if (array != null) {
                array.removeIndex(index);
            }
        }

        public void removeChild(Element child) {
            Array<Element> array = this.children;
            if (array != null) {
                array.removeValue(child, true);
            }
        }

        public void remove() {
            this.parent.removeChild(this);
        }

        public Element getParent() {
            return this.parent;
        }

        public String toString() {
            return toString(BuildConfig.FLAVOR);
        }

        public String toString(String indent) {
            String str;
            StringBuilder buffer = new StringBuilder(128);
            buffer.append(indent);
            buffer.append(Typography.less);
            buffer.append(this.name);
            ObjectMap<String, String> objectMap = this.attributes;
            if (objectMap != null) {
                ObjectMap.Entries<String, String> it = objectMap.entries().iterator();
                while (it.hasNext()) {
                    ObjectMap.Entry entry = it.next();
                    buffer.append(' ');
                    buffer.append((String) entry.key);
                    buffer.append("=\"");
                    buffer.append((String) entry.value);
                    buffer.append(Typography.quote);
                }
            }
            if (this.children == null && ((str = this.text) == null || str.length() == 0)) {
                buffer.append("/>");
            } else {
                buffer.append(">\n");
                String childIndent = indent + '\t';
                String str2 = this.text;
                if (str2 != null && str2.length() > 0) {
                    buffer.append(childIndent);
                    buffer.append(this.text);
                    buffer.append('\n');
                }
                Array<Element> array = this.children;
                if (array != null) {
                    Array.ArrayIterator<Element> it2 = array.iterator();
                    while (it2.hasNext()) {
                        Element child = it2.next();
                        buffer.append(child.toString(childIndent));
                        buffer.append('\n');
                    }
                }
                buffer.append(indent);
                buffer.append("</");
                buffer.append(this.name);
                buffer.append(Typography.greater);
            }
            return buffer.toString();
        }

        public Element getChildByName(String name) {
            if (this.children == null) {
                return null;
            }
            for (int i = 0; i < this.children.size; i++) {
                Element element = this.children.get(i);
                if (element.name.equals(name)) {
                    return element;
                }
            }
            return null;
        }

        public boolean hasChild(String name) {
            return (this.children == null || getChildByName(name) == null) ? false : true;
        }

        public Element getChildByNameRecursive(String name) {
            if (this.children == null) {
                return null;
            }
            for (int i = 0; i < this.children.size; i++) {
                Element element = this.children.get(i);
                if (element.name.equals(name)) {
                    return element;
                }
                Element found = element.getChildByNameRecursive(name);
                if (found != null) {
                    return found;
                }
            }
            return null;
        }

        public boolean hasChildRecursive(String name) {
            return (this.children == null || getChildByNameRecursive(name) == null) ? false : true;
        }

        public Array<Element> getChildrenByName(String name) {
            Array<Element> result = new Array<>();
            if (this.children == null) {
                return result;
            }
            for (int i = 0; i < this.children.size; i++) {
                Element child = this.children.get(i);
                if (child.name.equals(name)) {
                    result.add(child);
                }
            }
            return result;
        }

        public Array<Element> getChildrenByNameRecursively(String name) {
            Array<Element> result = new Array<>();
            getChildrenByNameRecursively(name, result);
            return result;
        }

        private void getChildrenByNameRecursively(String name, Array<Element> result) {
            if (this.children == null) {
                return;
            }
            for (int i = 0; i < this.children.size; i++) {
                Element child = this.children.get(i);
                if (child.name.equals(name)) {
                    result.add(child);
                }
                child.getChildrenByNameRecursively(name, result);
            }
        }

        public float getFloatAttribute(String name) {
            return Float.parseFloat(getAttribute(name));
        }

        public float getFloatAttribute(String name, float defaultValue) {
            String value = getAttribute(name, null);
            return value == null ? defaultValue : Float.parseFloat(value);
        }

        public int getIntAttribute(String name) {
            return Integer.parseInt(getAttribute(name));
        }

        public int getIntAttribute(String name, int defaultValue) {
            String value = getAttribute(name, null);
            return value == null ? defaultValue : Integer.parseInt(value);
        }

        public boolean getBooleanAttribute(String name) {
            return Boolean.parseBoolean(getAttribute(name));
        }

        public boolean getBooleanAttribute(String name, boolean defaultValue) {
            String value = getAttribute(name, null);
            return value == null ? defaultValue : Boolean.parseBoolean(value);
        }

        public String get(String name) {
            String value = get(name, null);
            if (value == null) {
                throw new GdxRuntimeException("Element " + this.name + " doesn't have attribute or child: " + name);
            }
            return value;
        }

        public String get(String name, String defaultValue) {
            String value;
            String value2;
            ObjectMap<String, String> objectMap = this.attributes;
            if (objectMap == null || (value2 = objectMap.get(name)) == null) {
                Element child = getChildByName(name);
                return (child == null || (value = child.getText()) == null) ? defaultValue : value;
            }
            return value2;
        }

        public int getInt(String name) {
            String value = get(name, null);
            if (value == null) {
                throw new GdxRuntimeException("Element " + this.name + " doesn't have attribute or child: " + name);
            }
            return Integer.parseInt(value);
        }

        public int getInt(String name, int defaultValue) {
            String value = get(name, null);
            return value == null ? defaultValue : Integer.parseInt(value);
        }

        public float getFloat(String name) {
            String value = get(name, null);
            if (value == null) {
                throw new GdxRuntimeException("Element " + this.name + " doesn't have attribute or child: " + name);
            }
            return Float.parseFloat(value);
        }

        public float getFloat(String name, float defaultValue) {
            String value = get(name, null);
            return value == null ? defaultValue : Float.parseFloat(value);
        }

        public boolean getBoolean(String name) {
            String value = get(name, null);
            if (value == null) {
                throw new GdxRuntimeException("Element " + this.name + " doesn't have attribute or child: " + name);
            }
            return Boolean.parseBoolean(value);
        }

        public boolean getBoolean(String name, boolean defaultValue) {
            String value = get(name, null);
            return value == null ? defaultValue : Boolean.parseBoolean(value);
        }
    }
}