package com.badlogic.gdx.utils;

import com.badlogic.gdx.net.HttpStatus;
import com.badlogic.gdx.utils.ObjectMap;
import java.io.IOException;
import java.io.Writer;
import java.util.Date;

/* loaded from: classes.dex */
public final class PropertiesUtils {
    private static final int CONTINUE = 3;
    private static final int IGNORE = 5;
    private static final int KEY_DONE = 4;
    private static final String LINE_SEPARATOR = "\n";
    private static final int NONE = 0;
    private static final int SLASH = 1;
    private static final int UNICODE = 2;

    private PropertiesUtils() {
    }

    /* JADX WARN: Removed duplicated region for block: B:107:0x0128 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:111:0x012f  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x0148  */
    /* JADX WARN: Removed duplicated region for block: B:154:0x0126 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:97:0x0115  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static void load(com.badlogic.gdx.utils.ObjectMap<java.lang.String, java.lang.String> r17, java.io.Reader r18) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 367
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.PropertiesUtils.load(com.badlogic.gdx.utils.ObjectMap, java.io.Reader):void");
    }

    public static void store(ObjectMap<String, String> properties, Writer writer, String comment) throws IOException {
        storeImpl(properties, writer, comment, false);
    }

    private static void storeImpl(ObjectMap<String, String> properties, Writer writer, String comment, boolean escapeUnicode) throws IOException {
        if (comment != null) {
            writeComment(writer, comment);
        }
        writer.write("#");
        writer.write(new Date().toString());
        writer.write(LINE_SEPARATOR);
        StringBuilder sb = new StringBuilder((int) HttpStatus.SC_OK);
        ObjectMap.Entries<String, String> it = properties.entries().iterator();
        while (it.hasNext()) {
            ObjectMap.Entry entry = it.next();
            dumpString(sb, (String) entry.key, true, escapeUnicode);
            sb.append('=');
            dumpString(sb, (String) entry.value, false, escapeUnicode);
            writer.write(LINE_SEPARATOR);
            writer.write(sb.toString());
            sb.setLength(0);
        }
        writer.flush();
    }

    private static void dumpString(StringBuilder outBuffer, String string, boolean escapeSpace, boolean escapeUnicode) {
        int len = string.length();
        for (int i = 0; i < len; i++) {
            char ch = string.charAt(i);
            if (ch > '=' && ch < 127) {
                outBuffer.append(ch == '\\' ? "\\\\" : Character.valueOf(ch));
            } else if (ch == '\t') {
                outBuffer.append("\\t");
            } else if (ch == '\n') {
                outBuffer.append("\\n");
            } else if (ch == '\f') {
                outBuffer.append("\\f");
            } else if (ch == '\r') {
                outBuffer.append("\\r");
            } else if (ch != ' ') {
                if (ch == '!' || ch == '#' || ch == ':' || ch == '=') {
                    outBuffer.append('\\').append(ch);
                } else if ((ch < ' ' || ch > '~') & escapeUnicode) {
                    String hex = Integer.toHexString(ch);
                    outBuffer.append("\\u");
                    for (int j = 0; j < 4 - hex.length(); j++) {
                        outBuffer.append('0');
                    }
                    outBuffer.append(hex);
                } else {
                    outBuffer.append(ch);
                }
            } else if (i == 0 || escapeSpace) {
                outBuffer.append("\\ ");
            } else {
                outBuffer.append(ch);
            }
        }
    }

    private static void writeComment(Writer writer, String comment) throws IOException {
        writer.write("#");
        int len = comment.length();
        int curIndex = 0;
        int lastIndex = 0;
        while (curIndex < len) {
            char c = comment.charAt(curIndex);
            if (c > 255 || c == '\n' || c == '\r') {
                if (lastIndex != curIndex) {
                    writer.write(comment.substring(lastIndex, curIndex));
                }
                if (c > 255) {
                    String hex = Integer.toHexString(c);
                    writer.write("\\u");
                    for (int j = 0; j < 4 - hex.length(); j++) {
                        writer.write(48);
                    }
                    writer.write(hex);
                } else {
                    writer.write(LINE_SEPARATOR);
                    if (c == '\r' && curIndex != len - 1 && comment.charAt(curIndex + 1) == '\n') {
                        curIndex++;
                    }
                    if (curIndex == len - 1 || (comment.charAt(curIndex + 1) != '#' && comment.charAt(curIndex + 1) != '!')) {
                        writer.write("#");
                    }
                }
                lastIndex = curIndex + 1;
            }
            curIndex++;
        }
        if (lastIndex != curIndex) {
            writer.write(comment.substring(lastIndex, curIndex));
        }
        writer.write(LINE_SEPARATOR);
    }
}