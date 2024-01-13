package com.badlogic.gdx.utils;

import java.text.MessageFormat;
import java.util.Locale;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
class TextFormatter {
    private StringBuilder buffer = new StringBuilder();
    private MessageFormat messageFormat;

    public TextFormatter(Locale locale, boolean useMessageFormat) {
        if (useMessageFormat) {
            this.messageFormat = new MessageFormat(BuildConfig.FLAVOR, locale);
        }
    }

    public String format(String pattern, Object... args) {
        MessageFormat messageFormat = this.messageFormat;
        if (messageFormat != null) {
            messageFormat.applyPattern(replaceEscapeChars(pattern));
            return this.messageFormat.format(args);
        }
        return simpleFormat(pattern, args);
    }

    private String replaceEscapeChars(String pattern) {
        this.buffer.setLength(0);
        boolean changed = false;
        int len = pattern.length();
        int i = 0;
        while (i < len) {
            char ch = pattern.charAt(i);
            if (ch == '\'') {
                changed = true;
                this.buffer.append("''");
            } else if (ch == '{') {
                int j = i + 1;
                while (j < len && pattern.charAt(j) == '{') {
                    j++;
                }
                int escaped = (j - i) / 2;
                if (escaped > 0) {
                    this.buffer.append('\'');
                    do {
                        this.buffer.append('{');
                        escaped--;
                    } while (escaped > 0);
                    this.buffer.append('\'');
                    changed = true;
                }
                if ((j - i) % 2 != 0) {
                    this.buffer.append('{');
                }
                i = j - 1;
            } else {
                this.buffer.append(ch);
            }
            i++;
        }
        return changed ? this.buffer.toString() : pattern;
    }

    private String simpleFormat(String pattern, Object... args) {
        this.buffer.setLength(0);
        boolean changed = false;
        int placeholder = -1;
        int patternLength = pattern.length();
        int i = 0;
        while (i < patternLength) {
            char ch = pattern.charAt(i);
            if (placeholder < 0) {
                if (ch == '{') {
                    changed = true;
                    if (i + 1 < patternLength && pattern.charAt(i + 1) == '{') {
                        this.buffer.append(ch);
                        i++;
                    } else {
                        placeholder = 0;
                    }
                } else {
                    this.buffer.append(ch);
                }
            } else if (ch == '}') {
                if (placeholder < args.length) {
                    if (pattern.charAt(i - 1) == '{') {
                        throw new IllegalArgumentException("Missing argument index after a left curly brace");
                    }
                    if (args[placeholder] == null) {
                        this.buffer.append("null");
                    } else {
                        this.buffer.append(args[placeholder].toString());
                    }
                    placeholder = -1;
                } else {
                    throw new IllegalArgumentException("Argument index out of bounds: " + placeholder);
                }
            } else if (ch < '0' || ch > '9') {
                throw new IllegalArgumentException("Unexpected '" + ch + "' while parsing argument index");
            } else {
                placeholder = (placeholder * 10) + (ch - '0');
            }
            i++;
        }
        if (placeholder < 0) {
            return changed ? this.buffer.toString() : pattern;
        }
        throw new IllegalArgumentException("Unmatched braces in the pattern.");
    }
}