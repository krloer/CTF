package com.badlogic.gdx.utils;

import java.util.Arrays;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class StringBuilder implements Appendable, CharSequence {
    static final int INITIAL_CAPACITY = 16;
    private static final char[] digits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    public char[] chars;
    public int length;

    public static int numChars(int value, int radix) {
        int result = value < 0 ? 2 : 1;
        while (true) {
            int i = value / radix;
            value = i;
            if (i != 0) {
                result++;
            } else {
                return result;
            }
        }
    }

    public static int numChars(long value, int radix) {
        int result = value < 0 ? 2 : 1;
        while (true) {
            long j = value / radix;
            value = j;
            if (j != 0) {
                result++;
            } else {
                return result;
            }
        }
    }

    final char[] getValue() {
        return this.chars;
    }

    public StringBuilder() {
        this.chars = new char[16];
    }

    public StringBuilder(int capacity) {
        if (capacity < 0) {
            throw new NegativeArraySizeException();
        }
        this.chars = new char[capacity];
    }

    public StringBuilder(CharSequence seq) {
        this(seq.toString());
    }

    public StringBuilder(StringBuilder builder) {
        this.length = builder.length;
        int i = this.length;
        this.chars = new char[i + 16];
        System.arraycopy(builder.chars, 0, this.chars, 0, i);
    }

    public StringBuilder(String string) {
        this.length = string.length();
        int i = this.length;
        this.chars = new char[i + 16];
        string.getChars(0, i, this.chars, 0);
    }

    private void enlargeBuffer(int min) {
        char[] cArr = this.chars;
        int newSize = (cArr.length >> 1) + cArr.length + 2;
        char[] newData = new char[min > newSize ? min : newSize];
        System.arraycopy(this.chars, 0, newData, 0, this.length);
        this.chars = newData;
    }

    final void appendNull() {
        int newSize = this.length + 4;
        if (newSize > this.chars.length) {
            enlargeBuffer(newSize);
        }
        char[] cArr = this.chars;
        int i = this.length;
        this.length = i + 1;
        cArr[i] = 'n';
        int i2 = this.length;
        this.length = i2 + 1;
        cArr[i2] = 'u';
        int i3 = this.length;
        this.length = i3 + 1;
        cArr[i3] = 'l';
        int i4 = this.length;
        this.length = i4 + 1;
        cArr[i4] = 'l';
    }

    final void append0(char[] value) {
        int newSize = this.length + value.length;
        if (newSize > this.chars.length) {
            enlargeBuffer(newSize);
        }
        System.arraycopy(value, 0, this.chars, this.length, value.length);
        this.length = newSize;
    }

    final void append0(char[] value, int offset, int length) {
        if (offset > value.length || offset < 0) {
            throw new ArrayIndexOutOfBoundsException("Offset out of bounds: " + offset);
        } else if (length < 0 || value.length - offset < length) {
            throw new ArrayIndexOutOfBoundsException("Length out of bounds: " + length);
        } else {
            int newSize = this.length + length;
            if (newSize > this.chars.length) {
                enlargeBuffer(newSize);
            }
            System.arraycopy(value, offset, this.chars, this.length, length);
            this.length = newSize;
        }
    }

    final void append0(char ch) {
        int i = this.length;
        if (i == this.chars.length) {
            enlargeBuffer(i + 1);
        }
        char[] cArr = this.chars;
        int i2 = this.length;
        this.length = i2 + 1;
        cArr[i2] = ch;
    }

    final void append0(String string) {
        if (string == null) {
            appendNull();
            return;
        }
        int adding = string.length();
        int newSize = this.length + adding;
        if (newSize > this.chars.length) {
            enlargeBuffer(newSize);
        }
        string.getChars(0, adding, this.chars, this.length);
        this.length = newSize;
    }

    final void append0(CharSequence s, int start, int end) {
        if (s == null) {
            s = "null";
        }
        if (start < 0 || end < 0 || start > end || end > s.length()) {
            throw new IndexOutOfBoundsException();
        }
        append0(s.subSequence(start, end).toString());
    }

    public int capacity() {
        return this.chars.length;
    }

    @Override // java.lang.CharSequence
    public char charAt(int index) {
        if (index < 0 || index >= this.length) {
            throw new StringIndexOutOfBoundsException(index);
        }
        return this.chars[index];
    }

    final void delete0(int start, int end) {
        if (start >= 0) {
            if (end > this.length) {
                end = this.length;
            }
            if (end == start) {
                return;
            }
            if (end > start) {
                int count = this.length - end;
                if (count >= 0) {
                    char[] cArr = this.chars;
                    System.arraycopy(cArr, end, cArr, start, count);
                }
                this.length -= end - start;
                return;
            }
        }
        throw new StringIndexOutOfBoundsException();
    }

    final void deleteCharAt0(int location) {
        int i;
        if (location < 0 || location >= (i = this.length)) {
            throw new StringIndexOutOfBoundsException(location);
        }
        int count = (i - location) - 1;
        if (count > 0) {
            char[] cArr = this.chars;
            System.arraycopy(cArr, location + 1, cArr, location, count);
        }
        this.length--;
    }

    public void ensureCapacity(int min) {
        char[] cArr = this.chars;
        if (min > cArr.length) {
            int twice = (cArr.length << 1) + 2;
            enlargeBuffer(twice > min ? twice : min);
        }
    }

    public void getChars(int start, int end, char[] dest, int destStart) {
        int i = this.length;
        if (start > i || end > i || start > end) {
            throw new StringIndexOutOfBoundsException();
        }
        System.arraycopy(this.chars, start, dest, destStart, end - start);
    }

    final void insert0(int index, char[] value) {
        if (index < 0 || index > this.length) {
            throw new StringIndexOutOfBoundsException(index);
        }
        if (value.length != 0) {
            move(value.length, index);
            System.arraycopy(value, 0, value, index, value.length);
            this.length += value.length;
        }
    }

    final void insert0(int index, char[] value, int start, int length) {
        if (index >= 0 && index <= length) {
            if (start >= 0 && length >= 0 && length <= value.length - start) {
                if (length != 0) {
                    move(length, index);
                    System.arraycopy(value, start, this.chars, index, length);
                    this.length += length;
                    return;
                }
                return;
            }
            throw new StringIndexOutOfBoundsException("offset " + start + ", length " + length + ", char[].length " + value.length);
        }
        throw new StringIndexOutOfBoundsException(index);
    }

    final void insert0(int index, char ch) {
        if (index < 0 || index > this.length) {
            throw new ArrayIndexOutOfBoundsException(index);
        }
        move(1, index);
        this.chars[index] = ch;
        this.length++;
    }

    final void insert0(int index, String string) {
        if (index >= 0 && index <= this.length) {
            if (string == null) {
                string = "null";
            }
            int min = string.length();
            if (min != 0) {
                move(min, index);
                string.getChars(0, min, this.chars, index);
                this.length += min;
                return;
            }
            return;
        }
        throw new StringIndexOutOfBoundsException(index);
    }

    final void insert0(int index, CharSequence s, int start, int end) {
        if (s == null) {
            s = "null";
        }
        if (index < 0 || index > this.length || start < 0 || end < 0 || start > end || end > s.length()) {
            throw new IndexOutOfBoundsException();
        }
        insert0(index, s.subSequence(start, end).toString());
    }

    @Override // java.lang.CharSequence
    public int length() {
        return this.length;
    }

    private void move(int size, int index) {
        char[] cArr = this.chars;
        int length = cArr.length;
        int i = this.length;
        if (length - i >= size) {
            System.arraycopy(cArr, index, cArr, index + size, i - index);
            return;
        }
        int a = i + size;
        int b = (cArr.length << 1) + 2;
        int newSize = a > b ? a : b;
        char[] newData = new char[newSize];
        System.arraycopy(this.chars, 0, newData, 0, index);
        System.arraycopy(this.chars, index, newData, index + size, this.length - index);
        this.chars = newData;
    }

    final void replace0(int start, int end, String string) {
        if (start >= 0) {
            if (end > this.length) {
                end = this.length;
            }
            if (end > start) {
                int stringLength = string.length();
                int diff = (end - start) - stringLength;
                if (diff > 0) {
                    char[] cArr = this.chars;
                    System.arraycopy(cArr, end, cArr, start + stringLength, this.length - end);
                } else if (diff < 0) {
                    move(-diff, end);
                }
                string.getChars(0, stringLength, this.chars, start);
                this.length -= diff;
                return;
            } else if (start == end) {
                if (string == null) {
                    throw new NullPointerException();
                }
                insert0(start, string);
                return;
            }
        }
        throw new StringIndexOutOfBoundsException();
    }

    final void reverse0() {
        int i = this.length;
        if (i < 2) {
            return;
        }
        int end = i - 1;
        char[] cArr = this.chars;
        char frontHigh = cArr[0];
        char endLow = cArr[end];
        boolean allowFrontSur = true;
        boolean allowEndSur = true;
        int i2 = 0;
        int mid = i / 2;
        while (i2 < mid) {
            char[] cArr2 = this.chars;
            char frontLow = cArr2[i2 + 1];
            char endHigh = cArr2[end - 1];
            boolean surAtFront = allowFrontSur && frontLow >= 56320 && frontLow <= 57343 && frontHigh >= 55296 && frontHigh <= 56319;
            if (surAtFront && this.length < 3) {
                return;
            }
            boolean surAtEnd = allowEndSur && endHigh >= 55296 && endHigh <= 56319 && endLow >= 56320 && endLow <= 57343;
            allowEndSur = true;
            allowFrontSur = true;
            if (surAtFront == surAtEnd) {
                if (surAtFront) {
                    char[] cArr3 = this.chars;
                    cArr3[end] = frontLow;
                    cArr3[end - 1] = frontHigh;
                    cArr3[i2] = endHigh;
                    cArr3[i2 + 1] = endLow;
                    frontHigh = cArr3[i2 + 2];
                    endLow = cArr3[end - 2];
                    i2++;
                    end--;
                } else {
                    char[] cArr4 = this.chars;
                    cArr4[end] = frontHigh;
                    cArr4[i2] = endLow;
                    frontHigh = frontLow;
                    endLow = endHigh;
                }
            } else if (surAtFront) {
                char[] cArr5 = this.chars;
                cArr5[end] = frontLow;
                cArr5[i2] = endLow;
                endLow = endHigh;
                allowFrontSur = false;
            } else {
                char[] cArr6 = this.chars;
                cArr6[end] = frontHigh;
                cArr6[i2] = endHigh;
                frontHigh = frontLow;
                allowEndSur = false;
            }
            i2++;
            end--;
        }
        int mid2 = this.length;
        if ((mid2 & 1) == 1) {
            if (!allowFrontSur || !allowEndSur) {
                this.chars[end] = allowFrontSur ? endLow : frontHigh;
            }
        }
    }

    public void setCharAt(int index, char ch) {
        if (index < 0 || index >= this.length) {
            throw new StringIndexOutOfBoundsException(index);
        }
        this.chars[index] = ch;
    }

    public void setLength(int newLength) {
        if (newLength < 0) {
            throw new StringIndexOutOfBoundsException(newLength);
        }
        char[] cArr = this.chars;
        if (newLength > cArr.length) {
            enlargeBuffer(newLength);
        } else {
            int i = this.length;
            if (i < newLength) {
                Arrays.fill(cArr, i, newLength, (char) 0);
            }
        }
        this.length = newLength;
    }

    public String substring(int start) {
        int i;
        if (start >= 0 && start <= (i = this.length)) {
            if (start == i) {
                return BuildConfig.FLAVOR;
            }
            return new String(this.chars, start, i - start);
        }
        throw new StringIndexOutOfBoundsException(start);
    }

    public String substring(int start, int end) {
        if (start >= 0 && start <= end && end <= this.length) {
            if (start == end) {
                return BuildConfig.FLAVOR;
            }
            return new String(this.chars, start, end - start);
        }
        throw new StringIndexOutOfBoundsException();
    }

    @Override // java.lang.CharSequence
    public String toString() {
        int i = this.length;
        return i == 0 ? BuildConfig.FLAVOR : new String(this.chars, 0, i);
    }

    @Override // java.lang.CharSequence
    public CharSequence subSequence(int start, int end) {
        return substring(start, end);
    }

    public int indexOf(String string) {
        return indexOf(string, 0);
    }

    public int indexOf(String subString, int start) {
        if (start < 0) {
            start = 0;
        }
        int subCount = subString.length();
        if (subCount == 0) {
            int i = this.length;
            return (start < i || start == 0) ? start : i;
        }
        int maxIndex = this.length - subCount;
        if (start > maxIndex) {
            return -1;
        }
        char firstChar = subString.charAt(0);
        while (true) {
            int i2 = start;
            boolean found = false;
            while (true) {
                if (i2 > maxIndex) {
                    break;
                } else if (this.chars[i2] != firstChar) {
                    i2++;
                } else {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return -1;
            }
            int o1 = i2;
            int o2 = 0;
            do {
                o2++;
                if (o2 >= subCount) {
                    break;
                }
                o1++;
            } while (this.chars[o1] == subString.charAt(o2));
            if (o2 == subCount) {
                return i2;
            }
            start = i2 + 1;
        }
    }

    public int indexOfIgnoreCase(String subString, int start) {
        char c;
        char upper;
        if (start < 0) {
            start = 0;
        }
        int subCount = subString.length();
        if (subCount == 0) {
            int i = this.length;
            return (start < i || start == 0) ? start : i;
        }
        int maxIndex = this.length - subCount;
        if (start > maxIndex) {
            return -1;
        }
        char firstUpper = Character.toUpperCase(subString.charAt(0));
        char firstLower = Character.toLowerCase(firstUpper);
        while (true) {
            int i2 = start;
            boolean found = false;
            while (i2 <= maxIndex) {
                char c2 = this.chars[i2];
                if (c2 != firstUpper && c2 != firstLower) {
                    i2++;
                } else {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return -1;
            }
            int o1 = i2;
            int o2 = 0;
            while (true) {
                o2++;
                if (o2 >= subCount || ((c = this.chars[(o1 = o1 + 1)]) != (upper = Character.toUpperCase(subString.charAt(o2))) && c != Character.toLowerCase(upper))) {
                    break;
                }
            }
            if (o2 == subCount) {
                return i2;
            }
            start = i2 + 1;
        }
    }

    public boolean contains(String subString) {
        return indexOf(subString, 0) != -1;
    }

    public boolean containsIgnoreCase(String subString) {
        return indexOfIgnoreCase(subString, 0) != -1;
    }

    public int lastIndexOf(String string) {
        return lastIndexOf(string, this.length);
    }

    public int lastIndexOf(String subString, int start) {
        int subCount = subString.length();
        int i = this.length;
        if (subCount > i || start < 0) {
            return -1;
        }
        if (subCount <= 0) {
            return start < i ? start : i;
        }
        if (start > i - subCount) {
            start = i - subCount;
        }
        char firstChar = subString.charAt(0);
        while (true) {
            int i2 = start;
            boolean found = false;
            while (true) {
                if (i2 < 0) {
                    break;
                } else if (this.chars[i2] != firstChar) {
                    i2--;
                } else {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return -1;
            }
            int o1 = i2;
            int o2 = 0;
            do {
                o2++;
                if (o2 >= subCount) {
                    break;
                }
                o1++;
            } while (this.chars[o1] == subString.charAt(o2));
            if (o2 == subCount) {
                return i2;
            }
            start = i2 - 1;
        }
    }

    public void trimToSize() {
        int i = this.length;
        char[] cArr = this.chars;
        if (i < cArr.length) {
            char[] newValue = new char[i];
            System.arraycopy(cArr, 0, newValue, 0, i);
            this.chars = newValue;
        }
    }

    public int codePointAt(int index) {
        int i;
        if (index < 0 || index >= (i = this.length)) {
            throw new StringIndexOutOfBoundsException(index);
        }
        return Character.codePointAt(this.chars, index, i);
    }

    public int codePointBefore(int index) {
        if (index < 1 || index > this.length) {
            throw new StringIndexOutOfBoundsException(index);
        }
        return Character.codePointBefore(this.chars, index);
    }

    public int codePointCount(int beginIndex, int endIndex) {
        if (beginIndex < 0 || endIndex > this.length || beginIndex > endIndex) {
            throw new StringIndexOutOfBoundsException();
        }
        return Character.codePointCount(this.chars, beginIndex, endIndex - beginIndex);
    }

    public int offsetByCodePoints(int index, int codePointOffset) {
        return Character.offsetByCodePoints(this.chars, 0, this.length, index, codePointOffset);
    }

    public StringBuilder append(boolean b) {
        append0(b ? "true" : "false");
        return this;
    }

    @Override // java.lang.Appendable
    public StringBuilder append(char c) {
        append0(c);
        return this;
    }

    public StringBuilder append(int value) {
        return append(value, 0);
    }

    public StringBuilder append(int value, int minLength) {
        return append(value, minLength, '0');
    }

    public StringBuilder append(int value, int minLength, char prefix) {
        if (value == Integer.MIN_VALUE) {
            append0("-2147483648");
            return this;
        }
        if (value < 0) {
            append0('-');
            value = -value;
        }
        if (minLength > 1) {
            for (int j = minLength - numChars(value, 10); j > 0; j--) {
                append(prefix);
            }
        }
        if (value >= 10000) {
            if (value >= 1000000000) {
                append0(digits[(int) ((value % 10000000000L) / 1000000000)]);
            }
            if (value >= 100000000) {
                append0(digits[(value % 1000000000) / 100000000]);
            }
            if (value >= 10000000) {
                append0(digits[(value % 100000000) / 10000000]);
            }
            if (value >= 1000000) {
                append0(digits[(value % 10000000) / 1000000]);
            }
            if (value >= 100000) {
                append0(digits[(value % 1000000) / 100000]);
            }
            append0(digits[(value % 100000) / 10000]);
        }
        if (value >= 1000) {
            append0(digits[(value % 10000) / 1000]);
        }
        if (value >= 100) {
            append0(digits[(value % 1000) / 100]);
        }
        if (value >= 10) {
            append0(digits[(value % 100) / 10]);
        }
        append0(digits[value % 10]);
        return this;
    }

    public StringBuilder append(long value) {
        return append(value, 0);
    }

    public StringBuilder append(long value, int minLength) {
        return append(value, minLength, '0');
    }

    public StringBuilder append(long value, int minLength, char prefix) {
        if (value == Long.MIN_VALUE) {
            append0("-9223372036854775808");
            return this;
        }
        if (value < 0) {
            append0('-');
            value = -value;
        }
        if (minLength > 1) {
            for (int j = minLength - numChars(value, 10); j > 0; j--) {
                append(prefix);
            }
        }
        if (value >= 10000) {
            if (value >= 1000000000000000000L) {
                char[] cArr = digits;
                double d = value;
                Double.isNaN(d);
                append0(cArr[(int) ((d % 1.0E19d) / 1.0E18d)]);
            }
            if (value >= 100000000000000000L) {
                append0(digits[(int) ((value % 1000000000000000000L) / 100000000000000000L)]);
            }
            if (value >= 10000000000000000L) {
                append0(digits[(int) ((value % 100000000000000000L) / 10000000000000000L)]);
            }
            if (value >= 1000000000000000L) {
                append0(digits[(int) ((value % 10000000000000000L) / 1000000000000000L)]);
            }
            if (value >= 100000000000000L) {
                append0(digits[(int) ((value % 1000000000000000L) / 100000000000000L)]);
            }
            if (value >= 10000000000000L) {
                append0(digits[(int) ((value % 100000000000000L) / 10000000000000L)]);
            }
            if (value >= 1000000000000L) {
                append0(digits[(int) ((value % 10000000000000L) / 1000000000000L)]);
            }
            if (value >= 100000000000L) {
                append0(digits[(int) ((value % 1000000000000L) / 100000000000L)]);
            }
            if (value >= 10000000000L) {
                append0(digits[(int) ((value % 100000000000L) / 10000000000L)]);
            }
            if (value >= 1000000000) {
                append0(digits[(int) ((value % 10000000000L) / 1000000000)]);
            }
            if (value >= 100000000) {
                append0(digits[(int) ((value % 1000000000) / 100000000)]);
            }
            if (value >= 10000000) {
                append0(digits[(int) ((value % 100000000) / 10000000)]);
            }
            if (value >= 1000000) {
                append0(digits[(int) ((value % 10000000) / 1000000)]);
            }
            if (value >= 100000) {
                append0(digits[(int) ((value % 1000000) / 100000)]);
            }
            append0(digits[(int) ((value % 100000) / 10000)]);
        }
        if (value >= 1000) {
            append0(digits[(int) ((value % 10000) / 1000)]);
        }
        if (value >= 100) {
            append0(digits[(int) ((value % 1000) / 100)]);
        }
        if (value >= 10) {
            append0(digits[(int) ((value % 100) / 10)]);
        }
        append0(digits[(int) (value % 10)]);
        return this;
    }

    public StringBuilder append(float f) {
        append0(Float.toString(f));
        return this;
    }

    public StringBuilder append(double d) {
        append0(Double.toString(d));
        return this;
    }

    public StringBuilder append(Object obj) {
        if (obj == null) {
            appendNull();
        } else {
            append0(obj.toString());
        }
        return this;
    }

    public StringBuilder append(String str) {
        append0(str);
        return this;
    }

    public StringBuilder appendLine(String str) {
        append0(str);
        append0('\n');
        return this;
    }

    public StringBuilder append(char[] ch) {
        append0(ch);
        return this;
    }

    public StringBuilder append(char[] str, int offset, int len) {
        append0(str, offset, len);
        return this;
    }

    @Override // java.lang.Appendable
    public StringBuilder append(CharSequence csq) {
        if (csq == null) {
            appendNull();
        } else if (csq instanceof StringBuilder) {
            StringBuilder builder = (StringBuilder) csq;
            append0(builder.chars, 0, builder.length);
        } else {
            append0(csq.toString());
        }
        return this;
    }

    public StringBuilder append(StringBuilder builder) {
        if (builder == null) {
            appendNull();
        } else {
            append0(builder.chars, 0, builder.length);
        }
        return this;
    }

    @Override // java.lang.Appendable
    public StringBuilder append(CharSequence csq, int start, int end) {
        append0(csq, start, end);
        return this;
    }

    public StringBuilder append(StringBuilder builder, int start, int end) {
        if (builder == null) {
            appendNull();
        } else {
            append0(builder.chars, start, end);
        }
        return this;
    }

    public StringBuilder appendCodePoint(int codePoint) {
        append0(Character.toChars(codePoint));
        return this;
    }

    public StringBuilder delete(int start, int end) {
        delete0(start, end);
        return this;
    }

    public StringBuilder deleteCharAt(int index) {
        deleteCharAt0(index);
        return this;
    }

    public void clear() {
        this.length = 0;
    }

    public StringBuilder insert(int offset, boolean b) {
        insert0(offset, b ? "true" : "false");
        return this;
    }

    public StringBuilder insert(int offset, char c) {
        insert0(offset, c);
        return this;
    }

    public StringBuilder insert(int offset, int i) {
        insert0(offset, Integer.toString(i));
        return this;
    }

    public StringBuilder insert(int offset, long l) {
        insert0(offset, Long.toString(l));
        return this;
    }

    public StringBuilder insert(int offset, float f) {
        insert0(offset, Float.toString(f));
        return this;
    }

    public StringBuilder insert(int offset, double d) {
        insert0(offset, Double.toString(d));
        return this;
    }

    public StringBuilder insert(int offset, Object obj) {
        insert0(offset, obj == null ? "null" : obj.toString());
        return this;
    }

    public StringBuilder insert(int offset, String str) {
        insert0(offset, str);
        return this;
    }

    public StringBuilder insert(int offset, char[] ch) {
        insert0(offset, ch);
        return this;
    }

    public StringBuilder insert(int offset, char[] str, int strOffset, int strLen) {
        insert0(offset, str, strOffset, strLen);
        return this;
    }

    public StringBuilder insert(int offset, CharSequence s) {
        insert0(offset, s == null ? "null" : s.toString());
        return this;
    }

    public StringBuilder insert(int offset, CharSequence s, int start, int end) {
        insert0(offset, s, start, end);
        return this;
    }

    public StringBuilder replace(int start, int end, String str) {
        replace0(start, end, str);
        return this;
    }

    public StringBuilder replace(String find, String replace) {
        int findLength = find.length();
        int replaceLength = replace.length();
        int index = 0;
        while (true) {
            int index2 = indexOf(find, index);
            if (index2 != -1) {
                replace0(index2, index2 + findLength, replace);
                index = index2 + replaceLength;
            } else {
                return this;
            }
        }
    }

    public StringBuilder replace(char find, String replace) {
        int replaceLength = replace.length();
        int index = 0;
        while (index != this.length) {
            if (this.chars[index] != find) {
                index++;
            } else {
                replace0(index, index + 1, replace);
                index += replaceLength;
            }
        }
        return this;
    }

    public StringBuilder reverse() {
        reverse0();
        return this;
    }

    public boolean isEmpty() {
        return this.length == 0;
    }

    public boolean notEmpty() {
        return this.length != 0;
    }

    public int hashCode() {
        int result = this.length + 31;
        for (int index = 0; index < this.length; index++) {
            result = (result * 31) + this.chars[index];
        }
        return result;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        StringBuilder other = (StringBuilder) obj;
        int length = this.length;
        if (length != other.length) {
            return false;
        }
        char[] chars = this.chars;
        char[] chars2 = other.chars;
        for (int i = 0; i < length; i++) {
            if (chars[i] != chars2[i]) {
                return false;
            }
        }
        return true;
    }

    public boolean equalsIgnoreCase(StringBuilder other) {
        int length;
        if (this == other) {
            return true;
        }
        if (other == null || (length = this.length) != other.length) {
            return false;
        }
        char[] chars = this.chars;
        char[] chars2 = other.chars;
        for (int i = 0; i < length; i++) {
            char c = chars[i];
            char upper = Character.toUpperCase(chars2[i]);
            if (c != upper && c != Character.toLowerCase(upper)) {
                return false;
            }
        }
        return true;
    }

    public boolean equalsIgnoreCase(String other) {
        int length;
        if (other == null || (length = this.length) != other.length()) {
            return false;
        }
        char[] chars = this.chars;
        for (int i = 0; i < length; i++) {
            char c = chars[i];
            char upper = Character.toUpperCase(other.charAt(i));
            if (c != upper && c != Character.toLowerCase(upper)) {
                return false;
            }
        }
        return true;
    }
}