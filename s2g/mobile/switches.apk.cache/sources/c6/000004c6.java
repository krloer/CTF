package com.badlogic.gdx.utils;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.JsonValue;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import kotlin.UShort;
import kotlin.io.ConstantsKt;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class UBJsonReader implements BaseJsonReader {
    public boolean oldFormat = true;

    @Override // com.badlogic.gdx.utils.BaseJsonReader
    public JsonValue parse(InputStream input) {
        DataInputStream din = null;
        try {
            try {
                din = new DataInputStream(input);
                return parse(din);
            } catch (IOException ex) {
                throw new SerializationException(ex);
            }
        } finally {
            StreamUtils.closeQuietly(din);
        }
    }

    @Override // com.badlogic.gdx.utils.BaseJsonReader
    public JsonValue parse(FileHandle file) {
        try {
            return parse(file.read(ConstantsKt.DEFAULT_BUFFER_SIZE));
        } catch (Exception ex) {
            throw new SerializationException("Error parsing file: " + file, ex);
        }
    }

    public JsonValue parse(DataInputStream din) throws IOException {
        try {
            return parse(din, din.readByte());
        } finally {
            StreamUtils.closeQuietly(din);
        }
    }

    protected JsonValue parse(DataInputStream din, byte type) throws IOException {
        if (type == 91) {
            return parseArray(din);
        }
        if (type == 123) {
            return parseObject(din);
        }
        if (type == 90) {
            return new JsonValue(JsonValue.ValueType.nullValue);
        }
        if (type == 84) {
            return new JsonValue(true);
        }
        if (type == 70) {
            return new JsonValue(false);
        }
        if (type == 66) {
            return new JsonValue(readUChar(din));
        }
        if (type == 85) {
            return new JsonValue(readUChar(din));
        }
        if (type == 105) {
            return new JsonValue(this.oldFormat ? din.readShort() : din.readByte());
        } else if (type == 73) {
            return new JsonValue(this.oldFormat ? din.readInt() : din.readShort());
        } else if (type == 108) {
            return new JsonValue(din.readInt());
        } else {
            if (type == 76) {
                return new JsonValue(din.readLong());
            }
            if (type == 100) {
                return new JsonValue(din.readFloat());
            }
            if (type == 68) {
                return new JsonValue(din.readDouble());
            }
            if (type == 115 || type == 83) {
                return new JsonValue(parseString(din, type));
            }
            if (type == 97 || type == 65) {
                return parseData(din, type);
            }
            if (type == 67) {
                return new JsonValue(din.readChar());
            }
            throw new GdxRuntimeException("Unrecognized data type");
        }
    }

    protected JsonValue parseArray(DataInputStream din) throws IOException {
        JsonValue result = new JsonValue(JsonValue.ValueType.array);
        byte type = din.readByte();
        byte valueType = 0;
        if (type == 36) {
            valueType = din.readByte();
            type = din.readByte();
        }
        long size = -1;
        if (type == 35) {
            size = parseSize(din, false, -1L);
            if (size < 0) {
                throw new GdxRuntimeException("Unrecognized data type");
            }
            if (size == 0) {
                return result;
            }
            type = valueType == 0 ? din.readByte() : valueType;
        }
        JsonValue prev = null;
        long c = 0;
        while (din.available() > 0 && type != 93) {
            JsonValue val = parse(din, type);
            val.parent = result;
            if (prev != null) {
                val.prev = prev;
                prev.next = val;
                result.size++;
            } else {
                result.child = val;
                result.size = 1;
            }
            prev = val;
            if (size > 0) {
                long j = 1 + c;
                c = j;
                if (j >= size) {
                    break;
                }
            }
            type = valueType == 0 ? din.readByte() : valueType;
        }
        return result;
    }

    protected JsonValue parseObject(DataInputStream din) throws IOException {
        JsonValue result = new JsonValue(JsonValue.ValueType.object);
        byte type = din.readByte();
        byte valueType = 0;
        if (type == 36) {
            valueType = din.readByte();
            type = din.readByte();
        }
        long size = -1;
        if (type == 35) {
            size = parseSize(din, false, -1L);
            if (size < 0) {
                throw new GdxRuntimeException("Unrecognized data type");
            }
            if (size == 0) {
                return result;
            }
            type = din.readByte();
        }
        JsonValue prev = null;
        long c = 0;
        while (din.available() > 0 && type != 125) {
            String key = parseString(din, true, type);
            JsonValue child = parse(din, valueType == 0 ? din.readByte() : valueType);
            child.setName(key);
            child.parent = result;
            if (prev != null) {
                child.prev = prev;
                prev.next = child;
                result.size++;
            } else {
                result.child = child;
                result.size = 1;
            }
            prev = child;
            if (size > 0) {
                long j = 1 + c;
                c = j;
                if (j >= size) {
                    break;
                }
            }
            type = din.readByte();
        }
        return result;
    }

    protected JsonValue parseData(DataInputStream din, byte blockType) throws IOException {
        byte dataType = din.readByte();
        long size = blockType == 65 ? readUInt(din) : readUChar(din);
        JsonValue result = new JsonValue(JsonValue.ValueType.array);
        JsonValue prev = null;
        for (long i = 0; i < size; i++) {
            JsonValue val = parse(din, dataType);
            val.parent = result;
            if (prev != null) {
                prev.next = val;
                result.size++;
            } else {
                result.child = val;
                result.size = 1;
            }
            prev = val;
        }
        return result;
    }

    protected String parseString(DataInputStream din, byte type) throws IOException {
        return parseString(din, false, type);
    }

    protected String parseString(DataInputStream din, boolean sOptional, byte type) throws IOException {
        long size = -1;
        if (type == 83) {
            size = parseSize(din, true, -1L);
        } else if (type == 115) {
            size = readUChar(din);
        } else if (sOptional) {
            size = parseSize(din, type, false, -1L);
        }
        if (size >= 0) {
            return size > 0 ? readString(din, size) : BuildConfig.FLAVOR;
        }
        throw new GdxRuntimeException("Unrecognized data type, string expected");
    }

    protected long parseSize(DataInputStream din, boolean useIntOnError, long defaultValue) throws IOException {
        return parseSize(din, din.readByte(), useIntOnError, defaultValue);
    }

    protected long parseSize(DataInputStream din, byte type, boolean useIntOnError, long defaultValue) throws IOException {
        if (type == 105) {
            return readUChar(din);
        }
        if (type == 73) {
            return readUShort(din);
        }
        if (type == 108) {
            return readUInt(din);
        }
        if (type == 76) {
            return din.readLong();
        }
        if (useIntOnError) {
            long result = (type & 255) << 24;
            return result | ((din.readByte() & 255) << 16) | ((din.readByte() & 255) << 8) | (din.readByte() & 255);
        }
        return defaultValue;
    }

    protected short readUChar(DataInputStream din) throws IOException {
        return (short) (din.readByte() & 255);
    }

    protected int readUShort(DataInputStream din) throws IOException {
        return din.readShort() & UShort.MAX_VALUE;
    }

    protected long readUInt(DataInputStream din) throws IOException {
        return din.readInt() & (-1);
    }

    protected String readString(DataInputStream din, long size) throws IOException {
        byte[] data = new byte[(int) size];
        din.readFully(data);
        return new String(data, "UTF-8");
    }
}