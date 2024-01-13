package com.badlogic.gdx.utils;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.IntMap;
import com.badlogic.gdx.utils.IntSet;
import com.badlogic.gdx.utils.JsonValue;
import com.badlogic.gdx.utils.JsonWriter;
import com.badlogic.gdx.utils.LongMap;
import com.badlogic.gdx.utils.ObjectFloatMap;
import com.badlogic.gdx.utils.ObjectIntMap;
import com.badlogic.gdx.utils.ObjectMap;
import com.badlogic.gdx.utils.ObjectSet;
import com.badlogic.gdx.utils.reflect.ArrayReflection;
import com.badlogic.gdx.utils.reflect.ClassReflection;
import com.badlogic.gdx.utils.reflect.Constructor;
import com.badlogic.gdx.utils.reflect.Field;
import com.badlogic.gdx.utils.reflect.ReflectionException;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.security.AccessControlException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes.dex */
public class Json {
    private static final boolean debug = false;
    private final ObjectMap<Class, Object[]> classToDefaultValues;
    private final ObjectMap<Class, Serializer> classToSerializer;
    private final ObjectMap<Class, String> classToTag;
    private Serializer defaultSerializer;
    private boolean enumNames;
    private final Object[] equals1;
    private final Object[] equals2;
    private boolean ignoreDeprecated;
    private boolean ignoreUnknownFields;
    private JsonWriter.OutputType outputType;
    private boolean quoteLongValues;
    private boolean readDeprecated;
    private boolean sortFields;
    private final ObjectMap<String, Class> tagToClass;
    private String typeName;
    private final ObjectMap<Class, OrderedMap<String, FieldMetadata>> typeToFields;
    private boolean usePrototypes;
    private JsonWriter writer;

    /* loaded from: classes.dex */
    public interface Serializable {
        void read(Json json, JsonValue jsonValue);

        void write(Json json);
    }

    /* loaded from: classes.dex */
    public interface Serializer<T> {
        T read(Json json, JsonValue jsonValue, Class cls);

        void write(Json json, T t, Class cls);
    }

    public Json() {
        this.typeName = "class";
        this.usePrototypes = true;
        this.enumNames = true;
        this.typeToFields = new ObjectMap<>();
        this.tagToClass = new ObjectMap<>();
        this.classToTag = new ObjectMap<>();
        this.classToSerializer = new ObjectMap<>();
        this.classToDefaultValues = new ObjectMap<>();
        this.equals1 = new Object[]{null};
        this.equals2 = new Object[]{null};
        this.outputType = JsonWriter.OutputType.minimal;
    }

    public Json(JsonWriter.OutputType outputType) {
        this.typeName = "class";
        this.usePrototypes = true;
        this.enumNames = true;
        this.typeToFields = new ObjectMap<>();
        this.tagToClass = new ObjectMap<>();
        this.classToTag = new ObjectMap<>();
        this.classToSerializer = new ObjectMap<>();
        this.classToDefaultValues = new ObjectMap<>();
        this.equals1 = new Object[]{null};
        this.equals2 = new Object[]{null};
        this.outputType = outputType;
    }

    public void setIgnoreUnknownFields(boolean ignoreUnknownFields) {
        this.ignoreUnknownFields = ignoreUnknownFields;
    }

    public boolean getIgnoreUnknownFields() {
        return this.ignoreUnknownFields;
    }

    public void setIgnoreDeprecated(boolean ignoreDeprecated) {
        this.ignoreDeprecated = ignoreDeprecated;
    }

    public void setReadDeprecated(boolean readDeprecated) {
        this.readDeprecated = readDeprecated;
    }

    public void setOutputType(JsonWriter.OutputType outputType) {
        this.outputType = outputType;
    }

    public void setQuoteLongValues(boolean quoteLongValues) {
        this.quoteLongValues = quoteLongValues;
    }

    public void setEnumNames(boolean enumNames) {
        this.enumNames = enumNames;
    }

    public void addClassTag(String tag, Class type) {
        this.tagToClass.put(tag, type);
        this.classToTag.put(type, tag);
    }

    public Class getClass(String tag) {
        return this.tagToClass.get(tag);
    }

    public String getTag(Class type) {
        return this.classToTag.get(type);
    }

    public void setTypeName(String typeName) {
        this.typeName = typeName;
    }

    public void setDefaultSerializer(Serializer defaultSerializer) {
        this.defaultSerializer = defaultSerializer;
    }

    public <T> void setSerializer(Class<T> type, Serializer<T> serializer) {
        this.classToSerializer.put(type, serializer);
    }

    public <T> Serializer<T> getSerializer(Class<T> type) {
        return this.classToSerializer.get(type);
    }

    public void setUsePrototypes(boolean usePrototypes) {
        this.usePrototypes = usePrototypes;
    }

    public void setElementType(Class type, String fieldName, Class elementType) {
        FieldMetadata metadata = getFields(type).get(fieldName);
        if (metadata == null) {
            throw new SerializationException("Field not found: " + fieldName + " (" + type.getName() + ")");
        }
        metadata.elementType = elementType;
    }

    public void setDeprecated(Class type, String fieldName, boolean deprecated) {
        FieldMetadata metadata = getFields(type).get(fieldName);
        if (metadata == null) {
            throw new SerializationException("Field not found: " + fieldName + " (" + type.getName() + ")");
        }
        metadata.deprecated = deprecated;
    }

    public void setSortFields(boolean sortFields) {
        this.sortFields = sortFields;
    }

    private OrderedMap<String, FieldMetadata> getFields(Class type) {
        OrderedMap<String, FieldMetadata> fields = this.typeToFields.get(type);
        if (fields != null) {
            return fields;
        }
        Array<Class> classHierarchy = new Array<>();
        for (Class nextClass = type; nextClass != Object.class; nextClass = nextClass.getSuperclass()) {
            classHierarchy.add(nextClass);
        }
        ArrayList<Field> allFields = new ArrayList<>();
        for (int i = classHierarchy.size - 1; i >= 0; i--) {
            java.util.Collections.addAll(allFields, ClassReflection.getDeclaredFields(classHierarchy.get(i)));
        }
        OrderedMap<String, FieldMetadata> nameToField = new OrderedMap<>(allFields.size());
        int n = allFields.size();
        for (int i2 = 0; i2 < n; i2++) {
            Field field = allFields.get(i2);
            if (!field.isTransient() && !field.isStatic() && !field.isSynthetic()) {
                if (!field.isAccessible()) {
                    try {
                        field.setAccessible(true);
                    } catch (AccessControlException e) {
                    }
                }
                nameToField.put(field.getName(), new FieldMetadata(field));
            }
        }
        if (this.sortFields) {
            nameToField.keys.sort();
        }
        this.typeToFields.put(type, nameToField);
        return nameToField;
    }

    public String toJson(Object object) {
        return toJson(object, object == null ? null : object.getClass(), (Class) null);
    }

    public String toJson(Object object, Class knownType) {
        return toJson(object, knownType, (Class) null);
    }

    public String toJson(Object object, Class knownType, Class elementType) {
        StringWriter buffer = new StringWriter();
        toJson(object, knownType, elementType, buffer);
        return buffer.toString();
    }

    public void toJson(Object object, FileHandle file) {
        toJson(object, object == null ? null : object.getClass(), (Class) null, file);
    }

    public void toJson(Object object, Class knownType, FileHandle file) {
        toJson(object, knownType, (Class) null, file);
    }

    public void toJson(Object object, Class knownType, Class elementType, FileHandle file) {
        Writer writer = null;
        try {
            try {
                writer = file.writer(false, "UTF-8");
                toJson(object, knownType, elementType, writer);
            } catch (Exception ex) {
                throw new SerializationException("Error writing file: " + file, ex);
            }
        } finally {
            StreamUtils.closeQuietly(writer);
        }
    }

    public void toJson(Object object, Writer writer) {
        toJson(object, object == null ? null : object.getClass(), (Class) null, writer);
    }

    public void toJson(Object object, Class knownType, Writer writer) {
        toJson(object, knownType, (Class) null, writer);
    }

    public void toJson(Object object, Class knownType, Class elementType, Writer writer) {
        setWriter(writer);
        try {
            writeValue(object, knownType, elementType);
        } finally {
            StreamUtils.closeQuietly(this.writer);
            this.writer = null;
        }
    }

    public void setWriter(Writer writer) {
        if (!(writer instanceof JsonWriter)) {
            writer = new JsonWriter(writer);
        }
        this.writer = (JsonWriter) writer;
        this.writer.setOutputType(this.outputType);
        this.writer.setQuoteLongValues(this.quoteLongValues);
    }

    public JsonWriter getWriter() {
        return this.writer;
    }

    /* JADX WARN: Code restructure failed: missing block: B:29:0x0080, code lost:
        if (java.util.Arrays.deepEquals(r15, r5) != false) goto L20;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public void writeFields(java.lang.Object r18) {
        /*
            Method dump skipped, instructions count: 312
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.Json.writeFields(java.lang.Object):void");
    }

    private Object[] getDefaultValues(Class type) {
        if (this.usePrototypes) {
            if (this.classToDefaultValues.containsKey(type)) {
                return this.classToDefaultValues.get(type);
            }
            try {
                Object object = newInstance(type);
                OrderedMap<String, FieldMetadata> fields = getFields(type);
                Object[] values = new Object[fields.size];
                this.classToDefaultValues.put(type, values);
                int defaultIndex = 0;
                Array<String> fieldNames = fields.orderedKeys();
                int n = fieldNames.size;
                for (int i = 0; i < n; i++) {
                    FieldMetadata metadata = fields.get(fieldNames.get(i));
                    if (!this.ignoreDeprecated || !metadata.deprecated) {
                        Field field = metadata.field;
                        int defaultIndex2 = defaultIndex + 1;
                        try {
                            values[defaultIndex] = field.get(object);
                            defaultIndex = defaultIndex2;
                        } catch (SerializationException ex) {
                            ex.addTrace(field + " (" + type.getName() + ")");
                            throw ex;
                        } catch (ReflectionException ex2) {
                            throw new SerializationException("Error accessing field: " + field.getName() + " (" + type.getName() + ")", ex2);
                        } catch (RuntimeException runtimeEx) {
                            SerializationException ex3 = new SerializationException(runtimeEx);
                            ex3.addTrace(field + " (" + type.getName() + ")");
                            throw ex3;
                        }
                    }
                }
                return values;
            } catch (Exception e) {
                this.classToDefaultValues.put(type, null);
                return null;
            }
        }
        return null;
    }

    public void writeField(Object object, String name) {
        writeField(object, name, name, null);
    }

    public void writeField(Object object, String name, Class elementType) {
        writeField(object, name, name, elementType);
    }

    public void writeField(Object object, String fieldName, String jsonName) {
        writeField(object, fieldName, jsonName, null);
    }

    public void writeField(Object object, String fieldName, String jsonName, Class elementType) {
        Class type = object.getClass();
        FieldMetadata metadata = getFields(type).get(fieldName);
        if (metadata == null) {
            throw new SerializationException("Field not found: " + fieldName + " (" + type.getName() + ")");
        }
        Field field = metadata.field;
        if (elementType == null) {
            elementType = metadata.elementType;
        }
        try {
            this.writer.name(jsonName);
            writeValue(field.get(object), field.getType(), elementType);
        } catch (SerializationException ex) {
            ex.addTrace(field + " (" + type.getName() + ")");
            throw ex;
        } catch (ReflectionException ex2) {
            throw new SerializationException("Error accessing field: " + field.getName() + " (" + type.getName() + ")", ex2);
        } catch (Exception runtimeEx) {
            SerializationException ex3 = new SerializationException(runtimeEx);
            ex3.addTrace(field + " (" + type.getName() + ")");
            throw ex3;
        }
    }

    public void writeValue(String name, Object value) {
        try {
            this.writer.name(name);
            if (value != null) {
                writeValue(value, value.getClass(), (Class) null);
            } else {
                writeValue(value, (Class) null, (Class) null);
            }
        } catch (IOException ex) {
            throw new SerializationException(ex);
        }
    }

    public void writeValue(String name, Object value, Class knownType) {
        try {
            this.writer.name(name);
            writeValue(value, knownType, (Class) null);
        } catch (IOException ex) {
            throw new SerializationException(ex);
        }
    }

    public void writeValue(String name, Object value, Class knownType, Class elementType) {
        try {
            this.writer.name(name);
            writeValue(value, knownType, elementType);
        } catch (IOException ex) {
            throw new SerializationException(ex);
        }
    }

    public void writeValue(Object value) {
        if (value != null) {
            writeValue(value, value.getClass(), (Class) null);
        } else {
            writeValue(value, (Class) null, (Class) null);
        }
    }

    public void writeValue(Object value, Class knownType) {
        writeValue(value, knownType, (Class) null);
    }

    public void writeValue(Object value, Class knownType, Class elementType) {
        try {
            if (value == null) {
                this.writer.value(null);
                return;
            }
            if ((knownType == null || !knownType.isPrimitive()) && knownType != String.class && knownType != Integer.class && knownType != Boolean.class && knownType != Float.class && knownType != Long.class && knownType != Double.class && knownType != Short.class && knownType != Byte.class && knownType != Character.class) {
                Class actualType = value.getClass();
                if (!actualType.isPrimitive() && actualType != String.class && actualType != Integer.class && actualType != Boolean.class && actualType != Float.class && actualType != Long.class && actualType != Double.class && actualType != Short.class && actualType != Byte.class && actualType != Character.class) {
                    if (value instanceof Serializable) {
                        writeObjectStart(actualType, knownType);
                        ((Serializable) value).write(this);
                        writeObjectEnd();
                        return;
                    }
                    Serializer serializer = this.classToSerializer.get(actualType);
                    if (serializer != null) {
                        serializer.write(this, value, knownType);
                        return;
                    } else if (value instanceof Array) {
                        if (knownType != null && actualType != knownType && actualType != Array.class) {
                            throw new SerializationException("Serialization of an Array other than the known type is not supported.\nKnown type: " + knownType + "\nActual type: " + actualType);
                        }
                        writeArrayStart();
                        Array array = (Array) value;
                        int n = array.size;
                        for (int i = 0; i < n; i++) {
                            writeValue(array.get(i), elementType, (Class) null);
                        }
                        writeArrayEnd();
                        return;
                    } else if (value instanceof Queue) {
                        if (knownType != null && actualType != knownType && actualType != Queue.class) {
                            throw new SerializationException("Serialization of a Queue other than the known type is not supported.\nKnown type: " + knownType + "\nActual type: " + actualType);
                        }
                        writeArrayStart();
                        Queue queue = (Queue) value;
                        int n2 = queue.size;
                        for (int i2 = 0; i2 < n2; i2++) {
                            writeValue(queue.get(i2), elementType, (Class) null);
                        }
                        writeArrayEnd();
                        return;
                    } else if (value instanceof Collection) {
                        if (this.typeName != null && actualType != ArrayList.class && (knownType == null || knownType != actualType)) {
                            writeObjectStart(actualType, knownType);
                            writeArrayStart("items");
                            for (Object item : (Collection) value) {
                                writeValue(item, elementType, (Class) null);
                            }
                            writeArrayEnd();
                            writeObjectEnd();
                            return;
                        }
                        writeArrayStart();
                        for (Object item2 : (Collection) value) {
                            writeValue(item2, elementType, (Class) null);
                        }
                        writeArrayEnd();
                        return;
                    } else if (actualType.isArray()) {
                        if (elementType == null) {
                            elementType = actualType.getComponentType();
                        }
                        int length = ArrayReflection.getLength(value);
                        writeArrayStart();
                        for (int i3 = 0; i3 < length; i3++) {
                            writeValue(ArrayReflection.get(value, i3), elementType, (Class) null);
                        }
                        writeArrayEnd();
                        return;
                    } else if (value instanceof ObjectMap) {
                        if (knownType == null) {
                            knownType = ObjectMap.class;
                        }
                        writeObjectStart(actualType, knownType);
                        ObjectMap.Entries it = ((ObjectMap) value).entries().iterator();
                        while (it.hasNext()) {
                            ObjectMap.Entry entry = it.next();
                            this.writer.name(convertToString(entry.key));
                            writeValue(entry.value, elementType, (Class) null);
                        }
                        writeObjectEnd();
                        return;
                    } else if (value instanceof ObjectIntMap) {
                        if (knownType == null) {
                            knownType = ObjectIntMap.class;
                        }
                        writeObjectStart(actualType, knownType);
                        ObjectIntMap.Entries it2 = ((ObjectIntMap) value).entries().iterator();
                        while (it2.hasNext()) {
                            ObjectIntMap.Entry entry2 = it2.next();
                            this.writer.name(convertToString(entry2.key));
                            writeValue(Integer.valueOf(entry2.value), Integer.class);
                        }
                        writeObjectEnd();
                        return;
                    } else if (value instanceof ObjectFloatMap) {
                        if (knownType == null) {
                            knownType = ObjectFloatMap.class;
                        }
                        writeObjectStart(actualType, knownType);
                        ObjectFloatMap.Entries it3 = ((ObjectFloatMap) value).entries().iterator();
                        while (it3.hasNext()) {
                            ObjectFloatMap.Entry entry3 = it3.next();
                            this.writer.name(convertToString(entry3.key));
                            writeValue(Float.valueOf(entry3.value), Float.class);
                        }
                        writeObjectEnd();
                        return;
                    } else if (value instanceof ObjectSet) {
                        if (knownType == null) {
                            knownType = ObjectSet.class;
                        }
                        writeObjectStart(actualType, knownType);
                        this.writer.name("values");
                        writeArrayStart();
                        ObjectSet.ObjectSetIterator it4 = ((ObjectSet) value).iterator();
                        while (it4.hasNext()) {
                            writeValue(it4.next(), elementType, (Class) null);
                        }
                        writeArrayEnd();
                        writeObjectEnd();
                        return;
                    } else if (value instanceof IntMap) {
                        if (knownType == null) {
                            knownType = IntMap.class;
                        }
                        writeObjectStart(actualType, knownType);
                        Iterator it5 = ((IntMap) value).entries().iterator();
                        while (it5.hasNext()) {
                            IntMap.Entry entry4 = (IntMap.Entry) it5.next();
                            this.writer.name(String.valueOf(entry4.key));
                            writeValue(entry4.value, elementType, (Class) null);
                        }
                        writeObjectEnd();
                        return;
                    } else if (value instanceof LongMap) {
                        if (knownType == null) {
                            knownType = LongMap.class;
                        }
                        writeObjectStart(actualType, knownType);
                        Iterator it6 = ((LongMap) value).entries().iterator();
                        while (it6.hasNext()) {
                            LongMap.Entry entry5 = (LongMap.Entry) it6.next();
                            this.writer.name(String.valueOf(entry5.key));
                            writeValue(entry5.value, elementType, (Class) null);
                        }
                        writeObjectEnd();
                        return;
                    } else if (value instanceof IntSet) {
                        if (knownType == null) {
                            knownType = IntSet.class;
                        }
                        writeObjectStart(actualType, knownType);
                        this.writer.name("values");
                        writeArrayStart();
                        IntSet.IntSetIterator iter = ((IntSet) value).iterator();
                        while (iter.hasNext) {
                            writeValue(Integer.valueOf(iter.next()), Integer.class, (Class) null);
                        }
                        writeArrayEnd();
                        writeObjectEnd();
                        return;
                    } else if (value instanceof ArrayMap) {
                        if (knownType == null) {
                            knownType = ArrayMap.class;
                        }
                        writeObjectStart(actualType, knownType);
                        ArrayMap map = (ArrayMap) value;
                        int n3 = map.size;
                        for (int i4 = 0; i4 < n3; i4++) {
                            this.writer.name(convertToString(map.keys[i4]));
                            writeValue(map.values[i4], elementType, (Class) null);
                        }
                        writeObjectEnd();
                        return;
                    } else if (value instanceof Map) {
                        if (knownType == null) {
                            knownType = HashMap.class;
                        }
                        writeObjectStart(actualType, knownType);
                        for (Map.Entry entry6 : ((Map) value).entrySet()) {
                            this.writer.name(convertToString(entry6.getKey()));
                            writeValue(entry6.getValue(), elementType, (Class) null);
                        }
                        writeObjectEnd();
                        return;
                    } else if (ClassReflection.isAssignableFrom(Enum.class, actualType)) {
                        if (this.typeName != null && (knownType == null || knownType != actualType)) {
                            if (actualType.getEnumConstants() == null) {
                                actualType = actualType.getSuperclass();
                            }
                            writeObjectStart(actualType, null);
                            this.writer.name("value");
                            this.writer.value(convertToString((Enum) value));
                            writeObjectEnd();
                            return;
                        }
                        this.writer.value(convertToString((Enum) value));
                        return;
                    } else {
                        writeObjectStart(actualType, knownType);
                        writeFields(value);
                        writeObjectEnd();
                        return;
                    }
                }
                writeObjectStart(actualType, null);
                writeValue("value", value);
                writeObjectEnd();
                return;
            }
            this.writer.value(value);
        } catch (IOException ex) {
            throw new SerializationException(ex);
        }
    }

    public void writeObjectStart(String name) {
        try {
            this.writer.name(name);
            writeObjectStart();
        } catch (IOException ex) {
            throw new SerializationException(ex);
        }
    }

    public void writeObjectStart(String name, Class actualType, Class knownType) {
        try {
            this.writer.name(name);
            writeObjectStart(actualType, knownType);
        } catch (IOException ex) {
            throw new SerializationException(ex);
        }
    }

    public void writeObjectStart() {
        try {
            this.writer.object();
        } catch (IOException ex) {
            throw new SerializationException(ex);
        }
    }

    public void writeObjectStart(Class actualType, Class knownType) {
        try {
            this.writer.object();
            if (knownType == null || knownType != actualType) {
                writeType(actualType);
            }
        } catch (IOException ex) {
            throw new SerializationException(ex);
        }
    }

    public void writeObjectEnd() {
        try {
            this.writer.pop();
        } catch (IOException ex) {
            throw new SerializationException(ex);
        }
    }

    public void writeArrayStart(String name) {
        try {
            this.writer.name(name);
            this.writer.array();
        } catch (IOException ex) {
            throw new SerializationException(ex);
        }
    }

    public void writeArrayStart() {
        try {
            this.writer.array();
        } catch (IOException ex) {
            throw new SerializationException(ex);
        }
    }

    public void writeArrayEnd() {
        try {
            this.writer.pop();
        } catch (IOException ex) {
            throw new SerializationException(ex);
        }
    }

    public void writeType(Class type) {
        if (this.typeName == null) {
            return;
        }
        String className = getTag(type);
        if (className == null) {
            className = type.getName();
        }
        try {
            this.writer.set(this.typeName, className);
        } catch (IOException ex) {
            throw new SerializationException(ex);
        }
    }

    public <T> T fromJson(Class<T> type, Reader reader) {
        return (T) readValue(type, (Class) null, new JsonReader().parse(reader));
    }

    public <T> T fromJson(Class<T> type, Class elementType, Reader reader) {
        return (T) readValue(type, elementType, new JsonReader().parse(reader));
    }

    public <T> T fromJson(Class<T> type, InputStream input) {
        return (T) readValue(type, (Class) null, new JsonReader().parse(input));
    }

    public <T> T fromJson(Class<T> type, Class elementType, InputStream input) {
        return (T) readValue(type, elementType, new JsonReader().parse(input));
    }

    public <T> T fromJson(Class<T> type, FileHandle file) {
        try {
            return (T) readValue(type, (Class) null, new JsonReader().parse(file));
        } catch (Exception ex) {
            throw new SerializationException("Error reading file: " + file, ex);
        }
    }

    public <T> T fromJson(Class<T> type, Class elementType, FileHandle file) {
        try {
            return (T) readValue(type, elementType, new JsonReader().parse(file));
        } catch (Exception ex) {
            throw new SerializationException("Error reading file: " + file, ex);
        }
    }

    public <T> T fromJson(Class<T> type, char[] data, int offset, int length) {
        return (T) readValue(type, (Class) null, new JsonReader().parse(data, offset, length));
    }

    public <T> T fromJson(Class<T> type, Class elementType, char[] data, int offset, int length) {
        return (T) readValue(type, elementType, new JsonReader().parse(data, offset, length));
    }

    public <T> T fromJson(Class<T> type, String json) {
        return (T) readValue(type, (Class) null, new JsonReader().parse(json));
    }

    public <T> T fromJson(Class<T> type, Class elementType, String json) {
        return (T) readValue(type, elementType, new JsonReader().parse(json));
    }

    public void readField(Object object, String name, JsonValue jsonData) {
        readField(object, name, name, (Class) null, jsonData);
    }

    public void readField(Object object, String name, Class elementType, JsonValue jsonData) {
        readField(object, name, name, elementType, jsonData);
    }

    public void readField(Object object, String fieldName, String jsonName, JsonValue jsonData) {
        readField(object, fieldName, jsonName, (Class) null, jsonData);
    }

    public void readField(Object object, String fieldName, String jsonName, Class elementType, JsonValue jsonMap) {
        Class type = object.getClass();
        FieldMetadata metadata = getFields(type).get(fieldName);
        if (metadata == null) {
            throw new SerializationException("Field not found: " + fieldName + " (" + type.getName() + ")");
        }
        Field field = metadata.field;
        if (elementType == null) {
            elementType = metadata.elementType;
        }
        readField(object, field, jsonName, elementType, jsonMap);
    }

    public void readField(Object object, Field field, String jsonName, Class elementType, JsonValue jsonMap) {
        JsonValue jsonValue = jsonMap.get(jsonName);
        if (jsonValue == null) {
            return;
        }
        try {
            field.set(object, readValue(field.getType(), elementType, jsonValue));
        } catch (SerializationException ex) {
            ex.addTrace(field.getName() + " (" + field.getDeclaringClass().getName() + ")");
            throw ex;
        } catch (ReflectionException ex2) {
            throw new SerializationException("Error accessing field: " + field.getName() + " (" + field.getDeclaringClass().getName() + ")", ex2);
        } catch (RuntimeException runtimeEx) {
            SerializationException ex3 = new SerializationException(runtimeEx);
            ex3.addTrace(jsonValue.trace());
            ex3.addTrace(field.getName() + " (" + field.getDeclaringClass().getName() + ")");
            throw ex3;
        }
    }

    public void readFields(Object object, JsonValue jsonMap) {
        Class type = object.getClass();
        OrderedMap<String, FieldMetadata> fields = getFields(type);
        for (JsonValue child = jsonMap.child; child != null; child = child.next) {
            FieldMetadata metadata = fields.get(child.name().replace(" ", "_"));
            if (metadata == null) {
                if (!child.name.equals(this.typeName) && !this.ignoreUnknownFields && !ignoreUnknownField(type, child.name)) {
                    SerializationException ex = new SerializationException("Field not found: " + child.name + " (" + type.getName() + ")");
                    ex.addTrace(child.trace());
                    throw ex;
                }
            } else if (!this.ignoreDeprecated || this.readDeprecated || !metadata.deprecated) {
                Field field = metadata.field;
                try {
                    field.set(object, readValue(field.getType(), metadata.elementType, child));
                } catch (SerializationException ex2) {
                    ex2.addTrace(field.getName() + " (" + type.getName() + ")");
                    throw ex2;
                } catch (ReflectionException ex3) {
                    throw new SerializationException("Error accessing field: " + field.getName() + " (" + type.getName() + ")", ex3);
                } catch (RuntimeException runtimeEx) {
                    SerializationException ex4 = new SerializationException(runtimeEx);
                    ex4.addTrace(child.trace());
                    ex4.addTrace(field.getName() + " (" + type.getName() + ")");
                    throw ex4;
                }
            }
        }
    }

    protected boolean ignoreUnknownField(Class type, String fieldName) {
        return false;
    }

    public <T> T readValue(String name, Class<T> type, JsonValue jsonMap) {
        return (T) readValue(type, (Class) null, jsonMap.get(name));
    }

    public <T> T readValue(String name, Class<T> type, T defaultValue, JsonValue jsonMap) {
        JsonValue jsonValue = jsonMap.get(name);
        return jsonValue == null ? defaultValue : (T) readValue(type, (Class) null, jsonValue);
    }

    public <T> T readValue(String name, Class<T> type, Class elementType, JsonValue jsonMap) {
        return (T) readValue(type, elementType, jsonMap.get(name));
    }

    public <T> T readValue(String name, Class<T> type, Class elementType, T defaultValue, JsonValue jsonMap) {
        JsonValue jsonValue = jsonMap.get(name);
        return (T) readValue((Class<Class>) type, elementType, (Class) defaultValue, jsonValue);
    }

    public <T> T readValue(Class<T> type, Class elementType, T defaultValue, JsonValue jsonData) {
        return jsonData == null ? defaultValue : (T) readValue(type, elementType, jsonData);
    }

    public <T> T readValue(Class<T> type, JsonValue jsonData) {
        return (T) readValue(type, (Class) null, jsonData);
    }

    /* JADX WARN: Code restructure failed: missing block: B:138:0x01f7, code lost:
        if (r10 == java.lang.Object.class) goto L194;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v19, types: [T, com.badlogic.gdx.utils.IntSet] */
    /* JADX WARN: Type inference failed for: r0v2, types: [T, java.lang.String] */
    /* JADX WARN: Type inference failed for: r12v0, types: [com.badlogic.gdx.utils.JsonValue, T] */
    /* JADX WARN: Type inference failed for: r12v6, types: [com.badlogic.gdx.utils.JsonValue, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r1v111, types: [com.badlogic.gdx.utils.Queue] */
    /* JADX WARN: Type inference failed for: r1v115, types: [com.badlogic.gdx.utils.Array] */
    /* JADX WARN: Type inference failed for: r4v18, types: [T, java.util.Map] */
    /* JADX WARN: Type inference failed for: r4v20, types: [T, com.badlogic.gdx.utils.ArrayMap] */
    /* JADX WARN: Type inference failed for: r4v25, types: [com.badlogic.gdx.utils.LongMap, T] */
    /* JADX WARN: Type inference failed for: r4v27, types: [T, com.badlogic.gdx.utils.IntMap] */
    /* JADX WARN: Type inference failed for: r4v29, types: [T, com.badlogic.gdx.utils.ObjectSet] */
    /* JADX WARN: Type inference failed for: r4v31, types: [T, com.badlogic.gdx.utils.ObjectFloatMap] */
    /* JADX WARN: Type inference failed for: r4v33, types: [T, com.badlogic.gdx.utils.ObjectIntMap] */
    /* JADX WARN: Type inference failed for: r4v35, types: [T, com.badlogic.gdx.utils.ObjectMap] */
    /* JADX WARN: Type inference failed for: r4v39, types: [java.lang.StringBuilder] */
    /* JADX WARN: Type inference failed for: r7v0, types: [java.lang.Enum, T] */
    /* JADX WARN: Type inference failed for: r9v0, types: [com.badlogic.gdx.utils.Json] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public <T> T readValue(java.lang.Class<T> r10, java.lang.Class r11, com.badlogic.gdx.utils.JsonValue r12) {
        /*
            Method dump skipped, instructions count: 1087
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.Json.readValue(java.lang.Class, java.lang.Class, com.badlogic.gdx.utils.JsonValue):java.lang.Object");
    }

    public void copyFields(Object from, Object to) {
        OrderedMap<String, FieldMetadata> toFields = getFields(to.getClass());
        ObjectMap.Entries<String, FieldMetadata> it = getFields(from.getClass()).iterator();
        while (it.hasNext()) {
            ObjectMap.Entry entry = it.next();
            FieldMetadata toField = toFields.get(entry.key);
            Field fromField = ((FieldMetadata) entry.value).field;
            if (toField == null) {
                throw new SerializationException("To object is missing field: " + ((String) entry.key));
            }
            try {
                toField.field.set(to, fromField.get(from));
            } catch (ReflectionException ex) {
                throw new SerializationException("Error copying field: " + fromField.getName(), ex);
            }
        }
    }

    private String convertToString(Enum e) {
        return this.enumNames ? e.name() : e.toString();
    }

    private String convertToString(Object object) {
        return object instanceof Enum ? convertToString((Enum) object) : object instanceof Class ? ((Class) object).getName() : String.valueOf(object);
    }

    protected Object newInstance(Class type) {
        try {
            return ClassReflection.newInstance(type);
        } catch (Exception e) {
            ex = e;
            try {
                Constructor constructor = ClassReflection.getDeclaredConstructor(type, new Class[0]);
                constructor.setAccessible(true);
                return constructor.newInstance(new Object[0]);
            } catch (ReflectionException e2) {
                if (ClassReflection.isAssignableFrom(Enum.class, type)) {
                    if (type.getEnumConstants() == null) {
                        type = type.getSuperclass();
                    }
                    return type.getEnumConstants()[0];
                } else if (type.isArray()) {
                    throw new SerializationException("Encountered JSON object when expected array of type: " + type.getName(), ex);
                } else if (ClassReflection.isMemberClass(type) && !ClassReflection.isStaticClass(type)) {
                    throw new SerializationException("Class cannot be created (non-static member class): " + type.getName(), ex);
                } else {
                    throw new SerializationException("Class cannot be created (missing no-arg constructor): " + type.getName(), ex);
                }
            } catch (SecurityException e3) {
                throw new SerializationException("Error constructing instance of class: " + type.getName(), ex);
            } catch (Exception privateConstructorException) {
                ex = privateConstructorException;
                throw new SerializationException("Error constructing instance of class: " + type.getName(), ex);
            }
        }
    }

    public String prettyPrint(Object object) {
        return prettyPrint(object, 0);
    }

    public String prettyPrint(String json) {
        return prettyPrint(json, 0);
    }

    public String prettyPrint(Object object, int singleLineColumns) {
        return prettyPrint(toJson(object), singleLineColumns);
    }

    public String prettyPrint(String json, int singleLineColumns) {
        return new JsonReader().parse(json).prettyPrint(this.outputType, singleLineColumns);
    }

    public String prettyPrint(Object object, JsonValue.PrettyPrintSettings settings) {
        return prettyPrint(toJson(object), settings);
    }

    public String prettyPrint(String json, JsonValue.PrettyPrintSettings settings) {
        return new JsonReader().parse(json).prettyPrint(settings);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class FieldMetadata {
        boolean deprecated;
        Class elementType;
        final Field field;

        public FieldMetadata(Field field) {
            this.field = field;
            int index = (ClassReflection.isAssignableFrom(ObjectMap.class, field.getType()) || ClassReflection.isAssignableFrom(Map.class, field.getType())) ? 1 : 0;
            this.elementType = field.getElementType(index);
            this.deprecated = field.isAnnotationPresent(Deprecated.class);
        }
    }

    /* loaded from: classes.dex */
    public static abstract class ReadOnlySerializer<T> implements Serializer<T> {
        @Override // com.badlogic.gdx.utils.Json.Serializer
        public abstract T read(Json json, JsonValue jsonValue, Class cls);

        @Override // com.badlogic.gdx.utils.Json.Serializer
        public void write(Json json, T object, Class knownType) {
        }
    }
}