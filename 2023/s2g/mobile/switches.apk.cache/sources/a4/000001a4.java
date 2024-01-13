package com.badlogic.gdx.graphics.g3d.particles;

import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.reflect.ArrayReflection;

/* loaded from: classes.dex */
public class ParallelArray {
    public int capacity;
    Array<Channel> arrays = new Array<>(false, 2, Channel.class);
    public int size = 0;

    /* loaded from: classes.dex */
    public interface ChannelInitializer<T extends Channel> {
        void init(T t);
    }

    /* loaded from: classes.dex */
    public static class ChannelDescriptor {
        public int count;
        public int id;
        public Class<?> type;

        public ChannelDescriptor(int id, Class<?> type, int count) {
            this.id = id;
            this.type = type;
            this.count = count;
        }
    }

    /* loaded from: classes.dex */
    public abstract class Channel {
        public Object data;
        public int id;
        public int strideSize;

        public abstract void add(int i, Object... objArr);

        protected abstract void setCapacity(int i);

        public abstract void swap(int i, int i2);

        public Channel(int id, Object data, int strideSize) {
            this.id = id;
            this.strideSize = strideSize;
            this.data = data;
        }
    }

    /* loaded from: classes.dex */
    public class FloatChannel extends Channel {
        public float[] data;

        public FloatChannel(int id, int strideSize, int size) {
            super(id, new float[size * strideSize], strideSize);
            this.data = (float[]) super.data;
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParallelArray.Channel
        public void add(int index, Object... objects) {
            int i = this.strideSize * ParallelArray.this.size;
            int c = this.strideSize + i;
            int k = 0;
            while (i < c) {
                this.data[i] = ((Float) objects[k]).floatValue();
                i++;
                k++;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParallelArray.Channel
        public void swap(int i, int k) {
            int i2 = this.strideSize * i;
            int i3 = this.strideSize;
            int k2 = i3 * k;
            int k3 = this.strideSize;
            int c = k3 + i2;
            while (i2 < c) {
                float[] fArr = this.data;
                float t = fArr[i2];
                fArr[i2] = fArr[k2];
                fArr[k2] = t;
                i2++;
                k2++;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParallelArray.Channel
        public void setCapacity(int requiredCapacity) {
            float[] newData = new float[this.strideSize * requiredCapacity];
            float[] fArr = this.data;
            System.arraycopy(fArr, 0, newData, 0, Math.min(fArr.length, newData.length));
            this.data = newData;
            super.data = newData;
        }
    }

    /* loaded from: classes.dex */
    public class IntChannel extends Channel {
        public int[] data;

        public IntChannel(int id, int strideSize, int size) {
            super(id, new int[size * strideSize], strideSize);
            this.data = (int[]) super.data;
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParallelArray.Channel
        public void add(int index, Object... objects) {
            int i = this.strideSize * ParallelArray.this.size;
            int c = this.strideSize + i;
            int k = 0;
            while (i < c) {
                this.data[i] = ((Integer) objects[k]).intValue();
                i++;
                k++;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParallelArray.Channel
        public void swap(int i, int k) {
            int i2 = this.strideSize * i;
            int i3 = this.strideSize;
            int k2 = i3 * k;
            int k3 = this.strideSize;
            int c = k3 + i2;
            while (i2 < c) {
                int[] iArr = this.data;
                int t = iArr[i2];
                iArr[i2] = iArr[k2];
                iArr[k2] = t;
                i2++;
                k2++;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParallelArray.Channel
        public void setCapacity(int requiredCapacity) {
            int[] newData = new int[this.strideSize * requiredCapacity];
            int[] iArr = this.data;
            System.arraycopy(iArr, 0, newData, 0, Math.min(iArr.length, newData.length));
            this.data = newData;
            super.data = newData;
        }
    }

    /* loaded from: classes.dex */
    public class ObjectChannel<T> extends Channel {
        Class<T> componentType;
        public T[] data;

        public ObjectChannel(int id, int strideSize, int size, Class<T> type) {
            super(id, ArrayReflection.newInstance(type, size * strideSize), strideSize);
            this.componentType = type;
            this.data = (T[]) ((Object[]) super.data);
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Override // com.badlogic.gdx.graphics.g3d.particles.ParallelArray.Channel
        public void add(int index, Object... objects) {
            int i = this.strideSize * ParallelArray.this.size;
            int c = this.strideSize + i;
            int k = 0;
            while (i < c) {
                this.data[i] = objects[k];
                i++;
                k++;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParallelArray.Channel
        public void swap(int i, int k) {
            int i2 = this.strideSize * i;
            int i3 = this.strideSize;
            int k2 = i3 * k;
            int k3 = this.strideSize;
            int c = k3 + i2;
            while (i2 < c) {
                T[] tArr = this.data;
                T t = tArr[i2];
                tArr[i2] = tArr[k2];
                tArr[k2] = t;
                i2++;
                k2++;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParallelArray.Channel
        public void setCapacity(int requiredCapacity) {
            T[] newData = (T[]) ((Object[]) ArrayReflection.newInstance(this.componentType, this.strideSize * requiredCapacity));
            T[] tArr = this.data;
            System.arraycopy(tArr, 0, newData, 0, Math.min(tArr.length, newData.length));
            this.data = newData;
            super.data = newData;
        }
    }

    public ParallelArray(int capacity) {
        this.capacity = capacity;
    }

    public <T extends Channel> T addChannel(ChannelDescriptor channelDescriptor) {
        return (T) addChannel(channelDescriptor, null);
    }

    public <T extends Channel> T addChannel(ChannelDescriptor channelDescriptor, ChannelInitializer<T> initializer) {
        T channel = (T) getChannel(channelDescriptor);
        if (channel == null) {
            channel = (T) allocateChannel(channelDescriptor);
            if (initializer != null) {
                initializer.init(channel);
            }
            this.arrays.add(channel);
        }
        return channel;
    }

    private <T extends Channel> T allocateChannel(ChannelDescriptor channelDescriptor) {
        if (channelDescriptor.type == Float.TYPE) {
            return new FloatChannel(channelDescriptor.id, channelDescriptor.count, this.capacity);
        }
        if (channelDescriptor.type == Integer.TYPE) {
            return new IntChannel(channelDescriptor.id, channelDescriptor.count, this.capacity);
        }
        return new ObjectChannel(channelDescriptor.id, channelDescriptor.count, this.capacity, channelDescriptor.type);
    }

    public <T> void removeArray(int id) {
        this.arrays.removeIndex(findIndex(id));
    }

    private int findIndex(int id) {
        for (int i = 0; i < this.arrays.size; i++) {
            Channel array = this.arrays.items[i];
            if (array.id == id) {
                return i;
            }
        }
        return -1;
    }

    public void addElement(Object... values) {
        if (this.size == this.capacity) {
            throw new GdxRuntimeException("Capacity reached, cannot add other elements");
        }
        int k = 0;
        Array.ArrayIterator<Channel> it = this.arrays.iterator();
        while (it.hasNext()) {
            Channel strideArray = it.next();
            strideArray.add(k, values);
            k += strideArray.strideSize;
        }
        this.size++;
    }

    public void removeElement(int index) {
        int last = this.size - 1;
        Array.ArrayIterator<Channel> it = this.arrays.iterator();
        while (it.hasNext()) {
            Channel strideArray = it.next();
            strideArray.swap(index, last);
        }
        this.size = last;
    }

    public <T extends Channel> T getChannel(ChannelDescriptor descriptor) {
        Array.ArrayIterator<Channel> it = this.arrays.iterator();
        while (it.hasNext()) {
            T t = (T) it.next();
            if (t.id == descriptor.id) {
                return t;
            }
        }
        return null;
    }

    public void clear() {
        this.arrays.clear();
        this.size = 0;
    }

    public void setCapacity(int requiredCapacity) {
        if (this.capacity != requiredCapacity) {
            Array.ArrayIterator<Channel> it = this.arrays.iterator();
            while (it.hasNext()) {
                Channel channel = it.next();
                channel.setCapacity(requiredCapacity);
            }
            this.capacity = requiredCapacity;
        }
    }
}