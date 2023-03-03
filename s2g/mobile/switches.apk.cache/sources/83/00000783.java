package kotlin.collections;

import java.util.Arrays;
import java.util.Iterator;
import java.util.RandomAccess;
import kotlin.Metadata;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;

/* compiled from: SlidingWindow.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0011\n\u0002\u0010\u0000\n\u0002\b\b\n\u0002\u0010\u0002\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010(\n\u0002\b\f\b\u0002\u0018\u0000*\u0004\b\u0000\u0010\u00012\b\u0012\u0004\u0012\u0002H\u00010\u00022\u00060\u0003j\u0002`\u0004B\r\u0012\u0006\u0010\u0005\u001a\u00020\u0006¢\u0006\u0002\u0010\u0007J\u0013\u0010\u0012\u001a\u00020\u00132\u0006\u0010\u0014\u001a\u00028\u0000¢\u0006\u0002\u0010\u0015J\u0016\u0010\u0016\u001a\u00028\u00002\u0006\u0010\u0017\u001a\u00020\u0006H\u0096\u0002¢\u0006\u0002\u0010\u0018J\u0006\u0010\u0019\u001a\u00020\u001aJ\u000f\u0010\u001b\u001a\b\u0012\u0004\u0012\u00028\u00000\u001cH\u0096\u0002J\u000e\u0010\u001d\u001a\u00020\u00132\u0006\u0010\u001e\u001a\u00020\u0006J\u0015\u0010\u001f\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\n0\tH\u0014¢\u0006\u0002\u0010 J'\u0010\u001f\u001a\b\u0012\u0004\u0012\u0002H\u00010\t\"\u0004\b\u0001\u0010\u00012\f\u0010!\u001a\b\u0012\u0004\u0012\u0002H\u00010\tH\u0014¢\u0006\u0002\u0010\"J9\u0010#\u001a\u00020\u0013\"\u0004\b\u0001\u0010\u0001*\b\u0012\u0004\u0012\u0002H\u00010\t2\u0006\u0010\u0014\u001a\u0002H\u00012\b\b\u0002\u0010$\u001a\u00020\u00062\b\b\u0002\u0010%\u001a\u00020\u0006H\u0002¢\u0006\u0002\u0010&J\u0015\u0010'\u001a\u00020\u0006*\u00020\u00062\u0006\u0010\u001e\u001a\u00020\u0006H\u0082\bR\u0018\u0010\b\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\n0\tX\u0082\u0004¢\u0006\u0004\n\u0002\u0010\u000bR\u0011\u0010\u0005\u001a\u00020\u0006¢\u0006\b\n\u0000\u001a\u0004\b\f\u0010\rR\u001e\u0010\u000f\u001a\u00020\u00062\u0006\u0010\u000e\u001a\u00020\u0006@RX\u0096\u000e¢\u0006\b\n\u0000\u001a\u0004\b\u0010\u0010\rR\u000e\u0010\u0011\u001a\u00020\u0006X\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006("}, d2 = {"Lkotlin/collections/RingBuffer;", "T", "Lkotlin/collections/AbstractList;", "Ljava/util/RandomAccess;", "Lkotlin/collections/RandomAccess;", "capacity", BuildConfig.FLAVOR, "(I)V", "buffer", BuildConfig.FLAVOR, BuildConfig.FLAVOR, "[Ljava/lang/Object;", "getCapacity", "()I", "<set-?>", "size", "getSize", "startIndex", "add", BuildConfig.FLAVOR, "element", "(Ljava/lang/Object;)V", "get", "index", "(I)Ljava/lang/Object;", "isFull", BuildConfig.FLAVOR, "iterator", BuildConfig.FLAVOR, "removeFirst", "n", "toArray", "()[Ljava/lang/Object;", "array", "([Ljava/lang/Object;)[Ljava/lang/Object;", "fill", "fromIndex", "toIndex", "([Ljava/lang/Object;Ljava/lang/Object;II)V", "forward", "kotlin-stdlib"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class RingBuffer<T> extends AbstractList<T> implements RandomAccess {
    private final Object[] buffer;
    private final int capacity;
    private int size;
    private int startIndex;

    public RingBuffer(int capacity) {
        this.capacity = capacity;
        if (this.capacity >= 0) {
            this.buffer = new Object[this.capacity];
            return;
        }
        throw new IllegalArgumentException(("ring buffer capacity should not be negative but it is " + this.capacity).toString());
    }

    public static final /* synthetic */ Object[] access$getBuffer$p(RingBuffer $this) {
        return $this.buffer;
    }

    public static final /* synthetic */ int access$getStartIndex$p(RingBuffer $this) {
        return $this.startIndex;
    }

    public final int getCapacity() {
        return this.capacity;
    }

    @Override // kotlin.collections.AbstractList, kotlin.collections.AbstractCollection
    public int getSize() {
        return this.size;
    }

    @Override // kotlin.collections.AbstractList, java.util.List
    public T get(int index) {
        AbstractList.Companion.checkElementIndex$kotlin_stdlib(index, size());
        Object[] objArr = this.buffer;
        int $this$forward$iv = this.startIndex;
        return (T) objArr[($this$forward$iv + index) % getCapacity()];
    }

    public final boolean isFull() {
        return size() == this.capacity;
    }

    @Override // kotlin.collections.AbstractList, kotlin.collections.AbstractCollection, java.util.Collection, java.lang.Iterable
    public Iterator<T> iterator() {
        return new AbstractIterator<T>() { // from class: kotlin.collections.RingBuffer$iterator$1
            private int count;
            private int index;

            /* JADX INFO: Access modifiers changed from: package-private */
            {
                this.count = RingBuffer.this.size();
                this.index = RingBuffer.access$getStartIndex$p(RingBuffer.this);
            }

            @Override // kotlin.collections.AbstractIterator
            protected void computeNext() {
                if (this.count == 0) {
                    done();
                    return;
                }
                setNext(RingBuffer.access$getBuffer$p(RingBuffer.this)[this.index]);
                RingBuffer this_$iv = RingBuffer.this;
                int $this$forward$iv = this.index;
                this.index = ($this$forward$iv + 1) % this_$iv.getCapacity();
                this.count--;
            }
        };
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.collections.AbstractCollection, java.util.Collection
    public <T> T[] toArray(T[] array) {
        Object[] result;
        Intrinsics.checkParameterIsNotNull(array, "array");
        if (array.length < size()) {
            result = (T[]) Arrays.copyOf(array, size());
            Intrinsics.checkExpressionValueIsNotNull(result, "java.util.Arrays.copyOf(this, newSize)");
        } else {
            result = array;
        }
        int size = size();
        int widx = 0;
        for (int idx = this.startIndex; widx < size && idx < this.capacity; idx++) {
            result[widx] = this.buffer[idx];
            widx++;
        }
        int idx2 = 0;
        while (widx < size) {
            result[widx] = this.buffer[idx2];
            widx++;
            idx2++;
        }
        if (result.length > size()) {
            result[size()] = null;
        }
        if (result != null) {
            return (T[]) result;
        }
        throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.collections.AbstractCollection, java.util.Collection
    public Object[] toArray() {
        return toArray(new Object[size()]);
    }

    @Override // kotlin.collections.AbstractCollection, java.util.Collection
    public final void add(T t) {
        if (isFull()) {
            throw new IllegalStateException("ring buffer is full");
        }
        Object[] objArr = this.buffer;
        int $this$forward$iv = this.startIndex;
        int n$iv = size();
        objArr[($this$forward$iv + n$iv) % getCapacity()] = t;
        this.size = size() + 1;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void removeFirst(int n) {
        if (!(n >= 0)) {
            throw new IllegalArgumentException(("n shouldn't be negative but it is " + n).toString());
        }
        if (!(n <= size())) {
            throw new IllegalArgumentException(("n shouldn't be greater than the buffer size: n = " + n + ", size = " + size()).toString());
        } else if (n > 0) {
            int start = this.startIndex;
            int end = (start + n) % getCapacity();
            if (start <= end) {
                fill(this.buffer, null, start, end);
            } else {
                fill(this.buffer, null, start, this.capacity);
                fill(this.buffer, null, 0, end);
            }
            this.startIndex = end;
            this.size = size() - n;
        }
    }

    public final int forward(int $this$forward, int n) {
        return ($this$forward + n) % getCapacity();
    }

    static /* synthetic */ void fill$default(RingBuffer ringBuffer, Object[] objArr, Object obj, int i, int i2, int i3, Object obj2) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = objArr.length;
        }
        ringBuffer.fill(objArr, obj, i, i2);
    }

    private final <T> void fill(T[] tArr, T t, int fromIndex, int toIndex) {
        for (int idx = fromIndex; idx < toIndex; idx++) {
            tArr[idx] = t;
        }
    }
}