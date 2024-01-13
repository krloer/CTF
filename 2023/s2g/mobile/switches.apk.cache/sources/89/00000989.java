package kotlin.sequences;

import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.jvm.internal.markers.KMappedMarker;
import s2g.project.game.BuildConfig;

/* compiled from: Sequences.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u001d\n\u0000\n\u0002\u0010(\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\u0003*\u0001\u0000\b\n\u0018\u00002\b\u0012\u0004\u0012\u00028\u00000\u0001J\t\u0010\u000b\u001a\u00020\fH\u0096\u0002J\u000e\u0010\r\u001a\u00028\u0000H\u0096\u0002¢\u0006\u0002\u0010\u000eR\u0017\u0010\u0002\u001a\b\u0012\u0004\u0012\u00028\u00000\u0001¢\u0006\b\n\u0000\u001a\u0004\b\u0003\u0010\u0004R\u001a\u0010\u0005\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0007\u0010\b\"\u0004\b\t\u0010\n¨\u0006\u000f"}, d2 = {"kotlin/sequences/TakeSequence$iterator$1", BuildConfig.FLAVOR, "iterator", "getIterator", "()Ljava/util/Iterator;", "left", BuildConfig.FLAVOR, "getLeft", "()I", "setLeft", "(I)V", "hasNext", BuildConfig.FLAVOR, "next", "()Ljava/lang/Object;", "kotlin-stdlib"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class TakeSequence$iterator$1 implements Iterator<T>, KMappedMarker {
    private final Iterator<T> iterator;
    private int left;
    final /* synthetic */ TakeSequence this$0;

    @Override // java.util.Iterator
    public void remove() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public TakeSequence$iterator$1(TakeSequence $outer) {
        int i;
        Sequence sequence;
        this.this$0 = $outer;
        i = $outer.count;
        this.left = i;
        sequence = $outer.sequence;
        this.iterator = sequence.iterator();
    }

    public final int getLeft() {
        return this.left;
    }

    public final void setLeft(int i) {
        this.left = i;
    }

    public final Iterator<T> getIterator() {
        return this.iterator;
    }

    /* JADX WARN: Type inference failed for: r0v5, types: [T, java.lang.Object] */
    @Override // java.util.Iterator
    public T next() {
        int i = this.left;
        if (i == 0) {
            throw new NoSuchElementException();
        }
        this.left = i - 1;
        return this.iterator.next();
    }

    @Override // java.util.Iterator
    public boolean hasNext() {
        return this.left > 0 && this.iterator.hasNext();
    }
}