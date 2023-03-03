package kotlin.sequences;

import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.internal.Ref;
import s2g.project.game.BuildConfig;

/* compiled from: _Sequences.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0011\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010(\n\u0000*\u0001\u0000\b\n\u0018\u00002\b\u0012\u0004\u0012\u00028\u00000\u0001J\u000f\u0010\u0002\u001a\b\u0012\u0004\u0012\u00028\u00000\u0003H\u0096\u0002¨\u0006\u0004"}, d2 = {"kotlin/sequences/SequencesKt___SequencesKt$minus$1", "Lkotlin/sequences/Sequence;", "iterator", BuildConfig.FLAVOR, "kotlin-stdlib"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class SequencesKt___SequencesKt$minus$1 implements Sequence<T> {
    final /* synthetic */ Object $element;
    final /* synthetic */ Sequence $this_minus;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SequencesKt___SequencesKt$minus$1(Sequence<? extends T> sequence, Object $captured_local_variable$1) {
        this.$this_minus = sequence;
        this.$element = $captured_local_variable$1;
    }

    @Override // kotlin.sequences.Sequence
    public Iterator<T> iterator() {
        Ref.BooleanRef removed = new Ref.BooleanRef();
        removed.element = false;
        return SequencesKt.filter(this.$this_minus, new SequencesKt___SequencesKt$minus$1$iterator$1(this, removed)).iterator();
    }
}