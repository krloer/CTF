package kotlin.text;

import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Lambda;
import kotlin.ranges.RangesKt;
import s2g.project.game.BuildConfig;

/* compiled from: _Strings.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\f\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0002\u0010\u0000\u001a\u0002H\u0001\"\u0004\b\u0000\u0010\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\n¢\u0006\u0004\b\u0004\u0010\u0005"}, d2 = {"<anonymous>", "R", "index", BuildConfig.FLAVOR, "invoke", "(I)Ljava/lang/Object;"}, k = 3, mv = {1, 1, 15})
/* loaded from: classes.dex */
final class StringsKt___StringsKt$windowedSequence$2 extends Lambda implements Function1<Integer, R> {
    final /* synthetic */ int $size;
    final /* synthetic */ CharSequence $this_windowedSequence;
    final /* synthetic */ Function1 $transform;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public StringsKt___StringsKt$windowedSequence$2(CharSequence charSequence, Function1 function1, int i) {
        super(1);
        this.$this_windowedSequence = charSequence;
        this.$transform = function1;
        this.$size = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public /* bridge */ /* synthetic */ Object invoke(Integer num) {
        return invoke(num.intValue());
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [R, java.lang.Object] */
    public final R invoke(int index) {
        Function1 function1 = this.$transform;
        CharSequence charSequence = this.$this_windowedSequence;
        return function1.invoke(charSequence.subSequence(index, RangesKt.coerceAtMost(this.$size + index, charSequence.length())));
    }
}