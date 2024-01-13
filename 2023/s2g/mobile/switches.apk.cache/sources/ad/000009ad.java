package kotlin.text;

import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Lambda;
import s2g.project.game.BuildConfig;

/* compiled from: Regex.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000 \n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0002\b\u0004\n\u0002\b\u0004\n\u0002\b\u0004\n\u0002\b\u0005\u0010\u0000\u001a\u00020\u0001\"\u0014\b\u0000\u0010\u0002\u0018\u0001*\u00020\u0003*\b\u0012\u0004\u0012\u0002H\u00020\u00042\u000e\u0010\u0005\u001a\n \u0006*\u0004\u0018\u0001H\u0002H\u0002H\n¢\u0006\u0004\b\u0007\u0010\b¨\u0006\t"}, d2 = {"<anonymous>", BuildConfig.FLAVOR, "T", "Lkotlin/text/FlagEnum;", BuildConfig.FLAVOR, "it", "kotlin.jvm.PlatformType", "invoke", "(Ljava/lang/Enum;)Z", "kotlin/text/RegexKt$fromInt$1$1"}, k = 3, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class Regex$fromInt$$inlined$apply$lambda$1 extends Lambda implements Function1<T, Boolean> {
    final /* synthetic */ int $value$inlined;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Regex$fromInt$$inlined$apply$lambda$1(int i) {
        super(1);
        this.$value$inlined = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public /* bridge */ /* synthetic */ Boolean invoke(Object obj) {
        return Boolean.valueOf(invoke((Enum) obj));
    }

    /* JADX WARN: Incorrect types in method signature: (TT;)Z */
    public final boolean invoke(Enum it) {
        return (this.$value$inlined & ((FlagEnum) it).getMask()) == ((FlagEnum) it).getValue();
    }
}