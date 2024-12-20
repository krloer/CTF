package kotlin;

import s2g.project.game.BuildConfig;

/* compiled from: NoWhenBranchMatchedException.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0003\n\u0002\b\u0003\b\u0016\u0018\u00002\u00060\u0001j\u0002`\u0002B\u0007\b\u0016¢\u0006\u0002\u0010\u0003B\u0011\b\u0016\u0012\b\u0010\u0004\u001a\u0004\u0018\u00010\u0005¢\u0006\u0002\u0010\u0006B\u001b\b\u0016\u0012\b\u0010\u0004\u001a\u0004\u0018\u00010\u0005\u0012\b\u0010\u0007\u001a\u0004\u0018\u00010\b¢\u0006\u0002\u0010\tB\u0011\b\u0016\u0012\b\u0010\u0007\u001a\u0004\u0018\u00010\b¢\u0006\u0002\u0010\n¨\u0006\u000b"}, d2 = {"Lkotlin/NoWhenBranchMatchedException;", "Ljava/lang/RuntimeException;", "Lkotlin/RuntimeException;", "()V", "message", BuildConfig.FLAVOR, "(Ljava/lang/String;)V", "cause", BuildConfig.FLAVOR, "(Ljava/lang/String;Ljava/lang/Throwable;)V", "(Ljava/lang/Throwable;)V", "kotlin-stdlib"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public class NoWhenBranchMatchedException extends RuntimeException {
    public NoWhenBranchMatchedException() {
    }

    public NoWhenBranchMatchedException(String message) {
        super(message);
    }

    public NoWhenBranchMatchedException(String message, Throwable cause) {
        super(message, cause);
    }

    public NoWhenBranchMatchedException(Throwable cause) {
        super(cause);
    }
}