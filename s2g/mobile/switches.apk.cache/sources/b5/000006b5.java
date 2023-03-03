package kotlin;

import java.io.PrintStream;
import java.io.PrintWriter;
import kotlin.internal.PlatformImplementationsKt;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: Exceptions.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000&\n\u0000\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\u0010\u0003\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u001a\u0012\u0010\b\u001a\u00020\t*\u00020\u00032\u0006\u0010\n\u001a\u00020\u0003\u001a\r\u0010\u000b\u001a\u00020\t*\u00020\u0003H\u0087\b\u001a\u0015\u0010\u000b\u001a\u00020\t*\u00020\u00032\u0006\u0010\f\u001a\u00020\rH\u0087\b\u001a\u0015\u0010\u000b\u001a\u00020\t*\u00020\u00032\u0006\u0010\u000e\u001a\u00020\u000fH\u0087\b\"!\u0010\u0000\u001a\b\u0012\u0004\u0012\u00020\u00020\u0001*\u00020\u00038F¢\u0006\f\u0012\u0004\b\u0004\u0010\u0005\u001a\u0004\b\u0006\u0010\u0007¨\u0006\u0010"}, d2 = {"stackTrace", BuildConfig.FLAVOR, "Ljava/lang/StackTraceElement;", BuildConfig.FLAVOR, "stackTrace$annotations", "(Ljava/lang/Throwable;)V", "getStackTrace", "(Ljava/lang/Throwable;)[Ljava/lang/StackTraceElement;", "addSuppressed", BuildConfig.FLAVOR, "exception", "printStackTrace", "stream", "Ljava/io/PrintStream;", "writer", "Ljava/io/PrintWriter;", "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/ExceptionsKt")
/* loaded from: classes.dex */
public class ExceptionsKt__ExceptionsKt {
    public static /* synthetic */ void stackTrace$annotations(Throwable th) {
    }

    private static final void printStackTrace(Throwable $this$printStackTrace) {
        if ($this$printStackTrace == null) {
            throw new TypeCastException("null cannot be cast to non-null type java.lang.Throwable");
        }
        $this$printStackTrace.printStackTrace();
    }

    private static final void printStackTrace(Throwable $this$printStackTrace, PrintWriter writer) {
        if ($this$printStackTrace == null) {
            throw new TypeCastException("null cannot be cast to non-null type java.lang.Throwable");
        }
        $this$printStackTrace.printStackTrace(writer);
    }

    private static final void printStackTrace(Throwable $this$printStackTrace, PrintStream stream) {
        if ($this$printStackTrace == null) {
            throw new TypeCastException("null cannot be cast to non-null type java.lang.Throwable");
        }
        $this$printStackTrace.printStackTrace(stream);
    }

    public static final StackTraceElement[] getStackTrace(Throwable stackTrace) {
        Intrinsics.checkParameterIsNotNull(stackTrace, "$this$stackTrace");
        StackTraceElement[] stackTrace2 = stackTrace.getStackTrace();
        if (stackTrace2 == null) {
            Intrinsics.throwNpe();
        }
        return stackTrace2;
    }

    public static final void addSuppressed(Throwable addSuppressed, Throwable exception) {
        Intrinsics.checkParameterIsNotNull(addSuppressed, "$this$addSuppressed");
        Intrinsics.checkParameterIsNotNull(exception, "exception");
        PlatformImplementationsKt.IMPLEMENTATIONS.addSuppressed(addSuppressed, exception);
    }
}