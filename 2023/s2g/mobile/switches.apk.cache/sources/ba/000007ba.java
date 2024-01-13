package kotlin.concurrent;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;

/* compiled from: Thread.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000:\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\u001aJ\u0010\u0000\u001a\u00020\u00012\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00032\n\b\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u00062\n\b\u0002\u0010\u0007\u001a\u0004\u0018\u00010\b2\b\b\u0002\u0010\t\u001a\u00020\n2\f\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\r0\f\u001a0\u0010\u000e\u001a\u0002H\u000f\"\b\b\u0000\u0010\u000f*\u00020\u0010*\b\u0012\u0004\u0012\u0002H\u000f0\u00112\f\u0010\u0012\u001a\b\u0012\u0004\u0012\u0002H\u000f0\fH\u0087\b¢\u0006\u0002\u0010\u0013¨\u0006\u0014"}, d2 = {"thread", "Ljava/lang/Thread;", "start", BuildConfig.FLAVOR, "isDaemon", "contextClassLoader", "Ljava/lang/ClassLoader;", "name", BuildConfig.FLAVOR, "priority", BuildConfig.FLAVOR, "block", "Lkotlin/Function0;", BuildConfig.FLAVOR, "getOrSet", "T", BuildConfig.FLAVOR, "Ljava/lang/ThreadLocal;", "default", "(Ljava/lang/ThreadLocal;Lkotlin/jvm/functions/Function0;)Ljava/lang/Object;", "kotlin-stdlib"}, k = 2, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class ThreadsKt {
    public static /* synthetic */ Thread thread$default(boolean z, boolean z2, ClassLoader classLoader, String str, int i, Function0 function0, int i2, Object obj) {
        ClassLoader classLoader2;
        String str2;
        boolean z3 = (i2 & 1) != 0 ? true : z;
        boolean z4 = (i2 & 2) != 0 ? false : z2;
        if ((i2 & 4) == 0) {
            classLoader2 = classLoader;
        } else {
            classLoader2 = null;
        }
        if ((i2 & 8) == 0) {
            str2 = str;
        } else {
            str2 = null;
        }
        return thread(z3, z4, classLoader2, str2, (i2 & 16) != 0 ? -1 : i, function0);
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [kotlin.concurrent.ThreadsKt$thread$thread$1] */
    public static final Thread thread(boolean start, boolean isDaemon, ClassLoader contextClassLoader, String name, int priority, final Function0<Unit> block) {
        Intrinsics.checkParameterIsNotNull(block, "block");
        ?? r0 = new Thread() { // from class: kotlin.concurrent.ThreadsKt$thread$thread$1
            @Override // java.lang.Thread, java.lang.Runnable
            public void run() {
                Function0.this.invoke();
            }
        };
        if (isDaemon) {
            r0.setDaemon(true);
        }
        if (priority > 0) {
            r0.setPriority(priority);
        }
        if (name != null) {
            r0.setName(name);
        }
        if (contextClassLoader != null) {
            r0.setContextClassLoader(contextClassLoader);
        }
        if (start) {
            r0.start();
        }
        return (Thread) r0;
    }

    private static final <T> T getOrSet(ThreadLocal<T> threadLocal, Function0<? extends T> function0) {
        T t = threadLocal.get();
        if (t != null) {
            return t;
        }
        T invoke = function0.invoke();
        threadLocal.set(invoke);
        return invoke;
    }
}