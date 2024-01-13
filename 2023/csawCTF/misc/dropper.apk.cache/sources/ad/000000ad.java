package androidx.emoji2.text;

import android.content.Context;
import android.os.Looper;
import androidx.lifecycle.ProcessLifecycleInitializer;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

/* loaded from: classes.dex */
public class EmojiCompatInitializer implements s0.b {
    @Override // s0.b
    public final List a() {
        return Collections.singletonList(ProcessLifecycleInitializer.class);
    }

    @Override // s0.b
    /* renamed from: c */
    public final Boolean b(Context context) {
        k kVar = new k(context);
        if (j.f668j == null) {
            synchronized (j.f667i) {
                if (j.f668j == null) {
                    j.f668j = new j(kVar);
                }
            }
        }
        if (s0.a.f3136d == null) {
            synchronized (s0.a.f3137e) {
                if (s0.a.f3136d == null) {
                    s0.a.f3136d = new s0.a(context);
                }
            }
        }
        s0.a aVar = s0.a.f3136d;
        aVar.getClass();
        final androidx.lifecycle.q f2 = ((androidx.lifecycle.o) aVar.a(ProcessLifecycleInitializer.class, new HashSet())).f();
        f2.a(new androidx.lifecycle.d() { // from class: androidx.emoji2.text.EmojiCompatInitializer.1
            @Override // androidx.lifecycle.d
            public final void a() {
                EmojiCompatInitializer.this.getClass();
                b.a(Looper.getMainLooper()).postDelayed(new n(), 500L);
                f2.d(this);
            }
        });
        return Boolean.TRUE;
    }
}