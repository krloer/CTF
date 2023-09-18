package androidx.emoji2.text;

import android.os.Handler;
import android.os.Looper;
import java.util.ArrayList;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/* loaded from: classes.dex */
public final class j {

    /* renamed from: i  reason: collision with root package name */
    public static final Object f667i = new Object();

    /* renamed from: j  reason: collision with root package name */
    public static volatile j f668j;

    /* renamed from: a  reason: collision with root package name */
    public final ReentrantReadWriteLock f669a;

    /* renamed from: b  reason: collision with root package name */
    public final j.c f670b;

    /* renamed from: c  reason: collision with root package name */
    public volatile int f671c;

    /* renamed from: d  reason: collision with root package name */
    public final Handler f672d;

    /* renamed from: e  reason: collision with root package name */
    public final d f673e;

    /* renamed from: f  reason: collision with root package name */
    public final h f674f;

    /* renamed from: g  reason: collision with root package name */
    public final int f675g;

    /* renamed from: h  reason: collision with root package name */
    public final p f676h;

    public j(k kVar) {
        ReentrantReadWriteLock reentrantReadWriteLock = new ReentrantReadWriteLock();
        this.f669a = reentrantReadWriteLock;
        this.f671c = 3;
        this.f674f = kVar.f649a;
        int i2 = kVar.f650b;
        this.f675g = i2;
        this.f676h = kVar.f651c;
        this.f672d = new Handler(Looper.getMainLooper());
        this.f670b = new j.c();
        d dVar = new d(this);
        this.f673e = dVar;
        reentrantReadWriteLock.writeLock().lock();
        if (i2 == 0) {
            try {
                this.f671c = 0;
            } catch (Throwable th) {
                this.f669a.writeLock().unlock();
                throw th;
            }
        }
        reentrantReadWriteLock.writeLock().unlock();
        if (b() == 0) {
            try {
                this.f674f.a(new c(dVar));
            } catch (Throwable th2) {
                d(th2);
            }
        }
    }

    public static j a() {
        j jVar;
        synchronized (f667i) {
            jVar = f668j;
            if (!(jVar != null)) {
                throw new IllegalStateException("EmojiCompat is not initialized.\n\nYou must initialize EmojiCompat prior to referencing the EmojiCompat instance.\n\nThe most likely cause of this error is disabling the EmojiCompatInitializer\neither explicitly in AndroidManifest.xml, or by including\nandroidx.emoji2:emoji2-bundled.\n\nAutomatic initialization is typically performed by EmojiCompatInitializer. If\nyou are not expecting to initialize EmojiCompat manually in your application,\nplease check to ensure it has not been removed from your APK's manifest. You can\ndo this in Android Studio using Build > Analyze APK.\n\nIn the APK Analyzer, ensure that the startup entry for\nEmojiCompatInitializer and InitializationProvider is present in\n AndroidManifest.xml. If it is missing or contains tools:node=\"remove\", and you\nintend to use automatic configuration, verify:\n\n  1. Your application does not include emoji2-bundled\n  2. All modules do not contain an exclusion manifest rule for\n     EmojiCompatInitializer or InitializationProvider. For more information\n     about manifest exclusions see the documentation for the androidx startup\n     library.\n\nIf you intend to use emoji2-bundled, please call EmojiCompat.init. You can\nlearn more in the documentation for BundledEmojiCompatConfig.\n\nIf you intended to perform manual configuration, it is recommended that you call\nEmojiCompat.init immediately on application startup.\n\nIf you still cannot resolve this issue, please open a bug with your specific\nconfiguration to help improve error message.");
            }
        }
        return jVar;
    }

    public final int b() {
        this.f669a.readLock().lock();
        try {
            return this.f671c;
        } finally {
            this.f669a.readLock().unlock();
        }
    }

    public final void c() {
        if (!(this.f675g == 1)) {
            throw new IllegalStateException("Set metadataLoadStrategy to LOAD_STRATEGY_MANUAL to execute manual loading");
        }
        if (b() == 1) {
            return;
        }
        this.f669a.writeLock().lock();
        try {
            if (this.f671c == 0) {
                return;
            }
            this.f671c = 0;
            this.f669a.writeLock().unlock();
            d dVar = this.f673e;
            Object obj = dVar.f1858b;
            try {
                ((j) obj).f674f.a(new c(dVar));
            } catch (Throwable th) {
                ((j) obj).d(th);
            }
        } finally {
            this.f669a.writeLock().unlock();
        }
    }

    public final void d(Throwable th) {
        ArrayList arrayList = new ArrayList();
        this.f669a.writeLock().lock();
        try {
            this.f671c = 2;
            arrayList.addAll(this.f670b);
            this.f670b.clear();
            this.f669a.writeLock().unlock();
            this.f672d.post(new b0.b(arrayList, this.f671c, th));
        } catch (Throwable th2) {
            this.f669a.writeLock().unlock();
            throw th2;
        }
    }

    public final void e() {
        ArrayList arrayList = new ArrayList();
        this.f669a.writeLock().lock();
        try {
            this.f671c = 1;
            arrayList.addAll(this.f670b);
            this.f670b.clear();
            this.f669a.writeLock().unlock();
            this.f672d.post(new b0.b(arrayList, this.f671c));
        } catch (Throwable th) {
            this.f669a.writeLock().unlock();
            throw th;
        }
    }

    public final CharSequence f(int i2, int i3, CharSequence charSequence) {
        if (b() == 1) {
            if (i2 >= 0) {
                if (i3 >= 0) {
                    i.p(i2 <= i3, "start should be <= than end");
                    if (charSequence == null) {
                        return null;
                    }
                    i.p(i2 <= charSequence.length(), "start should be < than charSequence length");
                    i.p(i3 <= charSequence.length(), "end should be < than charSequence length");
                    return (charSequence.length() == 0 || i2 == i3) ? charSequence : this.f673e.w(charSequence, i2, i3, false);
                }
                throw new IllegalArgumentException("end cannot be negative");
            }
            throw new IllegalArgumentException("start cannot be negative");
        }
        throw new IllegalStateException("Not initialized yet");
    }

    public final void g(g gVar) {
        if (gVar == null) {
            throw new NullPointerException("initCallback cannot be null");
        }
        this.f669a.writeLock().lock();
        try {
            if (this.f671c != 1 && this.f671c != 2) {
                this.f670b.add(gVar);
            }
            this.f672d.post(new b0.b(gVar, this.f671c));
        } finally {
            this.f669a.writeLock().unlock();
        }
    }
}