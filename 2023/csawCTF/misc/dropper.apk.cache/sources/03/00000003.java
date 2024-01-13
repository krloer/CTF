package a0;

/* loaded from: classes.dex */
public final class b {

    /* renamed from: a  reason: collision with root package name */
    public boolean f2a;

    /* renamed from: b  reason: collision with root package name */
    public a f3b;

    /* renamed from: c  reason: collision with root package name */
    public boolean f4c;

    public final void a() {
        synchronized (this) {
            if (this.f2a) {
                return;
            }
            this.f2a = true;
            this.f4c = true;
            a aVar = this.f3b;
            if (aVar != null) {
                try {
                    aVar.c();
                } catch (Throwable th) {
                    synchronized (this) {
                        this.f4c = false;
                        notifyAll();
                        throw th;
                    }
                }
            }
            synchronized (this) {
                this.f4c = false;
                notifyAll();
            }
        }
    }

    public final void b(a aVar) {
        synchronized (this) {
            while (this.f4c) {
                try {
                    wait();
                } catch (InterruptedException unused) {
                }
            }
            if (this.f3b == aVar) {
                return;
            }
            this.f3b = aVar;
            if (this.f2a) {
                aVar.c();
            }
        }
    }
}