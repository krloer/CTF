package androidx.emoji2.text;

/* loaded from: classes.dex */
public final class c extends i {

    /* renamed from: q  reason: collision with root package name */
    public final /* synthetic */ d f646q;

    public c(d dVar) {
        this.f646q = dVar;
    }

    @Override // androidx.emoji2.text.i
    public final void i0(Throwable th) {
        ((j) this.f646q.f1858b).d(th);
    }

    @Override // androidx.emoji2.text.i
    public final void o0(f.g gVar) {
        d dVar = this.f646q;
        dVar.f648d = gVar;
        f.g gVar2 = dVar.f648d;
        l1.e eVar = new l1.e(5, 0);
        Object obj = dVar.f1858b;
        p pVar = ((j) obj).f676h;
        ((j) obj).getClass();
        dVar.f647c = new r(gVar2, eVar, pVar);
        ((j) dVar.f1858b).e();
    }
}