package v0;

import android.os.Parcel;
import android.util.SparseIntArray;

/* loaded from: classes.dex */
public final class b extends a {

    /* renamed from: d  reason: collision with root package name */
    public final SparseIntArray f3272d;

    /* renamed from: e  reason: collision with root package name */
    public final Parcel f3273e;

    /* renamed from: f  reason: collision with root package name */
    public final int f3274f;

    /* renamed from: g  reason: collision with root package name */
    public final int f3275g;

    /* renamed from: h  reason: collision with root package name */
    public final String f3276h;

    /* renamed from: i  reason: collision with root package name */
    public int f3277i;

    /* renamed from: j  reason: collision with root package name */
    public int f3278j;

    /* renamed from: k  reason: collision with root package name */
    public int f3279k;

    public b(Parcel parcel) {
        this(parcel, parcel.dataPosition(), parcel.dataSize(), "", new j.b(), new j.b(), new j.b());
    }

    @Override // v0.a
    public final b a() {
        Parcel parcel = this.f3273e;
        int dataPosition = parcel.dataPosition();
        int i2 = this.f3278j;
        if (i2 == this.f3274f) {
            i2 = this.f3275g;
        }
        int i3 = i2;
        return new b(parcel, dataPosition, i3, this.f3276h + "  ", this.f3269a, this.f3270b, this.f3271c);
    }

    @Override // v0.a
    public final boolean e(int i2) {
        while (this.f3278j < this.f3275g) {
            int i3 = this.f3279k;
            if (i3 == i2) {
                return true;
            }
            if (String.valueOf(i3).compareTo(String.valueOf(i2)) > 0) {
                return false;
            }
            int i4 = this.f3278j;
            Parcel parcel = this.f3273e;
            parcel.setDataPosition(i4);
            int readInt = parcel.readInt();
            this.f3279k = parcel.readInt();
            this.f3278j += readInt;
        }
        return this.f3279k == i2;
    }

    @Override // v0.a
    public final void h(int i2) {
        int i3 = this.f3277i;
        SparseIntArray sparseIntArray = this.f3272d;
        Parcel parcel = this.f3273e;
        if (i3 >= 0) {
            int i4 = sparseIntArray.get(i3);
            int dataPosition = parcel.dataPosition();
            parcel.setDataPosition(i4);
            parcel.writeInt(dataPosition - i4);
            parcel.setDataPosition(dataPosition);
        }
        this.f3277i = i2;
        sparseIntArray.put(i2, parcel.dataPosition());
        parcel.writeInt(0);
        parcel.writeInt(i2);
    }

    public b(Parcel parcel, int i2, int i3, String str, j.b bVar, j.b bVar2, j.b bVar3) {
        super(bVar, bVar2, bVar3);
        this.f3272d = new SparseIntArray();
        this.f3277i = -1;
        this.f3279k = -1;
        this.f3273e = parcel;
        this.f3274f = i2;
        this.f3275g = i3;
        this.f3278j = i2;
        this.f3276h = str;
    }
}