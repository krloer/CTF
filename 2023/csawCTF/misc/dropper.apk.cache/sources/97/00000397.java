package y0;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.appcompat.widget.m2;

/* loaded from: classes.dex */
public final class a extends j0.b {
    public static final Parcelable.Creator<a> CREATOR = new m2(5);

    /* renamed from: c  reason: collision with root package name */
    public boolean f3323c;

    /* renamed from: d  reason: collision with root package name */
    public int f3324d;

    /* renamed from: e  reason: collision with root package name */
    public float f3325e;

    /* renamed from: f  reason: collision with root package name */
    public boolean f3326f;

    public a(Parcel parcel, ClassLoader classLoader) {
        super(parcel, classLoader);
        this.f3323c = parcel.readByte() != 0;
        this.f3324d = parcel.readInt();
        this.f3325e = parcel.readFloat();
        this.f3326f = parcel.readByte() != 0;
    }

    @Override // j0.b, android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i2) {
        parcel.writeParcelable(this.f2163a, i2);
        parcel.writeByte(this.f3323c ? (byte) 1 : (byte) 0);
        parcel.writeInt(this.f3324d);
        parcel.writeFloat(this.f3325e);
        parcel.writeByte(this.f3326f ? (byte) 1 : (byte) 0);
    }
}