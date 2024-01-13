package a1;

import android.os.Parcel;
import android.os.Parcelable;
import android.view.AbsSavedState;
import androidx.appcompat.widget.m2;
import com.google.android.material.bottomsheet.BottomSheetBehavior;

/* loaded from: classes.dex */
public final class d extends j0.b {
    public static final Parcelable.Creator<d> CREATOR = new m2(6);

    /* renamed from: c  reason: collision with root package name */
    public final int f10c;

    /* renamed from: d  reason: collision with root package name */
    public final int f11d;

    /* renamed from: e  reason: collision with root package name */
    public final boolean f12e;

    /* renamed from: f  reason: collision with root package name */
    public final boolean f13f;

    /* renamed from: g  reason: collision with root package name */
    public final boolean f14g;

    public d(Parcel parcel, ClassLoader classLoader) {
        super(parcel, classLoader);
        this.f10c = parcel.readInt();
        this.f11d = parcel.readInt();
        this.f12e = parcel.readInt() == 1;
        this.f13f = parcel.readInt() == 1;
        this.f14g = parcel.readInt() == 1;
    }

    @Override // j0.b, android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i2) {
        parcel.writeParcelable(this.f2163a, i2);
        parcel.writeInt(this.f10c);
        parcel.writeInt(this.f11d);
        parcel.writeInt(this.f12e ? 1 : 0);
        parcel.writeInt(this.f13f ? 1 : 0);
        parcel.writeInt(this.f14g ? 1 : 0);
    }

    public d(AbsSavedState absSavedState, BottomSheetBehavior bottomSheetBehavior) {
        super(absSavedState);
        this.f10c = bottomSheetBehavior.G;
        this.f11d = bottomSheetBehavior.f1239d;
        this.f12e = bottomSheetBehavior.f1237b;
        this.f13f = bottomSheetBehavior.D;
        this.f14g = bottomSheetBehavior.E;
    }
}