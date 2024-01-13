package androidx.core.graphics.drawable;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.os.Parcel;
import android.os.Parcelable;
import java.nio.charset.Charset;
import v0.a;
import v0.b;

/* loaded from: classes.dex */
public class IconCompatParcelizer {
    public static IconCompat read(a aVar) {
        Parcelable parcelable;
        IconCompat iconCompat = new IconCompat();
        int i2 = iconCompat.f609a;
        if (aVar.e(1)) {
            i2 = ((b) aVar).f3273e.readInt();
        }
        iconCompat.f609a = i2;
        byte[] bArr = iconCompat.f611c;
        if (aVar.e(2)) {
            Parcel parcel = ((b) aVar).f3273e;
            int readInt = parcel.readInt();
            if (readInt < 0) {
                bArr = null;
            } else {
                byte[] bArr2 = new byte[readInt];
                parcel.readByteArray(bArr2);
                bArr = bArr2;
            }
        }
        iconCompat.f611c = bArr;
        iconCompat.f612d = aVar.f(iconCompat.f612d, 3);
        int i3 = iconCompat.f613e;
        if (aVar.e(4)) {
            i3 = ((b) aVar).f3273e.readInt();
        }
        iconCompat.f613e = i3;
        int i4 = iconCompat.f614f;
        if (aVar.e(5)) {
            i4 = ((b) aVar).f3273e.readInt();
        }
        iconCompat.f614f = i4;
        iconCompat.f615g = (ColorStateList) aVar.f(iconCompat.f615g, 6);
        String str = iconCompat.f617i;
        if (aVar.e(7)) {
            str = ((b) aVar).f3273e.readString();
        }
        iconCompat.f617i = str;
        String str2 = iconCompat.f618j;
        if (aVar.e(8)) {
            str2 = ((b) aVar).f3273e.readString();
        }
        iconCompat.f618j = str2;
        iconCompat.f616h = PorterDuff.Mode.valueOf(iconCompat.f617i);
        switch (iconCompat.f609a) {
            case -1:
                parcelable = iconCompat.f612d;
                if (parcelable == null) {
                    throw new IllegalArgumentException("Invalid icon");
                }
                iconCompat.f610b = parcelable;
                break;
            case 1:
            case 5:
                parcelable = iconCompat.f612d;
                if (parcelable == null) {
                    byte[] bArr3 = iconCompat.f611c;
                    iconCompat.f610b = bArr3;
                    iconCompat.f609a = 3;
                    iconCompat.f613e = 0;
                    iconCompat.f614f = bArr3.length;
                    break;
                }
                iconCompat.f610b = parcelable;
                break;
            case 2:
            case 4:
            case 6:
                String str3 = new String(iconCompat.f611c, Charset.forName("UTF-16"));
                iconCompat.f610b = str3;
                if (iconCompat.f609a == 2 && iconCompat.f618j == null) {
                    iconCompat.f618j = str3.split(":", -1)[0];
                    break;
                }
                break;
            case 3:
                iconCompat.f610b = iconCompat.f611c;
                break;
        }
        return iconCompat;
    }

    public static void write(IconCompat iconCompat, a aVar) {
        aVar.getClass();
        iconCompat.f617i = iconCompat.f616h.name();
        switch (iconCompat.f609a) {
            case -1:
            case 1:
            case 5:
                iconCompat.f612d = (Parcelable) iconCompat.f610b;
                break;
            case 2:
                iconCompat.f611c = ((String) iconCompat.f610b).getBytes(Charset.forName("UTF-16"));
                break;
            case 3:
                iconCompat.f611c = (byte[]) iconCompat.f610b;
                break;
            case 4:
            case 6:
                iconCompat.f611c = iconCompat.f610b.toString().getBytes(Charset.forName("UTF-16"));
                break;
        }
        int i2 = iconCompat.f609a;
        if (-1 != i2) {
            aVar.h(1);
            ((b) aVar).f3273e.writeInt(i2);
        }
        byte[] bArr = iconCompat.f611c;
        if (bArr != null) {
            aVar.h(2);
            int length = bArr.length;
            Parcel parcel = ((b) aVar).f3273e;
            parcel.writeInt(length);
            parcel.writeByteArray(bArr);
        }
        Parcelable parcelable = iconCompat.f612d;
        if (parcelable != null) {
            aVar.h(3);
            ((b) aVar).f3273e.writeParcelable(parcelable, 0);
        }
        int i3 = iconCompat.f613e;
        if (i3 != 0) {
            aVar.h(4);
            ((b) aVar).f3273e.writeInt(i3);
        }
        int i4 = iconCompat.f614f;
        if (i4 != 0) {
            aVar.h(5);
            ((b) aVar).f3273e.writeInt(i4);
        }
        ColorStateList colorStateList = iconCompat.f615g;
        if (colorStateList != null) {
            aVar.h(6);
            ((b) aVar).f3273e.writeParcelable(colorStateList, 0);
        }
        String str = iconCompat.f617i;
        if (str != null) {
            aVar.h(7);
            ((b) aVar).f3273e.writeString(str);
        }
        String str2 = iconCompat.f618j;
        if (str2 != null) {
            aVar.h(8);
            ((b) aVar).f3273e.writeString(str2);
        }
    }
}