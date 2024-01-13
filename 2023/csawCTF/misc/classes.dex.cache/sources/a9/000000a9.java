package androidx.core.app;

import android.app.PendingIntent;
import android.os.Parcel;
import android.text.TextUtils;
import androidx.core.graphics.drawable.IconCompat;
import v0.a;
import v0.b;
import v0.c;

/* loaded from: /home/moody/general/ctf/csawCTF/misc/classes.dex */
public class RemoteActionCompatParcelizer {
    public static RemoteActionCompat read(a aVar) {
        RemoteActionCompat remoteActionCompat = new RemoteActionCompat();
        c cVar = remoteActionCompat.f602a;
        if (aVar.e(1)) {
            cVar = aVar.g();
        }
        remoteActionCompat.f602a = (IconCompat) cVar;
        CharSequence charSequence = remoteActionCompat.f603b;
        if (aVar.e(2)) {
            charSequence = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(((b) aVar).f3273e);
        }
        remoteActionCompat.f603b = charSequence;
        CharSequence charSequence2 = remoteActionCompat.f604c;
        if (aVar.e(3)) {
            charSequence2 = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(((b) aVar).f3273e);
        }
        remoteActionCompat.f604c = charSequence2;
        remoteActionCompat.f605d = (PendingIntent) aVar.f(remoteActionCompat.f605d, 4);
        boolean z = remoteActionCompat.f606e;
        if (aVar.e(5)) {
            z = ((b) aVar).f3273e.readInt() != 0;
        }
        remoteActionCompat.f606e = z;
        boolean z2 = remoteActionCompat.f607f;
        if (aVar.e(6)) {
            z2 = ((b) aVar).f3273e.readInt() != 0;
        }
        remoteActionCompat.f607f = z2;
        return remoteActionCompat;
    }

    public static void write(RemoteActionCompat remoteActionCompat, a aVar) {
        aVar.getClass();
        IconCompat iconCompat = remoteActionCompat.f602a;
        aVar.h(1);
        aVar.i(iconCompat);
        CharSequence charSequence = remoteActionCompat.f603b;
        aVar.h(2);
        Parcel parcel = ((b) aVar).f3273e;
        TextUtils.writeToParcel(charSequence, parcel, 0);
        CharSequence charSequence2 = remoteActionCompat.f604c;
        aVar.h(3);
        TextUtils.writeToParcel(charSequence2, parcel, 0);
        PendingIntent pendingIntent = remoteActionCompat.f605d;
        aVar.h(4);
        parcel.writeParcelable(pendingIntent, 0);
        boolean z = remoteActionCompat.f606e;
        aVar.h(5);
        parcel.writeInt(z ? 1 : 0);
        boolean z2 = remoteActionCompat.f607f;
        aVar.h(6);
        parcel.writeInt(z2 ? 1 : 0);
    }
}