package androidx.startup;

import android.content.ComponentName;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Trace;
import androidx.fragment.app.q;
import com.example.dropper.R;
import java.util.HashSet;
import s0.a;
import s0.b;

/* loaded from: classes.dex */
public final class InitializationProvider extends ContentProvider {
    @Override // android.content.ContentProvider
    public final int delete(Uri uri, String str, String[] strArr) {
        throw new IllegalStateException("Not allowed.");
    }

    @Override // android.content.ContentProvider
    public final String getType(Uri uri) {
        throw new IllegalStateException("Not allowed.");
    }

    @Override // android.content.ContentProvider
    public final Uri insert(Uri uri, ContentValues contentValues) {
        throw new IllegalStateException("Not allowed.");
    }

    @Override // android.content.ContentProvider
    public final boolean onCreate() {
        Context context = getContext();
        if (context != null) {
            if (a.f3136d == null) {
                synchronized (a.f3137e) {
                    if (a.f3136d == null) {
                        a.f3136d = new a(context);
                    }
                }
            }
            a aVar = a.f3136d;
            Context context2 = aVar.f3140c;
            try {
                try {
                    Trace.beginSection("Startup");
                    Bundle bundle = context2.getPackageManager().getProviderInfo(new ComponentName(context2.getPackageName(), InitializationProvider.class.getName()), 128).metaData;
                    String string = context2.getString(R.string.androidx_startup);
                    if (bundle != null) {
                        HashSet hashSet = new HashSet();
                        for (String str : bundle.keySet()) {
                            if (string.equals(bundle.getString(str, null))) {
                                Class<?> cls = Class.forName(str);
                                if (b.class.isAssignableFrom(cls)) {
                                    aVar.f3139b.add(cls);
                                    aVar.a(cls, hashSet);
                                }
                            }
                        }
                    }
                    Trace.endSection();
                    return true;
                } catch (PackageManager.NameNotFoundException | ClassNotFoundException e2) {
                    throw new q(e2);
                }
            } catch (Throwable th) {
                Trace.endSection();
                throw th;
            }
        }
        throw new q();
    }

    @Override // android.content.ContentProvider
    public final Cursor query(Uri uri, String[] strArr, String str, String[] strArr2, String str2) {
        throw new IllegalStateException("Not allowed.");
    }

    @Override // android.content.ContentProvider
    public final int update(Uri uri, ContentValues contentValues, String str, String[] strArr) {
        throw new IllegalStateException("Not allowed.");
    }
}