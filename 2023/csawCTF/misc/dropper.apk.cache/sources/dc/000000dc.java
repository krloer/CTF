package androidx.fragment.app;

import android.content.Context;
import java.lang.reflect.InvocationTargetException;

/* loaded from: classes.dex */
public final class g0 {

    /* renamed from: b  reason: collision with root package name */
    public static final j.j f804b = new j.j();

    /* renamed from: a  reason: collision with root package name */
    public final /* synthetic */ l0 f805a;

    public g0(l0 l0Var) {
        this.f805a = l0Var;
    }

    public static Class b(ClassLoader classLoader, String str) {
        j.j jVar = f804b;
        j.j jVar2 = (j.j) jVar.getOrDefault(classLoader, null);
        if (jVar2 == null) {
            jVar2 = new j.j();
            jVar.put(classLoader, jVar2);
        }
        Class cls = (Class) jVar2.getOrDefault(str, null);
        if (cls == null) {
            Class<?> cls2 = Class.forName(str, false, classLoader);
            jVar2.put(str, cls2);
            return cls2;
        }
        return cls;
    }

    public static Class c(ClassLoader classLoader, String str) {
        try {
            return b(classLoader, str);
        } catch (ClassCastException e2) {
            throw new q("Unable to instantiate fragment " + str + ": make sure class is a valid subclass of Fragment", e2);
        } catch (ClassNotFoundException e3) {
            throw new q("Unable to instantiate fragment " + str + ": make sure class name exists", e3);
        }
    }

    public final r a(String str) {
        Context context = this.f805a.f838p.f946r;
        Object obj = r.R;
        try {
            return (r) c(context.getClassLoader(), str).getConstructor(new Class[0]).newInstance(new Object[0]);
        } catch (IllegalAccessException e2) {
            throw new q("Unable to instantiate fragment " + str + ": make sure class name exists, is public, and has an empty constructor that is public", e2);
        } catch (InstantiationException e3) {
            throw new q("Unable to instantiate fragment " + str + ": make sure class name exists, is public, and has an empty constructor that is public", e3);
        } catch (NoSuchMethodException e4) {
            throw new q("Unable to instantiate fragment " + str + ": could not find Fragment constructor", e4);
        } catch (InvocationTargetException e5) {
            throw new q("Unable to instantiate fragment " + str + ": calling Fragment constructor caused an exception", e5);
        }
    }
}