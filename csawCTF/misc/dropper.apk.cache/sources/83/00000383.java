package v;

import android.content.res.Resources;
import java.util.Objects;

/* loaded from: classes.dex */
public final class h {

    /* renamed from: a  reason: collision with root package name */
    public final Resources f3250a;

    /* renamed from: b  reason: collision with root package name */
    public final Resources.Theme f3251b;

    public h(Resources resources, Resources.Theme theme) {
        this.f3250a = resources;
        this.f3251b = theme;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || h.class != obj.getClass()) {
            return false;
        }
        h hVar = (h) obj;
        return this.f3250a.equals(hVar.f3250a) && Objects.equals(this.f3251b, hVar.f3251b);
    }

    public final int hashCode() {
        return Objects.hash(this.f3250a, this.f3251b);
    }
}