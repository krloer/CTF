package androidx.core.graphics.drawable;

import android.content.res.ColorStateList;
import android.graphics.Bitmap;
import android.graphics.PorterDuff;
import android.graphics.drawable.Icon;
import android.os.Parcelable;
import androidx.versionedparcelable.CustomVersionedParcelable;

/* loaded from: classes.dex */
public class IconCompat extends CustomVersionedParcelable {

    /* renamed from: k  reason: collision with root package name */
    public static final PorterDuff.Mode f608k = PorterDuff.Mode.SRC_IN;

    /* renamed from: b  reason: collision with root package name */
    public Object f610b;

    /* renamed from: j  reason: collision with root package name */
    public String f618j;

    /* renamed from: a  reason: collision with root package name */
    public int f609a = -1;

    /* renamed from: c  reason: collision with root package name */
    public byte[] f611c = null;

    /* renamed from: d  reason: collision with root package name */
    public Parcelable f612d = null;

    /* renamed from: e  reason: collision with root package name */
    public int f613e = 0;

    /* renamed from: f  reason: collision with root package name */
    public int f614f = 0;

    /* renamed from: g  reason: collision with root package name */
    public ColorStateList f615g = null;

    /* renamed from: h  reason: collision with root package name */
    public PorterDuff.Mode f616h = f608k;

    /* renamed from: i  reason: collision with root package name */
    public String f617i = null;

    public final String toString() {
        String str;
        int height;
        int i2;
        if (this.f609a == -1) {
            return String.valueOf(this.f610b);
        }
        StringBuilder sb = new StringBuilder("Icon(typ=");
        switch (this.f609a) {
            case 1:
                str = "BITMAP";
                break;
            case 2:
                str = "RESOURCE";
                break;
            case 3:
                str = "DATA";
                break;
            case 4:
                str = "URI";
                break;
            case 5:
                str = "BITMAP_MASKABLE";
                break;
            case 6:
                str = "URI_MASKABLE";
                break;
            default:
                str = "UNKNOWN";
                break;
        }
        sb.append(str);
        switch (this.f609a) {
            case 1:
            case 5:
                sb.append(" size=");
                sb.append(((Bitmap) this.f610b).getWidth());
                sb.append("x");
                height = ((Bitmap) this.f610b).getHeight();
                sb.append(height);
                break;
            case 2:
                sb.append(" pkg=");
                sb.append(this.f618j);
                sb.append(" id=");
                Object[] objArr = new Object[1];
                int i3 = this.f609a;
                if (i3 == -1) {
                    i2 = ((Icon) this.f610b).getResId();
                } else if (i3 != 2) {
                    throw new IllegalStateException("called getResId() on " + this);
                } else {
                    i2 = this.f613e;
                }
                objArr[0] = Integer.valueOf(i2);
                sb.append(String.format("0x%08x", objArr));
                break;
            case 3:
                sb.append(" len=");
                sb.append(this.f613e);
                if (this.f614f != 0) {
                    sb.append(" off=");
                    height = this.f614f;
                    sb.append(height);
                    break;
                }
                break;
            case 4:
            case 6:
                sb.append(" uri=");
                sb.append(this.f610b);
                break;
        }
        if (this.f615g != null) {
            sb.append(" tint=");
            sb.append(this.f615g);
        }
        if (this.f616h != f608k) {
            sb.append(" mode=");
            sb.append(this.f616h);
        }
        sb.append(")");
        return sb.toString();
    }
}