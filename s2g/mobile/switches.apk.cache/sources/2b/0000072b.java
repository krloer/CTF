package kotlin.collections;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import kotlin.Metadata;
import kotlin.TypeCastException;
import kotlin.internal.PlatformImplementationsKt;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: _ArraysJvm.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0096\u0001\n\u0000\n\u0002\u0010 \n\u0000\n\u0002\u0010\u0011\n\u0000\n\u0002\u0010\u000b\n\u0002\u0010\u0018\n\u0002\u0010\u0005\n\u0002\u0010\u0012\n\u0002\u0010\f\n\u0002\u0010\u0019\n\u0002\u0010\u0006\n\u0002\u0010\u0013\n\u0002\u0010\u0007\n\u0002\u0010\u0014\n\u0002\u0010\b\n\u0002\u0010\u0015\n\u0002\u0010\t\n\u0002\u0010\u0016\n\u0002\u0010\n\n\u0002\u0010\u0017\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0010\u000e\n\u0002\b\u0017\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u001f\n\u0002\b\u0005\n\u0002\u0010\u001e\n\u0002\b\u0004\n\u0002\u0010\u000f\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\f\u001a#\u0010\u0000\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0003¢\u0006\u0002\u0010\u0004\u001a\u0010\u0010\u0000\u001a\b\u0012\u0004\u0012\u00020\u00050\u0001*\u00020\u0006\u001a\u0010\u0010\u0000\u001a\b\u0012\u0004\u0012\u00020\u00070\u0001*\u00020\b\u001a\u0010\u0010\u0000\u001a\b\u0012\u0004\u0012\u00020\t0\u0001*\u00020\n\u001a\u0010\u0010\u0000\u001a\b\u0012\u0004\u0012\u00020\u000b0\u0001*\u00020\f\u001a\u0010\u0010\u0000\u001a\b\u0012\u0004\u0012\u00020\r0\u0001*\u00020\u000e\u001a\u0010\u0010\u0000\u001a\b\u0012\u0004\u0012\u00020\u000f0\u0001*\u00020\u0010\u001a\u0010\u0010\u0000\u001a\b\u0012\u0004\u0012\u00020\u00110\u0001*\u00020\u0012\u001a\u0010\u0010\u0000\u001a\b\u0012\u0004\u0012\u00020\u00130\u0001*\u00020\u0014\u001aU\u0010\u0015\u001a\u00020\u000f\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\u0006\u0010\u0016\u001a\u0002H\u00022\u001a\u0010\u0017\u001a\u0016\u0012\u0006\b\u0000\u0012\u0002H\u00020\u0018j\n\u0012\u0006\b\u0000\u0012\u0002H\u0002`\u00192\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f¢\u0006\u0002\u0010\u001c\u001a9\u0010\u0015\u001a\u00020\u000f\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\u0006\u0010\u0016\u001a\u0002H\u00022\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f¢\u0006\u0002\u0010\u001d\u001a&\u0010\u0015\u001a\u00020\u000f*\u00020\b2\u0006\u0010\u0016\u001a\u00020\u00072\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a&\u0010\u0015\u001a\u00020\u000f*\u00020\n2\u0006\u0010\u0016\u001a\u00020\t2\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a&\u0010\u0015\u001a\u00020\u000f*\u00020\f2\u0006\u0010\u0016\u001a\u00020\u000b2\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a&\u0010\u0015\u001a\u00020\u000f*\u00020\u000e2\u0006\u0010\u0016\u001a\u00020\r2\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a&\u0010\u0015\u001a\u00020\u000f*\u00020\u00102\u0006\u0010\u0016\u001a\u00020\u000f2\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a&\u0010\u0015\u001a\u00020\u000f*\u00020\u00122\u0006\u0010\u0016\u001a\u00020\u00112\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a&\u0010\u0015\u001a\u00020\u000f*\u00020\u00142\u0006\u0010\u0016\u001a\u00020\u00132\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a2\u0010\u001e\u001a\u00020\u0005\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\u000e\u0010\u001f\u001a\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0003H\u0087\f¢\u0006\u0004\b \u0010!\u001a\"\u0010\"\u001a\u00020\u000f\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0003H\u0087\b¢\u0006\u0004\b#\u0010$\u001a\"\u0010%\u001a\u00020&\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0003H\u0087\b¢\u0006\u0004\b'\u0010(\u001a0\u0010)\u001a\u00020\u0005\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\u000e\u0010\u001f\u001a\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0003H\u0087\f¢\u0006\u0002\u0010!\u001a\u0015\u0010)\u001a\u00020\u0005*\u00020\u00062\u0006\u0010\u001f\u001a\u00020\u0006H\u0087\f\u001a\u0015\u0010)\u001a\u00020\u0005*\u00020\b2\u0006\u0010\u001f\u001a\u00020\bH\u0087\f\u001a\u0015\u0010)\u001a\u00020\u0005*\u00020\n2\u0006\u0010\u001f\u001a\u00020\nH\u0087\f\u001a\u0015\u0010)\u001a\u00020\u0005*\u00020\f2\u0006\u0010\u001f\u001a\u00020\fH\u0087\f\u001a\u0015\u0010)\u001a\u00020\u0005*\u00020\u000e2\u0006\u0010\u001f\u001a\u00020\u000eH\u0087\f\u001a\u0015\u0010)\u001a\u00020\u0005*\u00020\u00102\u0006\u0010\u001f\u001a\u00020\u0010H\u0087\f\u001a\u0015\u0010)\u001a\u00020\u0005*\u00020\u00122\u0006\u0010\u001f\u001a\u00020\u0012H\u0087\f\u001a\u0015\u0010)\u001a\u00020\u0005*\u00020\u00142\u0006\u0010\u001f\u001a\u00020\u0014H\u0087\f\u001a \u0010*\u001a\u00020\u000f\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0003H\u0087\b¢\u0006\u0002\u0010$\u001a\r\u0010*\u001a\u00020\u000f*\u00020\u0006H\u0087\b\u001a\r\u0010*\u001a\u00020\u000f*\u00020\bH\u0087\b\u001a\r\u0010*\u001a\u00020\u000f*\u00020\nH\u0087\b\u001a\r\u0010*\u001a\u00020\u000f*\u00020\fH\u0087\b\u001a\r\u0010*\u001a\u00020\u000f*\u00020\u000eH\u0087\b\u001a\r\u0010*\u001a\u00020\u000f*\u00020\u0010H\u0087\b\u001a\r\u0010*\u001a\u00020\u000f*\u00020\u0012H\u0087\b\u001a\r\u0010*\u001a\u00020\u000f*\u00020\u0014H\u0087\b\u001a \u0010+\u001a\u00020&\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0003H\u0087\b¢\u0006\u0002\u0010(\u001a\r\u0010+\u001a\u00020&*\u00020\u0006H\u0087\b\u001a\r\u0010+\u001a\u00020&*\u00020\bH\u0087\b\u001a\r\u0010+\u001a\u00020&*\u00020\nH\u0087\b\u001a\r\u0010+\u001a\u00020&*\u00020\fH\u0087\b\u001a\r\u0010+\u001a\u00020&*\u00020\u000eH\u0087\b\u001a\r\u0010+\u001a\u00020&*\u00020\u0010H\u0087\b\u001a\r\u0010+\u001a\u00020&*\u00020\u0012H\u0087\b\u001a\r\u0010+\u001a\u00020&*\u00020\u0014H\u0087\b\u001aQ\u0010,\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0003\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\f\u0010-\u001a\b\u0012\u0004\u0012\u0002H\u00020\u00032\b\b\u0002\u0010.\u001a\u00020\u000f2\b\b\u0002\u0010/\u001a\u00020\u000f2\b\b\u0002\u00100\u001a\u00020\u000fH\u0007¢\u0006\u0002\u00101\u001a2\u0010,\u001a\u00020\u0006*\u00020\u00062\u0006\u0010-\u001a\u00020\u00062\b\b\u0002\u0010.\u001a\u00020\u000f2\b\b\u0002\u0010/\u001a\u00020\u000f2\b\b\u0002\u00100\u001a\u00020\u000fH\u0007\u001a2\u0010,\u001a\u00020\b*\u00020\b2\u0006\u0010-\u001a\u00020\b2\b\b\u0002\u0010.\u001a\u00020\u000f2\b\b\u0002\u0010/\u001a\u00020\u000f2\b\b\u0002\u00100\u001a\u00020\u000fH\u0007\u001a2\u0010,\u001a\u00020\n*\u00020\n2\u0006\u0010-\u001a\u00020\n2\b\b\u0002\u0010.\u001a\u00020\u000f2\b\b\u0002\u0010/\u001a\u00020\u000f2\b\b\u0002\u00100\u001a\u00020\u000fH\u0007\u001a2\u0010,\u001a\u00020\f*\u00020\f2\u0006\u0010-\u001a\u00020\f2\b\b\u0002\u0010.\u001a\u00020\u000f2\b\b\u0002\u0010/\u001a\u00020\u000f2\b\b\u0002\u00100\u001a\u00020\u000fH\u0007\u001a2\u0010,\u001a\u00020\u000e*\u00020\u000e2\u0006\u0010-\u001a\u00020\u000e2\b\b\u0002\u0010.\u001a\u00020\u000f2\b\b\u0002\u0010/\u001a\u00020\u000f2\b\b\u0002\u00100\u001a\u00020\u000fH\u0007\u001a2\u0010,\u001a\u00020\u0010*\u00020\u00102\u0006\u0010-\u001a\u00020\u00102\b\b\u0002\u0010.\u001a\u00020\u000f2\b\b\u0002\u0010/\u001a\u00020\u000f2\b\b\u0002\u00100\u001a\u00020\u000fH\u0007\u001a2\u0010,\u001a\u00020\u0012*\u00020\u00122\u0006\u0010-\u001a\u00020\u00122\b\b\u0002\u0010.\u001a\u00020\u000f2\b\b\u0002\u0010/\u001a\u00020\u000f2\b\b\u0002\u00100\u001a\u00020\u000fH\u0007\u001a2\u0010,\u001a\u00020\u0014*\u00020\u00142\u0006\u0010-\u001a\u00020\u00142\b\b\u0002\u0010.\u001a\u00020\u000f2\b\b\u0002\u0010/\u001a\u00020\u000f2\b\b\u0002\u00100\u001a\u00020\u000fH\u0007\u001a$\u00102\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0003\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u0003H\u0087\b¢\u0006\u0002\u00103\u001a.\u00102\u001a\n\u0012\u0006\u0012\u0004\u0018\u0001H\u00020\u0003\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u00032\u0006\u00104\u001a\u00020\u000fH\u0087\b¢\u0006\u0002\u00105\u001a\r\u00102\u001a\u00020\u0006*\u00020\u0006H\u0087\b\u001a\u0015\u00102\u001a\u00020\u0006*\u00020\u00062\u0006\u00104\u001a\u00020\u000fH\u0087\b\u001a\r\u00102\u001a\u00020\b*\u00020\bH\u0087\b\u001a\u0015\u00102\u001a\u00020\b*\u00020\b2\u0006\u00104\u001a\u00020\u000fH\u0087\b\u001a\r\u00102\u001a\u00020\n*\u00020\nH\u0087\b\u001a\u0015\u00102\u001a\u00020\n*\u00020\n2\u0006\u00104\u001a\u00020\u000fH\u0087\b\u001a\r\u00102\u001a\u00020\f*\u00020\fH\u0087\b\u001a\u0015\u00102\u001a\u00020\f*\u00020\f2\u0006\u00104\u001a\u00020\u000fH\u0087\b\u001a\r\u00102\u001a\u00020\u000e*\u00020\u000eH\u0087\b\u001a\u0015\u00102\u001a\u00020\u000e*\u00020\u000e2\u0006\u00104\u001a\u00020\u000fH\u0087\b\u001a\r\u00102\u001a\u00020\u0010*\u00020\u0010H\u0087\b\u001a\u0015\u00102\u001a\u00020\u0010*\u00020\u00102\u0006\u00104\u001a\u00020\u000fH\u0087\b\u001a\r\u00102\u001a\u00020\u0012*\u00020\u0012H\u0087\b\u001a\u0015\u00102\u001a\u00020\u0012*\u00020\u00122\u0006\u00104\u001a\u00020\u000fH\u0087\b\u001a\r\u00102\u001a\u00020\u0014*\u00020\u0014H\u0087\b\u001a\u0015\u00102\u001a\u00020\u0014*\u00020\u00142\u0006\u00104\u001a\u00020\u000fH\u0087\b\u001a6\u00106\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0003\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u00032\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0087\b¢\u0006\u0004\b7\u00108\u001a\"\u00106\u001a\u00020\u0006*\u00020\u00062\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0087\b¢\u0006\u0002\b7\u001a\"\u00106\u001a\u00020\b*\u00020\b2\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0087\b¢\u0006\u0002\b7\u001a\"\u00106\u001a\u00020\n*\u00020\n2\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0087\b¢\u0006\u0002\b7\u001a\"\u00106\u001a\u00020\f*\u00020\f2\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0087\b¢\u0006\u0002\b7\u001a\"\u00106\u001a\u00020\u000e*\u00020\u000e2\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0087\b¢\u0006\u0002\b7\u001a\"\u00106\u001a\u00020\u0010*\u00020\u00102\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0087\b¢\u0006\u0002\b7\u001a\"\u00106\u001a\u00020\u0012*\u00020\u00122\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0087\b¢\u0006\u0002\b7\u001a\"\u00106\u001a\u00020\u0014*\u00020\u00142\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0087\b¢\u0006\u0002\b7\u001a5\u00109\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0003\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u00032\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0001¢\u0006\u0004\b6\u00108\u001a!\u00109\u001a\u00020\u0006*\u00020\u00062\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0001¢\u0006\u0002\b6\u001a!\u00109\u001a\u00020\b*\u00020\b2\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0001¢\u0006\u0002\b6\u001a!\u00109\u001a\u00020\n*\u00020\n2\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0001¢\u0006\u0002\b6\u001a!\u00109\u001a\u00020\f*\u00020\f2\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0001¢\u0006\u0002\b6\u001a!\u00109\u001a\u00020\u000e*\u00020\u000e2\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0001¢\u0006\u0002\b6\u001a!\u00109\u001a\u00020\u0010*\u00020\u00102\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0001¢\u0006\u0002\b6\u001a!\u00109\u001a\u00020\u0012*\u00020\u00122\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0001¢\u0006\u0002\b6\u001a!\u00109\u001a\u00020\u0014*\u00020\u00142\u0006\u0010\u001a\u001a\u00020\u000f2\u0006\u0010\u001b\u001a\u00020\u000fH\u0001¢\u0006\u0002\b6\u001a(\u0010:\u001a\u0002H\u0002\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\u0006\u0010;\u001a\u00020\u000fH\u0087\b¢\u0006\u0002\u0010<\u001a\u0015\u0010:\u001a\u00020\u0005*\u00020\u00062\u0006\u0010;\u001a\u00020\u000fH\u0087\b\u001a\u0015\u0010:\u001a\u00020\u0007*\u00020\b2\u0006\u0010;\u001a\u00020\u000fH\u0087\b\u001a\u0015\u0010:\u001a\u00020\t*\u00020\n2\u0006\u0010;\u001a\u00020\u000fH\u0087\b\u001a\u0015\u0010:\u001a\u00020\u000b*\u00020\f2\u0006\u0010;\u001a\u00020\u000fH\u0087\b\u001a\u0015\u0010:\u001a\u00020\r*\u00020\u000e2\u0006\u0010;\u001a\u00020\u000fH\u0087\b\u001a\u0015\u0010:\u001a\u00020\u000f*\u00020\u00102\u0006\u0010;\u001a\u00020\u000fH\u0087\b\u001a\u0015\u0010:\u001a\u00020\u0011*\u00020\u00122\u0006\u0010;\u001a\u00020\u000fH\u0087\b\u001a\u0015\u0010:\u001a\u00020\u0013*\u00020\u00142\u0006\u0010;\u001a\u00020\u000fH\u0087\b\u001a7\u0010=\u001a\u00020>\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u00032\u0006\u0010\u0016\u001a\u0002H\u00022\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f¢\u0006\u0002\u0010?\u001a&\u0010=\u001a\u00020>*\u00020\u00062\u0006\u0010\u0016\u001a\u00020\u00052\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a&\u0010=\u001a\u00020>*\u00020\b2\u0006\u0010\u0016\u001a\u00020\u00072\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a&\u0010=\u001a\u00020>*\u00020\n2\u0006\u0010\u0016\u001a\u00020\t2\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a&\u0010=\u001a\u00020>*\u00020\f2\u0006\u0010\u0016\u001a\u00020\u000b2\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a&\u0010=\u001a\u00020>*\u00020\u000e2\u0006\u0010\u0016\u001a\u00020\r2\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a&\u0010=\u001a\u00020>*\u00020\u00102\u0006\u0010\u0016\u001a\u00020\u000f2\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a&\u0010=\u001a\u00020>*\u00020\u00122\u0006\u0010\u0016\u001a\u00020\u00112\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a&\u0010=\u001a\u00020>*\u00020\u00142\u0006\u0010\u0016\u001a\u00020\u00132\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a-\u0010@\u001a\b\u0012\u0004\u0012\u0002HA0\u0001\"\u0004\b\u0000\u0010A*\u0006\u0012\u0002\b\u00030\u00032\f\u0010B\u001a\b\u0012\u0004\u0012\u0002HA0C¢\u0006\u0002\u0010D\u001aA\u0010E\u001a\u0002HF\"\u0010\b\u0000\u0010F*\n\u0012\u0006\b\u0000\u0012\u0002HA0G\"\u0004\b\u0001\u0010A*\u0006\u0012\u0002\b\u00030\u00032\u0006\u0010-\u001a\u0002HF2\f\u0010B\u001a\b\u0012\u0004\u0012\u0002HA0C¢\u0006\u0002\u0010H\u001a,\u0010I\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0003\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u00032\u0006\u0010\u0016\u001a\u0002H\u0002H\u0086\u0002¢\u0006\u0002\u0010J\u001a4\u0010I\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0003\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u00032\u000e\u0010K\u001a\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0003H\u0086\u0002¢\u0006\u0002\u0010L\u001a2\u0010I\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0003\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u00032\f\u0010K\u001a\b\u0012\u0004\u0012\u0002H\u00020MH\u0086\u0002¢\u0006\u0002\u0010N\u001a\u0015\u0010I\u001a\u00020\u0006*\u00020\u00062\u0006\u0010\u0016\u001a\u00020\u0005H\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\u0006*\u00020\u00062\u0006\u0010K\u001a\u00020\u0006H\u0086\u0002\u001a\u001b\u0010I\u001a\u00020\u0006*\u00020\u00062\f\u0010K\u001a\b\u0012\u0004\u0012\u00020\u00050MH\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\b*\u00020\b2\u0006\u0010\u0016\u001a\u00020\u0007H\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\b*\u00020\b2\u0006\u0010K\u001a\u00020\bH\u0086\u0002\u001a\u001b\u0010I\u001a\u00020\b*\u00020\b2\f\u0010K\u001a\b\u0012\u0004\u0012\u00020\u00070MH\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\n*\u00020\n2\u0006\u0010\u0016\u001a\u00020\tH\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\n*\u00020\n2\u0006\u0010K\u001a\u00020\nH\u0086\u0002\u001a\u001b\u0010I\u001a\u00020\n*\u00020\n2\f\u0010K\u001a\b\u0012\u0004\u0012\u00020\t0MH\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\f*\u00020\f2\u0006\u0010\u0016\u001a\u00020\u000bH\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\f*\u00020\f2\u0006\u0010K\u001a\u00020\fH\u0086\u0002\u001a\u001b\u0010I\u001a\u00020\f*\u00020\f2\f\u0010K\u001a\b\u0012\u0004\u0012\u00020\u000b0MH\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\u000e*\u00020\u000e2\u0006\u0010\u0016\u001a\u00020\rH\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\u000e*\u00020\u000e2\u0006\u0010K\u001a\u00020\u000eH\u0086\u0002\u001a\u001b\u0010I\u001a\u00020\u000e*\u00020\u000e2\f\u0010K\u001a\b\u0012\u0004\u0012\u00020\r0MH\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\u0010*\u00020\u00102\u0006\u0010\u0016\u001a\u00020\u000fH\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\u0010*\u00020\u00102\u0006\u0010K\u001a\u00020\u0010H\u0086\u0002\u001a\u001b\u0010I\u001a\u00020\u0010*\u00020\u00102\f\u0010K\u001a\b\u0012\u0004\u0012\u00020\u000f0MH\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\u0012*\u00020\u00122\u0006\u0010\u0016\u001a\u00020\u0011H\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\u0012*\u00020\u00122\u0006\u0010K\u001a\u00020\u0012H\u0086\u0002\u001a\u001b\u0010I\u001a\u00020\u0012*\u00020\u00122\f\u0010K\u001a\b\u0012\u0004\u0012\u00020\u00110MH\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\u0014*\u00020\u00142\u0006\u0010\u0016\u001a\u00020\u0013H\u0086\u0002\u001a\u0015\u0010I\u001a\u00020\u0014*\u00020\u00142\u0006\u0010K\u001a\u00020\u0014H\u0086\u0002\u001a\u001b\u0010I\u001a\u00020\u0014*\u00020\u00142\f\u0010K\u001a\b\u0012\u0004\u0012\u00020\u00130MH\u0086\u0002\u001a,\u0010O\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0003\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u00032\u0006\u0010\u0016\u001a\u0002H\u0002H\u0087\b¢\u0006\u0002\u0010J\u001a\u001d\u0010P\u001a\u00020>\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0003¢\u0006\u0002\u0010Q\u001a*\u0010P\u001a\u00020>\"\u000e\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020R*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0003H\u0087\b¢\u0006\u0002\u0010S\u001a1\u0010P\u001a\u00020>\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f¢\u0006\u0002\u0010T\u001a\n\u0010P\u001a\u00020>*\u00020\b\u001a\u001e\u0010P\u001a\u00020>*\u00020\b2\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a\n\u0010P\u001a\u00020>*\u00020\n\u001a\u001e\u0010P\u001a\u00020>*\u00020\n2\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a\n\u0010P\u001a\u00020>*\u00020\f\u001a\u001e\u0010P\u001a\u00020>*\u00020\f2\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a\n\u0010P\u001a\u00020>*\u00020\u000e\u001a\u001e\u0010P\u001a\u00020>*\u00020\u000e2\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a\n\u0010P\u001a\u00020>*\u00020\u0010\u001a\u001e\u0010P\u001a\u00020>*\u00020\u00102\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a\n\u0010P\u001a\u00020>*\u00020\u0012\u001a\u001e\u0010P\u001a\u00020>*\u00020\u00122\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a\n\u0010P\u001a\u00020>*\u00020\u0014\u001a\u001e\u0010P\u001a\u00020>*\u00020\u00142\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f\u001a9\u0010U\u001a\u00020>\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\u001a\u0010\u0017\u001a\u0016\u0012\u0006\b\u0000\u0012\u0002H\u00020\u0018j\n\u0012\u0006\b\u0000\u0012\u0002H\u0002`\u0019¢\u0006\u0002\u0010V\u001aM\u0010U\u001a\u00020>\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\u001a\u0010\u0017\u001a\u0016\u0012\u0006\b\u0000\u0012\u0002H\u00020\u0018j\n\u0012\u0006\b\u0000\u0012\u0002H\u0002`\u00192\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f¢\u0006\u0002\u0010W\u001a-\u0010X\u001a\b\u0012\u0004\u0012\u0002H\u00020Y\"\u000e\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020R*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0003¢\u0006\u0002\u0010Z\u001a?\u0010X\u001a\b\u0012\u0004\u0012\u0002H\u00020Y\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\u001a\u0010\u0017\u001a\u0016\u0012\u0006\b\u0000\u0012\u0002H\u00020\u0018j\n\u0012\u0006\b\u0000\u0012\u0002H\u0002`\u0019¢\u0006\u0002\u0010[\u001a\u0010\u0010X\u001a\b\u0012\u0004\u0012\u00020\u00050Y*\u00020\u0006\u001a\u0010\u0010X\u001a\b\u0012\u0004\u0012\u00020\u00070Y*\u00020\b\u001a\u0010\u0010X\u001a\b\u0012\u0004\u0012\u00020\t0Y*\u00020\n\u001a\u0010\u0010X\u001a\b\u0012\u0004\u0012\u00020\u000b0Y*\u00020\f\u001a\u0010\u0010X\u001a\b\u0012\u0004\u0012\u00020\r0Y*\u00020\u000e\u001a\u0010\u0010X\u001a\b\u0012\u0004\u0012\u00020\u000f0Y*\u00020\u0010\u001a\u0010\u0010X\u001a\b\u0012\u0004\u0012\u00020\u00110Y*\u00020\u0012\u001a\u0010\u0010X\u001a\b\u0012\u0004\u0012\u00020\u00130Y*\u00020\u0014\u001a\u0015\u0010\\\u001a\b\u0012\u0004\u0012\u00020\u00050\u0003*\u00020\u0006¢\u0006\u0002\u0010]\u001a\u0015\u0010\\\u001a\b\u0012\u0004\u0012\u00020\u00070\u0003*\u00020\b¢\u0006\u0002\u0010^\u001a\u0015\u0010\\\u001a\b\u0012\u0004\u0012\u00020\t0\u0003*\u00020\n¢\u0006\u0002\u0010_\u001a\u0015\u0010\\\u001a\b\u0012\u0004\u0012\u00020\u000b0\u0003*\u00020\f¢\u0006\u0002\u0010`\u001a\u0015\u0010\\\u001a\b\u0012\u0004\u0012\u00020\r0\u0003*\u00020\u000e¢\u0006\u0002\u0010a\u001a\u0015\u0010\\\u001a\b\u0012\u0004\u0012\u00020\u000f0\u0003*\u00020\u0010¢\u0006\u0002\u0010b\u001a\u0015\u0010\\\u001a\b\u0012\u0004\u0012\u00020\u00110\u0003*\u00020\u0012¢\u0006\u0002\u0010c\u001a\u0015\u0010\\\u001a\b\u0012\u0004\u0012\u00020\u00130\u0003*\u00020\u0014¢\u0006\u0002\u0010d¨\u0006e"}, d2 = {"asList", BuildConfig.FLAVOR, "T", BuildConfig.FLAVOR, "([Ljava/lang/Object;)Ljava/util/List;", BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, "binarySearch", "element", "comparator", "Ljava/util/Comparator;", "Lkotlin/Comparator;", "fromIndex", "toIndex", "([Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;II)I", "([Ljava/lang/Object;Ljava/lang/Object;II)I", "contentDeepEquals", "other", "contentDeepEqualsInline", "([Ljava/lang/Object;[Ljava/lang/Object;)Z", "contentDeepHashCode", "contentDeepHashCodeInline", "([Ljava/lang/Object;)I", "contentDeepToString", BuildConfig.FLAVOR, "contentDeepToStringInline", "([Ljava/lang/Object;)Ljava/lang/String;", "contentEquals", "contentHashCode", "contentToString", "copyInto", "destination", "destinationOffset", "startIndex", "endIndex", "([Ljava/lang/Object;[Ljava/lang/Object;III)[Ljava/lang/Object;", "copyOf", "([Ljava/lang/Object;)[Ljava/lang/Object;", "newSize", "([Ljava/lang/Object;I)[Ljava/lang/Object;", "copyOfRange", "copyOfRangeInline", "([Ljava/lang/Object;II)[Ljava/lang/Object;", "copyOfRangeImpl", "elementAt", "index", "([Ljava/lang/Object;I)Ljava/lang/Object;", "fill", BuildConfig.FLAVOR, "([Ljava/lang/Object;Ljava/lang/Object;II)V", "filterIsInstance", "R", "klass", "Ljava/lang/Class;", "([Ljava/lang/Object;Ljava/lang/Class;)Ljava/util/List;", "filterIsInstanceTo", "C", BuildConfig.FLAVOR, "([Ljava/lang/Object;Ljava/util/Collection;Ljava/lang/Class;)Ljava/util/Collection;", "plus", "([Ljava/lang/Object;Ljava/lang/Object;)[Ljava/lang/Object;", "elements", "([Ljava/lang/Object;[Ljava/lang/Object;)[Ljava/lang/Object;", BuildConfig.FLAVOR, "([Ljava/lang/Object;Ljava/util/Collection;)[Ljava/lang/Object;", "plusElement", "sort", "([Ljava/lang/Object;)V", BuildConfig.FLAVOR, "([Ljava/lang/Comparable;)V", "([Ljava/lang/Object;II)V", "sortWith", "([Ljava/lang/Object;Ljava/util/Comparator;)V", "([Ljava/lang/Object;Ljava/util/Comparator;II)V", "toSortedSet", "Ljava/util/SortedSet;", "([Ljava/lang/Comparable;)Ljava/util/SortedSet;", "([Ljava/lang/Object;Ljava/util/Comparator;)Ljava/util/SortedSet;", "toTypedArray", "([Z)[Ljava/lang/Boolean;", "([B)[Ljava/lang/Byte;", "([C)[Ljava/lang/Character;", "([D)[Ljava/lang/Double;", "([F)[Ljava/lang/Float;", "([I)[Ljava/lang/Integer;", "([J)[Ljava/lang/Long;", "([S)[Ljava/lang/Short;", "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/collections/ArraysKt")
/* loaded from: classes.dex */
public class ArraysKt___ArraysJvmKt extends ArraysKt__ArraysKt {
    private static final <T> T elementAt(T[] tArr, int index) {
        return tArr[index];
    }

    private static final byte elementAt(byte[] $this$elementAt, int index) {
        return $this$elementAt[index];
    }

    private static final short elementAt(short[] $this$elementAt, int index) {
        return $this$elementAt[index];
    }

    private static final int elementAt(int[] $this$elementAt, int index) {
        return $this$elementAt[index];
    }

    private static final long elementAt(long[] $this$elementAt, int index) {
        return $this$elementAt[index];
    }

    private static final float elementAt(float[] $this$elementAt, int index) {
        return $this$elementAt[index];
    }

    private static final double elementAt(double[] $this$elementAt, int index) {
        return $this$elementAt[index];
    }

    private static final boolean elementAt(boolean[] $this$elementAt, int index) {
        return $this$elementAt[index];
    }

    private static final char elementAt(char[] $this$elementAt, int index) {
        return $this$elementAt[index];
    }

    public static final <R> List<R> filterIsInstance(Object[] filterIsInstance, Class<R> klass) {
        Intrinsics.checkParameterIsNotNull(filterIsInstance, "$this$filterIsInstance");
        Intrinsics.checkParameterIsNotNull(klass, "klass");
        return (List) ArraysKt.filterIsInstanceTo(filterIsInstance, new ArrayList(), klass);
    }

    public static final <C extends Collection<? super R>, R> C filterIsInstanceTo(Object[] filterIsInstanceTo, C destination, Class<R> klass) {
        Intrinsics.checkParameterIsNotNull(filterIsInstanceTo, "$this$filterIsInstanceTo");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        Intrinsics.checkParameterIsNotNull(klass, "klass");
        for (Object element : filterIsInstanceTo) {
            if (klass.isInstance(element)) {
                destination.add(element);
            }
        }
        return destination;
    }

    public static final <T> List<T> asList(T[] asList) {
        Intrinsics.checkParameterIsNotNull(asList, "$this$asList");
        List<T> asList2 = ArraysUtilJVM.asList(asList);
        Intrinsics.checkExpressionValueIsNotNull(asList2, "ArraysUtilJVM.asList(this)");
        return asList2;
    }

    public static final List<Byte> asList(byte[] asList) {
        Intrinsics.checkParameterIsNotNull(asList, "$this$asList");
        return new ArraysKt___ArraysJvmKt$asList$1(asList);
    }

    public static final List<Short> asList(short[] asList) {
        Intrinsics.checkParameterIsNotNull(asList, "$this$asList");
        return new ArraysKt___ArraysJvmKt$asList$2(asList);
    }

    public static final List<Integer> asList(int[] asList) {
        Intrinsics.checkParameterIsNotNull(asList, "$this$asList");
        return new ArraysKt___ArraysJvmKt$asList$3(asList);
    }

    public static final List<Long> asList(long[] asList) {
        Intrinsics.checkParameterIsNotNull(asList, "$this$asList");
        return new ArraysKt___ArraysJvmKt$asList$4(asList);
    }

    public static final List<Float> asList(float[] asList) {
        Intrinsics.checkParameterIsNotNull(asList, "$this$asList");
        return new ArraysKt___ArraysJvmKt$asList$5(asList);
    }

    public static final List<Double> asList(double[] asList) {
        Intrinsics.checkParameterIsNotNull(asList, "$this$asList");
        return new ArraysKt___ArraysJvmKt$asList$6(asList);
    }

    public static final List<Boolean> asList(boolean[] asList) {
        Intrinsics.checkParameterIsNotNull(asList, "$this$asList");
        return new ArraysKt___ArraysJvmKt$asList$7(asList);
    }

    public static final List<Character> asList(char[] asList) {
        Intrinsics.checkParameterIsNotNull(asList, "$this$asList");
        return new ArraysKt___ArraysJvmKt$asList$8(asList);
    }

    public static /* synthetic */ int binarySearch$default(Object[] objArr, Object obj, Comparator comparator, int i, int i2, int i3, Object obj2) {
        if ((i3 & 4) != 0) {
            i = 0;
        }
        if ((i3 & 8) != 0) {
            i2 = objArr.length;
        }
        return ArraysKt.binarySearch(objArr, obj, comparator, i, i2);
    }

    public static final <T> int binarySearch(T[] binarySearch, T t, Comparator<? super T> comparator, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(binarySearch, "$this$binarySearch");
        Intrinsics.checkParameterIsNotNull(comparator, "comparator");
        return Arrays.binarySearch(binarySearch, fromIndex, toIndex, t, comparator);
    }

    public static /* synthetic */ int binarySearch$default(Object[] objArr, Object obj, int i, int i2, int i3, Object obj2) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = objArr.length;
        }
        return ArraysKt.binarySearch(objArr, obj, i, i2);
    }

    public static final <T> int binarySearch(T[] binarySearch, T t, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(binarySearch, "$this$binarySearch");
        return Arrays.binarySearch(binarySearch, fromIndex, toIndex, t);
    }

    public static /* synthetic */ int binarySearch$default(byte[] bArr, byte b, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = bArr.length;
        }
        return ArraysKt.binarySearch(bArr, b, i, i2);
    }

    public static final int binarySearch(byte[] binarySearch, byte element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(binarySearch, "$this$binarySearch");
        return Arrays.binarySearch(binarySearch, fromIndex, toIndex, element);
    }

    public static /* synthetic */ int binarySearch$default(short[] sArr, short s, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = sArr.length;
        }
        return ArraysKt.binarySearch(sArr, s, i, i2);
    }

    public static final int binarySearch(short[] binarySearch, short element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(binarySearch, "$this$binarySearch");
        return Arrays.binarySearch(binarySearch, fromIndex, toIndex, element);
    }

    public static /* synthetic */ int binarySearch$default(int[] iArr, int i, int i2, int i3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i2 = 0;
        }
        if ((i4 & 4) != 0) {
            i3 = iArr.length;
        }
        return ArraysKt.binarySearch(iArr, i, i2, i3);
    }

    public static final int binarySearch(int[] binarySearch, int element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(binarySearch, "$this$binarySearch");
        return Arrays.binarySearch(binarySearch, fromIndex, toIndex, element);
    }

    public static /* synthetic */ int binarySearch$default(long[] jArr, long j, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = jArr.length;
        }
        return ArraysKt.binarySearch(jArr, j, i, i2);
    }

    public static final int binarySearch(long[] binarySearch, long element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(binarySearch, "$this$binarySearch");
        return Arrays.binarySearch(binarySearch, fromIndex, toIndex, element);
    }

    public static /* synthetic */ int binarySearch$default(float[] fArr, float f, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = fArr.length;
        }
        return ArraysKt.binarySearch(fArr, f, i, i2);
    }

    public static final int binarySearch(float[] binarySearch, float element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(binarySearch, "$this$binarySearch");
        return Arrays.binarySearch(binarySearch, fromIndex, toIndex, element);
    }

    public static /* synthetic */ int binarySearch$default(double[] dArr, double d, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = dArr.length;
        }
        return ArraysKt.binarySearch(dArr, d, i, i2);
    }

    public static final int binarySearch(double[] binarySearch, double element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(binarySearch, "$this$binarySearch");
        return Arrays.binarySearch(binarySearch, fromIndex, toIndex, element);
    }

    public static /* synthetic */ int binarySearch$default(char[] cArr, char c, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = cArr.length;
        }
        return ArraysKt.binarySearch(cArr, c, i, i2);
    }

    public static final int binarySearch(char[] binarySearch, char element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(binarySearch, "$this$binarySearch");
        return Arrays.binarySearch(binarySearch, fromIndex, toIndex, element);
    }

    private static final <T> boolean contentDeepEqualsInline(T[] tArr, T[] tArr2) {
        if (PlatformImplementationsKt.apiVersionIsAtLeast(1, 3, 0)) {
            return ArraysKt.contentDeepEquals(tArr, tArr2);
        }
        return Arrays.deepEquals(tArr, tArr2);
    }

    private static final <T> int contentDeepHashCodeInline(T[] tArr) {
        if (PlatformImplementationsKt.apiVersionIsAtLeast(1, 3, 0)) {
            return ArraysKt.contentDeepHashCode(tArr);
        }
        return Arrays.deepHashCode(tArr);
    }

    private static final <T> String contentDeepToStringInline(T[] tArr) {
        if (PlatformImplementationsKt.apiVersionIsAtLeast(1, 3, 0)) {
            return ArraysKt.contentDeepToString(tArr);
        }
        String deepToString = Arrays.deepToString(tArr);
        Intrinsics.checkExpressionValueIsNotNull(deepToString, "java.util.Arrays.deepToString(this)");
        return deepToString;
    }

    private static final <T> boolean contentEquals(T[] tArr, T[] tArr2) {
        return Arrays.equals(tArr, tArr2);
    }

    private static final boolean contentEquals(byte[] $this$contentEquals, byte[] other) {
        return Arrays.equals($this$contentEquals, other);
    }

    private static final boolean contentEquals(short[] $this$contentEquals, short[] other) {
        return Arrays.equals($this$contentEquals, other);
    }

    private static final boolean contentEquals(int[] $this$contentEquals, int[] other) {
        return Arrays.equals($this$contentEquals, other);
    }

    private static final boolean contentEquals(long[] $this$contentEquals, long[] other) {
        return Arrays.equals($this$contentEquals, other);
    }

    private static final boolean contentEquals(float[] $this$contentEquals, float[] other) {
        return Arrays.equals($this$contentEquals, other);
    }

    private static final boolean contentEquals(double[] $this$contentEquals, double[] other) {
        return Arrays.equals($this$contentEquals, other);
    }

    private static final boolean contentEquals(boolean[] $this$contentEquals, boolean[] other) {
        return Arrays.equals($this$contentEquals, other);
    }

    private static final boolean contentEquals(char[] $this$contentEquals, char[] other) {
        return Arrays.equals($this$contentEquals, other);
    }

    private static final <T> int contentHashCode(T[] tArr) {
        return Arrays.hashCode(tArr);
    }

    private static final int contentHashCode(byte[] $this$contentHashCode) {
        return Arrays.hashCode($this$contentHashCode);
    }

    private static final int contentHashCode(short[] $this$contentHashCode) {
        return Arrays.hashCode($this$contentHashCode);
    }

    private static final int contentHashCode(int[] $this$contentHashCode) {
        return Arrays.hashCode($this$contentHashCode);
    }

    private static final int contentHashCode(long[] $this$contentHashCode) {
        return Arrays.hashCode($this$contentHashCode);
    }

    private static final int contentHashCode(float[] $this$contentHashCode) {
        return Arrays.hashCode($this$contentHashCode);
    }

    private static final int contentHashCode(double[] $this$contentHashCode) {
        return Arrays.hashCode($this$contentHashCode);
    }

    private static final int contentHashCode(boolean[] $this$contentHashCode) {
        return Arrays.hashCode($this$contentHashCode);
    }

    private static final int contentHashCode(char[] $this$contentHashCode) {
        return Arrays.hashCode($this$contentHashCode);
    }

    private static final <T> String contentToString(T[] tArr) {
        String arrays = Arrays.toString(tArr);
        Intrinsics.checkExpressionValueIsNotNull(arrays, "java.util.Arrays.toString(this)");
        return arrays;
    }

    private static final String contentToString(byte[] $this$contentToString) {
        String arrays = Arrays.toString($this$contentToString);
        Intrinsics.checkExpressionValueIsNotNull(arrays, "java.util.Arrays.toString(this)");
        return arrays;
    }

    private static final String contentToString(short[] $this$contentToString) {
        String arrays = Arrays.toString($this$contentToString);
        Intrinsics.checkExpressionValueIsNotNull(arrays, "java.util.Arrays.toString(this)");
        return arrays;
    }

    private static final String contentToString(int[] $this$contentToString) {
        String arrays = Arrays.toString($this$contentToString);
        Intrinsics.checkExpressionValueIsNotNull(arrays, "java.util.Arrays.toString(this)");
        return arrays;
    }

    private static final String contentToString(long[] $this$contentToString) {
        String arrays = Arrays.toString($this$contentToString);
        Intrinsics.checkExpressionValueIsNotNull(arrays, "java.util.Arrays.toString(this)");
        return arrays;
    }

    private static final String contentToString(float[] $this$contentToString) {
        String arrays = Arrays.toString($this$contentToString);
        Intrinsics.checkExpressionValueIsNotNull(arrays, "java.util.Arrays.toString(this)");
        return arrays;
    }

    private static final String contentToString(double[] $this$contentToString) {
        String arrays = Arrays.toString($this$contentToString);
        Intrinsics.checkExpressionValueIsNotNull(arrays, "java.util.Arrays.toString(this)");
        return arrays;
    }

    private static final String contentToString(boolean[] $this$contentToString) {
        String arrays = Arrays.toString($this$contentToString);
        Intrinsics.checkExpressionValueIsNotNull(arrays, "java.util.Arrays.toString(this)");
        return arrays;
    }

    private static final String contentToString(char[] $this$contentToString) {
        String arrays = Arrays.toString($this$contentToString);
        Intrinsics.checkExpressionValueIsNotNull(arrays, "java.util.Arrays.toString(this)");
        return arrays;
    }

    public static /* synthetic */ Object[] copyInto$default(Object[] objArr, Object[] objArr2, int i, int i2, int i3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i = 0;
        }
        if ((i4 & 4) != 0) {
            i2 = 0;
        }
        if ((i4 & 8) != 0) {
            i3 = objArr.length;
        }
        return ArraysKt.copyInto(objArr, objArr2, i, i2, i3);
    }

    public static final <T> T[] copyInto(T[] copyInto, T[] destination, int destinationOffset, int startIndex, int endIndex) {
        Intrinsics.checkParameterIsNotNull(copyInto, "$this$copyInto");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        System.arraycopy(copyInto, startIndex, destination, destinationOffset, endIndex - startIndex);
        return destination;
    }

    public static /* synthetic */ byte[] copyInto$default(byte[] bArr, byte[] bArr2, int i, int i2, int i3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i = 0;
        }
        if ((i4 & 4) != 0) {
            i2 = 0;
        }
        if ((i4 & 8) != 0) {
            i3 = bArr.length;
        }
        return ArraysKt.copyInto(bArr, bArr2, i, i2, i3);
    }

    public static final byte[] copyInto(byte[] copyInto, byte[] destination, int destinationOffset, int startIndex, int endIndex) {
        Intrinsics.checkParameterIsNotNull(copyInto, "$this$copyInto");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        System.arraycopy(copyInto, startIndex, destination, destinationOffset, endIndex - startIndex);
        return destination;
    }

    public static /* synthetic */ short[] copyInto$default(short[] sArr, short[] sArr2, int i, int i2, int i3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i = 0;
        }
        if ((i4 & 4) != 0) {
            i2 = 0;
        }
        if ((i4 & 8) != 0) {
            i3 = sArr.length;
        }
        return ArraysKt.copyInto(sArr, sArr2, i, i2, i3);
    }

    public static final short[] copyInto(short[] copyInto, short[] destination, int destinationOffset, int startIndex, int endIndex) {
        Intrinsics.checkParameterIsNotNull(copyInto, "$this$copyInto");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        System.arraycopy(copyInto, startIndex, destination, destinationOffset, endIndex - startIndex);
        return destination;
    }

    public static /* synthetic */ int[] copyInto$default(int[] iArr, int[] iArr2, int i, int i2, int i3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i = 0;
        }
        if ((i4 & 4) != 0) {
            i2 = 0;
        }
        if ((i4 & 8) != 0) {
            i3 = iArr.length;
        }
        return ArraysKt.copyInto(iArr, iArr2, i, i2, i3);
    }

    public static final int[] copyInto(int[] copyInto, int[] destination, int destinationOffset, int startIndex, int endIndex) {
        Intrinsics.checkParameterIsNotNull(copyInto, "$this$copyInto");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        System.arraycopy(copyInto, startIndex, destination, destinationOffset, endIndex - startIndex);
        return destination;
    }

    public static /* synthetic */ long[] copyInto$default(long[] jArr, long[] jArr2, int i, int i2, int i3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i = 0;
        }
        if ((i4 & 4) != 0) {
            i2 = 0;
        }
        if ((i4 & 8) != 0) {
            i3 = jArr.length;
        }
        return ArraysKt.copyInto(jArr, jArr2, i, i2, i3);
    }

    public static final long[] copyInto(long[] copyInto, long[] destination, int destinationOffset, int startIndex, int endIndex) {
        Intrinsics.checkParameterIsNotNull(copyInto, "$this$copyInto");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        System.arraycopy(copyInto, startIndex, destination, destinationOffset, endIndex - startIndex);
        return destination;
    }

    public static /* synthetic */ float[] copyInto$default(float[] fArr, float[] fArr2, int i, int i2, int i3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i = 0;
        }
        if ((i4 & 4) != 0) {
            i2 = 0;
        }
        if ((i4 & 8) != 0) {
            i3 = fArr.length;
        }
        return ArraysKt.copyInto(fArr, fArr2, i, i2, i3);
    }

    public static final float[] copyInto(float[] copyInto, float[] destination, int destinationOffset, int startIndex, int endIndex) {
        Intrinsics.checkParameterIsNotNull(copyInto, "$this$copyInto");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        System.arraycopy(copyInto, startIndex, destination, destinationOffset, endIndex - startIndex);
        return destination;
    }

    public static /* synthetic */ double[] copyInto$default(double[] dArr, double[] dArr2, int i, int i2, int i3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i = 0;
        }
        if ((i4 & 4) != 0) {
            i2 = 0;
        }
        if ((i4 & 8) != 0) {
            i3 = dArr.length;
        }
        return ArraysKt.copyInto(dArr, dArr2, i, i2, i3);
    }

    public static final double[] copyInto(double[] copyInto, double[] destination, int destinationOffset, int startIndex, int endIndex) {
        Intrinsics.checkParameterIsNotNull(copyInto, "$this$copyInto");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        System.arraycopy(copyInto, startIndex, destination, destinationOffset, endIndex - startIndex);
        return destination;
    }

    public static /* synthetic */ boolean[] copyInto$default(boolean[] zArr, boolean[] zArr2, int i, int i2, int i3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i = 0;
        }
        if ((i4 & 4) != 0) {
            i2 = 0;
        }
        if ((i4 & 8) != 0) {
            i3 = zArr.length;
        }
        return ArraysKt.copyInto(zArr, zArr2, i, i2, i3);
    }

    public static final boolean[] copyInto(boolean[] copyInto, boolean[] destination, int destinationOffset, int startIndex, int endIndex) {
        Intrinsics.checkParameterIsNotNull(copyInto, "$this$copyInto");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        System.arraycopy(copyInto, startIndex, destination, destinationOffset, endIndex - startIndex);
        return destination;
    }

    public static /* synthetic */ char[] copyInto$default(char[] cArr, char[] cArr2, int i, int i2, int i3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i = 0;
        }
        if ((i4 & 4) != 0) {
            i2 = 0;
        }
        if ((i4 & 8) != 0) {
            i3 = cArr.length;
        }
        return ArraysKt.copyInto(cArr, cArr2, i, i2, i3);
    }

    public static final char[] copyInto(char[] copyInto, char[] destination, int destinationOffset, int startIndex, int endIndex) {
        Intrinsics.checkParameterIsNotNull(copyInto, "$this$copyInto");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        System.arraycopy(copyInto, startIndex, destination, destinationOffset, endIndex - startIndex);
        return destination;
    }

    private static final <T> T[] copyOf(T[] tArr) {
        T[] tArr2 = (T[]) Arrays.copyOf(tArr, tArr.length);
        Intrinsics.checkExpressionValueIsNotNull(tArr2, "java.util.Arrays.copyOf(this, size)");
        return tArr2;
    }

    private static final byte[] copyOf(byte[] $this$copyOf) {
        byte[] copyOf = Arrays.copyOf($this$copyOf, $this$copyOf.length);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, size)");
        return copyOf;
    }

    private static final short[] copyOf(short[] $this$copyOf) {
        short[] copyOf = Arrays.copyOf($this$copyOf, $this$copyOf.length);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, size)");
        return copyOf;
    }

    private static final int[] copyOf(int[] $this$copyOf) {
        int[] copyOf = Arrays.copyOf($this$copyOf, $this$copyOf.length);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, size)");
        return copyOf;
    }

    private static final long[] copyOf(long[] $this$copyOf) {
        long[] copyOf = Arrays.copyOf($this$copyOf, $this$copyOf.length);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, size)");
        return copyOf;
    }

    private static final float[] copyOf(float[] $this$copyOf) {
        float[] copyOf = Arrays.copyOf($this$copyOf, $this$copyOf.length);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, size)");
        return copyOf;
    }

    private static final double[] copyOf(double[] $this$copyOf) {
        double[] copyOf = Arrays.copyOf($this$copyOf, $this$copyOf.length);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, size)");
        return copyOf;
    }

    private static final boolean[] copyOf(boolean[] $this$copyOf) {
        boolean[] copyOf = Arrays.copyOf($this$copyOf, $this$copyOf.length);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, size)");
        return copyOf;
    }

    private static final char[] copyOf(char[] $this$copyOf) {
        char[] copyOf = Arrays.copyOf($this$copyOf, $this$copyOf.length);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, size)");
        return copyOf;
    }

    private static final byte[] copyOf(byte[] $this$copyOf, int newSize) {
        byte[] copyOf = Arrays.copyOf($this$copyOf, newSize);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, newSize)");
        return copyOf;
    }

    private static final short[] copyOf(short[] $this$copyOf, int newSize) {
        short[] copyOf = Arrays.copyOf($this$copyOf, newSize);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, newSize)");
        return copyOf;
    }

    private static final int[] copyOf(int[] $this$copyOf, int newSize) {
        int[] copyOf = Arrays.copyOf($this$copyOf, newSize);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, newSize)");
        return copyOf;
    }

    private static final long[] copyOf(long[] $this$copyOf, int newSize) {
        long[] copyOf = Arrays.copyOf($this$copyOf, newSize);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, newSize)");
        return copyOf;
    }

    private static final float[] copyOf(float[] $this$copyOf, int newSize) {
        float[] copyOf = Arrays.copyOf($this$copyOf, newSize);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, newSize)");
        return copyOf;
    }

    private static final double[] copyOf(double[] $this$copyOf, int newSize) {
        double[] copyOf = Arrays.copyOf($this$copyOf, newSize);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, newSize)");
        return copyOf;
    }

    private static final boolean[] copyOf(boolean[] $this$copyOf, int newSize) {
        boolean[] copyOf = Arrays.copyOf($this$copyOf, newSize);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, newSize)");
        return copyOf;
    }

    private static final char[] copyOf(char[] $this$copyOf, int newSize) {
        char[] copyOf = Arrays.copyOf($this$copyOf, newSize);
        Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, newSize)");
        return copyOf;
    }

    private static final <T> T[] copyOf(T[] tArr, int newSize) {
        T[] tArr2 = (T[]) Arrays.copyOf(tArr, newSize);
        Intrinsics.checkExpressionValueIsNotNull(tArr2, "java.util.Arrays.copyOf(this, newSize)");
        return tArr2;
    }

    private static final <T> T[] copyOfRangeInline(T[] tArr, int fromIndex, int toIndex) {
        if (PlatformImplementationsKt.apiVersionIsAtLeast(1, 3, 0)) {
            return (T[]) ArraysKt.copyOfRange(tArr, fromIndex, toIndex);
        }
        if (toIndex > tArr.length) {
            throw new IndexOutOfBoundsException("toIndex: " + toIndex + ", size: " + tArr.length);
        }
        T[] tArr2 = (T[]) Arrays.copyOfRange(tArr, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(tArr2, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return tArr2;
    }

    private static final byte[] copyOfRangeInline(byte[] $this$copyOfRange, int fromIndex, int toIndex) {
        if (PlatformImplementationsKt.apiVersionIsAtLeast(1, 3, 0)) {
            return ArraysKt.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        }
        if (toIndex > $this$copyOfRange.length) {
            throw new IndexOutOfBoundsException("toIndex: " + toIndex + ", size: " + $this$copyOfRange.length);
        }
        byte[] copyOfRange = Arrays.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    private static final short[] copyOfRangeInline(short[] $this$copyOfRange, int fromIndex, int toIndex) {
        if (PlatformImplementationsKt.apiVersionIsAtLeast(1, 3, 0)) {
            return ArraysKt.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        }
        if (toIndex > $this$copyOfRange.length) {
            throw new IndexOutOfBoundsException("toIndex: " + toIndex + ", size: " + $this$copyOfRange.length);
        }
        short[] copyOfRange = Arrays.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    private static final int[] copyOfRangeInline(int[] $this$copyOfRange, int fromIndex, int toIndex) {
        if (PlatformImplementationsKt.apiVersionIsAtLeast(1, 3, 0)) {
            return ArraysKt.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        }
        if (toIndex > $this$copyOfRange.length) {
            throw new IndexOutOfBoundsException("toIndex: " + toIndex + ", size: " + $this$copyOfRange.length);
        }
        int[] copyOfRange = Arrays.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    private static final long[] copyOfRangeInline(long[] $this$copyOfRange, int fromIndex, int toIndex) {
        if (PlatformImplementationsKt.apiVersionIsAtLeast(1, 3, 0)) {
            return ArraysKt.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        }
        if (toIndex > $this$copyOfRange.length) {
            throw new IndexOutOfBoundsException("toIndex: " + toIndex + ", size: " + $this$copyOfRange.length);
        }
        long[] copyOfRange = Arrays.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    private static final float[] copyOfRangeInline(float[] $this$copyOfRange, int fromIndex, int toIndex) {
        if (PlatformImplementationsKt.apiVersionIsAtLeast(1, 3, 0)) {
            return ArraysKt.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        }
        if (toIndex > $this$copyOfRange.length) {
            throw new IndexOutOfBoundsException("toIndex: " + toIndex + ", size: " + $this$copyOfRange.length);
        }
        float[] copyOfRange = Arrays.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    private static final double[] copyOfRangeInline(double[] $this$copyOfRange, int fromIndex, int toIndex) {
        if (PlatformImplementationsKt.apiVersionIsAtLeast(1, 3, 0)) {
            return ArraysKt.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        }
        if (toIndex > $this$copyOfRange.length) {
            throw new IndexOutOfBoundsException("toIndex: " + toIndex + ", size: " + $this$copyOfRange.length);
        }
        double[] copyOfRange = Arrays.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    private static final boolean[] copyOfRangeInline(boolean[] $this$copyOfRange, int fromIndex, int toIndex) {
        if (PlatformImplementationsKt.apiVersionIsAtLeast(1, 3, 0)) {
            return ArraysKt.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        }
        if (toIndex > $this$copyOfRange.length) {
            throw new IndexOutOfBoundsException("toIndex: " + toIndex + ", size: " + $this$copyOfRange.length);
        }
        boolean[] copyOfRange = Arrays.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    private static final char[] copyOfRangeInline(char[] $this$copyOfRange, int fromIndex, int toIndex) {
        if (PlatformImplementationsKt.apiVersionIsAtLeast(1, 3, 0)) {
            return ArraysKt.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        }
        if (toIndex > $this$copyOfRange.length) {
            throw new IndexOutOfBoundsException("toIndex: " + toIndex + ", size: " + $this$copyOfRange.length);
        }
        char[] copyOfRange = Arrays.copyOfRange($this$copyOfRange, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    public static final <T> T[] copyOfRange(T[] copyOfRangeImpl, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(copyOfRangeImpl, "$this$copyOfRangeImpl");
        ArraysKt.copyOfRangeToIndexCheck(toIndex, copyOfRangeImpl.length);
        T[] tArr = (T[]) Arrays.copyOfRange(copyOfRangeImpl, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(tArr, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return tArr;
    }

    public static final byte[] copyOfRange(byte[] copyOfRangeImpl, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(copyOfRangeImpl, "$this$copyOfRangeImpl");
        ArraysKt.copyOfRangeToIndexCheck(toIndex, copyOfRangeImpl.length);
        byte[] copyOfRange = Arrays.copyOfRange(copyOfRangeImpl, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    public static final short[] copyOfRange(short[] copyOfRangeImpl, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(copyOfRangeImpl, "$this$copyOfRangeImpl");
        ArraysKt.copyOfRangeToIndexCheck(toIndex, copyOfRangeImpl.length);
        short[] copyOfRange = Arrays.copyOfRange(copyOfRangeImpl, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    public static final int[] copyOfRange(int[] copyOfRangeImpl, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(copyOfRangeImpl, "$this$copyOfRangeImpl");
        ArraysKt.copyOfRangeToIndexCheck(toIndex, copyOfRangeImpl.length);
        int[] copyOfRange = Arrays.copyOfRange(copyOfRangeImpl, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    public static final long[] copyOfRange(long[] copyOfRangeImpl, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(copyOfRangeImpl, "$this$copyOfRangeImpl");
        ArraysKt.copyOfRangeToIndexCheck(toIndex, copyOfRangeImpl.length);
        long[] copyOfRange = Arrays.copyOfRange(copyOfRangeImpl, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    public static final float[] copyOfRange(float[] copyOfRangeImpl, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(copyOfRangeImpl, "$this$copyOfRangeImpl");
        ArraysKt.copyOfRangeToIndexCheck(toIndex, copyOfRangeImpl.length);
        float[] copyOfRange = Arrays.copyOfRange(copyOfRangeImpl, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    public static final double[] copyOfRange(double[] copyOfRangeImpl, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(copyOfRangeImpl, "$this$copyOfRangeImpl");
        ArraysKt.copyOfRangeToIndexCheck(toIndex, copyOfRangeImpl.length);
        double[] copyOfRange = Arrays.copyOfRange(copyOfRangeImpl, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    public static final boolean[] copyOfRange(boolean[] copyOfRangeImpl, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(copyOfRangeImpl, "$this$copyOfRangeImpl");
        ArraysKt.copyOfRangeToIndexCheck(toIndex, copyOfRangeImpl.length);
        boolean[] copyOfRange = Arrays.copyOfRange(copyOfRangeImpl, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    public static final char[] copyOfRange(char[] copyOfRangeImpl, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(copyOfRangeImpl, "$this$copyOfRangeImpl");
        ArraysKt.copyOfRangeToIndexCheck(toIndex, copyOfRangeImpl.length);
        char[] copyOfRange = Arrays.copyOfRange(copyOfRangeImpl, fromIndex, toIndex);
        Intrinsics.checkExpressionValueIsNotNull(copyOfRange, "java.util.Arrays.copyOfR…this, fromIndex, toIndex)");
        return copyOfRange;
    }

    public static /* synthetic */ void fill$default(Object[] objArr, Object obj, int i, int i2, int i3, Object obj2) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = objArr.length;
        }
        ArraysKt.fill(objArr, obj, i, i2);
    }

    public static final <T> void fill(T[] fill, T t, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(fill, "$this$fill");
        Arrays.fill(fill, fromIndex, toIndex, t);
    }

    public static /* synthetic */ void fill$default(byte[] bArr, byte b, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = bArr.length;
        }
        ArraysKt.fill(bArr, b, i, i2);
    }

    public static final void fill(byte[] fill, byte element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(fill, "$this$fill");
        Arrays.fill(fill, fromIndex, toIndex, element);
    }

    public static /* synthetic */ void fill$default(short[] sArr, short s, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = sArr.length;
        }
        ArraysKt.fill(sArr, s, i, i2);
    }

    public static final void fill(short[] fill, short element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(fill, "$this$fill");
        Arrays.fill(fill, fromIndex, toIndex, element);
    }

    public static /* synthetic */ void fill$default(int[] iArr, int i, int i2, int i3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i2 = 0;
        }
        if ((i4 & 4) != 0) {
            i3 = iArr.length;
        }
        ArraysKt.fill(iArr, i, i2, i3);
    }

    public static final void fill(int[] fill, int element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(fill, "$this$fill");
        Arrays.fill(fill, fromIndex, toIndex, element);
    }

    public static /* synthetic */ void fill$default(long[] jArr, long j, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = jArr.length;
        }
        ArraysKt.fill(jArr, j, i, i2);
    }

    public static final void fill(long[] fill, long element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(fill, "$this$fill");
        Arrays.fill(fill, fromIndex, toIndex, element);
    }

    public static /* synthetic */ void fill$default(float[] fArr, float f, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = fArr.length;
        }
        ArraysKt.fill(fArr, f, i, i2);
    }

    public static final void fill(float[] fill, float element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(fill, "$this$fill");
        Arrays.fill(fill, fromIndex, toIndex, element);
    }

    public static /* synthetic */ void fill$default(double[] dArr, double d, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = dArr.length;
        }
        ArraysKt.fill(dArr, d, i, i2);
    }

    public static final void fill(double[] fill, double element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(fill, "$this$fill");
        Arrays.fill(fill, fromIndex, toIndex, element);
    }

    public static /* synthetic */ void fill$default(boolean[] zArr, boolean z, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = zArr.length;
        }
        ArraysKt.fill(zArr, z, i, i2);
    }

    public static final void fill(boolean[] fill, boolean element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(fill, "$this$fill");
        Arrays.fill(fill, fromIndex, toIndex, element);
    }

    public static /* synthetic */ void fill$default(char[] cArr, char c, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = cArr.length;
        }
        ArraysKt.fill(cArr, c, i, i2);
    }

    public static final void fill(char[] fill, char element, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(fill, "$this$fill");
        Arrays.fill(fill, fromIndex, toIndex, element);
    }

    public static final <T> T[] plus(T[] plus, T t) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        int index = plus.length;
        T[] result = (T[]) Arrays.copyOf(plus, index + 1);
        result[index] = t;
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final byte[] plus(byte[] plus, byte element) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        int index = plus.length;
        byte[] result = Arrays.copyOf(plus, index + 1);
        result[index] = element;
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final short[] plus(short[] plus, short element) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        int index = plus.length;
        short[] result = Arrays.copyOf(plus, index + 1);
        result[index] = element;
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final int[] plus(int[] plus, int element) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        int index = plus.length;
        int[] result = Arrays.copyOf(plus, index + 1);
        result[index] = element;
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final long[] plus(long[] plus, long element) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        int index = plus.length;
        long[] result = Arrays.copyOf(plus, index + 1);
        result[index] = element;
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final float[] plus(float[] plus, float element) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        int index = plus.length;
        float[] result = Arrays.copyOf(plus, index + 1);
        result[index] = element;
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final double[] plus(double[] plus, double element) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        int index = plus.length;
        double[] result = Arrays.copyOf(plus, index + 1);
        result[index] = element;
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final boolean[] plus(boolean[] plus, boolean element) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        int index = plus.length;
        boolean[] result = Arrays.copyOf(plus, index + 1);
        result[index] = element;
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final char[] plus(char[] plus, char element) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        int index = plus.length;
        char[] result = Arrays.copyOf(plus, index + 1);
        result[index] = element;
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final <T> T[] plus(T[] plus, Collection<? extends T> elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int index = plus.length;
        T[] result = (T[]) Arrays.copyOf(plus, elements.size() + index);
        for (Object element : elements) {
            result[index] = element;
            index++;
        }
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final byte[] plus(byte[] plus, Collection<Byte> elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int index = plus.length;
        byte[] result = Arrays.copyOf(plus, elements.size() + index);
        for (Byte b : elements) {
            byte element = b.byteValue();
            result[index] = element;
            index++;
        }
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final short[] plus(short[] plus, Collection<Short> elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int index = plus.length;
        short[] result = Arrays.copyOf(plus, elements.size() + index);
        for (Short sh : elements) {
            short element = sh.shortValue();
            result[index] = element;
            index++;
        }
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final int[] plus(int[] plus, Collection<Integer> elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int index = plus.length;
        int[] result = Arrays.copyOf(plus, elements.size() + index);
        for (Integer num : elements) {
            int element = num.intValue();
            result[index] = element;
            index++;
        }
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final long[] plus(long[] plus, Collection<Long> elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int index = plus.length;
        long[] result = Arrays.copyOf(plus, elements.size() + index);
        for (Long l : elements) {
            long element = l.longValue();
            result[index] = element;
            index++;
        }
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final float[] plus(float[] plus, Collection<Float> elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int index = plus.length;
        float[] result = Arrays.copyOf(plus, elements.size() + index);
        for (Float f : elements) {
            float element = f.floatValue();
            result[index] = element;
            index++;
        }
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final double[] plus(double[] plus, Collection<Double> elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int index = plus.length;
        double[] result = Arrays.copyOf(plus, elements.size() + index);
        for (Double d : elements) {
            double element = d.doubleValue();
            result[index] = element;
            index++;
        }
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final boolean[] plus(boolean[] plus, Collection<Boolean> elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int index = plus.length;
        boolean[] result = Arrays.copyOf(plus, elements.size() + index);
        for (Boolean bool : elements) {
            boolean element = bool.booleanValue();
            result[index] = element;
            index++;
        }
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final char[] plus(char[] plus, Collection<Character> elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int index = plus.length;
        char[] result = Arrays.copyOf(plus, elements.size() + index);
        for (Character ch : elements) {
            char element = ch.charValue();
            result[index] = element;
            index++;
        }
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final <T> T[] plus(T[] plus, T[] elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int thisSize = plus.length;
        int arraySize = elements.length;
        T[] result = (T[]) Arrays.copyOf(plus, thisSize + arraySize);
        System.arraycopy(elements, 0, result, thisSize, arraySize);
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final byte[] plus(byte[] plus, byte[] elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int thisSize = plus.length;
        int arraySize = elements.length;
        byte[] result = Arrays.copyOf(plus, thisSize + arraySize);
        System.arraycopy(elements, 0, result, thisSize, arraySize);
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final short[] plus(short[] plus, short[] elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int thisSize = plus.length;
        int arraySize = elements.length;
        short[] result = Arrays.copyOf(plus, thisSize + arraySize);
        System.arraycopy(elements, 0, result, thisSize, arraySize);
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final int[] plus(int[] plus, int[] elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int thisSize = plus.length;
        int arraySize = elements.length;
        int[] result = Arrays.copyOf(plus, thisSize + arraySize);
        System.arraycopy(elements, 0, result, thisSize, arraySize);
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final long[] plus(long[] plus, long[] elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int thisSize = plus.length;
        int arraySize = elements.length;
        long[] result = Arrays.copyOf(plus, thisSize + arraySize);
        System.arraycopy(elements, 0, result, thisSize, arraySize);
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final float[] plus(float[] plus, float[] elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int thisSize = plus.length;
        int arraySize = elements.length;
        float[] result = Arrays.copyOf(plus, thisSize + arraySize);
        System.arraycopy(elements, 0, result, thisSize, arraySize);
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final double[] plus(double[] plus, double[] elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int thisSize = plus.length;
        int arraySize = elements.length;
        double[] result = Arrays.copyOf(plus, thisSize + arraySize);
        System.arraycopy(elements, 0, result, thisSize, arraySize);
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final boolean[] plus(boolean[] plus, boolean[] elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int thisSize = plus.length;
        int arraySize = elements.length;
        boolean[] result = Arrays.copyOf(plus, thisSize + arraySize);
        System.arraycopy(elements, 0, result, thisSize, arraySize);
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    public static final char[] plus(char[] plus, char[] elements) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        int thisSize = plus.length;
        int arraySize = elements.length;
        char[] result = Arrays.copyOf(plus, thisSize + arraySize);
        System.arraycopy(elements, 0, result, thisSize, arraySize);
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        return result;
    }

    private static final <T> T[] plusElement(T[] tArr, T t) {
        return (T[]) ArraysKt.plus(tArr, t);
    }

    public static final void sort(int[] sort) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        if (sort.length > 1) {
            Arrays.sort(sort);
        }
    }

    public static final void sort(long[] sort) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        if (sort.length > 1) {
            Arrays.sort(sort);
        }
    }

    public static final void sort(byte[] sort) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        if (sort.length > 1) {
            Arrays.sort(sort);
        }
    }

    public static final void sort(short[] sort) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        if (sort.length > 1) {
            Arrays.sort(sort);
        }
    }

    public static final void sort(double[] sort) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        if (sort.length > 1) {
            Arrays.sort(sort);
        }
    }

    public static final void sort(float[] sort) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        if (sort.length > 1) {
            Arrays.sort(sort);
        }
    }

    public static final void sort(char[] sort) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        if (sort.length > 1) {
            Arrays.sort(sort);
        }
    }

    private static final <T extends Comparable<? super T>> void sort(T[] tArr) {
        if (tArr == null) {
            throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        }
        ArraysKt.sort((Object[]) tArr);
    }

    public static final <T> void sort(T[] sort) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        if (sort.length > 1) {
            Arrays.sort(sort);
        }
    }

    public static /* synthetic */ void sort$default(Object[] objArr, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = objArr.length;
        }
        ArraysKt.sort(objArr, i, i2);
    }

    public static final <T> void sort(T[] sort, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        Arrays.sort(sort, fromIndex, toIndex);
    }

    public static /* synthetic */ void sort$default(byte[] bArr, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = bArr.length;
        }
        ArraysKt.sort(bArr, i, i2);
    }

    public static final void sort(byte[] sort, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        Arrays.sort(sort, fromIndex, toIndex);
    }

    public static /* synthetic */ void sort$default(short[] sArr, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = sArr.length;
        }
        ArraysKt.sort(sArr, i, i2);
    }

    public static final void sort(short[] sort, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        Arrays.sort(sort, fromIndex, toIndex);
    }

    public static /* synthetic */ void sort$default(int[] iArr, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = iArr.length;
        }
        ArraysKt.sort(iArr, i, i2);
    }

    public static final void sort(int[] sort, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        Arrays.sort(sort, fromIndex, toIndex);
    }

    public static /* synthetic */ void sort$default(long[] jArr, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = jArr.length;
        }
        ArraysKt.sort(jArr, i, i2);
    }

    public static final void sort(long[] sort, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        Arrays.sort(sort, fromIndex, toIndex);
    }

    public static /* synthetic */ void sort$default(float[] fArr, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = fArr.length;
        }
        ArraysKt.sort(fArr, i, i2);
    }

    public static final void sort(float[] sort, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        Arrays.sort(sort, fromIndex, toIndex);
    }

    public static /* synthetic */ void sort$default(double[] dArr, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = dArr.length;
        }
        ArraysKt.sort(dArr, i, i2);
    }

    public static final void sort(double[] sort, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        Arrays.sort(sort, fromIndex, toIndex);
    }

    public static /* synthetic */ void sort$default(char[] cArr, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = cArr.length;
        }
        ArraysKt.sort(cArr, i, i2);
    }

    public static final void sort(char[] sort, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(sort, "$this$sort");
        Arrays.sort(sort, fromIndex, toIndex);
    }

    public static final <T> void sortWith(T[] sortWith, Comparator<? super T> comparator) {
        Intrinsics.checkParameterIsNotNull(sortWith, "$this$sortWith");
        Intrinsics.checkParameterIsNotNull(comparator, "comparator");
        if (sortWith.length > 1) {
            Arrays.sort(sortWith, comparator);
        }
    }

    public static /* synthetic */ void sortWith$default(Object[] objArr, Comparator comparator, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = objArr.length;
        }
        ArraysKt.sortWith(objArr, comparator, i, i2);
    }

    public static final <T> void sortWith(T[] sortWith, Comparator<? super T> comparator, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(sortWith, "$this$sortWith");
        Intrinsics.checkParameterIsNotNull(comparator, "comparator");
        Arrays.sort(sortWith, fromIndex, toIndex, comparator);
    }

    public static final Byte[] toTypedArray(byte[] toTypedArray) {
        Intrinsics.checkParameterIsNotNull(toTypedArray, "$this$toTypedArray");
        Byte[] result = new Byte[toTypedArray.length];
        int length = toTypedArray.length;
        for (int index = 0; index < length; index++) {
            result[index] = Byte.valueOf(toTypedArray[index]);
        }
        return result;
    }

    public static final Short[] toTypedArray(short[] toTypedArray) {
        Intrinsics.checkParameterIsNotNull(toTypedArray, "$this$toTypedArray");
        Short[] result = new Short[toTypedArray.length];
        int length = toTypedArray.length;
        for (int index = 0; index < length; index++) {
            result[index] = Short.valueOf(toTypedArray[index]);
        }
        return result;
    }

    public static final Integer[] toTypedArray(int[] toTypedArray) {
        Intrinsics.checkParameterIsNotNull(toTypedArray, "$this$toTypedArray");
        Integer[] result = new Integer[toTypedArray.length];
        int length = toTypedArray.length;
        for (int index = 0; index < length; index++) {
            result[index] = Integer.valueOf(toTypedArray[index]);
        }
        return result;
    }

    public static final Long[] toTypedArray(long[] toTypedArray) {
        Intrinsics.checkParameterIsNotNull(toTypedArray, "$this$toTypedArray");
        Long[] result = new Long[toTypedArray.length];
        int length = toTypedArray.length;
        for (int index = 0; index < length; index++) {
            result[index] = Long.valueOf(toTypedArray[index]);
        }
        return result;
    }

    public static final Float[] toTypedArray(float[] toTypedArray) {
        Intrinsics.checkParameterIsNotNull(toTypedArray, "$this$toTypedArray");
        Float[] result = new Float[toTypedArray.length];
        int length = toTypedArray.length;
        for (int index = 0; index < length; index++) {
            result[index] = Float.valueOf(toTypedArray[index]);
        }
        return result;
    }

    public static final Double[] toTypedArray(double[] toTypedArray) {
        Intrinsics.checkParameterIsNotNull(toTypedArray, "$this$toTypedArray");
        Double[] result = new Double[toTypedArray.length];
        int length = toTypedArray.length;
        for (int index = 0; index < length; index++) {
            result[index] = Double.valueOf(toTypedArray[index]);
        }
        return result;
    }

    public static final Boolean[] toTypedArray(boolean[] toTypedArray) {
        Intrinsics.checkParameterIsNotNull(toTypedArray, "$this$toTypedArray");
        Boolean[] result = new Boolean[toTypedArray.length];
        int length = toTypedArray.length;
        for (int index = 0; index < length; index++) {
            result[index] = Boolean.valueOf(toTypedArray[index]);
        }
        return result;
    }

    public static final Character[] toTypedArray(char[] toTypedArray) {
        Intrinsics.checkParameterIsNotNull(toTypedArray, "$this$toTypedArray");
        Character[] result = new Character[toTypedArray.length];
        int length = toTypedArray.length;
        for (int index = 0; index < length; index++) {
            result[index] = Character.valueOf(toTypedArray[index]);
        }
        return result;
    }

    public static final <T extends Comparable<? super T>> SortedSet<T> toSortedSet(T[] toSortedSet) {
        Intrinsics.checkParameterIsNotNull(toSortedSet, "$this$toSortedSet");
        return (SortedSet) ArraysKt.toCollection(toSortedSet, new TreeSet());
    }

    public static final SortedSet<Byte> toSortedSet(byte[] toSortedSet) {
        Intrinsics.checkParameterIsNotNull(toSortedSet, "$this$toSortedSet");
        return (SortedSet) ArraysKt.toCollection(toSortedSet, new TreeSet());
    }

    public static final SortedSet<Short> toSortedSet(short[] toSortedSet) {
        Intrinsics.checkParameterIsNotNull(toSortedSet, "$this$toSortedSet");
        return (SortedSet) ArraysKt.toCollection(toSortedSet, new TreeSet());
    }

    public static final SortedSet<Integer> toSortedSet(int[] toSortedSet) {
        Intrinsics.checkParameterIsNotNull(toSortedSet, "$this$toSortedSet");
        return (SortedSet) ArraysKt.toCollection(toSortedSet, new TreeSet());
    }

    public static final SortedSet<Long> toSortedSet(long[] toSortedSet) {
        Intrinsics.checkParameterIsNotNull(toSortedSet, "$this$toSortedSet");
        return (SortedSet) ArraysKt.toCollection(toSortedSet, new TreeSet());
    }

    public static final SortedSet<Float> toSortedSet(float[] toSortedSet) {
        Intrinsics.checkParameterIsNotNull(toSortedSet, "$this$toSortedSet");
        return (SortedSet) ArraysKt.toCollection(toSortedSet, new TreeSet());
    }

    public static final SortedSet<Double> toSortedSet(double[] toSortedSet) {
        Intrinsics.checkParameterIsNotNull(toSortedSet, "$this$toSortedSet");
        return (SortedSet) ArraysKt.toCollection(toSortedSet, new TreeSet());
    }

    public static final SortedSet<Boolean> toSortedSet(boolean[] toSortedSet) {
        Intrinsics.checkParameterIsNotNull(toSortedSet, "$this$toSortedSet");
        return (SortedSet) ArraysKt.toCollection(toSortedSet, new TreeSet());
    }

    public static final SortedSet<Character> toSortedSet(char[] toSortedSet) {
        Intrinsics.checkParameterIsNotNull(toSortedSet, "$this$toSortedSet");
        return (SortedSet) ArraysKt.toCollection(toSortedSet, new TreeSet());
    }

    public static final <T> SortedSet<T> toSortedSet(T[] toSortedSet, Comparator<? super T> comparator) {
        Intrinsics.checkParameterIsNotNull(toSortedSet, "$this$toSortedSet");
        Intrinsics.checkParameterIsNotNull(comparator, "comparator");
        return (SortedSet) ArraysKt.toCollection(toSortedSet, new TreeSet(comparator));
    }
}