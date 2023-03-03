package s2g.project.game.ecs;

import com.badlogic.ashley.core.ComponentMapper;
import com.badlogic.ashley.core.Entity;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import kotlin.Metadata;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.functions.Function4;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import s2g.project.game.BuildConfig;
import s2g.project.game.ecs.component.PositionComponent;

/* compiled from: Utils.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000>\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a\u0016\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0003\u001a&\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\f\u001a&\u0010\r\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u000e\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\f\u001aM\u0010\u000f\u001a\u0004\u0018\u0001H\u0010\"\u0004\b\u0000\u0010\u0011\"\u0004\b\u0001\u0010\u0012\"\u0004\b\u0002\u0010\u00102\b\u0010\u0013\u001a\u0004\u0018\u0001H\u00112\b\u0010\u0014\u001a\u0004\u0018\u0001H\u00122\u0018\u0010\u0015\u001a\u0014\u0012\u0004\u0012\u0002H\u0011\u0012\u0004\u0012\u0002H\u0012\u0012\u0004\u0012\u0002H\u00100\u0016¢\u0006\u0002\u0010\u0017\u001ac\u0010\u000f\u001a\u0004\u0018\u0001H\u0018\"\u0004\b\u0000\u0010\u0011\"\u0004\b\u0001\u0010\u0012\"\u0004\b\u0002\u0010\u0010\"\u0004\b\u0003\u0010\u00182\b\u0010\u0013\u001a\u0004\u0018\u0001H\u00112\b\u0010\u0014\u001a\u0004\u0018\u0001H\u00122\b\u0010\u0019\u001a\u0004\u0018\u0001H\u00102\u001e\u0010\u0015\u001a\u001a\u0012\u0004\u0012\u0002H\u0011\u0012\u0004\u0012\u0002H\u0012\u0012\u0004\u0012\u0002H\u0010\u0012\u0004\u0012\u0002H\u00180\u001a¢\u0006\u0002\u0010\u001b\u001ay\u0010\u000f\u001a\u0004\u0018\u0001H\u001c\"\u0004\b\u0000\u0010\u0011\"\u0004\b\u0001\u0010\u0012\"\u0004\b\u0002\u0010\u0010\"\u0004\b\u0003\u0010\u0018\"\u0004\b\u0004\u0010\u001c2\b\u0010\u0013\u001a\u0004\u0018\u0001H\u00112\b\u0010\u0014\u001a\u0004\u0018\u0001H\u00122\b\u0010\u0019\u001a\u0004\u0018\u0001H\u00102\b\u0010\u001d\u001a\u0004\u0018\u0001H\u00182$\u0010\u0015\u001a \u0012\u0004\u0012\u0002H\u0011\u0012\u0004\u0012\u0002H\u0012\u0012\u0004\u0012\u0002H\u0010\u0012\u0004\u0012\u0002H\u0018\u0012\u0004\u0012\u0002H\u001c0\u001e¢\u0006\u0002\u0010\u001f¨\u0006 "}, d2 = {"compareEntityByPosition", BuildConfig.FLAVOR, "e1", "Lcom/badlogic/ashley/core/Entity;", "e2", "decrypt", BuildConfig.FLAVOR, "algorithm", "cipherText", "key", "Ljavax/crypto/spec/SecretKeySpec;", "iv", "Ljavax/crypto/spec/IvParameterSpec;", "encrypt", "inputText", "notNull", "T3", "T1", "T2", "t1", "t2", "body", "Lkotlin/Function2;", "(Ljava/lang/Object;Ljava/lang/Object;Lkotlin/jvm/functions/Function2;)Ljava/lang/Object;", "T4", "t3", "Lkotlin/Function3;", "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/jvm/functions/Function3;)Ljava/lang/Object;", "T5", "t4", "Lkotlin/Function4;", "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/jvm/functions/Function4;)Ljava/lang/Object;", "core"}, k = 2, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class UtilsKt {
    public static final String encrypt(String algorithm, String inputText, SecretKeySpec key, IvParameterSpec iv) {
        Intrinsics.checkParameterIsNotNull(algorithm, "algorithm");
        Intrinsics.checkParameterIsNotNull(inputText, "inputText");
        Intrinsics.checkParameterIsNotNull(key, "key");
        Intrinsics.checkParameterIsNotNull(iv, "iv");
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(1, key, iv);
        byte[] bytes = inputText.getBytes(Charsets.UTF_8);
        Intrinsics.checkExpressionValueIsNotNull(bytes, "(this as java.lang.String).getBytes(charset)");
        byte[] cipherText = cipher.doFinal(bytes);
        String encodeToString = Base64.getEncoder().encodeToString(cipherText);
        Intrinsics.checkExpressionValueIsNotNull(encodeToString, "Base64.getEncoder().encodeToString(cipherText)");
        return encodeToString;
    }

    public static final String decrypt(String algorithm, String cipherText, SecretKeySpec key, IvParameterSpec iv) {
        Intrinsics.checkParameterIsNotNull(algorithm, "algorithm");
        Intrinsics.checkParameterIsNotNull(cipherText, "cipherText");
        Intrinsics.checkParameterIsNotNull(key, "key");
        Intrinsics.checkParameterIsNotNull(iv, "iv");
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(2, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        Intrinsics.checkExpressionValueIsNotNull(plainText, "plainText");
        return new String(plainText, Charsets.UTF_8);
    }

    public static final int compareEntityByPosition(Entity e1, Entity e2) {
        Intrinsics.checkParameterIsNotNull(e1, "e1");
        Intrinsics.checkParameterIsNotNull(e2, "e2");
        ComponentMapper mapper = ComponentMapper.getFor(PositionComponent.class);
        PositionComponent positionComponent = (PositionComponent) mapper.get(e1);
        float z1 = positionComponent != null ? positionComponent.getZ() : 0.0f;
        PositionComponent positionComponent2 = (PositionComponent) mapper.get(e2);
        float z2 = positionComponent2 != null ? positionComponent2.getZ() : 0.0f;
        return Float.compare(z1, z2);
    }

    public static final <T1, T2, T3> T3 notNull(T1 t1, T2 t2, Function2<? super T1, ? super T2, ? extends T3> body) {
        Intrinsics.checkParameterIsNotNull(body, "body");
        if (t1 != null && t2 != null) {
            return body.invoke(t1, t2);
        }
        return null;
    }

    public static final <T1, T2, T3, T4> T4 notNull(T1 t1, T2 t2, T3 t3, Function3<? super T1, ? super T2, ? super T3, ? extends T4> body) {
        Intrinsics.checkParameterIsNotNull(body, "body");
        if (t1 != null && t2 != null && t3 != null) {
            return body.invoke(t1, t2, t3);
        }
        return null;
    }

    public static final <T1, T2, T3, T4, T5> T5 notNull(T1 t1, T2 t2, T3 t3, T4 t4, Function4<? super T1, ? super T2, ? super T3, ? super T4, ? extends T5> body) {
        Intrinsics.checkParameterIsNotNull(body, "body");
        if (t1 != null && t2 != null && t3 != null && t4 != null) {
            return body.invoke(t1, t2, t3, t4);
        }
        return null;
    }
}