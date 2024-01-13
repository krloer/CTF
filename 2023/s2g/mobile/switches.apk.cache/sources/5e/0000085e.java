package kotlin.jvm;

import java.lang.annotation.Annotation;
import kotlin.Deprecated;
import kotlin.DeprecationLevel;
import kotlin.Metadata;
import kotlin.ReplaceWith;
import kotlin.TypeCastException;
import kotlin.jvm.internal.ClassBasedDeclarationContainer;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.reflect.KClass;
import s2g.project.game.BuildConfig;

/* compiled from: JvmClassMapping.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000,\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u001b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0000\n\u0002\b\u000b\n\u0002\u0010\u000b\n\u0002\u0010\u0011\n\u0002\b\u0002\u001a\u001f\u0010\u0018\u001a\u00020\u0019\"\n\b\u0000\u0010\u0002\u0018\u0001*\u00020\r*\u0006\u0012\u0002\b\u00030\u001a¢\u0006\u0002\u0010\u001b\"'\u0010\u0000\u001a\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0001\"\b\b\u0000\u0010\u0002*\u00020\u0003*\u0002H\u00028F¢\u0006\u0006\u001a\u0004\b\u0004\u0010\u0005\"-\u0010\u0006\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0007\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u00018G¢\u0006\f\u0012\u0004\b\b\u0010\t\u001a\u0004\b\n\u0010\u000b\"&\u0010\f\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0007\"\b\b\u0000\u0010\u0002*\u00020\r*\u0002H\u00028Æ\u0002¢\u0006\u0006\u001a\u0004\b\n\u0010\u000e\";\u0010\f\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u0002H\u00020\u00010\u0007\"\b\b\u0000\u0010\u0002*\u00020\r*\b\u0012\u0004\u0012\u0002H\u00020\u00018Ç\u0002X\u0087\u0004¢\u0006\f\u0012\u0004\b\u000f\u0010\t\u001a\u0004\b\u0010\u0010\u000b\"+\u0010\u0011\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0007\"\b\b\u0000\u0010\u0002*\u00020\r*\b\u0012\u0004\u0012\u0002H\u00020\u00018F¢\u0006\u0006\u001a\u0004\b\u0012\u0010\u000b\"-\u0010\u0013\u001a\n\u0012\u0004\u0012\u0002H\u0002\u0018\u00010\u0007\"\b\b\u0000\u0010\u0002*\u00020\r*\b\u0012\u0004\u0012\u0002H\u00020\u00018F¢\u0006\u0006\u001a\u0004\b\u0014\u0010\u000b\"+\u0010\u0015\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001\"\b\b\u0000\u0010\u0002*\u00020\r*\b\u0012\u0004\u0012\u0002H\u00020\u00078G¢\u0006\u0006\u001a\u0004\b\u0016\u0010\u0017¨\u0006\u001c"}, d2 = {"annotationClass", "Lkotlin/reflect/KClass;", "T", BuildConfig.FLAVOR, "getAnnotationClass", "(Ljava/lang/annotation/Annotation;)Lkotlin/reflect/KClass;", "java", "Ljava/lang/Class;", "java$annotations", "(Lkotlin/reflect/KClass;)V", "getJavaClass", "(Lkotlin/reflect/KClass;)Ljava/lang/Class;", "javaClass", BuildConfig.FLAVOR, "(Ljava/lang/Object;)Ljava/lang/Class;", "javaClass$annotations", "getRuntimeClassOfKClassInstance", "javaObjectType", "getJavaObjectType", "javaPrimitiveType", "getJavaPrimitiveType", "kotlin", "getKotlinClass", "(Ljava/lang/Class;)Lkotlin/reflect/KClass;", "isArrayOf", BuildConfig.FLAVOR, BuildConfig.FLAVOR, "([Ljava/lang/Object;)Z", "kotlin-stdlib"}, k = 2, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class JvmClassMappingKt {
    public static /* synthetic */ void java$annotations(KClass kClass) {
    }

    @Deprecated(level = DeprecationLevel.ERROR, message = "Use 'java' property to get Java class corresponding to this Kotlin class or cast this instance to Any if you really want to get the runtime Java class of this implementation of KClass.", replaceWith = @ReplaceWith(expression = "(this as Any).javaClass", imports = {}))
    public static /* synthetic */ void javaClass$annotations(KClass kClass) {
    }

    public static final <T> Class<T> getJavaClass(KClass<T> java) {
        Intrinsics.checkParameterIsNotNull(java, "$this$java");
        Class<T> cls = (Class<T>) ((ClassBasedDeclarationContainer) java).getJClass();
        if (cls != null) {
            return cls;
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.Class<T>");
    }

    public static final <T> Class<T> getJavaPrimitiveType(KClass<T> javaPrimitiveType) {
        Intrinsics.checkParameterIsNotNull(javaPrimitiveType, "$this$javaPrimitiveType");
        Class thisJClass = (Class<T>) ((ClassBasedDeclarationContainer) javaPrimitiveType).getJClass();
        if (thisJClass.isPrimitive()) {
            if (thisJClass != null) {
                return thisJClass;
            }
            throw new TypeCastException("null cannot be cast to non-null type java.lang.Class<T>");
        }
        String name = thisJClass.getName();
        if (name != null) {
            switch (name.hashCode()) {
                case -2056817302:
                    if (name.equals("java.lang.Integer")) {
                        return Integer.TYPE;
                    }
                    break;
                case -527879800:
                    if (name.equals("java.lang.Float")) {
                        return Float.TYPE;
                    }
                    break;
                case -515992664:
                    if (name.equals("java.lang.Short")) {
                        return Short.TYPE;
                    }
                    break;
                case 155276373:
                    if (name.equals("java.lang.Character")) {
                        return Character.TYPE;
                    }
                    break;
                case 344809556:
                    if (name.equals("java.lang.Boolean")) {
                        return Boolean.TYPE;
                    }
                    break;
                case 398507100:
                    if (name.equals("java.lang.Byte")) {
                        return Byte.TYPE;
                    }
                    break;
                case 398795216:
                    if (name.equals("java.lang.Long")) {
                        return Long.TYPE;
                    }
                    break;
                case 399092968:
                    if (name.equals("java.lang.Void")) {
                        return Void.TYPE;
                    }
                    break;
                case 761287205:
                    if (name.equals("java.lang.Double")) {
                        return Double.TYPE;
                    }
                    break;
            }
        }
        return null;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0093 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0094  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static final <T> java.lang.Class<T> getJavaObjectType(kotlin.reflect.KClass<T> r4) {
        /*
            java.lang.String r0 = "$this$javaObjectType"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r4, r0)
            r0 = r4
            kotlin.jvm.internal.ClassBasedDeclarationContainer r0 = (kotlin.jvm.internal.ClassBasedDeclarationContainer) r0
            java.lang.Class r0 = r0.getJClass()
            boolean r1 = r0.isPrimitive()
            java.lang.String r2 = "null cannot be cast to non-null type java.lang.Class<T>"
            if (r1 != 0) goto L1d
            if (r0 == 0) goto L17
            return r0
        L17:
            kotlin.TypeCastException r1 = new kotlin.TypeCastException
            r1.<init>(r2)
            throw r1
        L1d:
            java.lang.String r1 = r0.getName()
            if (r1 != 0) goto L24
            goto L2b
        L24:
            int r3 = r1.hashCode()
            switch(r3) {
                case -1325958191: goto L85;
                case 104431: goto L7a;
                case 3039496: goto L6f;
                case 3052374: goto L64;
                case 3327612: goto L59;
                case 3625364: goto L4e;
                case 64711720: goto L43;
                case 97526364: goto L38;
                case 109413500: goto L2d;
                default: goto L2b;
            }
        L2b:
            goto L90
        L2d:
            java.lang.String r3 = "short"
            boolean r1 = r1.equals(r3)
            if (r1 == 0) goto L2b
            java.lang.Class<java.lang.Short> r1 = java.lang.Short.class
            goto L91
        L38:
            java.lang.String r3 = "float"
            boolean r1 = r1.equals(r3)
            if (r1 == 0) goto L2b
            java.lang.Class<java.lang.Float> r1 = java.lang.Float.class
            goto L91
        L43:
            java.lang.String r3 = "boolean"
            boolean r1 = r1.equals(r3)
            if (r1 == 0) goto L2b
            java.lang.Class<java.lang.Boolean> r1 = java.lang.Boolean.class
            goto L91
        L4e:
            java.lang.String r3 = "void"
            boolean r1 = r1.equals(r3)
            if (r1 == 0) goto L2b
            java.lang.Class<java.lang.Void> r1 = java.lang.Void.class
            goto L91
        L59:
            java.lang.String r3 = "long"
            boolean r1 = r1.equals(r3)
            if (r1 == 0) goto L2b
            java.lang.Class<java.lang.Long> r1 = java.lang.Long.class
            goto L91
        L64:
            java.lang.String r3 = "char"
            boolean r1 = r1.equals(r3)
            if (r1 == 0) goto L2b
            java.lang.Class<java.lang.Character> r1 = java.lang.Character.class
            goto L91
        L6f:
            java.lang.String r3 = "byte"
            boolean r1 = r1.equals(r3)
            if (r1 == 0) goto L2b
            java.lang.Class<java.lang.Byte> r1 = java.lang.Byte.class
            goto L91
        L7a:
            java.lang.String r3 = "int"
            boolean r1 = r1.equals(r3)
            if (r1 == 0) goto L2b
            java.lang.Class<java.lang.Integer> r1 = java.lang.Integer.class
            goto L91
        L85:
            java.lang.String r3 = "double"
            boolean r1 = r1.equals(r3)
            if (r1 == 0) goto L2b
            java.lang.Class<java.lang.Double> r1 = java.lang.Double.class
            goto L91
        L90:
            r1 = r0
        L91:
            if (r1 == 0) goto L94
            return r1
        L94:
            kotlin.TypeCastException r1 = new kotlin.TypeCastException
            r1.<init>(r2)
            goto L9b
        L9a:
            throw r1
        L9b:
            goto L9a
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.jvm.JvmClassMappingKt.getJavaObjectType(kotlin.reflect.KClass):java.lang.Class");
    }

    public static final <T> KClass<T> getKotlinClass(Class<T> kotlin2) {
        Intrinsics.checkParameterIsNotNull(kotlin2, "$this$kotlin");
        return Reflection.getOrCreateKotlinClass(kotlin2);
    }

    public static final <T> Class<T> getJavaClass(T javaClass) {
        Intrinsics.checkParameterIsNotNull(javaClass, "$this$javaClass");
        Class<T> cls = (Class<T>) javaClass.getClass();
        if (cls != null) {
            return cls;
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.Class<T>");
    }

    public static final <T> Class<KClass<T>> getRuntimeClassOfKClassInstance(KClass<T> javaClass) {
        Intrinsics.checkParameterIsNotNull(javaClass, "$this$javaClass");
        Class<KClass<T>> cls = (Class<KClass<T>>) javaClass.getClass();
        if (cls != null) {
            return cls;
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.Class<kotlin.reflect.KClass<T>>");
    }

    private static final <T> boolean isArrayOf(Object[] $this$isArrayOf) {
        Intrinsics.reifiedOperationMarker(4, "T");
        return Object.class.isAssignableFrom($this$isArrayOf.getClass().getComponentType());
    }

    public static final <T extends Annotation> KClass<? extends T> getAnnotationClass(T annotationClass) {
        Intrinsics.checkParameterIsNotNull(annotationClass, "$this$annotationClass");
        Class<? extends Annotation> annotationType = annotationClass.annotationType();
        Intrinsics.checkExpressionValueIsNotNull(annotationType, "(this as java.lang.annot…otation).annotationType()");
        KClass<? extends T> kotlinClass = getKotlinClass(annotationType);
        if (kotlinClass != null) {
            return kotlinClass;
        }
        throw new TypeCastException("null cannot be cast to non-null type kotlin.reflect.KClass<out T>");
    }
}