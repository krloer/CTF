package kotlin.collections;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.functions.Function4;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;

/* compiled from: Grouping.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000@\n\u0000\n\u0002\u0010$\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010%\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\n\u001a\u009b\u0001\u0010\u0000\u001a\u000e\u0012\u0004\u0012\u0002H\u0002\u0012\u0004\u0012\u0002H\u00030\u0001\"\u0004\b\u0000\u0010\u0004\"\u0004\b\u0001\u0010\u0002\"\u0004\b\u0002\u0010\u0003*\u000e\u0012\u0004\u0012\u0002H\u0004\u0012\u0004\u0012\u0002H\u00020\u00052b\u0010\u0006\u001a^\u0012\u0013\u0012\u0011H\u0002¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0015\u0012\u0013\u0018\u0001H\u0003¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u000b\u0012\u0013\u0012\u0011H\u0004¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\f\u0012\u0013\u0012\u00110\r¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u000e\u0012\u0004\u0012\u0002H\u00030\u0007H\u0087\b\u001a´\u0001\u0010\u000f\u001a\u0002H\u0010\"\u0004\b\u0000\u0010\u0004\"\u0004\b\u0001\u0010\u0002\"\u0004\b\u0002\u0010\u0003\"\u0016\b\u0003\u0010\u0010*\u0010\u0012\u0006\b\u0000\u0012\u0002H\u0002\u0012\u0004\u0012\u0002H\u00030\u0011*\u000e\u0012\u0004\u0012\u0002H\u0004\u0012\u0004\u0012\u0002H\u00020\u00052\u0006\u0010\u0012\u001a\u0002H\u00102b\u0010\u0006\u001a^\u0012\u0013\u0012\u0011H\u0002¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0015\u0012\u0013\u0018\u0001H\u0003¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u000b\u0012\u0013\u0012\u0011H\u0004¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\f\u0012\u0013\u0012\u00110\r¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u000e\u0012\u0004\u0012\u0002H\u00030\u0007H\u0087\b¢\u0006\u0002\u0010\u0013\u001aI\u0010\u0014\u001a\u0002H\u0010\"\u0004\b\u0000\u0010\u0004\"\u0004\b\u0001\u0010\u0002\"\u0016\b\u0002\u0010\u0010*\u0010\u0012\u0006\b\u0000\u0012\u0002H\u0002\u0012\u0004\u0012\u00020\u00150\u0011*\u000e\u0012\u0004\u0012\u0002H\u0004\u0012\u0004\u0012\u0002H\u00020\u00052\u0006\u0010\u0012\u001a\u0002H\u0010H\u0007¢\u0006\u0002\u0010\u0016\u001a¼\u0001\u0010\u0017\u001a\u000e\u0012\u0004\u0012\u0002H\u0002\u0012\u0004\u0012\u0002H\u00030\u0001\"\u0004\b\u0000\u0010\u0004\"\u0004\b\u0001\u0010\u0002\"\u0004\b\u0002\u0010\u0003*\u000e\u0012\u0004\u0012\u0002H\u0004\u0012\u0004\u0012\u0002H\u00020\u000526\u0010\u0018\u001a2\u0012\u0013\u0012\u0011H\u0002¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0013\u0012\u0011H\u0004¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\f\u0012\u0004\u0012\u0002H\u00030\u00192K\u0010\u0006\u001aG\u0012\u0013\u0012\u0011H\u0002¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0013\u0012\u0011H\u0003¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u000b\u0012\u0013\u0012\u0011H\u0004¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\f\u0012\u0004\u0012\u0002H\u00030\u001aH\u0087\b\u001a|\u0010\u0017\u001a\u000e\u0012\u0004\u0012\u0002H\u0002\u0012\u0004\u0012\u0002H\u00030\u0001\"\u0004\b\u0000\u0010\u0004\"\u0004\b\u0001\u0010\u0002\"\u0004\b\u0002\u0010\u0003*\u000e\u0012\u0004\u0012\u0002H\u0004\u0012\u0004\u0012\u0002H\u00020\u00052\u0006\u0010\u001b\u001a\u0002H\u000326\u0010\u0006\u001a2\u0012\u0013\u0012\u0011H\u0003¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u000b\u0012\u0013\u0012\u0011H\u0004¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\f\u0012\u0004\u0012\u0002H\u00030\u0019H\u0087\b¢\u0006\u0002\u0010\u001c\u001aÕ\u0001\u0010\u001d\u001a\u0002H\u0010\"\u0004\b\u0000\u0010\u0004\"\u0004\b\u0001\u0010\u0002\"\u0004\b\u0002\u0010\u0003\"\u0016\b\u0003\u0010\u0010*\u0010\u0012\u0006\b\u0000\u0012\u0002H\u0002\u0012\u0004\u0012\u0002H\u00030\u0011*\u000e\u0012\u0004\u0012\u0002H\u0004\u0012\u0004\u0012\u0002H\u00020\u00052\u0006\u0010\u0012\u001a\u0002H\u001026\u0010\u0018\u001a2\u0012\u0013\u0012\u0011H\u0002¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0013\u0012\u0011H\u0004¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\f\u0012\u0004\u0012\u0002H\u00030\u00192K\u0010\u0006\u001aG\u0012\u0013\u0012\u0011H\u0002¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0013\u0012\u0011H\u0003¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u000b\u0012\u0013\u0012\u0011H\u0004¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\f\u0012\u0004\u0012\u0002H\u00030\u001aH\u0087\b¢\u0006\u0002\u0010\u001e\u001a\u0090\u0001\u0010\u001d\u001a\u0002H\u0010\"\u0004\b\u0000\u0010\u0004\"\u0004\b\u0001\u0010\u0002\"\u0004\b\u0002\u0010\u0003\"\u0016\b\u0003\u0010\u0010*\u0010\u0012\u0006\b\u0000\u0012\u0002H\u0002\u0012\u0004\u0012\u0002H\u00030\u0011*\u000e\u0012\u0004\u0012\u0002H\u0004\u0012\u0004\u0012\u0002H\u00020\u00052\u0006\u0010\u0012\u001a\u0002H\u00102\u0006\u0010\u001b\u001a\u0002H\u000326\u0010\u0006\u001a2\u0012\u0013\u0012\u0011H\u0003¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u000b\u0012\u0013\u0012\u0011H\u0004¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\f\u0012\u0004\u0012\u0002H\u00030\u0019H\u0087\b¢\u0006\u0002\u0010\u001f\u001a\u0088\u0001\u0010 \u001a\u000e\u0012\u0004\u0012\u0002H\u0002\u0012\u0004\u0012\u0002H!0\u0001\"\u0004\b\u0000\u0010!\"\b\b\u0001\u0010\u0004*\u0002H!\"\u0004\b\u0002\u0010\u0002*\u000e\u0012\u0004\u0012\u0002H\u0004\u0012\u0004\u0012\u0002H\u00020\u00052K\u0010\u0006\u001aG\u0012\u0013\u0012\u0011H\u0002¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0013\u0012\u0011H!¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u000b\u0012\u0013\u0012\u0011H\u0004¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\f\u0012\u0004\u0012\u0002H!0\u001aH\u0087\b\u001a¡\u0001\u0010\"\u001a\u0002H\u0010\"\u0004\b\u0000\u0010!\"\b\b\u0001\u0010\u0004*\u0002H!\"\u0004\b\u0002\u0010\u0002\"\u0016\b\u0003\u0010\u0010*\u0010\u0012\u0006\b\u0000\u0012\u0002H\u0002\u0012\u0004\u0012\u0002H!0\u0011*\u000e\u0012\u0004\u0012\u0002H\u0004\u0012\u0004\u0012\u0002H\u00020\u00052\u0006\u0010\u0012\u001a\u0002H\u00102K\u0010\u0006\u001aG\u0012\u0013\u0012\u0011H\u0002¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0013\u0012\u0011H!¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u000b\u0012\u0013\u0012\u0011H\u0004¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\f\u0012\u0004\u0012\u0002H!0\u001aH\u0087\b¢\u0006\u0002\u0010#¨\u0006$"}, d2 = {"aggregate", BuildConfig.FLAVOR, "K", "R", "T", "Lkotlin/collections/Grouping;", "operation", "Lkotlin/Function4;", "Lkotlin/ParameterName;", "name", "key", "accumulator", "element", BuildConfig.FLAVOR, "first", "aggregateTo", "M", BuildConfig.FLAVOR, "destination", "(Lkotlin/collections/Grouping;Ljava/util/Map;Lkotlin/jvm/functions/Function4;)Ljava/util/Map;", "eachCountTo", BuildConfig.FLAVOR, "(Lkotlin/collections/Grouping;Ljava/util/Map;)Ljava/util/Map;", "fold", "initialValueSelector", "Lkotlin/Function2;", "Lkotlin/Function3;", "initialValue", "(Lkotlin/collections/Grouping;Ljava/lang/Object;Lkotlin/jvm/functions/Function2;)Ljava/util/Map;", "foldTo", "(Lkotlin/collections/Grouping;Ljava/util/Map;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function3;)Ljava/util/Map;", "(Lkotlin/collections/Grouping;Ljava/util/Map;Ljava/lang/Object;Lkotlin/jvm/functions/Function2;)Ljava/util/Map;", "reduce", "S", "reduceTo", "(Lkotlin/collections/Grouping;Ljava/util/Map;Lkotlin/jvm/functions/Function3;)Ljava/util/Map;", "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/collections/GroupingKt")
/* loaded from: classes.dex */
class GroupingKt__GroupingKt extends GroupingKt__GroupingJVMKt {
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r5v1, types: [java.lang.Object] */
    public static final <T, K, R> Map<K, R> aggregate(Grouping<T, ? extends K> aggregate, Function4<? super K, ? super R, ? super T, ? super Boolean, ? extends R> operation) {
        Intrinsics.checkParameterIsNotNull(aggregate, "$this$aggregate");
        Intrinsics.checkParameterIsNotNull(operation, "operation");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Iterator<T> sourceIterator = aggregate.sourceIterator();
        while (sourceIterator.hasNext()) {
            ?? next = sourceIterator.next();
            Object key$iv = (K) aggregate.keyOf(next);
            Object accumulator$iv = (Object) linkedHashMap.get(key$iv);
            linkedHashMap.put(key$iv, operation.invoke(key$iv, accumulator$iv, next, Boolean.valueOf(accumulator$iv == null && !linkedHashMap.containsKey(key$iv))));
        }
        return linkedHashMap;
    }

    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Object] */
    public static final <T, K, R, M extends Map<? super K, R>> M aggregateTo(Grouping<T, ? extends K> aggregateTo, M destination, Function4<? super K, ? super R, ? super T, ? super Boolean, ? extends R> operation) {
        Intrinsics.checkParameterIsNotNull(aggregateTo, "$this$aggregateTo");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        Intrinsics.checkParameterIsNotNull(operation, "operation");
        Iterator<T> sourceIterator = aggregateTo.sourceIterator();
        while (sourceIterator.hasNext()) {
            ?? next = sourceIterator.next();
            Object key = aggregateTo.keyOf(next);
            Object accumulator = (Object) destination.get(key);
            destination.put(key, operation.invoke(key, accumulator, next, Boolean.valueOf(accumulator == null && !destination.containsKey(key))));
        }
        return destination;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r6v1, types: [java.util.Map, java.util.Map<K, R>] */
    public static final <T, K, R> Map<K, R> fold(Grouping<T, ? extends K> fold, Function2<? super K, ? super T, ? extends R> function2, Function3<? super K, ? super R, ? super T, ? extends R> operation) {
        int $i$f$fold;
        Object e;
        Object obj;
        Function2<? super K, ? super T, ? extends R> initialValueSelector = function2;
        int $i$f$fold2 = 0;
        Intrinsics.checkParameterIsNotNull(fold, "$this$fold");
        Intrinsics.checkParameterIsNotNull(initialValueSelector, "initialValueSelector");
        Intrinsics.checkParameterIsNotNull(operation, "operation");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Iterator<T> sourceIterator = fold.sourceIterator();
        while (sourceIterator.hasNext()) {
            T next = sourceIterator.next();
            Object key$iv$iv = (K) fold.keyOf(next);
            Object accumulator$iv$iv = linkedHashMap.get(key$iv$iv);
            boolean first = accumulator$iv$iv == null && !linkedHashMap.containsKey(key$iv$iv);
            if (first) {
                $i$f$fold = $i$f$fold2;
                e = next;
                obj = initialValueSelector.invoke(key$iv$iv, e);
            } else {
                $i$f$fold = $i$f$fold2;
                e = next;
                obj = accumulator$iv$iv;
            }
            linkedHashMap.put(key$iv$iv, operation.invoke(key$iv$iv, obj, e));
            initialValueSelector = function2;
            $i$f$fold2 = $i$f$fold;
        }
        return linkedHashMap;
    }

    public static final <T, K, R, M extends Map<? super K, R>> M foldTo(Grouping<T, ? extends K> foldTo, M destination, Function2<? super K, ? super T, ? extends R> function2, Function3<? super K, ? super R, ? super T, ? extends R> operation) {
        Function2<? super K, ? super T, ? extends R> initialValueSelector = function2;
        Intrinsics.checkParameterIsNotNull(foldTo, "$this$foldTo");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        Intrinsics.checkParameterIsNotNull(initialValueSelector, "initialValueSelector");
        Intrinsics.checkParameterIsNotNull(operation, "operation");
        Iterator<T> sourceIterator = foldTo.sourceIterator();
        while (sourceIterator.hasNext()) {
            T next = sourceIterator.next();
            Object key$iv = foldTo.keyOf(next);
            Object accumulator$iv = destination.get(key$iv);
            boolean first = accumulator$iv == null && !destination.containsKey(key$iv);
            destination.put(key$iv, operation.invoke(key$iv, first ? initialValueSelector.invoke(key$iv, next) : accumulator$iv, next));
            initialValueSelector = function2;
        }
        return destination;
    }

    public static final <T, K, R> Map<K, R> fold(Grouping<T, ? extends K> fold, R r, Function2<? super R, ? super T, ? extends R> operation) {
        int $i$f$fold = 0;
        Intrinsics.checkParameterIsNotNull(fold, "$this$fold");
        Intrinsics.checkParameterIsNotNull(operation, "operation");
        Map destination$iv$iv = new LinkedHashMap();
        Iterator<T> sourceIterator = fold.sourceIterator();
        while (sourceIterator.hasNext()) {
            T next = sourceIterator.next();
            K keyOf = fold.keyOf(next);
            Object accumulator$iv$iv = destination$iv$iv.get(keyOf);
            boolean first = accumulator$iv$iv == null && !destination$iv$iv.containsKey(keyOf);
            int $i$f$fold2 = $i$f$fold;
            destination$iv$iv.put(keyOf, operation.invoke(first ? r : accumulator$iv$iv, next));
            $i$f$fold = $i$f$fold2;
        }
        return destination$iv$iv;
    }

    public static final <T, K, R, M extends Map<? super K, R>> M foldTo(Grouping<T, ? extends K> foldTo, M destination, R r, Function2<? super R, ? super T, ? extends R> operation) {
        Intrinsics.checkParameterIsNotNull(foldTo, "$this$foldTo");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        Intrinsics.checkParameterIsNotNull(operation, "operation");
        Iterator<T> sourceIterator = foldTo.sourceIterator();
        while (sourceIterator.hasNext()) {
            T next = sourceIterator.next();
            K keyOf = foldTo.keyOf(next);
            Object accumulator$iv = destination.get(keyOf);
            boolean first = accumulator$iv == null && !destination.containsKey(keyOf);
            destination.put(keyOf, operation.invoke(first ? r : accumulator$iv, next));
        }
        return destination;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final <S, T extends S, K> Map<K, S> reduce(Grouping<T, ? extends K> reduce, Function3<? super K, ? super S, ? super T, ? extends S> operation) {
        Intrinsics.checkParameterIsNotNull(reduce, "$this$reduce");
        Intrinsics.checkParameterIsNotNull(operation, "operation");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Iterator<T> sourceIterator = reduce.sourceIterator();
        while (sourceIterator.hasNext()) {
            T next = sourceIterator.next();
            Object key$iv$iv = (K) reduce.keyOf(next);
            Object accumulator$iv$iv = (Object) linkedHashMap.get(key$iv$iv);
            boolean first = accumulator$iv$iv == null && !linkedHashMap.containsKey(key$iv$iv);
            Object e = next;
            if (!first) {
                e = operation.invoke(key$iv$iv, accumulator$iv$iv, e);
            }
            linkedHashMap.put(key$iv$iv, e);
        }
        return linkedHashMap;
    }

    public static final <S, T extends S, K, M extends Map<? super K, S>> M reduceTo(Grouping<T, ? extends K> reduceTo, M destination, Function3<? super K, ? super S, ? super T, ? extends S> operation) {
        Intrinsics.checkParameterIsNotNull(reduceTo, "$this$reduceTo");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        Intrinsics.checkParameterIsNotNull(operation, "operation");
        Iterator<T> sourceIterator = reduceTo.sourceIterator();
        while (sourceIterator.hasNext()) {
            T next = sourceIterator.next();
            Object key$iv = reduceTo.keyOf(next);
            Object accumulator$iv = (Object) destination.get(key$iv);
            boolean first = accumulator$iv == null && !destination.containsKey(key$iv);
            Object e = next;
            if (!first) {
                e = operation.invoke(key$iv, accumulator$iv, e);
            }
            destination.put(key$iv, e);
        }
        return destination;
    }

    public static final <T, K, M extends Map<? super K, Integer>> M eachCountTo(Grouping<T, ? extends K> eachCountTo, M destination) {
        Intrinsics.checkParameterIsNotNull(eachCountTo, "$this$eachCountTo");
        Intrinsics.checkParameterIsNotNull(destination, "destination");
        Iterator<T> sourceIterator = eachCountTo.sourceIterator();
        while (sourceIterator.hasNext()) {
            K keyOf = eachCountTo.keyOf(sourceIterator.next());
            Object accumulator$iv$iv = destination.get(keyOf);
            boolean first$iv = accumulator$iv$iv == null && !destination.containsKey(keyOf);
            int acc = ((Number) (first$iv ? 0 : accumulator$iv$iv)).intValue();
            destination.put(keyOf, Integer.valueOf(acc + 1));
        }
        return destination;
    }
}