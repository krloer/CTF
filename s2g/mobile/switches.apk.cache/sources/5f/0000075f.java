package kotlin.collections;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.RandomAccess;
import kotlin.Deprecated;
import kotlin.DeprecationLevel;
import kotlin.Metadata;
import kotlin.ReplaceWith;
import kotlin.TypeCastException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.TypeIntrinsics;
import kotlin.random.Random;
import kotlin.sequences.Sequence;
import kotlin.sequences.SequencesKt;
import s2g.project.game.BuildConfig;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: MutableCollections.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000^\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u001f\n\u0000\n\u0002\u0010\u0011\n\u0000\n\u0002\u0010\u001c\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u001d\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010!\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u001e\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0000\u001a-\u0010\u0000\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\u000e\u0010\u0004\u001a\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0005¢\u0006\u0002\u0010\u0006\u001a&\u0010\u0000\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0007\u001a&\u0010\u0000\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\b\u001a9\u0010\t\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\n2\u0012\u0010\u000b\u001a\u000e\u0012\u0004\u0012\u0002H\u0002\u0012\u0004\u0012\u00020\u00010\f2\u0006\u0010\r\u001a\u00020\u0001H\u0002¢\u0006\u0002\b\u000e\u001a9\u0010\t\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u000f2\u0012\u0010\u000b\u001a\u000e\u0012\u0004\u0012\u0002H\u0002\u0012\u0004\u0012\u00020\u00010\f2\u0006\u0010\r\u001a\u00020\u0001H\u0002¢\u0006\u0002\b\u000e\u001a(\u0010\u0010\u001a\u00020\u0011\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\u0006\u0010\u0012\u001a\u0002H\u0002H\u0087\n¢\u0006\u0002\u0010\u0013\u001a.\u0010\u0010\u001a\u00020\u0011\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0005H\u0087\n¢\u0006\u0002\u0010\u0014\u001a)\u0010\u0010\u001a\u00020\u0011\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0007H\u0087\n\u001a)\u0010\u0010\u001a\u00020\u0011\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\bH\u0087\n\u001a(\u0010\u0015\u001a\u00020\u0011\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\u0006\u0010\u0012\u001a\u0002H\u0002H\u0087\n¢\u0006\u0002\u0010\u0013\u001a.\u0010\u0015\u001a\u00020\u0011\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0005H\u0087\n¢\u0006\u0002\u0010\u0014\u001a)\u0010\u0015\u001a\u00020\u0011\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0007H\u0087\n\u001a)\u0010\u0015\u001a\u00020\u0011\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\bH\u0087\n\u001a-\u0010\u0016\u001a\u00020\u0001\"\t\b\u0000\u0010\u0002¢\u0006\u0002\b\u0017*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\u0006\u0010\u0012\u001a\u0002H\u0002H\u0087\b¢\u0006\u0002\u0010\u0018\u001a&\u0010\u0016\u001a\u0002H\u0002\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u000f2\u0006\u0010\u0019\u001a\u00020\u001aH\u0087\b¢\u0006\u0002\u0010\u001b\u001a-\u0010\u001c\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\u000e\u0010\u0004\u001a\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0005¢\u0006\u0002\u0010\u0006\u001a&\u0010\u001c\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0007\u001a&\u0010\u001c\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\b\u001a.\u0010\u001c\u001a\u00020\u0001\"\t\b\u0000\u0010\u0002¢\u0006\u0002\b\u0017*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\u001dH\u0087\b\u001a*\u0010\u001c\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\n2\u0012\u0010\u000b\u001a\u000e\u0012\u0004\u0012\u0002H\u0002\u0012\u0004\u0012\u00020\u00010\f\u001a*\u0010\u001c\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u000f2\u0012\u0010\u000b\u001a\u000e\u0012\u0004\u0012\u0002H\u0002\u0012\u0004\u0012\u00020\u00010\f\u001a-\u0010\u001e\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\u000e\u0010\u0004\u001a\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0005¢\u0006\u0002\u0010\u0006\u001a&\u0010\u001e\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0007\u001a&\u0010\u001e\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0000\u0012\u0002H\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\b\u001a.\u0010\u001e\u001a\u00020\u0001\"\t\b\u0000\u0010\u0002¢\u0006\u0002\b\u0017*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\u001dH\u0087\b\u001a*\u0010\u001e\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\n2\u0012\u0010\u000b\u001a\u000e\u0012\u0004\u0012\u0002H\u0002\u0012\u0004\u0012\u00020\u00010\f\u001a*\u0010\u001e\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u000f2\u0012\u0010\u000b\u001a\u000e\u0012\u0004\u0012\u0002H\u0002\u0012\u0004\u0012\u00020\u00010\f\u001a\u0015\u0010\u001f\u001a\u00020\u0001*\u0006\u0012\u0002\b\u00030\u0003H\u0002¢\u0006\u0002\b \u001a \u0010!\u001a\u00020\u0011\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u000f2\u0006\u0010\"\u001a\u00020#H\u0007\u001a&\u0010$\u001a\b\u0012\u0004\u0012\u0002H\u00020%\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u00072\u0006\u0010\"\u001a\u00020#H\u0007¨\u0006&"}, d2 = {"addAll", BuildConfig.FLAVOR, "T", BuildConfig.FLAVOR, "elements", BuildConfig.FLAVOR, "(Ljava/util/Collection;[Ljava/lang/Object;)Z", BuildConfig.FLAVOR, "Lkotlin/sequences/Sequence;", "filterInPlace", BuildConfig.FLAVOR, "predicate", "Lkotlin/Function1;", "predicateResultToRemove", "filterInPlace$CollectionsKt__MutableCollectionsKt", BuildConfig.FLAVOR, "minusAssign", BuildConfig.FLAVOR, "element", "(Ljava/util/Collection;Ljava/lang/Object;)V", "(Ljava/util/Collection;[Ljava/lang/Object;)V", "plusAssign", "remove", "Lkotlin/internal/OnlyInputTypes;", "(Ljava/util/Collection;Ljava/lang/Object;)Z", "index", BuildConfig.FLAVOR, "(Ljava/util/List;I)Ljava/lang/Object;", "removeAll", BuildConfig.FLAVOR, "retainAll", "retainNothing", "retainNothing$CollectionsKt__MutableCollectionsKt", "shuffle", "random", "Lkotlin/random/Random;", "shuffled", BuildConfig.FLAVOR, "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/collections/CollectionsKt")
/* loaded from: classes.dex */
public class CollectionsKt__MutableCollectionsKt extends CollectionsKt__MutableCollectionsJVMKt {
    private static final <T> boolean remove(Collection<? extends T> collection, T t) {
        if (collection != null) {
            return TypeIntrinsics.asMutableCollection(collection).remove(t);
        }
        throw new TypeCastException("null cannot be cast to non-null type kotlin.collections.MutableCollection<T>");
    }

    private static final <T> boolean removeAll(Collection<? extends T> collection, Collection<? extends T> collection2) {
        if (collection != null) {
            return TypeIntrinsics.asMutableCollection(collection).removeAll(collection2);
        }
        throw new TypeCastException("null cannot be cast to non-null type kotlin.collections.MutableCollection<T>");
    }

    private static final <T> boolean retainAll(Collection<? extends T> collection, Collection<? extends T> collection2) {
        if (collection != null) {
            return TypeIntrinsics.asMutableCollection(collection).retainAll(collection2);
        }
        throw new TypeCastException("null cannot be cast to non-null type kotlin.collections.MutableCollection<T>");
    }

    @Deprecated(level = DeprecationLevel.ERROR, message = "Use removeAt(index) instead.", replaceWith = @ReplaceWith(expression = "removeAt(index)", imports = {}))
    private static final <T> T remove(List<T> list, int index) {
        return list.remove(index);
    }

    /* JADX WARN: Multi-variable type inference failed */
    private static final <T> void plusAssign(Collection<? super T> plusAssign, T t) {
        Intrinsics.checkParameterIsNotNull(plusAssign, "$this$plusAssign");
        plusAssign.add(t);
    }

    private static final <T> void plusAssign(Collection<? super T> plusAssign, Iterable<? extends T> iterable) {
        Intrinsics.checkParameterIsNotNull(plusAssign, "$this$plusAssign");
        CollectionsKt.addAll(plusAssign, iterable);
    }

    private static final <T> void plusAssign(Collection<? super T> plusAssign, T[] tArr) {
        Intrinsics.checkParameterIsNotNull(plusAssign, "$this$plusAssign");
        CollectionsKt.addAll(plusAssign, tArr);
    }

    private static final <T> void plusAssign(Collection<? super T> plusAssign, Sequence<? extends T> sequence) {
        Intrinsics.checkParameterIsNotNull(plusAssign, "$this$plusAssign");
        CollectionsKt.addAll(plusAssign, sequence);
    }

    private static final <T> void minusAssign(Collection<? super T> minusAssign, T t) {
        Intrinsics.checkParameterIsNotNull(minusAssign, "$this$minusAssign");
        minusAssign.remove(t);
    }

    private static final <T> void minusAssign(Collection<? super T> minusAssign, Iterable<? extends T> iterable) {
        Intrinsics.checkParameterIsNotNull(minusAssign, "$this$minusAssign");
        CollectionsKt.removeAll(minusAssign, iterable);
    }

    private static final <T> void minusAssign(Collection<? super T> minusAssign, T[] tArr) {
        Intrinsics.checkParameterIsNotNull(minusAssign, "$this$minusAssign");
        CollectionsKt.removeAll(minusAssign, tArr);
    }

    private static final <T> void minusAssign(Collection<? super T> minusAssign, Sequence<? extends T> sequence) {
        Intrinsics.checkParameterIsNotNull(minusAssign, "$this$minusAssign");
        CollectionsKt.removeAll(minusAssign, sequence);
    }

    public static final <T> boolean addAll(Collection<? super T> addAll, Iterable<? extends T> elements) {
        Intrinsics.checkParameterIsNotNull(addAll, "$this$addAll");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        if (elements instanceof Collection) {
            return addAll.addAll((Collection) elements);
        }
        boolean result = false;
        Iterator<? extends T> it = elements.iterator();
        while (it.hasNext()) {
            Object item = (T) it.next();
            if (addAll.add(item)) {
                result = true;
            }
        }
        return result;
    }

    public static final <T> boolean addAll(Collection<? super T> addAll, Sequence<? extends T> elements) {
        Intrinsics.checkParameterIsNotNull(addAll, "$this$addAll");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        boolean result = false;
        Iterator<? extends T> it = elements.iterator();
        while (it.hasNext()) {
            Object item = (T) it.next();
            if (addAll.add(item)) {
                result = true;
            }
        }
        return result;
    }

    public static final <T> boolean addAll(Collection<? super T> addAll, T[] elements) {
        Intrinsics.checkParameterIsNotNull(addAll, "$this$addAll");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        return addAll.addAll(ArraysKt.asList(elements));
    }

    public static final <T> boolean removeAll(Iterable<? extends T> removeAll, Function1<? super T, Boolean> predicate) {
        Intrinsics.checkParameterIsNotNull(removeAll, "$this$removeAll");
        Intrinsics.checkParameterIsNotNull(predicate, "predicate");
        return filterInPlace$CollectionsKt__MutableCollectionsKt((Iterable) removeAll, (Function1) predicate, true);
    }

    public static final <T> boolean retainAll(Iterable<? extends T> retainAll, Function1<? super T, Boolean> predicate) {
        Intrinsics.checkParameterIsNotNull(retainAll, "$this$retainAll");
        Intrinsics.checkParameterIsNotNull(predicate, "predicate");
        return filterInPlace$CollectionsKt__MutableCollectionsKt((Iterable) retainAll, (Function1) predicate, false);
    }

    private static final <T> boolean filterInPlace$CollectionsKt__MutableCollectionsKt(Iterable<? extends T> iterable, Function1<? super T, Boolean> function1, boolean predicateResultToRemove) {
        boolean result = false;
        Iterator $this$with = iterable.iterator();
        while ($this$with.hasNext()) {
            if (function1.invoke((T) $this$with.next()).booleanValue() == predicateResultToRemove) {
                $this$with.remove();
                result = true;
            }
        }
        return result;
    }

    public static final <T> boolean removeAll(List<T> removeAll, Function1<? super T, Boolean> predicate) {
        Intrinsics.checkParameterIsNotNull(removeAll, "$this$removeAll");
        Intrinsics.checkParameterIsNotNull(predicate, "predicate");
        return filterInPlace$CollectionsKt__MutableCollectionsKt((List) removeAll, (Function1) predicate, true);
    }

    public static final <T> boolean retainAll(List<T> retainAll, Function1<? super T, Boolean> predicate) {
        Intrinsics.checkParameterIsNotNull(retainAll, "$this$retainAll");
        Intrinsics.checkParameterIsNotNull(predicate, "predicate");
        return filterInPlace$CollectionsKt__MutableCollectionsKt((List) retainAll, (Function1) predicate, false);
    }

    private static final <T> boolean filterInPlace$CollectionsKt__MutableCollectionsKt(List<T> list, Function1<? super T, Boolean> function1, boolean predicateResultToRemove) {
        if (!(list instanceof RandomAccess)) {
            if (list != null) {
                return filterInPlace$CollectionsKt__MutableCollectionsKt(TypeIntrinsics.asMutableIterable(list), function1, predicateResultToRemove);
            }
            throw new TypeCastException("null cannot be cast to non-null type kotlin.collections.MutableIterable<T>");
        }
        int writeIndex = 0;
        int lastIndex = CollectionsKt.getLastIndex(list);
        if (lastIndex >= 0) {
            int readIndex = 0;
            while (true) {
                T t = list.get(readIndex);
                if (function1.invoke(t).booleanValue() != predicateResultToRemove) {
                    if (writeIndex != readIndex) {
                        list.set(writeIndex, t);
                    }
                    writeIndex++;
                }
                if (readIndex == lastIndex) {
                    break;
                }
                readIndex++;
            }
        }
        if (writeIndex >= list.size()) {
            return false;
        }
        int removeIndex = CollectionsKt.getLastIndex(list);
        if (removeIndex < writeIndex) {
            return true;
        }
        while (true) {
            list.remove(removeIndex);
            if (removeIndex == writeIndex) {
                return true;
            }
            removeIndex--;
        }
    }

    public static final <T> boolean removeAll(Collection<? super T> removeAll, Iterable<? extends T> elements) {
        Intrinsics.checkParameterIsNotNull(removeAll, "$this$removeAll");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        return TypeIntrinsics.asMutableCollection(removeAll).removeAll(CollectionsKt.convertToSetForSetOperationWith(elements, removeAll));
    }

    public static final <T> boolean removeAll(Collection<? super T> removeAll, Sequence<? extends T> elements) {
        Intrinsics.checkParameterIsNotNull(removeAll, "$this$removeAll");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        HashSet set = SequencesKt.toHashSet(elements);
        return (set.isEmpty() ^ true) && removeAll.removeAll(set);
    }

    public static final <T> boolean removeAll(Collection<? super T> removeAll, T[] elements) {
        Intrinsics.checkParameterIsNotNull(removeAll, "$this$removeAll");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        return ((elements.length == 0) ^ true) && removeAll.removeAll(ArraysKt.toHashSet(elements));
    }

    public static final <T> boolean retainAll(Collection<? super T> retainAll, Iterable<? extends T> elements) {
        Intrinsics.checkParameterIsNotNull(retainAll, "$this$retainAll");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        return TypeIntrinsics.asMutableCollection(retainAll).retainAll(CollectionsKt.convertToSetForSetOperationWith(elements, retainAll));
    }

    public static final <T> boolean retainAll(Collection<? super T> retainAll, T[] elements) {
        Intrinsics.checkParameterIsNotNull(retainAll, "$this$retainAll");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        if (!(elements.length == 0)) {
            return retainAll.retainAll(ArraysKt.toHashSet(elements));
        }
        return retainNothing$CollectionsKt__MutableCollectionsKt(retainAll);
    }

    public static final <T> boolean retainAll(Collection<? super T> retainAll, Sequence<? extends T> elements) {
        Intrinsics.checkParameterIsNotNull(retainAll, "$this$retainAll");
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        HashSet set = SequencesKt.toHashSet(elements);
        if (!set.isEmpty()) {
            return retainAll.retainAll(set);
        }
        return retainNothing$CollectionsKt__MutableCollectionsKt(retainAll);
    }

    private static final boolean retainNothing$CollectionsKt__MutableCollectionsKt(Collection<?> collection) {
        boolean result = !collection.isEmpty();
        collection.clear();
        return result;
    }

    public static final <T> void shuffle(List<T> shuffle, Random random) {
        Intrinsics.checkParameterIsNotNull(shuffle, "$this$shuffle");
        Intrinsics.checkParameterIsNotNull(random, "random");
        for (int i = CollectionsKt.getLastIndex(shuffle); i >= 1; i--) {
            int j = random.nextInt(i + 1);
            T t = shuffle.get(i);
            shuffle.set(i, shuffle.get(j));
            shuffle.set(j, t);
        }
    }

    public static final <T> List<T> shuffled(Iterable<? extends T> shuffled, Random random) {
        Intrinsics.checkParameterIsNotNull(shuffled, "$this$shuffled");
        Intrinsics.checkParameterIsNotNull(random, "random");
        List $this$apply = CollectionsKt.toMutableList(shuffled);
        CollectionsKt.shuffle($this$apply, random);
        return $this$apply;
    }
}