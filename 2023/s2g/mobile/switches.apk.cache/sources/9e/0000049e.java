package com.badlogic.gdx.utils;

import java.util.Iterator;

/* loaded from: classes.dex */
public interface Predicate<T> {
    boolean evaluate(T t);

    /* loaded from: classes.dex */
    public static class PredicateIterator<T> implements Iterator<T> {
        public boolean end;
        public Iterator<T> iterator;
        public T next;
        public boolean peeked;
        public Predicate<T> predicate;

        public PredicateIterator(Iterable<T> iterable, Predicate<T> predicate) {
            this(iterable.iterator(), predicate);
        }

        public PredicateIterator(Iterator<T> iterator, Predicate<T> predicate) {
            this.end = false;
            this.peeked = false;
            this.next = null;
            set(iterator, predicate);
        }

        public void set(Iterable<T> iterable, Predicate<T> predicate) {
            set(iterable.iterator(), predicate);
        }

        public void set(Iterator<T> iterator, Predicate<T> predicate) {
            this.iterator = iterator;
            this.predicate = predicate;
            this.peeked = false;
            this.end = false;
            this.next = null;
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            if (this.end) {
                return false;
            }
            if (this.next != null) {
                return true;
            }
            this.peeked = true;
            while (this.iterator.hasNext()) {
                T n = this.iterator.next();
                if (this.predicate.evaluate(n)) {
                    this.next = n;
                    return true;
                }
            }
            this.end = true;
            return false;
        }

        @Override // java.util.Iterator
        public T next() {
            if (this.next != null || hasNext()) {
                T result = this.next;
                this.next = null;
                this.peeked = false;
                return result;
            }
            return null;
        }

        @Override // java.util.Iterator
        public void remove() {
            if (this.peeked) {
                throw new GdxRuntimeException("Cannot remove between a call to hasNext() and next().");
            }
            this.iterator.remove();
        }
    }

    /* loaded from: classes.dex */
    public static class PredicateIterable<T> implements Iterable<T> {
        public Iterable<T> iterable;
        public PredicateIterator<T> iterator = null;
        public Predicate<T> predicate;

        public PredicateIterable(Iterable<T> iterable, Predicate<T> predicate) {
            set(iterable, predicate);
        }

        public void set(Iterable<T> iterable, Predicate<T> predicate) {
            this.iterable = iterable;
            this.predicate = predicate;
        }

        @Override // java.lang.Iterable
        public Iterator<T> iterator() {
            if (Collections.allocateIterators) {
                return new PredicateIterator(this.iterable.iterator(), this.predicate);
            }
            PredicateIterator<T> predicateIterator = this.iterator;
            if (predicateIterator == null) {
                this.iterator = new PredicateIterator<>(this.iterable.iterator(), this.predicate);
            } else {
                predicateIterator.set(this.iterable.iterator(), this.predicate);
            }
            return this.iterator;
        }
    }
}