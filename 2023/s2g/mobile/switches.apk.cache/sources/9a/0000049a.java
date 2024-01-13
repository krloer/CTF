package com.badlogic.gdx.utils;

/* loaded from: classes.dex */
public class PooledLinkedList<T> {
    private Item<T> curr;
    private Item<T> head;
    private Item<T> iter;
    private final Pool<Item<T>> pool;
    private int size = 0;
    private Item<T> tail;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class Item<T> {
        public Item<T> next;
        public T payload;
        public Item<T> prev;

        Item() {
        }
    }

    public PooledLinkedList(int maxPoolSize) {
        this.pool = new Pool<Item<T>>(16, maxPoolSize) { // from class: com.badlogic.gdx.utils.PooledLinkedList.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.badlogic.gdx.utils.Pool
            public Item<T> newObject() {
                return new Item<>();
            }
        };
    }

    public void add(T object) {
        Item<T> item = this.pool.obtain();
        item.payload = object;
        item.next = null;
        item.prev = null;
        if (this.head == null) {
            this.head = item;
            this.tail = item;
            this.size++;
            return;
        }
        Item<T> item2 = this.tail;
        item.prev = item2;
        item2.next = item;
        this.tail = item;
        this.size++;
    }

    public void addFirst(T object) {
        Item<T> item = this.pool.obtain();
        item.payload = object;
        Item<T> item2 = this.head;
        item.next = item2;
        item.prev = null;
        if (item2 != null) {
            item2.prev = item;
        } else {
            this.tail = item;
        }
        this.head = item;
        this.size++;
    }

    public int size() {
        return this.size;
    }

    public void iter() {
        this.iter = this.head;
    }

    public void iterReverse() {
        this.iter = this.tail;
    }

    public T next() {
        Item<T> item = this.iter;
        if (item == null) {
            return null;
        }
        T payload = item.payload;
        Item<T> item2 = this.iter;
        this.curr = item2;
        this.iter = item2.next;
        return payload;
    }

    public T previous() {
        Item<T> item = this.iter;
        if (item == null) {
            return null;
        }
        T payload = item.payload;
        Item<T> item2 = this.iter;
        this.curr = item2;
        this.iter = item2.prev;
        return payload;
    }

    public void remove() {
        Item<T> item = this.curr;
        if (item == null) {
            return;
        }
        this.size--;
        Item<T> c = this.curr;
        Item<T> n = item.next;
        Item<T> p = this.curr.prev;
        this.pool.free(this.curr);
        this.curr = null;
        if (this.size == 0) {
            this.head = null;
            this.tail = null;
        } else if (c == this.head) {
            n.prev = null;
            this.head = n;
        } else if (c == this.tail) {
            p.next = null;
            this.tail = p;
        } else {
            p.next = n;
            n.prev = p;
        }
    }

    public T removeLast() {
        Item<T> item = this.tail;
        if (item == null) {
            return null;
        }
        T payload = item.payload;
        this.size--;
        Item<T> p = this.tail.prev;
        this.pool.free(this.tail);
        if (this.size == 0) {
            this.head = null;
            this.tail = null;
        } else {
            this.tail = p;
            this.tail.next = null;
        }
        return payload;
    }

    public void clear() {
        iter();
        while (next() != null) {
            remove();
        }
    }
}