package com.badlogic.gdx.utils;

/* loaded from: classes.dex */
public class SortedIntList<E> implements Iterable<Node<E>> {
    Node<E> first;
    private transient SortedIntList<E>.Iterator iterator;
    private NodePool<E> nodePool = new NodePool<>();
    int size = 0;

    /* loaded from: classes.dex */
    public static class Node<E> {
        public int index;
        protected Node<E> n;
        protected Node<E> p;
        public E value;
    }

    public E insert(int index, E value) {
        if (this.first != null) {
            Node<E> c = this.first;
            while (c.n != null && c.n.index <= index) {
                c = c.n;
            }
            if (index > c.index) {
                c.n = this.nodePool.obtain(c, c.n, value, index);
                if (c.n.n != null) {
                    c.n.n.p = c.n;
                }
                this.size++;
            } else if (index < c.index) {
                Node<E> newFirst = this.nodePool.obtain(null, this.first, value, index);
                this.first.p = newFirst;
                this.first = newFirst;
                this.size++;
            } else {
                c.value = value;
            }
        } else {
            this.first = this.nodePool.obtain(null, null, value, index);
            this.size++;
        }
        return null;
    }

    public E get(int index) {
        if (this.first == null) {
            return null;
        }
        Node<E> c = this.first;
        while (c.n != null && c.index < index) {
            c = c.n;
        }
        if (c.index != index) {
            return null;
        }
        E match = c.value;
        return match;
    }

    public void clear() {
        while (true) {
            Node<E> node = this.first;
            if (node != null) {
                this.nodePool.free(node);
                this.first = this.first.n;
            } else {
                this.size = 0;
                return;
            }
        }
    }

    public int size() {
        return this.size;
    }

    public boolean notEmpty() {
        return this.size > 0;
    }

    public boolean isEmpty() {
        return this.size == 0;
    }

    @Override // java.lang.Iterable
    public java.util.Iterator<Node<E>> iterator() {
        if (Collections.allocateIterators) {
            return new Iterator();
        }
        if (this.iterator == null) {
            this.iterator = new Iterator();
        }
        return this.iterator.reset();
    }

    /* loaded from: classes.dex */
    public class Iterator implements java.util.Iterator<Node<E>> {
        private Node<E> position;
        private Node<E> previousPosition;

        public Iterator() {
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            return this.position != null;
        }

        @Override // java.util.Iterator
        public Node<E> next() {
            Node<E> node = this.position;
            this.previousPosition = node;
            this.position = node.n;
            return this.previousPosition;
        }

        @Override // java.util.Iterator
        public void remove() {
            Node<E> node = this.previousPosition;
            if (node != null) {
                if (node == SortedIntList.this.first) {
                    SortedIntList.this.first = this.position;
                } else {
                    Node<E> node2 = this.previousPosition.p;
                    Node<E> node3 = this.position;
                    node2.n = node3;
                    if (node3 != null) {
                        node3.p = this.previousPosition.p;
                    }
                }
                SortedIntList sortedIntList = SortedIntList.this;
                sortedIntList.size--;
            }
        }

        public SortedIntList<E>.Iterator reset() {
            this.position = SortedIntList.this.first;
            this.previousPosition = null;
            return this;
        }
    }

    /* loaded from: classes.dex */
    static class NodePool<E> extends Pool<Node<E>> {
        NodePool() {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.badlogic.gdx.utils.Pool
        public Node<E> newObject() {
            return new Node<>();
        }

        public Node<E> obtain(Node<E> p, Node<E> n, E value, int index) {
            Node<E> newNode = (Node) super.obtain();
            newNode.p = p;
            newNode.n = n;
            newNode.value = value;
            newNode.index = index;
            return newNode;
        }
    }
}