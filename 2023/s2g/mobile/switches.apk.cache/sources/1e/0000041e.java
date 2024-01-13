package com.badlogic.gdx.scenes.scene2d.utils;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.OrderedSet;
import com.badlogic.gdx.utils.Pools;
import java.util.Iterator;

/* loaded from: classes.dex */
public class Selection<T> implements Disableable, Iterable<T> {
    private Actor actor;
    boolean isDisabled;
    T lastSelected;
    boolean multiple;
    boolean required;
    private boolean toggle;
    final OrderedSet<T> selected = new OrderedSet<>();
    private final OrderedSet<T> old = new OrderedSet<>();
    private boolean programmaticChangeEvents = true;

    public void setActor(Actor actor) {
        this.actor = actor;
    }

    public void choose(T item) {
        if (item == null) {
            throw new IllegalArgumentException("item cannot be null.");
        }
        if (this.isDisabled) {
            return;
        }
        snapshot();
        try {
            boolean z = true;
            if ((!this.toggle && !UIUtils.ctrl()) || !this.selected.contains(item)) {
                boolean modified = false;
                if (!this.multiple || (!this.toggle && !UIUtils.ctrl())) {
                    if (this.selected.size == 1 && this.selected.contains(item)) {
                        return;
                    }
                    if (this.selected.size <= 0) {
                        z = false;
                    }
                    modified = z;
                    this.selected.clear(8);
                }
                if (!this.selected.add(item) && !modified) {
                    return;
                }
                this.lastSelected = item;
            } else if (this.required && this.selected.size == 1) {
                return;
            } else {
                this.selected.remove(item);
                this.lastSelected = null;
            }
            if (fireChangeEvent()) {
                revert();
            } else {
                changed();
            }
        } finally {
            cleanup();
        }
    }

    @Deprecated
    public boolean hasItems() {
        return this.selected.size > 0;
    }

    public boolean notEmpty() {
        return this.selected.size > 0;
    }

    public boolean isEmpty() {
        return this.selected.size == 0;
    }

    public int size() {
        return this.selected.size;
    }

    public OrderedSet<T> items() {
        return this.selected;
    }

    public T first() {
        if (this.selected.size == 0) {
            return null;
        }
        return this.selected.first();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void snapshot() {
        this.old.clear(this.selected.size);
        this.old.addAll((OrderedSet) this.selected);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void revert() {
        this.selected.clear(this.old.size);
        this.selected.addAll((OrderedSet) this.old);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void cleanup() {
        this.old.clear(32);
    }

    public void set(T item) {
        if (item == null) {
            throw new IllegalArgumentException("item cannot be null.");
        }
        if (this.selected.size == 1 && this.selected.first() == item) {
            return;
        }
        snapshot();
        this.selected.clear(8);
        this.selected.add(item);
        if (this.programmaticChangeEvents && fireChangeEvent()) {
            revert();
        } else {
            this.lastSelected = item;
            changed();
        }
        cleanup();
    }

    public void setAll(Array<T> items) {
        boolean added = false;
        snapshot();
        this.lastSelected = null;
        this.selected.clear(items.size);
        int n = items.size;
        for (int i = 0; i < n; i++) {
            T item = items.get(i);
            if (item == null) {
                throw new IllegalArgumentException("item cannot be null.");
            }
            if (this.selected.add(item)) {
                added = true;
            }
        }
        if (added) {
            if (this.programmaticChangeEvents && fireChangeEvent()) {
                revert();
            } else if (items.size > 0) {
                this.lastSelected = items.peek();
                changed();
            }
        }
        cleanup();
    }

    public void add(T item) {
        if (item == null) {
            throw new IllegalArgumentException("item cannot be null.");
        }
        if (this.selected.add(item)) {
            if (this.programmaticChangeEvents && fireChangeEvent()) {
                this.selected.remove(item);
                return;
            }
            this.lastSelected = item;
            changed();
        }
    }

    public void addAll(Array<T> items) {
        boolean added = false;
        snapshot();
        int n = items.size;
        for (int i = 0; i < n; i++) {
            T item = items.get(i);
            if (item == null) {
                throw new IllegalArgumentException("item cannot be null.");
            }
            if (this.selected.add(item)) {
                added = true;
            }
        }
        if (added) {
            if (this.programmaticChangeEvents && fireChangeEvent()) {
                revert();
            } else {
                this.lastSelected = items.peek();
                changed();
            }
        }
        cleanup();
    }

    public void remove(T item) {
        if (item == null) {
            throw new IllegalArgumentException("item cannot be null.");
        }
        if (this.selected.remove(item)) {
            if (this.programmaticChangeEvents && fireChangeEvent()) {
                this.selected.add(item);
                return;
            }
            this.lastSelected = null;
            changed();
        }
    }

    public void removeAll(Array<T> items) {
        boolean removed = false;
        snapshot();
        int n = items.size;
        for (int i = 0; i < n; i++) {
            T item = items.get(i);
            if (item == null) {
                throw new IllegalArgumentException("item cannot be null.");
            }
            if (this.selected.remove(item)) {
                removed = true;
            }
        }
        if (removed) {
            if (this.programmaticChangeEvents && fireChangeEvent()) {
                revert();
            } else {
                this.lastSelected = null;
                changed();
            }
        }
        cleanup();
    }

    public void clear() {
        if (this.selected.size == 0) {
            return;
        }
        snapshot();
        this.selected.clear(8);
        if (this.programmaticChangeEvents && fireChangeEvent()) {
            revert();
        } else {
            this.lastSelected = null;
            changed();
        }
        cleanup();
    }

    protected void changed() {
    }

    public boolean fireChangeEvent() {
        if (this.actor == null) {
            return false;
        }
        ChangeListener.ChangeEvent changeEvent = (ChangeListener.ChangeEvent) Pools.obtain(ChangeListener.ChangeEvent.class);
        try {
            return this.actor.fire(changeEvent);
        } finally {
            Pools.free(changeEvent);
        }
    }

    public boolean contains(T item) {
        if (item == null) {
            return false;
        }
        return this.selected.contains(item);
    }

    public T getLastSelected() {
        T t = this.lastSelected;
        if (t != null) {
            return t;
        }
        if (this.selected.size > 0) {
            return this.selected.first();
        }
        return null;
    }

    @Override // java.lang.Iterable
    public Iterator<T> iterator() {
        return this.selected.iterator();
    }

    public Array<T> toArray() {
        return this.selected.iterator().toArray();
    }

    public Array<T> toArray(Array<T> array) {
        return this.selected.iterator().toArray(array);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Disableable
    public void setDisabled(boolean isDisabled) {
        this.isDisabled = isDisabled;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Disableable
    public boolean isDisabled() {
        return this.isDisabled;
    }

    public boolean getToggle() {
        return this.toggle;
    }

    public void setToggle(boolean toggle) {
        this.toggle = toggle;
    }

    public boolean getMultiple() {
        return this.multiple;
    }

    public void setMultiple(boolean multiple) {
        this.multiple = multiple;
    }

    public boolean getRequired() {
        return this.required;
    }

    public void setRequired(boolean required) {
        this.required = required;
    }

    public void setProgrammaticChangeEvents(boolean programmaticChangeEvents) {
        this.programmaticChangeEvents = programmaticChangeEvents;
    }

    public String toString() {
        return this.selected.toString();
    }
}