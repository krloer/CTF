package com.kotcrab.vis.ui.util.adapter;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.EventListener;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.utils.ClickListener;
import com.badlogic.gdx.scenes.scene2d.utils.UIUtils;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.widget.ListView;
import com.kotcrab.vis.ui.widget.VisTable;
import java.util.Comparator;
import java.util.Iterator;

/* loaded from: classes.dex */
public abstract class AbstractListAdapter<ItemT, ViewT extends Actor> extends CachedItemAdapter<ItemT, ViewT> implements ListAdapter<ItemT> {
    private ListView.ItemClickListener<ItemT> clickListener;
    private Comparator<ItemT> itemsComparator;
    protected ListView<ItemT> view;
    protected ListView.ListAdapterListener viewListener;
    private SelectionMode selectionMode = SelectionMode.DISABLED;
    private ListSelection<ItemT, ViewT> selection = new ListSelection<>();

    /* loaded from: classes.dex */
    public interface ListSelectionListener<ItemT, ViewT> {
        void deselected(ItemT itemt, ViewT viewt);

        void selected(ItemT itemt, ViewT viewt);
    }

    /* loaded from: classes.dex */
    public enum SelectionMode {
        DISABLED,
        SINGLE,
        MULTIPLE
    }

    protected abstract void sort(Comparator<ItemT> comparator);

    @Override // com.kotcrab.vis.ui.util.adapter.ListAdapter
    public void fillTable(VisTable itemsTable) {
        Comparator<ItemT> comparator = this.itemsComparator;
        if (comparator != null) {
            sort(comparator);
        }
        for (ItemT item : iterable()) {
            ViewT view = getView(item);
            prepareViewBeforeAddingToTable(item, view);
            itemsTable.add((VisTable) view).growX();
            itemsTable.row();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void prepareViewBeforeAddingToTable(ItemT item, ViewT view) {
        boolean listenerMissing = true;
        Iterator it = view.getListeners().iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            EventListener listener = (EventListener) it.next();
            if (listener instanceof ListClickListener) {
                listenerMissing = false;
                break;
            }
        }
        if (listenerMissing) {
            view.setTouchable(Touchable.enabled);
            view.addListener(new ListClickListener(view, item));
        }
    }

    @Override // com.kotcrab.vis.ui.util.adapter.ListAdapter
    public void setListView(ListView<ItemT> view, ListView.ListAdapterListener viewListener) {
        if (this.view != null) {
            throw new IllegalStateException("Adapter was already assigned to ListView");
        }
        this.view = view;
        this.viewListener = viewListener;
    }

    @Override // com.kotcrab.vis.ui.util.adapter.ListAdapter
    public void setItemClickListener(ListView.ItemClickListener<ItemT> listener) {
        this.clickListener = listener;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void itemAdded(ItemT item) {
        this.viewListener.invalidateDataSet();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void itemRemoved(ItemT item) {
        this.selection.deselect(item);
        getViews().remove(item);
        this.viewListener.invalidateDataSet();
    }

    public void itemsChanged() {
        this.selection.deselectAll();
        getViews().clear();
        this.viewListener.invalidateDataSet();
    }

    public void itemsDataChanged() {
        this.viewListener.invalidateDataSet();
    }

    @Override // com.kotcrab.vis.ui.util.adapter.CachedItemAdapter
    protected void updateView(ViewT view, ItemT item) {
    }

    public SelectionMode getSelectionMode() {
        return this.selectionMode;
    }

    public void setSelectionMode(SelectionMode selectionMode) {
        if (selectionMode == null) {
            throw new IllegalArgumentException("selectionMode can't be null");
        }
        this.selectionMode = selectionMode;
    }

    public void setItemsSorter(Comparator<ItemT> comparator) {
        this.itemsComparator = comparator;
    }

    public Comparator<ItemT> getItemsSorter() {
        return this.itemsComparator;
    }

    public Array<ItemT> getSelection() {
        return this.selection.getSelection();
    }

    public ListSelection<ItemT, ViewT> getSelectionManager() {
        return this.selection;
    }

    protected void selectView(ViewT view) {
        if (this.selectionMode != SelectionMode.DISABLED) {
            throw new UnsupportedOperationException("selectView must be implemented when `selectionMode` is different than SelectionMode.DISABLED");
        }
    }

    protected void deselectView(ViewT view) {
        if (this.selectionMode != SelectionMode.DISABLED) {
            throw new UnsupportedOperationException("deselectView must be implemented when `selectionMode` is different than SelectionMode.DISABLED");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class ListClickListener extends ClickListener {
        private ItemT item;
        private ViewT view;

        public ListClickListener(ViewT view, ItemT item) {
            this.view = view;
            this.item = item;
        }

        @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
            super.touchDown(event, x, y, pointer, button);
            AbstractListAdapter.this.selection.touchDown(this.view, this.item);
            return true;
        }

        @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener
        public void clicked(InputEvent event, float x, float y) {
            if (AbstractListAdapter.this.clickListener != null) {
                AbstractListAdapter.this.clickListener.clicked(this.item);
            }
        }
    }

    /* loaded from: classes.dex */
    public static class ListSelection<ItemT, ViewT extends Actor> {
        public static final int DEFAULT_KEY = -1;
        private AbstractListAdapter<ItemT, ViewT> adapter;
        private int groupMultiSelectKey;
        private ListSelectionListener<ItemT, ViewT> listener;
        private int multiSelectKey;
        private boolean programmaticChangeEvents;
        private Array<ItemT> selection;

        private ListSelection(AbstractListAdapter<ItemT, ViewT> adapter) {
            this.groupMultiSelectKey = -1;
            this.multiSelectKey = -1;
            this.selection = new Array<>();
            this.programmaticChangeEvents = true;
            this.listener = new ListSelectionAdapter();
            this.adapter = adapter;
        }

        public void select(ItemT item) {
            select(item, this.adapter.getViews().get(item), true);
        }

        void select(ItemT item, ViewT view, boolean programmaticChange) {
            if (this.adapter.getSelectionMode() == SelectionMode.DISABLED) {
                return;
            }
            if (this.adapter.getSelectionMode() == SelectionMode.SINGLE) {
                deselectAll(programmaticChange);
            }
            if (this.adapter.getSelectionMode() == SelectionMode.MULTIPLE && this.selection.size >= 1 && isGroupMultiSelectKeyPressed()) {
                selectGroup(item);
            }
            doSelect(item, view, programmaticChange);
        }

        private void doSelect(ItemT item, ViewT view, boolean programmaticChange) {
            if (!this.selection.contains(item, true)) {
                this.adapter.selectView(view);
                this.selection.add(item);
                if (!programmaticChange || this.programmaticChangeEvents) {
                    this.listener.selected(item, view);
                }
            }
        }

        public void deselect(ItemT item) {
            deselect(item, this.adapter.getViews().get(item), true);
        }

        public void deselectAll() {
            deselectAll(true);
        }

        private void selectGroup(ItemT newItem) {
            int start;
            int end;
            int thisSelectionIndex = this.adapter.indexOf(newItem);
            int lastSelectionIndex = this.adapter.indexOf(this.selection.peek());
            if (lastSelectionIndex == -1) {
                return;
            }
            if (thisSelectionIndex > lastSelectionIndex) {
                start = lastSelectionIndex;
                end = thisSelectionIndex;
            } else {
                start = thisSelectionIndex;
                end = lastSelectionIndex;
            }
            for (int i = start; i < end; i++) {
                ItemT item = this.adapter.get(i);
                doSelect(item, this.adapter.getViews().get(item), false);
            }
        }

        void deselect(ItemT item, ViewT view, boolean programmaticChange) {
            if (this.selection.contains(item, true)) {
                this.adapter.deselectView(view);
                this.selection.removeValue(item, true);
                if (!programmaticChange || this.programmaticChangeEvents) {
                    this.listener.deselected(item, view);
                }
            }
        }

        /* JADX WARN: Multi-variable type inference failed */
        void deselectAll(boolean programmaticChange) {
            Array<ItemT> items = new Array<>((Array<? extends ItemT>) this.selection);
            Iterator it = items.iterator();
            while (it.hasNext()) {
                Object next = it.next();
                deselect(next, this.adapter.getViews().get(next), programmaticChange);
            }
        }

        public Array<ItemT> getSelection() {
            return this.selection;
        }

        void touchDown(ViewT view, ItemT item) {
            if (this.adapter.getSelectionMode() == SelectionMode.DISABLED) {
                return;
            }
            if (!isMultiSelectKeyPressed() && !isGroupMultiSelectKeyPressed()) {
                deselectAll(false);
            }
            if (!this.selection.contains(item, true)) {
                select(item, view, false);
            } else {
                deselect(item, view, false);
            }
        }

        public int getMultiSelectKey() {
            return this.multiSelectKey;
        }

        public void setMultiSelectKey(int multiSelectKey) {
            this.multiSelectKey = multiSelectKey;
        }

        public int getGroupMultiSelectKey() {
            return this.groupMultiSelectKey;
        }

        public void setGroupMultiSelectKey(int groupMultiSelectKey) {
            this.groupMultiSelectKey = groupMultiSelectKey;
        }

        public void setListener(ListSelectionListener<ItemT, ViewT> listener) {
            if (listener == null) {
                listener = new ListSelectionAdapter();
            }
            this.listener = listener;
        }

        public ListSelectionListener<ItemT, ViewT> getListener() {
            return this.listener;
        }

        public boolean isProgrammaticChangeEvents() {
            return this.programmaticChangeEvents;
        }

        public void setProgrammaticChangeEvents(boolean programmaticChangeEvents) {
            this.programmaticChangeEvents = programmaticChangeEvents;
        }

        private boolean isMultiSelectKeyPressed() {
            if (this.multiSelectKey == -1) {
                return UIUtils.ctrl();
            }
            return Gdx.input.isKeyPressed(this.multiSelectKey);
        }

        private boolean isGroupMultiSelectKeyPressed() {
            if (this.groupMultiSelectKey == -1) {
                return UIUtils.shift();
            }
            return Gdx.input.isKeyPressed(this.groupMultiSelectKey);
        }
    }
}