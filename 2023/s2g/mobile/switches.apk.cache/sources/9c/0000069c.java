package com.kotcrab.vis.ui.widget.tabbedpane;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.Button;
import com.badlogic.gdx.scenes.scene2d.ui.ButtonGroup;
import com.badlogic.gdx.scenes.scene2d.ui.Cell;
import com.badlogic.gdx.scenes.scene2d.ui.Image;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.UIUtils;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.I18NBundle;
import com.badlogic.gdx.utils.IdentityMap;
import com.badlogic.gdx.utils.ObjectMap;
import com.badlogic.gdx.utils.Scaling;
import com.kotcrab.vis.ui.Locales;
import com.kotcrab.vis.ui.Sizes;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.i18n.BundleText;
import com.kotcrab.vis.ui.layout.DragPane;
import com.kotcrab.vis.ui.layout.HorizontalFlowGroup;
import com.kotcrab.vis.ui.layout.VerticalFlowGroup;
import com.kotcrab.vis.ui.util.dialog.Dialogs;
import com.kotcrab.vis.ui.util.dialog.OptionDialogAdapter;
import com.kotcrab.vis.ui.widget.Draggable;
import com.kotcrab.vis.ui.widget.VisImageButton;
import com.kotcrab.vis.ui.widget.VisTable;
import com.kotcrab.vis.ui.widget.VisTextButton;
import java.util.Iterator;

/* loaded from: classes.dex */
public class TabbedPane {
    private Tab activeTab;
    private boolean allowTabDeselect;
    private ButtonGroup<Button> group;
    private Array<TabbedPaneListener> listeners;
    private TabbedPaneTable mainTable;
    private VisImageButton.VisImageButtonStyle sharedCloseActiveButtonStyle;
    private Sizes sizes;
    private TabbedPaneStyle style;
    private Array<Tab> tabs;
    private IdentityMap<Tab, TabButtonTable> tabsButtonMap;
    private DragPane tabsPane;
    private static final Vector2 tmpVector = new Vector2();
    private static final Rectangle tmpRect = new Rectangle();

    public TabbedPane() {
        this((TabbedPaneStyle) VisUI.getSkin().get(TabbedPaneStyle.class));
    }

    public TabbedPane(String styleName) {
        this((TabbedPaneStyle) VisUI.getSkin().get(styleName, TabbedPaneStyle.class));
    }

    public TabbedPane(TabbedPaneStyle style) {
        this(style, VisUI.getSizes());
    }

    public TabbedPane(TabbedPaneStyle style, Sizes sizes) {
        this.style = style;
        this.sizes = sizes;
        this.listeners = new Array<>();
        this.sharedCloseActiveButtonStyle = (VisImageButton.VisImageButtonStyle) VisUI.getSkin().get("close-active-tab", VisImageButton.VisImageButtonStyle.class);
        this.group = new ButtonGroup<>();
        this.mainTable = new TabbedPaneTable(this);
        this.tabsPane = new DragPane(style.vertical ? new VerticalFlowGroup() : new HorizontalFlowGroup());
        configureDragPane(style);
        this.mainTable.setBackground(style.background);
        this.tabs = new Array<>();
        this.tabsButtonMap = new IdentityMap<>();
        Cell<DragPane> tabsPaneCell = this.mainTable.add((TabbedPaneTable) this.tabsPane);
        Cell<Image> separatorCell = null;
        if (style.vertical) {
            tabsPaneCell.top().growY().minSize(0.0f, 0.0f);
        } else {
            tabsPaneCell.left().growX().minSize(0.0f, 0.0f);
        }
        if (style.separatorBar != null) {
            if (style.vertical) {
                separatorCell = this.mainTable.add((TabbedPaneTable) new Image(style.separatorBar)).growY().width(style.separatorBar.getMinWidth());
            } else {
                this.mainTable.row();
                separatorCell = this.mainTable.add((TabbedPaneTable) new Image(style.separatorBar)).growX().height(style.separatorBar.getMinHeight());
            }
        } else if (style.vertical) {
            this.mainTable.add().growY();
        } else {
            this.mainTable.add().growX();
        }
        this.mainTable.setPaneCells(tabsPaneCell, separatorCell);
    }

    private void configureDragPane(TabbedPaneStyle style) {
        this.tabsPane.setTouchable(Touchable.childrenOnly);
        this.tabsPane.setListener(new DragPane.DragPaneListener.AcceptOwnChildren());
        if (style.draggable) {
            Draggable draggable = new Draggable();
            draggable.setInvisibleWhenDragged(true);
            draggable.setKeepWithinParent(true);
            draggable.setBlockInput(true);
            draggable.setFadingTime(0.0f);
            draggable.setListener(new DragPane.DefaultDragListener() { // from class: com.kotcrab.vis.ui.widget.tabbedpane.TabbedPane.1
                public boolean dragged;

                @Override // com.kotcrab.vis.ui.layout.DragPane.DefaultDragListener, com.kotcrab.vis.ui.widget.Draggable.DragListener
                public boolean onStart(Draggable draggable2, Actor actor, float stageX, float stageY) {
                    this.dragged = false;
                    if ((actor instanceof TabButtonTable) && ((TabButtonTable) actor).closeButton.isOver()) {
                        return false;
                    }
                    return super.onStart(draggable2, actor, stageX, stageY);
                }

                @Override // com.kotcrab.vis.ui.layout.DragPane.DefaultDragListener, com.kotcrab.vis.ui.widget.Draggable.DragListener
                public void onDrag(Draggable draggable2, Actor actor, float stageX, float stageY) {
                    super.onDrag(draggable2, actor, stageX, stageY);
                    this.dragged = true;
                }

                @Override // com.kotcrab.vis.ui.layout.DragPane.DefaultDragListener, com.kotcrab.vis.ui.widget.Draggable.DragListener
                public boolean onEnd(Draggable draggable2, Actor actor, float stageX, float stageY) {
                    boolean result = super.onEnd(draggable2, actor, stageX, stageY);
                    if (result) {
                        return true;
                    }
                    if (this.dragged) {
                        TabbedPane.this.tabsPane.stageToLocalCoordinates(TabbedPane.tmpVector.set(stageX, stageY));
                        if (TabbedPane.this.tabsPane.hit(TabbedPane.tmpVector.x, TabbedPane.tmpVector.y, true) == null && TabbedPane.this.tabsPane.hit(TabbedPane.tmpVector.x + actor.getWidth(), TabbedPane.tmpVector.y, true) == null && TabbedPane.this.tabsPane.hit(TabbedPane.tmpVector.x, TabbedPane.tmpVector.y - actor.getHeight(), true) == null && TabbedPane.this.tabsPane.hit(TabbedPane.tmpVector.x + actor.getWidth(), TabbedPane.tmpVector.y - actor.getHeight(), true) == null) {
                            Vector2 stagePos = TabbedPane.this.tabsPane.localToStageCoordinates(TabbedPane.tmpVector.setZero());
                            TabbedPane.tmpRect.set(stagePos.x, stagePos.y, TabbedPane.this.tabsPane.getGroup().getWidth(), TabbedPane.this.tabsPane.getGroup().getHeight());
                            if (TabbedPane.tmpRect.contains(stageX, stageY)) {
                                if (TabbedPane.this.tabsPane.isHorizontalFlow() || TabbedPane.this.tabsPane.isVerticalFlow()) {
                                    DRAG_POSITION.set(stageX, stageY);
                                    TabbedPane.this.tabsPane.addActor(actor);
                                    return true;
                                }
                                return false;
                            }
                            return false;
                        }
                        return false;
                    }
                    return false;
                }
            });
            this.tabsPane.setDraggable(draggable);
        }
    }

    public DragPane getTabsPane() {
        return this.tabsPane;
    }

    public void setAllowTabDeselect(boolean allowTabDeselect) {
        this.allowTabDeselect = allowTabDeselect;
        if (allowTabDeselect) {
            this.group.setMinCheckCount(0);
        } else {
            this.group.setMinCheckCount(1);
        }
    }

    public boolean isAllowTabDeselect() {
        return this.allowTabDeselect;
    }

    public void add(Tab tab) {
        tab.setPane(this);
        this.tabs.add(tab);
        addTab(tab, this.tabsPane.getChildren().size);
        switchTab(tab);
    }

    public void insert(int index, Tab tab) {
        tab.setPane(this);
        this.tabs.insert(index, tab);
        addTab(tab, index);
    }

    protected void addTab(Tab tab, int index) {
        TabButtonTable buttonTable = this.tabsButtonMap.get(tab);
        if (buttonTable == null) {
            buttonTable = new TabButtonTable(tab);
            this.tabsButtonMap.put(tab, buttonTable);
        }
        buttonTable.setTouchable(Touchable.enabled);
        if (index >= this.tabsPane.getChildren().size) {
            this.tabsPane.addActor(buttonTable);
        } else {
            this.tabsPane.addActorAt(index, buttonTable);
        }
        this.group.add((ButtonGroup<Button>) buttonTable.button);
        if (this.tabs.size != 1 || this.activeTab == null) {
            if (tab != this.activeTab) {
                return;
            }
            buttonTable.select();
            return;
        }
        buttonTable.select();
        notifyListenersSwitched(tab);
    }

    public void disableTab(Tab tab, boolean disable) {
        checkIfTabsBelongsToThisPane(tab);
        TabButtonTable buttonTable = this.tabsButtonMap.get(tab);
        buttonTable.button.setDisabled(disable);
        if (this.activeTab == tab && disable) {
            if (selectFirstEnabledTab()) {
                return;
            }
            this.activeTab = null;
            notifyListenersSwitched(null);
        }
        if (this.activeTab == null && !this.allowTabDeselect) {
            selectFirstEnabledTab();
        }
    }

    public boolean isTabDisabled(Tab tab) {
        TabButtonTable table = this.tabsButtonMap.get(tab);
        if (table == null) {
            throwNotBelongingTabException(tab);
        }
        return table.button.isDisabled();
    }

    private boolean selectFirstEnabledTab() {
        ObjectMap.Entries<Tab, TabButtonTable> it = this.tabsButtonMap.iterator();
        while (it.hasNext()) {
            IdentityMap.Entry<Tab, TabButtonTable> entry = it.next();
            if (!((TabButtonTable) entry.value).button.isDisabled()) {
                switchTab((Tab) entry.key);
                return true;
            }
        }
        return false;
    }

    private void checkIfTabsBelongsToThisPane(Tab tab) {
        if (!this.tabs.contains(tab, true)) {
            throwNotBelongingTabException(tab);
        }
    }

    protected void throwNotBelongingTabException(Tab tab) {
        throw new IllegalArgumentException("Tab '" + tab.getTabTitle() + "' does not belong to this TabbedPane");
    }

    public boolean remove(Tab tab) {
        return remove(tab, true);
    }

    public boolean remove(final Tab tab, boolean ignoreTabDirty) {
        checkIfTabsBelongsToThisPane(tab);
        if (ignoreTabDirty) {
            return removeTab(tab);
        }
        if (tab.isDirty() && this.mainTable.getStage() != null) {
            Dialogs.showOptionDialog(this.mainTable.getStage(), Text.UNSAVED_DIALOG_TITLE.get(), Text.UNSAVED_DIALOG_TEXT.get(), Dialogs.OptionDialogType.YES_NO_CANCEL, new OptionDialogAdapter() { // from class: com.kotcrab.vis.ui.widget.tabbedpane.TabbedPane.2
                @Override // com.kotcrab.vis.ui.util.dialog.OptionDialogAdapter, com.kotcrab.vis.ui.util.dialog.OptionDialogListener
                public void yes() {
                    tab.save();
                    TabbedPane.this.removeTab(tab);
                }

                @Override // com.kotcrab.vis.ui.util.dialog.OptionDialogAdapter, com.kotcrab.vis.ui.util.dialog.OptionDialogListener
                public void no() {
                    TabbedPane.this.removeTab(tab);
                }
            });
            return false;
        }
        return removeTab(tab);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean removeTab(Tab tab) {
        int index = this.tabs.indexOf(tab, true);
        boolean success = this.tabs.removeValue(tab, true);
        if (success) {
            TabButtonTable buttonTable = this.tabsButtonMap.get(tab);
            this.tabsPane.removeActor(buttonTable, true);
            this.tabsPane.invalidateHierarchy();
            this.tabsButtonMap.remove(tab);
            tab.setPane(null);
            tab.onHide();
            tab.dispose();
            notifyListenersRemoved(tab);
            if (this.tabs.size == 0) {
                notifyListenersRemovedAll();
            } else if (this.activeTab == tab) {
                if (index > 0) {
                    switchTab(index - 1);
                } else {
                    switchTab(index);
                }
            }
        }
        return success;
    }

    public void removeAll() {
        Iterator it = this.tabs.iterator();
        while (it.hasNext()) {
            Tab tab = (Tab) it.next();
            tab.setPane(null);
            tab.onHide();
            tab.dispose();
        }
        this.tabs.clear();
        this.tabsButtonMap.clear();
        this.tabsPane.clear();
        notifyListenersRemovedAll();
    }

    public void switchTab(int index) {
        this.tabsButtonMap.get(this.tabs.get(index)).select();
    }

    public void switchTab(Tab tab) {
        TabButtonTable table = this.tabsButtonMap.get(tab);
        if (table == null) {
            throwNotBelongingTabException(tab);
        }
        table.select();
    }

    public void updateTabTitle(Tab tab) {
        TabButtonTable table = this.tabsButtonMap.get(tab);
        if (table == null) {
            throwNotBelongingTabException(tab);
        }
        table.button.setText(getTabTitle(tab));
    }

    protected String getTabTitle(Tab tab) {
        if (tab.isDirty()) {
            return "*" + tab.getTabTitle();
        }
        return tab.getTabTitle();
    }

    public TabbedPaneTable getTable() {
        return this.mainTable;
    }

    public Tab getActiveTab() {
        return this.activeTab;
    }

    public void addListener(TabbedPaneListener listener) {
        this.listeners.add(listener);
    }

    public boolean removeListener(TabbedPaneListener listener) {
        return this.listeners.removeValue(listener, true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyListenersSwitched(Tab tab) {
        Iterator it = this.listeners.iterator();
        while (it.hasNext()) {
            TabbedPaneListener listener = (TabbedPaneListener) it.next();
            listener.switchedTab(tab);
        }
    }

    private void notifyListenersRemoved(Tab tab) {
        Iterator it = this.listeners.iterator();
        while (it.hasNext()) {
            TabbedPaneListener listener = (TabbedPaneListener) it.next();
            listener.removedTab(tab);
        }
    }

    private void notifyListenersRemovedAll() {
        Iterator it = this.listeners.iterator();
        while (it.hasNext()) {
            TabbedPaneListener listener = (TabbedPaneListener) it.next();
            listener.removedAllTabs();
        }
    }

    public Array<Tab> getTabs() {
        return this.tabs;
    }

    public Array<Tab> getUIOrderedTabs() {
        Array<Tab> tabs = new Array<>();
        Array.ArrayIterator<Actor> it = getTabsPane().getChildren().iterator();
        while (it.hasNext()) {
            Actor actor = it.next();
            if (actor instanceof TabButtonTable) {
                tabs.add(((TabButtonTable) actor).tab);
            }
        }
        return tabs;
    }

    /* loaded from: classes.dex */
    public static class TabbedPaneStyle {
        public Drawable background;
        public VisTextButton.VisTextButtonStyle buttonStyle;
        public boolean draggable;
        public Drawable separatorBar;
        public boolean vertical;

        public TabbedPaneStyle() {
            this.vertical = false;
            this.draggable = true;
        }

        public TabbedPaneStyle(TabbedPaneStyle style) {
            this.vertical = false;
            this.draggable = true;
            this.background = style.background;
            this.buttonStyle = style.buttonStyle;
            this.separatorBar = style.separatorBar;
            this.vertical = style.vertical;
            this.draggable = style.draggable;
        }

        public TabbedPaneStyle(Drawable background, Drawable separatorBar, VisTextButton.VisTextButtonStyle buttonStyle) {
            this.vertical = false;
            this.draggable = true;
            this.background = background;
            this.separatorBar = separatorBar;
            this.buttonStyle = buttonStyle;
        }

        public TabbedPaneStyle(Drawable separatorBar, Drawable background, VisTextButton.VisTextButtonStyle buttonStyle, boolean vertical, boolean draggable) {
            this.vertical = false;
            this.draggable = true;
            this.separatorBar = separatorBar;
            this.background = background;
            this.buttonStyle = buttonStyle;
            this.vertical = vertical;
            this.draggable = draggable;
        }
    }

    /* loaded from: classes.dex */
    public static class TabbedPaneTable extends VisTable {
        private Cell<Image> separatorCell;
        private TabbedPane tabbedPane;
        private Cell<DragPane> tabsPaneCell;

        public TabbedPaneTable(TabbedPane tabbedPane) {
            this.tabbedPane = tabbedPane;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setPaneCells(Cell<DragPane> tabsPaneCell, Cell<Image> separatorCell) {
            this.tabsPaneCell = tabsPaneCell;
            this.separatorCell = separatorCell;
        }

        public Cell<DragPane> getTabsPaneCell() {
            return this.tabsPaneCell;
        }

        public Cell<Image> getSeparatorCell() {
            return this.separatorCell;
        }

        public TabbedPane getTabbedPane() {
            return this.tabbedPane;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class TabButtonTable extends VisTable {
        public VisTextButton button;
        private VisTextButton.VisTextButtonStyle buttonStyle;
        public VisImageButton closeButton;
        private VisImageButton.VisImageButtonStyle closeButtonStyle;
        private Tab tab;
        private Drawable up;

        public TabButtonTable(Tab tab) {
            this.tab = tab;
            this.button = new VisTextButton(TabbedPane.this.getTabTitle(tab), TabbedPane.this.style.buttonStyle) { // from class: com.kotcrab.vis.ui.widget.tabbedpane.TabbedPane.TabButtonTable.1
                @Override // com.badlogic.gdx.scenes.scene2d.ui.Button, com.badlogic.gdx.scenes.scene2d.utils.Disableable
                public void setDisabled(boolean isDisabled) {
                    super.setDisabled(isDisabled);
                    TabButtonTable.this.closeButton.setDisabled(isDisabled);
                    TabButtonTable.this.deselect();
                }
            };
            this.button.setFocusBorderEnabled(false);
            this.button.setProgrammaticChangeEvents(false);
            this.closeButtonStyle = new VisImageButton.VisImageButtonStyle((VisImageButton.VisImageButtonStyle) VisUI.getSkin().get("close", VisImageButton.VisImageButtonStyle.class));
            this.closeButton = new VisImageButton(this.closeButtonStyle);
            this.closeButton.setGenerateDisabledImage(true);
            this.closeButton.getImage().setScaling(Scaling.fill);
            this.closeButton.getImage().setColor(Color.RED);
            addListeners();
            this.buttonStyle = new VisTextButton.VisTextButtonStyle((VisTextButton.VisTextButtonStyle) this.button.getStyle());
            this.button.setStyle(this.buttonStyle);
            this.closeButtonStyle = this.closeButton.getStyle();
            this.up = this.buttonStyle.up;
            add((TabButtonTable) this.button);
            if (tab.isCloseableByUser()) {
                add((TabButtonTable) this.closeButton).size(TabbedPane.this.sizes.scaleFactor * 14.0f, this.button.getHeight());
            }
        }

        private void addListeners() {
            this.closeButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.tabbedpane.TabbedPane.TabButtonTable.2
                @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                    TabButtonTable.this.closeTabAsUser();
                }
            });
            this.button.addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.tabbedpane.TabbedPane.TabButtonTable.3
                private boolean isDown;

                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public boolean touchDown(InputEvent event, float x, float y, int pointer, int mouseButton) {
                    if (TabButtonTable.this.button.isDisabled()) {
                        return false;
                    }
                    this.isDown = true;
                    if (UIUtils.left()) {
                        setDraggedUpImage();
                    }
                    if (mouseButton == 2) {
                        TabButtonTable.this.closeTabAsUser();
                    }
                    return true;
                }

                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                    setDefaultUpImage();
                    this.isDown = false;
                }

                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public boolean mouseMoved(InputEvent event, float x, float y) {
                    if (!TabButtonTable.this.button.isDisabled() && TabbedPane.this.activeTab != TabButtonTable.this.tab) {
                        setCloseButtonOnMouseMove();
                        return false;
                    }
                    return false;
                }

                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public void exit(InputEvent event, float x, float y, int pointer, Actor toActor) {
                    if (!TabButtonTable.this.button.isDisabled() && !this.isDown && TabbedPane.this.activeTab != TabButtonTable.this.tab && pointer == -1) {
                        setDefaultUpImage();
                    }
                }

                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public void enter(InputEvent event, float x, float y, int pointer, Actor fromActor) {
                    if (!TabButtonTable.this.button.isDisabled() && TabbedPane.this.activeTab != TabButtonTable.this.tab && !Gdx.input.justTouched() && pointer == -1) {
                        setCloseButtonOnMouseMove();
                    }
                }

                private void setCloseButtonOnMouseMove() {
                    if (this.isDown) {
                        TabButtonTable.this.closeButtonStyle.up = TabButtonTable.this.buttonStyle.down;
                        return;
                    }
                    TabButtonTable.this.closeButtonStyle.up = TabButtonTable.this.buttonStyle.over;
                }

                private void setDraggedUpImage() {
                    TabButtonTable.this.closeButtonStyle.up = TabButtonTable.this.buttonStyle.down;
                    TabButtonTable.this.buttonStyle.up = TabButtonTable.this.buttonStyle.down;
                }

                private void setDefaultUpImage() {
                    TabButtonTable.this.closeButtonStyle.up = TabButtonTable.this.up;
                    TabButtonTable.this.buttonStyle.up = TabButtonTable.this.up;
                }
            });
            this.button.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.tabbedpane.TabbedPane.TabButtonTable.4
                @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                    TabButtonTable.this.switchToNewTab();
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void switchToNewTab() {
            TabButtonTable table;
            if (TabbedPane.this.activeTab != null && TabbedPane.this.activeTab != this.tab && (table = (TabButtonTable) TabbedPane.this.tabsButtonMap.get(TabbedPane.this.activeTab)) != null) {
                table.deselect();
                TabbedPane.this.activeTab.onHide();
            }
            if (!this.button.isChecked() || this.tab == TabbedPane.this.activeTab) {
                if (TabbedPane.this.group.getCheckedIndex() == -1) {
                    TabbedPane.this.activeTab = null;
                    TabbedPane.this.notifyListenersSwitched(null);
                    return;
                }
                return;
            }
            TabbedPane.this.activeTab = this.tab;
            TabbedPane.this.notifyListenersSwitched(this.tab);
            this.tab.onShow();
            this.closeButton.setStyle(TabbedPane.this.sharedCloseActiveButtonStyle);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void closeTabAsUser() {
            if (this.tab.isCloseableByUser()) {
                TabbedPane.this.remove(this.tab, false);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void select() {
            this.button.setChecked(true);
            switchToNewTab();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void deselect() {
            this.closeButton.setStyle(this.closeButtonStyle);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public enum Text implements BundleText {
        UNSAVED_DIALOG_TITLE("unsavedDialogTitle"),
        UNSAVED_DIALOG_TEXT("unsavedDialogText");
        
        private final String name;

        Text(String name) {
            this.name = name;
        }

        private static I18NBundle getBundle() {
            return Locales.getTabbedPaneBundle();
        }

        @Override // com.kotcrab.vis.ui.i18n.BundleText
        public final String getName() {
            return this.name;
        }

        @Override // com.kotcrab.vis.ui.i18n.BundleText
        public final String get() {
            return getBundle().get(this.name);
        }

        @Override // com.kotcrab.vis.ui.i18n.BundleText
        public final String format() {
            return getBundle().format(this.name, new Object[0]);
        }

        @Override // com.kotcrab.vis.ui.i18n.BundleText
        public final String format(Object... arguments) {
            return getBundle().format(this.name, arguments);
        }

        @Override // java.lang.Enum
        public final String toString() {
            return get();
        }
    }
}