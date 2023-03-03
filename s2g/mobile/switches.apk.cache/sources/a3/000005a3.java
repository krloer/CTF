package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.Cell;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.SnapshotArray;
import com.kotcrab.vis.ui.Sizes;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.ActorUtils;
import java.util.Iterator;

/* loaded from: classes.dex */
public class PopupMenu extends Table {
    private static final Vector2 tmpVector = new Vector2();
    private MenuItem activeItem;
    private PopupMenu activeSubMenu;
    private InputListener defaultInputListener;
    private PopupMenuListener listener;
    private PopupMenu parentSubMenu;
    private ChangeListener sharedMenuItemChangeListener;
    private InputListener sharedMenuItemInputListener;
    private Sizes sizes;
    private InputListener stageListener;
    private PopupMenuStyle style;

    /* loaded from: classes.dex */
    public interface PopupMenuListener {
        void activeItemChanged(MenuItem menuItem, boolean z);
    }

    public PopupMenu() {
        this("default");
    }

    public PopupMenu(String styleName) {
        this((PopupMenuStyle) VisUI.getSkin().get(styleName, PopupMenuStyle.class));
    }

    public PopupMenu(PopupMenuStyle style) {
        this(VisUI.getSizes(), style);
    }

    public PopupMenu(Sizes sizes, PopupMenuStyle style) {
        this.sizes = sizes;
        this.style = style;
        setTouchable(Touchable.enabled);
        pad(0.0f);
        setBackground(style.background);
        createListeners();
    }

    public static void removeEveryMenu(Stage stage) {
        Iterator it = stage.getActors().iterator();
        while (it.hasNext()) {
            Actor actor = (Actor) it.next();
            if (actor instanceof PopupMenu) {
                PopupMenu menu = (PopupMenu) actor;
                menu.removeHierarchy();
            }
        }
    }

    private void createListeners() {
        this.stageListener = new InputListener() { // from class: com.kotcrab.vis.ui.widget.PopupMenu.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                if (!PopupMenu.this.getRootMenu().subMenuStructureContains(x, y)) {
                    PopupMenu.this.remove();
                    return true;
                }
                return true;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyDown(InputEvent event, int keycode) {
                SnapshotArray<Actor> children = PopupMenu.this.getChildren();
                if (children.size == 0 || PopupMenu.this.activeSubMenu != null) {
                    return false;
                }
                if (keycode == 20) {
                    PopupMenu.this.selectNextItem();
                }
                if (PopupMenu.this.activeItem == null) {
                    return false;
                }
                if (keycode == 19) {
                    PopupMenu.this.selectPreviousItem();
                }
                if (keycode == 21 && PopupMenu.this.activeItem.containerMenu.parentSubMenu != null) {
                    PopupMenu.this.activeItem.containerMenu.parentSubMenu.setActiveSubMenu(null);
                }
                if (keycode == 22 && PopupMenu.this.activeItem.getSubMenu() != null) {
                    PopupMenu.this.activeItem.showSubMenu();
                    PopupMenu.this.activeSubMenu.selectNextItem();
                }
                if (keycode == 66) {
                    PopupMenu.this.activeItem.fireChangeEvent();
                }
                return false;
            }
        };
        this.sharedMenuItemInputListener = new InputListener() { // from class: com.kotcrab.vis.ui.widget.PopupMenu.2
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void enter(InputEvent event, float x, float y, int pointer, Actor fromActor) {
                if (pointer == -1 && (event.getListenerActor() instanceof MenuItem)) {
                    MenuItem item = (MenuItem) event.getListenerActor();
                    if (!item.isDisabled()) {
                        PopupMenu.this.setActiveItem(item, false);
                    }
                }
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void exit(InputEvent event, float x, float y, int pointer, Actor toActor) {
                if (pointer == -1 && (event.getListenerActor() instanceof MenuItem) && PopupMenu.this.activeSubMenu == null) {
                    MenuItem item = (MenuItem) event.getListenerActor();
                    if (item == PopupMenu.this.activeItem) {
                        PopupMenu.this.setActiveItem(null, false);
                    }
                }
            }
        };
        this.sharedMenuItemChangeListener = new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.PopupMenu.3
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                if (!event.isStopped()) {
                    PopupMenu.this.removeHierarchy();
                }
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: private */
    public PopupMenu getRootMenu() {
        PopupMenu popupMenu = this.parentSubMenu;
        return popupMenu != null ? popupMenu.getRootMenu() : this;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean subMenuStructureContains(float x, float y) {
        if (contains(x, y)) {
            return true;
        }
        PopupMenu popupMenu = this.activeSubMenu;
        if (popupMenu != null) {
            return popupMenu.subMenuStructureContains(x, y);
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void removeHierarchy() {
        MenuItem menuItem = this.activeItem;
        if (menuItem != null && menuItem.containerMenu.parentSubMenu != null) {
            this.activeItem.containerMenu.parentSubMenu.removeHierarchy();
        }
        remove();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void selectNextItem() {
        SnapshotArray<Actor> children = getChildren();
        if (children.size == 0) {
            return;
        }
        MenuItem menuItem = this.activeItem;
        int startIndex = menuItem == null ? 0 : children.indexOf(menuItem, true) + 1;
        int i = startIndex;
        while (true) {
            if (i >= children.size) {
                i = 0;
            }
            Actor actor = children.get(i);
            if (!(actor instanceof MenuItem) || ((MenuItem) actor).isDisabled()) {
                i++;
            } else {
                setActiveItem((MenuItem) actor, true);
                return;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void selectPreviousItem() {
        SnapshotArray<Actor> children = getChildren();
        if (children.size == 0) {
            return;
        }
        int startIndex = children.indexOf(this.activeItem, true) - 1;
        int i = startIndex;
        while (true) {
            if (i == -1) {
                i = children.size - 1;
            }
            Actor actor = children.get(i);
            if (!(actor instanceof MenuItem) || ((MenuItem) actor).isDisabled()) {
                i--;
            } else {
                setActiveItem((MenuItem) actor, true);
                return;
            }
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Table
    public <T extends Actor> Cell<T> add(T actor) {
        if (actor instanceof MenuItem) {
            throw new IllegalArgumentException("MenuItems can be only added to PopupMenu by using addItem(MenuItem) method");
        }
        return super.add((PopupMenu) actor);
    }

    public void addItem(MenuItem item) {
        super.add((PopupMenu) item).fillX().expandX().row();
        pack();
        item.addListener(this.sharedMenuItemChangeListener);
        item.addListener(this.sharedMenuItemInputListener);
    }

    public void addSeparator() {
        add((PopupMenu) new Separator("menu")).padTop(2.0f).padBottom(2.0f).fill().expand().row();
    }

    public InputListener getDefaultInputListener() {
        return getDefaultInputListener(1);
    }

    public InputListener getDefaultInputListener(final int mouseButton) {
        if (this.defaultInputListener == null) {
            this.defaultInputListener = new InputListener() { // from class: com.kotcrab.vis.ui.widget.PopupMenu.4
                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                    return true;
                }

                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                    if (event.getButton() == mouseButton) {
                        PopupMenu.this.showMenu(event.getStage(), event.getStageX(), event.getStageY());
                    }
                }
            };
        }
        return this.defaultInputListener;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        super.draw(batch, parentAlpha);
        if (this.style.border != null) {
            this.style.border.draw(batch, getX(), getY(), getWidth(), getHeight());
        }
    }

    public void showMenu(Stage stage, float x, float y) {
        setPosition(x, y - getHeight());
        if (stage.getHeight() - getY() > stage.getHeight()) {
            setY(getY() + getHeight());
        }
        ActorUtils.keepWithinStage(stage, this);
        stage.addActor(this);
    }

    public void showMenu(Stage stage, Actor actor) {
        float menuY;
        Vector2 pos = actor.localToStageCoordinates(tmpVector.setZero());
        if (pos.y - getHeight() <= 0.0f) {
            menuY = ((pos.y + actor.getHeight()) + getHeight()) - this.sizes.borderSize;
        } else {
            float menuY2 = pos.y;
            menuY = menuY2 + this.sizes.borderSize;
        }
        showMenu(stage, pos.x, menuY);
    }

    public boolean contains(float x, float y) {
        return getX() < x && getX() + getWidth() > x && getY() < y && getY() + getHeight() > y;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setActiveSubMenu(PopupMenu newSubMenu) {
        PopupMenu popupMenu = this.activeSubMenu;
        if (popupMenu == newSubMenu) {
            return;
        }
        if (popupMenu != null) {
            popupMenu.remove();
        }
        this.activeSubMenu = newSubMenu;
        if (newSubMenu != null) {
            newSubMenu.setParentMenu(this);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void setStage(Stage stage) {
        super.setStage(stage);
        if (stage != null) {
            stage.addListener(this.stageListener);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public boolean remove() {
        if (getStage() != null) {
            getStage().removeListener(this.stageListener);
        }
        PopupMenu popupMenu = this.activeSubMenu;
        if (popupMenu != null) {
            popupMenu.remove();
        }
        setActiveItem(null, false);
        this.parentSubMenu = null;
        this.activeSubMenu = null;
        return super.remove();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setActiveItem(MenuItem newItem, boolean keyboardChange) {
        this.activeItem = newItem;
        PopupMenuListener popupMenuListener = this.listener;
        if (popupMenuListener != null) {
            popupMenuListener.activeItemChanged(newItem, keyboardChange);
        }
    }

    public MenuItem getActiveItem() {
        return this.activeItem;
    }

    void setParentMenu(PopupMenu parentSubMenu) {
        this.parentSubMenu = parentSubMenu;
    }

    public PopupMenuListener getListener() {
        return this.listener;
    }

    public void setListener(PopupMenuListener listener) {
        this.listener = listener;
    }

    /* loaded from: classes.dex */
    public static class PopupMenuStyle {
        public Drawable background;
        public Drawable border;

        public PopupMenuStyle() {
        }

        public PopupMenuStyle(Drawable background, Drawable border) {
            this.background = background;
            this.border = border;
        }

        public PopupMenuStyle(PopupMenuStyle style) {
            this.background = style.background;
            this.border = style.border;
        }
    }
}