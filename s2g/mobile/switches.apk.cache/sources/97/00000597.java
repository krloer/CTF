package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.VisUI;
import java.util.Iterator;

/* loaded from: classes.dex */
public class MenuBar {
    private Menu currentMenu;
    private Table mainTable;
    private Table menuItems;
    private MenuBarListener menuListener;
    private Array<Menu> menus;

    /* loaded from: classes.dex */
    public interface MenuBarListener {
        void menuClosed(Menu menu);

        void menuOpened(Menu menu);
    }

    public MenuBar() {
        this("default");
    }

    public MenuBar(String styleName) {
        this((MenuBarStyle) VisUI.getSkin().get(styleName, MenuBarStyle.class));
    }

    public MenuBar(MenuBarStyle style) {
        this.menus = new Array<>();
        this.menuItems = new VisTable();
        this.mainTable = new VisTable() { // from class: com.kotcrab.vis.ui.widget.MenuBar.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Actor
            public void sizeChanged() {
                super.sizeChanged();
                MenuBar.this.closeMenu();
            }
        };
        this.mainTable.left();
        this.mainTable.add(this.menuItems);
        this.mainTable.setBackground(style.background);
    }

    public void addMenu(Menu menu) {
        this.menus.add(menu);
        menu.setMenuBar(this);
        this.menuItems.add(menu.getOpenButton());
    }

    public boolean removeMenu(Menu menu) {
        boolean removed = this.menus.removeValue(menu, true);
        if (removed) {
            menu.setMenuBar(null);
            this.menuItems.removeActor(menu.getOpenButton());
        }
        return removed;
    }

    public void insertMenu(int index, Menu menu) {
        this.menus.insert(index, menu);
        menu.setMenuBar(this);
        rebuild();
    }

    private void rebuild() {
        this.menuItems.clear();
        Iterator it = this.menus.iterator();
        while (it.hasNext()) {
            Menu menu = (Menu) it.next();
            this.menuItems.add(menu.getOpenButton());
        }
    }

    public void closeMenu() {
        Menu menu = this.currentMenu;
        if (menu != null) {
            menu.deselectButton();
            this.currentMenu.remove();
            this.currentMenu = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Menu getCurrentMenu() {
        return this.currentMenu;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setCurrentMenu(Menu newMenu) {
        Menu menu = this.currentMenu;
        if (menu == newMenu) {
            return;
        }
        if (menu != null) {
            menu.deselectButton();
            MenuBarListener menuBarListener = this.menuListener;
            if (menuBarListener != null) {
                menuBarListener.menuClosed(this.currentMenu);
            }
        }
        if (newMenu != null) {
            newMenu.selectButton();
            MenuBarListener menuBarListener2 = this.menuListener;
            if (menuBarListener2 != null) {
                menuBarListener2.menuOpened(newMenu);
            }
        }
        this.currentMenu = newMenu;
    }

    public void setMenuListener(MenuBarListener menuListener) {
        this.menuListener = menuListener;
    }

    public Table getTable() {
        return this.mainTable;
    }

    /* loaded from: classes.dex */
    public static class MenuBarStyle {
        public Drawable background;

        public MenuBarStyle() {
        }

        public MenuBarStyle(MenuBarStyle style) {
            this.background = style.background;
        }

        public MenuBarStyle(Drawable background) {
            this.background = background;
        }
    }
}