package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.ui.TextButton;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.widget.PopupMenu;
import com.kotcrab.vis.ui.widget.VisTextButton;

/* loaded from: classes.dex */
public class Menu extends PopupMenu {
    public Drawable buttonDefault;
    private MenuBar menuBar;
    public VisTextButton openButton;
    private String title;

    public Menu(String title) {
        this(title, "default");
    }

    public Menu(String title, String styleName) {
        this(title, (MenuStyle) VisUI.getSkin().get(styleName, MenuStyle.class));
    }

    public Menu(String title, MenuStyle style) {
        super(style);
        this.title = title;
        this.openButton = new VisTextButton(title, new VisTextButton.VisTextButtonStyle(style.openButtonStyle));
        this.buttonDefault = this.openButton.getStyle().up;
        this.openButton.addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.Menu.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                Menu currentMenu = Menu.this.menuBar.getCurrentMenu();
                Menu menu = Menu.this;
                if (currentMenu == menu) {
                    menu.menuBar.closeMenu();
                    return true;
                }
                menu.switchMenu();
                event.stop();
                return true;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void enter(InputEvent event, float x, float y, int pointer, Actor fromActor) {
                if (Menu.this.menuBar.getCurrentMenu() != null) {
                    Menu currentMenu = Menu.this.menuBar.getCurrentMenu();
                    Menu menu = Menu.this;
                    if (currentMenu != menu) {
                        menu.switchMenu();
                    }
                }
            }
        });
    }

    public String getTitle() {
        return this.title;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void switchMenu() {
        this.menuBar.closeMenu();
        showMenu();
    }

    private void showMenu() {
        Vector2 pos = this.openButton.localToStageCoordinates(new Vector2(0.0f, 0.0f));
        setPosition(pos.x, pos.y - getHeight());
        this.openButton.getStage().addActor(this);
        this.menuBar.setCurrentMenu(this);
    }

    @Override // com.kotcrab.vis.ui.widget.PopupMenu, com.badlogic.gdx.scenes.scene2d.Actor
    public boolean remove() {
        boolean result = super.remove();
        this.menuBar.setCurrentMenu(null);
        return result;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setMenuBar(MenuBar menuBar) {
        if (this.menuBar != null) {
            throw new IllegalStateException("Menu was already added to MenuBar");
        }
        this.menuBar = menuBar;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public TextButton getOpenButton() {
        return this.openButton;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void selectButton() {
        this.openButton.getStyle().up = this.openButton.getStyle().over;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void deselectButton() {
        this.openButton.getStyle().up = this.buttonDefault;
    }

    /* loaded from: classes.dex */
    public static class MenuStyle extends PopupMenu.PopupMenuStyle {
        public VisTextButton.VisTextButtonStyle openButtonStyle;

        public MenuStyle() {
        }

        public MenuStyle(MenuStyle style) {
            super(style);
            this.openButtonStyle = style.openButtonStyle;
        }

        public MenuStyle(Drawable background, Drawable border, VisTextButton.VisTextButtonStyle openButtonStyle) {
            super(background, border);
            this.openButtonStyle = openButtonStyle;
        }
    }
}