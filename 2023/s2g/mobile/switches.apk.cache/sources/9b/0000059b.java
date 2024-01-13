package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.Input;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Group;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.ui.Button;
import com.badlogic.gdx.scenes.scene2d.ui.Cell;
import com.badlogic.gdx.scenes.scene2d.ui.Image;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.badlogic.gdx.scenes.scene2d.ui.TextButton;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.Pools;
import com.badlogic.gdx.utils.Scaling;
import com.kotcrab.vis.ui.Sizes;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.OsUtils;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class MenuItem extends Button {
    private static final Vector2 tmpVector = new Vector2();
    PopupMenu containerMenu;
    private boolean generateDisabledImage;
    private Image image;
    private Label label;
    private VisLabel shortcutLabel;
    private Color shortcutLabelColor;
    private MenuItemStyle style;
    private PopupMenu subMenu;
    private Cell<Image> subMenuIconCell;
    private Image subMenuImage;

    public MenuItem(String text) {
        this(text, (Image) null, (MenuItemStyle) VisUI.getSkin().get(MenuItemStyle.class));
    }

    public MenuItem(String text, String styleName) {
        this(text, (Image) null, (MenuItemStyle) VisUI.getSkin().get(styleName, MenuItemStyle.class));
    }

    public MenuItem(String text, ChangeListener changeListener) {
        this(text, (Image) null, (MenuItemStyle) VisUI.getSkin().get(MenuItemStyle.class));
        addListener(changeListener);
    }

    public MenuItem(String text, Drawable drawable) {
        this(text, drawable, (MenuItemStyle) VisUI.getSkin().get(MenuItemStyle.class));
    }

    public MenuItem(String text, Drawable drawable, ChangeListener changeListener) {
        this(text, drawable, (MenuItemStyle) VisUI.getSkin().get(MenuItemStyle.class));
        addListener(changeListener);
    }

    public MenuItem(String text, Drawable drawable, String styleName) {
        this(text, drawable, (MenuItemStyle) VisUI.getSkin().get(styleName, MenuItemStyle.class));
    }

    public MenuItem(String text, Image image) {
        this(text, image, (MenuItemStyle) VisUI.getSkin().get(MenuItemStyle.class));
    }

    public MenuItem(String text, Image image, ChangeListener changeListener) {
        this(text, image, (MenuItemStyle) VisUI.getSkin().get(MenuItemStyle.class));
        addListener(changeListener);
    }

    public MenuItem(String text, Image image, String styleName) {
        this(text, image, (MenuItemStyle) VisUI.getSkin().get(styleName, MenuItemStyle.class));
    }

    public MenuItem(String text, Image image, MenuItemStyle style) {
        super(style);
        this.generateDisabledImage = true;
        init(text, image, style);
    }

    public MenuItem(String text, Drawable drawable, MenuItemStyle style) {
        super(style);
        this.generateDisabledImage = true;
        init(text, new Image(drawable), style);
    }

    private void init(String text, Image image, MenuItemStyle style) {
        this.style = style;
        this.image = image;
        setSkin(VisUI.getSkin());
        Sizes sizes = VisUI.getSizes();
        defaults().space(3.0f);
        if (image != null) {
            image.setScaling(Scaling.fit);
        }
        add((MenuItem) image).size(sizes.menuItemIconSize);
        this.label = new Label(text, new Label.LabelStyle(style.font, style.fontColor));
        this.label.setAlignment(8);
        add((MenuItem) this.label).expand().fill();
        VisLabel visLabel = new VisLabel(BuildConfig.FLAVOR, "menuitem-shortcut");
        this.shortcutLabel = visLabel;
        add((MenuItem) visLabel).padLeft(10.0f).right();
        this.shortcutLabelColor = this.shortcutLabel.getStyle().fontColor;
        Image image2 = new Image(style.subMenu);
        this.subMenuImage = image2;
        this.subMenuIconCell = add((MenuItem) image2).padLeft(3.0f).padRight(3.0f).size(style.subMenu.getMinWidth(), style.subMenu.getMinHeight());
        this.subMenuIconCell.setActor(null);
        addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.MenuItem.1
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                if (MenuItem.this.subMenu != null) {
                    event.stop();
                }
            }
        });
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.MenuItem.2
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void enter(InputEvent event, float x, float y, int pointer, Actor fromActor) {
                if (MenuItem.this.subMenu != null) {
                    MenuItem.this.subMenu.setActiveItem(null, false);
                    MenuItem.this.subMenu.setActiveSubMenu(null);
                }
                if (MenuItem.this.subMenu == null || MenuItem.this.isDisabled()) {
                    MenuItem.this.hideSubMenu();
                } else {
                    MenuItem.this.showSubMenu();
                }
            }
        });
    }

    public void setSubMenu(PopupMenu subMenu) {
        this.subMenu = subMenu;
        if (subMenu == null) {
            this.subMenuIconCell.setActor(null);
        } else {
            this.subMenuIconCell.setActor(this.subMenuImage);
        }
    }

    public PopupMenu getSubMenu() {
        return this.subMenu;
    }

    void packContainerMenu() {
        PopupMenu popupMenu = this.containerMenu;
        if (popupMenu != null) {
            popupMenu.pack();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void setParent(Group parent) {
        super.setParent(parent);
        if (parent instanceof PopupMenu) {
            this.containerMenu = (PopupMenu) parent;
        } else {
            this.containerMenu = null;
        }
    }

    void hideSubMenu() {
        PopupMenu popupMenu = this.containerMenu;
        if (popupMenu != null) {
            popupMenu.setActiveSubMenu(null);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void showSubMenu() {
        float subMenuX;
        Stage stage = getStage();
        Vector2 pos = localToStageCoordinates(tmpVector.setZero());
        float availableSpaceLeft = pos.x;
        float availableSpaceRight = stage.getWidth() - (pos.x + getWidth());
        boolean canFitOnTheRight = (pos.x + getWidth()) + this.subMenu.getWidth() <= stage.getWidth();
        if (!canFitOnTheRight && availableSpaceRight <= availableSpaceLeft) {
            subMenuX = (pos.x - this.subMenu.getWidth()) + 1.0f;
        } else {
            float subMenuX2 = pos.x;
            subMenuX = (subMenuX2 + getWidth()) - 1.0f;
        }
        this.subMenu.setPosition(subMenuX, (pos.y - this.subMenu.getHeight()) + getHeight());
        if (this.subMenu.getY() < 0.0f) {
            PopupMenu popupMenu = this.subMenu;
            popupMenu.setY((popupMenu.getY() + this.subMenu.getHeight()) - getHeight());
        }
        stage.addActor(this.subMenu);
        this.containerMenu.setActiveSubMenu(this.subMenu);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void fireChangeEvent() {
        ChangeListener.ChangeEvent changeEvent = (ChangeListener.ChangeEvent) Pools.obtain(ChangeListener.ChangeEvent.class);
        fire(changeEvent);
        Pools.free(changeEvent);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button
    public MenuItemStyle getStyle() {
        return this.style;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button
    public void setStyle(Button.ButtonStyle style) {
        if (!(style instanceof MenuItemStyle)) {
            throw new IllegalArgumentException("style must be a MenuItemStyle.");
        }
        super.setStyle(style);
        this.style = (MenuItemStyle) style;
        Label label = this.label;
        if (label != null) {
            TextButton.TextButtonStyle textButtonStyle = (TextButton.TextButtonStyle) style;
            Label.LabelStyle labelStyle = label.getStyle();
            labelStyle.font = textButtonStyle.font;
            labelStyle.fontColor = textButtonStyle.fontColor;
            this.label.setStyle(labelStyle);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button, com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        Color fontColor;
        if (isDisabled() && this.style.disabledFontColor != null) {
            fontColor = this.style.disabledFontColor;
        } else if (isPressed() && this.style.downFontColor != null) {
            fontColor = this.style.downFontColor;
        } else if (isChecked() && this.style.checkedFontColor != null) {
            fontColor = (!isOver() || this.style.checkedOverFontColor == null) ? this.style.checkedFontColor : this.style.checkedOverFontColor;
        } else if (isOver() && this.style.overFontColor != null) {
            fontColor = this.style.overFontColor;
        } else {
            fontColor = this.style.fontColor;
        }
        if (fontColor != null) {
            this.label.getStyle().fontColor = fontColor;
        }
        if (isDisabled()) {
            this.shortcutLabel.getStyle().fontColor = this.style.disabledFontColor;
        } else {
            this.shortcutLabel.getStyle().fontColor = this.shortcutLabelColor;
        }
        if (this.image != null && this.generateDisabledImage) {
            if (isDisabled()) {
                this.image.setColor(Color.GRAY);
            } else {
                this.image.setColor(Color.WHITE);
            }
        }
        super.draw(batch, parentAlpha);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button
    public boolean isOver() {
        PopupMenu popupMenu = this.containerMenu;
        if (popupMenu == null || popupMenu.getActiveItem() == null) {
            return super.isOver();
        }
        return this.containerMenu.getActiveItem() == this;
    }

    public boolean isGenerateDisabledImage() {
        return this.generateDisabledImage;
    }

    public void setGenerateDisabledImage(boolean generateDisabledImage) {
        this.generateDisabledImage = generateDisabledImage;
    }

    public MenuItem setShortcut(int keycode) {
        return setShortcut(Input.Keys.toString(keycode));
    }

    public CharSequence getShortcut() {
        return this.shortcutLabel.getText();
    }

    public MenuItem setShortcut(String text) {
        this.shortcutLabel.setText(text);
        packContainerMenu();
        return this;
    }

    public MenuItem setShortcut(int... keycodes) {
        this.shortcutLabel.setText(OsUtils.getShortcutFor(keycodes));
        packContainerMenu();
        return this;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void setStage(Stage stage) {
        super.setStage(stage);
        this.label.invalidate();
    }

    public Image getImage() {
        return this.image;
    }

    public Cell<?> getImageCell() {
        return getCell(this.image);
    }

    public Label getLabel() {
        return this.label;
    }

    public Cell<?> getLabelCell() {
        return getCell(this.label);
    }

    public CharSequence getText() {
        return this.label.getText();
    }

    public void setText(CharSequence text) {
        this.label.setText(text);
    }

    public Cell<Image> getSubMenuIconCell() {
        return this.subMenuIconCell;
    }

    public Cell<VisLabel> getShortcutCell() {
        return getCell(this.shortcutLabel);
    }

    /* loaded from: classes.dex */
    public static class MenuItemStyle extends TextButton.TextButtonStyle {
        public Drawable subMenu;

        public MenuItemStyle() {
        }

        public MenuItemStyle(Drawable subMenu) {
            this.subMenu = subMenu;
        }

        public MenuItemStyle(MenuItemStyle style) {
            super(style);
            this.subMenu = style.subMenu;
        }
    }
}