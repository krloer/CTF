package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.graphics.g2d.GlyphLayout;
import com.badlogic.gdx.math.Interpolation;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.actions.Actions;
import com.badlogic.gdx.scenes.scene2d.ui.List;
import com.badlogic.gdx.scenes.scene2d.ui.ScrollPane;
import com.badlogic.gdx.scenes.scene2d.utils.ArraySelection;
import com.badlogic.gdx.scenes.scene2d.utils.ClickListener;
import com.badlogic.gdx.scenes.scene2d.utils.Disableable;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.ObjectSet;
import com.badlogic.gdx.utils.Pool;
import com.badlogic.gdx.utils.Pools;

/* loaded from: classes.dex */
public class SelectBox<T> extends Widget implements Disableable {
    static final Vector2 temp = new Vector2();
    private int alignment;
    private ClickListener clickListener;
    boolean disabled;
    final Array<T> items;
    private float prefHeight;
    private float prefWidth;
    SelectBoxList<T> selectBoxList;
    boolean selectedPrefWidth;
    final ArraySelection<T> selection;
    SelectBoxStyle style;

    public SelectBox(Skin skin) {
        this((SelectBoxStyle) skin.get(SelectBoxStyle.class));
    }

    public SelectBox(Skin skin, String styleName) {
        this((SelectBoxStyle) skin.get(styleName, SelectBoxStyle.class));
    }

    public SelectBox(SelectBoxStyle style) {
        this.items = new Array<>();
        this.alignment = 8;
        this.selection = new ArraySelection(this.items) { // from class: com.badlogic.gdx.scenes.scene2d.ui.SelectBox.1
            @Override // com.badlogic.gdx.scenes.scene2d.utils.Selection
            public boolean fireChangeEvent() {
                if (SelectBox.this.selectedPrefWidth) {
                    SelectBox.this.invalidateHierarchy();
                }
                return super.fireChangeEvent();
            }
        };
        setStyle(style);
        setSize(getPrefWidth(), getPrefHeight());
        this.selection.setActor(this);
        this.selection.setRequired(true);
        this.selectBoxList = new SelectBoxList<>(this);
        ClickListener clickListener = new ClickListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.SelectBox.2
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                if ((pointer == 0 && button != 0) || SelectBox.this.isDisabled()) {
                    return false;
                }
                if (SelectBox.this.selectBoxList.hasParent()) {
                    SelectBox.this.hideList();
                    return true;
                }
                SelectBox.this.showList();
                return true;
            }
        };
        this.clickListener = clickListener;
        addListener(clickListener);
    }

    public void setMaxListCount(int maxListCount) {
        this.selectBoxList.maxListCount = maxListCount;
    }

    public int getMaxListCount() {
        return this.selectBoxList.maxListCount;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void setStage(Stage stage) {
        if (stage == null) {
            this.selectBoxList.hide();
        }
        super.setStage(stage);
    }

    public void setStyle(SelectBoxStyle style) {
        if (style == null) {
            throw new IllegalArgumentException("style cannot be null.");
        }
        this.style = style;
        SelectBoxList<T> selectBoxList = this.selectBoxList;
        if (selectBoxList != null) {
            selectBoxList.setStyle(style.scrollStyle);
            this.selectBoxList.list.setStyle(style.listStyle);
        }
        invalidateHierarchy();
    }

    public SelectBoxStyle getStyle() {
        return this.style;
    }

    public void setItems(T... newItems) {
        if (newItems == null) {
            throw new IllegalArgumentException("newItems cannot be null.");
        }
        float oldPrefWidth = getPrefWidth();
        this.items.clear();
        this.items.addAll(newItems);
        this.selection.validate();
        this.selectBoxList.list.setItems(this.items);
        invalidate();
        if (oldPrefWidth != getPrefWidth()) {
            invalidateHierarchy();
        }
    }

    public void setItems(Array<T> newItems) {
        if (newItems == null) {
            throw new IllegalArgumentException("newItems cannot be null.");
        }
        float oldPrefWidth = getPrefWidth();
        Array<T> array = this.items;
        if (newItems != array) {
            array.clear();
            this.items.addAll(newItems);
        }
        this.selection.validate();
        this.selectBoxList.list.setItems(this.items);
        invalidate();
        if (oldPrefWidth != getPrefWidth()) {
            invalidateHierarchy();
        }
    }

    public void clearItems() {
        if (this.items.size == 0) {
            return;
        }
        this.items.clear();
        this.selection.clear();
        invalidateHierarchy();
    }

    public Array<T> getItems() {
        return this.items;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void layout() {
        Drawable bg = this.style.background;
        BitmapFont font = this.style.font;
        if (bg == null) {
            this.prefHeight = font.getCapHeight() - (font.getDescent() * 2.0f);
        } else {
            this.prefHeight = Math.max(((bg.getTopHeight() + bg.getBottomHeight()) + font.getCapHeight()) - (font.getDescent() * 2.0f), bg.getMinHeight());
        }
        Pool<GlyphLayout> layoutPool = Pools.get(GlyphLayout.class);
        GlyphLayout layout = layoutPool.obtain();
        if (this.selectedPrefWidth) {
            this.prefWidth = 0.0f;
            if (bg != null) {
                this.prefWidth = bg.getLeftWidth() + bg.getRightWidth();
            }
            T selected = getSelected();
            if (selected != null) {
                layout.setText(font, toString(selected));
                this.prefWidth += layout.width;
            }
        } else {
            float maxItemWidth = 0.0f;
            for (int i = 0; i < this.items.size; i++) {
                layout.setText(font, toString(this.items.get(i)));
                maxItemWidth = Math.max(layout.width, maxItemWidth);
            }
            this.prefWidth = maxItemWidth;
            if (bg != null) {
                this.prefWidth = Math.max(this.prefWidth + bg.getLeftWidth() + bg.getRightWidth(), bg.getMinWidth());
            }
            List.ListStyle listStyle = this.style.listStyle;
            ScrollPane.ScrollPaneStyle scrollStyle = this.style.scrollStyle;
            float listWidth = listStyle.selection.getLeftWidth() + maxItemWidth + listStyle.selection.getRightWidth();
            Drawable bg2 = scrollStyle.background;
            if (bg2 != null) {
                listWidth = Math.max(bg2.getLeftWidth() + listWidth + bg2.getRightWidth(), bg2.getMinWidth());
            }
            SelectBoxList<T> selectBoxList = this.selectBoxList;
            if (selectBoxList == null || !selectBoxList.disableY) {
                listWidth += Math.max(this.style.scrollStyle.vScroll != null ? this.style.scrollStyle.vScroll.getMinWidth() : 0.0f, this.style.scrollStyle.vScrollKnob != null ? this.style.scrollStyle.vScrollKnob.getMinWidth() : 0.0f);
            }
            this.prefWidth = Math.max(this.prefWidth, listWidth);
        }
        layoutPool.free(layout);
    }

    protected Drawable getBackgroundDrawable() {
        return (!isDisabled() || this.style.backgroundDisabled == null) ? (!this.selectBoxList.hasParent() || this.style.backgroundOpen == null) ? (!isOver() || this.style.backgroundOver == null) ? this.style.background : this.style.backgroundOver : this.style.backgroundOpen : this.style.backgroundDisabled;
    }

    protected Color getFontColor() {
        return (!isDisabled() || this.style.disabledFontColor == null) ? (this.style.overFontColor == null || !(isOver() || this.selectBoxList.hasParent())) ? this.style.fontColor : this.style.overFontColor : this.style.disabledFontColor;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        float height;
        float width;
        float y;
        validate();
        Drawable background = getBackgroundDrawable();
        Color fontColor = getFontColor();
        BitmapFont font = this.style.font;
        Color color = getColor();
        float x = getX();
        float y2 = getY();
        float width2 = getWidth();
        float height2 = getHeight();
        batch.setColor(color.r, color.g, color.b, color.a * parentAlpha);
        if (background != null) {
            background.draw(batch, x, y2, width2, height2);
        }
        T selected = this.selection.first();
        if (selected != null) {
            if (background == null) {
                height = width2;
                width = y2 + ((int) ((height2 / 2.0f) + (font.getData().capHeight / 2.0f)));
                y = x;
            } else {
                float width3 = width2 - (background.getLeftWidth() + background.getRightWidth());
                float height3 = height2 - (background.getBottomHeight() + background.getTopHeight());
                float x2 = x + background.getLeftWidth();
                height = width3;
                width = y2 + ((int) ((height3 / 2.0f) + background.getBottomHeight() + (font.getData().capHeight / 2.0f)));
                y = x2;
            }
            font.setColor(fontColor.r, fontColor.g, fontColor.b, fontColor.a * parentAlpha);
            drawItem(batch, font, selected, y, width, height);
        }
    }

    protected GlyphLayout drawItem(Batch batch, BitmapFont font, T item, float x, float y, float width) {
        String string = toString(item);
        return font.draw(batch, string, x, y, 0, string.length(), width, this.alignment, false, "...");
    }

    public void setAlignment(int alignment) {
        this.alignment = alignment;
    }

    public ArraySelection<T> getSelection() {
        return this.selection;
    }

    public T getSelected() {
        return this.selection.first();
    }

    public void setSelected(T item) {
        if (this.items.contains(item, false)) {
            this.selection.set(item);
        } else if (this.items.size > 0) {
            this.selection.set(this.items.first());
        } else {
            this.selection.clear();
        }
    }

    public int getSelectedIndex() {
        ObjectSet<T> selected = this.selection.items();
        if (selected.size == 0) {
            return -1;
        }
        return this.items.indexOf(selected.first(), false);
    }

    public void setSelectedIndex(int index) {
        this.selection.set(this.items.get(index));
    }

    public void setSelectedPrefWidth(boolean selectedPrefWidth) {
        this.selectedPrefWidth = selectedPrefWidth;
    }

    public float getMaxSelectedPrefWidth() {
        Pool<GlyphLayout> layoutPool = Pools.get(GlyphLayout.class);
        GlyphLayout layout = layoutPool.obtain();
        float width = 0.0f;
        for (int i = 0; i < this.items.size; i++) {
            layout.setText(this.style.font, toString(this.items.get(i)));
            width = Math.max(layout.width, width);
        }
        Drawable bg = this.style.background;
        return bg != null ? Math.max(bg.getLeftWidth() + width + bg.getRightWidth(), bg.getMinWidth()) : width;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Disableable
    public void setDisabled(boolean disabled) {
        if (disabled && !this.disabled) {
            hideList();
        }
        this.disabled = disabled;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Disableable
    public boolean isDisabled() {
        return this.disabled;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        validate();
        return this.prefWidth;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        validate();
        return this.prefHeight;
    }

    protected String toString(T item) {
        return item.toString();
    }

    public void showList() {
        if (this.items.size != 0 && getStage() != null) {
            this.selectBoxList.show(getStage());
        }
    }

    public void hideList() {
        this.selectBoxList.hide();
    }

    public List<T> getList() {
        return this.selectBoxList.list;
    }

    public void setScrollingDisabled(boolean y) {
        this.selectBoxList.setScrollingDisabled(true, y);
        invalidateHierarchy();
    }

    public ScrollPane getScrollPane() {
        return this.selectBoxList;
    }

    public boolean isOver() {
        return this.clickListener.isOver();
    }

    public ClickListener getClickListener() {
        return this.clickListener;
    }

    protected void onShow(Actor selectBoxList, boolean below) {
        selectBoxList.getColor().a = 0.0f;
        selectBoxList.addAction(Actions.fadeIn(0.3f, Interpolation.fade));
    }

    protected void onHide(Actor selectBoxList) {
        selectBoxList.getColor().a = 1.0f;
        selectBoxList.addAction(Actions.sequence(Actions.fadeOut(0.15f, Interpolation.fade), Actions.removeActor()));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class SelectBoxList<T> extends ScrollPane {
        private InputListener hideListener;
        final List<T> list;
        int maxListCount;
        private Actor previousScrollFocus;
        private final SelectBox<T> selectBox;
        private final Vector2 stagePosition;

        public SelectBoxList(final SelectBox<T> selectBox) {
            super((Actor) null, selectBox.style.scrollStyle);
            this.stagePosition = new Vector2();
            this.selectBox = selectBox;
            setOverscroll(false, false);
            setFadeScrollBars(false);
            setScrollingDisabled(true, false);
            this.list = new List<T>(selectBox.style.listStyle) { // from class: com.badlogic.gdx.scenes.scene2d.ui.SelectBox.SelectBoxList.1
                @Override // com.badlogic.gdx.scenes.scene2d.ui.List
                public String toString(T obj) {
                    return selectBox.toString(obj);
                }
            };
            this.list.setTouchable(Touchable.disabled);
            this.list.setTypeToSelect(true);
            setActor(this.list);
            this.list.addListener(new ClickListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.SelectBox.SelectBoxList.2
                @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener
                public void clicked(InputEvent event, float x, float y) {
                    T selected = SelectBoxList.this.list.getSelected();
                    if (selected != null) {
                        selectBox.selection.items().clear();
                    }
                    selectBox.selection.choose(selected);
                    SelectBoxList.this.hide();
                }

                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public boolean mouseMoved(InputEvent event, float x, float y) {
                    int index = SelectBoxList.this.list.getItemIndexAt(y);
                    if (index != -1) {
                        SelectBoxList.this.list.setSelectedIndex(index);
                        return true;
                    }
                    return true;
                }
            });
            addListener(new InputListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.SelectBox.SelectBoxList.3
                /* JADX WARN: Multi-variable type inference failed */
                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public void exit(InputEvent event, float x, float y, int pointer, Actor toActor) {
                    if (toActor == null || !SelectBoxList.this.isAscendantOf(toActor)) {
                        SelectBoxList.this.list.selection.set(selectBox.getSelected());
                    }
                }
            });
            this.hideListener = new InputListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.SelectBox.SelectBoxList.4
                /* JADX WARN: Multi-variable type inference failed */
                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                    Actor target = event.getTarget();
                    if (SelectBoxList.this.isAscendantOf(target)) {
                        return false;
                    }
                    SelectBoxList.this.list.selection.set(selectBox.getSelected());
                    SelectBoxList.this.hide();
                    return false;
                }

                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public boolean keyDown(InputEvent event, int keycode) {
                    if (keycode != 66) {
                        if (keycode != 111) {
                            if (keycode != 160) {
                                return false;
                            }
                        }
                        SelectBoxList.this.hide();
                        event.stop();
                        return true;
                    }
                    selectBox.selection.choose(SelectBoxList.this.list.getSelected());
                    SelectBoxList.this.hide();
                    event.stop();
                    return true;
                }
            };
        }

        public void show(Stage stage) {
            int i;
            float height;
            boolean below;
            if (this.list.isTouchable()) {
                return;
            }
            stage.addActor(this);
            stage.addCaptureListener(this.hideListener);
            stage.addListener(this.list.getKeyListener());
            this.selectBox.localToStageCoordinates(this.stagePosition.set(0.0f, 0.0f));
            float itemHeight = this.list.getItemHeight();
            float height2 = (this.maxListCount <= 0 ? this.selectBox.items.size : Math.min(i, this.selectBox.items.size)) * itemHeight;
            Drawable scrollPaneBackground = getStyle().background;
            if (scrollPaneBackground != null) {
                height2 += scrollPaneBackground.getTopHeight() + scrollPaneBackground.getBottomHeight();
            }
            Drawable listBackground = this.list.getStyle().background;
            if (listBackground != null) {
                height2 += listBackground.getTopHeight() + listBackground.getBottomHeight();
            }
            float heightBelow = this.stagePosition.y;
            float heightAbove = (stage.getHeight() - heightBelow) - this.selectBox.getHeight();
            if (height2 <= heightBelow) {
                height = height2;
                below = true;
            } else if (heightAbove > heightBelow) {
                height = Math.min(height2, heightAbove);
                below = false;
            } else {
                height = heightBelow;
                below = true;
            }
            if (below) {
                setY(this.stagePosition.y - height);
            } else {
                setY(this.stagePosition.y + this.selectBox.getHeight());
            }
            setX(this.stagePosition.x);
            setHeight(height);
            validate();
            float width = Math.max(getPrefWidth(), this.selectBox.getWidth());
            setWidth((getPrefHeight() <= height || this.disableY) ? width : width + getScrollBarWidth());
            validate();
            scrollTo(0.0f, (this.list.getHeight() - (this.selectBox.getSelectedIndex() * itemHeight)) - (itemHeight / 2.0f), 0.0f, 0.0f, true, true);
            updateVisualScroll();
            this.previousScrollFocus = null;
            Actor actor = stage.getScrollFocus();
            if (actor != null && !actor.isDescendantOf(this)) {
                this.previousScrollFocus = actor;
            }
            stage.setScrollFocus(this);
            this.list.selection.set(this.selectBox.getSelected());
            this.list.setTouchable(Touchable.enabled);
            clearActions();
            this.selectBox.onShow(this, below);
        }

        public void hide() {
            if (!this.list.isTouchable() || !hasParent()) {
                return;
            }
            this.list.setTouchable(Touchable.disabled);
            Stage stage = getStage();
            if (stage != null) {
                stage.removeCaptureListener(this.hideListener);
                stage.removeListener(this.list.getKeyListener());
                Actor actor = this.previousScrollFocus;
                if (actor != null && actor.getStage() == null) {
                    this.previousScrollFocus = null;
                }
                Actor actor2 = stage.getScrollFocus();
                if (actor2 == null || isAscendantOf(actor2)) {
                    stage.setScrollFocus(this.previousScrollFocus);
                }
            }
            clearActions();
            this.selectBox.onHide(this);
        }

        @Override // com.badlogic.gdx.scenes.scene2d.ui.ScrollPane, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
        public void draw(Batch batch, float parentAlpha) {
            this.selectBox.localToStageCoordinates(SelectBox.temp.set(0.0f, 0.0f));
            if (!SelectBox.temp.equals(this.stagePosition)) {
                hide();
            }
            super.draw(batch, parentAlpha);
        }

        @Override // com.badlogic.gdx.scenes.scene2d.ui.ScrollPane, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
        public void act(float delta) {
            super.act(delta);
            toFront();
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
        public void setStage(Stage stage) {
            Stage oldStage = getStage();
            if (oldStage != null) {
                oldStage.removeCaptureListener(this.hideListener);
                oldStage.removeListener(this.list.getKeyListener());
            }
            super.setStage(stage);
        }
    }

    /* loaded from: classes.dex */
    public static class SelectBoxStyle {
        public Drawable background;
        public Drawable backgroundDisabled;
        public Drawable backgroundOpen;
        public Drawable backgroundOver;
        public Color disabledFontColor;
        public BitmapFont font;
        public Color fontColor = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        public List.ListStyle listStyle;
        public Color overFontColor;
        public ScrollPane.ScrollPaneStyle scrollStyle;

        public SelectBoxStyle() {
        }

        public SelectBoxStyle(BitmapFont font, Color fontColor, Drawable background, ScrollPane.ScrollPaneStyle scrollStyle, List.ListStyle listStyle) {
            this.font = font;
            this.fontColor.set(fontColor);
            this.background = background;
            this.scrollStyle = scrollStyle;
            this.listStyle = listStyle;
        }

        public SelectBoxStyle(SelectBoxStyle style) {
            this.font = style.font;
            this.fontColor.set(style.fontColor);
            Color color = style.overFontColor;
            if (color != null) {
                this.overFontColor = new Color(color);
            }
            Color color2 = style.disabledFontColor;
            if (color2 != null) {
                this.disabledFontColor = new Color(color2);
            }
            this.background = style.background;
            this.scrollStyle = new ScrollPane.ScrollPaneStyle(style.scrollStyle);
            this.listStyle = new List.ListStyle(style.listStyle);
            this.backgroundOver = style.backgroundOver;
            this.backgroundOpen = style.backgroundOpen;
            this.backgroundDisabled = style.backgroundDisabled;
        }
    }
}