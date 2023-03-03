package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.graphics.g2d.GlyphLayout;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.utils.ArraySelection;
import com.badlogic.gdx.scenes.scene2d.utils.Cullable;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.UIUtils;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.ObjectSet;
import com.badlogic.gdx.utils.Pool;
import com.badlogic.gdx.utils.Pools;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class List<T> extends Widget implements Cullable {
    private int alignment;
    private Rectangle cullingArea;
    float itemHeight;
    final Array<T> items;
    private InputListener keyListener;
    int overIndex;
    private float prefHeight;
    private float prefWidth;
    int pressedIndex;
    ArraySelection<T> selection;
    ListStyle style;
    boolean typeToSelect;

    public List(Skin skin) {
        this((ListStyle) skin.get(ListStyle.class));
    }

    public List(Skin skin, String styleName) {
        this((ListStyle) skin.get(styleName, ListStyle.class));
    }

    public List(ListStyle style) {
        this.items = new Array<>();
        this.selection = new ArraySelection<>(this.items);
        this.alignment = 8;
        this.pressedIndex = -1;
        this.overIndex = -1;
        this.selection.setActor(this);
        this.selection.setRequired(true);
        setStyle(style);
        setSize(getPrefWidth(), getPrefHeight());
        InputListener inputListener = new InputListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.List.1
            String prefix;
            long typeTimeout;

            /* JADX WARN: Multi-variable type inference failed */
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyDown(InputEvent event, int keycode) {
                if (List.this.items.isEmpty()) {
                    return false;
                }
                if (keycode == 3) {
                    List.this.setSelectedIndex(0);
                    return true;
                }
                if (keycode != 29) {
                    if (keycode == 111) {
                        if (List.this.getStage() != null) {
                            List.this.getStage().setKeyboardFocus(null);
                        }
                        return true;
                    } else if (keycode == 123) {
                        List list = List.this;
                        list.setSelectedIndex(list.items.size - 1);
                        return true;
                    } else if (keycode == 19) {
                        int index = List.this.items.indexOf(List.this.getSelected(), false) - 1;
                        if (index < 0) {
                            index = List.this.items.size - 1;
                        }
                        List.this.setSelectedIndex(index);
                        return true;
                    } else if (keycode == 20) {
                        int index2 = List.this.items.indexOf(List.this.getSelected(), false) + 1;
                        if (index2 >= List.this.items.size) {
                            index2 = 0;
                        }
                        List.this.setSelectedIndex(index2);
                        return true;
                    }
                } else if (UIUtils.ctrl() && List.this.selection.getMultiple()) {
                    List.this.selection.clear();
                    List.this.selection.addAll(List.this.items);
                    return true;
                }
                return false;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyTyped(InputEvent event, char character) {
                if (List.this.typeToSelect) {
                    long time = System.currentTimeMillis();
                    if (time > this.typeTimeout) {
                        this.prefix = BuildConfig.FLAVOR;
                    }
                    this.typeTimeout = 300 + time;
                    this.prefix += Character.toLowerCase(character);
                    int i = 0;
                    int n = List.this.items.size;
                    while (true) {
                        if (i >= n) {
                            break;
                        }
                        List list = List.this;
                        if (!list.toString(list.items.get(i)).toLowerCase().startsWith(this.prefix)) {
                            i++;
                        } else {
                            List.this.setSelectedIndex(i);
                            break;
                        }
                    }
                    return false;
                }
                return false;
            }
        };
        this.keyListener = inputListener;
        addListener(inputListener);
        addListener(new InputListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.List.2
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                int index;
                if (pointer != 0 || button != 0 || List.this.selection.isDisabled()) {
                    return true;
                }
                if (List.this.getStage() != null) {
                    List.this.getStage().setKeyboardFocus(List.this);
                }
                if (List.this.items.size == 0 || (index = List.this.getItemIndexAt(y)) == -1) {
                    return true;
                }
                List.this.selection.choose(List.this.items.get(index));
                List.this.pressedIndex = index;
                return true;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                if (pointer != 0 || button != 0) {
                    return;
                }
                List.this.pressedIndex = -1;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchDragged(InputEvent event, float x, float y, int pointer) {
                List list = List.this;
                list.overIndex = list.getItemIndexAt(y);
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean mouseMoved(InputEvent event, float x, float y) {
                List list = List.this;
                list.overIndex = list.getItemIndexAt(y);
                return false;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void exit(InputEvent event, float x, float y, int pointer, Actor toActor) {
                if (pointer == 0) {
                    List.this.pressedIndex = -1;
                }
                if (pointer == -1) {
                    List.this.overIndex = -1;
                }
            }
        });
    }

    public void setStyle(ListStyle style) {
        if (style == null) {
            throw new IllegalArgumentException("style cannot be null.");
        }
        this.style = style;
        invalidateHierarchy();
    }

    public ListStyle getStyle() {
        return this.style;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void layout() {
        BitmapFont font = this.style.font;
        Drawable selectedDrawable = this.style.selection;
        this.itemHeight = font.getCapHeight() - (font.getDescent() * 2.0f);
        this.itemHeight += selectedDrawable.getTopHeight() + selectedDrawable.getBottomHeight();
        this.prefWidth = 0.0f;
        Pool<GlyphLayout> layoutPool = Pools.get(GlyphLayout.class);
        GlyphLayout layout = layoutPool.obtain();
        for (int i = 0; i < this.items.size; i++) {
            layout.setText(font, toString(this.items.get(i)));
            this.prefWidth = Math.max(layout.width, this.prefWidth);
        }
        layoutPool.free(layout);
        this.prefWidth += selectedDrawable.getLeftWidth() + selectedDrawable.getRightWidth();
        this.prefHeight = this.items.size * this.itemHeight;
        Drawable background = this.style.background;
        if (background != null) {
            this.prefWidth = Math.max(this.prefWidth + background.getLeftWidth() + background.getRightWidth(), background.getMinWidth());
            this.prefHeight = Math.max(this.prefHeight + background.getTopHeight() + background.getBottomHeight(), background.getMinHeight());
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        float x;
        float width;
        Drawable drawable;
        int i;
        Drawable background;
        validate();
        drawBackground(batch, parentAlpha);
        BitmapFont font = this.style.font;
        Drawable selectedDrawable = this.style.selection;
        Color fontColorSelected = this.style.fontColorSelected;
        Color fontColorUnselected = this.style.fontColorUnselected;
        Color color = getColor();
        batch.setColor(color.r, color.g, color.b, color.a * parentAlpha);
        float x2 = getX();
        float y = getY();
        float width2 = getWidth();
        float height = getHeight();
        float itemY = height;
        Drawable background2 = this.style.background;
        if (background2 == null) {
            x = x2;
            width = width2;
        } else {
            float leftWidth = background2.getLeftWidth();
            itemY -= background2.getTopHeight();
            x = x2 + leftWidth;
            width = width2 - (background2.getRightWidth() + leftWidth);
        }
        float textOffsetX = selectedDrawable.getLeftWidth();
        float textWidth = (width - textOffsetX) - selectedDrawable.getRightWidth();
        float textOffsetY = selectedDrawable.getTopHeight() - font.getDescent();
        font.setColor(fontColorUnselected.r, fontColorUnselected.g, fontColorUnselected.b, fontColorUnselected.a * parentAlpha);
        int i2 = 0;
        float itemY2 = itemY;
        while (i2 < this.items.size) {
            Rectangle rectangle = this.cullingArea;
            if (rectangle == null || (itemY2 - this.itemHeight <= rectangle.y + this.cullingArea.height && itemY2 >= this.cullingArea.y)) {
                T item = this.items.get(i2);
                boolean selected = this.selection.contains(item);
                if (this.pressedIndex == i2 && this.style.down != null) {
                    Drawable drawable2 = this.style.down;
                    drawable = drawable2;
                } else if (selected) {
                    font.setColor(fontColorSelected.r, fontColorSelected.g, fontColorSelected.b, fontColorSelected.a * parentAlpha);
                    drawable = selectedDrawable;
                } else if (this.overIndex == i2 && this.style.over != null) {
                    Drawable drawable3 = this.style.over;
                    drawable = drawable3;
                } else {
                    drawable = null;
                }
                if (drawable != null) {
                    float f = this.itemHeight;
                    drawable.draw(batch, x, (y + itemY2) - f, width, f);
                }
                i = i2;
                background = background2;
                drawItem(batch, font, i2, item, x + textOffsetX, (y + itemY2) - textOffsetY, textWidth);
                if (selected) {
                    font.setColor(fontColorUnselected.r, fontColorUnselected.g, fontColorUnselected.b, fontColorUnselected.a * parentAlpha);
                }
            } else if (itemY2 >= this.cullingArea.y) {
                i = i2;
                background = background2;
            } else {
                return;
            }
            itemY2 -= this.itemHeight;
            i2 = i + 1;
            background2 = background;
        }
    }

    protected void drawBackground(Batch batch, float parentAlpha) {
        if (this.style.background != null) {
            Color color = getColor();
            batch.setColor(color.r, color.g, color.b, color.a * parentAlpha);
            this.style.background.draw(batch, getX(), getY(), getWidth(), getHeight());
        }
    }

    protected GlyphLayout drawItem(Batch batch, BitmapFont font, int index, T item, float x, float y, float width) {
        String string = toString(item);
        return font.draw(batch, string, x, y, 0, string.length(), width, this.alignment, false, "...");
    }

    public ArraySelection<T> getSelection() {
        return this.selection;
    }

    public void setSelection(ArraySelection<T> selection) {
        this.selection = selection;
    }

    public T getSelected() {
        return this.selection.first();
    }

    public void setSelected(T item) {
        if (this.items.contains(item, false)) {
            this.selection.set(item);
        } else if (this.selection.getRequired() && this.items.size > 0) {
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
        if (index < -1 || index >= this.items.size) {
            throw new IllegalArgumentException("index must be >= -1 and < " + this.items.size + ": " + index);
        } else if (index == -1) {
            this.selection.clear();
        } else {
            this.selection.set(this.items.get(index));
        }
    }

    public T getOverItem() {
        int i = this.overIndex;
        if (i == -1) {
            return null;
        }
        return this.items.get(i);
    }

    public T getPressedItem() {
        int i = this.pressedIndex;
        if (i == -1) {
            return null;
        }
        return this.items.get(i);
    }

    public T getItemAt(float y) {
        int index = getItemIndexAt(y);
        if (index == -1) {
            return null;
        }
        return this.items.get(index);
    }

    public int getItemIndexAt(float y) {
        float height = getHeight();
        Drawable background = this.style.background;
        if (background != null) {
            height -= background.getTopHeight() + background.getBottomHeight();
            y -= background.getBottomHeight();
        }
        int index = (int) ((height - y) / this.itemHeight);
        if (index < 0 || index >= this.items.size) {
            return -1;
        }
        return index;
    }

    public void setItems(T... newItems) {
        if (newItems == null) {
            throw new IllegalArgumentException("newItems cannot be null.");
        }
        float oldPrefWidth = getPrefWidth();
        float oldPrefHeight = getPrefHeight();
        this.items.clear();
        this.items.addAll(newItems);
        this.overIndex = -1;
        this.pressedIndex = -1;
        this.selection.validate();
        invalidate();
        if (oldPrefWidth != getPrefWidth() || oldPrefHeight != getPrefHeight()) {
            invalidateHierarchy();
        }
    }

    public void setItems(Array newItems) {
        if (newItems == null) {
            throw new IllegalArgumentException("newItems cannot be null.");
        }
        float oldPrefWidth = getPrefWidth();
        float oldPrefHeight = getPrefHeight();
        Array<T> array = this.items;
        if (newItems != array) {
            array.clear();
            this.items.addAll(newItems);
        }
        this.overIndex = -1;
        this.pressedIndex = -1;
        this.selection.validate();
        invalidate();
        if (oldPrefWidth != getPrefWidth() || oldPrefHeight != getPrefHeight()) {
            invalidateHierarchy();
        }
    }

    public void clearItems() {
        if (this.items.size == 0) {
            return;
        }
        this.items.clear();
        this.overIndex = -1;
        this.pressedIndex = -1;
        this.selection.clear();
        invalidateHierarchy();
    }

    public Array<T> getItems() {
        return this.items;
    }

    public float getItemHeight() {
        return this.itemHeight;
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

    public String toString(T object) {
        return object.toString();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Cullable
    public void setCullingArea(Rectangle cullingArea) {
        this.cullingArea = cullingArea;
    }

    public Rectangle getCullingArea() {
        return this.cullingArea;
    }

    public void setAlignment(int alignment) {
        this.alignment = alignment;
    }

    public void setTypeToSelect(boolean typeToSelect) {
        this.typeToSelect = typeToSelect;
    }

    public InputListener getKeyListener() {
        return this.keyListener;
    }

    /* loaded from: classes.dex */
    public static class ListStyle {
        public Drawable background;
        public Drawable down;
        public BitmapFont font;
        public Color fontColorSelected = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        public Color fontColorUnselected = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        public Drawable over;
        public Drawable selection;

        public ListStyle() {
        }

        public ListStyle(BitmapFont font, Color fontColorSelected, Color fontColorUnselected, Drawable selection) {
            this.font = font;
            this.fontColorSelected.set(fontColorSelected);
            this.fontColorUnselected.set(fontColorUnselected);
            this.selection = selection;
        }

        public ListStyle(ListStyle style) {
            this.font = style.font;
            this.fontColorSelected.set(style.fontColorSelected);
            this.fontColorUnselected.set(style.fontColorUnselected);
            this.selection = style.selection;
            this.down = style.down;
            this.over = style.over;
            this.background = style.background;
        }
    }
}