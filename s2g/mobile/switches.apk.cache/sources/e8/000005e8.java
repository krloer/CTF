package com.kotcrab.vis.ui.widget.color;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.ui.Image;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.ClickListener;
import com.badlogic.gdx.utils.Disposable;
import com.kotcrab.vis.ui.Sizes;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.ColorUtils;
import com.kotcrab.vis.ui.widget.VisLabel;
import com.kotcrab.vis.ui.widget.VisTable;
import com.kotcrab.vis.ui.widget.VisTextField;
import com.kotcrab.vis.ui.widget.VisValidatableTextField;
import com.kotcrab.vis.ui.widget.color.internal.AlphaImage;
import com.kotcrab.vis.ui.widget.color.internal.ColorPickerText;
import com.kotcrab.vis.ui.widget.color.internal.Palette;
import com.kotcrab.vis.ui.widget.color.internal.PickerCommons;
import com.kotcrab.vis.ui.widget.color.internal.VerticalChannelBar;

/* loaded from: classes.dex */
public class BasicColorPicker extends VisTable implements Disposable {
    public static final int BAR_HEIGHT = 12;
    public static final int BAR_WIDTH = 130;
    public static final int FIELD_WIDTH = 50;
    private static final int HEX_COLOR_LENGTH = 6;
    private static final int HEX_COLOR_LENGTH_WITH_ALPHA = 8;
    private static final int HEX_FIELD_WIDTH = 95;
    public static final int PALETTE_SIZE = 160;
    private static final float VERTICAL_BAR_WIDTH = 15.0f;
    private boolean allowAlphaEdit;
    Color color;
    private VisTable colorPreviewsTable;
    protected PickerCommons commons;
    private Image currentColorImg;
    private boolean disposed;
    private VisValidatableTextField hexField;
    private VisTable hexTable;
    protected ColorPickerListener listener;
    private VisTable mainTable;
    private Image newColorImg;
    Color oldColor;
    protected Palette palette;
    private boolean showHexFields;
    protected Sizes sizes;
    protected ColorPickerWidgetStyle style;
    protected VerticalChannelBar verticalBar;

    public BasicColorPicker() {
        this(null);
    }

    public BasicColorPicker(ColorPickerListener listener) {
        this("default", listener);
    }

    public BasicColorPicker(String styleName, ColorPickerListener listener) {
        this((ColorPickerWidgetStyle) VisUI.getSkin().get(styleName, ColorPickerWidgetStyle.class), listener, false);
    }

    public BasicColorPicker(ColorPickerWidgetStyle style, ColorPickerListener listener) {
        this(style, listener, false);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public BasicColorPicker(ColorPickerWidgetStyle style, ColorPickerListener listener, boolean loadExtendedShaders) {
        this.allowAlphaEdit = false;
        this.showHexFields = true;
        this.disposed = false;
        this.listener = listener;
        this.style = style;
        this.sizes = VisUI.getSizes();
        this.oldColor = new Color(Color.BLACK);
        this.color = new Color(Color.BLACK);
        this.commons = new PickerCommons(style, this.sizes, loadExtendedShaders);
        createColorWidgets();
        createUI();
        updateValuesFromCurrentColor();
        updateUI();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void createUI() {
        this.mainTable = new VisTable(true);
        this.colorPreviewsTable = createColorsPreviewTable();
        this.hexTable = createHexTable();
        rebuildMainTable();
        add((BasicColorPicker) this.mainTable).top();
    }

    private void rebuildMainTable() {
        this.mainTable.clearChildren();
        this.mainTable.add((VisTable) this.palette).size(this.sizes.scaleFactor * 160.0f);
        this.mainTable.add((VisTable) this.verticalBar).size(this.sizes.scaleFactor * VERTICAL_BAR_WIDTH, this.sizes.scaleFactor * 160.0f).top();
        this.mainTable.row();
        this.mainTable.add(this.colorPreviewsTable).colspan(2).expandX().fillX();
        if (this.showHexFields) {
            this.mainTable.row();
            this.mainTable.add(this.hexTable).colspan(2).expandX().left();
        }
    }

    private VisTable createColorsPreviewTable() {
        VisTable table = new VisTable(false);
        AlphaImage alphaImage = new AlphaImage(this.commons, this.sizes.scaleFactor * 5.0f);
        this.currentColorImg = alphaImage;
        table.add((VisTable) alphaImage).height(this.sizes.scaleFactor * 25.0f).width(this.sizes.scaleFactor * 80.0f).expandX().fillX();
        table.add((VisTable) new Image(this.style.iconArrowRight)).pad(0.0f, 2.0f, 0.0f, 2.0f);
        AlphaImage alphaImage2 = new AlphaImage(this.commons, this.sizes.scaleFactor * 5.0f);
        this.newColorImg = alphaImage2;
        table.add((VisTable) alphaImage2).height(this.sizes.scaleFactor * 25.0f).width(this.sizes.scaleFactor * 80.0f).expandX().fillX();
        this.currentColorImg.setColor(this.color);
        this.newColorImg.setColor(this.color);
        this.currentColorImg.addListener(new ClickListener() { // from class: com.kotcrab.vis.ui.widget.color.BasicColorPicker.1
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener
            public void clicked(InputEvent event, float x, float y) {
                BasicColorPicker.this.restoreLastColor();
            }
        });
        return table;
    }

    private VisTable createHexTable() {
        VisTable table = new VisTable(true);
        table.add((VisTable) new VisLabel(ColorPickerText.HEX.get()));
        VisValidatableTextField visValidatableTextField = new VisValidatableTextField("00000000");
        this.hexField = visValidatableTextField;
        table.add((VisTable) visValidatableTextField).width(this.sizes.scaleFactor * 95.0f);
        table.row();
        this.hexField.setMaxLength(6);
        this.hexField.setProgrammaticChangeEvents(false);
        this.hexField.setTextFieldFilter(new VisTextField.TextFieldFilter() { // from class: com.kotcrab.vis.ui.widget.color.BasicColorPicker.2
            @Override // com.kotcrab.vis.ui.widget.VisTextField.TextFieldFilter
            public boolean acceptChar(VisTextField textField, char c) {
                return Character.isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            }
        });
        this.hexField.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.color.BasicColorPicker.3
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                if (BasicColorPicker.this.hexField.getText().length() == (BasicColorPicker.this.allowAlphaEdit ? 8 : 6)) {
                    BasicColorPicker basicColorPicker = BasicColorPicker.this;
                    basicColorPicker.setColor(Color.valueOf(basicColorPicker.hexField.getText()), false);
                }
            }
        });
        return table;
    }

    protected void createColorWidgets() {
        PickerChangeListener pickerListener = new PickerChangeListener();
        this.palette = new Palette(this.commons, 100, pickerListener);
        this.verticalBar = new VerticalChannelBar(this.commons, 360, pickerListener);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void updateUI() {
        this.palette.setPickerHue(this.verticalBar.getValue());
        this.newColorImg.setColor(this.color);
        this.hexField.setText(this.color.toString().toUpperCase());
        VisValidatableTextField visValidatableTextField = this.hexField;
        visValidatableTextField.setCursorPosition(visValidatableTextField.getMaxLength());
        ColorPickerListener colorPickerListener = this.listener;
        if (colorPickerListener != null) {
            colorPickerListener.changed(this.color);
        }
    }

    protected void updateValuesFromCurrentColor() {
        int[] hsv = ColorUtils.RGBtoHSV(this.color);
        int ch = hsv[0];
        int cs = hsv[1];
        int cv = hsv[2];
        this.verticalBar.setValue(ch);
        this.palette.setValue(cs, cv);
    }

    protected void updateValuesFromHSVFields() {
        this.color = ColorUtils.HSVtoRGB(this.verticalBar.getValue(), this.palette.getS(), this.palette.getV(), this.color.a);
    }

    public void restoreLastColor() {
        Color colorBeforeReset = new Color(this.color);
        setColor(this.oldColor);
        ColorPickerListener colorPickerListener = this.listener;
        if (colorPickerListener != null) {
            colorPickerListener.reset(colorBeforeReset, this.color);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void setColor(Color newColor) {
        if (!this.allowAlphaEdit) {
            newColor.a = 1.0f;
        }
        setColor(newColor, true);
    }

    protected void setColor(Color newColor, boolean updateCurrentColor) {
        if (updateCurrentColor) {
            this.currentColorImg.setColor(new Color(newColor));
            this.oldColor = new Color(newColor);
        }
        this.color = new Color(newColor);
        updateValuesFromCurrentColor();
        updateUI();
    }

    public ColorPickerListener getListener() {
        return this.listener;
    }

    public void setListener(ColorPickerListener listener) {
        this.listener = listener;
    }

    public void setAllowAlphaEdit(boolean allowAlphaEdit) {
        this.allowAlphaEdit = allowAlphaEdit;
        this.hexField.setMaxLength(allowAlphaEdit ? 8 : 6);
        if (!allowAlphaEdit) {
            setColor(new Color(this.color));
        }
    }

    public boolean isAllowAlphaEdit() {
        return this.allowAlphaEdit;
    }

    public void setShowHexFields(boolean showHexFields) {
        this.showHexFields = showHexFields;
        this.hexTable.setVisible(showHexFields);
        rebuildMainTable();
    }

    public boolean isShowHexFields() {
        return this.showHexFields;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        boolean wasPedantic = ShaderProgram.pedantic;
        ShaderProgram.pedantic = false;
        super.draw(batch, parentAlpha);
        ShaderProgram.pedantic = wasPedantic;
    }

    public boolean isDisposed() {
        return this.disposed;
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        if (this.disposed) {
            throw new IllegalStateException("ColorPicker can't be disposed twice!");
        }
        this.commons.dispose();
        this.disposed = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class PickerChangeListener extends ChangeListener {
        /* JADX INFO: Access modifiers changed from: package-private */
        public PickerChangeListener() {
        }

        protected void updateLinkedWidget() {
        }

        @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
        public void changed(ChangeListener.ChangeEvent event, Actor actor) {
            updateLinkedWidget();
            BasicColorPicker.this.updateValuesFromHSVFields();
            BasicColorPicker.this.updateUI();
        }
    }
}