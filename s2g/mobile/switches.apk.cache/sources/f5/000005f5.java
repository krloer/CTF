package com.kotcrab.vis.ui.widget.color;

import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.utils.Disposable;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.ColorUtils;
import com.kotcrab.vis.ui.widget.VisTable;
import com.kotcrab.vis.ui.widget.color.BasicColorPicker;
import com.kotcrab.vis.ui.widget.color.internal.ChannelBar;
import com.kotcrab.vis.ui.widget.color.internal.ColorChannelWidget;
import com.kotcrab.vis.ui.widget.color.internal.Palette;
import com.kotcrab.vis.ui.widget.color.internal.VerticalChannelBar;

/* loaded from: classes.dex */
public class ExtendedColorPicker extends BasicColorPicker implements Disposable {
    private ColorChannelWidget aBar;
    private ColorChannelWidget bBar;
    private ColorChannelWidget gBar;
    private ColorChannelWidget hBar;
    private ColorChannelWidget rBar;
    private ColorChannelWidget sBar;
    private ColorChannelWidget vBar;

    public ExtendedColorPicker() {
        this(null);
    }

    public ExtendedColorPicker(ColorPickerListener listener) {
        this("default", listener);
    }

    public ExtendedColorPicker(String styleName, ColorPickerListener listener) {
        this((ColorPickerWidgetStyle) VisUI.getSkin().get(styleName, ColorPickerWidgetStyle.class), listener);
    }

    public ExtendedColorPicker(ColorPickerWidgetStyle style, ColorPickerListener listener) {
        super(style, listener, true);
        setAllowAlphaEdit(true);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.kotcrab.vis.ui.widget.color.BasicColorPicker
    public void createUI() {
        super.createUI();
        VisTable extendedTable = new VisTable(true);
        extendedTable.add(this.hBar).row();
        extendedTable.add(this.sBar).row();
        extendedTable.add(this.vBar).row();
        extendedTable.add();
        extendedTable.row();
        extendedTable.add(this.rBar).row();
        extendedTable.add(this.gBar).row();
        extendedTable.add(this.bBar).row();
        extendedTable.add();
        extendedTable.row();
        extendedTable.add(this.aBar).row();
        add((ExtendedColorPicker) extendedTable).expand().left().top().pad(0.0f, 9.0f, 4.0f, 4.0f);
    }

    @Override // com.kotcrab.vis.ui.widget.color.BasicColorPicker
    protected void createColorWidgets() {
        this.palette = new Palette(this.commons, 100, new BasicColorPicker.PickerChangeListener() { // from class: com.kotcrab.vis.ui.widget.color.ExtendedColorPicker.1
            @Override // com.kotcrab.vis.ui.widget.color.BasicColorPicker.PickerChangeListener
            public void updateLinkedWidget() {
                ExtendedColorPicker.this.sBar.setValue(ExtendedColorPicker.this.palette.getS());
                ExtendedColorPicker.this.vBar.setValue(ExtendedColorPicker.this.palette.getV());
            }
        });
        this.verticalBar = new VerticalChannelBar(this.commons, 360, new BasicColorPicker.PickerChangeListener() { // from class: com.kotcrab.vis.ui.widget.color.ExtendedColorPicker.2
            @Override // com.kotcrab.vis.ui.widget.color.BasicColorPicker.PickerChangeListener
            public void updateLinkedWidget() {
                ExtendedColorPicker.this.hBar.setValue(ExtendedColorPicker.this.verticalBar.getValue());
            }
        });
        HsvChannelBarListener svListener = new HsvChannelBarListener() { // from class: com.kotcrab.vis.ui.widget.color.ExtendedColorPicker.3
            @Override // com.kotcrab.vis.ui.widget.color.ExtendedColorPicker.HsvChannelBarListener
            protected void updateLinkedWidget() {
                ExtendedColorPicker.this.palette.setValue(ExtendedColorPicker.this.sBar.getValue(), ExtendedColorPicker.this.vBar.getValue());
            }
        };
        this.hBar = new ColorChannelWidget(this.commons, "H", 4, 360, new HsvChannelBarListener() { // from class: com.kotcrab.vis.ui.widget.color.ExtendedColorPicker.4
            @Override // com.kotcrab.vis.ui.widget.color.ExtendedColorPicker.HsvChannelBarListener
            protected void updateLinkedWidget() {
                ExtendedColorPicker.this.verticalBar.setValue(ExtendedColorPicker.this.hBar.getValue());
            }
        });
        this.sBar = new ColorChannelWidget(this.commons, "S", 5, 100, svListener);
        this.vBar = new ColorChannelWidget(this.commons, "V", 6, 100, svListener);
        RgbChannelBarListener rgbListener = new RgbChannelBarListener();
        this.rBar = new ColorChannelWidget(this.commons, "R", 1, 255, rgbListener);
        this.gBar = new ColorChannelWidget(this.commons, "G", 2, 255, rgbListener);
        this.bBar = new ColorChannelWidget(this.commons, "B", 3, 255, rgbListener);
        this.aBar = new ColorChannelWidget(this.commons, "A", 0, 255, new AlphaChannelBarListener());
    }

    @Override // com.kotcrab.vis.ui.widget.color.BasicColorPicker
    public void setAllowAlphaEdit(boolean allowAlphaEdit) {
        this.aBar.setVisible(allowAlphaEdit);
        super.setAllowAlphaEdit(allowAlphaEdit);
    }

    @Override // com.kotcrab.vis.ui.widget.color.BasicColorPicker
    protected void updateValuesFromCurrentColor() {
        int[] hsv = ColorUtils.RGBtoHSV(this.color);
        int ch = hsv[0];
        int cs = hsv[1];
        int cv = hsv[2];
        int cr = MathUtils.round(this.color.r * 255.0f);
        int cg = MathUtils.round(this.color.g * 255.0f);
        int cb = MathUtils.round(this.color.b * 255.0f);
        int ca = MathUtils.round(this.color.a * 255.0f);
        this.hBar.setValue(ch);
        this.sBar.setValue(cs);
        this.vBar.setValue(cv);
        this.rBar.setValue(cr);
        this.gBar.setValue(cg);
        this.bBar.setValue(cb);
        this.aBar.setValue(ca);
        this.verticalBar.setValue(this.hBar.getValue());
        this.palette.setValue(this.sBar.getValue(), this.vBar.getValue());
    }

    @Override // com.kotcrab.vis.ui.widget.color.BasicColorPicker
    protected void updateValuesFromHSVFields() {
        int[] hsv = ColorUtils.RGBtoHSV(this.color);
        int h = hsv[0];
        int s = hsv[1];
        int v = hsv[2];
        if (this.hBar.isInputValid()) {
            h = this.hBar.getValue();
        }
        if (this.sBar.isInputValid()) {
            s = this.sBar.getValue();
        }
        if (this.vBar.isInputValid()) {
            v = this.vBar.getValue();
        }
        this.color = ColorUtils.HSVtoRGB(h, s, v, this.color.a);
        int cr = MathUtils.round(this.color.r * 255.0f);
        int cg = MathUtils.round(this.color.g * 255.0f);
        int cb = MathUtils.round(this.color.b * 255.0f);
        this.rBar.setValue(cr);
        this.gBar.setValue(cg);
        this.bBar.setValue(cb);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateValuesFromRGBFields() {
        int r = MathUtils.round(this.color.r * 255.0f);
        int g = MathUtils.round(this.color.g * 255.0f);
        int b = MathUtils.round(this.color.b * 255.0f);
        if (this.rBar.isInputValid()) {
            r = this.rBar.getValue();
        }
        if (this.gBar.isInputValid()) {
            g = this.gBar.getValue();
        }
        if (this.bBar.isInputValid()) {
            b = this.bBar.getValue();
        }
        this.color.set(r / 255.0f, g / 255.0f, b / 255.0f, this.color.a);
        int[] hsv = ColorUtils.RGBtoHSV(this.color);
        int ch = hsv[0];
        int cs = hsv[1];
        int cv = hsv[2];
        this.hBar.setValue(ch);
        this.sBar.setValue(cs);
        this.vBar.setValue(cv);
        this.verticalBar.setValue(this.hBar.getValue());
        this.palette.setValue(this.sBar.getValue(), this.vBar.getValue());
    }

    /* loaded from: classes.dex */
    private class RgbChannelBarListener implements ChannelBar.ChannelBarListener {
        private RgbChannelBarListener() {
        }

        @Override // com.kotcrab.vis.ui.widget.color.internal.ChannelBar.ChannelBarListener
        public void updateFields() {
            ExtendedColorPicker.this.updateValuesFromRGBFields();
            ExtendedColorPicker.this.updateUI();
        }

        @Override // com.kotcrab.vis.ui.widget.color.internal.ChannelBar.ChannelBarListener
        public void setShaderUniforms(ShaderProgram shader) {
            shader.setUniformf("u_r", ExtendedColorPicker.this.color.r);
            shader.setUniformf("u_g", ExtendedColorPicker.this.color.g);
            shader.setUniformf("u_b", ExtendedColorPicker.this.color.b);
        }
    }

    /* loaded from: classes.dex */
    private class AlphaChannelBarListener extends RgbChannelBarListener {
        private AlphaChannelBarListener() {
            super();
        }

        @Override // com.kotcrab.vis.ui.widget.color.ExtendedColorPicker.RgbChannelBarListener, com.kotcrab.vis.ui.widget.color.internal.ChannelBar.ChannelBarListener
        public void updateFields() {
            if (ExtendedColorPicker.this.aBar.isInputValid()) {
                ExtendedColorPicker.this.color.a = ExtendedColorPicker.this.aBar.getValue() / 255.0f;
            }
            ExtendedColorPicker.this.updateUI();
        }
    }

    /* loaded from: classes.dex */
    private abstract class HsvChannelBarListener implements ChannelBar.ChannelBarListener {
        protected abstract void updateLinkedWidget();

        private HsvChannelBarListener() {
        }

        @Override // com.kotcrab.vis.ui.widget.color.internal.ChannelBar.ChannelBarListener
        public void updateFields() {
            updateLinkedWidget();
            ExtendedColorPicker.this.updateValuesFromHSVFields();
            ExtendedColorPicker.this.updateUI();
        }

        @Override // com.kotcrab.vis.ui.widget.color.internal.ChannelBar.ChannelBarListener
        public void setShaderUniforms(ShaderProgram shader) {
            shader.setUniformf("u_h", ExtendedColorPicker.this.hBar.getValue() / 360.0f);
            shader.setUniformf("u_s", ExtendedColorPicker.this.sBar.getValue() / 100.0f);
            shader.setUniformf("u_v", ExtendedColorPicker.this.vBar.getValue() / 100.0f);
        }
    }
}