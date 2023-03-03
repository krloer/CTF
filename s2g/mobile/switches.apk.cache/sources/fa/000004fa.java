package com.kotcrab.vis.ui;

/* loaded from: classes.dex */
public class Sizes {
    public float borderSize;
    public float buttonBarSpacing;
    public float fileChooserViewModeBigIconsSize;
    public float fileChooserViewModeListWidthSize;
    public float fileChooserViewModeMediumIconsSize;
    public float fileChooserViewModeSmallIconsSize;
    public float menuItemIconSize;
    public float scaleFactor;
    public float spacingBottom;
    public float spacingLeft;
    public float spacingRight;
    public float spacingTop;
    public float spinnerButtonHeight;
    public float spinnerFieldSize;

    public Sizes() {
    }

    public Sizes(Sizes other) {
        this.scaleFactor = other.scaleFactor;
        this.spacingTop = other.spacingTop;
        this.spacingBottom = other.spacingBottom;
        this.spacingRight = other.spacingRight;
        this.spacingLeft = other.spacingLeft;
        this.buttonBarSpacing = other.buttonBarSpacing;
        this.menuItemIconSize = other.menuItemIconSize;
        this.borderSize = other.borderSize;
        this.spinnerButtonHeight = other.spinnerButtonHeight;
        this.spinnerFieldSize = other.spinnerFieldSize;
        this.fileChooserViewModeBigIconsSize = other.fileChooserViewModeBigIconsSize;
        this.fileChooserViewModeMediumIconsSize = other.fileChooserViewModeMediumIconsSize;
        this.fileChooserViewModeSmallIconsSize = other.fileChooserViewModeSmallIconsSize;
        this.fileChooserViewModeListWidthSize = other.fileChooserViewModeListWidthSize;
    }
}