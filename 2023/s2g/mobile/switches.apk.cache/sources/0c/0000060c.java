package com.kotcrab.vis.ui.widget.color.internal;

import com.badlogic.gdx.utils.I18NBundle;
import com.kotcrab.vis.ui.Locales;
import com.kotcrab.vis.ui.i18n.BundleText;

/* loaded from: classes.dex */
public enum ColorPickerText implements BundleText {
    TITLE("title"),
    RESTORE("restore"),
    CANCEL("cancel"),
    OK("ok"),
    HEX("hex");
    
    private final String name;

    ColorPickerText(String name) {
        this.name = name;
    }

    private static I18NBundle getBundle() {
        return Locales.getColorPickerBundle();
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