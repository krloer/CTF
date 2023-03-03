package com.kotcrab.vis.ui;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.I18NBundle;
import com.kotcrab.vis.ui.i18n.BundleText;
import java.util.Locale;

/* loaded from: classes.dex */
public class Locales {
    private static I18NBundle buttonBarBundle;
    private static I18NBundle colorPickerBundle;
    private static I18NBundle commonBundle;
    private static I18NBundle dialogsBundle;
    private static I18NBundle fileChooserBundle;
    private static Locale locale = new Locale("en");
    private static I18NBundle tabbedPaneBundle;

    public static I18NBundle getCommonBundle() {
        if (commonBundle == null) {
            commonBundle = getBundle("com/kotcrab/vis/ui/i18n/Common");
        }
        return commonBundle;
    }

    public static void setCommonBundle(I18NBundle commonBundle2) {
        commonBundle = commonBundle2;
    }

    public static I18NBundle getFileChooserBundle() {
        if (fileChooserBundle == null) {
            fileChooserBundle = getBundle("com/kotcrab/vis/ui/i18n/FileChooser");
        }
        return fileChooserBundle;
    }

    public static void setFileChooserBundle(I18NBundle fileChooserBundle2) {
        fileChooserBundle = fileChooserBundle2;
    }

    public static I18NBundle getDialogsBundle() {
        if (dialogsBundle == null) {
            dialogsBundle = getBundle("com/kotcrab/vis/ui/i18n/Dialogs");
        }
        return dialogsBundle;
    }

    public static void setDialogsBundle(I18NBundle dialogsBundle2) {
        dialogsBundle = dialogsBundle2;
    }

    public static I18NBundle getTabbedPaneBundle() {
        if (tabbedPaneBundle == null) {
            tabbedPaneBundle = getBundle("com/kotcrab/vis/ui/i18n/TabbedPane");
        }
        return tabbedPaneBundle;
    }

    public static void setTabbedPaneBundle(I18NBundle tabbedPaneBundle2) {
        tabbedPaneBundle = tabbedPaneBundle2;
    }

    public static I18NBundle getColorPickerBundle() {
        if (colorPickerBundle == null) {
            colorPickerBundle = getBundle("com/kotcrab/vis/ui/i18n/ColorPicker");
        }
        return colorPickerBundle;
    }

    public static void setColorPickerBundle(I18NBundle colorPickerBundle2) {
        colorPickerBundle = colorPickerBundle2;
    }

    public static I18NBundle getButtonBarBundle() {
        if (buttonBarBundle == null) {
            buttonBarBundle = getBundle("com/kotcrab/vis/ui/i18n/ButtonBar");
        }
        return buttonBarBundle;
    }

    public static void setButtonBarBundle(I18NBundle buttonBarBundle2) {
        buttonBarBundle = buttonBarBundle2;
    }

    public static void setLocale(Locale locale2) {
        locale = locale2;
    }

    private static I18NBundle getBundle(String path) {
        FileHandle bundleFile = Gdx.files.classpath(path);
        return I18NBundle.createBundle(bundleFile, locale);
    }

    /* loaded from: classes.dex */
    public enum CommonText implements BundleText {
        PLEASE_WAIT("pleaseWait"),
        UNKNOWN_ERROR_OCCURRED("unknownErrorOccurred");
        
        private final String name;

        CommonText(String name) {
            this.name = name;
        }

        private static I18NBundle getBundle() {
            return Locales.getCommonBundle();
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
}