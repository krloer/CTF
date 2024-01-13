package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.scenes.scene2d.ui.Button;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.utils.ObjectMap;
import com.kotcrab.vis.ui.Locales;
import com.kotcrab.vis.ui.Sizes;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.OsUtils;

/* loaded from: classes.dex */
public class ButtonBar {
    public static final String LINUX_ORDER = "L H NYACBEFO R";
    public static final String OSX_ORDER = "L H BEF NYCOA R";
    public static final String WINDOWS_ORDER = "L H BEF YNOCA R";
    private ObjectMap<Character, Button> buttons;
    private boolean ignoreSpacing;
    private String order;
    private Sizes sizes;

    public ButtonBar() {
        this(VisUI.getSizes(), getDefaultOrder());
    }

    public ButtonBar(String order) {
        this(VisUI.getSizes(), order);
    }

    public ButtonBar(Sizes sizes) {
        this(sizes, getDefaultOrder());
    }

    public ButtonBar(Sizes sizes, String order) {
        this.buttons = new ObjectMap<>();
        if (sizes == null) {
            throw new IllegalArgumentException("sizes can't be null");
        }
        this.sizes = sizes;
        setOrder(order);
    }

    private static String getDefaultOrder() {
        if (OsUtils.isWindows()) {
            return WINDOWS_ORDER;
        }
        if (OsUtils.isMac()) {
            return OSX_ORDER;
        }
        return LINUX_ORDER;
    }

    public boolean isIgnoreSpacing() {
        return this.ignoreSpacing;
    }

    public void setIgnoreSpacing(boolean ignoreSpacing) {
        this.ignoreSpacing = ignoreSpacing;
    }

    public String getOrder() {
        return this.order;
    }

    public void setOrder(String order) {
        if (order == null) {
            throw new IllegalArgumentException("order can't be null");
        }
        this.order = order;
    }

    public void setButton(ButtonType type, ChangeListener listener) {
        setButton(type, type.getText(), listener);
    }

    public void setButton(ButtonType type, String text, ChangeListener listener) {
        setButton(type, new VisTextButton(text), listener);
    }

    public void setButton(ButtonType type, Button button) {
        setButton(type, button, (ChangeListener) null);
    }

    public void setButton(ButtonType type, Button button, ChangeListener listener) {
        if (type == null) {
            throw new IllegalArgumentException("type can't be null");
        }
        if (button == null) {
            throw new IllegalArgumentException("button can't be null");
        }
        if (this.buttons.containsKey(Character.valueOf(type.id))) {
            this.buttons.remove(Character.valueOf(type.id));
        }
        this.buttons.put(Character.valueOf(type.id), button);
        if (listener != null) {
            button.addListener(listener);
        }
    }

    public Button getButton(ButtonType type) {
        return this.buttons.get(Character.valueOf(type.getId()));
    }

    public VisTextButton getTextButton(ButtonType type) {
        return (VisTextButton) getButton(type);
    }

    public VisTable createTable() {
        VisTable table = new VisTable(true);
        table.left();
        boolean spacingValid = false;
        for (int i = 0; i < this.order.length(); i++) {
            char ch = this.order.charAt(i);
            if (!this.ignoreSpacing && ch == ' ' && spacingValid) {
                table.add().width(this.sizes.buttonBarSpacing);
                spacingValid = false;
            }
            Button button = this.buttons.get(Character.valueOf(ch));
            if (button != null) {
                table.add((VisTable) button);
                spacingValid = true;
            }
        }
        return table;
    }

    /* loaded from: classes.dex */
    public enum ButtonType {
        LEFT("left", 'L'),
        RIGHT("right", 'R'),
        HELP("help", 'H'),
        NO("no", 'N'),
        YES("yes", 'Y'),
        CANCEL("cancel", 'C'),
        BACK("back", 'B'),
        NEXT("next", 'E'),
        APPLY("apply", 'A'),
        FINISH("finish", 'F'),
        OK("ok", 'O');
        
        private final char id;
        private final String key;

        ButtonType(String key, char id) {
            this.key = key;
            this.id = id;
        }

        public char getId() {
            return this.id;
        }

        public final String getText() {
            return Locales.getButtonBarBundle().get(this.key);
        }

        @Override // java.lang.Enum
        public final String toString() {
            return getText();
        }
    }
}