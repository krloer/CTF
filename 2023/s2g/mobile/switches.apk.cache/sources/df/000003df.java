package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;

/* loaded from: classes.dex */
public class TextTooltip extends Tooltip<Label> {
    public TextTooltip(String text, Skin skin) {
        this(text, TooltipManager.getInstance(), (TextTooltipStyle) skin.get(TextTooltipStyle.class));
    }

    public TextTooltip(String text, Skin skin, String styleName) {
        this(text, TooltipManager.getInstance(), (TextTooltipStyle) skin.get(styleName, TextTooltipStyle.class));
    }

    public TextTooltip(String text, TextTooltipStyle style) {
        this(text, TooltipManager.getInstance(), style);
    }

    public TextTooltip(String text, TooltipManager manager, Skin skin) {
        this(text, manager, (TextTooltipStyle) skin.get(TextTooltipStyle.class));
    }

    public TextTooltip(String text, TooltipManager manager, Skin skin, String styleName) {
        this(text, manager, (TextTooltipStyle) skin.get(styleName, TextTooltipStyle.class));
    }

    public TextTooltip(String text, final TooltipManager manager, TextTooltipStyle style) {
        super(null, manager);
        final Label label = new Label(text, style.label);
        label.setWrap(true);
        this.container.setActor(label);
        this.container.width(new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.TextTooltip.1
            @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
            public float get(Actor context) {
                return Math.min(manager.maxWidth, label.getGlyphLayout().width);
            }
        });
        setStyle(style);
    }

    public void setStyle(TextTooltipStyle style) {
        if (style == null) {
            throw new NullPointerException("style cannot be null");
        }
        ((Label) this.container.getActor()).setStyle(style.label);
        this.container.setBackground(style.background);
        this.container.maxWidth(style.wrapWidth);
    }

    /* loaded from: classes.dex */
    public static class TextTooltipStyle {
        public Drawable background;
        public Label.LabelStyle label;
        public float wrapWidth;

        public TextTooltipStyle() {
        }

        public TextTooltipStyle(Label.LabelStyle label, Drawable background) {
            this.label = label;
            this.background = background;
        }

        public TextTooltipStyle(TextTooltipStyle style) {
            this.label = new Label.LabelStyle(style.label);
            this.background = style.background;
            this.wrapWidth = style.wrapWidth;
        }
    }
}