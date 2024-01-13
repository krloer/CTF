package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Cursor;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.badlogic.gdx.scenes.scene2d.utils.ClickListener;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.CursorManager;

/* loaded from: classes.dex */
public class LinkLabel extends VisLabel {
    private static final Color tempColor = new Color();
    private ClickListener clickListener;
    private LinkLabelListener listener;
    private LinkLabelStyle style;
    private CharSequence url;

    /* loaded from: classes.dex */
    public interface LinkLabelListener {
        void clicked(String str);
    }

    public LinkLabel(CharSequence url) {
        super(url, (Label.LabelStyle) VisUI.getSkin().get(LinkLabelStyle.class));
        init(url);
    }

    public LinkLabel(CharSequence text, CharSequence url) {
        super(text, (Label.LabelStyle) VisUI.getSkin().get(LinkLabelStyle.class));
        init(url);
    }

    public LinkLabel(CharSequence text, int alignment) {
        super(text, (Label.LabelStyle) VisUI.getSkin().get(LinkLabelStyle.class));
        setAlignment(alignment);
        init(text);
    }

    public LinkLabel(CharSequence text, Color textColor) {
        super(text, (Label.LabelStyle) VisUI.getSkin().get(LinkLabelStyle.class));
        setColor(textColor);
        init(text);
    }

    public LinkLabel(CharSequence text, LinkLabelStyle style) {
        super(text, style);
        init(text);
    }

    public LinkLabel(CharSequence text, CharSequence url, String styleName) {
        super(text, (Label.LabelStyle) VisUI.getSkin().get(styleName, LinkLabelStyle.class));
        init(url);
    }

    public LinkLabel(CharSequence text, CharSequence url, LinkLabelStyle style) {
        super(text, style);
        init(url);
    }

    public LinkLabel(CharSequence text, String fontName, Color color) {
        super(text, new LinkLabelStyle(VisUI.getSkin().getFont(fontName), color, VisUI.getSkin().getDrawable("white")));
        init(text);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Label
    public LinkLabelStyle getStyle() {
        return (LinkLabelStyle) super.getStyle();
    }

    private void init(CharSequence linkUrl) {
        this.url = linkUrl;
        this.style = getStyle();
        ClickListener clickListener = new ClickListener(0) { // from class: com.kotcrab.vis.ui.widget.LinkLabel.1
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener
            public void clicked(InputEvent event, float x, float y) {
                super.clicked(event, x, y);
                if (LinkLabel.this.listener == null) {
                    Gdx.net.openURI(LinkLabel.this.url.toString());
                } else {
                    LinkLabel.this.listener.clicked(LinkLabel.this.url.toString());
                }
            }

            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
            public void enter(InputEvent event, float x, float y, int pointer, Actor fromActor) {
                super.enter(event, x, y, pointer, fromActor);
                Gdx.graphics.setSystemCursor(Cursor.SystemCursor.Hand);
            }

            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
            public void exit(InputEvent event, float x, float y, int pointer, Actor toActor) {
                super.exit(event, x, y, pointer, toActor);
                CursorManager.restoreDefaultCursor();
            }
        };
        this.clickListener = clickListener;
        addListener(clickListener);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Label, com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        super.draw(batch, parentAlpha);
        Drawable underline = this.style.underline;
        if (underline != null && this.clickListener.isOver()) {
            Color color = tempColor.set(getColor());
            color.a *= parentAlpha;
            if (this.style.fontColor != null) {
                color.mul(this.style.fontColor);
            }
            batch.setColor(color);
            underline.draw(batch, getX(), getY(), getWidth(), 1.0f);
        }
    }

    public CharSequence getUrl() {
        return this.url;
    }

    public void setUrl(CharSequence url) {
        this.url = url;
    }

    public LinkLabelListener getListener() {
        return this.listener;
    }

    public void setListener(LinkLabelListener listener) {
        this.listener = listener;
    }

    /* loaded from: classes.dex */
    public static class LinkLabelStyle extends Label.LabelStyle {
        public Drawable underline;

        public LinkLabelStyle() {
        }

        public LinkLabelStyle(BitmapFont font, Color fontColor, Drawable underline) {
            super(font, fontColor);
            this.underline = underline;
        }

        public LinkLabelStyle(LinkLabelStyle style) {
            super(style);
            this.underline = style.underline;
        }
    }
}