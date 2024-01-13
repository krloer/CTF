package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.math.Interpolation;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.EventListener;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.actions.Actions;
import com.badlogic.gdx.scenes.scene2d.ui.Cell;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Timer;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.ActorUtils;
import java.util.Iterator;

/* loaded from: classes.dex */
public class Tooltip extends VisTable {
    private float appearDelayTime;
    private Actor content;
    private Cell<Actor> contentCell;
    private DisplayTask displayTask;
    private float fadeTime;
    private TooltipInputListener listener;
    private boolean mouseMoveFadeOut;
    private Actor target;
    public static float DEFAULT_FADE_TIME = 0.3f;
    public static float DEFAULT_APPEAR_DELAY_TIME = 0.6f;
    public static boolean MOUSE_MOVED_FADEOUT = false;

    private Tooltip(Builder builder) {
        super(true);
        this.mouseMoveFadeOut = MOUSE_MOVED_FADEOUT;
        this.fadeTime = DEFAULT_FADE_TIME;
        this.appearDelayTime = DEFAULT_APPEAR_DELAY_TIME;
        TooltipStyle style = builder.style;
        init(style == null ? (TooltipStyle) VisUI.getSkin().get("default", TooltipStyle.class) : style, builder.target, builder.content);
        if (builder.width == -1.0f) {
            return;
        }
        this.contentCell.width(builder.width);
        pack();
    }

    public Tooltip() {
        this("default");
    }

    public Tooltip(String styleName) {
        super(true);
        this.mouseMoveFadeOut = MOUSE_MOVED_FADEOUT;
        this.fadeTime = DEFAULT_FADE_TIME;
        this.appearDelayTime = DEFAULT_APPEAR_DELAY_TIME;
        init((TooltipStyle) VisUI.getSkin().get(styleName, TooltipStyle.class), null, null);
    }

    public Tooltip(TooltipStyle style) {
        super(true);
        this.mouseMoveFadeOut = MOUSE_MOVED_FADEOUT;
        this.fadeTime = DEFAULT_FADE_TIME;
        this.appearDelayTime = DEFAULT_APPEAR_DELAY_TIME;
        init(style, null, null);
    }

    public static void removeTooltip(Actor target) {
        Array<EventListener> listeners = target.getListeners();
        Iterator it = listeners.iterator();
        while (it.hasNext()) {
            EventListener listener = (EventListener) it.next();
            if (listener instanceof TooltipInputListener) {
                target.removeListener(listener);
            }
        }
    }

    private void init(TooltipStyle style, Actor target, Actor content) {
        this.target = target;
        this.content = content;
        this.listener = new TooltipInputListener();
        this.displayTask = new DisplayTask();
        setBackground(style.background);
        this.contentCell = add((Tooltip) content).padLeft(3.0f).padRight(3.0f).padBottom(2.0f);
        pack();
        if (target != null) {
            attach();
        }
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.Tooltip.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                Tooltip.this.toFront();
                return true;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void enter(InputEvent event, float x, float y, int pointer, Actor fromActor) {
                if (pointer == -1) {
                    Tooltip.this.clearActions();
                    Tooltip tooltip = Tooltip.this;
                    tooltip.addAction(Actions.sequence(Actions.fadeIn(tooltip.fadeTime, Interpolation.fade)));
                }
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void exit(InputEvent event, float x, float y, int pointer, Actor toActor) {
                if (pointer == -1) {
                    Tooltip.this.fadeOut();
                }
            }
        });
    }

    public void attach() {
        Actor actor = this.target;
        if (actor == null) {
            return;
        }
        Array<EventListener> listeners = actor.getListeners();
        Iterator it = listeners.iterator();
        while (it.hasNext()) {
            EventListener listener = (EventListener) it.next();
            if (listener instanceof TooltipInputListener) {
                throw new IllegalStateException("More than one tooltip cannot be added to the same target!");
            }
        }
        this.target.addListener(this.listener);
    }

    public void detach() {
        Actor actor = this.target;
        if (actor == null) {
            return;
        }
        actor.removeListener(this.listener);
    }

    public void setTarget(Actor newTarget) {
        detach();
        this.target = newTarget;
        attach();
    }

    public Actor getTarget() {
        return this.target;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void fadeOut() {
        clearActions();
        addAction(Actions.sequence(Actions.fadeOut(this.fadeTime, Interpolation.fade), Actions.removeActor()));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public VisTable fadeIn() {
        clearActions();
        setColor(1.0f, 1.0f, 1.0f, 0.0f);
        addAction(Actions.sequence(Actions.fadeIn(this.fadeTime, Interpolation.fade)));
        return this;
    }

    public Actor getContent() {
        return this.content;
    }

    public void setContent(Actor content) {
        this.content = content;
        this.contentCell.setActor(content);
        pack();
    }

    public Cell<Actor> getContentCell() {
        return this.contentCell;
    }

    public void setText(String text) {
        Actor actor = this.content;
        if (actor instanceof VisLabel) {
            ((VisLabel) actor).setText(text);
        } else {
            setContent(new VisLabel(text));
        }
        pack();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void setPosition(float x, float y) {
        super.setPosition((int) x, (int) y);
    }

    public float getAppearDelayTime() {
        return this.appearDelayTime;
    }

    public void setAppearDelayTime(float appearDelayTime) {
        this.appearDelayTime = appearDelayTime;
    }

    public float getFadeTime() {
        return this.fadeTime;
    }

    public void setFadeTime(float fadeTime) {
        this.fadeTime = fadeTime;
    }

    public boolean isMouseMoveFadeOut() {
        return this.mouseMoveFadeOut;
    }

    public void setMouseMoveFadeOut(boolean mouseMoveFadeOut) {
        this.mouseMoveFadeOut = mouseMoveFadeOut;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class DisplayTask extends Timer.Task {
        private DisplayTask() {
        }

        @Override // com.badlogic.gdx.utils.Timer.Task, java.lang.Runnable
        public void run() {
            if (Tooltip.this.target.getStage() == null) {
                return;
            }
            Tooltip.this.target.getStage().addActor(Tooltip.this.fadeIn());
            ActorUtils.keepWithinStage(Tooltip.this.getStage(), Tooltip.this);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class TooltipInputListener extends InputListener {
        private TooltipInputListener() {
        }

        @Override // com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
            Tooltip.this.displayTask.cancel();
            Tooltip.this.toFront();
            Tooltip.this.fadeOut();
            return true;
        }

        @Override // com.badlogic.gdx.scenes.scene2d.InputListener
        public void enter(InputEvent event, float x, float y, int pointer, Actor fromActor) {
            if (pointer == -1) {
                Vector2 targetPos = Tooltip.this.target.localToStageCoordinates(new Vector2());
                Tooltip.this.setX(targetPos.x + ((Tooltip.this.target.getWidth() - Tooltip.this.getWidth()) / 2.0f));
                float tooltipY = (targetPos.y - Tooltip.this.getHeight()) - 6.0f;
                float stageHeight = Tooltip.this.target.getStage().getHeight();
                if (stageHeight - tooltipY > stageHeight) {
                    Tooltip.this.setY(targetPos.y + Tooltip.this.target.getHeight() + 6.0f);
                } else {
                    Tooltip.this.setY(tooltipY);
                }
                Tooltip.this.displayTask.cancel();
                Timer.schedule(Tooltip.this.displayTask, Tooltip.this.appearDelayTime);
            }
        }

        @Override // com.badlogic.gdx.scenes.scene2d.InputListener
        public void exit(InputEvent event, float x, float y, int pointer, Actor toActor) {
            if (pointer == -1) {
                Tooltip.this.displayTask.cancel();
                Tooltip.this.fadeOut();
            }
        }

        @Override // com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean mouseMoved(InputEvent event, float x, float y) {
            if (Tooltip.this.mouseMoveFadeOut && Tooltip.this.isVisible() && Tooltip.this.getActions().size == 0) {
                Tooltip.this.fadeOut();
                return false;
            }
            return false;
        }
    }

    /* loaded from: classes.dex */
    public static class TooltipStyle {
        public Drawable background;

        public TooltipStyle() {
        }

        public TooltipStyle(TooltipStyle style) {
            this.background = style.background;
        }

        public TooltipStyle(Drawable background) {
            this.background = background;
        }
    }

    /* loaded from: classes.dex */
    public static class Builder {
        private final Actor content;
        private TooltipStyle style;
        private Actor target;
        private float width;

        public Builder(Actor content) {
            this.target = null;
            this.style = null;
            this.width = -1.0f;
            this.content = content;
        }

        public Builder(String text) {
            this(text, 1);
        }

        public Builder(String text, int textAlign) {
            this.target = null;
            this.style = null;
            this.width = -1.0f;
            VisLabel label = new VisLabel(text);
            label.setAlignment(textAlign);
            this.content = label;
        }

        public Builder target(Actor target) {
            this.target = target;
            return this;
        }

        public Builder style(String styleName) {
            return style((TooltipStyle) VisUI.getSkin().get(styleName, TooltipStyle.class));
        }

        public Builder style(TooltipStyle style) {
            this.style = style;
            return this;
        }

        public Builder width(float width) {
            if (width < 0.0f) {
                throw new IllegalArgumentException("width must be > 0");
            }
            this.width = width;
            Actor actor = this.content;
            if (actor instanceof VisLabel) {
                ((VisLabel) actor).setWrap(true);
            }
            return this;
        }

        public Tooltip build() {
            return new Tooltip(this);
        }
    }
}