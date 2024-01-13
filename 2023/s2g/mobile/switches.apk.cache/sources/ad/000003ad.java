package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.glutils.ShapeRenderer;
import com.badlogic.gdx.math.Interpolation;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Event;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.utils.ActorGestureListener;
import com.badlogic.gdx.scenes.scene2d.utils.Cullable;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.Layout;

/* loaded from: classes.dex */
public class ScrollPane extends WidgetGroup {
    float amountX;
    float amountY;
    boolean cancelTouchFocus;
    private boolean clamp;
    boolean disableX;
    boolean disableY;
    int draggingPointer;
    float fadeAlpha;
    float fadeAlphaSeconds;
    float fadeDelay;
    float fadeDelaySeconds;
    boolean fadeScrollBars;
    boolean flickScroll;
    private ActorGestureListener flickScrollListener;
    float flingTime;
    float flingTimer;
    private boolean forceScrollX;
    private boolean forceScrollY;
    final Rectangle hKnobBounds;
    final Rectangle hScrollBounds;
    boolean hScrollOnBottom;
    final Vector2 lastPoint;
    float maxX;
    float maxY;
    private float overscrollDistance;
    private float overscrollSpeedMax;
    private float overscrollSpeedMin;
    private boolean overscrollX;
    private boolean overscrollY;
    boolean scrollBarTouch;
    boolean scrollX;
    boolean scrollY;
    private boolean scrollbarsOnTop;
    boolean smoothScrolling;
    private ScrollPaneStyle style;
    boolean touchScrollH;
    boolean touchScrollV;
    final Rectangle vKnobBounds;
    final Rectangle vScrollBounds;
    boolean vScrollOnRight;
    private boolean variableSizeKnobs;
    float velocityX;
    float velocityY;
    float visualAmountX;
    float visualAmountY;
    private Actor widget;
    final Rectangle widgetArea;
    private final Rectangle widgetCullingArea;

    public ScrollPane(Actor widget) {
        this(widget, new ScrollPaneStyle());
    }

    public ScrollPane(Actor widget, Skin skin) {
        this(widget, (ScrollPaneStyle) skin.get(ScrollPaneStyle.class));
    }

    public ScrollPane(Actor widget, Skin skin, String styleName) {
        this(widget, (ScrollPaneStyle) skin.get(styleName, ScrollPaneStyle.class));
    }

    public ScrollPane(Actor widget, ScrollPaneStyle style) {
        this.widgetArea = new Rectangle();
        this.hScrollBounds = new Rectangle();
        this.hKnobBounds = new Rectangle();
        this.vScrollBounds = new Rectangle();
        this.vKnobBounds = new Rectangle();
        this.widgetCullingArea = new Rectangle();
        this.vScrollOnRight = true;
        this.hScrollOnBottom = true;
        this.lastPoint = new Vector2();
        this.fadeScrollBars = true;
        this.smoothScrolling = true;
        this.scrollBarTouch = true;
        this.fadeAlphaSeconds = 1.0f;
        this.fadeDelaySeconds = 1.0f;
        this.cancelTouchFocus = true;
        this.flickScroll = true;
        this.flingTime = 1.0f;
        this.overscrollX = true;
        this.overscrollY = true;
        this.overscrollDistance = 50.0f;
        this.overscrollSpeedMin = 30.0f;
        this.overscrollSpeedMax = 200.0f;
        this.clamp = true;
        this.variableSizeKnobs = true;
        this.draggingPointer = -1;
        if (style == null) {
            throw new IllegalArgumentException("style cannot be null.");
        }
        this.style = style;
        setActor(widget);
        setSize(150.0f, 150.0f);
        addCaptureListener();
        this.flickScrollListener = getFlickScrollListener();
        addListener(this.flickScrollListener);
        addScrollListener();
    }

    protected void addCaptureListener() {
        addCaptureListener(new InputListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.ScrollPane.1
            private float handlePosition;

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                if (ScrollPane.this.draggingPointer != -1) {
                    return false;
                }
                if (pointer != 0 || button == 0) {
                    if (ScrollPane.this.getStage() != null) {
                        ScrollPane.this.getStage().setScrollFocus(ScrollPane.this);
                    }
                    if (!ScrollPane.this.flickScroll) {
                        ScrollPane.this.setScrollbarsVisible(true);
                    }
                    if (ScrollPane.this.fadeAlpha == 0.0f) {
                        return false;
                    }
                    if (ScrollPane.this.scrollBarTouch && ScrollPane.this.scrollX && ScrollPane.this.hScrollBounds.contains(x, y)) {
                        event.stop();
                        ScrollPane.this.setScrollbarsVisible(true);
                        if (ScrollPane.this.hKnobBounds.contains(x, y)) {
                            ScrollPane.this.lastPoint.set(x, y);
                            this.handlePosition = ScrollPane.this.hKnobBounds.x;
                            ScrollPane scrollPane = ScrollPane.this;
                            scrollPane.touchScrollH = true;
                            scrollPane.draggingPointer = pointer;
                            return true;
                        }
                        ScrollPane scrollPane2 = ScrollPane.this;
                        scrollPane2.setScrollX(scrollPane2.amountX + (ScrollPane.this.widgetArea.width * (x >= ScrollPane.this.hKnobBounds.x ? 1 : -1)));
                        return true;
                    } else if (ScrollPane.this.scrollBarTouch && ScrollPane.this.scrollY && ScrollPane.this.vScrollBounds.contains(x, y)) {
                        event.stop();
                        ScrollPane.this.setScrollbarsVisible(true);
                        if (ScrollPane.this.vKnobBounds.contains(x, y)) {
                            ScrollPane.this.lastPoint.set(x, y);
                            this.handlePosition = ScrollPane.this.vKnobBounds.y;
                            ScrollPane scrollPane3 = ScrollPane.this;
                            scrollPane3.touchScrollV = true;
                            scrollPane3.draggingPointer = pointer;
                            return true;
                        }
                        ScrollPane scrollPane4 = ScrollPane.this;
                        scrollPane4.setScrollY(scrollPane4.amountY + (ScrollPane.this.widgetArea.height * (y < ScrollPane.this.vKnobBounds.y ? 1 : -1)));
                        return true;
                    } else {
                        return false;
                    }
                }
                return false;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                if (pointer != ScrollPane.this.draggingPointer) {
                    return;
                }
                ScrollPane.this.cancel();
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchDragged(InputEvent event, float x, float y, int pointer) {
                if (pointer != ScrollPane.this.draggingPointer) {
                    return;
                }
                if (ScrollPane.this.touchScrollH) {
                    float delta = x - ScrollPane.this.lastPoint.x;
                    float scrollH = this.handlePosition + delta;
                    this.handlePosition = scrollH;
                    float scrollH2 = Math.min((ScrollPane.this.hScrollBounds.x + ScrollPane.this.hScrollBounds.width) - ScrollPane.this.hKnobBounds.width, Math.max(ScrollPane.this.hScrollBounds.x, scrollH));
                    float total = ScrollPane.this.hScrollBounds.width - ScrollPane.this.hKnobBounds.width;
                    if (total != 0.0f) {
                        ScrollPane scrollPane = ScrollPane.this;
                        scrollPane.setScrollPercentX((scrollH2 - scrollPane.hScrollBounds.x) / total);
                    }
                    ScrollPane.this.lastPoint.set(x, y);
                } else if (ScrollPane.this.touchScrollV) {
                    float delta2 = y - ScrollPane.this.lastPoint.y;
                    float scrollV = this.handlePosition + delta2;
                    this.handlePosition = scrollV;
                    float scrollV2 = Math.min((ScrollPane.this.vScrollBounds.y + ScrollPane.this.vScrollBounds.height) - ScrollPane.this.vKnobBounds.height, Math.max(ScrollPane.this.vScrollBounds.y, scrollV));
                    float total2 = ScrollPane.this.vScrollBounds.height - ScrollPane.this.vKnobBounds.height;
                    if (total2 != 0.0f) {
                        ScrollPane scrollPane2 = ScrollPane.this;
                        scrollPane2.setScrollPercentY(1.0f - ((scrollV2 - scrollPane2.vScrollBounds.y) / total2));
                    }
                    ScrollPane.this.lastPoint.set(x, y);
                }
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean mouseMoved(InputEvent event, float x, float y) {
                if (!ScrollPane.this.flickScroll) {
                    ScrollPane.this.setScrollbarsVisible(true);
                    return false;
                }
                return false;
            }
        });
    }

    protected ActorGestureListener getFlickScrollListener() {
        return new ActorGestureListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.ScrollPane.2
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ActorGestureListener
            public void pan(InputEvent event, float x, float y, float deltaX, float deltaY) {
                ScrollPane.this.setScrollbarsVisible(true);
                ScrollPane.this.amountX -= deltaX;
                ScrollPane.this.amountY += deltaY;
                ScrollPane.this.clamp();
                if (ScrollPane.this.cancelTouchFocus) {
                    if ((!ScrollPane.this.scrollX || deltaX == 0.0f) && (!ScrollPane.this.scrollY || deltaY == 0.0f)) {
                        return;
                    }
                    ScrollPane.this.cancelTouchFocus();
                }
            }

            @Override // com.badlogic.gdx.scenes.scene2d.utils.ActorGestureListener
            public void fling(InputEvent event, float x, float y, int button) {
                if (Math.abs(x) > 150.0f && ScrollPane.this.scrollX) {
                    ScrollPane scrollPane = ScrollPane.this;
                    scrollPane.flingTimer = scrollPane.flingTime;
                    ScrollPane scrollPane2 = ScrollPane.this;
                    scrollPane2.velocityX = x;
                    if (scrollPane2.cancelTouchFocus) {
                        ScrollPane.this.cancelTouchFocus();
                    }
                }
                if (Math.abs(y) > 150.0f && ScrollPane.this.scrollY) {
                    ScrollPane scrollPane3 = ScrollPane.this;
                    scrollPane3.flingTimer = scrollPane3.flingTime;
                    ScrollPane scrollPane4 = ScrollPane.this;
                    scrollPane4.velocityY = -y;
                    if (scrollPane4.cancelTouchFocus) {
                        ScrollPane.this.cancelTouchFocus();
                    }
                }
            }

            @Override // com.badlogic.gdx.scenes.scene2d.utils.ActorGestureListener, com.badlogic.gdx.scenes.scene2d.EventListener
            public boolean handle(Event event) {
                if (super.handle(event)) {
                    if (((InputEvent) event).getType() == InputEvent.Type.touchDown) {
                        ScrollPane.this.flingTimer = 0.0f;
                        return true;
                    }
                    return true;
                } else if ((event instanceof InputEvent) && ((InputEvent) event).isTouchFocusCancel()) {
                    ScrollPane.this.cancel();
                    return false;
                } else {
                    return false;
                }
            }
        };
    }

    protected void addScrollListener() {
        addListener(new InputListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.ScrollPane.3
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean scrolled(InputEvent event, float x, float y, float scrollAmountX, float scrollAmountY) {
                ScrollPane.this.setScrollbarsVisible(true);
                if (ScrollPane.this.scrollY || ScrollPane.this.scrollX) {
                    if (ScrollPane.this.scrollY) {
                        if (!ScrollPane.this.scrollX && scrollAmountY == 0.0f) {
                            scrollAmountY = scrollAmountX;
                        }
                    } else if (ScrollPane.this.scrollX && scrollAmountX == 0.0f) {
                        scrollAmountX = scrollAmountY;
                    }
                    ScrollPane scrollPane = ScrollPane.this;
                    scrollPane.setScrollY(scrollPane.amountY + (ScrollPane.this.getMouseWheelY() * scrollAmountY));
                    ScrollPane scrollPane2 = ScrollPane.this;
                    scrollPane2.setScrollX(scrollPane2.amountX + (ScrollPane.this.getMouseWheelX() * scrollAmountX));
                    return true;
                }
                return false;
            }
        });
    }

    public void setScrollbarsVisible(boolean visible) {
        if (visible) {
            this.fadeAlpha = this.fadeAlphaSeconds;
            this.fadeDelay = this.fadeDelaySeconds;
            return;
        }
        this.fadeAlpha = 0.0f;
        this.fadeDelay = 0.0f;
    }

    public void cancelTouchFocus() {
        Stage stage = getStage();
        if (stage != null) {
            stage.cancelTouchFocusExcept(this.flickScrollListener, this);
        }
    }

    public void cancel() {
        this.draggingPointer = -1;
        this.touchScrollH = false;
        this.touchScrollV = false;
        this.flickScrollListener.getGestureDetector().cancel();
    }

    void clamp() {
        float clamp;
        float clamp2;
        if (this.clamp) {
            if (this.overscrollX) {
                float f = this.amountX;
                float f2 = this.overscrollDistance;
                clamp = MathUtils.clamp(f, -f2, this.maxX + f2);
            } else {
                clamp = MathUtils.clamp(this.amountX, 0.0f, this.maxX);
            }
            scrollX(clamp);
            if (this.overscrollY) {
                float f3 = this.amountY;
                float f4 = this.overscrollDistance;
                clamp2 = MathUtils.clamp(f3, -f4, this.maxY + f4);
            } else {
                clamp2 = MathUtils.clamp(this.amountY, 0.0f, this.maxY);
            }
            scrollY(clamp2);
        }
    }

    public void setStyle(ScrollPaneStyle style) {
        if (style == null) {
            throw new IllegalArgumentException("style cannot be null.");
        }
        this.style = style;
        invalidateHierarchy();
    }

    public ScrollPaneStyle getStyle() {
        return this.style;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void act(float delta) {
        Stage stage;
        super.act(delta);
        boolean panning = this.flickScrollListener.getGestureDetector().isPanning();
        boolean animating = false;
        float f = this.fadeAlpha;
        if (f > 0.0f && this.fadeScrollBars && !panning && !this.touchScrollH && !this.touchScrollV) {
            this.fadeDelay -= delta;
            if (this.fadeDelay <= 0.0f) {
                this.fadeAlpha = Math.max(0.0f, f - delta);
            }
            animating = true;
        }
        if (this.flingTimer > 0.0f) {
            setScrollbarsVisible(true);
            float alpha = this.flingTimer / this.flingTime;
            this.amountX -= (this.velocityX * alpha) * delta;
            this.amountY -= (this.velocityY * alpha) * delta;
            clamp();
            if (this.amountX == (-this.overscrollDistance)) {
                this.velocityX = 0.0f;
            }
            if (this.amountX >= this.maxX + this.overscrollDistance) {
                this.velocityX = 0.0f;
            }
            if (this.amountY == (-this.overscrollDistance)) {
                this.velocityY = 0.0f;
            }
            if (this.amountY >= this.maxY + this.overscrollDistance) {
                this.velocityY = 0.0f;
            }
            this.flingTimer -= delta;
            if (this.flingTimer <= 0.0f) {
                this.velocityX = 0.0f;
                this.velocityY = 0.0f;
            }
            animating = true;
        }
        if (this.smoothScrolling && this.flingTimer <= 0.0f && !panning && ((!this.touchScrollH || (this.scrollX && this.maxX / (this.hScrollBounds.width - this.hKnobBounds.width) > this.widgetArea.width * 0.1f)) && (!this.touchScrollV || (this.scrollY && this.maxY / (this.vScrollBounds.height - this.vKnobBounds.height) > this.widgetArea.height * 0.1f)))) {
            float f2 = this.visualAmountX;
            float f3 = this.amountX;
            if (f2 != f3) {
                if (f2 < f3) {
                    visualScrollX(Math.min(f3, f2 + Math.max(delta * 200.0f, (f3 - f2) * 7.0f * delta)));
                } else {
                    visualScrollX(Math.max(f3, f2 - Math.max(delta * 200.0f, ((f2 - f3) * 7.0f) * delta)));
                }
                animating = true;
            }
            float f4 = this.visualAmountY;
            float f5 = this.amountY;
            if (f4 != f5) {
                if (f4 < f5) {
                    visualScrollY(Math.min(f5, f4 + Math.max(200.0f * delta, (f5 - f4) * 7.0f * delta)));
                } else {
                    visualScrollY(Math.max(f5, f4 - Math.max(200.0f * delta, ((f4 - f5) * 7.0f) * delta)));
                }
                animating = true;
            }
        } else {
            float f6 = this.visualAmountX;
            float f7 = this.amountX;
            if (f6 != f7) {
                visualScrollX(f7);
            }
            float f8 = this.visualAmountY;
            float f9 = this.amountY;
            if (f8 != f9) {
                visualScrollY(f9);
            }
        }
        if (!panning) {
            if (this.overscrollX && this.scrollX) {
                float f10 = this.amountX;
                if (f10 < 0.0f) {
                    setScrollbarsVisible(true);
                    float f11 = this.amountX;
                    float f12 = this.overscrollSpeedMin;
                    this.amountX = f11 + ((f12 + (((this.overscrollSpeedMax - f12) * (-f11)) / this.overscrollDistance)) * delta);
                    if (this.amountX > 0.0f) {
                        scrollX(0.0f);
                    }
                    animating = true;
                } else if (f10 > this.maxX) {
                    setScrollbarsVisible(true);
                    float f13 = this.amountX;
                    float f14 = this.overscrollSpeedMin;
                    float f15 = this.maxX;
                    this.amountX = f13 - ((f14 + (((this.overscrollSpeedMax - f14) * (-(f15 - f13))) / this.overscrollDistance)) * delta);
                    if (this.amountX < f15) {
                        scrollX(f15);
                    }
                    animating = true;
                }
            }
            if (this.overscrollY && this.scrollY) {
                float f16 = this.amountY;
                if (f16 < 0.0f) {
                    setScrollbarsVisible(true);
                    float f17 = this.amountY;
                    float f18 = this.overscrollSpeedMin;
                    this.amountY = f17 + ((f18 + (((this.overscrollSpeedMax - f18) * (-f17)) / this.overscrollDistance)) * delta);
                    if (this.amountY > 0.0f) {
                        scrollY(0.0f);
                    }
                    animating = true;
                } else if (f16 > this.maxY) {
                    setScrollbarsVisible(true);
                    float f19 = this.amountY;
                    float f20 = this.overscrollSpeedMin;
                    float f21 = this.maxY;
                    this.amountY = f19 - ((f20 + (((this.overscrollSpeedMax - f20) * (-(f21 - f19))) / this.overscrollDistance)) * delta);
                    if (this.amountY < f21) {
                        scrollY(f21);
                    }
                    animating = true;
                }
            }
        }
        if (!animating || (stage = getStage()) == null || !stage.getActionsRequestRendering()) {
            return;
        }
        Gdx.graphics.requestRendering();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void layout() {
        float widgetWidth;
        float widgetHeight;
        float bgLeftWidth;
        float bgBottomHeight;
        Drawable bg = this.style.background;
        Drawable hScrollKnob = this.style.hScrollKnob;
        Drawable vScrollKnob = this.style.vScrollKnob;
        float bgLeftWidth2 = 0.0f;
        float bgRightWidth = 0.0f;
        float bgTopHeight = 0.0f;
        float bgBottomHeight2 = 0.0f;
        if (bg != null) {
            bgLeftWidth2 = bg.getLeftWidth();
            bgRightWidth = bg.getRightWidth();
            bgTopHeight = bg.getTopHeight();
            bgBottomHeight2 = bg.getBottomHeight();
        }
        float width = getWidth();
        float height = getHeight();
        this.widgetArea.set(bgLeftWidth2, bgBottomHeight2, (width - bgLeftWidth2) - bgRightWidth, (height - bgTopHeight) - bgBottomHeight2);
        if (this.widget == null) {
            return;
        }
        float scrollbarHeight = hScrollKnob != null ? hScrollKnob.getMinHeight() : 0.0f;
        if (this.style.hScroll != null) {
            scrollbarHeight = Math.max(scrollbarHeight, this.style.hScroll.getMinHeight());
        }
        float scrollbarWidth = vScrollKnob != null ? vScrollKnob.getMinWidth() : 0.0f;
        if (this.style.vScroll != null) {
            scrollbarWidth = Math.max(scrollbarWidth, this.style.vScroll.getMinWidth());
        }
        Actor actor = this.widget;
        if (actor instanceof Layout) {
            Layout layout = (Layout) actor;
            widgetWidth = layout.getPrefWidth();
            widgetHeight = layout.getPrefHeight();
        } else {
            widgetWidth = actor.getWidth();
            widgetHeight = this.widget.getHeight();
        }
        this.scrollX = this.forceScrollX || (widgetWidth > this.widgetArea.width && !this.disableX);
        this.scrollY = this.forceScrollY || (widgetHeight > this.widgetArea.height && !this.disableY);
        if (!this.scrollbarsOnTop) {
            if (this.scrollY) {
                this.widgetArea.width -= scrollbarWidth;
                if (!this.vScrollOnRight) {
                    this.widgetArea.x += scrollbarWidth;
                }
                if (!this.scrollX && widgetWidth > this.widgetArea.width && !this.disableX) {
                    this.scrollX = true;
                }
            }
            if (this.scrollX) {
                this.widgetArea.height -= scrollbarHeight;
                if (this.hScrollOnBottom) {
                    this.widgetArea.y += scrollbarHeight;
                }
                if (!this.scrollY && widgetHeight > this.widgetArea.height && !this.disableY) {
                    this.scrollY = true;
                    this.widgetArea.width -= scrollbarWidth;
                    if (!this.vScrollOnRight) {
                        this.widgetArea.x += scrollbarWidth;
                    }
                }
            }
        }
        float widgetWidth2 = this.disableX ? this.widgetArea.width : Math.max(this.widgetArea.width, widgetWidth);
        float widgetHeight2 = this.disableY ? this.widgetArea.height : Math.max(this.widgetArea.height, widgetHeight);
        this.maxX = widgetWidth2 - this.widgetArea.width;
        this.maxY = widgetHeight2 - this.widgetArea.height;
        scrollX(MathUtils.clamp(this.amountX, 0.0f, this.maxX));
        scrollY(MathUtils.clamp(this.amountY, 0.0f, this.maxY));
        if (!this.scrollX) {
            bgLeftWidth = bgLeftWidth2;
            bgBottomHeight = bgBottomHeight2;
        } else if (hScrollKnob != null) {
            float x = this.scrollbarsOnTop ? bgLeftWidth2 : this.widgetArea.x;
            float y = this.hScrollOnBottom ? bgBottomHeight2 : (height - bgTopHeight) - scrollbarHeight;
            bgLeftWidth = bgLeftWidth2;
            this.hScrollBounds.set(x, y, this.widgetArea.width, scrollbarHeight);
            if (this.scrollY && this.scrollbarsOnTop) {
                this.hScrollBounds.width -= scrollbarWidth;
                if (!this.vScrollOnRight) {
                    this.hScrollBounds.x += scrollbarWidth;
                }
            }
            if (this.variableSizeKnobs) {
                bgBottomHeight = bgBottomHeight2;
                this.hKnobBounds.width = Math.max(hScrollKnob.getMinWidth(), (int) ((this.hScrollBounds.width * this.widgetArea.width) / widgetWidth2));
            } else {
                bgBottomHeight = bgBottomHeight2;
                this.hKnobBounds.width = hScrollKnob.getMinWidth();
            }
            if (this.hKnobBounds.width > widgetWidth2) {
                this.hKnobBounds.width = 0.0f;
            }
            this.hKnobBounds.height = hScrollKnob.getMinHeight();
            this.hKnobBounds.x = this.hScrollBounds.x + ((int) ((this.hScrollBounds.width - this.hKnobBounds.width) * getScrollPercentX()));
            this.hKnobBounds.y = this.hScrollBounds.y;
        } else {
            bgLeftWidth = bgLeftWidth2;
            bgBottomHeight = bgBottomHeight2;
            this.hScrollBounds.set(0.0f, 0.0f, 0.0f, 0.0f);
            this.hKnobBounds.set(0.0f, 0.0f, 0.0f, 0.0f);
        }
        if (this.scrollY) {
            if (vScrollKnob != null) {
                float x2 = this.vScrollOnRight ? (width - bgRightWidth) - scrollbarWidth : bgLeftWidth;
                float y2 = this.scrollbarsOnTop ? bgBottomHeight : this.widgetArea.y;
                this.vScrollBounds.set(x2, y2, scrollbarWidth, this.widgetArea.height);
                if (this.scrollX && this.scrollbarsOnTop) {
                    this.vScrollBounds.height -= scrollbarHeight;
                    if (this.hScrollOnBottom) {
                        this.vScrollBounds.y += scrollbarHeight;
                    }
                }
                this.vKnobBounds.width = vScrollKnob.getMinWidth();
                if (this.variableSizeKnobs) {
                    this.vKnobBounds.height = Math.max(vScrollKnob.getMinHeight(), (int) ((this.vScrollBounds.height * this.widgetArea.height) / widgetHeight2));
                } else {
                    this.vKnobBounds.height = vScrollKnob.getMinHeight();
                }
                if (this.vKnobBounds.height > widgetHeight2) {
                    this.vKnobBounds.height = 0.0f;
                }
                this.vKnobBounds.x = this.vScrollOnRight ? (width - bgRightWidth) - vScrollKnob.getMinWidth() : bgLeftWidth;
                this.vKnobBounds.y = this.vScrollBounds.y + ((int) ((this.vScrollBounds.height - this.vKnobBounds.height) * (1.0f - getScrollPercentY())));
            } else {
                this.vScrollBounds.set(0.0f, 0.0f, 0.0f, 0.0f);
                this.vKnobBounds.set(0.0f, 0.0f, 0.0f, 0.0f);
            }
        }
        updateWidgetPosition();
        Actor actor2 = this.widget;
        if (actor2 instanceof Layout) {
            actor2.setSize(widgetWidth2, widgetHeight2);
            ((Layout) this.widget).validate();
        }
    }

    private void updateWidgetPosition() {
        float x = this.widgetArea.x - (this.scrollX ? (int) this.visualAmountX : 0);
        float y = this.widgetArea.y - ((int) (this.scrollY ? this.maxY - this.visualAmountY : this.maxY));
        this.widget.setPosition(x, y);
        if (this.widget instanceof Cullable) {
            this.widgetCullingArea.x = this.widgetArea.x - x;
            this.widgetCullingArea.y = this.widgetArea.y - y;
            this.widgetCullingArea.width = this.widgetArea.width;
            this.widgetCullingArea.height = this.widgetArea.height;
            ((Cullable) this.widget).setCullingArea(this.widgetCullingArea);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        if (this.widget == null) {
            return;
        }
        validate();
        applyTransform(batch, computeTransform());
        if (this.scrollX) {
            this.hKnobBounds.x = this.hScrollBounds.x + ((int) ((this.hScrollBounds.width - this.hKnobBounds.width) * getVisualScrollPercentX()));
        }
        if (this.scrollY) {
            this.vKnobBounds.y = this.vScrollBounds.y + ((int) ((this.vScrollBounds.height - this.vKnobBounds.height) * (1.0f - getVisualScrollPercentY())));
        }
        updateWidgetPosition();
        Color color = getColor();
        float alpha = color.a * parentAlpha;
        if (this.style.background != null) {
            batch.setColor(color.r, color.g, color.b, alpha);
            this.style.background.draw(batch, 0.0f, 0.0f, getWidth(), getHeight());
        }
        batch.flush();
        if (clipBegin(this.widgetArea.x, this.widgetArea.y, this.widgetArea.width, this.widgetArea.height)) {
            drawChildren(batch, parentAlpha);
            batch.flush();
            clipEnd();
        }
        batch.setColor(color.r, color.g, color.b, alpha);
        if (this.fadeScrollBars) {
            alpha *= Interpolation.fade.apply(this.fadeAlpha / this.fadeAlphaSeconds);
        }
        drawScrollBars(batch, color.r, color.g, color.b, alpha);
        resetTransform(batch);
    }

    protected void drawScrollBars(Batch batch, float r, float g, float b, float a) {
        if (a <= 0.0f) {
            return;
        }
        batch.setColor(r, g, b, a);
        boolean z = true;
        boolean x = this.scrollX && this.hKnobBounds.width > 0.0f;
        boolean y = (!this.scrollY || this.vKnobBounds.height <= 0.0f) ? false : false;
        if (x && y && this.style.corner != null) {
            this.style.corner.draw(batch, this.hScrollBounds.x + this.hScrollBounds.width, this.hScrollBounds.y, this.vScrollBounds.width, this.vScrollBounds.y);
        }
        if (x) {
            if (this.style.hScroll != null) {
                this.style.hScroll.draw(batch, this.hScrollBounds.x, this.hScrollBounds.y, this.hScrollBounds.width, this.hScrollBounds.height);
            }
            if (this.style.hScrollKnob != null) {
                this.style.hScrollKnob.draw(batch, this.hKnobBounds.x, this.hKnobBounds.y, this.hKnobBounds.width, this.hKnobBounds.height);
            }
        }
        if (y) {
            if (this.style.vScroll != null) {
                this.style.vScroll.draw(batch, this.vScrollBounds.x, this.vScrollBounds.y, this.vScrollBounds.width, this.vScrollBounds.height);
            }
            if (this.style.vScrollKnob != null) {
                this.style.vScrollKnob.draw(batch, this.vKnobBounds.x, this.vKnobBounds.y, this.vKnobBounds.width, this.vKnobBounds.height);
            }
        }
    }

    public void fling(float flingTime, float velocityX, float velocityY) {
        this.flingTimer = flingTime;
        this.velocityX = velocityX;
        this.velocityY = velocityY;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        float width = 0.0f;
        Actor actor = this.widget;
        if (actor instanceof Layout) {
            width = ((Layout) actor).getPrefWidth();
        } else if (actor != null) {
            width = actor.getWidth();
        }
        Drawable background = this.style.background;
        if (background != null) {
            width = Math.max(background.getLeftWidth() + width + background.getRightWidth(), background.getMinWidth());
        }
        if (this.scrollY) {
            float scrollbarWidth = this.style.vScrollKnob != null ? this.style.vScrollKnob.getMinWidth() : 0.0f;
            if (this.style.vScroll != null) {
                scrollbarWidth = Math.max(scrollbarWidth, this.style.vScroll.getMinWidth());
            }
            return width + scrollbarWidth;
        }
        return width;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        float height = 0.0f;
        Actor actor = this.widget;
        if (actor instanceof Layout) {
            height = ((Layout) actor).getPrefHeight();
        } else if (actor != null) {
            height = actor.getHeight();
        }
        Drawable background = this.style.background;
        if (background != null) {
            height = Math.max(background.getTopHeight() + height + background.getBottomHeight(), background.getMinHeight());
        }
        if (this.scrollX) {
            float scrollbarHeight = this.style.hScrollKnob != null ? this.style.hScrollKnob.getMinHeight() : 0.0f;
            if (this.style.hScroll != null) {
                scrollbarHeight = Math.max(scrollbarHeight, this.style.hScroll.getMinHeight());
            }
            return height + scrollbarHeight;
        }
        return height;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMinWidth() {
        return 0.0f;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMinHeight() {
        return 0.0f;
    }

    public void setActor(Actor actor) {
        Actor actor2 = this.widget;
        if (actor2 == this) {
            throw new IllegalArgumentException("widget cannot be the ScrollPane.");
        }
        if (actor2 != null) {
            super.removeActor(actor2);
        }
        this.widget = actor;
        Actor actor3 = this.widget;
        if (actor3 != null) {
            super.addActor(actor3);
        }
    }

    public Actor getActor() {
        return this.widget;
    }

    @Deprecated
    public void setWidget(Actor actor) {
        setActor(actor);
    }

    @Deprecated
    public Actor getWidget() {
        return this.widget;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    @Deprecated
    public void addActor(Actor actor) {
        throw new UnsupportedOperationException("Use ScrollPane#setWidget.");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    @Deprecated
    public void addActorAt(int index, Actor actor) {
        throw new UnsupportedOperationException("Use ScrollPane#setWidget.");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    @Deprecated
    public void addActorBefore(Actor actorBefore, Actor actor) {
        throw new UnsupportedOperationException("Use ScrollPane#setWidget.");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    @Deprecated
    public void addActorAfter(Actor actorAfter, Actor actor) {
        throw new UnsupportedOperationException("Use ScrollPane#setWidget.");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public boolean removeActor(Actor actor) {
        if (actor == null) {
            throw new IllegalArgumentException("actor cannot be null.");
        }
        if (actor != this.widget) {
            return false;
        }
        setActor(null);
        return true;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public boolean removeActor(Actor actor, boolean unfocus) {
        if (actor == null) {
            throw new IllegalArgumentException("actor cannot be null.");
        }
        if (actor != this.widget) {
            return false;
        }
        this.widget = null;
        return super.removeActor(actor, unfocus);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public Actor removeActorAt(int index, boolean unfocus) {
        Actor actor = super.removeActorAt(index, unfocus);
        if (actor == this.widget) {
            this.widget = null;
        }
        return actor;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public Actor hit(float x, float y, boolean touchable) {
        if (x < 0.0f || x >= getWidth() || y < 0.0f || y >= getHeight()) {
            return null;
        }
        if (touchable && getTouchable() == Touchable.enabled && isVisible()) {
            if (this.scrollX && this.touchScrollH && this.hScrollBounds.contains(x, y)) {
                return this;
            }
            if (this.scrollY && this.touchScrollV && this.vScrollBounds.contains(x, y)) {
                return this;
            }
        }
        return super.hit(x, y, touchable);
    }

    protected void scrollX(float pixelsX) {
        this.amountX = pixelsX;
    }

    protected void scrollY(float pixelsY) {
        this.amountY = pixelsY;
    }

    protected void visualScrollX(float pixelsX) {
        this.visualAmountX = pixelsX;
    }

    protected void visualScrollY(float pixelsY) {
        this.visualAmountY = pixelsY;
    }

    protected float getMouseWheelX() {
        return Math.min(this.widgetArea.width, Math.max(this.widgetArea.width * 0.9f, this.maxX * 0.1f) / 4.0f);
    }

    protected float getMouseWheelY() {
        return Math.min(this.widgetArea.height, Math.max(this.widgetArea.height * 0.9f, this.maxY * 0.1f) / 4.0f);
    }

    public void setScrollX(float pixels) {
        scrollX(MathUtils.clamp(pixels, 0.0f, this.maxX));
    }

    public float getScrollX() {
        return this.amountX;
    }

    public void setScrollY(float pixels) {
        scrollY(MathUtils.clamp(pixels, 0.0f, this.maxY));
    }

    public float getScrollY() {
        return this.amountY;
    }

    public void updateVisualScroll() {
        this.visualAmountX = this.amountX;
        this.visualAmountY = this.amountY;
    }

    public float getVisualScrollX() {
        if (this.scrollX) {
            return this.visualAmountX;
        }
        return 0.0f;
    }

    public float getVisualScrollY() {
        if (this.scrollY) {
            return this.visualAmountY;
        }
        return 0.0f;
    }

    public float getVisualScrollPercentX() {
        float f = this.maxX;
        if (f == 0.0f) {
            return 0.0f;
        }
        return MathUtils.clamp(this.visualAmountX / f, 0.0f, 1.0f);
    }

    public float getVisualScrollPercentY() {
        float f = this.maxY;
        if (f == 0.0f) {
            return 0.0f;
        }
        return MathUtils.clamp(this.visualAmountY / f, 0.0f, 1.0f);
    }

    public float getScrollPercentX() {
        float f = this.maxX;
        if (f == 0.0f) {
            return 0.0f;
        }
        return MathUtils.clamp(this.amountX / f, 0.0f, 1.0f);
    }

    public void setScrollPercentX(float percentX) {
        scrollX(this.maxX * MathUtils.clamp(percentX, 0.0f, 1.0f));
    }

    public float getScrollPercentY() {
        float f = this.maxY;
        if (f == 0.0f) {
            return 0.0f;
        }
        return MathUtils.clamp(this.amountY / f, 0.0f, 1.0f);
    }

    public void setScrollPercentY(float percentY) {
        scrollY(this.maxY * MathUtils.clamp(percentY, 0.0f, 1.0f));
    }

    public void setFlickScroll(boolean flickScroll) {
        if (this.flickScroll == flickScroll) {
            return;
        }
        this.flickScroll = flickScroll;
        if (flickScroll) {
            addListener(this.flickScrollListener);
        } else {
            removeListener(this.flickScrollListener);
        }
        invalidate();
    }

    public void setFlickScrollTapSquareSize(float halfTapSquareSize) {
        this.flickScrollListener.getGestureDetector().setTapSquareSize(halfTapSquareSize);
    }

    public void scrollTo(float x, float y, float width, float height) {
        scrollTo(x, y, width, height, false, false);
    }

    public void scrollTo(float x, float y, float width, float height, boolean centerHorizontal, boolean centerVertical) {
        float amountX;
        float amountY;
        validate();
        float amountX2 = this.amountX;
        if (centerHorizontal) {
            amountX = (x - (this.widgetArea.width / 2.0f)) + (width / 2.0f);
        } else {
            if (x + width > this.widgetArea.width + amountX2) {
                amountX2 = (x + width) - this.widgetArea.width;
            }
            amountX = amountX2;
            if (x < amountX) {
                amountX = x;
            }
        }
        scrollX(MathUtils.clamp(amountX, 0.0f, this.maxX));
        float amountY2 = this.amountY;
        if (centerVertical) {
            amountY = ((this.maxY - y) + (this.widgetArea.height / 2.0f)) - (height / 2.0f);
        } else {
            if (amountY2 > ((this.maxY - y) - height) + this.widgetArea.height) {
                amountY2 = ((this.maxY - y) - height) + this.widgetArea.height;
            }
            amountY = amountY2;
            float amountY3 = this.maxY;
            if (amountY < amountY3 - y) {
                amountY = amountY3 - y;
            }
        }
        scrollY(MathUtils.clamp(amountY, 0.0f, this.maxY));
    }

    public float getMaxX() {
        return this.maxX;
    }

    public float getMaxY() {
        return this.maxY;
    }

    public float getScrollBarHeight() {
        if (this.scrollX) {
            float height = this.style.hScrollKnob != null ? this.style.hScrollKnob.getMinHeight() : 0.0f;
            return this.style.hScroll != null ? Math.max(height, this.style.hScroll.getMinHeight()) : height;
        }
        return 0.0f;
    }

    public float getScrollBarWidth() {
        if (this.scrollY) {
            float width = this.style.vScrollKnob != null ? this.style.vScrollKnob.getMinWidth() : 0.0f;
            return this.style.vScroll != null ? Math.max(width, this.style.vScroll.getMinWidth()) : width;
        }
        return 0.0f;
    }

    public float getScrollWidth() {
        return this.widgetArea.width;
    }

    public float getScrollHeight() {
        return this.widgetArea.height;
    }

    public boolean isScrollX() {
        return this.scrollX;
    }

    public boolean isScrollY() {
        return this.scrollY;
    }

    public void setScrollingDisabled(boolean x, boolean y) {
        this.disableX = x;
        this.disableY = y;
        invalidate();
    }

    public boolean isScrollingDisabledX() {
        return this.disableX;
    }

    public boolean isScrollingDisabledY() {
        return this.disableY;
    }

    public boolean isLeftEdge() {
        return !this.scrollX || this.amountX <= 0.0f;
    }

    public boolean isRightEdge() {
        return !this.scrollX || this.amountX >= this.maxX;
    }

    public boolean isTopEdge() {
        return !this.scrollY || this.amountY <= 0.0f;
    }

    public boolean isBottomEdge() {
        return !this.scrollY || this.amountY >= this.maxY;
    }

    public boolean isDragging() {
        return this.draggingPointer != -1;
    }

    public boolean isPanning() {
        return this.flickScrollListener.getGestureDetector().isPanning();
    }

    public boolean isFlinging() {
        return this.flingTimer > 0.0f;
    }

    public void setVelocityX(float velocityX) {
        this.velocityX = velocityX;
    }

    public float getVelocityX() {
        return this.velocityX;
    }

    public void setVelocityY(float velocityY) {
        this.velocityY = velocityY;
    }

    public float getVelocityY() {
        return this.velocityY;
    }

    public void setOverscroll(boolean overscrollX, boolean overscrollY) {
        this.overscrollX = overscrollX;
        this.overscrollY = overscrollY;
    }

    public void setupOverscroll(float distance, float speedMin, float speedMax) {
        this.overscrollDistance = distance;
        this.overscrollSpeedMin = speedMin;
        this.overscrollSpeedMax = speedMax;
    }

    public float getOverscrollDistance() {
        return this.overscrollDistance;
    }

    public void setForceScroll(boolean x, boolean y) {
        this.forceScrollX = x;
        this.forceScrollY = y;
    }

    public boolean isForceScrollX() {
        return this.forceScrollX;
    }

    public boolean isForceScrollY() {
        return this.forceScrollY;
    }

    public void setFlingTime(float flingTime) {
        this.flingTime = flingTime;
    }

    public void setClamp(boolean clamp) {
        this.clamp = clamp;
    }

    public void setScrollBarPositions(boolean bottom, boolean right) {
        this.hScrollOnBottom = bottom;
        this.vScrollOnRight = right;
    }

    public void setFadeScrollBars(boolean fadeScrollBars) {
        if (this.fadeScrollBars == fadeScrollBars) {
            return;
        }
        this.fadeScrollBars = fadeScrollBars;
        if (!fadeScrollBars) {
            this.fadeAlpha = this.fadeAlphaSeconds;
        }
        invalidate();
    }

    public void setupFadeScrollBars(float fadeAlphaSeconds, float fadeDelaySeconds) {
        this.fadeAlphaSeconds = fadeAlphaSeconds;
        this.fadeDelaySeconds = fadeDelaySeconds;
    }

    public boolean getFadeScrollBars() {
        return this.fadeScrollBars;
    }

    public void setScrollBarTouch(boolean scrollBarTouch) {
        this.scrollBarTouch = scrollBarTouch;
    }

    public void setSmoothScrolling(boolean smoothScrolling) {
        this.smoothScrolling = smoothScrolling;
    }

    public void setScrollbarsOnTop(boolean scrollbarsOnTop) {
        this.scrollbarsOnTop = scrollbarsOnTop;
        invalidate();
    }

    public boolean getVariableSizeKnobs() {
        return this.variableSizeKnobs;
    }

    public void setVariableSizeKnobs(boolean variableSizeKnobs) {
        this.variableSizeKnobs = variableSizeKnobs;
    }

    public void setCancelTouchFocus(boolean cancelTouchFocus) {
        this.cancelTouchFocus = cancelTouchFocus;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void drawDebug(ShapeRenderer shapes) {
        drawDebugBounds(shapes);
        applyTransform(shapes, computeTransform());
        if (clipBegin(this.widgetArea.x, this.widgetArea.y, this.widgetArea.width, this.widgetArea.height)) {
            drawDebugChildren(shapes);
            shapes.flush();
            clipEnd();
        }
        resetTransform(shapes);
    }

    /* loaded from: classes.dex */
    public static class ScrollPaneStyle {
        public Drawable background;
        public Drawable corner;
        public Drawable hScroll;
        public Drawable hScrollKnob;
        public Drawable vScroll;
        public Drawable vScrollKnob;

        public ScrollPaneStyle() {
        }

        public ScrollPaneStyle(Drawable background, Drawable hScroll, Drawable hScrollKnob, Drawable vScroll, Drawable vScrollKnob) {
            this.background = background;
            this.hScroll = hScroll;
            this.hScrollKnob = hScrollKnob;
            this.vScroll = vScroll;
            this.vScrollKnob = vScrollKnob;
        }

        public ScrollPaneStyle(ScrollPaneStyle style) {
            this.background = style.background;
            this.corner = style.corner;
            this.hScroll = style.hScroll;
            this.hScrollKnob = style.hScrollKnob;
            this.vScroll = style.vScroll;
            this.vScrollKnob = style.vScrollKnob;
        }
    }
}