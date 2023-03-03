package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.OrthographicCamera;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;

/* loaded from: classes.dex */
public class Window extends Table {
    private static final int MOVE = 32;
    private static final Vector2 tmpPosition = new Vector2();
    private static final Vector2 tmpSize = new Vector2();
    protected boolean dragging;
    boolean drawTitleTable;
    protected int edge;
    boolean isModal;
    boolean isMovable;
    boolean isResizable;
    boolean keepWithinStage;
    int resizeBorder;
    private WindowStyle style;
    Label titleLabel;
    Table titleTable;

    public Window(String title, Skin skin) {
        this(title, (WindowStyle) skin.get(WindowStyle.class));
        setSkin(skin);
    }

    public Window(String title, Skin skin, String styleName) {
        this(title, (WindowStyle) skin.get(styleName, WindowStyle.class));
        setSkin(skin);
    }

    public Window(String title, WindowStyle style) {
        this.isMovable = true;
        this.resizeBorder = 8;
        this.keepWithinStage = true;
        if (title == null) {
            throw new IllegalArgumentException("title cannot be null.");
        }
        setTouchable(Touchable.enabled);
        setClip(true);
        this.titleLabel = new Label(title, new Label.LabelStyle(style.titleFont, style.titleFontColor));
        this.titleLabel.setEllipsis(true);
        this.titleTable = new Table() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Window.1
            @Override // com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
            public void draw(Batch batch, float parentAlpha) {
                if (Window.this.drawTitleTable) {
                    super.draw(batch, parentAlpha);
                }
            }
        };
        this.titleTable.add((Table) this.titleLabel).expandX().fillX().minWidth(0.0f);
        addActor(this.titleTable);
        setStyle(style);
        setWidth(150.0f);
        setHeight(150.0f);
        addCaptureListener(new InputListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Window.2
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                Window.this.toFront();
                return false;
            }
        });
        addListener(new InputListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Window.3
            float lastX;
            float lastY;
            float startX;
            float startY;

            private void updateEdge(float x, float y) {
                float border = Window.this.resizeBorder / 2.0f;
                float width = Window.this.getWidth();
                float height = Window.this.getHeight();
                float padTop = Window.this.getPadTop();
                float padLeft = Window.this.getPadLeft();
                float padBottom = Window.this.getPadBottom();
                float padRight = Window.this.getPadRight();
                float right = width - padRight;
                Window window = Window.this;
                window.edge = 0;
                if (window.isResizable && x >= padLeft - border && x <= right + border && y >= padBottom - border) {
                    if (x < padLeft + border) {
                        Window.this.edge |= 8;
                    }
                    if (x > right - border) {
                        Window.this.edge |= 16;
                    }
                    if (y < padBottom + border) {
                        Window.this.edge |= 4;
                    }
                    if (Window.this.edge != 0) {
                        border += 25.0f;
                    }
                    if (x < padLeft + border) {
                        Window.this.edge |= 8;
                    }
                    if (x > right - border) {
                        Window.this.edge |= 16;
                    }
                    if (y < padBottom + border) {
                        Window.this.edge |= 4;
                    }
                }
                if (!Window.this.isMovable || Window.this.edge != 0 || y > height || y < height - padTop || x < padLeft || x > right) {
                    return;
                }
                Window.this.edge = 32;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                if (button == 0) {
                    updateEdge(x, y);
                    Window window = Window.this;
                    window.dragging = window.edge != 0;
                    this.startX = x;
                    this.startY = y;
                    this.lastX = x - Window.this.getWidth();
                    this.lastY = y - Window.this.getHeight();
                }
                return Window.this.edge != 0 || Window.this.isModal;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                Window.this.dragging = false;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchDragged(InputEvent event, float x, float y, int pointer) {
                if (Window.this.dragging) {
                    float width = Window.this.getWidth();
                    float height = Window.this.getHeight();
                    float windowX = Window.this.getX();
                    float windowY = Window.this.getY();
                    float minWidth = Window.this.getMinWidth();
                    Window.this.getMaxWidth();
                    float minHeight = Window.this.getMinHeight();
                    Window.this.getMaxHeight();
                    Stage stage = Window.this.getStage();
                    boolean clampPosition = Window.this.keepWithinStage && stage != null && Window.this.getParent() == stage.getRoot();
                    if ((Window.this.edge & 32) != 0) {
                        windowX += x - this.startX;
                        windowY += y - this.startY;
                    }
                    if ((Window.this.edge & 8) != 0) {
                        float amountX = x - this.startX;
                        if (width - amountX < minWidth) {
                            amountX = -(minWidth - width);
                        }
                        if (clampPosition && windowX + amountX < 0.0f) {
                            amountX = -windowX;
                        }
                        width -= amountX;
                        windowX += amountX;
                    }
                    if ((Window.this.edge & 4) != 0) {
                        float amountY = y - this.startY;
                        if (height - amountY < minHeight) {
                            amountY = -(minHeight - height);
                        }
                        if (clampPosition && windowY + amountY < 0.0f) {
                            amountY = -windowY;
                        }
                        height -= amountY;
                        windowY += amountY;
                    }
                    if ((Window.this.edge & 16) != 0) {
                        float amountX2 = (x - this.lastX) - width;
                        if (width + amountX2 < minWidth) {
                            amountX2 = minWidth - width;
                        }
                        if (clampPosition && windowX + width + amountX2 > stage.getWidth()) {
                            amountX2 = (stage.getWidth() - windowX) - width;
                        }
                        width += amountX2;
                    }
                    if ((Window.this.edge & 2) != 0) {
                        float amountY2 = (y - this.lastY) - height;
                        if (height + amountY2 < minHeight) {
                            amountY2 = minHeight - height;
                        }
                        if (clampPosition && windowY + height + amountY2 > stage.getHeight()) {
                            amountY2 = (stage.getHeight() - windowY) - height;
                        }
                        height += amountY2;
                    }
                    Window.this.setBounds(Math.round(windowX), Math.round(windowY), Math.round(width), Math.round(height));
                }
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean mouseMoved(InputEvent event, float x, float y) {
                updateEdge(x, y);
                return Window.this.isModal;
            }

            public boolean scrolled(InputEvent event, float x, float y, int amount) {
                return Window.this.isModal;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyDown(InputEvent event, int keycode) {
                return Window.this.isModal;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyUp(InputEvent event, int keycode) {
                return Window.this.isModal;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyTyped(InputEvent event, char character) {
                return Window.this.isModal;
            }
        });
    }

    public void setStyle(WindowStyle style) {
        if (style == null) {
            throw new IllegalArgumentException("style cannot be null.");
        }
        this.style = style;
        setBackground(style.background);
        this.titleLabel.setStyle(new Label.LabelStyle(style.titleFont, style.titleFontColor));
        invalidateHierarchy();
    }

    public WindowStyle getStyle() {
        return this.style;
    }

    public void keepWithinStage() {
        Stage stage;
        if (this.keepWithinStage && (stage = getStage()) != null) {
            Camera camera = stage.getCamera();
            if (camera instanceof OrthographicCamera) {
                OrthographicCamera orthographicCamera = (OrthographicCamera) camera;
                float parentWidth = stage.getWidth();
                float parentHeight = stage.getHeight();
                if (getX(16) - camera.position.x > (parentWidth / 2.0f) / orthographicCamera.zoom) {
                    setPosition(camera.position.x + ((parentWidth / 2.0f) / orthographicCamera.zoom), getY(16), 16);
                }
                if (getX(8) - camera.position.x < ((-parentWidth) / 2.0f) / orthographicCamera.zoom) {
                    setPosition(camera.position.x - ((parentWidth / 2.0f) / orthographicCamera.zoom), getY(8), 8);
                }
                if (getY(2) - camera.position.y > (parentHeight / 2.0f) / orthographicCamera.zoom) {
                    setPosition(getX(2), camera.position.y + ((parentHeight / 2.0f) / orthographicCamera.zoom), 2);
                }
                if (getY(4) - camera.position.y < ((-parentHeight) / 2.0f) / orthographicCamera.zoom) {
                    setPosition(getX(4), camera.position.y - ((parentHeight / 2.0f) / orthographicCamera.zoom), 4);
                }
            } else if (getParent() == stage.getRoot()) {
                float parentWidth2 = stage.getWidth();
                float parentHeight2 = stage.getHeight();
                if (getX() < 0.0f) {
                    setX(0.0f);
                }
                if (getRight() > parentWidth2) {
                    setX(parentWidth2 - getWidth());
                }
                if (getY() < 0.0f) {
                    setY(0.0f);
                }
                if (getTop() > parentHeight2) {
                    setY(parentHeight2 - getHeight());
                }
            }
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        Stage stage = getStage();
        if (stage != null) {
            if (stage.getKeyboardFocus() == null) {
                stage.setKeyboardFocus(this);
            }
            keepWithinStage();
            if (this.style.stageBackground != null) {
                stageToLocalCoordinates(tmpPosition.set(0.0f, 0.0f));
                stageToLocalCoordinates(tmpSize.set(stage.getWidth(), stage.getHeight()));
                drawStageBackground(batch, parentAlpha, getX() + tmpPosition.x, getY() + tmpPosition.y, getX() + tmpSize.x, getY() + tmpSize.y);
            }
        }
        super.draw(batch, parentAlpha);
    }

    protected void drawStageBackground(Batch batch, float parentAlpha, float x, float y, float width, float height) {
        Color color = getColor();
        batch.setColor(color.r, color.g, color.b, color.a * parentAlpha);
        this.style.stageBackground.draw(batch, x, y, width, height);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.ui.Table
    public void drawBackground(Batch batch, float parentAlpha, float x, float y) {
        super.drawBackground(batch, parentAlpha, x, y);
        this.titleTable.getColor().a = getColor().a;
        float padTop = getPadTop();
        float padLeft = getPadLeft();
        this.titleTable.setSize((getWidth() - padLeft) - getPadRight(), padTop);
        this.titleTable.setPosition(padLeft, getHeight() - padTop);
        this.drawTitleTable = true;
        this.titleTable.draw(batch, parentAlpha);
        this.drawTitleTable = false;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public Actor hit(float x, float y, boolean touchable) {
        if (isVisible()) {
            Actor hit = super.hit(x, y, touchable);
            if (hit == null && this.isModal && (!touchable || getTouchable() == Touchable.enabled)) {
                return this;
            }
            float height = getHeight();
            if (hit == null || hit == this) {
                return hit;
            }
            if (y <= height && y >= height - getPadTop() && x >= 0.0f && x <= getWidth()) {
                Actor current = hit;
                while (current.getParent() != this) {
                    current = current.getParent();
                }
                if (getCell(current) != null) {
                    return this;
                }
            }
            return hit;
        }
        return null;
    }

    public boolean isMovable() {
        return this.isMovable;
    }

    public void setMovable(boolean isMovable) {
        this.isMovable = isMovable;
    }

    public boolean isModal() {
        return this.isModal;
    }

    public void setModal(boolean isModal) {
        this.isModal = isModal;
    }

    public void setKeepWithinStage(boolean keepWithinStage) {
        this.keepWithinStage = keepWithinStage;
    }

    public boolean isResizable() {
        return this.isResizable;
    }

    public void setResizable(boolean isResizable) {
        this.isResizable = isResizable;
    }

    public void setResizeBorder(int resizeBorder) {
        this.resizeBorder = resizeBorder;
    }

    public boolean isDragging() {
        return this.dragging;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        return Math.max(super.getPrefWidth(), this.titleTable.getPrefWidth() + getPadLeft() + getPadRight());
    }

    public Table getTitleTable() {
        return this.titleTable;
    }

    public Label getTitleLabel() {
        return this.titleLabel;
    }

    /* loaded from: classes.dex */
    public static class WindowStyle {
        public Drawable background;
        public Drawable stageBackground;
        public BitmapFont titleFont;
        public Color titleFontColor;

        public WindowStyle() {
            this.titleFontColor = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        }

        public WindowStyle(BitmapFont titleFont, Color titleFontColor, Drawable background) {
            this.titleFontColor = new Color(1.0f, 1.0f, 1.0f, 1.0f);
            this.titleFont = titleFont;
            this.titleFontColor.set(titleFontColor);
            this.background = background;
        }

        public WindowStyle(WindowStyle style) {
            this.titleFontColor = new Color(1.0f, 1.0f, 1.0f, 1.0f);
            this.background = style.background;
            this.titleFont = style.titleFont;
            Color color = style.titleFontColor;
            if (color != null) {
                this.titleFontColor = new Color(color);
            }
            this.background = style.background;
        }
    }
}