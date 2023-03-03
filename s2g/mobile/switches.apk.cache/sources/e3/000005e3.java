package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.math.Interpolation;
import com.badlogic.gdx.scenes.scene2d.Action;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Group;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.actions.Actions;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.scenes.scene2d.ui.Window;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.ClickListener;
import com.kotcrab.vis.ui.FocusManager;
import com.kotcrab.vis.ui.VisUI;

/* loaded from: classes.dex */
public class VisWindow extends Window {
    public static float FADE_TIME = 0.3f;
    private boolean centerOnAdd;
    private boolean fadeOutActionRunning;
    private boolean keepWithinParent;

    public VisWindow(String title) {
        this(title, true);
        getTitleLabel().setAlignment(VisUI.getDefaultTitleAlign());
    }

    public VisWindow(String title, boolean showWindowBorder) {
        super(title, VisUI.getSkin(), showWindowBorder ? "default" : "noborder");
        this.keepWithinParent = false;
        getTitleLabel().setAlignment(VisUI.getDefaultTitleAlign());
    }

    public VisWindow(String title, String styleName) {
        super(title, VisUI.getSkin(), styleName);
        this.keepWithinParent = false;
        getTitleLabel().setAlignment(VisUI.getDefaultTitleAlign());
    }

    public VisWindow(String title, Window.WindowStyle style) {
        super(title, style);
        this.keepWithinParent = false;
        getTitleLabel().setAlignment(VisUI.getDefaultTitleAlign());
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void setPosition(float x, float y) {
        super.setPosition((int) x, (int) y);
    }

    public boolean centerWindow() {
        Group parent = getParent();
        if (parent == null) {
            this.centerOnAdd = true;
            return false;
        }
        moveToCenter();
        return true;
    }

    public void setCenterOnAdd(boolean centerOnAdd) {
        this.centerOnAdd = centerOnAdd;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void setStage(Stage stage) {
        super.setStage(stage);
        if (stage != null) {
            stage.setKeyboardFocus(this);
            if (this.centerOnAdd) {
                this.centerOnAdd = false;
                moveToCenter();
            }
        }
    }

    private void moveToCenter() {
        Stage parent = getStage();
        if (parent != null) {
            setPosition((parent.getWidth() - getWidth()) / 2.0f, (parent.getHeight() - getHeight()) / 2.0f);
        }
    }

    public void fadeOut(float time) {
        if (this.fadeOutActionRunning) {
            return;
        }
        this.fadeOutActionRunning = true;
        final Touchable previousTouchable = getTouchable();
        setTouchable(Touchable.disabled);
        Stage stage = getStage();
        if (stage != null && stage.getKeyboardFocus() != null && stage.getKeyboardFocus().isDescendantOf(this)) {
            FocusManager.resetFocus(stage);
        }
        addAction(Actions.sequence(Actions.fadeOut(time, Interpolation.fade), new Action() { // from class: com.kotcrab.vis.ui.widget.VisWindow.1
            @Override // com.badlogic.gdx.scenes.scene2d.Action
            public boolean act(float delta) {
                VisWindow.this.setTouchable(previousTouchable);
                VisWindow.this.remove();
                VisWindow.this.getColor().a = 1.0f;
                VisWindow.this.fadeOutActionRunning = false;
                return true;
            }
        }));
    }

    public VisWindow fadeIn(float time) {
        setColor(1.0f, 1.0f, 1.0f, 0.0f);
        addAction(Actions.fadeIn(time, Interpolation.fade));
        return this;
    }

    public void fadeOut() {
        fadeOut(FADE_TIME);
    }

    public VisWindow fadeIn() {
        return fadeIn(FADE_TIME);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void close() {
        fadeOut();
    }

    public void addCloseButton() {
        Label titleLabel = getTitleLabel();
        Table titleTable = getTitleTable();
        VisImageButton closeButton = new VisImageButton("close-window");
        titleTable.add(closeButton).padRight((-getPadRight()) + 0.7f);
        closeButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.VisWindow.2
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                VisWindow.this.close();
            }
        });
        closeButton.addListener(new ClickListener() { // from class: com.kotcrab.vis.ui.widget.VisWindow.3
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                event.cancel();
                return true;
            }
        });
        if (titleLabel.getLabelAlign() == 1 && titleTable.getChildren().size == 2) {
            titleTable.getCell(titleLabel).padLeft(closeButton.getWidth() * 2.0f);
        }
    }

    public void closeOnEscape() {
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.VisWindow.4
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyDown(InputEvent event, int keycode) {
                if (keycode == 131) {
                    VisWindow.this.close();
                    return true;
                }
                return false;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyUp(InputEvent event, int keycode) {
                if (keycode == 4) {
                    VisWindow.this.close();
                    return true;
                }
                return false;
            }
        });
    }

    public boolean isKeepWithinParent() {
        return this.keepWithinParent;
    }

    public void setKeepWithinParent(boolean keepWithinParent) {
        this.keepWithinParent = keepWithinParent;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Window, com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        if (this.keepWithinParent && getParent() != null) {
            float parentWidth = getParent().getWidth();
            float parentHeight = getParent().getHeight();
            if (getX() < 0.0f) {
                setX(0.0f);
            }
            if (getRight() > parentWidth) {
                setX(parentWidth - getWidth());
            }
            if (getY() < 0.0f) {
                setY(0.0f);
            }
            if (getTop() > parentHeight) {
                setY(parentHeight - getHeight());
            }
        }
        super.draw(batch, parentAlpha);
    }
}