package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.math.Interpolation;
import com.badlogic.gdx.scenes.scene2d.Action;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.actions.Actions;
import com.badlogic.gdx.scenes.scene2d.ui.Button;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.badlogic.gdx.scenes.scene2d.ui.Skin;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.scenes.scene2d.ui.Window;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.FocusListener;
import com.badlogic.gdx.utils.ObjectMap;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.widget.VisTextButton;

/* loaded from: classes.dex */
public class VisDialog extends VisWindow {
    Table buttonTable;
    boolean cancelHide;
    Table contentTable;
    FocusListener focusListener;
    protected InputListener ignoreTouchDown;
    Actor previousKeyboardFocus;
    Actor previousScrollFocus;
    private Skin skin;
    ObjectMap<Actor, Object> values;

    public VisDialog(String title) {
        super(title);
        this.values = new ObjectMap<>();
        this.ignoreTouchDown = new InputListener() { // from class: com.kotcrab.vis.ui.widget.VisDialog.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                event.cancel();
                return false;
            }
        };
        this.skin = VisUI.getSkin();
        setSkin(this.skin);
        initialize();
    }

    public VisDialog(String title, String windowStyleName) {
        super(title, (Window.WindowStyle) VisUI.getSkin().get(windowStyleName, Window.WindowStyle.class));
        this.values = new ObjectMap<>();
        this.ignoreTouchDown = new InputListener() { // from class: com.kotcrab.vis.ui.widget.VisDialog.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                event.cancel();
                return false;
            }
        };
        this.skin = VisUI.getSkin();
        setSkin(this.skin);
        initialize();
    }

    public VisDialog(String title, Window.WindowStyle windowStyle) {
        super(title, windowStyle);
        this.values = new ObjectMap<>();
        this.ignoreTouchDown = new InputListener() { // from class: com.kotcrab.vis.ui.widget.VisDialog.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                event.cancel();
                return false;
            }
        };
        this.skin = VisUI.getSkin();
        setSkin(this.skin);
        initialize();
    }

    private void initialize() {
        setModal(true);
        getTitleLabel().setAlignment(VisUI.getDefaultTitleAlign());
        defaults().space(6.0f);
        Table table = new Table(this.skin);
        this.contentTable = table;
        add((VisDialog) table).expand().fill();
        row();
        Table table2 = new Table(this.skin);
        this.buttonTable = table2;
        add((VisDialog) table2);
        this.contentTable.defaults().space(2.0f).padLeft(3.0f).padRight(3.0f);
        this.buttonTable.defaults().space(6.0f).padBottom(3.0f);
        this.buttonTable.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.VisDialog.2
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                if (VisDialog.this.values.containsKey(actor)) {
                    while (actor.getParent() != VisDialog.this.buttonTable) {
                        actor = actor.getParent();
                    }
                    VisDialog visDialog = VisDialog.this;
                    visDialog.result(visDialog.values.get(actor));
                    if (!VisDialog.this.cancelHide) {
                        VisDialog.this.hide();
                    }
                    VisDialog.this.cancelHide = false;
                }
            }
        });
        this.focusListener = new FocusListener() { // from class: com.kotcrab.vis.ui.widget.VisDialog.3
            @Override // com.badlogic.gdx.scenes.scene2d.utils.FocusListener
            public void keyboardFocusChanged(FocusListener.FocusEvent event, Actor actor, boolean focused) {
                if (!focused) {
                    focusChanged(event);
                }
            }

            @Override // com.badlogic.gdx.scenes.scene2d.utils.FocusListener
            public void scrollFocusChanged(FocusListener.FocusEvent event, Actor actor, boolean focused) {
                if (!focused) {
                    focusChanged(event);
                }
            }

            private void focusChanged(FocusListener.FocusEvent event) {
                Actor newFocusedActor;
                Stage stage = VisDialog.this.getStage();
                if (!VisDialog.this.isModal() || stage == null || stage.getRoot().getChildren().size <= 0 || stage.getRoot().getChildren().peek() != VisDialog.this || (newFocusedActor = event.getRelatedActor()) == null || newFocusedActor.isDescendantOf(VisDialog.this)) {
                    return;
                }
                event.cancel();
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.kotcrab.vis.ui.widget.VisWindow, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void setStage(Stage stage) {
        if (stage == null) {
            addListener(this.focusListener);
        } else {
            removeListener(this.focusListener);
        }
        super.setStage(stage);
    }

    public Table getContentTable() {
        return this.contentTable;
    }

    public Table getButtonsTable() {
        return this.buttonTable;
    }

    public VisDialog text(String text) {
        Skin skin = this.skin;
        if (skin == null) {
            throw new IllegalStateException("This method may only be used if the dialog was constructed with a Skin.");
        }
        return text(text, (Label.LabelStyle) skin.get(Label.LabelStyle.class));
    }

    public VisDialog text(String text, Label.LabelStyle labelStyle) {
        return text(new Label(text, labelStyle));
    }

    public VisDialog text(Label label) {
        this.contentTable.add((Table) label);
        return this;
    }

    public VisDialog button(String text) {
        return button(text, (Object) null);
    }

    public VisDialog button(String text, Object object) {
        Skin skin = this.skin;
        if (skin == null) {
            throw new IllegalStateException("This method may only be used if the dialog was constructed with a Skin.");
        }
        return button(text, object, (VisTextButton.VisTextButtonStyle) skin.get(VisTextButton.VisTextButtonStyle.class));
    }

    public VisDialog button(String text, Object object, VisTextButton.VisTextButtonStyle buttonStyle) {
        return button(new VisTextButton(text, buttonStyle), object);
    }

    public VisDialog button(Button button) {
        return button(button, (Object) null);
    }

    public VisDialog button(Button button, Object object) {
        this.buttonTable.add(button);
        setObject(button, object);
        return this;
    }

    public VisDialog show(Stage stage, Action action) {
        clearActions();
        removeCaptureListener(this.ignoreTouchDown);
        this.previousKeyboardFocus = null;
        Actor actor = stage.getKeyboardFocus();
        if (actor != null && !actor.isDescendantOf(this)) {
            this.previousKeyboardFocus = actor;
        }
        this.previousScrollFocus = null;
        Actor actor2 = stage.getScrollFocus();
        if (actor2 != null && !actor2.isDescendantOf(this)) {
            this.previousScrollFocus = actor2;
        }
        pack();
        stage.addActor(this);
        stage.setKeyboardFocus(this);
        stage.setScrollFocus(this);
        if (action != null) {
            addAction(action);
        }
        return this;
    }

    public VisDialog show(Stage stage) {
        show(stage, Actions.sequence(Actions.alpha(0.0f), Actions.fadeIn(0.4f, Interpolation.fade)));
        setPosition(Math.round((stage.getWidth() - getWidth()) / 2.0f), Math.round((stage.getHeight() - getHeight()) / 2.0f));
        return this;
    }

    public void hide(Action action) {
        Stage stage = getStage();
        if (stage != null) {
            removeListener(this.focusListener);
            Actor actor = this.previousKeyboardFocus;
            if (actor != null && actor.getStage() == null) {
                this.previousKeyboardFocus = null;
            }
            Actor actor2 = stage.getKeyboardFocus();
            if (actor2 == null || actor2.isDescendantOf(this)) {
                stage.setKeyboardFocus(this.previousKeyboardFocus);
            }
            Actor actor3 = this.previousScrollFocus;
            if (actor3 != null && actor3.getStage() == null) {
                this.previousScrollFocus = null;
            }
            Actor actor4 = stage.getScrollFocus();
            if (actor4 == null || actor4.isDescendantOf(this)) {
                stage.setScrollFocus(this.previousScrollFocus);
            }
        }
        if (action != null) {
            addCaptureListener(this.ignoreTouchDown);
            addAction(Actions.sequence(action, Actions.removeListener(this.ignoreTouchDown, true), Actions.removeActor()));
            return;
        }
        remove();
    }

    public void hide() {
        hide(Actions.sequence(Actions.fadeOut(FADE_TIME, Interpolation.fade), Actions.removeListener(this.ignoreTouchDown, true), Actions.removeActor()));
    }

    public void setObject(Actor actor, Object object) {
        this.values.put(actor, object);
    }

    public VisDialog key(final int keycode, final Object object) {
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.VisDialog.4
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyDown(InputEvent event, int keycode2) {
                if (keycode == keycode2) {
                    VisDialog.this.result(object);
                    if (!VisDialog.this.cancelHide) {
                        VisDialog.this.hide();
                    }
                    VisDialog.this.cancelHide = false;
                }
                return false;
            }
        });
        return this;
    }

    protected void result(Object object) {
    }

    public void cancel() {
        this.cancelHide = true;
    }
}