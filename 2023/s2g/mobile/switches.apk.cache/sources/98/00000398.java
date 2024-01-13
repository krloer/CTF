package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.math.Interpolation;
import com.badlogic.gdx.scenes.scene2d.Action;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.actions.Actions;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.badlogic.gdx.scenes.scene2d.ui.TextButton;
import com.badlogic.gdx.scenes.scene2d.ui.Window;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.FocusListener;
import com.badlogic.gdx.utils.ObjectMap;

/* loaded from: classes.dex */
public class Dialog extends Window {
    Table buttonTable;
    boolean cancelHide;
    Table contentTable;
    FocusListener focusListener;
    protected InputListener ignoreTouchDown;
    Actor previousKeyboardFocus;
    Actor previousScrollFocus;
    private Skin skin;
    ObjectMap<Actor, Object> values;

    public Dialog(String title, Skin skin) {
        super(title, (Window.WindowStyle) skin.get(Window.WindowStyle.class));
        this.values = new ObjectMap<>();
        this.ignoreTouchDown = new InputListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Dialog.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                event.cancel();
                return false;
            }
        };
        setSkin(skin);
        this.skin = skin;
        initialize();
    }

    public Dialog(String title, Skin skin, String windowStyleName) {
        super(title, (Window.WindowStyle) skin.get(windowStyleName, Window.WindowStyle.class));
        this.values = new ObjectMap<>();
        this.ignoreTouchDown = new InputListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Dialog.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                event.cancel();
                return false;
            }
        };
        setSkin(skin);
        this.skin = skin;
        initialize();
    }

    public Dialog(String title, Window.WindowStyle windowStyle) {
        super(title, windowStyle);
        this.values = new ObjectMap<>();
        this.ignoreTouchDown = new InputListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Dialog.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                event.cancel();
                return false;
            }
        };
        initialize();
    }

    private void initialize() {
        setModal(true);
        defaults().space(6.0f);
        Table table = new Table(this.skin);
        this.contentTable = table;
        add((Dialog) table).expand().fill();
        row();
        Table table2 = new Table(this.skin);
        this.buttonTable = table2;
        add((Dialog) table2).fillX();
        this.contentTable.defaults().space(6.0f);
        this.buttonTable.defaults().space(6.0f);
        this.buttonTable.addListener(new ChangeListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Dialog.2
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                if (Dialog.this.values.containsKey(actor)) {
                    while (actor.getParent() != Dialog.this.buttonTable) {
                        actor = actor.getParent();
                    }
                    Dialog dialog = Dialog.this;
                    dialog.result(dialog.values.get(actor));
                    if (!Dialog.this.cancelHide) {
                        Dialog.this.hide();
                    }
                    Dialog.this.cancelHide = false;
                }
            }
        });
        this.focusListener = new FocusListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Dialog.3
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
                Stage stage = Dialog.this.getStage();
                if (Dialog.this.isModal && stage != null && stage.getRoot().getChildren().size > 0 && stage.getRoot().getChildren().peek() == Dialog.this && (newFocusedActor = event.getRelatedActor()) != null && !newFocusedActor.isDescendantOf(Dialog.this) && !newFocusedActor.equals(Dialog.this.previousKeyboardFocus) && !newFocusedActor.equals(Dialog.this.previousScrollFocus)) {
                    event.cancel();
                }
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
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

    public Table getButtonTable() {
        return this.buttonTable;
    }

    public Dialog text(String text) {
        Skin skin = this.skin;
        if (skin == null) {
            throw new IllegalStateException("This method may only be used if the dialog was constructed with a Skin.");
        }
        return text(text, (Label.LabelStyle) skin.get(Label.LabelStyle.class));
    }

    public Dialog text(String text, Label.LabelStyle labelStyle) {
        return text(new Label(text, labelStyle));
    }

    public Dialog text(Label label) {
        this.contentTable.add((Table) label);
        return this;
    }

    public Dialog button(String text) {
        return button(text, (Object) null);
    }

    public Dialog button(String text, Object object) {
        Skin skin = this.skin;
        if (skin == null) {
            throw new IllegalStateException("This method may only be used if the dialog was constructed with a Skin.");
        }
        return button(text, object, (TextButton.TextButtonStyle) skin.get(TextButton.TextButtonStyle.class));
    }

    public Dialog button(String text, Object object, TextButton.TextButtonStyle buttonStyle) {
        return button(new TextButton(text, buttonStyle), object);
    }

    public Dialog button(Button button) {
        return button(button, (Object) null);
    }

    public Dialog button(Button button, Object object) {
        this.buttonTable.add(button);
        setObject(button, object);
        return this;
    }

    public Dialog show(Stage stage, Action action) {
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
        stage.addActor(this);
        pack();
        stage.cancelTouchFocus();
        stage.setKeyboardFocus(this);
        stage.setScrollFocus(this);
        if (action != null) {
            addAction(action);
        }
        return this;
    }

    public Dialog show(Stage stage) {
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
        hide(Actions.fadeOut(0.4f, Interpolation.fade));
    }

    public void setObject(Actor actor, Object object) {
        this.values.put(actor, object);
    }

    public Dialog key(final int keycode, final Object object) {
        addListener(new InputListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Dialog.4
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyDown(InputEvent event, int keycode2) {
                if (keycode == keycode2) {
                    Gdx.app.postRunnable(new Runnable() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Dialog.4.1
                        @Override // java.lang.Runnable
                        public void run() {
                            Dialog.this.result(object);
                            if (!Dialog.this.cancelHide) {
                                Dialog.this.hide();
                            }
                            Dialog.this.cancelHide = false;
                        }
                    });
                    return false;
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