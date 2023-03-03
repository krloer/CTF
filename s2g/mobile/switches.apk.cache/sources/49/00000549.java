package com.kotcrab.vis.ui.util.dialog;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.ui.Cell;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.utils.I18NBundle;
import com.badlogic.gdx.utils.StringBuilder;
import com.kotcrab.vis.ui.Locales;
import com.kotcrab.vis.ui.Sizes;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.i18n.BundleText;
import com.kotcrab.vis.ui.util.InputValidator;
import com.kotcrab.vis.ui.util.TableUtils;
import com.kotcrab.vis.ui.widget.ButtonBar;
import com.kotcrab.vis.ui.widget.VisDialog;
import com.kotcrab.vis.ui.widget.VisLabel;
import com.kotcrab.vis.ui.widget.VisScrollPane;
import com.kotcrab.vis.ui.widget.VisTable;
import com.kotcrab.vis.ui.widget.VisTextButton;
import com.kotcrab.vis.ui.widget.VisTextField;
import com.kotcrab.vis.ui.widget.VisValidatableTextField;
import com.kotcrab.vis.ui.widget.VisWindow;

/* loaded from: classes.dex */
public class Dialogs {
    private static final int BUTTON_DETAILS = 2;
    private static final int BUTTON_OK = 1;

    /* loaded from: classes.dex */
    public enum OptionDialogType {
        YES_NO,
        YES_NO_CANCEL,
        YES_CANCEL
    }

    public static VisDialog showOKDialog(Stage stage, String title, String text) {
        final VisDialog dialog = new VisDialog(title);
        dialog.closeOnEscape();
        dialog.text(text);
        dialog.button(ButtonBar.ButtonType.OK.getText()).padBottom(3.0f);
        dialog.pack();
        dialog.centerWindow();
        dialog.addListener(new InputListener() { // from class: com.kotcrab.vis.ui.util.dialog.Dialogs.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyDown(InputEvent event, int keycode) {
                if (keycode == 66) {
                    VisDialog.this.fadeOut();
                    return true;
                }
                return false;
            }
        });
        stage.addActor(dialog.fadeIn());
        return dialog;
    }

    public static OptionDialog showOptionDialog(Stage stage, String title, String text, OptionDialogType type, OptionDialogListener listener) {
        OptionDialog dialog = new OptionDialog(title, text, type, listener);
        stage.addActor(dialog.fadeIn());
        return dialog;
    }

    public static <T> ConfirmDialog<T> showConfirmDialog(Stage stage, String title, String text, String[] buttons, T[] returns, ConfirmDialogListener<T> listener) {
        ConfirmDialog<T> dialog = new ConfirmDialog<>(title, text, buttons, returns, listener);
        stage.addActor(dialog.fadeIn());
        return dialog;
    }

    public static InputDialog showInputDialog(Stage stage, String title, String fieldTitle, InputDialogListener listener) {
        InputDialog dialog = new InputDialog(title, fieldTitle, true, null, listener);
        stage.addActor(dialog.fadeIn());
        return dialog;
    }

    public static InputDialog showInputDialog(Stage stage, String title, String fieldTitle, InputValidator validator, InputDialogListener listener) {
        InputDialog dialog = new InputDialog(title, fieldTitle, true, validator, listener);
        stage.addActor(dialog.fadeIn());
        return dialog;
    }

    public static InputDialog showInputDialog(Stage stage, String title, String fieldTitle, boolean cancelable, InputDialogListener listener) {
        InputDialog dialog = new InputDialog(title, fieldTitle, cancelable, null, listener);
        stage.addActor(dialog.fadeIn());
        return dialog;
    }

    public static InputDialog showInputDialog(Stage stage, String title, String fieldTitle, boolean cancelable, InputValidator validator, InputDialogListener listener) {
        InputDialog dialog = new InputDialog(title, fieldTitle, cancelable, validator, listener);
        stage.addActor(dialog.fadeIn());
        return dialog;
    }

    public static DetailsDialog showErrorDialog(Stage stage, String text) {
        return showErrorDialog(stage, text, (String) null);
    }

    public static DetailsDialog showErrorDialog(Stage stage, String text, Exception exception) {
        if (exception == null) {
            return showErrorDialog(stage, text, (String) null);
        }
        return showErrorDialog(stage, text, getStackTrace(exception));
    }

    public static DetailsDialog showErrorDialog(Stage stage, String text, String details) {
        DetailsDialog dialog = new DetailsDialog(text, Text.ERROR.get(), details);
        stage.addActor(dialog.fadeIn());
        return dialog;
    }

    public static DetailsDialog showDetailsDialog(Stage stage, String text, String title, String details) {
        return showDetailsDialog(stage, text, title, details, false);
    }

    public static DetailsDialog showDetailsDialog(Stage stage, String text, String title, String details, boolean expandDetails) {
        DetailsDialog dialog = new DetailsDialog(text, title, details);
        dialog.setDetailsVisible(expandDetails);
        stage.addActor(dialog.fadeIn());
        return dialog;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static VisScrollPane createScrollPane(Actor widget) {
        VisScrollPane scrollPane = new VisScrollPane(widget);
        scrollPane.setOverscroll(false, true);
        scrollPane.setFadeScrollBars(false);
        return scrollPane;
    }

    private static String getStackTrace(Throwable throwable) {
        StringBuilder builder = new StringBuilder();
        getStackTrace(throwable, builder);
        return builder.toString();
    }

    private static void getStackTrace(Throwable throwable, StringBuilder builder) {
        StackTraceElement[] stackTrace;
        String msg = throwable.getMessage();
        if (msg != null) {
            builder.append(msg);
            builder.append("\n\n");
        }
        for (StackTraceElement element : throwable.getStackTrace()) {
            builder.append(element);
            builder.append("\n");
        }
        if (throwable.getCause() != null) {
            builder.append("\nCaused by: ");
            getStackTrace(throwable.getCause(), builder);
        }
    }

    /* loaded from: classes.dex */
    public static class InputDialog extends VisWindow {
        private VisTextButton cancelButton;
        private VisTextField field;
        private InputDialogListener listener;
        private VisTextButton okButton;

        public InputDialog(String title, String fieldTitle, boolean cancelable, InputValidator validator, InputDialogListener listener) {
            super(title);
            this.listener = listener;
            TableUtils.setSpacingDefaults(this);
            setModal(true);
            if (cancelable) {
                addCloseButton();
                closeOnEscape();
            }
            ButtonBar buttonBar = new ButtonBar();
            buttonBar.setIgnoreSpacing(true);
            ButtonBar.ButtonType buttonType = ButtonBar.ButtonType.CANCEL;
            VisTextButton visTextButton = new VisTextButton(ButtonBar.ButtonType.CANCEL.getText());
            this.cancelButton = visTextButton;
            buttonBar.setButton(buttonType, visTextButton);
            ButtonBar.ButtonType buttonType2 = ButtonBar.ButtonType.OK;
            VisTextButton visTextButton2 = new VisTextButton(ButtonBar.ButtonType.OK.getText());
            this.okButton = visTextButton2;
            buttonBar.setButton(buttonType2, visTextButton2);
            VisTable fieldTable = new VisTable(true);
            if (validator == null) {
                this.field = new VisTextField();
            } else {
                this.field = new VisValidatableTextField(validator);
            }
            if (fieldTitle != null) {
                fieldTable.add((VisTable) new VisLabel(fieldTitle));
            }
            fieldTable.add((VisTable) this.field).expand().fill();
            add((InputDialog) fieldTable).padTop(3.0f).spaceBottom(4.0f);
            row();
            add((InputDialog) buttonBar.createTable()).padBottom(3.0f);
            addListeners();
            if (validator != null) {
                addValidatableFieldListener(this.field);
                this.okButton.setDisabled(true ^ this.field.isInputValid());
            }
            pack();
            centerWindow();
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.kotcrab.vis.ui.widget.VisWindow
        public void close() {
            super.close();
            this.listener.canceled();
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.kotcrab.vis.ui.widget.VisWindow, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
        public void setStage(Stage stage) {
            super.setStage(stage);
            if (stage != null) {
                this.field.focusField();
            }
        }

        public InputDialog setText(String text) {
            return setText(text, false);
        }

        public InputDialog setText(String text, boolean selectText) {
            this.field.setText(text);
            this.field.setCursorPosition(text.length());
            if (selectText) {
                this.field.selectAll();
            }
            return this;
        }

        private InputDialog addValidatableFieldListener(final VisTextField field) {
            field.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.util.dialog.Dialogs.InputDialog.1
                @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                    if (field.isInputValid()) {
                        InputDialog.this.okButton.setDisabled(false);
                    } else {
                        InputDialog.this.okButton.setDisabled(true);
                    }
                }
            });
            return this;
        }

        private void addListeners() {
            this.okButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.util.dialog.Dialogs.InputDialog.2
                @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                    InputDialog.this.listener.finished(InputDialog.this.field.getText());
                    InputDialog.this.fadeOut();
                }
            });
            this.cancelButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.util.dialog.Dialogs.InputDialog.3
                @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                    InputDialog.this.close();
                }
            });
            this.field.addListener(new InputListener() { // from class: com.kotcrab.vis.ui.util.dialog.Dialogs.InputDialog.4
                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public boolean keyDown(InputEvent event, int keycode) {
                    if (keycode == 66 && !InputDialog.this.okButton.isDisabled()) {
                        InputDialog.this.listener.finished(InputDialog.this.field.getText());
                        InputDialog.this.fadeOut();
                    }
                    return super.keyDown(event, keycode);
                }
            });
        }
    }

    /* loaded from: classes.dex */
    public static class OptionDialog extends VisWindow {
        private final ButtonBar buttonBar;

        public OptionDialog(String title, String text, OptionDialogType type, final OptionDialogListener listener) {
            super(title);
            setModal(true);
            add((OptionDialog) new VisLabel(text, 1));
            row();
            defaults().space(6.0f);
            defaults().padBottom(3.0f);
            this.buttonBar = new ButtonBar();
            this.buttonBar.setIgnoreSpacing(true);
            ChangeListener yesBtnListener = new ChangeListener() { // from class: com.kotcrab.vis.ui.util.dialog.Dialogs.OptionDialog.1
                @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                    listener.yes();
                    OptionDialog.this.fadeOut();
                }
            };
            ChangeListener noBtnListener = new ChangeListener() { // from class: com.kotcrab.vis.ui.util.dialog.Dialogs.OptionDialog.2
                @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                    listener.no();
                    OptionDialog.this.fadeOut();
                }
            };
            ChangeListener cancelBtnListener = new ChangeListener() { // from class: com.kotcrab.vis.ui.util.dialog.Dialogs.OptionDialog.3
                @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                    listener.cancel();
                    OptionDialog.this.fadeOut();
                }
            };
            int i = AnonymousClass2.$SwitchMap$com$kotcrab$vis$ui$util$dialog$Dialogs$OptionDialogType[type.ordinal()];
            if (i == 1) {
                this.buttonBar.setButton(ButtonBar.ButtonType.YES, yesBtnListener);
                this.buttonBar.setButton(ButtonBar.ButtonType.NO, noBtnListener);
            } else if (i == 2) {
                this.buttonBar.setButton(ButtonBar.ButtonType.YES, yesBtnListener);
                this.buttonBar.setButton(ButtonBar.ButtonType.CANCEL, cancelBtnListener);
            } else if (i == 3) {
                this.buttonBar.setButton(ButtonBar.ButtonType.YES, yesBtnListener);
                this.buttonBar.setButton(ButtonBar.ButtonType.NO, noBtnListener);
                this.buttonBar.setButton(ButtonBar.ButtonType.CANCEL, cancelBtnListener);
            }
            add((OptionDialog) this.buttonBar.createTable());
            pack();
            centerWindow();
        }

        public OptionDialog setNoButtonText(String text) {
            this.buttonBar.getTextButton(ButtonBar.ButtonType.NO).setText(text);
            pack();
            return this;
        }

        public OptionDialog setYesButtonText(String text) {
            this.buttonBar.getTextButton(ButtonBar.ButtonType.YES).setText(text);
            pack();
            return this;
        }

        public OptionDialog setCancelButtonText(String text) {
            this.buttonBar.getTextButton(ButtonBar.ButtonType.CANCEL).setText(text);
            pack();
            return this;
        }
    }

    /* renamed from: com.kotcrab.vis.ui.util.dialog.Dialogs$2  reason: invalid class name */
    /* loaded from: classes.dex */
    static /* synthetic */ class AnonymousClass2 {
        static final /* synthetic */ int[] $SwitchMap$com$kotcrab$vis$ui$util$dialog$Dialogs$OptionDialogType = new int[OptionDialogType.values().length];

        static {
            try {
                $SwitchMap$com$kotcrab$vis$ui$util$dialog$Dialogs$OptionDialogType[OptionDialogType.YES_NO.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$kotcrab$vis$ui$util$dialog$Dialogs$OptionDialogType[OptionDialogType.YES_CANCEL.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$kotcrab$vis$ui$util$dialog$Dialogs$OptionDialogType[OptionDialogType.YES_NO_CANCEL.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
        }
    }

    /* loaded from: classes.dex */
    public static class DetailsDialog extends VisDialog {
        private VisTextButton copyButton;
        private Cell<?> detailsCell;
        private VisLabel detailsLabel;
        private VisTable detailsTable;
        private boolean detailsVisible;

        public DetailsDialog(String text, String title, String details) {
            super(title);
            this.detailsTable = new VisTable(true);
            text(text);
            if (details != null) {
                this.copyButton = new VisTextButton(Text.COPY.get());
                this.detailsLabel = new VisLabel(details);
                Sizes sizes = VisUI.getSizes();
                this.copyButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.util.dialog.Dialogs.DetailsDialog.1
                    @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                    public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                        Gdx.app.getClipboard().setContents(DetailsDialog.this.detailsLabel.getText().toString());
                        DetailsDialog.this.copyButton.setText(Text.COPIED.get());
                    }
                });
                this.detailsTable.add((VisTable) new VisLabel(Text.DETAILS_COLON.get())).left().expand().padTop(6.0f);
                this.detailsTable.add((VisTable) this.copyButton);
                this.detailsTable.row();
                VisTable detailsTable = new VisTable();
                detailsTable.add((VisTable) this.detailsLabel).top().expand().fillX();
                this.detailsTable.add((VisTable) Dialogs.createScrollPane(detailsTable)).colspan(2).minWidth(sizes.scaleFactor * 600.0f).height(sizes.scaleFactor * 300.0f);
                getContentTable().row();
                this.detailsCell = getContentTable().add(this.detailsTable);
                this.detailsCell.setActor(null);
                button(Text.DETAILS.get(), (Object) 2);
            }
            button(ButtonBar.ButtonType.OK.getText(), (Object) 1).padBottom(3.0f);
            pack();
            centerWindow();
        }

        @Override // com.kotcrab.vis.ui.widget.VisDialog
        protected void result(Object object) {
            int result = ((Integer) object).intValue();
            if (result == 2) {
                setDetailsVisible(!this.detailsVisible);
                cancel();
            }
        }

        public void setWrapDetails(boolean wrap) {
            this.detailsLabel.setWrap(wrap);
        }

        public void setCopyDetailsButtonVisible(boolean visible) {
            this.copyButton.setVisible(visible);
        }

        public boolean isCopyDetailsButtonVisible() {
            return this.copyButton.isVisible();
        }

        public void setDetailsVisible(boolean visible) {
            if (this.detailsVisible == visible) {
                return;
            }
            this.detailsVisible = visible;
            Cell<?> cell = this.detailsCell;
            cell.setActor(cell.hasActor() ? null : this.detailsTable);
            if (getStage() == null) {
                Gdx.app.postRunnable(new Runnable() { // from class: com.kotcrab.vis.ui.util.dialog.Dialogs.DetailsDialog.2
                    @Override // java.lang.Runnable
                    public void run() {
                        DetailsDialog.this.pack();
                        DetailsDialog.this.centerWindow();
                    }
                });
                return;
            }
            pack();
            centerWindow();
        }

        public boolean isDetailsVisible() {
            return this.detailsVisible;
        }
    }

    /* loaded from: classes.dex */
    public static class ConfirmDialog<T> extends VisDialog {
        private ConfirmDialogListener<T> listener;

        public ConfirmDialog(String title, String text, String[] buttons, T[] returns, ConfirmDialogListener<T> listener) {
            super(title);
            if (buttons.length != returns.length) {
                throw new IllegalStateException("buttons.length must be equal to returns.length");
            }
            this.listener = listener;
            text(new VisLabel(text, 1));
            defaults().padBottom(3.0f);
            for (int i = 0; i < buttons.length; i++) {
                button(buttons[i], returns[i]);
            }
            padBottom(3.0f);
            pack();
            centerWindow();
        }

        @Override // com.kotcrab.vis.ui.widget.VisDialog
        protected void result(Object object) {
            this.listener.result(object);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public enum Text implements BundleText {
        DETAILS("details"),
        DETAILS_COLON("detailsColon"),
        COPY("copy"),
        COPIED("copied"),
        ERROR("error");
        
        private final String name;

        Text(String name) {
            this.name = name;
        }

        private static I18NBundle getBundle() {
            return Locales.getDialogsBundle();
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