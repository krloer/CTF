package com.kotcrab.vis.ui.widget.file;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.Cell;
import com.badlogic.gdx.scenes.scene2d.ui.Image;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.scenes.scene2d.ui.Value;
import com.badlogic.gdx.scenes.scene2d.ui.VerticalGroup;
import com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.ClickListener;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.FocusListener;
import com.badlogic.gdx.scenes.scene2d.utils.Layout;
import com.badlogic.gdx.scenes.scene2d.utils.UIUtils;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.IdentityMap;
import com.badlogic.gdx.utils.Scaling;
import com.badlogic.gdx.utils.Timer;
import com.kotcrab.vis.ui.FocusManager;
import com.kotcrab.vis.ui.Focusable;
import com.kotcrab.vis.ui.Sizes;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.layout.GridGroup;
import com.kotcrab.vis.ui.util.OsUtils;
import com.kotcrab.vis.ui.util.dialog.Dialogs;
import com.kotcrab.vis.ui.util.dialog.InputDialogAdapter;
import com.kotcrab.vis.ui.util.dialog.InputDialogListener;
import com.kotcrab.vis.ui.util.dialog.OptionDialogAdapter;
import com.kotcrab.vis.ui.util.value.ConstantIfVisibleValue;
import com.kotcrab.vis.ui.util.value.PrefHeightIfVisibleValue;
import com.kotcrab.vis.ui.util.value.PrefWidthIfVisibleValue;
import com.kotcrab.vis.ui.widget.BusyBar;
import com.kotcrab.vis.ui.widget.ButtonBar;
import com.kotcrab.vis.ui.widget.ListView;
import com.kotcrab.vis.ui.widget.MenuItem;
import com.kotcrab.vis.ui.widget.PopupMenu;
import com.kotcrab.vis.ui.widget.Tooltip;
import com.kotcrab.vis.ui.widget.VisCheckBox;
import com.kotcrab.vis.ui.widget.VisImage;
import com.kotcrab.vis.ui.widget.VisImageButton;
import com.kotcrab.vis.ui.widget.VisLabel;
import com.kotcrab.vis.ui.widget.VisScrollPane;
import com.kotcrab.vis.ui.widget.VisSelectBox;
import com.kotcrab.vis.ui.widget.VisSplitPane;
import com.kotcrab.vis.ui.widget.VisTable;
import com.kotcrab.vis.ui.widget.VisTextButton;
import com.kotcrab.vis.ui.widget.VisTextField;
import com.kotcrab.vis.ui.widget.VisWindow;
import com.kotcrab.vis.ui.widget.file.FileTypeFilter;
import com.kotcrab.vis.ui.widget.file.internal.DirsSuggestionPopup;
import com.kotcrab.vis.ui.widget.file.internal.DriveCheckerService;
import com.kotcrab.vis.ui.widget.file.internal.FileChooserText;
import com.kotcrab.vis.ui.widget.file.internal.FileChooserWinService;
import com.kotcrab.vis.ui.widget.file.internal.FileHandleMetadata;
import com.kotcrab.vis.ui.widget.file.internal.FileHistoryManager;
import com.kotcrab.vis.ui.widget.file.internal.FileListAdapter;
import com.kotcrab.vis.ui.widget.file.internal.FilePopupMenu;
import com.kotcrab.vis.ui.widget.file.internal.FileSuggestionPopup;
import com.kotcrab.vis.ui.widget.file.internal.IconStack;
import com.kotcrab.vis.ui.widget.file.internal.PreferencesIO;
import com.kotcrab.vis.ui.widget.file.internal.ServiceThreadFactory;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.text.Typography;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class FileChooser extends VisWindow implements FileHistoryManager.FileHistoryCallback {
    public static final int DEFAULT_KEY = -1;
    private static final long FILE_WATCHER_CHECK_DELAY_MILLIS = 2000;
    private FileTypeFilter.Rule activeFileTypeRule;
    private FileChooserWinService chooserWinService;
    private VisTextButton confirmButton;
    private FileHandle currentDirectory;
    private Array<FileHandle> currentFiles;
    private IdentityMap<FileHandle, FileHandleMetadata> currentFilesMetadata;
    private VisTextField currentPath;
    private SimpleDateFormat dateFormat;
    private DirsSuggestionPopup dirsSuggestionPopup;
    private Array<DriveCheckerService.DriveCheckerListener> driveCheckerListeners;
    private DriveCheckerService driveCheckerService;
    private VisImageButton favoriteFolderButton;
    private Tooltip favoriteFolderButtonTooltip;
    private Array<FileHandle> favorites;
    private FileDeleter fileDeleter;
    private FileFilter fileFilter;
    private FileListAdapter fileListAdapter;
    private BusyBar fileListBusyBar;
    private ListView<FileHandle> fileListView;
    private FilePopupMenu fileMenu;
    private FileSuggestionPopup fileNameSuggestionPopup;
    private FileTypeFilter fileTypeFilter;
    private VisLabel fileTypeLabel;
    private VisSelectBox<FileTypeFilter.Rule> fileTypeSelectBox;
    private Thread fileWatcherThread;
    private boolean filesListRebuildScheduled;
    private int groupMultiSelectKey;
    private FileHistoryManager historyManager;
    private FileIconProvider iconProvider;
    private ExecutorService listDirExecutor;
    private Future<?> listDirFuture;
    private FileChooserListener listener;
    private VisSplitPane mainSplitPane;
    private float maxDateLabelWidth;
    private Mode mode;
    private int multiSelectKey;
    private boolean multiSelectionEnabled;
    private PreferencesIO preferencesIO;
    private Array<FileHandle> recentDirectories;
    private VisTextField selectedFileTextField;
    private Array<FileItem> selectedItems;
    private ShortcutItem selectedShortcut;
    private SelectionMode selectionMode;
    private VerticalGroup shortcutsFavoritesPanel;
    private boolean shortcutsListRebuildScheduled;
    private VerticalGroup shortcutsMainPanel;
    private VerticalGroup shortcutsRootsPanel;
    private VisTable shortcutsTable;
    private ShowBusyBarTask showBusyBarTask;
    private boolean showSelectionCheckboxes;
    private Sizes sizes;
    private AtomicReference<FileSorting> sorting;
    private AtomicBoolean sortingOrderAscending;
    private FileChooserStyle style;
    private ViewMode viewMode;
    private VisImageButton viewModeButton;
    private PopupMenu viewModePopupMenu;
    private boolean watchingFilesEnabled;
    private static final ShortcutsComparator SHORTCUTS_COMPARATOR = new ShortcutsComparator();
    private static final Vector2 tmpVector = new Vector2();
    private static boolean saveLastDirectory = false;
    public static boolean focusFileScrollPaneOnShow = true;

    /* loaded from: classes.dex */
    public interface FileDeleter {
        boolean delete(FileHandle fileHandle) throws IOException;

        boolean hasTrash();
    }

    /* loaded from: classes.dex */
    public interface FileIconProvider {
        void directoryChanged(FileHandle fileHandle);

        boolean isThumbnailModesSupported();

        Drawable provideIcon(FileItem fileItem);

        void viewModeChanged(ViewMode viewMode);
    }

    /* loaded from: classes.dex */
    public enum HistoryPolicy {
        ADD,
        CLEAR,
        IGNORE
    }

    /* loaded from: classes.dex */
    public enum Mode {
        OPEN,
        SAVE
    }

    /* loaded from: classes.dex */
    public enum SelectionMode {
        FILES,
        DIRECTORIES,
        FILES_AND_DIRECTORIES
    }

    public FileChooser(Mode mode) {
        this((FileHandle) null, mode);
    }

    public FileChooser(FileHandle directory, Mode mode) {
        super(BuildConfig.FLAVOR);
        this.viewMode = ViewMode.DETAILS;
        this.selectionMode = SelectionMode.FILES;
        this.sorting = new AtomicReference<>(FileSorting.NAME);
        this.sortingOrderAscending = new AtomicBoolean(true);
        this.listener = new FileChooserAdapter();
        this.fileFilter = new DefaultFileFilter(this);
        this.fileDeleter = new DefaultFileDeleter();
        this.fileTypeFilter = null;
        this.activeFileTypeRule = null;
        this.driveCheckerService = DriveCheckerService.getInstance();
        this.driveCheckerListeners = new Array<>();
        this.chooserWinService = FileChooserWinService.getInstance();
        this.listDirExecutor = Executors.newSingleThreadExecutor(new ServiceThreadFactory("FileChooserListDirThread"));
        this.showBusyBarTask = new ShowBusyBarTask();
        this.dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        this.showSelectionCheckboxes = false;
        this.multiSelectionEnabled = false;
        this.groupMultiSelectKey = -1;
        this.multiSelectKey = -1;
        this.currentFiles = new Array<>();
        this.currentFilesMetadata = new IdentityMap<>();
        this.selectedItems = new Array<>();
        this.watchingFilesEnabled = true;
        this.mode = mode;
        getTitleLabel().setText(FileChooserText.TITLE_CHOOSE_FILES.get());
        this.style = (FileChooserStyle) VisUI.getSkin().get(FileChooserStyle.class);
        this.sizes = VisUI.getSizes();
        init(directory);
    }

    public FileChooser(String title, Mode mode) {
        this("default", title, mode);
    }

    public FileChooser(String styleName, String title, Mode mode) {
        super(title);
        this.viewMode = ViewMode.DETAILS;
        this.selectionMode = SelectionMode.FILES;
        this.sorting = new AtomicReference<>(FileSorting.NAME);
        this.sortingOrderAscending = new AtomicBoolean(true);
        this.listener = new FileChooserAdapter();
        this.fileFilter = new DefaultFileFilter(this);
        this.fileDeleter = new DefaultFileDeleter();
        this.fileTypeFilter = null;
        this.activeFileTypeRule = null;
        this.driveCheckerService = DriveCheckerService.getInstance();
        this.driveCheckerListeners = new Array<>();
        this.chooserWinService = FileChooserWinService.getInstance();
        this.listDirExecutor = Executors.newSingleThreadExecutor(new ServiceThreadFactory("FileChooserListDirThread"));
        this.showBusyBarTask = new ShowBusyBarTask();
        this.dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        this.showSelectionCheckboxes = false;
        this.multiSelectionEnabled = false;
        this.groupMultiSelectKey = -1;
        this.multiSelectKey = -1;
        this.currentFiles = new Array<>();
        this.currentFilesMetadata = new IdentityMap<>();
        this.selectedItems = new Array<>();
        this.watchingFilesEnabled = true;
        this.mode = mode;
        this.style = (FileChooserStyle) VisUI.getSkin().get(styleName, FileChooserStyle.class);
        this.sizes = VisUI.getSizes();
        init(null);
    }

    public static void setDefaultPrefsName(String prefsName) {
        PreferencesIO.setDefaultPrefsName(prefsName);
    }

    @Deprecated
    public static void setFavoritesPrefsName(String name) {
        PreferencesIO.setDefaultPrefsName(name);
    }

    private void init(FileHandle directory) {
        setModal(true);
        setResizable(true);
        setMovable(true);
        addCloseButton();
        closeOnEscape();
        this.iconProvider = new DefaultFileIconProvider(this);
        this.preferencesIO = new PreferencesIO();
        reloadPreferences(false);
        createToolbar();
        this.viewModePopupMenu = new PopupMenu(this.style.popupMenuStyle);
        createViewModePopupMenu();
        createCenterContentPanel();
        createFileTextBox();
        createBottomButtons();
        createShortcutsMainPanel();
        this.shortcutsRootsPanel = new VerticalGroup();
        this.shortcutsFavoritesPanel = new VerticalGroup();
        rebuildShortcutsFavoritesPanel();
        this.fileMenu = new FilePopupMenu(this, new FilePopupMenu.FilePopupMenuCallback() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.1
            @Override // com.kotcrab.vis.ui.widget.file.internal.FilePopupMenu.FilePopupMenuCallback
            public void showNewDirDialog() {
                FileChooser.this.showNewDirectoryDialog();
            }

            @Override // com.kotcrab.vis.ui.widget.file.internal.FilePopupMenu.FilePopupMenuCallback
            public void showFileDelDialog(FileHandle file) {
                FileChooser.this.showFileDeleteDialog(file);
            }
        });
        this.fileNameSuggestionPopup = new FileSuggestionPopup(this);
        rebuildShortcutsList();
        if (directory == null) {
            FileHandle startingDir = saveLastDirectory ? this.preferencesIO.loadLastDirectory() : null;
            if (startingDir == null || !startingDir.exists()) {
                startingDir = getDefaultStartingDirectory();
            }
            setDirectory(startingDir, HistoryPolicy.IGNORE);
        } else {
            setDirectory(directory, HistoryPolicy.IGNORE);
        }
        setSize(500.0f, 600.0f);
        centerWindow();
        createListeners();
        setFileTypeFilter(null);
        setFavoriteFolderButtonVisible(false);
    }

    private void createToolbar() {
        VisTable toolbarTable = new VisTable(true);
        toolbarTable.defaults().minWidth(30.0f).right();
        add((FileChooser) toolbarTable).fillX().expandX().pad(3.0f).padRight(2.0f);
        this.historyManager = new FileHistoryManager(this.style, this);
        this.currentPath = new VisTextField();
        final VisImageButton showRecentDirButton = new VisImageButton(this.style.expandDropdown);
        showRecentDirButton.setFocusBorderEnabled(false);
        this.dirsSuggestionPopup = new DirsSuggestionPopup(this, this.currentPath);
        this.dirsSuggestionPopup.setListener(new PopupMenu.PopupMenuListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.2
            @Override // com.kotcrab.vis.ui.widget.PopupMenu.PopupMenuListener
            public void activeItemChanged(MenuItem newItem, boolean changedByKeyboard) {
                if (changedByKeyboard && newItem != null) {
                    FileChooser.this.setCurrentPathFieldText(newItem.getText().toString());
                }
            }
        });
        this.currentPath.addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.3
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyTyped(InputEvent event, char character) {
                if (event.getKeyCode() == 66) {
                    FileChooser.this.dirsSuggestionPopup.remove();
                    return false;
                }
                float targetWidth = FileChooser.this.currentPath.getWidth() + showRecentDirButton.getWidth();
                FileChooser.this.dirsSuggestionPopup.pathFieldKeyTyped(FileChooser.this.getChooserStage(), targetWidth);
                return false;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyDown(InputEvent event, int keycode) {
                if (keycode == 66) {
                    FileHandle file = Gdx.files.absolute(FileChooser.this.currentPath.getText());
                    if (!file.exists()) {
                        FileChooser.this.showDialog(FileChooserText.POPUP_DIRECTORY_DOES_NOT_EXIST.get());
                        FileChooser fileChooser = FileChooser.this;
                        fileChooser.setCurrentPathFieldText(fileChooser.currentDirectory.path());
                    } else {
                        if (!file.isDirectory()) {
                            file = file.parent();
                        }
                        FileChooser.this.setDirectory(file, HistoryPolicy.ADD);
                        FileChooser.this.addRecentDirectory(file);
                    }
                    event.stop();
                    return false;
                }
                return false;
            }
        });
        this.currentPath.addListener(new FocusListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.4
            @Override // com.badlogic.gdx.scenes.scene2d.utils.FocusListener
            public void keyboardFocusChanged(FocusListener.FocusEvent event, Actor actor, boolean focused) {
                if (!focused) {
                    FileChooser fileChooser = FileChooser.this;
                    fileChooser.setCurrentPathFieldText(fileChooser.currentDirectory.path());
                }
            }
        });
        showRecentDirButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.5
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                float targetWidth = FileChooser.this.currentPath.getWidth() + showRecentDirButton.getWidth();
                FileChooser.this.dirsSuggestionPopup.showRecentDirectories(FileChooser.this.getChooserStage(), FileChooser.this.recentDirectories, targetWidth);
            }
        });
        VisImageButton folderParentButton = new VisImageButton(this.style.iconFolderParent, FileChooserText.PARENT_DIRECTORY.get());
        this.favoriteFolderButton = new VisImageButton(this.style.iconStar);
        this.favoriteFolderButtonTooltip = new Tooltip.Builder(FileChooserText.CONTEXT_MENU_ADD_TO_FAVORITES.get()).target(this.favoriteFolderButton).build();
        this.viewModeButton = new VisImageButton(this.style.iconListSettings);
        new Tooltip.Builder(FileChooserText.CHANGE_VIEW_MODE.get()).target(this.viewModeButton).build();
        VisImageButton folderNewButton = new VisImageButton(this.style.iconFolderNew, FileChooserText.NEW_DIRECTORY.get());
        toolbarTable.add(this.historyManager.getButtonsTable());
        toolbarTable.add((VisTable) this.currentPath).spaceRight(0.0f).expand().fill();
        toolbarTable.add((VisTable) showRecentDirButton).width(this.sizes.scaleFactor * 15.0f).growY();
        toolbarTable.add((VisTable) folderParentButton);
        toolbarTable.add((VisTable) this.favoriteFolderButton).width(PrefWidthIfVisibleValue.INSTANCE).spaceRight(new ConstantIfVisibleValue(this.sizes.spacingRight));
        toolbarTable.add((VisTable) this.viewModeButton).width(PrefWidthIfVisibleValue.INSTANCE).spaceRight(new ConstantIfVisibleValue(this.sizes.spacingRight));
        toolbarTable.add((VisTable) folderNewButton);
        folderParentButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.6
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                FileHandle parent = FileChooser.this.currentDirectory.parent();
                if (OsUtils.isWindows() && FileChooser.this.currentDirectory.path().endsWith(":/")) {
                    return;
                }
                FileChooser.this.setDirectory(parent, HistoryPolicy.ADD);
            }
        });
        this.favoriteFolderButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.7
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                if (FileChooser.this.favorites.contains(FileChooser.this.currentDirectory, false)) {
                    FileChooser fileChooser = FileChooser.this;
                    fileChooser.removeFavorite(fileChooser.currentDirectory);
                    return;
                }
                FileChooser fileChooser2 = FileChooser.this;
                fileChooser2.addFavorite(fileChooser2.currentDirectory);
            }
        });
        folderNewButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.8
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                FileChooser.this.showNewDirectoryDialog();
            }
        });
        addListener(this.historyManager.getDefaultClickListener());
    }

    private void createViewModePopupMenu() {
        rebuildViewModePopupMenu();
        this.viewModeButton.addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.9
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                Gdx.app.postRunnable(new Runnable() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.9.1
                    @Override // java.lang.Runnable
                    public void run() {
                        FileChooser.this.viewModePopupMenu.showMenu(FileChooser.this.getChooserStage(), FileChooser.this.viewModeButton);
                    }
                });
                return true;
            }
        });
    }

    private void rebuildViewModePopupMenu() {
        ViewMode[] values;
        this.viewModePopupMenu.clear();
        for (final ViewMode mode : ViewMode.values()) {
            if (!mode.thumbnailMode || this.iconProvider.isThumbnailModesSupported()) {
                this.viewModePopupMenu.addItem(new MenuItem(mode.getBundleText(), new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.10
                    @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                    public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                        FileChooser.this.setViewMode(mode);
                    }
                }));
            }
        }
    }

    private void updateFavoriteFolderButton() {
        VisLabel label = (VisLabel) this.favoriteFolderButtonTooltip.getContent();
        if (this.favorites.contains(this.currentDirectory, false)) {
            this.favoriteFolderButton.getStyle().imageUp = this.style.iconStar;
            label.setText(FileChooserText.CONTEXT_MENU_REMOVE_FROM_FAVORITES.get());
        } else {
            this.favoriteFolderButton.getStyle().imageUp = this.style.iconStarOutline;
            label.setText(FileChooserText.CONTEXT_MENU_ADD_TO_FAVORITES.get());
        }
        this.favoriteFolderButtonTooltip.pack();
    }

    private void createCenterContentPanel() {
        this.fileListAdapter = new FileListAdapter(this, this.currentFiles);
        this.fileListView = new ListView<>(this.fileListAdapter);
        setupDefaultScrollPane(this.fileListView.getScrollPane());
        VisTable fileScrollPaneTable = new VisTable();
        this.fileListBusyBar = new BusyBar();
        this.fileListBusyBar.setVisible(false);
        fileScrollPaneTable.add((VisTable) this.fileListBusyBar).space(0.0f).height(PrefHeightIfVisibleValue.INSTANCE).growX().row();
        fileScrollPaneTable.add(this.fileListView.getMainTable()).pad(2.0f).top().expand().fillX();
        fileScrollPaneTable.setTouchable(Touchable.enabled);
        this.shortcutsTable = new VisTable();
        final VisScrollPane shortcutsScrollPane = setupDefaultScrollPane(new VisScrollPane(this.shortcutsTable));
        VisTable shortcutsScrollPaneTable = new VisTable();
        shortcutsScrollPaneTable.add((VisTable) shortcutsScrollPane).pad(2.0f).top().expand().fillX();
        this.mainSplitPane = new VisSplitPane(shortcutsScrollPaneTable, fileScrollPaneTable, false) { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.11
            @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
            public void invalidate() {
                super.invalidate();
                FileChooser.this.invalidateChildHierarchy(shortcutsScrollPane);
            }
        };
        this.mainSplitPane.setSplitAmount(0.3f);
        this.mainSplitPane.setMinSplitAmount(0.05f);
        this.mainSplitPane.setMaxSplitAmount(0.8f);
        row();
        add((FileChooser) this.mainSplitPane).expand().fill();
        row();
        fileScrollPaneTable.addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.12
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                return true;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                if (button == 1 && !FileChooser.this.fileMenu.isAddedToStage()) {
                    FileChooser.this.fileMenu.build();
                    FileChooser.this.fileMenu.showMenu(FileChooser.this.getChooserStage(), event.getStageX(), event.getStageY());
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void invalidateChildHierarchy(WidgetGroup layout) {
        if (layout != null) {
            layout.invalidate();
            Array.ArrayIterator<Actor> it = layout.getChildren().iterator();
            while (it.hasNext()) {
                Actor actor = it.next();
                if (actor instanceof WidgetGroup) {
                    invalidateChildHierarchy((WidgetGroup) actor);
                } else if (actor instanceof Layout) {
                    ((Layout) actor).invalidate();
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setCurrentPathFieldText(String text) {
        this.currentPath.setText(text);
        this.currentPath.setCursorAtTextEnd();
    }

    private void createFileTextBox() {
        VisTable table = new VisTable(true);
        VisLabel nameLabel = new VisLabel(FileChooserText.FILE_NAME.get());
        this.selectedFileTextField = new VisTextField();
        this.fileTypeLabel = new VisLabel(FileChooserText.FILE_TYPE.get());
        this.fileTypeSelectBox = new VisSelectBox<>();
        this.fileTypeSelectBox.getSelection().setProgrammaticChangeEvents(false);
        this.fileTypeSelectBox.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.13
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                FileChooser fileChooser = FileChooser.this;
                fileChooser.activeFileTypeRule = (FileTypeFilter.Rule) fileChooser.fileTypeSelectBox.getSelected();
                FileChooser.this.rebuildFileList();
            }
        });
        table.defaults().left();
        table.add((VisTable) nameLabel).spaceBottom(new ConstantIfVisibleValue(this.fileTypeSelectBox, 5.0f));
        table.add((VisTable) this.selectedFileTextField).expandX().fillX().spaceBottom(new ConstantIfVisibleValue(this.fileTypeSelectBox, 5.0f)).row();
        table.add((VisTable) this.fileTypeLabel).height(PrefHeightIfVisibleValue.INSTANCE).spaceBottom(new ConstantIfVisibleValue(this.sizes.spacingBottom));
        table.add((VisTable) this.fileTypeSelectBox).height(PrefHeightIfVisibleValue.INSTANCE).spaceBottom(new ConstantIfVisibleValue(this.sizes.spacingBottom)).expand().fill();
        this.selectedFileTextField.addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.14
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyDown(InputEvent event, int keycode) {
                if (keycode == 66) {
                    FileChooser.this.selectionFinished();
                    return true;
                }
                return false;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyTyped(InputEvent event, char character) {
                FileChooser.this.deselectAll(false);
                FileChooser.this.fileNameSuggestionPopup.pathFieldKeyTyped(FileChooser.this.getChooserStage(), FileChooser.this.currentFiles, FileChooser.this.selectedFileTextField);
                FileHandle enteredFile = FileChooser.this.currentDirectory.child(FileChooser.this.selectedFileTextField.getText());
                if (FileChooser.this.currentFiles.contains(enteredFile, false)) {
                    FileChooser.this.highlightFiles(enteredFile);
                }
                return false;
            }
        });
        add((FileChooser) table).expandX().fillX().pad(3.0f).padRight(2.0f).padBottom(2.0f);
        row();
    }

    private void updateFileTypeSelectBox() {
        if (this.fileTypeFilter == null || this.selectionMode == SelectionMode.DIRECTORIES) {
            this.fileTypeLabel.setVisible(false);
            this.fileTypeSelectBox.setVisible(false);
            this.fileTypeSelectBox.invalidateHierarchy();
            return;
        }
        this.fileTypeLabel.setVisible(true);
        this.fileTypeSelectBox.setVisible(true);
        this.fileTypeSelectBox.invalidateHierarchy();
        Array<FileTypeFilter.Rule> rules = new Array<>(this.fileTypeFilter.getRules());
        if (this.fileTypeFilter.isAllTypesAllowed()) {
            FileTypeFilter.Rule allTypesRule = new FileTypeFilter.Rule(FileChooserText.ALL_FILES.get());
            rules.add(allTypesRule);
        }
        this.fileTypeSelectBox.setItems(rules);
        this.fileTypeSelectBox.setSelected(this.activeFileTypeRule);
    }

    private void createBottomButtons() {
        VisTextButton cancelButton = new VisTextButton(FileChooserText.CANCEL.get());
        this.confirmButton = new VisTextButton((this.mode == Mode.OPEN ? FileChooserText.OPEN : FileChooserText.SAVE).get());
        VisTable buttonTable = new VisTable(true);
        buttonTable.defaults().minWidth(70.0f).right();
        add((FileChooser) buttonTable).padTop(3.0f).padBottom(3.0f).padRight(2.0f).fillX().expandX();
        ButtonBar buttonBar = new ButtonBar();
        buttonBar.setIgnoreSpacing(true);
        buttonBar.setButton(ButtonBar.ButtonType.CANCEL, cancelButton);
        buttonBar.setButton(ButtonBar.ButtonType.OK, this.confirmButton);
        buttonTable.add(buttonBar.createTable()).expand().right();
        cancelButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.15
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                FileChooser.this.fadeOut();
                FileChooser.this.listener.canceled();
            }
        });
        this.confirmButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.16
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                FileChooser.this.selectionFinished();
            }
        });
    }

    private void createShortcutsMainPanel() {
        this.shortcutsMainPanel = new VerticalGroup();
        String userHome = System.getProperty("user.home");
        String userName = System.getProperty("user.name");
        File userDesktop = new File(userHome + "/Desktop");
        if (userDesktop.exists()) {
            this.shortcutsMainPanel.addActor(new ShortcutItem(userDesktop, FileChooserText.DESKTOP.get(), this.style.iconFolder));
        }
        this.shortcutsMainPanel.addActor(new ShortcutItem(new File(userHome), userName, this.style.iconFolder));
    }

    private void createListeners() {
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.17
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyDown(InputEvent event, int keycode) {
                if (keycode == 29 && UIUtils.ctrl() && !(FileChooser.this.getChooserStage().getKeyboardFocus() instanceof VisTextField)) {
                    FileChooser.this.selectAll();
                    return true;
                }
                return false;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyTyped(InputEvent event, char character) {
                if (!(FileChooser.this.getChooserStage().getKeyboardFocus() instanceof VisTextField) && Character.isLetterOrDigit(character)) {
                    String name = String.valueOf(character);
                    Iterator it = FileChooser.this.currentFiles.iterator();
                    while (it.hasNext()) {
                        FileHandle file = (FileHandle) it.next();
                        if (file.name().toLowerCase().startsWith(name)) {
                            FileChooser.this.deselectAll();
                            FileChooser.this.highlightFiles(file);
                            return true;
                        }
                    }
                    return false;
                }
                return false;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void selectionFinished() {
        if (this.selectedItems.size == 1) {
            if (this.selectionMode == SelectionMode.FILES) {
                FileHandle selected = this.selectedItems.get(0).getFile();
                if (selected.isDirectory()) {
                    setDirectory(selected, HistoryPolicy.ADD);
                    return;
                }
            }
            if (this.selectionMode == SelectionMode.DIRECTORIES && !this.selectedItems.get(0).getFile().isDirectory()) {
                showDialog(FileChooserText.POPUP_ONLY_DIRECTORIES.get());
                return;
            }
        }
        if (this.selectedItems.size > 0 || this.mode == Mode.SAVE) {
            notifyListenerAndCloseDialog(getFileListFromSelected());
        } else if (this.selectionMode == SelectionMode.FILES) {
            showDialog(FileChooserText.POPUP_CHOOSE_FILE.get());
        } else {
            Array<FileHandle> files = new Array<>();
            if (this.selectedFileTextField.getText().length() != 0) {
                files.add(this.currentDirectory.child(this.selectedFileTextField.getText()));
            } else {
                files.add(this.currentDirectory);
            }
            notifyListenerAndCloseDialog(files);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.kotcrab.vis.ui.widget.VisWindow
    public void close() {
        this.listener.canceled();
        super.close();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyListenerAndCloseDialog(Array<FileHandle> files) {
        if (files == null) {
            return;
        }
        if (this.mode == Mode.OPEN) {
            Iterator it = files.iterator();
            while (it.hasNext()) {
                FileHandle file = (FileHandle) it.next();
                if (!file.exists()) {
                    showDialog(FileChooserText.POPUP_SELECTED_FILE_DOES_NOT_EXIST.get());
                    return;
                }
            }
        }
        if (files.size != 0) {
            this.listener.selected(files);
            if (saveLastDirectory) {
                this.preferencesIO.saveLastDirectory(this.currentDirectory);
            }
        }
        fadeOut();
    }

    @Override // com.kotcrab.vis.ui.widget.VisWindow
    public void fadeOut(float time) {
        super.fadeOut(time);
        this.fileMenu.remove();
        this.dirsSuggestionPopup.remove();
        this.fileNameSuggestionPopup.remove();
        this.viewModePopupMenu.remove();
    }

    protected VisScrollPane setupDefaultScrollPane(VisScrollPane scrollPane) {
        scrollPane.setOverscroll(false, false);
        scrollPane.setFlickScroll(false);
        scrollPane.setFadeScrollBars(false);
        scrollPane.setScrollingDisabled(true, false);
        return scrollPane;
    }

    private Array<FileHandle> getFileListFromSelected() {
        Array<FileHandle> list = new Array<>();
        if (this.mode == Mode.OPEN) {
            Iterator it = this.selectedItems.iterator();
            while (it.hasNext()) {
                FileItem item = (FileItem) it.next();
                list.add(item.getFile());
            }
            return list;
        } else if (this.selectedItems.size > 0) {
            Iterator it2 = this.selectedItems.iterator();
            while (it2.hasNext()) {
                FileItem item2 = (FileItem) it2.next();
                list.add(item2.getFile());
            }
            showOverwriteQuestion(list);
            return null;
        } else {
            String fileName = this.selectedFileTextField.getText();
            FileHandle file = this.currentDirectory.child(fileName);
            if (!FileUtils.isValidFileName(fileName)) {
                showDialog(FileChooserText.POPUP_FILENAME_INVALID.get());
                return null;
            } else if (file.exists()) {
                list.add(file);
                showOverwriteQuestion(list);
                return null;
            } else {
                FileTypeFilter.Rule rule = this.activeFileTypeRule;
                if (rule != null) {
                    Array<String> ruleExts = rule.getExtensions();
                    if (ruleExts.size > 0 && !ruleExts.contains(file.extension(), false)) {
                        file = file.sibling(file.nameWithoutExtension() + "." + ruleExts.first());
                    }
                }
                list.add(file);
                if (file.exists()) {
                    showOverwriteQuestion(list);
                    return null;
                }
                return list;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showDialog(String text) {
        Dialogs.showOKDialog(getChooserStage(), FileChooserText.POPUP_TITLE.get(), text);
    }

    private void showOverwriteQuestion(final Array<FileHandle> filesList) {
        String text = (filesList.size == 1 ? FileChooserText.POPUP_FILE_EXIST_OVERWRITE : FileChooserText.POPUP_MULTIPLE_FILE_EXIST_OVERWRITE).get();
        Dialogs.showOptionDialog(getChooserStage(), FileChooserText.POPUP_TITLE.get(), text, Dialogs.OptionDialogType.YES_NO, new OptionDialogAdapter() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.18
            @Override // com.kotcrab.vis.ui.util.dialog.OptionDialogAdapter, com.kotcrab.vis.ui.util.dialog.OptionDialogListener
            public void yes() {
                FileChooser.this.notifyListenerAndCloseDialog(filesList);
            }
        });
    }

    private void rebuildShortcutsList(boolean rebuildRootCache) {
        this.shortcutsTable.clear();
        this.shortcutsTable.add((VisTable) this.shortcutsMainPanel).left().row();
        this.shortcutsTable.addSeparator();
        if (rebuildRootCache) {
            rebuildFileRootsCache();
        }
        this.shortcutsTable.add((VisTable) this.shortcutsRootsPanel).left().row();
        if (this.shortcutsFavoritesPanel.getChildren().size > 0) {
            this.shortcutsTable.addSeparator();
        }
        this.shortcutsTable.add((VisTable) this.shortcutsFavoritesPanel).left().row();
    }

    private void rebuildShortcutsList() {
        this.shortcutsListRebuildScheduled = false;
        rebuildShortcutsList(true);
    }

    private void rebuildFileRootsCache() {
        this.shortcutsRootsPanel.clear();
        File[] roots = File.listRoots();
        this.driveCheckerListeners.clear();
        for (File root : roots) {
            DriveCheckerService.DriveCheckerListener listener = new DriveCheckerService.DriveCheckerListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.19
                @Override // com.kotcrab.vis.ui.widget.file.internal.DriveCheckerService.DriveCheckerListener
                public void rootMode(File root2, DriveCheckerService.RootMode mode) {
                    if (FileChooser.this.driveCheckerListeners.removeValue(this, true)) {
                        String initialName = root2.toString();
                        if (initialName.equals("/")) {
                            initialName = FileChooserText.COMPUTER.get();
                        }
                        FileChooser fileChooser = FileChooser.this;
                        ShortcutItem item = new ShortcutItem(root2, initialName, fileChooser.style.iconDrive);
                        if (OsUtils.isWindows()) {
                            FileChooser.this.chooserWinService.addListener(root2, item);
                        }
                        FileChooser.this.shortcutsRootsPanel.addActor(item);
                        FileChooser.this.shortcutsRootsPanel.getChildren().sort(FileChooser.SHORTCUTS_COMPARATOR);
                    }
                }
            };
            this.driveCheckerListeners.add(listener);
            this.driveCheckerService.addListener(root, this.mode == Mode.OPEN ? DriveCheckerService.RootMode.READABLE : DriveCheckerService.RootMode.WRITABLE, listener);
        }
    }

    private void rebuildShortcutsFavoritesPanel() {
        this.shortcutsFavoritesPanel.clear();
        if (this.favorites.size > 0) {
            Iterator it = this.favorites.iterator();
            while (it.hasNext()) {
                FileHandle f = (FileHandle) it.next();
                this.shortcutsFavoritesPanel.addActor(new ShortcutItem(f.file(), f.name(), this.style.iconFolder));
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void rebuildFileList() {
        this.filesListRebuildScheduled = false;
        final FileHandle[] selectedFiles = new FileHandle[this.selectedItems.size];
        for (int i = 0; i < selectedFiles.length; i++) {
            selectedFiles[i] = this.selectedItems.get(i).getFile();
        }
        deselectAll();
        setCurrentPathFieldText(this.currentDirectory.path());
        if (!this.showBusyBarTask.isScheduled()) {
            Timer.schedule(this.showBusyBarTask, 0.2f);
        }
        Future<?> future = this.listDirFuture;
        if (future != null) {
            future.cancel(true);
        }
        this.listDirFuture = this.listDirExecutor.submit(new Runnable() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.20
            @Override // java.lang.Runnable
            public void run() {
                if (FileChooser.this.currentDirectory.exists() && FileChooser.this.currentDirectory.isDirectory()) {
                    final Array<FileHandle> files = FileUtils.sortFiles(FileChooser.this.listFilteredCurrentDirectory(), ((FileSorting) FileChooser.this.sorting.get()).comparator, !FileChooser.this.sortingOrderAscending.get());
                    if (Thread.currentThread().isInterrupted()) {
                        return;
                    }
                    final IdentityMap<FileHandle, FileHandleMetadata> metadata = new IdentityMap<>(files.size);
                    Iterator it = files.iterator();
                    while (it.hasNext()) {
                        FileHandle file = (FileHandle) it.next();
                        metadata.put(file, FileHandleMetadata.of(file));
                    }
                    if (Thread.currentThread().isInterrupted()) {
                        return;
                    }
                    Gdx.app.postRunnable(new Runnable() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.20.2
                        @Override // java.lang.Runnable
                        public void run() {
                            FileChooser.this.buildFileList(files, metadata, selectedFiles);
                        }
                    });
                    return;
                }
                Gdx.app.postRunnable(new Runnable() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.20.1
                    @Override // java.lang.Runnable
                    public void run() {
                        FileChooser.this.setDirectory(FileChooser.this.getDefaultStartingDirectory(), HistoryPolicy.ADD);
                    }
                });
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void buildFileList(Array<FileHandle> files, IdentityMap<FileHandle, FileHandleMetadata> metadata, FileHandle[] selectedFiles) {
        this.currentFiles.clear();
        this.currentFilesMetadata.clear();
        this.showBusyBarTask.cancel();
        this.fileListBusyBar.setVisible(false);
        if (files.size == 0) {
            this.fileListAdapter.itemsChanged();
            return;
        }
        this.maxDateLabelWidth = 0.0f;
        this.currentFiles.addAll(files);
        this.currentFilesMetadata = metadata;
        this.fileListAdapter.itemsChanged();
        this.fileListView.getScrollPane().setScrollX(0.0f);
        this.fileListView.getScrollPane().setScrollY(0.0f);
        highlightFiles(selectedFiles);
    }

    public void setSelectedFiles(FileHandle... files) {
        deselectAll(false);
        for (FileHandle file : files) {
            FileItem item = this.fileListAdapter.getViews().get(file);
            if (item != null) {
                item.select(false);
            }
        }
        removeInvalidSelections();
        updateSelectedFileFieldText();
    }

    public void refresh() {
        rebuildShortcutsList();
        rebuildFileList();
    }

    public void addFavorite(FileHandle favourite) {
        this.favorites.add(favourite);
        this.preferencesIO.saveFavorites(this.favorites);
        rebuildShortcutsFavoritesPanel();
        rebuildShortcutsList(false);
        updateFavoriteFolderButton();
    }

    public boolean removeFavorite(FileHandle favorite) {
        boolean removed = this.favorites.removeValue(favorite, false);
        this.preferencesIO.saveFavorites(this.favorites);
        rebuildShortcutsFavoritesPanel();
        rebuildShortcutsList(false);
        updateFavoriteFolderButton();
        return removed;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void addRecentDirectory(FileHandle file) {
        if (this.recentDirectories.contains(file, false)) {
            return;
        }
        this.recentDirectories.insert(0, file);
        if (this.recentDirectories.size > 10) {
            this.recentDirectories.pop();
        }
        this.preferencesIO.saveRecentDirectories(this.recentDirectories);
    }

    public void clearRecentDirectories() {
        this.recentDirectories.clear();
        this.preferencesIO.saveRecentDirectories(this.recentDirectories);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void setVisible(boolean visible) {
        if (!isVisible() && visible) {
            deselectAll();
        }
        super.setVisible(visible);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void deselectAll() {
        deselectAll(true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void deselectAll(boolean updateTextField) {
        Iterator it = this.selectedItems.iterator();
        while (it.hasNext()) {
            FileItem item = (FileItem) it.next();
            item.deselect(false);
        }
        this.selectedItems.clear();
        if (updateTextField) {
            updateSelectedFileFieldText();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void selectAll() {
        Iterator it = this.fileListAdapter.getOrderedViews().iterator();
        while (it.hasNext()) {
            FileItem item = (FileItem) it.next();
            item.select(false);
        }
        removeInvalidSelections();
        updateSelectedFileFieldText();
    }

    public void highlightFiles(FileHandle... files) {
        FileItem item;
        for (FileHandle file : files) {
            FileItem item2 = this.fileListAdapter.getViews().get(file);
            if (item2 != null) {
                item2.select(false);
            }
        }
        if (files.length > 0 && (item = this.fileListAdapter.getViews().get(files[0])) != null) {
            if (item.getParent() instanceof Table) {
                ((Table) item.getParent()).layout();
            }
            item.localToParentCoordinates(tmpVector.setZero());
            this.fileListView.getScrollPane().scrollTo(tmpVector.x, tmpVector.y, item.getWidth(), item.getHeight(), false, true);
        }
        updateSelectedFileFieldText();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateSelectedFileFieldText() {
        if (getChooserStage() == null || getChooserStage().getKeyboardFocus() != this.selectedFileTextField) {
            if (this.selectedItems.size == 0) {
                this.selectedFileTextField.setText(BuildConfig.FLAVOR);
            } else if (this.selectedItems.size == 1) {
                this.selectedFileTextField.setText(this.selectedItems.get(0).getFile().name());
            } else {
                StringBuilder builder = new StringBuilder();
                Iterator it = this.selectedItems.iterator();
                while (it.hasNext()) {
                    FileItem item = (FileItem) it.next();
                    builder.append(Typography.quote);
                    builder.append(item.file.name());
                    builder.append("\" ");
                }
                this.selectedFileTextField.setText(builder.toString());
            }
            this.selectedFileTextField.setCursorAtTextEnd();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void removeInvalidSelections() {
        if (this.selectionMode == SelectionMode.FILES) {
            Iterator<FileItem> it = this.selectedItems.iterator();
            while (it.hasNext()) {
                FileItem item = it.next();
                if (item.file.isDirectory()) {
                    item.deselect(false);
                    it.remove();
                }
            }
        }
        if (this.selectionMode == SelectionMode.DIRECTORIES) {
            Iterator<FileItem> it2 = this.selectedItems.iterator();
            while (it2.hasNext()) {
                FileItem item2 = it2.next();
                if (!item2.file.isDirectory()) {
                    item2.deselect(false);
                    it2.remove();
                }
            }
        }
    }

    public Mode getMode() {
        return this.mode;
    }

    public void setMode(Mode mode) {
        this.mode = mode;
        this.confirmButton.setText((mode == Mode.OPEN ? FileChooserText.OPEN : FileChooserText.SAVE).get());
        refresh();
    }

    public ViewMode getViewMode() {
        return this.viewMode;
    }

    public void setViewMode(ViewMode viewMode) {
        if (this.viewMode == viewMode) {
            return;
        }
        this.viewMode = viewMode;
        this.iconProvider.viewModeChanged(viewMode);
        rebuildFileList();
    }

    public void setDirectory(String directory) {
        setDirectory(Gdx.files.absolute(directory), HistoryPolicy.CLEAR);
    }

    public void setDirectory(File directory) {
        setDirectory(Gdx.files.absolute(directory.getAbsolutePath()), HistoryPolicy.CLEAR);
    }

    public void setDirectory(FileHandle directory) {
        setDirectory(directory, HistoryPolicy.CLEAR);
    }

    @Override // com.kotcrab.vis.ui.widget.file.internal.FileHistoryManager.FileHistoryCallback
    public void setDirectory(FileHandle directory, HistoryPolicy historyPolicy) {
        if (directory.equals(this.currentDirectory)) {
            return;
        }
        if (historyPolicy == HistoryPolicy.ADD) {
            this.historyManager.historyAdd();
        }
        this.currentDirectory = directory;
        this.iconProvider.directoryChanged(directory);
        rebuildFileList();
        if (historyPolicy == HistoryPolicy.CLEAR) {
            this.historyManager.historyClear();
        }
        updateFavoriteFolderButton();
    }

    @Override // com.kotcrab.vis.ui.widget.file.internal.FileHistoryManager.FileHistoryCallback
    public FileHandle getCurrentDirectory() {
        return this.currentDirectory;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public FileHandle getDefaultStartingDirectory() {
        return Gdx.files.absolute(System.getProperty("user.home"));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public FileHandle[] listFilteredCurrentDirectory() {
        FileHandle[] files = this.currentDirectory.list(this.fileFilter);
        if (this.fileTypeFilter == null || this.activeFileTypeRule == null) {
            return files;
        }
        FileHandle[] filtered = new FileHandle[files.length];
        int count = 0;
        for (FileHandle file : files) {
            if (file.isDirectory() || this.activeFileTypeRule.accept(file)) {
                filtered[count] = file;
                count++;
            }
        }
        if (count == 0) {
            return new FileHandle[0];
        }
        FileHandle[] newFiltered = new FileHandle[count];
        System.arraycopy(filtered, 0, newFiltered, 0, count);
        return newFiltered;
    }

    public FileFilter getFileFilter() {
        return this.fileFilter;
    }

    public void setFileFilter(FileFilter fileFilter) {
        this.fileFilter = fileFilter;
        rebuildFileList();
    }

    public void setFileTypeFilter(FileTypeFilter fileTypeFilter) {
        if (fileTypeFilter == null) {
            this.fileTypeFilter = null;
            this.activeFileTypeRule = null;
        } else if (fileTypeFilter.getRules().size == 0) {
            throw new IllegalArgumentException("FileTypeFilter doesn't have any rules added");
        } else {
            this.fileTypeFilter = new FileTypeFilter(fileTypeFilter);
            this.activeFileTypeRule = this.fileTypeFilter.getRules().first();
        }
        updateFileTypeSelectBox();
        rebuildFileList();
    }

    public FileTypeFilter.Rule getActiveFileTypeFilterRule() {
        return this.activeFileTypeRule;
    }

    public SelectionMode getSelectionMode() {
        return this.selectionMode;
    }

    public void setSelectionMode(SelectionMode selectionMode) {
        if (selectionMode == null) {
            selectionMode = SelectionMode.FILES;
        }
        this.selectionMode = selectionMode;
        int i = AnonymousClass24.$SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$SelectionMode[selectionMode.ordinal()];
        if (i == 1) {
            getTitleLabel().setText(FileChooserText.TITLE_CHOOSE_FILES.get());
        } else if (i == 2) {
            getTitleLabel().setText(FileChooserText.TITLE_CHOOSE_DIRECTORIES.get());
        } else if (i == 3) {
            getTitleLabel().setText(FileChooserText.TITLE_CHOOSE_FILES_AND_DIRECTORIES.get());
        }
        updateFileTypeSelectBox();
        rebuildFileList();
    }

    public FileSorting getSorting() {
        return this.sorting.get();
    }

    public void setSorting(FileSorting sorting, boolean sortingOrderAscending) {
        this.sorting.set(sorting);
        this.sortingOrderAscending.set(sortingOrderAscending);
        rebuildFileList();
    }

    public void setSorting(FileSorting sorting) {
        this.sorting.set(sorting);
        rebuildFileList();
    }

    public boolean isSortingOrderAscending() {
        return this.sortingOrderAscending.get();
    }

    public void setSortingOrderAscending(boolean sortingOrderAscending) {
        this.sortingOrderAscending.set(sortingOrderAscending);
        rebuildFileList();
    }

    public void setFavoriteFolderButtonVisible(boolean favoriteFolderButtonVisible) {
        this.favoriteFolderButton.setVisible(favoriteFolderButtonVisible);
    }

    public boolean isFavoriteFolderButtonVisible() {
        return this.favoriteFolderButton.isVisible();
    }

    public void setViewModeButtonVisible(boolean viewModeButtonVisible) {
        this.viewModeButton.setVisible(viewModeButtonVisible);
    }

    public boolean isViewModeButtonVisible() {
        return this.viewModeButton.isVisible();
    }

    public boolean isMultiSelectionEnabled() {
        return this.multiSelectionEnabled;
    }

    public void setMultiSelectionEnabled(boolean multiSelectionEnabled) {
        this.multiSelectionEnabled = multiSelectionEnabled;
    }

    public void setListener(FileChooserListener newListener) {
        this.listener = newListener;
        if (this.listener == null) {
            this.listener = new FileChooserAdapter();
        }
    }

    public boolean isShowSelectionCheckboxes() {
        return this.showSelectionCheckboxes;
    }

    public void setShowSelectionCheckboxes(boolean showSelectionCheckboxes) {
        this.showSelectionCheckboxes = showSelectionCheckboxes;
        rebuildFileList();
    }

    public int getMultiSelectKey() {
        return this.multiSelectKey;
    }

    public void setMultiSelectKey(int multiSelectKey) {
        this.multiSelectKey = multiSelectKey;
    }

    public int getGroupMultiSelectKey() {
        return this.groupMultiSelectKey;
    }

    public void setGroupMultiSelectKey(int groupMultiSelectKey) {
        this.groupMultiSelectKey = groupMultiSelectKey;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean isMultiSelectKeyPressed() {
        if (this.multiSelectKey == -1) {
            return UIUtils.ctrl();
        }
        return Gdx.input.isKeyPressed(this.multiSelectKey);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean isGroupMultiSelectKeyPressed() {
        if (this.groupMultiSelectKey == -1) {
            return UIUtils.shift();
        }
        return Gdx.input.isKeyPressed(this.groupMultiSelectKey);
    }

    public FileChooserStyle getChooserStyle() {
        return this.style;
    }

    public Sizes getSizes() {
        return this.sizes;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public Stage getChooserStage() {
        return getStage();
    }

    public void setWatchingFilesEnabled(boolean watchingFilesEnabled) {
        if (getChooserStage() != null) {
            throw new IllegalStateException("Pooling setting cannot be changed when file chooser is added to Stage!");
        }
        this.watchingFilesEnabled = watchingFilesEnabled;
    }

    public void setPrefsName(String prefsName) {
        this.preferencesIO = new PreferencesIO(prefsName);
        reloadPreferences(true);
    }

    private void reloadPreferences(boolean rebuildUI) {
        this.favorites = this.preferencesIO.loadFavorites();
        this.recentDirectories = this.preferencesIO.loadRecentDirectories();
        if (rebuildUI) {
            rebuildShortcutsFavoritesPanel();
        }
    }

    @Override // com.kotcrab.vis.ui.widget.VisWindow, com.badlogic.gdx.scenes.scene2d.ui.Window, com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        super.draw(batch, parentAlpha);
        if (this.shortcutsListRebuildScheduled) {
            rebuildShortcutsList();
        }
        if (this.filesListRebuildScheduled) {
            rebuildFileList();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.kotcrab.vis.ui.widget.VisWindow, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void setStage(Stage stage) {
        super.setStage(stage);
        if (stage != null) {
            refresh();
            rebuildShortcutsFavoritesPanel();
            deselectAll();
            if (focusFileScrollPaneOnShow) {
                stage.setScrollFocus(this.fileListView.getScrollPane());
            }
        }
        if (this.watchingFilesEnabled) {
            if (stage != null) {
                startFileWatcher();
            } else {
                stopFileWatcher();
            }
        }
    }

    private void startFileWatcher() {
        if (this.fileWatcherThread != null) {
            return;
        }
        this.fileWatcherThread = new Thread(new Runnable() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.21
            FileHandle lastCurrentDirectory;
            FileHandle[] lastCurrentFiles;
            File[] lastRoots;

            @Override // java.lang.Runnable
            public void run() {
                this.lastRoots = File.listRoots();
                this.lastCurrentDirectory = FileChooser.this.currentDirectory;
                this.lastCurrentFiles = FileChooser.this.currentDirectory.list();
                while (FileChooser.this.fileWatcherThread != null) {
                    File[] roots = File.listRoots();
                    int length = roots.length;
                    File[] fileArr = this.lastRoots;
                    if (length != fileArr.length || !Arrays.equals(fileArr, roots)) {
                        FileChooser.this.shortcutsListRebuildScheduled = true;
                    }
                    this.lastRoots = roots;
                    if (this.lastCurrentDirectory.equals(FileChooser.this.currentDirectory)) {
                        FileHandle[] currentFiles = FileChooser.this.currentDirectory.list();
                        FileHandle[] fileHandleArr = this.lastCurrentFiles;
                        if (fileHandleArr.length != currentFiles.length || !Arrays.equals(fileHandleArr, currentFiles)) {
                            FileChooser.this.filesListRebuildScheduled = true;
                        }
                        this.lastCurrentFiles = currentFiles;
                    } else {
                        this.lastCurrentFiles = FileChooser.this.currentDirectory.list();
                    }
                    this.lastCurrentDirectory = FileChooser.this.currentDirectory;
                    try {
                        Thread.sleep(FileChooser.FILE_WATCHER_CHECK_DELAY_MILLIS);
                    } catch (InterruptedException e) {
                    }
                }
            }
        }, "FileWatcherThread");
        this.fileWatcherThread.setDaemon(true);
        this.fileWatcherThread.start();
    }

    private void stopFileWatcher() {
        Thread thread = this.fileWatcherThread;
        if (thread == null) {
            return;
        }
        thread.interrupt();
        this.fileWatcherThread = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showNewDirectoryDialog() {
        Dialogs.showInputDialog(getChooserStage(), FileChooserText.NEW_DIRECTORY_DIALOG_TITLE.get(), FileChooserText.NEW_DIRECTORY_DIALOG_TEXT.get(), true, (InputDialogListener) new InputDialogAdapter() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.22
            @Override // com.kotcrab.vis.ui.util.dialog.InputDialogAdapter, com.kotcrab.vis.ui.util.dialog.InputDialogListener
            public void finished(String input) {
                FileHandle[] list;
                if (!FileUtils.isValidFileName(input)) {
                    Dialogs.showErrorDialog(FileChooser.this.getChooserStage(), FileChooserText.NEW_DIRECTORY_DIALOG_ILLEGAL_CHARACTERS.get());
                    return;
                }
                for (FileHandle file : FileChooser.this.currentDirectory.list()) {
                    if (file.name().equals(input)) {
                        Dialogs.showErrorDialog(FileChooser.this.getChooserStage(), FileChooserText.NEW_DIRECTORY_DIALOG_ALREADY_EXISTS.get());
                        return;
                    }
                }
                FileHandle newDir = FileChooser.this.currentDirectory.child(input);
                newDir.mkdirs();
                FileChooser.this.refresh();
                FileChooser.this.highlightFiles(newDir);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showFileDeleteDialog(final FileHandle fileToDelete) {
        Dialogs.showOptionDialog(getChooserStage(), FileChooserText.POPUP_TITLE.get(), (this.fileDeleter.hasTrash() ? FileChooserText.CONTEXT_MENU_MOVE_TO_TRASH_WARNING : FileChooserText.CONTEXT_MENU_DELETE_WARNING).get(), Dialogs.OptionDialogType.YES_NO, new OptionDialogAdapter() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.23
            @Override // com.kotcrab.vis.ui.util.dialog.OptionDialogAdapter, com.kotcrab.vis.ui.util.dialog.OptionDialogListener
            public void yes() {
                try {
                    boolean success = FileChooser.this.fileDeleter.delete(fileToDelete);
                    if (!success) {
                        Dialogs.showErrorDialog(FileChooser.this.getChooserStage(), FileChooserText.POPUP_DELETE_FILE_FAILED.get());
                    }
                } catch (IOException e) {
                    Dialogs.showErrorDialog(FileChooser.this.getChooserStage(), FileChooserText.POPUP_DELETE_FILE_FAILED.get(), e);
                    e.printStackTrace();
                }
                FileChooser.this.refresh();
            }
        });
    }

    public void setFileDeleter(FileDeleter fileDeleter) {
        if (fileDeleter == null) {
            throw new IllegalStateException("fileDeleter can't be null");
        }
        this.fileDeleter = fileDeleter;
        this.fileMenu.fileDeleterChanged(fileDeleter.hasTrash());
    }

    public void setIconProvider(FileIconProvider iconProvider) {
        this.iconProvider = iconProvider;
        rebuildViewModePopupMenu();
    }

    public FileIconProvider getIconProvider() {
        return this.iconProvider;
    }

    public static boolean isSaveLastDirectory() {
        return saveLastDirectory;
    }

    public static void setSaveLastDirectory(boolean saveLastDirectory2) {
        saveLastDirectory = saveLastDirectory2;
    }

    /* loaded from: classes.dex */
    public enum FileSorting {
        NAME(FileUtils.FILE_NAME_COMPARATOR),
        MODIFIED_DATE(FileUtils.FILE_MODIFIED_DATE_COMPARATOR),
        SIZE(FileUtils.FILE_SIZE_COMPARATOR);
        
        private final Comparator<FileHandle> comparator;

        FileSorting(Comparator comparator) {
            this.comparator = comparator;
        }
    }

    /* loaded from: classes.dex */
    public enum ViewMode {
        DETAILS(false, FileChooserText.VIEW_MODE_DETAILS),
        BIG_ICONS(true, FileChooserText.VIEW_MODE_BIG_ICONS),
        MEDIUM_ICONS(true, FileChooserText.VIEW_MODE_MEDIUM_ICONS),
        SMALL_ICONS(true, FileChooserText.VIEW_MODE_SMALL_ICONS),
        LIST(false, FileChooserText.VIEW_MODE_LIST);
        
        private final FileChooserText bundleText;
        private final boolean thumbnailMode;

        ViewMode(boolean thumbnailMode, FileChooserText bundleText) {
            this.thumbnailMode = thumbnailMode;
            this.bundleText = bundleText;
        }

        public String getBundleText() {
            return this.bundleText.get();
        }

        public void setupGridGroup(Sizes sizes, GridGroup group) {
            if (isGridMode()) {
                float gridSize = getGridSize(sizes);
                if (gridSize < 0.0f) {
                    throw new IllegalStateException("FileChooser's ViewMode " + toString() + " has invalid size defined in Sizes. Expected value greater than 0, got: " + gridSize + ". Check your skin Sizes definition.");
                } else if (this == LIST) {
                    group.setItemSize(gridSize, sizes.scaleFactor * 22.0f);
                } else {
                    group.setItemSize(gridSize);
                }
            }
        }

        public boolean isGridMode() {
            return isThumbnailMode() || this == LIST;
        }

        public boolean isThumbnailMode() {
            return this.thumbnailMode;
        }

        public float getGridSize(Sizes sizes) {
            int i = AnonymousClass24.$SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$ViewMode[ordinal()];
            if (i != 1) {
                if (i != 2) {
                    if (i != 3) {
                        if (i != 4) {
                            if (i != 5) {
                                return -1.0f;
                            }
                            return sizes.fileChooserViewModeListWidthSize;
                        }
                        return sizes.fileChooserViewModeSmallIconsSize;
                    }
                    return sizes.fileChooserViewModeMediumIconsSize;
                }
                return sizes.fileChooserViewModeBigIconsSize;
            }
            return -1.0f;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: com.kotcrab.vis.ui.widget.file.FileChooser$24  reason: invalid class name */
    /* loaded from: classes.dex */
    public static /* synthetic */ class AnonymousClass24 {
        static final /* synthetic */ int[] $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$SelectionMode;
        static final /* synthetic */ int[] $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$ViewMode = new int[ViewMode.values().length];

        static {
            try {
                $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$ViewMode[ViewMode.DETAILS.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$ViewMode[ViewMode.BIG_ICONS.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$ViewMode[ViewMode.MEDIUM_ICONS.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$ViewMode[ViewMode.SMALL_ICONS.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$ViewMode[ViewMode.LIST.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
            $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$SelectionMode = new int[SelectionMode.values().length];
            try {
                $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$SelectionMode[SelectionMode.FILES.ordinal()] = 1;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$SelectionMode[SelectionMode.DIRECTORIES.ordinal()] = 2;
            } catch (NoSuchFieldError e7) {
            }
            try {
                $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$SelectionMode[SelectionMode.FILES_AND_DIRECTORIES.ordinal()] = 3;
            } catch (NoSuchFieldError e8) {
            }
        }
    }

    /* loaded from: classes.dex */
    public static class DefaultFileIconProvider implements FileIconProvider {
        protected FileChooser chooser;
        protected FileChooserStyle style;

        public DefaultFileIconProvider(FileChooser chooser) {
            this.chooser = chooser;
            this.style = chooser.style;
        }

        @Override // com.kotcrab.vis.ui.widget.file.FileChooser.FileIconProvider
        public Drawable provideIcon(FileItem item) {
            if (item.isDirectory()) {
                return getDirIcon(item);
            }
            String ext = item.getFile().extension().toLowerCase();
            if (ext.equals("jpg") || ext.equals("jpeg") || ext.equals("png") || ext.equals("bmp")) {
                return getImageIcon(item);
            }
            if (ext.equals("wav") || ext.equals("ogg") || ext.equals("mp3")) {
                return getAudioIcon(item);
            }
            return ext.equals("pdf") ? getPdfIcon(item) : ext.equals("txt") ? getTextIcon(item) : getDefaultIcon(item);
        }

        protected Drawable getDirIcon(FileItem item) {
            return this.style.iconFolder;
        }

        protected Drawable getImageIcon(FileItem item) {
            return this.style.iconFileImage;
        }

        protected Drawable getAudioIcon(FileItem item) {
            return this.style.iconFileAudio;
        }

        protected Drawable getPdfIcon(FileItem item) {
            return this.style.iconFilePdf;
        }

        protected Drawable getTextIcon(FileItem item) {
            return this.style.iconFileText;
        }

        protected Drawable getDefaultIcon(FileItem item) {
            return null;
        }

        @Override // com.kotcrab.vis.ui.widget.file.FileChooser.FileIconProvider
        public boolean isThumbnailModesSupported() {
            return false;
        }

        @Override // com.kotcrab.vis.ui.widget.file.FileChooser.FileIconProvider
        public void directoryChanged(FileHandle newDirectory) {
        }

        @Override // com.kotcrab.vis.ui.widget.file.FileChooser.FileIconProvider
        public void viewModeChanged(ViewMode newViewMode) {
        }
    }

    /* loaded from: classes.dex */
    public static class DefaultFileFilter implements FileFilter {
        private FileChooser chooser;
        private boolean ignoreChooserSelectionMode = false;

        public DefaultFileFilter(FileChooser chooser) {
            this.chooser = chooser;
        }

        @Override // java.io.FileFilter
        public boolean accept(File f) {
            if (f.isHidden()) {
                return false;
            }
            if (this.chooser.getMode() != Mode.OPEN ? f.canWrite() : f.canRead()) {
                return this.ignoreChooserSelectionMode || f.isDirectory() || this.chooser.getSelectionMode() != SelectionMode.DIRECTORIES;
            }
            return false;
        }

        public boolean isIgnoreChooserSelectionMode() {
            return this.ignoreChooserSelectionMode;
        }

        public void setIgnoreChooserSelectionMode(boolean ignoreChooserSelectionMode) {
            this.ignoreChooserSelectionMode = ignoreChooserSelectionMode;
        }
    }

    /* loaded from: classes.dex */
    public static final class DefaultFileDeleter implements FileDeleter {
        @Override // com.kotcrab.vis.ui.widget.file.FileChooser.FileDeleter
        public boolean hasTrash() {
            return false;
        }

        @Override // com.kotcrab.vis.ui.widget.file.FileChooser.FileDeleter
        public boolean delete(FileHandle file) {
            return file.deleteDirectory();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class ShowBusyBarTask extends Timer.Task {
        private ShowBusyBarTask() {
        }

        @Override // com.badlogic.gdx.utils.Timer.Task, java.lang.Runnable
        public void run() {
            FileChooser.this.fileListBusyBar.resetSegment();
            FileChooser.this.fileListBusyBar.setVisible(true);
            FileChooser.this.currentFiles.clear();
            FileChooser.this.currentFilesMetadata.clear();
            FileChooser.this.fileListAdapter.itemsChanged();
        }

        @Override // com.badlogic.gdx.utils.Timer.Task
        public synchronized void cancel() {
            super.cancel();
            FileChooser.this.fileListBusyBar.setVisible(false);
        }
    }

    /* loaded from: classes.dex */
    public class FileItem extends Table implements Focusable {
        private FileHandle file;
        private VisImage iconImage;
        private FileHandleMetadata metadata;
        private VisCheckBox selectCheckBox;

        public FileItem(FileHandle file, ViewMode viewMode) {
            this.file = file;
            this.metadata = (FileHandleMetadata) FileChooser.this.currentFilesMetadata.get(file);
            if (this.metadata == null) {
                this.metadata = FileHandleMetadata.of(file);
            }
            setTouchable(Touchable.enabled);
            VisLabel name = new VisLabel(this.metadata.name(), viewMode == ViewMode.SMALL_ICONS ? "small" : "default");
            boolean shouldShowItemShowCheckBox = true;
            name.setEllipsis(true);
            Drawable icon = FileChooser.this.iconProvider.provideIcon(this);
            String str = BuildConfig.FLAVOR;
            this.selectCheckBox = new VisCheckBox(BuildConfig.FLAVOR);
            this.selectCheckBox.setFocusBorderEnabled(false);
            this.selectCheckBox.setProgrammaticChangeEvents(false);
            if (!FileChooser.this.showSelectionCheckboxes || (FileChooser.this.selectionMode != SelectionMode.FILES_AND_DIRECTORIES && ((FileChooser.this.selectionMode != SelectionMode.FILES || this.metadata.isDirectory()) && (FileChooser.this.selectionMode != SelectionMode.DIRECTORIES || !this.metadata.isDirectory())))) {
                shouldShowItemShowCheckBox = false;
            }
            left();
            if (viewMode.isThumbnailMode()) {
                if (shouldShowItemShowCheckBox) {
                    VisImage visImage = new VisImage(icon, Scaling.none);
                    this.iconImage = visImage;
                    IconStack stack = new IconStack(visImage, this.selectCheckBox);
                    add((FileItem) stack).padTop(3.0f).grow().row();
                    add((FileItem) name).minWidth(1.0f);
                } else {
                    VisImage visImage2 = new VisImage(icon, Scaling.none);
                    this.iconImage = visImage2;
                    add((FileItem) visImage2).padTop(3.0f).grow().row();
                    add((FileItem) name).minWidth(1.0f);
                }
            } else {
                if (shouldShowItemShowCheckBox) {
                    add((FileItem) this.selectCheckBox).padLeft(3.0f);
                }
                VisImage visImage3 = new VisImage(icon);
                this.iconImage = visImage3;
                add((FileItem) visImage3).padTop(3.0f).minWidth(FileChooser.this.sizes.scaleFactor * 22.0f);
                add((FileItem) name).minWidth(1.0f).growX().padRight(10.0f);
                VisLabel size = new VisLabel(isDirectory() ? str : this.metadata.readableFileSize(), "small");
                VisLabel dateLabel = new VisLabel(FileChooser.this.dateFormat.format(Long.valueOf(this.metadata.lastModified())), "small");
                size.setAlignment(16);
                if (viewMode == ViewMode.DETAILS) {
                    FileChooser.this.maxDateLabelWidth = Math.max(dateLabel.getWidth(), FileChooser.this.maxDateLabelWidth);
                    add((FileItem) size).right().padRight(isDirectory() ? 0.0f : 10.0f);
                    add((FileItem) dateLabel).padRight(6.0f).width(new Value() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.FileItem.1
                        @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
                        public float get(Actor context) {
                            return FileChooser.this.maxDateLabelWidth;
                        }
                    });
                }
            }
            addListeners();
        }

        public void setIcon(Drawable icon, Scaling scaling) {
            this.iconImage.setDrawable(icon);
            this.iconImage.setScaling(scaling);
            this.iconImage.invalidateHierarchy();
        }

        private void addListeners() {
            addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.FileItem.2
                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                    FocusManager.switchFocus(FileChooser.this.getChooserStage(), FileItem.this);
                    FileChooser.this.getChooserStage().setKeyboardFocus(FileItem.this);
                    return true;
                }

                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                    if (event.getButton() == 1) {
                        FileChooser.this.fileMenu.build(FileChooser.this.favorites, FileItem.this.file);
                        FileChooser.this.fileMenu.showMenu(FileChooser.this.getChooserStage(), event.getStageX(), event.getStageY());
                    }
                }

                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public boolean keyDown(InputEvent event, int keycode) {
                    if (keycode == 112) {
                        FileChooser.this.showFileDeleteDialog(FileItem.this.file);
                        return true;
                    }
                    return false;
                }
            });
            addListener(new ClickListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.FileItem.3
                @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
                public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                    if (FileItem.this.handleSelectClick(false)) {
                        return super.touchDown(event, x, y, pointer, button);
                    }
                    return false;
                }

                @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener
                public void clicked(InputEvent event, float x, float y) {
                    super.clicked(event, x, y);
                    if (getTapCount() == 2 && FileChooser.this.selectedItems.contains(FileItem.this, true)) {
                        if (!FileItem.this.file.isDirectory()) {
                            FileChooser.this.selectionFinished();
                        } else {
                            FileChooser.this.setDirectory(FileItem.this.file, HistoryPolicy.ADD);
                        }
                    }
                }
            });
            this.selectCheckBox.addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.FileItem.4
                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                    event.stop();
                    return true;
                }
            });
            this.selectCheckBox.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.FileItem.5
                @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                    event.stop();
                    FileItem.this.handleSelectClick(true);
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: private */
        public boolean handleSelectClick(boolean checkboxClicked) {
            if (FileChooser.this.selectedShortcut != null) {
                FileChooser.this.selectedShortcut.deselect();
            }
            if (checkboxClicked) {
                if (!FileChooser.this.multiSelectionEnabled && !FileChooser.this.selectedItems.contains(this, true)) {
                    FileChooser.this.deselectAll();
                }
            } else if (!FileChooser.this.multiSelectionEnabled || (!FileChooser.this.isMultiSelectKeyPressed() && !FileChooser.this.isGroupMultiSelectKeyPressed())) {
                FileChooser.this.deselectAll();
            }
            boolean itemSelected = select();
            if (FileChooser.this.selectedItems.size > 1 && FileChooser.this.multiSelectionEnabled && FileChooser.this.isGroupMultiSelectKeyPressed()) {
                selectGroup();
            }
            if (FileChooser.this.selectedItems.size > 1) {
                FileChooser.this.removeInvalidSelections();
            }
            FileChooser.this.updateSelectedFileFieldText();
            return itemSelected;
        }

        private void selectGroup() {
            int start;
            int end;
            Array<FileItem> actors = FileChooser.this.fileListAdapter.getOrderedViews();
            int thisSelectionIndex = getItemId(actors, this);
            int lastSelectionIndex = getItemId(actors, (FileItem) FileChooser.this.selectedItems.get(FileChooser.this.selectedItems.size - 2));
            if (thisSelectionIndex > lastSelectionIndex) {
                start = lastSelectionIndex;
                end = thisSelectionIndex;
            } else {
                start = thisSelectionIndex;
                end = lastSelectionIndex;
            }
            for (int i = start; i < end; i++) {
                FileItem item = actors.get(i);
                item.select(false);
            }
        }

        private int getItemId(Array<FileItem> actors, FileItem item) {
            for (int i = 0; i < actors.size; i++) {
                if (actors.get(i) == item) {
                    return i;
                }
            }
            throw new IllegalStateException("Item not found in cells");
        }

        private boolean select() {
            return select(true);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public boolean select(boolean deselectIfAlreadySelected) {
            if (!deselectIfAlreadySelected || !FileChooser.this.selectedItems.contains(this, true)) {
                setBackground(FileChooser.this.style.highlight);
                this.selectCheckBox.setChecked(true);
                if (!FileChooser.this.selectedItems.contains(this, true)) {
                    FileChooser.this.selectedItems.add(this);
                }
                return true;
            }
            deselect();
            return false;
        }

        private void deselect() {
            deselect(true);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void deselect(boolean removeFromList) {
            setBackground((Drawable) null);
            this.selectCheckBox.setChecked(false);
            if (removeFromList) {
                FileChooser.this.selectedItems.removeValue(this, true);
            }
        }

        @Override // com.kotcrab.vis.ui.Focusable
        public void focusLost() {
        }

        @Override // com.kotcrab.vis.ui.Focusable
        public void focusGained() {
        }

        public FileHandle getFile() {
            return this.file;
        }

        public boolean isDirectory() {
            return this.metadata.isDirectory();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class ShortcutItem extends Table implements FileChooserWinService.RootNameListener, Focusable {
        public File file;
        private VisLabel name;

        public ShortcutItem(File file, String customName, Drawable icon) {
            this.file = file;
            this.name = new VisLabel(customName);
            this.name.setEllipsis(true);
            add((ShortcutItem) new Image(icon)).padTop(3.0f);
            Cell<VisLabel> labelCell = add((ShortcutItem) this.name).padRight(6.0f);
            labelCell.width(new Value() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.ShortcutItem.1
                @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
                public float get(Actor context) {
                    return FileChooser.this.mainSplitPane.getFirstWidgetBounds().width - 30.0f;
                }
            });
            addListener();
        }

        private void addListener() {
            addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.ShortcutItem.2
                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                    FocusManager.switchFocus(FileChooser.this.getChooserStage(), ShortcutItem.this);
                    FileChooser.this.getChooserStage().setKeyboardFocus(ShortcutItem.this);
                    return true;
                }

                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                    if (event.getButton() == 1) {
                        FileChooser.this.fileMenu.buildForFavorite(FileChooser.this.favorites, ShortcutItem.this.file);
                        FileChooser.this.fileMenu.showMenu(FileChooser.this.getChooserStage(), event.getStageX(), event.getStageY());
                    }
                }

                @Override // com.badlogic.gdx.scenes.scene2d.InputListener
                public boolean keyDown(InputEvent event, int keycode) {
                    if (keycode != 112) {
                        return false;
                    }
                    FileHandle gdxFile = Gdx.files.absolute(ShortcutItem.this.file.getAbsolutePath());
                    if (FileChooser.this.favorites.contains(gdxFile, false)) {
                        FileChooser.this.removeFavorite(gdxFile);
                        return true;
                    }
                    return true;
                }
            });
            addListener(new ClickListener() { // from class: com.kotcrab.vis.ui.widget.file.FileChooser.ShortcutItem.3
                @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
                public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                    FileChooser.this.deselectAll();
                    FileChooser.this.updateSelectedFileFieldText();
                    ShortcutItem.this.select();
                    return super.touchDown(event, x, y, pointer, button);
                }

                @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener
                public void clicked(InputEvent event, float x, float y) {
                    super.clicked(event, x, y);
                    if (getTapCount() == 1) {
                        File file = ShortcutItem.this.file;
                        if (!file.exists()) {
                            FileChooser.this.showDialog(FileChooserText.POPUP_DIRECTORY_DOES_NOT_EXIST.get());
                            FileChooser.this.refresh();
                        } else if (file.isDirectory()) {
                            FileChooser.this.setDirectory(Gdx.files.absolute(file.getAbsolutePath()), HistoryPolicy.ADD);
                            FileChooser.this.getChooserStage().setScrollFocus(FileChooser.this.fileListView.getScrollPane());
                        }
                    }
                }
            });
        }

        public void setLabelText(String text) {
            this.name.setText(text);
        }

        public String getLabelText() {
            return this.name.getText().toString();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void select() {
            if (FileChooser.this.selectedShortcut != null) {
                FileChooser.this.selectedShortcut.deselect();
            }
            FileChooser.this.selectedShortcut = this;
            setBackground(FileChooser.this.style.highlight);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void deselect() {
            setBackground((Drawable) null);
        }

        @Override // com.kotcrab.vis.ui.widget.file.internal.FileChooserWinService.RootNameListener
        public void setRootName(String newName) {
            setLabelText(newName);
        }

        @Override // com.kotcrab.vis.ui.Focusable
        public void focusGained() {
        }

        @Override // com.kotcrab.vis.ui.Focusable
        public void focusLost() {
        }
    }

    /* loaded from: classes.dex */
    private static class ShortcutsComparator implements Comparator<Actor> {
        private ShortcutsComparator() {
        }

        @Override // java.util.Comparator
        public int compare(Actor o1, Actor o2) {
            ShortcutItem s1 = (ShortcutItem) o1;
            ShortcutItem s2 = (ShortcutItem) o2;
            return s1.getLabelText().compareTo(s2.getLabelText());
        }
    }
}