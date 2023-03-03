package com.kotcrab.vis.ui.widget.file;

import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.kotcrab.vis.ui.widget.PopupMenu;

/* loaded from: classes.dex */
public class FileChooserStyle {
    public Drawable contextMenuSelectedItem;
    public Drawable expandDropdown;
    public Drawable highlight;
    public Drawable iconArrowLeft;
    public Drawable iconArrowRight;
    public Drawable iconDrive;
    public Drawable iconFileAudio;
    public Drawable iconFileImage;
    public Drawable iconFilePdf;
    public Drawable iconFileText;
    public Drawable iconFolder;
    public Drawable iconFolderNew;
    public Drawable iconFolderParent;
    public Drawable iconFolderStar;
    public Drawable iconListSettings;
    public Drawable iconRefresh;
    public Drawable iconStar;
    public Drawable iconStarOutline;
    public Drawable iconTrash;
    public PopupMenu.PopupMenuStyle popupMenuStyle;

    public FileChooserStyle() {
    }

    public FileChooserStyle(FileChooserStyle style) {
        this.popupMenuStyle = style.popupMenuStyle;
        this.highlight = style.highlight;
        this.iconArrowLeft = style.iconArrowLeft;
        this.iconArrowRight = style.iconArrowRight;
        this.iconFolder = style.iconFolder;
        this.iconFolderParent = style.iconFolderParent;
        this.iconFolderStar = style.iconFolderStar;
        this.iconFolderNew = style.iconFolderNew;
        this.iconDrive = style.iconDrive;
        this.iconTrash = style.iconTrash;
        this.iconStar = style.iconStar;
        this.iconStarOutline = style.iconStarOutline;
        this.iconRefresh = style.iconRefresh;
        this.iconListSettings = style.iconListSettings;
        this.iconFileText = style.iconFileText;
        this.iconFileImage = style.iconFileImage;
        this.iconFilePdf = style.iconFilePdf;
        this.iconFileAudio = style.iconFileAudio;
        this.contextMenuSelectedItem = style.contextMenuSelectedItem;
        this.expandDropdown = style.expandDropdown;
    }
}