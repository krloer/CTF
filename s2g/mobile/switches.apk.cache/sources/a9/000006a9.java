package com.kotcrab.vis.ui.widget.toast;

import com.kotcrab.vis.ui.widget.LinkLabel;
import com.kotcrab.vis.ui.widget.VisLabel;
import com.kotcrab.vis.ui.widget.VisTable;

/* loaded from: classes.dex */
public class MessageToast extends ToastTable {
    private VisTable linkLabelTable = new VisTable();

    public MessageToast(String message) {
        add((MessageToast) new VisLabel(message)).left().row();
        add((MessageToast) this.linkLabelTable).right();
    }

    public void addLinkLabel(String text, LinkLabel.LinkLabelListener labelListener) {
        LinkLabel label = new LinkLabel(text);
        label.setListener(labelListener);
        this.linkLabelTable.add((VisTable) label).spaceRight(12.0f);
    }
}