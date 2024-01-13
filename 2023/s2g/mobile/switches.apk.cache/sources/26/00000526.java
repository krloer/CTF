package com.kotcrab.vis.ui.util;

import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.kotcrab.vis.ui.Sizes;
import com.kotcrab.vis.ui.VisUI;

/* loaded from: classes.dex */
public class TableUtils {
    public static void setSpacingDefaults(Table table) {
        Sizes sizes = VisUI.getSizes();
        if (sizes.spacingTop != 0.0f) {
            table.defaults().spaceTop(sizes.spacingTop);
        }
        if (sizes.spacingBottom != 0.0f) {
            table.defaults().spaceBottom(sizes.spacingBottom);
        }
        if (sizes.spacingRight != 0.0f) {
            table.defaults().spaceRight(sizes.spacingRight);
        }
        if (sizes.spacingLeft != 0.0f) {
            table.defaults().spaceLeft(sizes.spacingLeft);
        }
    }
}