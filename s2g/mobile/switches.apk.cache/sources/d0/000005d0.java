package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.scenes.scene2d.ui.Cell;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.TableUtils;

/* loaded from: classes.dex */
public class VisTable extends Table {
    public VisTable() {
        super(VisUI.getSkin());
    }

    public VisTable(boolean setVisDefaults) {
        super(VisUI.getSkin());
        if (setVisDefaults) {
            TableUtils.setSpacingDefaults(this);
        }
    }

    public Cell<Separator> addSeparator(boolean vertical) {
        Cell<Separator> cell = add((VisTable) new Separator()).padTop(2.0f).padBottom(2.0f);
        if (vertical) {
            cell.fillY().expandY();
        } else {
            cell.fillX().expandX();
            row();
        }
        return cell;
    }

    public Cell<Separator> addSeparator() {
        return addSeparator(false);
    }
}