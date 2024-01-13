package com.kotcrab.vis.ui.building;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.kotcrab.vis.ui.building.utilities.CellWidget;
import com.kotcrab.vis.ui.building.utilities.Padding;
import java.util.Iterator;

/* loaded from: classes.dex */
public class OneColumnTableBuilder extends TableBuilder {
    public OneColumnTableBuilder() {
    }

    public OneColumnTableBuilder(Padding defaultWidgetPadding) {
        super(defaultWidgetPadding);
    }

    public OneColumnTableBuilder(int estimatedWidgetsAmount, int estimatedRowsAmount) {
        super(estimatedWidgetsAmount, estimatedRowsAmount);
    }

    public OneColumnTableBuilder(int estimatedWidgetsAmount, int estimatedRowsAmount, Padding defaultWidgetPadding) {
        super(estimatedWidgetsAmount, estimatedRowsAmount, defaultWidgetPadding);
    }

    @Override // com.kotcrab.vis.ui.building.TableBuilder
    protected void fillTable(Table table) {
        Iterator it = getWidgets().iterator();
        while (it.hasNext()) {
            CellWidget<? extends Actor> widget = (CellWidget) it.next();
            widget.buildCell(table, getDefaultWidgetPadding()).row();
        }
    }
}