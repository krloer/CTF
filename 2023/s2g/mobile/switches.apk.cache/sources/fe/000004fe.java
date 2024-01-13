package com.kotcrab.vis.ui.building;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.kotcrab.vis.ui.building.utilities.CellWidget;
import com.kotcrab.vis.ui.building.utilities.Padding;
import java.util.Iterator;

/* loaded from: classes.dex */
public class GridTableBuilder extends TableBuilder {
    private final int rowSize;

    public GridTableBuilder(int rowSize) {
        this.rowSize = rowSize;
    }

    public GridTableBuilder(Padding defaultWidgetPadding, int rowSize) {
        super(defaultWidgetPadding);
        this.rowSize = rowSize;
    }

    public GridTableBuilder(int rowSize, int estimatedWidgetsAmount, int estimatedRowsAmount) {
        super(estimatedWidgetsAmount, estimatedRowsAmount);
        this.rowSize = rowSize;
    }

    public GridTableBuilder(int rowSize, int estimatedWidgetsAmount, int estimatedRowsAmount, Padding defaultWidgetPadding) {
        super(estimatedWidgetsAmount, estimatedRowsAmount, defaultWidgetPadding);
        this.rowSize = rowSize;
    }

    @Override // com.kotcrab.vis.ui.building.TableBuilder
    protected void fillTable(Table table) {
        int widgetsCounter = 0;
        Iterator it = getWidgets().iterator();
        while (it.hasNext()) {
            CellWidget<? extends Actor> widget = (CellWidget) it.next();
            widget.buildCell(table, getDefaultWidgetPadding());
            widgetsCounter++;
            int i = this.rowSize;
            if (widgetsCounter == i) {
                widgetsCounter -= i;
                table.row();
            }
        }
    }
}