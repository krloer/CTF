package com.kotcrab.vis.ui.building;

import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.utils.IntArray;
import com.kotcrab.vis.ui.building.utilities.Padding;

/* loaded from: classes.dex */
public class StandardTableBuilder extends TableBuilder {
    public StandardTableBuilder() {
    }

    public StandardTableBuilder(Padding defaultWidgetPadding) {
        super(defaultWidgetPadding);
    }

    public StandardTableBuilder(int estimatedWidgetsAmount, int estimatedRowsAmount) {
        super(estimatedWidgetsAmount, estimatedRowsAmount);
    }

    public StandardTableBuilder(int estimatedWidgetsAmount, int estimatedRowsAmount, Padding defaultWidgetPadding) {
        super(estimatedWidgetsAmount, estimatedRowsAmount, defaultWidgetPadding);
    }

    @Override // com.kotcrab.vis.ui.building.TableBuilder
    protected void fillTable(Table table) {
        IntArray rowSizes = getRowSizes();
        int widgetsInRow = getLowestCommonMultiple(rowSizes);
        int widgetIndex = 0;
        for (int rowIndex = 0; rowIndex < rowSizes.size; rowIndex++) {
            int rowSize = rowSizes.get(rowIndex);
            int currentWidgetColspan = widgetsInRow / rowSize;
            int totalWidgets = widgetIndex + rowSize;
            while (widgetIndex < totalWidgets) {
                getWidget(widgetIndex).buildCell(table, getDefaultWidgetPadding()).colspan(currentWidgetColspan);
                widgetIndex++;
            }
            table.row();
        }
    }
}