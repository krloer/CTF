package com.kotcrab.vis.ui.building;

import com.badlogic.gdx.scenes.scene2d.ui.Cell;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.utils.IntArray;
import com.kotcrab.vis.ui.building.utilities.Padding;

/* loaded from: classes.dex */
public class CenteredTableBuilder extends TableBuilder {
    public CenteredTableBuilder() {
    }

    public CenteredTableBuilder(Padding defaultWidgetPadding) {
        super(defaultWidgetPadding);
    }

    public CenteredTableBuilder(int estimatedWidgetsAmount, int estimatedRowsAmount) {
        super(estimatedWidgetsAmount, estimatedRowsAmount);
    }

    public CenteredTableBuilder(int estimatedWidgetsAmount, int estimatedRowsAmount, Padding defaultWidgetPadding) {
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
            boolean isFirst = shouldExpand(rowSize);
            int totalWidgetsBeforeRowEnd = widgetIndex + rowSize;
            while (widgetIndex < totalWidgetsBeforeRowEnd) {
                Cell<?> cell = getWidget(widgetIndex).buildCell(table, getDefaultWidgetPadding()).colspan(currentWidgetColspan);
                if (isFirst) {
                    isFirst = false;
                    cell.expandX().right();
                } else if (isLast(widgetIndex, rowSize, totalWidgetsBeforeRowEnd)) {
                    cell.expandX().left();
                }
                widgetIndex++;
            }
            table.row();
        }
    }

    private boolean shouldExpand(int rowSize) {
        return rowSize != 1;
    }

    private boolean isLast(int widgetIndex, int rowSize, int totalWidgetsInRow) {
        return shouldExpand(rowSize) && widgetIndex == totalWidgetsInRow + (-1);
    }
}