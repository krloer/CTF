package com.kotcrab.vis.ui.building;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.IntArray;
import com.kotcrab.vis.ui.building.utilities.CellWidget;
import com.kotcrab.vis.ui.building.utilities.Padding;
import com.kotcrab.vis.ui.building.utilities.layouts.ActorLayout;
import com.kotcrab.vis.ui.building.utilities.layouts.TableLayout;

/* loaded from: classes.dex */
public abstract class TableBuilder {
    private static final int DEFAULT_ROWS_AMOUNT = 3;
    private static final int DEFAULT_WIDGETS_AMOUNT = 10;
    private int currentRowSize;
    private final IntArray rowSizes;
    private Padding tablePadding;
    private final Padding widgetPadding;
    private final Array<CellWidget<? extends Actor>> widgets;

    protected abstract void fillTable(Table table);

    public TableBuilder() {
        this(10, 3, Padding.PAD_0);
    }

    public TableBuilder(Padding defaultWidgetPadding) {
        this(10, 3, defaultWidgetPadding);
    }

    public TableBuilder(int estimatedWidgetsAmount, int estimatedRowsAmount) {
        this(estimatedWidgetsAmount, estimatedRowsAmount, Padding.PAD_0);
    }

    public TableBuilder(int estimatedWidgetsAmount, int estimatedRowsAmount, Padding defaultWidgetPadding) {
        this.widgets = new Array<>(estimatedWidgetsAmount);
        this.rowSizes = new IntArray(estimatedRowsAmount);
        this.widgetPadding = defaultWidgetPadding;
    }

    public static int getGreatestCommonDenominator(int valueA, int valueB) {
        return valueB == 0 ? valueA : getGreatestCommonDenominator(valueB, valueA % valueB);
    }

    public static int getLowestCommonMultiple(int valueA, int valueB) {
        return (valueB / getGreatestCommonDenominator(valueA, valueB)) * valueA;
    }

    public static int getLowestCommonMultiple(IntArray values) {
        int lowestCommonMultiple = values.first();
        for (int index = 1; index < values.size; index++) {
            lowestCommonMultiple = getLowestCommonMultiple(lowestCommonMultiple, values.get(index));
        }
        return lowestCommonMultiple;
    }

    public TableBuilder setTablePadding(Padding tablePadding) {
        this.tablePadding = tablePadding;
        return this;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public Padding getDefaultWidgetPadding() {
        return this.widgetPadding;
    }

    public TableBuilder append(Actor widget) {
        return append(CellWidget.of(widget).padding(this.widgetPadding).wrap());
    }

    public TableBuilder append(CellWidget<? extends Actor> widget) {
        this.widgets.add(widget);
        this.currentRowSize++;
        return this;
    }

    public TableBuilder append(Actor... widgets) {
        return append(TableLayout.HORIZONTAL, widgets);
    }

    public TableBuilder append(CellWidget<?>... widgets) {
        return append(TableLayout.HORIZONTAL, widgets);
    }

    public TableBuilder append(ActorLayout layout, Actor... widgets) {
        return append(layout.convertToActor(widgets));
    }

    public TableBuilder append(ActorLayout layout, CellWidget<?>... widgets) {
        return append(layout.convertToActor(widgets));
    }

    public TableBuilder append(CellWidget.CellWidgetBuilder<Actor> mergedCellSettings, Actor... widgets) {
        return append(TableLayout.HORIZONTAL, mergedCellSettings, widgets);
    }

    public TableBuilder append(CellWidget.CellWidgetBuilder<Actor> mergedCellSettings, CellWidget<?>... widgets) {
        return append(TableLayout.HORIZONTAL, mergedCellSettings, widgets);
    }

    public TableBuilder append(ActorLayout layout, CellWidget.CellWidgetBuilder<Actor> mergedCellSettings, Actor... widgets) {
        return append(mergedCellSettings.widget(layout.convertToActor(widgets)).wrap());
    }

    public TableBuilder append(ActorLayout layout, CellWidget.CellWidgetBuilder<Actor> mergedCellSettings, CellWidget<?>... widgets) {
        return append(mergedCellSettings.widget(layout.convertToActor(widgets)).wrap());
    }

    /* JADX WARN: Multi-variable type inference failed */
    public TableBuilder append() {
        return append((CellWidget<? extends Actor>) CellWidget.EMPTY);
    }

    public TableBuilder row() {
        int i = this.currentRowSize;
        if (i != 0) {
            this.rowSizes.add(i);
            this.currentRowSize = 0;
        }
        return this;
    }

    public Table build() {
        return build(new Table());
    }

    public <T extends Table> T build(T table) {
        prepareNewTable(table);
        if (this.widgets.size == 0) {
            return table;
        }
        fillTable(table);
        return (T) prepareBuiltTable(table);
    }

    private Table prepareNewTable(Table table) {
        validateRowSize();
        Padding padding = this.tablePadding;
        if (padding != null) {
            return padding.applyPadding(table);
        }
        return table;
    }

    private <T extends Table> T prepareBuiltTable(T table) {
        table.pack();
        return table;
    }

    private void validateRowSize() {
        if (this.currentRowSize != 0) {
            row();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public IntArray getRowSizes() {
        return this.rowSizes;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public CellWidget<? extends Actor> getWidget(int index) {
        return this.widgets.get(index);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public Array<CellWidget<? extends Actor>> getWidgets() {
        return this.widgets;
    }
}