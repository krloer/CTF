package com.kotcrab.vis.ui.building.utilities.layouts;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.kotcrab.vis.ui.building.GridTableBuilder;
import com.kotcrab.vis.ui.building.utilities.CellWidget;

/* loaded from: classes.dex */
public class GridTableLayout implements ActorLayout {
    private final int rowSize;

    public GridTableLayout(int rowSize) {
        this.rowSize = rowSize;
    }

    public static GridTableLayout withRowSize(int rowSize) {
        return new GridTableLayout(rowSize);
    }

    @Override // com.kotcrab.vis.ui.building.utilities.layouts.ActorLayout
    public Actor convertToActor(Actor... widgets) {
        return convertToActor(CellWidget.wrap(widgets));
    }

    @Override // com.kotcrab.vis.ui.building.utilities.layouts.ActorLayout
    public Actor convertToActor(CellWidget<?>... widgets) {
        return TableLayout.convertToTable(new GridTableBuilder(this.rowSize), widgets);
    }
}