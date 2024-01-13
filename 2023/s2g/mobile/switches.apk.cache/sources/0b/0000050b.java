package com.kotcrab.vis.ui.building.utilities.layouts;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.kotcrab.vis.ui.building.OneColumnTableBuilder;
import com.kotcrab.vis.ui.building.OneRowTableBuilder;
import com.kotcrab.vis.ui.building.TableBuilder;
import com.kotcrab.vis.ui.building.utilities.CellWidget;

/* loaded from: classes.dex */
public enum TableLayout implements ActorLayout {
    VERTICAL { // from class: com.kotcrab.vis.ui.building.utilities.layouts.TableLayout.1
        @Override // com.kotcrab.vis.ui.building.utilities.layouts.ActorLayout
        public Actor convertToActor(CellWidget<?>... widgets) {
            return convertToTable(new OneColumnTableBuilder(), widgets);
        }
    },
    HORIZONTAL { // from class: com.kotcrab.vis.ui.building.utilities.layouts.TableLayout.2
        @Override // com.kotcrab.vis.ui.building.utilities.layouts.ActorLayout
        public Actor convertToActor(CellWidget<?>... widgets) {
            return convertToTable(new OneRowTableBuilder(), widgets);
        }
    };

    @Override // com.kotcrab.vis.ui.building.utilities.layouts.ActorLayout
    public Actor convertToActor(Actor... widgets) {
        return convertToActor(CellWidget.wrap(widgets));
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static Actor convertToTable(TableBuilder usingBuilder, CellWidget<?>... widgets) {
        for (CellWidget<?> widget : widgets) {
            usingBuilder.append((CellWidget<? extends Actor>) widget);
        }
        return usingBuilder.build();
    }

    public static GridTableLayout grid(int rowSize) {
        return GridTableLayout.withRowSize(rowSize);
    }
}