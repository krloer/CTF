package com.kotcrab.vis.ui.building.utilities.layouts;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.kotcrab.vis.ui.building.utilities.CellWidget;

/* loaded from: classes.dex */
public interface ActorLayout {
    Actor convertToActor(Actor... actorArr);

    Actor convertToActor(CellWidget<?>... cellWidgetArr);
}