package com.kotcrab.vis.ui.building.utilities;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.ui.Cell;
import com.badlogic.gdx.scenes.scene2d.ui.Table;

/* loaded from: classes.dex */
public class CellWidget<Widget extends Actor> {
    public static final CellWidget<?> EMPTY = empty();
    private static final int IGNORED_SIZE = 0;
    private final Alignment alignment;
    private final boolean expandX;
    private final boolean expandY;
    private final boolean fillX;
    private final boolean fillY;
    private final int height;
    private final int minHeight;
    private final int minWidth;
    private final Padding padding;
    private final boolean useSpacing;
    private final Widget widget;
    private final int width;

    private CellWidget(CellWidgetBuilder<Widget> cellWidgetBuilder) {
        this.widget = (Widget) ((CellWidgetBuilder) cellWidgetBuilder).widget;
        this.padding = ((CellWidgetBuilder) cellWidgetBuilder).padding;
        this.expandX = ((CellWidgetBuilder) cellWidgetBuilder).expandX;
        this.expandY = ((CellWidgetBuilder) cellWidgetBuilder).expandY;
        this.fillX = ((CellWidgetBuilder) cellWidgetBuilder).fillX;
        this.fillY = ((CellWidgetBuilder) cellWidgetBuilder).fillY;
        this.useSpacing = ((CellWidgetBuilder) cellWidgetBuilder).useSpacing;
        this.alignment = ((CellWidgetBuilder) cellWidgetBuilder).alignment;
        this.width = ((CellWidgetBuilder) cellWidgetBuilder).width;
        this.height = ((CellWidgetBuilder) cellWidgetBuilder).height;
        this.minWidth = ((CellWidgetBuilder) cellWidgetBuilder).minWidth;
        this.minHeight = ((CellWidgetBuilder) cellWidgetBuilder).minHeight;
    }

    public static <Widget extends Actor> CellWidgetBuilder<Widget> of(Widget widget) {
        return new CellWidgetBuilder<>(widget);
    }

    public static <Widget extends Actor> CellWidgetBuilder<Widget> using(CellWidget<Widget> widget) {
        return new CellWidgetBuilder<>();
    }

    public static <Widget extends Actor> CellWidget<Widget> wrap(Widget widget) {
        return of(widget).wrap();
    }

    public static CellWidget<?>[] wrap(Actor... widgets) {
        CellWidget<?>[] wrappedWidgets = new CellWidget[widgets.length];
        for (int index = 0; index < widgets.length; index++) {
            wrappedWidgets[index] = of(widgets[index]).wrap();
        }
        return wrappedWidgets;
    }

    public static CellWidget<?> empty() {
        return builder().wrap();
    }

    public static CellWidgetBuilder<Actor> builder() {
        return of(null);
    }

    public Widget getWidget() {
        return this.widget;
    }

    public Cell<?> buildCell(Table table) {
        return buildCell(table, null);
    }

    public Cell<?> buildCell(Table table, Padding defaultWidgetPadding) {
        Cell<?> cell = table.add((Table) this.widget);
        applyPadding(cell, defaultWidgetPadding);
        applySizeData(cell);
        applyFillingData(cell);
        return cell;
    }

    private void applyPadding(Cell<?> cell, Padding defaultWidgetPadding) {
        Padding appliedPadding = (Padding) Nullables.getOrElse(this.padding, defaultWidgetPadding);
        if (appliedPadding != null) {
            if (this.useSpacing) {
                appliedPadding.applySpacing(cell);
            } else {
                appliedPadding.applyPadding(cell);
            }
        }
    }

    private void applySizeData(Cell<?> cell) {
        int i = this.width;
        if (i > 0) {
            cell.width(i);
        }
        int i2 = this.height;
        if (i2 > 0) {
            cell.height(i2);
        }
        int i3 = this.minWidth;
        if (i3 > 0) {
            cell.minWidth(i3);
        }
        int i4 = this.minHeight;
        if (i4 > 0) {
            cell.minHeight(i4);
        }
    }

    private void applyFillingData(Cell<?> cell) {
        Alignment alignment = this.alignment;
        if (alignment != null) {
            alignment.apply(cell);
        }
        cell.expand(this.expandX, this.expandY);
        cell.fill(this.fillX, this.fillY);
    }

    /* loaded from: classes.dex */
    public static class CellWidgetBuilder<Widget extends Actor> {
        private Alignment alignment;
        private boolean expandX;
        private boolean expandY;
        private boolean fillX;
        private boolean fillY;
        private int height;
        private int minHeight;
        private int minWidth;
        private Padding padding;
        private boolean useSpacing;
        private Actor widget;
        private int width;

        private CellWidgetBuilder(Actor widget) {
            this.width = 0;
            this.height = 0;
            this.minWidth = 0;
            this.minHeight = 0;
            this.widget = widget;
        }

        private CellWidgetBuilder(CellWidget<Widget> widget) {
            this.width = 0;
            this.height = 0;
            this.minWidth = 0;
            this.minHeight = 0;
            this.widget = ((CellWidget) widget).widget;
            this.padding = ((CellWidget) widget).padding;
            this.expandX = ((CellWidget) widget).expandX;
            this.expandY = ((CellWidget) widget).expandY;
            this.fillX = ((CellWidget) widget).fillX;
            this.fillY = ((CellWidget) widget).fillY;
            this.useSpacing = ((CellWidget) widget).useSpacing;
            this.alignment = ((CellWidget) widget).alignment;
            this.width = ((CellWidget) widget).width;
            this.height = ((CellWidget) widget).height;
            this.minWidth = ((CellWidget) widget).minWidth;
            this.minHeight = ((CellWidget) widget).minHeight;
        }

        public CellWidget<Widget> wrap() {
            return new CellWidget<>(this);
        }

        public CellWidgetBuilder<Widget> widget(Widget widget) {
            this.widget = widget;
            return this;
        }

        public CellWidgetBuilder<Widget> padding(Padding padding) {
            this.padding = padding;
            return this;
        }

        public CellWidgetBuilder<Widget> useSpacing() {
            this.useSpacing = true;
            return this;
        }

        public CellWidgetBuilder<Widget> expandX() {
            this.expandX = true;
            return this;
        }

        public CellWidgetBuilder<Widget> expandY() {
            this.expandY = true;
            return this;
        }

        public CellWidgetBuilder<Widget> fillX() {
            this.fillX = true;
            return this;
        }

        public CellWidgetBuilder<Widget> fillY() {
            this.fillY = true;
            return this;
        }

        public CellWidgetBuilder<Widget> align(Alignment alignment) {
            this.alignment = alignment;
            return this;
        }

        public CellWidgetBuilder<Widget> width(int width) {
            this.width = width;
            return this;
        }

        public CellWidgetBuilder<Widget> height(int height) {
            this.height = height;
            return this;
        }

        public CellWidgetBuilder<Widget> minWidth(int minWidth) {
            this.minWidth = minWidth;
            return this;
        }

        public CellWidgetBuilder<Widget> minHeight(int minHeight) {
            this.minHeight = minHeight;
            return this;
        }
    }
}