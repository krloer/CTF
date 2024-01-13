package com.kotcrab.vis.ui.layout;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Group;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.Container;
import com.badlogic.gdx.scenes.scene2d.ui.HorizontalGroup;
import com.badlogic.gdx.scenes.scene2d.ui.VerticalGroup;
import com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.SnapshotArray;
import com.kotcrab.vis.ui.widget.Draggable;

/* loaded from: classes.dex */
public class DragPane extends Container<WidgetGroup> {
    private Draggable draggable;
    private DragPaneListener listener;

    public DragPane() {
        this(false);
    }

    public DragPane(boolean vertical) {
        this(vertical ? new VerticalGroup() : new HorizontalGroup());
    }

    public DragPane(WidgetGroup group) {
        if (group == null) {
            throw new IllegalArgumentException("Group cannot be null.");
        }
        super.setActor((DragPane) group);
        setTouchable(Touchable.enabled);
    }

    public boolean isVertical() {
        return getActor() instanceof VerticalGroup;
    }

    public boolean isHorizontal() {
        return getActor() instanceof HorizontalGroup;
    }

    public boolean isGrid() {
        return getActor() instanceof GridGroup;
    }

    public boolean isVerticalFlow() {
        return getActor() instanceof VerticalFlowGroup;
    }

    public boolean isHorizontalFlow() {
        return getActor() instanceof HorizontalFlowGroup;
    }

    public boolean isFloating() {
        return getActor() instanceof FloatingGroup;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public SnapshotArray<Actor> getChildren() {
        return getActor().getChildren();
    }

    public WidgetGroup getGroup() {
        return getActor();
    }

    public void setGroup(WidgetGroup group) {
        setActor(group);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Container
    public void setActor(WidgetGroup group) {
        if (group == null) {
            throw new IllegalArgumentException("Group cannot be null.");
        }
        Group previousGroup = getActor();
        super.setActor((DragPane) group);
        attachListener();
        Array.ArrayIterator<Actor> it = previousGroup.getChildren().iterator();
        while (it.hasNext()) {
            Actor child = it.next();
            group.addActor(child);
        }
    }

    public HorizontalGroup getHorizontalGroup() {
        return (HorizontalGroup) getActor();
    }

    public VerticalGroup getVerticalGroup() {
        return (VerticalGroup) getActor();
    }

    public GridGroup getGridGroup() {
        return (GridGroup) getActor();
    }

    public HorizontalFlowGroup getHorizontalFlowGroup() {
        return (HorizontalFlowGroup) getActor();
    }

    public VerticalFlowGroup getVerticalFlowGroup() {
        return (VerticalFlowGroup) getActor();
    }

    public FloatingGroup getFloatingGroup() {
        return (FloatingGroup) getActor();
    }

    public Draggable getDraggable() {
        return this.draggable;
    }

    public void setDraggable(Draggable draggable) {
        removeListener();
        this.draggable = draggable;
        attachListener();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void setBounds(float x, float y, float width, float height) {
        super.setBounds(x, y, width, height);
        getActor().setWidth(width);
        getActor().setHeight(height);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void setWidth(float width) {
        super.setWidth(width);
        getActor().setWidth(width);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void setHeight(float height) {
        super.setHeight(height);
        getActor().setHeight(height);
    }

    private void removeListener() {
        if (this.draggable == null) {
            return;
        }
        Array.ArrayIterator<Actor> it = getChildren().iterator();
        while (it.hasNext()) {
            Actor actor = it.next();
            actor.removeListener(this.draggable);
        }
    }

    private void attachListener() {
        if (this.draggable == null) {
            return;
        }
        Array.ArrayIterator<Actor> it = getChildren().iterator();
        while (it.hasNext()) {
            Actor actor = it.next();
            this.draggable.attachTo(actor);
        }
    }

    public boolean contains(Actor actor) {
        return actor.getParent() == getActor();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Container, com.badlogic.gdx.scenes.scene2d.Group
    public boolean removeActor(Actor actor) {
        return removeActor(actor, true);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Container, com.badlogic.gdx.scenes.scene2d.Group
    public boolean removeActor(Actor actor, boolean unfocus) {
        if (getActor().getChildren().contains(actor, true)) {
            Stage stage = actor.getStage();
            getActor().removeActor(actor, false);
            if (unfocus && stage != null) {
                stage.unfocus(actor);
            }
            return true;
        }
        return false;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void clear() {
        getActor().clear();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Container, com.badlogic.gdx.scenes.scene2d.Group
    public void addActor(Actor actor) {
        getActor().addActor(actor);
        doOnAdd(actor);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Container, com.badlogic.gdx.scenes.scene2d.Group
    public void addActorAfter(Actor actorAfter, Actor actor) {
        getActor().addActorAfter(actorAfter, actor);
        doOnAdd(actor);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Container, com.badlogic.gdx.scenes.scene2d.Group
    public void addActorAt(int index, Actor actor) {
        getActor().addActorAt(index, actor);
        doOnAdd(actor);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Container, com.badlogic.gdx.scenes.scene2d.Group
    public void addActorBefore(Actor actorBefore, Actor actor) {
        getActor().addActorBefore(actorBefore, actor);
        doOnAdd(actor);
    }

    protected void doOnAdd(Actor actor) {
        Draggable draggable = this.draggable;
        if (draggable != null) {
            draggable.attachTo(actor);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public <T extends Actor> T findActor(String name) {
        return (T) getActor().findActor(name);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void invalidate() {
        super.invalidate();
        getActor().invalidate();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void validate() {
        super.validate();
        getActor().validate();
    }

    public void setListener(DragPaneListener listener) {
        this.listener = listener;
    }

    protected boolean accept(Actor actor) {
        DragPaneListener dragPaneListener = this.listener;
        return dragPaneListener == null || dragPaneListener.accept(this, actor);
    }

    /* loaded from: classes.dex */
    public static class DefaultDragListener implements Draggable.DragListener {
        protected static final Vector2 DRAG_POSITION = new Vector2();
        private Policy policy;

        /* loaded from: classes.dex */
        public enum DefaultPolicy implements Policy {
            ALLOW_REMOVAL { // from class: com.kotcrab.vis.ui.layout.DragPane.DefaultDragListener.DefaultPolicy.1
                @Override // com.kotcrab.vis.ui.layout.DragPane.DefaultDragListener.Policy
                public boolean accept(DragPane dragPane, Actor actor) {
                    return true;
                }
            },
            KEEP_CHILDREN { // from class: com.kotcrab.vis.ui.layout.DragPane.DefaultDragListener.DefaultPolicy.2
                @Override // com.kotcrab.vis.ui.layout.DragPane.DefaultDragListener.Policy
                public boolean accept(DragPane dragPane, Actor actor) {
                    return dragPane.contains(actor);
                }
            }
        }

        /* loaded from: classes.dex */
        public interface Policy {
            boolean accept(DragPane dragPane, Actor actor);
        }

        public DefaultDragListener() {
            this(DefaultPolicy.ALLOW_REMOVAL);
        }

        public DefaultDragListener(Policy policy) {
            setPolicy(policy);
        }

        public void setPolicy(Policy policy) {
            if (policy == null) {
                throw new IllegalArgumentException("Policy cannot be null.");
            }
            this.policy = policy;
        }

        @Override // com.kotcrab.vis.ui.widget.Draggable.DragListener
        public boolean onStart(Draggable draggable, Actor actor, float stageX, float stageY) {
            return true;
        }

        @Override // com.kotcrab.vis.ui.widget.Draggable.DragListener
        public void onDrag(Draggable draggable, Actor actor, float stageX, float stageY) {
        }

        @Override // com.kotcrab.vis.ui.widget.Draggable.DragListener
        public boolean onEnd(Draggable draggable, Actor actor, float stageX, float stageY) {
            Actor overActor;
            if (actor == null || actor.getStage() == null || (overActor = actor.getStage().hit(stageX, stageY, true)) == null || overActor == actor) {
                return false;
            }
            if (overActor.isAscendantOf(actor)) {
                DragPane dragPane = getDragPane(actor);
                if (dragPane == null || !dragPane.isFloating()) {
                    return false;
                }
                DRAG_POSITION.set(stageX, stageY);
                return addToFloatingGroup(draggable, actor, dragPane);
            }
            DRAG_POSITION.set(stageX, stageY);
            if (overActor instanceof DragPane) {
                return addDirectlyToPane(draggable, actor, (DragPane) overActor);
            }
            DragPane dragPane2 = getDragPane(overActor);
            if (!accept(actor, dragPane2)) {
                return false;
            }
            return addActor(draggable, actor, overActor, dragPane2);
        }

        protected boolean addDirectlyToPane(Draggable draggable, Actor actor, DragPane dragPane) {
            if (accept(actor, dragPane)) {
                if (dragPane.isFloating()) {
                    return addToFloatingGroup(draggable, actor, dragPane);
                }
                dragPane.addActor(actor);
                return true;
            }
            return false;
        }

        protected boolean accept(Actor actor, DragPane dragPane) {
            return dragPane != null && dragPane.accept(actor) && this.policy.accept(dragPane, actor);
        }

        protected boolean addActor(Draggable draggable, Actor actor, Actor overActor, DragPane dragPane) {
            Actor directPaneChild = getActorInDragPane(overActor, dragPane);
            directPaneChild.stageToLocalCoordinates(DRAG_POSITION);
            if (dragPane.isVertical() || dragPane.isVerticalFlow()) {
                return addToVerticalGroup(actor, dragPane, directPaneChild);
            }
            if (dragPane.isHorizontal() || dragPane.isHorizontalFlow()) {
                return addToHorizontalGroup(actor, dragPane, directPaneChild);
            }
            if (dragPane.isFloating()) {
                return addToFloatingGroup(draggable, actor, dragPane);
            }
            return addToOtherGroup(actor, dragPane, directPaneChild);
        }

        protected boolean addToHorizontalGroup(Actor actor, DragPane dragPane, Actor directPaneChild) {
            Array<Actor> children = dragPane.getChildren();
            int indexOfDraggedActor = children.indexOf(actor, true);
            if (indexOfDraggedActor >= 0) {
                int indexOfDirectChild = children.indexOf(directPaneChild, true);
                if (indexOfDirectChild > indexOfDraggedActor) {
                    dragPane.addActorAfter(directPaneChild, actor);
                } else {
                    dragPane.addActorBefore(directPaneChild, actor);
                }
            } else if (DRAG_POSITION.x > directPaneChild.getWidth() / 2.0f) {
                dragPane.addActorAfter(directPaneChild, actor);
            } else {
                dragPane.addActorBefore(directPaneChild, actor);
            }
            return true;
        }

        protected boolean addToVerticalGroup(Actor actor, DragPane dragPane, Actor directPaneChild) {
            Array<Actor> children = dragPane.getChildren();
            int indexOfDraggedActor = children.indexOf(actor, true);
            if (indexOfDraggedActor >= 0) {
                int indexOfDirectChild = children.indexOf(directPaneChild, true);
                if (indexOfDirectChild > indexOfDraggedActor) {
                    dragPane.addActorAfter(directPaneChild, actor);
                } else {
                    dragPane.addActorBefore(directPaneChild, actor);
                }
            } else if (DRAG_POSITION.y < directPaneChild.getHeight() / 2.0f) {
                dragPane.addActorAfter(directPaneChild, actor);
            } else {
                dragPane.addActorBefore(directPaneChild, actor);
            }
            return true;
        }

        protected boolean addToFloatingGroup(Draggable draggable, Actor actor, DragPane dragPane) {
            FloatingGroup group = dragPane.getFloatingGroup();
            dragPane.stageToLocalCoordinates(DRAG_POSITION);
            float x = DRAG_POSITION.x + draggable.getOffsetX();
            if (x < 0.0f || actor.getWidth() + x > dragPane.getWidth()) {
                if (!draggable.isKeptWithinParent()) {
                    return false;
                }
                x = x < 0.0f ? 0.0f : (dragPane.getWidth() - actor.getWidth()) - 1.0f;
            }
            float y = DRAG_POSITION.y + draggable.getOffsetY();
            if (y < 0.0f || actor.getHeight() + y > dragPane.getHeight()) {
                if (!draggable.isKeptWithinParent()) {
                    return false;
                }
                y = y >= 0.0f ? (dragPane.getHeight() - actor.getHeight()) - 1.0f : 0.0f;
            }
            actor.remove();
            actor.setPosition(x, y);
            group.addActor(actor);
            return true;
        }

        protected boolean addToOtherGroup(Actor actor, DragPane dragPane, Actor directPaneChild) {
            Array<Actor> children = dragPane.getChildren();
            int indexOfDirectChild = children.indexOf(directPaneChild, true);
            int indexOfDraggedActor = children.indexOf(actor, true);
            if (indexOfDraggedActor < 0) {
                if (indexOfDirectChild == children.size - 1) {
                    if (DRAG_POSITION.y < directPaneChild.getHeight() / 2.0f || DRAG_POSITION.x > directPaneChild.getWidth() / 2.0f) {
                        dragPane.addActor(actor);
                    } else {
                        dragPane.addActorBefore(directPaneChild, actor);
                    }
                } else if (indexOfDirectChild == 0) {
                    if (DRAG_POSITION.y < directPaneChild.getHeight() / 2.0f || DRAG_POSITION.x > directPaneChild.getWidth() / 2.0f) {
                        dragPane.addActorAfter(directPaneChild, actor);
                    } else {
                        dragPane.addActorBefore(directPaneChild, actor);
                    }
                } else {
                    dragPane.addActorBefore(directPaneChild, actor);
                }
            } else if (indexOfDraggedActor > indexOfDirectChild) {
                dragPane.addActorBefore(directPaneChild, actor);
            } else {
                dragPane.addActorAfter(directPaneChild, actor);
            }
            return true;
        }

        protected Actor getActorInDragPane(Actor actor, DragPane dragPane) {
            while (actor != dragPane && actor != null) {
                if (dragPane.contains(actor)) {
                    return actor;
                }
                actor = actor.getParent();
            }
            return null;
        }

        protected DragPane getDragPane(Actor fromActor) {
            while (fromActor != null) {
                if (fromActor instanceof DragPane) {
                    return (DragPane) fromActor;
                }
                fromActor = fromActor.getParent();
            }
            return null;
        }
    }

    /* loaded from: classes.dex */
    public interface DragPaneListener {
        public static final boolean ACCEPT = true;
        public static final boolean REFUSE = false;

        boolean accept(DragPane dragPane, Actor actor);

        /* loaded from: classes.dex */
        public static class AcceptOwnChildren implements DragPaneListener {
            @Override // com.kotcrab.vis.ui.layout.DragPane.DragPaneListener
            public boolean accept(DragPane dragPane, Actor actor) {
                return dragPane.contains(actor);
            }
        }

        /* loaded from: classes.dex */
        public static class LimitChildren implements DragPaneListener {
            private final int max;

            public LimitChildren(int max) {
                this.max = max;
            }

            @Override // com.kotcrab.vis.ui.layout.DragPane.DragPaneListener
            public boolean accept(DragPane dragPane, Actor actor) {
                return dragPane.contains(actor) || dragPane.getChildren().size < this.max;
            }
        }
    }
}