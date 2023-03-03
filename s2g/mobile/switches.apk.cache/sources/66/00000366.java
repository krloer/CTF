package com.badlogic.gdx.scenes.scene2d;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.glutils.ShapeRenderer;
import com.badlogic.gdx.math.Affine2;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.utils.Cullable;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.SnapshotArray;

/* loaded from: classes.dex */
public class Group extends Actor implements Cullable {
    private static final Vector2 tmp = new Vector2();
    private Rectangle cullingArea;
    final SnapshotArray<Actor> children = new SnapshotArray<>(true, 4, Actor.class);
    private final Affine2 worldTransform = new Affine2();
    private final Matrix4 computedTransform = new Matrix4();
    private final Matrix4 oldTransform = new Matrix4();
    boolean transform = true;

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void act(float delta) {
        super.act(delta);
        Actor[] actors = this.children.begin();
        int n = this.children.size;
        for (int i = 0; i < n; i++) {
            actors[i].act(delta);
        }
        this.children.end();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        if (this.transform) {
            applyTransform(batch, computeTransform());
        }
        drawChildren(batch, parentAlpha);
        if (this.transform) {
            resetTransform(batch);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void drawChildren(Batch batch, float parentAlpha) {
        Rectangle cullingArea;
        float cullRight;
        float parentAlpha2 = this.color.a * parentAlpha;
        SnapshotArray<Actor> children = this.children;
        Actor[] actors = children.begin();
        Rectangle cullingArea2 = this.cullingArea;
        if (cullingArea2 == null) {
            if (this.transform) {
                int n = children.size;
                for (int i = 0; i < n; i++) {
                    Actor child = actors[i];
                    if (child.isVisible()) {
                        child.draw(batch, parentAlpha2);
                    }
                }
            } else {
                float offsetX = this.x;
                float offsetY = this.y;
                this.x = 0.0f;
                this.y = 0.0f;
                int n2 = children.size;
                for (int i2 = 0; i2 < n2; i2++) {
                    Actor child2 = actors[i2];
                    if (child2.isVisible()) {
                        float cx = child2.x;
                        float cy = child2.y;
                        child2.x = cx + offsetX;
                        child2.y = cy + offsetY;
                        child2.draw(batch, parentAlpha2);
                        child2.x = cx;
                        child2.y = cy;
                    }
                }
                this.x = offsetX;
                this.y = offsetY;
            }
        } else {
            float cullLeft = cullingArea2.x;
            float cullRight2 = cullingArea2.width + cullLeft;
            float cullBottom = cullingArea2.y;
            float cullTop = cullingArea2.height + cullBottom;
            if (this.transform) {
                int n3 = children.size;
                for (int i3 = 0; i3 < n3; i3++) {
                    Actor child3 = actors[i3];
                    if (child3.isVisible()) {
                        float cx2 = child3.x;
                        float cy2 = child3.y;
                        if (cx2 <= cullRight2 && cy2 <= cullTop && child3.width + cx2 >= cullLeft && child3.height + cy2 >= cullBottom) {
                            child3.draw(batch, parentAlpha2);
                        }
                    }
                }
            } else {
                float offsetX2 = this.x;
                float offsetY2 = this.y;
                this.x = 0.0f;
                this.y = 0.0f;
                int i4 = 0;
                int n4 = children.size;
                while (i4 < n4) {
                    Actor child4 = actors[i4];
                    if (child4.isVisible()) {
                        float cx3 = child4.x;
                        cullingArea = cullingArea2;
                        float cy3 = child4.y;
                        if (cx3 > cullRight2 || cy3 > cullTop) {
                            cullRight = cullRight2;
                        } else {
                            cullRight = cullRight2;
                            if (child4.width + cx3 >= cullLeft && child4.height + cy3 >= cullBottom) {
                                child4.x = cx3 + offsetX2;
                                child4.y = cy3 + offsetY2;
                                child4.draw(batch, parentAlpha2);
                                child4.x = cx3;
                                child4.y = cy3;
                            }
                        }
                    } else {
                        cullingArea = cullingArea2;
                        cullRight = cullRight2;
                    }
                    i4++;
                    cullingArea2 = cullingArea;
                    cullRight2 = cullRight;
                }
                this.x = offsetX2;
                this.y = offsetY2;
            }
        }
        children.end();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void drawDebug(ShapeRenderer shapes) {
        drawDebugBounds(shapes);
        if (this.transform) {
            applyTransform(shapes, computeTransform());
        }
        drawDebugChildren(shapes);
        if (this.transform) {
            resetTransform(shapes);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void drawDebugChildren(ShapeRenderer shapes) {
        SnapshotArray<Actor> children = this.children;
        Actor[] actors = children.begin();
        if (this.transform) {
            int n = children.size;
            for (int i = 0; i < n; i++) {
                Actor child = actors[i];
                if (child.isVisible() && (child.getDebug() || (child instanceof Group))) {
                    child.drawDebug(shapes);
                }
            }
            shapes.flush();
        } else {
            float offsetX = this.x;
            float offsetY = this.y;
            this.x = 0.0f;
            this.y = 0.0f;
            int n2 = children.size;
            for (int i2 = 0; i2 < n2; i2++) {
                Actor child2 = actors[i2];
                if (child2.isVisible() && (child2.getDebug() || (child2 instanceof Group))) {
                    float cx = child2.x;
                    float cy = child2.y;
                    child2.x = cx + offsetX;
                    child2.y = cy + offsetY;
                    child2.drawDebug(shapes);
                    child2.x = cx;
                    child2.y = cy;
                }
            }
            this.x = offsetX;
            this.y = offsetY;
        }
        children.end();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public Matrix4 computeTransform() {
        Affine2 worldTransform = this.worldTransform;
        float originX = this.originX;
        float originY = this.originY;
        worldTransform.setToTrnRotScl(this.x + originX, this.y + originY, this.rotation, this.scaleX, this.scaleY);
        if (originX != 0.0f || originY != 0.0f) {
            worldTransform.translate(-originX, -originY);
        }
        Group parentGroup = this.parent;
        while (parentGroup != null && !parentGroup.transform) {
            parentGroup = parentGroup.parent;
        }
        if (parentGroup != null) {
            worldTransform.preMul(parentGroup.worldTransform);
        }
        this.computedTransform.set(worldTransform);
        return this.computedTransform;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void applyTransform(Batch batch, Matrix4 transform) {
        this.oldTransform.set(batch.getTransformMatrix());
        batch.setTransformMatrix(transform);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void resetTransform(Batch batch) {
        batch.setTransformMatrix(this.oldTransform);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void applyTransform(ShapeRenderer shapes, Matrix4 transform) {
        this.oldTransform.set(shapes.getTransformMatrix());
        shapes.setTransformMatrix(transform);
        shapes.flush();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void resetTransform(ShapeRenderer shapes) {
        shapes.setTransformMatrix(this.oldTransform);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Cullable
    public void setCullingArea(Rectangle cullingArea) {
        this.cullingArea = cullingArea;
    }

    public Rectangle getCullingArea() {
        return this.cullingArea;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public Actor hit(float x, float y, boolean touchable) {
        if ((touchable && getTouchable() == Touchable.disabled) || !isVisible()) {
            return null;
        }
        Vector2 point = tmp;
        Actor[] childrenArray = this.children.items;
        for (int i = this.children.size - 1; i >= 0; i--) {
            Actor child = childrenArray[i];
            child.parentToLocalCoordinates(point.set(x, y));
            Actor hit = child.hit(point.x, point.y, touchable);
            if (hit != null) {
                return hit;
            }
        }
        return super.hit(x, y, touchable);
    }

    protected void childrenChanged() {
    }

    public void addActor(Actor actor) {
        if (actor.parent != null) {
            if (actor.parent == this) {
                return;
            }
            actor.parent.removeActor(actor, false);
        }
        this.children.add(actor);
        actor.setParent(this);
        actor.setStage(getStage());
        childrenChanged();
    }

    public void addActorAt(int index, Actor actor) {
        if (actor.parent != null) {
            if (actor.parent == this) {
                return;
            }
            actor.parent.removeActor(actor, false);
        }
        if (index >= this.children.size) {
            this.children.add(actor);
        } else {
            this.children.insert(index, actor);
        }
        actor.setParent(this);
        actor.setStage(getStage());
        childrenChanged();
    }

    public void addActorBefore(Actor actorBefore, Actor actor) {
        if (actor.parent != null) {
            if (actor.parent == this) {
                return;
            }
            actor.parent.removeActor(actor, false);
        }
        int index = this.children.indexOf(actorBefore, true);
        this.children.insert(index, actor);
        actor.setParent(this);
        actor.setStage(getStage());
        childrenChanged();
    }

    public void addActorAfter(Actor actorAfter, Actor actor) {
        if (actor.parent != null) {
            if (actor.parent == this) {
                return;
            }
            actor.parent.removeActor(actor, false);
        }
        int index = this.children.indexOf(actorAfter, true);
        if (index == this.children.size || index == -1) {
            this.children.add(actor);
        } else {
            this.children.insert(index + 1, actor);
        }
        actor.setParent(this);
        actor.setStage(getStage());
        childrenChanged();
    }

    public boolean removeActor(Actor actor) {
        return removeActor(actor, true);
    }

    public boolean removeActor(Actor actor, boolean unfocus) {
        int index = this.children.indexOf(actor, true);
        if (index == -1) {
            return false;
        }
        removeActorAt(index, unfocus);
        return true;
    }

    public Actor removeActorAt(int index, boolean unfocus) {
        Stage stage;
        Actor actor = this.children.removeIndex(index);
        if (unfocus && (stage = getStage()) != null) {
            stage.unfocus(actor);
        }
        actor.setParent(null);
        actor.setStage(null);
        childrenChanged();
        return actor;
    }

    public void clearChildren() {
        clearChildren(true);
    }

    public void clearChildren(boolean unfocus) {
        Stage stage;
        Actor[] actors = this.children.begin();
        int n = this.children.size;
        for (int i = 0; i < n; i++) {
            Actor child = actors[i];
            if (unfocus && (stage = getStage()) != null) {
                stage.unfocus(child);
            }
            child.setStage(null);
            child.setParent(null);
        }
        this.children.end();
        this.children.clear();
        childrenChanged();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void clear() {
        super.clear();
        clearChildren(true);
    }

    public void clear(boolean unfocus) {
        super.clear();
        clearChildren(unfocus);
    }

    public <T extends Actor> T findActor(String name) {
        T t;
        Array<Actor> children = this.children;
        int n = children.size;
        for (int i = 0; i < n; i++) {
            if (name.equals(children.get(i).getName())) {
                return (T) children.get(i);
            }
        }
        int n2 = children.size;
        for (int i2 = 0; i2 < n2; i2++) {
            Actor child = children.get(i2);
            if ((child instanceof Group) && (t = (T) ((Group) child).findActor(name)) != null) {
                return t;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void setStage(Stage stage) {
        super.setStage(stage);
        Actor[] childrenArray = this.children.items;
        int n = this.children.size;
        for (int i = 0; i < n; i++) {
            childrenArray[i].setStage(stage);
        }
    }

    public boolean swapActor(int first, int second) {
        int maxIndex = this.children.size;
        if (first < 0 || first >= maxIndex || second < 0 || second >= maxIndex) {
            return false;
        }
        this.children.swap(first, second);
        return true;
    }

    public boolean swapActor(Actor first, Actor second) {
        int firstIndex = this.children.indexOf(first, true);
        int secondIndex = this.children.indexOf(second, true);
        if (firstIndex == -1 || secondIndex == -1) {
            return false;
        }
        this.children.swap(firstIndex, secondIndex);
        return true;
    }

    public Actor getChild(int index) {
        return this.children.get(index);
    }

    public SnapshotArray<Actor> getChildren() {
        return this.children;
    }

    public boolean hasChildren() {
        return this.children.size > 0;
    }

    public void setTransform(boolean transform) {
        this.transform = transform;
    }

    public boolean isTransform() {
        return this.transform;
    }

    public Vector2 localToDescendantCoordinates(Actor descendant, Vector2 localCoords) {
        Group parent = descendant.parent;
        if (parent == null) {
            throw new IllegalArgumentException("Child is not a descendant: " + descendant);
        }
        if (parent != this) {
            localToDescendantCoordinates(parent, localCoords);
        }
        descendant.parentToLocalCoordinates(localCoords);
        return localCoords;
    }

    public void setDebug(boolean enabled, boolean recursively) {
        setDebug(enabled);
        if (recursively) {
            Array.ArrayIterator<Actor> it = this.children.iterator();
            while (it.hasNext()) {
                Actor child = it.next();
                if (child instanceof Group) {
                    ((Group) child).setDebug(enabled, recursively);
                } else {
                    child.setDebug(enabled);
                }
            }
        }
    }

    public Group debugAll() {
        setDebug(true, true);
        return this;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public String toString() {
        StringBuilder buffer = new StringBuilder(128);
        toString(buffer, 1);
        buffer.setLength(buffer.length() - 1);
        return buffer.toString();
    }

    void toString(StringBuilder buffer, int indent) {
        buffer.append(super.toString());
        buffer.append('\n');
        Actor[] actors = this.children.begin();
        int n = this.children.size;
        for (int i = 0; i < n; i++) {
            for (int ii = 0; ii < indent; ii++) {
                buffer.append("|  ");
            }
            Actor actor = actors[i];
            if (actor instanceof Group) {
                ((Group) actor).toString(buffer, indent + 1);
            } else {
                buffer.append(actor);
                buffer.append('\n');
            }
        }
        this.children.end();
    }
}