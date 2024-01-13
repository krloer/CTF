package com.badlogic.gdx.scenes.scene2d;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.glutils.ShapeRenderer;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.utils.ScissorStack;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.DelayedRemovalArray;
import com.badlogic.gdx.utils.Pools;
import com.badlogic.gdx.utils.reflect.ClassReflection;
import kotlin.jvm.internal.IntCompanionObject;

/* loaded from: classes.dex */
public class Actor {
    private boolean debug;
    float height;
    private String name;
    float originX;
    float originY;
    Group parent;
    float rotation;
    private Stage stage;
    private Object userObject;
    float width;
    float x;
    float y;
    private final DelayedRemovalArray<EventListener> listeners = new DelayedRemovalArray<>(0);
    private final DelayedRemovalArray<EventListener> captureListeners = new DelayedRemovalArray<>(0);
    private final Array<Action> actions = new Array<>(0);
    private Touchable touchable = Touchable.enabled;
    private boolean visible = true;
    float scaleX = 1.0f;
    float scaleY = 1.0f;
    final Color color = new Color(1.0f, 1.0f, 1.0f, 1.0f);

    public void draw(Batch batch, float parentAlpha) {
    }

    public void act(float delta) {
        Array<Action> actions = this.actions;
        if (actions.size == 0) {
            return;
        }
        Stage stage = this.stage;
        if (stage != null && stage.getActionsRequestRendering()) {
            Gdx.graphics.requestRendering();
        }
        int i = 0;
        while (i < actions.size) {
            try {
                Action action = actions.get(i);
                if (action.act(delta) && i < actions.size) {
                    Action current = actions.get(i);
                    int actionIndex = current == action ? i : actions.indexOf(action, true);
                    if (actionIndex != -1) {
                        actions.removeIndex(actionIndex);
                        action.setActor(null);
                        i--;
                    }
                }
                i++;
            } catch (RuntimeException ex) {
                String context = toString();
                throw new RuntimeException("Actor: " + context.substring(0, Math.min(context.length(), 128)), ex);
            }
        }
    }

    public boolean fire(Event event) {
        if (event.getStage() == null) {
            event.setStage(getStage());
        }
        event.setTarget(this);
        Array<Group> ascendants = (Array) Pools.obtain(Array.class);
        for (Group parent = this.parent; parent != null; parent = parent.parent) {
            ascendants.add(parent);
        }
        try {
            Object[] ascendantsArray = ascendants.items;
            for (int i = ascendants.size - 1; i >= 0; i--) {
                Group currentTarget = (Group) ascendantsArray[i];
                currentTarget.notify(event, true);
                if (event.isStopped()) {
                    return event.isCancelled();
                }
            }
            notify(event, true);
            if (event.isStopped()) {
                return event.isCancelled();
            }
            notify(event, false);
            if (event.getBubbles()) {
                if (event.isStopped()) {
                    return event.isCancelled();
                }
                int n = ascendants.size;
                for (int i2 = 0; i2 < n; i2++) {
                    ((Group) ascendantsArray[i2]).notify(event, false);
                    if (event.isStopped()) {
                        return event.isCancelled();
                    }
                }
                return event.isCancelled();
            }
            return event.isCancelled();
        } finally {
            ascendants.clear();
            Pools.free(ascendants);
        }
    }

    public boolean notify(Event event, boolean capture) {
        if (event.getTarget() == null) {
            throw new IllegalArgumentException("The event target cannot be null.");
        }
        DelayedRemovalArray<EventListener> listeners = capture ? this.captureListeners : this.listeners;
        if (listeners.size == 0) {
            return event.isCancelled();
        }
        event.setListenerActor(this);
        event.setCapture(capture);
        if (event.getStage() == null) {
            event.setStage(this.stage);
        }
        try {
            listeners.begin();
            int n = listeners.size;
            for (int i = 0; i < n; i++) {
                if (listeners.get(i).handle(event)) {
                    event.handle();
                }
            }
            listeners.end();
            return event.isCancelled();
        } catch (RuntimeException ex) {
            String context = toString();
            throw new RuntimeException("Actor: " + context.substring(0, Math.min(context.length(), 128)), ex);
        }
    }

    public Actor hit(float x, float y, boolean touchable) {
        if ((!touchable || this.touchable == Touchable.enabled) && isVisible() && x >= 0.0f && x < this.width && y >= 0.0f && y < this.height) {
            return this;
        }
        return null;
    }

    public boolean remove() {
        Group group = this.parent;
        if (group != null) {
            return group.removeActor(this, true);
        }
        return false;
    }

    public boolean addListener(EventListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener cannot be null.");
        }
        if (!this.listeners.contains(listener, true)) {
            this.listeners.add(listener);
            return true;
        }
        return false;
    }

    public boolean removeListener(EventListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener cannot be null.");
        }
        return this.listeners.removeValue(listener, true);
    }

    public DelayedRemovalArray<EventListener> getListeners() {
        return this.listeners;
    }

    public boolean addCaptureListener(EventListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener cannot be null.");
        }
        if (!this.captureListeners.contains(listener, true)) {
            this.captureListeners.add(listener);
        }
        return true;
    }

    public boolean removeCaptureListener(EventListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener cannot be null.");
        }
        return this.captureListeners.removeValue(listener, true);
    }

    public DelayedRemovalArray<EventListener> getCaptureListeners() {
        return this.captureListeners;
    }

    public void addAction(Action action) {
        action.setActor(this);
        this.actions.add(action);
        Stage stage = this.stage;
        if (stage == null || !stage.getActionsRequestRendering()) {
            return;
        }
        Gdx.graphics.requestRendering();
    }

    public void removeAction(Action action) {
        if (action == null || !this.actions.removeValue(action, true)) {
            return;
        }
        action.setActor(null);
    }

    public Array<Action> getActions() {
        return this.actions;
    }

    public boolean hasActions() {
        return this.actions.size > 0;
    }

    public void clearActions() {
        for (int i = this.actions.size - 1; i >= 0; i--) {
            this.actions.get(i).setActor(null);
        }
        this.actions.clear();
    }

    public void clearListeners() {
        this.listeners.clear();
        this.captureListeners.clear();
    }

    public void clear() {
        clearActions();
        clearListeners();
    }

    public Stage getStage() {
        return this.stage;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void setStage(Stage stage) {
        this.stage = stage;
    }

    public boolean isDescendantOf(Actor actor) {
        if (actor == null) {
            throw new IllegalArgumentException("actor cannot be null.");
        }
        Actor parent = this;
        while (parent != actor) {
            parent = parent.parent;
            if (parent == null) {
                return false;
            }
        }
        return true;
    }

    public boolean isAscendantOf(Actor actor) {
        if (actor == null) {
            throw new IllegalArgumentException("actor cannot be null.");
        }
        while (actor != this) {
            actor = actor.parent;
            if (actor == null) {
                return false;
            }
        }
        return true;
    }

    public <T extends Actor> T firstAscendant(Class<T> type) {
        if (type == null) {
            throw new IllegalArgumentException("actor cannot be null.");
        }
        Actor actor = (T) this;
        while (!ClassReflection.isInstance(type, actor)) {
            actor = (T) actor.parent;
            if (actor == null) {
                return null;
            }
        }
        return (T) actor;
    }

    public boolean hasParent() {
        return this.parent != null;
    }

    public Group getParent() {
        return this.parent;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void setParent(Group parent) {
        this.parent = parent;
    }

    public boolean isTouchable() {
        return this.touchable == Touchable.enabled;
    }

    public Touchable getTouchable() {
        return this.touchable;
    }

    public void setTouchable(Touchable touchable) {
        this.touchable = touchable;
    }

    public boolean isVisible() {
        return this.visible;
    }

    public void setVisible(boolean visible) {
        this.visible = visible;
    }

    public boolean ascendantsVisible() {
        Actor actor = this;
        while (actor.isVisible()) {
            actor = actor.parent;
            if (actor == null) {
                return true;
            }
        }
        return false;
    }

    @Deprecated
    public boolean ancestorsVisible() {
        return ascendantsVisible();
    }

    public boolean hasKeyboardFocus() {
        Stage stage = getStage();
        return stage != null && stage.getKeyboardFocus() == this;
    }

    public boolean hasScrollFocus() {
        Stage stage = getStage();
        return stage != null && stage.getScrollFocus() == this;
    }

    public boolean isTouchFocusTarget() {
        Stage stage = getStage();
        if (stage == null) {
            return false;
        }
        int n = stage.touchFocuses.size;
        for (int i = 0; i < n; i++) {
            if (stage.touchFocuses.get(i).target == this) {
                return true;
            }
        }
        return false;
    }

    public boolean isTouchFocusListener() {
        Stage stage = getStage();
        if (stage == null) {
            return false;
        }
        int n = stage.touchFocuses.size;
        for (int i = 0; i < n; i++) {
            if (stage.touchFocuses.get(i).listenerActor == this) {
                return true;
            }
        }
        return false;
    }

    public Object getUserObject() {
        return this.userObject;
    }

    public void setUserObject(Object userObject) {
        this.userObject = userObject;
    }

    public float getX() {
        return this.x;
    }

    public float getX(int alignment) {
        float x = this.x;
        if ((alignment & 16) != 0) {
            return x + this.width;
        }
        if ((alignment & 8) == 0) {
            return x + (this.width / 2.0f);
        }
        return x;
    }

    public void setX(float x) {
        if (this.x != x) {
            this.x = x;
            positionChanged();
        }
    }

    public void setX(float x, int alignment) {
        if ((alignment & 16) != 0) {
            x -= this.width;
        } else if ((alignment & 8) == 0) {
            x -= this.width / 2.0f;
        }
        if (this.x != x) {
            this.x = x;
            positionChanged();
        }
    }

    public float getY() {
        return this.y;
    }

    public void setY(float y) {
        if (this.y != y) {
            this.y = y;
            positionChanged();
        }
    }

    public void setY(float y, int alignment) {
        if ((alignment & 2) != 0) {
            y -= this.height;
        } else if ((alignment & 4) == 0) {
            y -= this.height / 2.0f;
        }
        if (this.y != y) {
            this.y = y;
            positionChanged();
        }
    }

    public float getY(int alignment) {
        float y = this.y;
        if ((alignment & 2) != 0) {
            return y + this.height;
        }
        if ((alignment & 4) == 0) {
            return y + (this.height / 2.0f);
        }
        return y;
    }

    public void setPosition(float x, float y) {
        if (this.x != x || this.y != y) {
            this.x = x;
            this.y = y;
            positionChanged();
        }
    }

    public void setPosition(float x, float y, int alignment) {
        if ((alignment & 16) != 0) {
            x -= this.width;
        } else if ((alignment & 8) == 0) {
            x -= this.width / 2.0f;
        }
        if ((alignment & 2) != 0) {
            y -= this.height;
        } else if ((alignment & 4) == 0) {
            y -= this.height / 2.0f;
        }
        if (this.x != x || this.y != y) {
            this.x = x;
            this.y = y;
            positionChanged();
        }
    }

    public void moveBy(float x, float y) {
        if (x != 0.0f || y != 0.0f) {
            this.x += x;
            this.y += y;
            positionChanged();
        }
    }

    public float getWidth() {
        return this.width;
    }

    public void setWidth(float width) {
        if (this.width != width) {
            this.width = width;
            sizeChanged();
        }
    }

    public float getHeight() {
        return this.height;
    }

    public void setHeight(float height) {
        if (this.height != height) {
            this.height = height;
            sizeChanged();
        }
    }

    public float getTop() {
        return this.y + this.height;
    }

    public float getRight() {
        return this.x + this.width;
    }

    protected void positionChanged() {
    }

    protected void sizeChanged() {
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void scaleChanged() {
    }

    protected void rotationChanged() {
    }

    public void setSize(float width, float height) {
        if (this.width != width || this.height != height) {
            this.width = width;
            this.height = height;
            sizeChanged();
        }
    }

    public void sizeBy(float size) {
        if (size != 0.0f) {
            this.width += size;
            this.height += size;
            sizeChanged();
        }
    }

    public void sizeBy(float width, float height) {
        if (width != 0.0f || height != 0.0f) {
            this.width += width;
            this.height += height;
            sizeChanged();
        }
    }

    public void setBounds(float x, float y, float width, float height) {
        if (this.x != x || this.y != y) {
            this.x = x;
            this.y = y;
            positionChanged();
        }
        if (this.width != width || this.height != height) {
            this.width = width;
            this.height = height;
            sizeChanged();
        }
    }

    public float getOriginX() {
        return this.originX;
    }

    public void setOriginX(float originX) {
        this.originX = originX;
    }

    public float getOriginY() {
        return this.originY;
    }

    public void setOriginY(float originY) {
        this.originY = originY;
    }

    public void setOrigin(float originX, float originY) {
        this.originX = originX;
        this.originY = originY;
    }

    public void setOrigin(int alignment) {
        if ((alignment & 8) != 0) {
            this.originX = 0.0f;
        } else if ((alignment & 16) != 0) {
            this.originX = this.width;
        } else {
            this.originX = this.width / 2.0f;
        }
        if ((alignment & 4) != 0) {
            this.originY = 0.0f;
        } else if ((alignment & 2) != 0) {
            this.originY = this.height;
        } else {
            this.originY = this.height / 2.0f;
        }
    }

    public float getScaleX() {
        return this.scaleX;
    }

    public void setScaleX(float scaleX) {
        if (this.scaleX != scaleX) {
            this.scaleX = scaleX;
            scaleChanged();
        }
    }

    public float getScaleY() {
        return this.scaleY;
    }

    public void setScaleY(float scaleY) {
        if (this.scaleY != scaleY) {
            this.scaleY = scaleY;
            scaleChanged();
        }
    }

    public void setScale(float scaleXY) {
        if (this.scaleX != scaleXY || this.scaleY != scaleXY) {
            this.scaleX = scaleXY;
            this.scaleY = scaleXY;
            scaleChanged();
        }
    }

    public void setScale(float scaleX, float scaleY) {
        if (this.scaleX != scaleX || this.scaleY != scaleY) {
            this.scaleX = scaleX;
            this.scaleY = scaleY;
            scaleChanged();
        }
    }

    public void scaleBy(float scale) {
        if (scale != 0.0f) {
            this.scaleX += scale;
            this.scaleY += scale;
            scaleChanged();
        }
    }

    public void scaleBy(float scaleX, float scaleY) {
        if (scaleX != 0.0f || scaleY != 0.0f) {
            this.scaleX += scaleX;
            this.scaleY += scaleY;
            scaleChanged();
        }
    }

    public float getRotation() {
        return this.rotation;
    }

    public void setRotation(float degrees) {
        if (this.rotation != degrees) {
            this.rotation = degrees;
            rotationChanged();
        }
    }

    public void rotateBy(float amountInDegrees) {
        if (amountInDegrees != 0.0f) {
            this.rotation = (this.rotation + amountInDegrees) % 360.0f;
            rotationChanged();
        }
    }

    public void setColor(Color color) {
        this.color.set(color);
    }

    public void setColor(float r, float g, float b, float a) {
        this.color.set(r, g, b, a);
    }

    public Color getColor() {
        return this.color;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void toFront() {
        setZIndex(IntCompanionObject.MAX_VALUE);
    }

    public void toBack() {
        setZIndex(0);
    }

    public boolean setZIndex(int index) {
        if (index < 0) {
            throw new IllegalArgumentException("ZIndex cannot be < 0.");
        }
        Group parent = this.parent;
        if (parent == null) {
            return false;
        }
        Array<Actor> children = parent.children;
        if (children.size == 1) {
            return false;
        }
        int index2 = Math.min(index, children.size - 1);
        if (children.get(index2) == this || !children.removeValue(this, true)) {
            return false;
        }
        children.insert(index2, this);
        return true;
    }

    public int getZIndex() {
        Group parent = this.parent;
        if (parent == null) {
            return -1;
        }
        return parent.children.indexOf(this, true);
    }

    public boolean clipBegin() {
        return clipBegin(this.x, this.y, this.width, this.height);
    }

    public boolean clipBegin(float x, float y, float width, float height) {
        Stage stage;
        if (width <= 0.0f || height <= 0.0f || (stage = this.stage) == null) {
            return false;
        }
        Rectangle tableBounds = Rectangle.tmp;
        tableBounds.x = x;
        tableBounds.y = y;
        tableBounds.width = width;
        tableBounds.height = height;
        Rectangle scissorBounds = (Rectangle) Pools.obtain(Rectangle.class);
        stage.calculateScissors(tableBounds, scissorBounds);
        if (ScissorStack.pushScissors(scissorBounds)) {
            return true;
        }
        Pools.free(scissorBounds);
        return false;
    }

    public void clipEnd() {
        Pools.free(ScissorStack.popScissors());
    }

    public Vector2 screenToLocalCoordinates(Vector2 screenCoords) {
        Stage stage = this.stage;
        return stage == null ? screenCoords : stageToLocalCoordinates(stage.screenToStageCoordinates(screenCoords));
    }

    public Vector2 stageToLocalCoordinates(Vector2 stageCoords) {
        Group group = this.parent;
        if (group != null) {
            group.stageToLocalCoordinates(stageCoords);
        }
        parentToLocalCoordinates(stageCoords);
        return stageCoords;
    }

    public Vector2 parentToLocalCoordinates(Vector2 parentCoords) {
        float rotation = this.rotation;
        float scaleX = this.scaleX;
        float scaleY = this.scaleY;
        float childX = this.x;
        float childY = this.y;
        if (rotation == 0.0f) {
            if (scaleX == 1.0f && scaleY == 1.0f) {
                parentCoords.x -= childX;
                parentCoords.y -= childY;
            } else {
                float originX = this.originX;
                float originY = this.originY;
                parentCoords.x = (((parentCoords.x - childX) - originX) / scaleX) + originX;
                parentCoords.y = (((parentCoords.y - childY) - originY) / scaleY) + originY;
            }
        } else {
            float cos = (float) Math.cos(rotation * 0.017453292f);
            float sin = (float) Math.sin(0.017453292f * rotation);
            float originX2 = this.originX;
            float originY2 = this.originY;
            float tox = (parentCoords.x - childX) - originX2;
            float toy = (parentCoords.y - childY) - originY2;
            parentCoords.x = (((tox * cos) + (toy * sin)) / scaleX) + originX2;
            parentCoords.y = ((((-sin) * tox) + (toy * cos)) / scaleY) + originY2;
        }
        return parentCoords;
    }

    public Vector2 localToScreenCoordinates(Vector2 localCoords) {
        Stage stage = this.stage;
        return stage == null ? localCoords : stage.stageToScreenCoordinates(localToAscendantCoordinates(null, localCoords));
    }

    public Vector2 localToStageCoordinates(Vector2 localCoords) {
        return localToAscendantCoordinates(null, localCoords);
    }

    public Vector2 localToParentCoordinates(Vector2 localCoords) {
        float rotation = -this.rotation;
        float scaleX = this.scaleX;
        float scaleY = this.scaleY;
        float x = this.x;
        float y = this.y;
        if (rotation == 0.0f) {
            if (scaleX == 1.0f && scaleY == 1.0f) {
                localCoords.x += x;
                localCoords.y += y;
            } else {
                float originX = this.originX;
                float originY = this.originY;
                localCoords.x = ((localCoords.x - originX) * scaleX) + originX + x;
                localCoords.y = ((localCoords.y - originY) * scaleY) + originY + y;
            }
        } else {
            float cos = (float) Math.cos(rotation * 0.017453292f);
            float sin = (float) Math.sin(0.017453292f * rotation);
            float originX2 = this.originX;
            float originY2 = this.originY;
            float tox = (localCoords.x - originX2) * scaleX;
            float toy = (localCoords.y - originY2) * scaleY;
            localCoords.x = (tox * cos) + (toy * sin) + originX2 + x;
            localCoords.y = ((-sin) * tox) + (toy * cos) + originY2 + y;
        }
        return localCoords;
    }

    public Vector2 localToAscendantCoordinates(Actor ascendant, Vector2 localCoords) {
        Actor actor = this;
        do {
            actor.localToParentCoordinates(localCoords);
            actor = actor.parent;
            if (actor != ascendant) {
                break;
                break;
            }
            break;
        } while (actor != null);
        return localCoords;
    }

    public Vector2 localToActorCoordinates(Actor actor, Vector2 localCoords) {
        localToStageCoordinates(localCoords);
        return actor.stageToLocalCoordinates(localCoords);
    }

    public void drawDebug(ShapeRenderer shapes) {
        drawDebugBounds(shapes);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void drawDebugBounds(ShapeRenderer shapes) {
        if (this.debug) {
            shapes.set(ShapeRenderer.ShapeType.Line);
            Stage stage = this.stage;
            if (stage != null) {
                shapes.setColor(stage.getDebugColor());
            }
            shapes.rect(this.x, this.y, this.originX, this.originY, this.width, this.height, this.scaleX, this.scaleY, this.rotation);
        }
    }

    public void setDebug(boolean enabled) {
        this.debug = enabled;
        if (enabled) {
            Stage.debug = true;
        }
    }

    public boolean getDebug() {
        return this.debug;
    }

    public Actor debug() {
        setDebug(true);
        return this;
    }

    public String toString() {
        String name = this.name;
        if (name == null) {
            String name2 = getClass().getName();
            int dotIndex = name2.lastIndexOf(46);
            return dotIndex != -1 ? name2.substring(dotIndex + 1) : name2;
        }
        return name;
    }
}