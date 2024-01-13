package com.badlogic.gdx.input;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.InputAdapter;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.utils.TimeUtils;
import com.badlogic.gdx.utils.Timer;

/* loaded from: classes.dex */
public class GestureDetector extends InputAdapter {
    private boolean inTapRectangle;
    private final Vector2 initialPointer1;
    private final Vector2 initialPointer2;
    private int lastTapButton;
    private int lastTapPointer;
    private long lastTapTime;
    private float lastTapX;
    private float lastTapY;
    final GestureListener listener;
    boolean longPressFired;
    private float longPressSeconds;
    private final Timer.Task longPressTask;
    private long maxFlingDelay;
    private boolean panning;
    private boolean pinching;
    Vector2 pointer1;
    private final Vector2 pointer2;
    private int tapCount;
    private long tapCountInterval;
    private float tapRectangleCenterX;
    private float tapRectangleCenterY;
    private float tapRectangleHeight;
    private float tapRectangleWidth;
    private long touchDownTime;
    private final VelocityTracker tracker;

    /* loaded from: classes.dex */
    public interface GestureListener {
        boolean fling(float f, float f2, int i);

        boolean longPress(float f, float f2);

        boolean pan(float f, float f2, float f3, float f4);

        boolean panStop(float f, float f2, int i, int i2);

        boolean pinch(Vector2 vector2, Vector2 vector22, Vector2 vector23, Vector2 vector24);

        void pinchStop();

        boolean tap(float f, float f2, int i, int i2);

        boolean touchDown(float f, float f2, int i, int i2);

        boolean zoom(float f, float f2);
    }

    public GestureDetector(GestureListener listener) {
        this(20.0f, 0.4f, 1.1f, 2.14748365E9f, listener);
    }

    public GestureDetector(float halfTapSquareSize, float tapCountInterval, float longPressDuration, float maxFlingDelay, GestureListener listener) {
        this(halfTapSquareSize, halfTapSquareSize, tapCountInterval, longPressDuration, maxFlingDelay, listener);
    }

    public GestureDetector(float halfTapRectangleWidth, float halfTapRectangleHeight, float tapCountInterval, float longPressDuration, float maxFlingDelay, GestureListener listener) {
        this.tracker = new VelocityTracker();
        this.pointer1 = new Vector2();
        this.pointer2 = new Vector2();
        this.initialPointer1 = new Vector2();
        this.initialPointer2 = new Vector2();
        this.longPressTask = new Timer.Task() { // from class: com.badlogic.gdx.input.GestureDetector.1
            @Override // com.badlogic.gdx.utils.Timer.Task, java.lang.Runnable
            public void run() {
                if (!GestureDetector.this.longPressFired) {
                    GestureDetector gestureDetector = GestureDetector.this;
                    gestureDetector.longPressFired = gestureDetector.listener.longPress(GestureDetector.this.pointer1.x, GestureDetector.this.pointer1.y);
                }
            }
        };
        if (listener == null) {
            throw new IllegalArgumentException("listener cannot be null.");
        }
        this.tapRectangleWidth = halfTapRectangleWidth;
        this.tapRectangleHeight = halfTapRectangleHeight;
        this.tapCountInterval = tapCountInterval * 1.0E9f;
        this.longPressSeconds = longPressDuration;
        this.maxFlingDelay = 1.0E9f * maxFlingDelay;
        this.listener = listener;
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean touchDown(int x, int y, int pointer, int button) {
        return touchDown(x, y, pointer, button);
    }

    public boolean touchDown(float x, float y, int pointer, int button) {
        if (pointer > 1) {
            return false;
        }
        if (pointer == 0) {
            this.pointer1.set(x, y);
            this.touchDownTime = Gdx.input.getCurrentEventTime();
            this.tracker.start(x, y, this.touchDownTime);
            if (Gdx.input.isTouched(1)) {
                this.inTapRectangle = false;
                this.pinching = true;
                this.initialPointer1.set(this.pointer1);
                this.initialPointer2.set(this.pointer2);
                this.longPressTask.cancel();
            } else {
                this.inTapRectangle = true;
                this.pinching = false;
                this.longPressFired = false;
                this.tapRectangleCenterX = x;
                this.tapRectangleCenterY = y;
                if (!this.longPressTask.isScheduled()) {
                    Timer.schedule(this.longPressTask, this.longPressSeconds);
                }
            }
        } else {
            this.pointer2.set(x, y);
            this.inTapRectangle = false;
            this.pinching = true;
            this.initialPointer1.set(this.pointer1);
            this.initialPointer2.set(this.pointer2);
            this.longPressTask.cancel();
        }
        return this.listener.touchDown(x, y, pointer, button);
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean touchDragged(int x, int y, int pointer) {
        return touchDragged(x, y, pointer);
    }

    public boolean touchDragged(float x, float y, int pointer) {
        if (pointer <= 1 && !this.longPressFired) {
            if (pointer == 0) {
                this.pointer1.set(x, y);
            } else {
                this.pointer2.set(x, y);
            }
            if (this.pinching) {
                GestureListener gestureListener = this.listener;
                if (gestureListener != null) {
                    boolean result = gestureListener.pinch(this.initialPointer1, this.initialPointer2, this.pointer1, this.pointer2);
                    return this.listener.zoom(this.initialPointer1.dst(this.initialPointer2), this.pointer1.dst(this.pointer2)) || result;
                }
                return false;
            }
            this.tracker.update(x, y, Gdx.input.getCurrentEventTime());
            if (this.inTapRectangle && !isWithinTapRectangle(x, y, this.tapRectangleCenterX, this.tapRectangleCenterY)) {
                this.longPressTask.cancel();
                this.inTapRectangle = false;
            }
            if (this.inTapRectangle) {
                return false;
            }
            this.panning = true;
            return this.listener.pan(x, y, this.tracker.deltaX, this.tracker.deltaY);
        }
        return false;
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean touchUp(int x, int y, int pointer, int button) {
        return touchUp(x, y, pointer, button);
    }

    public boolean touchUp(float x, float y, int pointer, int button) {
        if (pointer > 1) {
            return false;
        }
        if (this.inTapRectangle && !isWithinTapRectangle(x, y, this.tapRectangleCenterX, this.tapRectangleCenterY)) {
            this.inTapRectangle = false;
        }
        boolean wasPanning = this.panning;
        this.panning = false;
        this.longPressTask.cancel();
        if (this.longPressFired) {
            return false;
        }
        if (this.inTapRectangle) {
            if (this.lastTapButton != button || this.lastTapPointer != pointer || TimeUtils.nanoTime() - this.lastTapTime > this.tapCountInterval || !isWithinTapRectangle(x, y, this.lastTapX, this.lastTapY)) {
                this.tapCount = 0;
            }
            this.tapCount++;
            this.lastTapTime = TimeUtils.nanoTime();
            this.lastTapX = x;
            this.lastTapY = y;
            this.lastTapButton = button;
            this.lastTapPointer = pointer;
            this.touchDownTime = 0L;
            return this.listener.tap(x, y, this.tapCount, button);
        } else if (this.pinching) {
            this.pinching = false;
            this.listener.pinchStop();
            this.panning = true;
            if (pointer == 0) {
                this.tracker.start(this.pointer2.x, this.pointer2.y, Gdx.input.getCurrentEventTime());
            } else {
                this.tracker.start(this.pointer1.x, this.pointer1.y, Gdx.input.getCurrentEventTime());
            }
            return false;
        } else {
            boolean handled = false;
            if (wasPanning && !this.panning) {
                handled = this.listener.panStop(x, y, pointer, button);
            }
            long time = Gdx.input.getCurrentEventTime();
            if (time - this.touchDownTime <= this.maxFlingDelay) {
                this.tracker.update(x, y, time);
                handled = this.listener.fling(this.tracker.getVelocityX(), this.tracker.getVelocityY(), button) || handled;
            }
            this.touchDownTime = 0L;
            return handled;
        }
    }

    public void cancel() {
        this.longPressTask.cancel();
        this.longPressFired = true;
    }

    public boolean isLongPressed() {
        return isLongPressed(this.longPressSeconds);
    }

    public boolean isLongPressed(float duration) {
        return this.touchDownTime != 0 && TimeUtils.nanoTime() - this.touchDownTime > ((long) (1.0E9f * duration));
    }

    public boolean isPanning() {
        return this.panning;
    }

    public void reset() {
        this.touchDownTime = 0L;
        this.panning = false;
        this.inTapRectangle = false;
        this.tracker.lastTime = 0L;
    }

    private boolean isWithinTapRectangle(float x, float y, float centerX, float centerY) {
        return Math.abs(x - centerX) < this.tapRectangleWidth && Math.abs(y - centerY) < this.tapRectangleHeight;
    }

    public void invalidateTapSquare() {
        this.inTapRectangle = false;
    }

    public void setTapSquareSize(float halfTapSquareSize) {
        setTapRectangleSize(halfTapSquareSize, halfTapSquareSize);
    }

    public void setTapRectangleSize(float halfTapRectangleWidth, float halfTapRectangleHeight) {
        this.tapRectangleWidth = halfTapRectangleWidth;
        this.tapRectangleHeight = halfTapRectangleHeight;
    }

    public void setTapCountInterval(float tapCountInterval) {
        this.tapCountInterval = 1.0E9f * tapCountInterval;
    }

    public void setLongPressSeconds(float longPressSeconds) {
        this.longPressSeconds = longPressSeconds;
    }

    public void setMaxFlingDelay(long maxFlingDelay) {
        this.maxFlingDelay = maxFlingDelay;
    }

    /* loaded from: classes.dex */
    public static class GestureAdapter implements GestureListener {
        @Override // com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean touchDown(float x, float y, int pointer, int button) {
            return false;
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean tap(float x, float y, int count, int button) {
            return false;
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean longPress(float x, float y) {
            return false;
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean fling(float velocityX, float velocityY, int button) {
            return false;
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean pan(float x, float y, float deltaX, float deltaY) {
            return false;
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean panStop(float x, float y, int pointer, int button) {
            return false;
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean zoom(float initialDistance, float distance) {
            return false;
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean pinch(Vector2 initialPointer1, Vector2 initialPointer2, Vector2 pointer1, Vector2 pointer2) {
            return false;
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureListener
        public void pinchStop() {
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class VelocityTracker {
        float deltaX;
        float deltaY;
        long lastTime;
        float lastX;
        float lastY;
        long[] meanTime;
        float[] meanX;
        float[] meanY;
        int numSamples;
        int sampleSize = 10;

        VelocityTracker() {
            int i = this.sampleSize;
            this.meanX = new float[i];
            this.meanY = new float[i];
            this.meanTime = new long[i];
        }

        public void start(float x, float y, long timeStamp) {
            this.lastX = x;
            this.lastY = y;
            this.deltaX = 0.0f;
            this.deltaY = 0.0f;
            this.numSamples = 0;
            for (int i = 0; i < this.sampleSize; i++) {
                this.meanX[i] = 0.0f;
                this.meanY[i] = 0.0f;
                this.meanTime[i] = 0;
            }
            this.lastTime = timeStamp;
        }

        public void update(float x, float y, long currTime) {
            this.deltaX = x - this.lastX;
            this.deltaY = y - this.lastY;
            this.lastX = x;
            this.lastY = y;
            long deltaTime = currTime - this.lastTime;
            this.lastTime = currTime;
            int i = this.numSamples;
            int index = i % this.sampleSize;
            this.meanX[index] = this.deltaX;
            this.meanY[index] = this.deltaY;
            this.meanTime[index] = deltaTime;
            this.numSamples = i + 1;
        }

        public float getVelocityX() {
            float meanX = getAverage(this.meanX, this.numSamples);
            float meanTime = ((float) getAverage(this.meanTime, this.numSamples)) / 1.0E9f;
            if (meanTime == 0.0f) {
                return 0.0f;
            }
            return meanX / meanTime;
        }

        public float getVelocityY() {
            float meanY = getAverage(this.meanY, this.numSamples);
            float meanTime = ((float) getAverage(this.meanTime, this.numSamples)) / 1.0E9f;
            if (meanTime == 0.0f) {
                return 0.0f;
            }
            return meanY / meanTime;
        }

        private float getAverage(float[] values, int numSamples) {
            int numSamples2 = Math.min(this.sampleSize, numSamples);
            float sum = 0.0f;
            for (int i = 0; i < numSamples2; i++) {
                sum += values[i];
            }
            return sum / numSamples2;
        }

        private long getAverage(long[] values, int numSamples) {
            int numSamples2 = Math.min(this.sampleSize, numSamples);
            long sum = 0;
            for (int i = 0; i < numSamples2; i++) {
                sum += values[i];
            }
            if (numSamples2 == 0) {
                return 0L;
            }
            return sum / numSamples2;
        }

        private float getSum(float[] values, int numSamples) {
            int numSamples2 = Math.min(this.sampleSize, numSamples);
            float sum = 0.0f;
            for (int i = 0; i < numSamples2; i++) {
                sum += values[i];
            }
            if (numSamples2 == 0) {
                return 0.0f;
            }
            return sum;
        }
    }
}