package com.badlogic.gdx;

import com.badlogic.gdx.utils.IntArray;
import com.badlogic.gdx.utils.NumberUtils;

/* loaded from: classes.dex */
public class InputEventQueue {
    private static final int KEY_DOWN = 0;
    private static final int KEY_TYPED = 2;
    private static final int KEY_UP = 1;
    private static final int MOUSE_MOVED = 6;
    private static final int SCROLLED = 7;
    private static final int SKIP = -1;
    private static final int TOUCH_DOWN = 3;
    private static final int TOUCH_DRAGGED = 5;
    private static final int TOUCH_UP = 4;
    private long currentEventTime;
    private final IntArray queue = new IntArray();
    private final IntArray processingQueue = new IntArray();

    public void drain(InputProcessor processor) {
        synchronized (this) {
            if (processor == null) {
                this.queue.clear();
                return;
            }
            this.processingQueue.addAll(this.queue);
            this.queue.clear();
            int[] q = this.processingQueue.items;
            int type = 0;
            int n = this.processingQueue.size;
            while (type < n) {
                int i = type + 1;
                int type2 = q[type];
                int i2 = i + 1;
                int i3 = i2 + 1;
                this.currentEventTime = (q[i] << 32) | (q[i2] & 4294967295L);
                switch (type2) {
                    case -1:
                        type = i3 + q[i3];
                        break;
                    case 0:
                        processor.keyDown(q[i3]);
                        type = i3 + 1;
                        break;
                    case 1:
                        processor.keyUp(q[i3]);
                        type = i3 + 1;
                        break;
                    case 2:
                        processor.keyTyped((char) q[i3]);
                        type = i3 + 1;
                        break;
                    case 3:
                        int i4 = i3 + 1;
                        int i5 = i4 + 1;
                        int i6 = i5 + 1;
                        processor.touchDown(q[i3], q[i4], q[i5], q[i6]);
                        type = i6 + 1;
                        break;
                    case 4:
                        int i7 = i3 + 1;
                        int i8 = i7 + 1;
                        int i9 = i8 + 1;
                        processor.touchUp(q[i3], q[i7], q[i8], q[i9]);
                        type = i9 + 1;
                        break;
                    case 5:
                        int i10 = i3 + 1;
                        int i11 = i10 + 1;
                        processor.touchDragged(q[i3], q[i10], q[i11]);
                        type = i11 + 1;
                        break;
                    case 6:
                        int i12 = i3 + 1;
                        processor.mouseMoved(q[i3], q[i12]);
                        type = i12 + 1;
                        break;
                    case 7:
                        int i13 = i3 + 1;
                        processor.scrolled(NumberUtils.intBitsToFloat(q[i3]), NumberUtils.intBitsToFloat(q[i13]));
                        type = i13 + 1;
                        break;
                    default:
                        throw new RuntimeException();
                }
            }
            this.processingQueue.clear();
        }
    }

    private synchronized int next(int nextType, int i) {
        int[] q = this.queue.items;
        int n = this.queue.size;
        while (i < n) {
            int type = q[i];
            if (type == nextType) {
                return i;
            }
            int i2 = i + 3;
            switch (type) {
                case -1:
                    i = i2 + q[i2];
                    break;
                case 0:
                    i = i2 + 1;
                    break;
                case 1:
                    i = i2 + 1;
                    break;
                case 2:
                    i = i2 + 1;
                    break;
                case 3:
                    i = i2 + 4;
                    break;
                case 4:
                    i = i2 + 4;
                    break;
                case 5:
                    i = i2 + 3;
                    break;
                case 6:
                    i = i2 + 2;
                    break;
                case 7:
                    i = i2 + 2;
                    break;
                default:
                    throw new RuntimeException();
            }
        }
        return -1;
    }

    private void queueTime(long time) {
        this.queue.add((int) (time >> 32));
        this.queue.add((int) time);
    }

    public synchronized boolean keyDown(int keycode, long time) {
        this.queue.add(0);
        queueTime(time);
        this.queue.add(keycode);
        return false;
    }

    public synchronized boolean keyUp(int keycode, long time) {
        this.queue.add(1);
        queueTime(time);
        this.queue.add(keycode);
        return false;
    }

    public synchronized boolean keyTyped(char character, long time) {
        this.queue.add(2);
        queueTime(time);
        this.queue.add(character);
        return false;
    }

    public synchronized boolean touchDown(int screenX, int screenY, int pointer, int button, long time) {
        this.queue.add(3);
        queueTime(time);
        this.queue.add(screenX);
        this.queue.add(screenY);
        this.queue.add(pointer);
        this.queue.add(button);
        return false;
    }

    public synchronized boolean touchUp(int screenX, int screenY, int pointer, int button, long time) {
        this.queue.add(4);
        queueTime(time);
        this.queue.add(screenX);
        this.queue.add(screenY);
        this.queue.add(pointer);
        this.queue.add(button);
        return false;
    }

    public synchronized boolean touchDragged(int screenX, int screenY, int pointer, long time) {
        int i = next(5, 0);
        while (i >= 0) {
            if (this.queue.get(i + 5) == pointer) {
                this.queue.set(i, -1);
                this.queue.set(i + 3, 3);
            }
            i = next(5, i + 6);
        }
        this.queue.add(5);
        queueTime(time);
        this.queue.add(screenX);
        this.queue.add(screenY);
        this.queue.add(pointer);
        return false;
    }

    public synchronized boolean mouseMoved(int screenX, int screenY, long time) {
        int i = next(6, 0);
        while (i >= 0) {
            this.queue.set(i, -1);
            this.queue.set(i + 3, 2);
            i = next(6, i + 5);
        }
        this.queue.add(6);
        queueTime(time);
        this.queue.add(screenX);
        this.queue.add(screenY);
        return false;
    }

    public synchronized boolean scrolled(float amountX, float amountY, long time) {
        this.queue.add(7);
        queueTime(time);
        this.queue.add(NumberUtils.floatToIntBits(amountX));
        this.queue.add(NumberUtils.floatToIntBits(amountY));
        return false;
    }

    public long getCurrentEventTime() {
        return this.currentEventTime;
    }
}