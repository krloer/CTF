package com.badlogic.gdx.backends.android;

import android.view.MotionEvent;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.backends.android.DefaultAndroidInput;

/* loaded from: classes.dex */
public class AndroidMouseHandler {
    private int deltaX = 0;
    private int deltaY = 0;

    public boolean onGenericMotion(MotionEvent event, DefaultAndroidInput input) {
        if ((event.getSource() & 2) == 0) {
            return false;
        }
        int action = event.getAction() & 255;
        long timeStamp = System.nanoTime();
        synchronized (input) {
            try {
                if (action == 7) {
                    int x = (int) event.getX();
                    int y = (int) event.getY();
                    if (x != this.deltaX || y != this.deltaY) {
                        postTouchEvent(input, 4, x, y, 0, 0, timeStamp);
                        this.deltaX = x;
                        this.deltaY = y;
                    }
                } else if (action == 8) {
                    int scrollAmountY = (int) (-Math.signum(event.getAxisValue(9)));
                    try {
                        int scrollAmountX = (int) (-Math.signum(event.getAxisValue(10)));
                        postTouchEvent(input, 3, 0, 0, scrollAmountX, scrollAmountY, timeStamp);
                    } catch (Throwable th) {
                        th = th;
                        throw th;
                    }
                }
                Gdx.app.getGraphics().requestRendering();
                return true;
            } catch (Throwable th2) {
                th = th2;
            }
        }
    }

    private void logAction(int action) {
        String actionStr;
        if (action == 9) {
            actionStr = "HOVER_ENTER";
        } else if (action == 7) {
            actionStr = "HOVER_MOVE";
        } else if (action == 10) {
            actionStr = "HOVER_EXIT";
        } else if (action == 8) {
            actionStr = "SCROLL";
        } else {
            actionStr = "UNKNOWN (" + action + ")";
        }
        Gdx.app.log("AndroidMouseHandler", "action " + actionStr);
    }

    private void postTouchEvent(DefaultAndroidInput input, int type, int x, int y, int scrollAmountX, int scrollAmountY, long timeStamp) {
        DefaultAndroidInput.TouchEvent event = input.usedTouchEvents.obtain();
        event.timeStamp = timeStamp;
        event.x = x;
        event.y = y;
        event.type = type;
        event.scrollAmountX = scrollAmountX;
        event.scrollAmountY = scrollAmountY;
        input.touchEvents.add(event);
    }
}