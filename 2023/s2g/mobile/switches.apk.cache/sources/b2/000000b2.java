package com.badlogic.gdx.backends.android;

import android.content.Context;
import android.view.MotionEvent;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.backends.android.DefaultAndroidInput;

/* loaded from: classes.dex */
public class AndroidTouchHandler {
    public void onTouch(MotionEvent event, DefaultAndroidInput input) {
        int button;
        int y;
        int realPointerIndex;
        int x;
        int button2;
        int button3;
        int y2;
        int realPointerIndex2;
        int x2;
        int pointerCount;
        int y3;
        int realPointerIndex3;
        int button4;
        int x3;
        int pointerIndex;
        int x4;
        int action = event.getAction() & 255;
        int pointerIndex2 = (event.getAction() & 65280) >> 8;
        int pointerId = event.getPointerId(pointerIndex2);
        long timeStamp = System.nanoTime();
        synchronized (input) {
            int i = 20;
            int i2 = -1;
            try {
                switch (action) {
                    case 0:
                    case 5:
                        int realPointerIndex4 = input.getFreePointerIndex();
                        if (realPointerIndex4 < 20) {
                            try {
                                input.realId[realPointerIndex4] = pointerId;
                                int x5 = (int) event.getX(pointerIndex2);
                                try {
                                    int y4 = (int) event.getY(pointerIndex2);
                                    try {
                                        int button5 = toGdxButton(event.getButtonState());
                                        if (button5 != -1) {
                                            button = button5;
                                            y = y4;
                                            realPointerIndex = realPointerIndex4;
                                            x = x5;
                                            try {
                                                postTouchEvent(input, 0, x5, y4, realPointerIndex4, button, timeStamp);
                                            } catch (Throwable th) {
                                                th = th;
                                                throw th;
                                            }
                                        } else {
                                            button = button5;
                                            y = y4;
                                            realPointerIndex = realPointerIndex4;
                                            x = x5;
                                        }
                                        try {
                                            input.touchX[realPointerIndex] = x;
                                            input.touchY[realPointerIndex] = y;
                                            input.deltaX[realPointerIndex] = 0;
                                            input.deltaY[realPointerIndex] = 0;
                                            button2 = button;
                                        } catch (Throwable th2) {
                                            th = th2;
                                        }
                                        try {
                                            input.touched[realPointerIndex] = button2 != -1;
                                            input.button[realPointerIndex] = button2;
                                            input.pressure[realPointerIndex] = event.getPressure(pointerIndex2);
                                        } catch (Throwable th3) {
                                            th = th3;
                                            throw th;
                                        }
                                    } catch (Throwable th4) {
                                        th = th4;
                                    }
                                } catch (Throwable th5) {
                                    th = th5;
                                }
                            } catch (Throwable th6) {
                                th = th6;
                            }
                        }
                        Gdx.app.getGraphics().requestRendering();
                        return;
                    case 1:
                    case 4:
                    case 6:
                        int realPointerIndex5 = input.lookUpPointerIndex(pointerId);
                        if (realPointerIndex5 != -1 && realPointerIndex5 < 20) {
                            try {
                                input.realId[realPointerIndex5] = -1;
                                int x6 = (int) event.getX(pointerIndex2);
                                try {
                                    int y5 = (int) event.getY(pointerIndex2);
                                    try {
                                        int button6 = input.button[realPointerIndex5];
                                        if (button6 != -1) {
                                            button3 = button6;
                                            y2 = y5;
                                            realPointerIndex2 = realPointerIndex5;
                                            x2 = x6;
                                            try {
                                                postTouchEvent(input, 1, x6, y5, realPointerIndex5, button3, timeStamp);
                                            } catch (Throwable th7) {
                                                th = th7;
                                                throw th;
                                            }
                                        } else {
                                            button3 = button6;
                                            y2 = y5;
                                            realPointerIndex2 = realPointerIndex5;
                                            x2 = x6;
                                        }
                                        input.touchX[realPointerIndex2] = x2;
                                        input.touchY[realPointerIndex2] = y2;
                                        input.deltaX[realPointerIndex2] = 0;
                                        input.deltaY[realPointerIndex2] = 0;
                                        input.touched[realPointerIndex2] = false;
                                        input.button[realPointerIndex2] = 0;
                                        input.pressure[realPointerIndex2] = 0.0f;
                                    } catch (Throwable th8) {
                                        th = th8;
                                    }
                                } catch (Throwable th9) {
                                    th = th9;
                                }
                            } catch (Throwable th10) {
                                th = th10;
                            }
                        }
                        Gdx.app.getGraphics().requestRendering();
                        return;
                    case 2:
                        int pointerCount2 = event.getPointerCount();
                        int y6 = 0;
                        int x7 = pointerIndex2;
                        int pointerIndex3 = 0;
                        int button7 = 0;
                        int button8 = 0;
                        int realPointerIndex6 = 0;
                        while (pointerIndex3 < pointerCount2) {
                            int pointerIndex4 = pointerIndex3;
                            try {
                                int pointerId2 = event.getPointerId(pointerIndex4);
                                int x8 = (int) event.getX(pointerIndex4);
                                try {
                                    int y7 = (int) event.getY(pointerIndex4);
                                    try {
                                        int realPointerIndex7 = input.lookUpPointerIndex(pointerId2);
                                        if (realPointerIndex7 == i2) {
                                            pointerCount = pointerCount2;
                                            y3 = y7;
                                            realPointerIndex3 = realPointerIndex7;
                                            x3 = x8;
                                            x4 = pointerIndex4;
                                        } else if (realPointerIndex7 >= i) {
                                            Gdx.app.getGraphics().requestRendering();
                                            return;
                                        } else {
                                            try {
                                                int button9 = input.button[realPointerIndex7];
                                                if (button9 != i2) {
                                                    y3 = y7;
                                                    realPointerIndex3 = realPointerIndex7;
                                                    button4 = button9;
                                                    x3 = x8;
                                                    pointerIndex = pointerIndex4;
                                                    pointerCount = pointerCount2;
                                                    try {
                                                        postTouchEvent(input, 2, x8, y3, realPointerIndex3, button4, timeStamp);
                                                    } catch (Throwable th11) {
                                                        th = th11;
                                                        throw th;
                                                    }
                                                } else {
                                                    pointerCount = pointerCount2;
                                                    y3 = y7;
                                                    realPointerIndex3 = realPointerIndex7;
                                                    button4 = button9;
                                                    x3 = x8;
                                                    pointerIndex = pointerIndex4;
                                                    try {
                                                        postTouchEvent(input, 4, x3, y3, realPointerIndex3, 0, timeStamp);
                                                    } catch (Throwable th12) {
                                                        th = th12;
                                                        throw th;
                                                    }
                                                }
                                                input.deltaX[realPointerIndex3] = x3 - input.touchX[realPointerIndex3];
                                                input.deltaY[realPointerIndex3] = y3 - input.touchY[realPointerIndex3];
                                                input.touchX[realPointerIndex3] = x3;
                                                input.touchY[realPointerIndex3] = y3;
                                                x4 = pointerIndex;
                                                try {
                                                    input.pressure[realPointerIndex3] = event.getPressure(x4);
                                                    button7 = button4;
                                                } catch (Throwable th13) {
                                                    th = th13;
                                                    throw th;
                                                }
                                            } catch (Throwable th14) {
                                                th = th14;
                                            }
                                        }
                                        pointerIndex3++;
                                        x7 = x4;
                                        button8 = realPointerIndex3;
                                        realPointerIndex6 = y3;
                                        y6 = x3;
                                        pointerCount2 = pointerCount;
                                        i = 20;
                                        i2 = -1;
                                    } catch (Throwable th15) {
                                        th = th15;
                                    }
                                } catch (Throwable th16) {
                                    th = th16;
                                }
                            } catch (Throwable th17) {
                                th = th17;
                            }
                        }
                        Gdx.app.getGraphics().requestRendering();
                        return;
                    case 3:
                        for (int i3 = 0; i3 < input.realId.length; i3++) {
                            input.realId[i3] = -1;
                            input.touchX[i3] = 0;
                            input.touchY[i3] = 0;
                            input.deltaX[i3] = 0;
                            input.deltaY[i3] = 0;
                            input.touched[i3] = false;
                            input.button[i3] = 0;
                            input.pressure[i3] = 0.0f;
                        }
                        Gdx.app.getGraphics().requestRendering();
                        return;
                    default:
                        Gdx.app.getGraphics().requestRendering();
                        return;
                }
            } catch (Throwable th18) {
                th = th18;
            }
        }
    }

    private void logAction(int action, int pointer) {
        String actionStr;
        if (action == 0) {
            actionStr = "DOWN";
        } else if (action == 5) {
            actionStr = "POINTER DOWN";
        } else if (action == 1) {
            actionStr = "UP";
        } else if (action == 6) {
            actionStr = "POINTER UP";
        } else if (action == 4) {
            actionStr = "OUTSIDE";
        } else if (action == 3) {
            actionStr = "CANCEL";
        } else if (action == 2) {
            actionStr = "MOVE";
        } else {
            actionStr = "UNKNOWN (" + action + ")";
        }
        Gdx.app.log("AndroidMultiTouchHandler", "action " + actionStr + ", Android pointer id: " + pointer);
    }

    private int toGdxButton(int button) {
        if (button == 0 || button == 1) {
            return 0;
        }
        if (button == 2) {
            return 1;
        }
        if (button == 4) {
            return 2;
        }
        if (button == 8) {
            return 3;
        }
        if (button == 16) {
            return 4;
        }
        return -1;
    }

    private void postTouchEvent(DefaultAndroidInput input, int type, int x, int y, int pointer, int button, long timeStamp) {
        DefaultAndroidInput.TouchEvent event = input.usedTouchEvents.obtain();
        event.timeStamp = timeStamp;
        event.pointer = pointer;
        event.x = x;
        event.y = y;
        event.type = type;
        event.button = button;
        input.touchEvents.add(event);
    }

    public boolean supportsMultitouch(Context activity) {
        return activity.getPackageManager().hasSystemFeature("android.hardware.touchscreen.multitouch");
    }
}