package com.badlogic.gdx.input;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.Input;
import com.badlogic.gdx.InputProcessor;
import com.badlogic.gdx.utils.GdxRuntimeException;
import java.net.InetAddress;
import java.net.ServerSocket;

/* loaded from: classes.dex */
public class RemoteInput implements Runnable, Input {
    public static int DEFAULT_PORT = 8190;
    private static final int MAX_TOUCHES = 20;
    private float[] accel;
    private float[] compass;
    private boolean connected;
    int[] deltaX;
    int[] deltaY;
    private float[] gyrate;
    public final String[] ips;
    boolean[] isTouched;
    boolean[] justPressedKeys;
    boolean justTouched;
    int keyCount;
    boolean keyJustPressed;
    boolean[] keys;
    private RemoteInputListener listener;
    private boolean multiTouch;
    private final int port;
    InputProcessor processor;
    private float remoteHeight;
    private float remoteWidth;
    private ServerSocket serverSocket;
    int[] touchX;
    int[] touchY;

    /* loaded from: classes.dex */
    public interface RemoteInputListener {
        void onConnected();

        void onDisconnected();
    }

    /* loaded from: classes.dex */
    class KeyEvent {
        static final int KEY_DOWN = 0;
        static final int KEY_TYPED = 2;
        static final int KEY_UP = 1;
        char keyChar;
        int keyCode;
        long timeStamp;
        int type;

        KeyEvent() {
        }
    }

    /* loaded from: classes.dex */
    class TouchEvent {
        static final int TOUCH_DOWN = 0;
        static final int TOUCH_DRAGGED = 2;
        static final int TOUCH_UP = 1;
        int pointer;
        long timeStamp;
        int type;
        int x;
        int y;

        TouchEvent() {
        }
    }

    /* loaded from: classes.dex */
    class EventTrigger implements Runnable {
        KeyEvent keyEvent;
        TouchEvent touchEvent;

        public EventTrigger(TouchEvent touchEvent, KeyEvent keyEvent) {
            this.touchEvent = touchEvent;
            this.keyEvent = keyEvent;
        }

        @Override // java.lang.Runnable
        public void run() {
            RemoteInput remoteInput = RemoteInput.this;
            remoteInput.justTouched = false;
            if (remoteInput.keyJustPressed) {
                RemoteInput.this.keyJustPressed = false;
                for (int i = 0; i < RemoteInput.this.justPressedKeys.length; i++) {
                    RemoteInput.this.justPressedKeys[i] = false;
                }
            }
            if (RemoteInput.this.processor != null) {
                TouchEvent touchEvent = this.touchEvent;
                if (touchEvent != null) {
                    int i2 = touchEvent.type;
                    if (i2 == 0) {
                        RemoteInput.this.deltaX[this.touchEvent.pointer] = 0;
                        RemoteInput.this.deltaY[this.touchEvent.pointer] = 0;
                        RemoteInput.this.processor.touchDown(this.touchEvent.x, this.touchEvent.y, this.touchEvent.pointer, 0);
                        RemoteInput.this.isTouched[this.touchEvent.pointer] = true;
                        RemoteInput.this.justTouched = true;
                    } else if (i2 == 1) {
                        RemoteInput.this.deltaX[this.touchEvent.pointer] = 0;
                        RemoteInput.this.deltaY[this.touchEvent.pointer] = 0;
                        RemoteInput.this.processor.touchUp(this.touchEvent.x, this.touchEvent.y, this.touchEvent.pointer, 0);
                        RemoteInput.this.isTouched[this.touchEvent.pointer] = false;
                    } else if (i2 == 2) {
                        RemoteInput.this.deltaX[this.touchEvent.pointer] = this.touchEvent.x - RemoteInput.this.touchX[this.touchEvent.pointer];
                        RemoteInput.this.deltaY[this.touchEvent.pointer] = this.touchEvent.y - RemoteInput.this.touchY[this.touchEvent.pointer];
                        RemoteInput.this.processor.touchDragged(this.touchEvent.x, this.touchEvent.y, this.touchEvent.pointer);
                    }
                    RemoteInput.this.touchX[this.touchEvent.pointer] = this.touchEvent.x;
                    RemoteInput.this.touchY[this.touchEvent.pointer] = this.touchEvent.y;
                }
                KeyEvent keyEvent = this.keyEvent;
                if (keyEvent != null) {
                    int i3 = keyEvent.type;
                    if (i3 == 0) {
                        RemoteInput.this.processor.keyDown(this.keyEvent.keyCode);
                        if (!RemoteInput.this.keys[this.keyEvent.keyCode]) {
                            RemoteInput.this.keyCount++;
                            RemoteInput.this.keys[this.keyEvent.keyCode] = true;
                        }
                        RemoteInput remoteInput2 = RemoteInput.this;
                        remoteInput2.keyJustPressed = true;
                        remoteInput2.justPressedKeys[this.keyEvent.keyCode] = true;
                        return;
                    } else if (i3 == 1) {
                        RemoteInput.this.processor.keyUp(this.keyEvent.keyCode);
                        if (RemoteInput.this.keys[this.keyEvent.keyCode]) {
                            RemoteInput.this.keyCount--;
                            RemoteInput.this.keys[this.keyEvent.keyCode] = false;
                            return;
                        }
                        return;
                    } else {
                        if (i3 == 2) {
                            RemoteInput.this.processor.keyTyped(this.keyEvent.keyChar);
                            return;
                        }
                        return;
                    }
                }
                return;
            }
            TouchEvent touchEvent2 = this.touchEvent;
            if (touchEvent2 != null) {
                int i4 = touchEvent2.type;
                if (i4 == 0) {
                    RemoteInput.this.deltaX[this.touchEvent.pointer] = 0;
                    RemoteInput.this.deltaY[this.touchEvent.pointer] = 0;
                    RemoteInput.this.isTouched[this.touchEvent.pointer] = true;
                    RemoteInput.this.justTouched = true;
                } else if (i4 == 1) {
                    RemoteInput.this.deltaX[this.touchEvent.pointer] = 0;
                    RemoteInput.this.deltaY[this.touchEvent.pointer] = 0;
                    RemoteInput.this.isTouched[this.touchEvent.pointer] = false;
                } else if (i4 == 2) {
                    RemoteInput.this.deltaX[this.touchEvent.pointer] = this.touchEvent.x - RemoteInput.this.touchX[this.touchEvent.pointer];
                    RemoteInput.this.deltaY[this.touchEvent.pointer] = this.touchEvent.y - RemoteInput.this.touchY[this.touchEvent.pointer];
                }
                RemoteInput.this.touchX[this.touchEvent.pointer] = this.touchEvent.x;
                RemoteInput.this.touchY[this.touchEvent.pointer] = this.touchEvent.y;
            }
            KeyEvent keyEvent2 = this.keyEvent;
            if (keyEvent2 != null) {
                if (keyEvent2.type == 0) {
                    if (!RemoteInput.this.keys[this.keyEvent.keyCode]) {
                        RemoteInput.this.keyCount++;
                        RemoteInput.this.keys[this.keyEvent.keyCode] = true;
                    }
                    RemoteInput remoteInput3 = RemoteInput.this;
                    remoteInput3.keyJustPressed = true;
                    remoteInput3.justPressedKeys[this.keyEvent.keyCode] = true;
                }
                if (this.keyEvent.type == 1 && RemoteInput.this.keys[this.keyEvent.keyCode]) {
                    RemoteInput.this.keyCount--;
                    RemoteInput.this.keys[this.keyEvent.keyCode] = false;
                }
            }
        }
    }

    public RemoteInput() {
        this(DEFAULT_PORT);
    }

    public RemoteInput(RemoteInputListener listener) {
        this(DEFAULT_PORT, listener);
    }

    public RemoteInput(int port) {
        this(port, null);
    }

    public RemoteInput(int port, RemoteInputListener listener) {
        this.accel = new float[3];
        this.gyrate = new float[3];
        this.compass = new float[3];
        this.multiTouch = false;
        this.remoteWidth = 0.0f;
        this.remoteHeight = 0.0f;
        this.connected = false;
        this.keyCount = 0;
        this.keys = new boolean[256];
        this.keyJustPressed = false;
        this.justPressedKeys = new boolean[256];
        this.deltaX = new int[20];
        this.deltaY = new int[20];
        this.touchX = new int[20];
        this.touchY = new int[20];
        this.isTouched = new boolean[20];
        this.justTouched = false;
        this.processor = null;
        this.listener = listener;
        try {
            this.port = port;
            this.serverSocket = new ServerSocket(port);
            Thread thread = new Thread(this);
            thread.setDaemon(true);
            thread.start();
            InetAddress[] allByName = InetAddress.getAllByName(InetAddress.getLocalHost().getHostName());
            this.ips = new String[allByName.length];
            for (int i = 0; i < allByName.length; i++) {
                this.ips[i] = allByName[i].getHostAddress();
            }
        } catch (Exception e) {
            throw new GdxRuntimeException("Couldn't open listening socket at port '" + port + "'", e);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x018a, code lost:
        continue;
     */
    @Override // java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public void run() {
        /*
            Method dump skipped, instructions count: 436
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.input.RemoteInput.run():void");
    }

    public boolean isConnected() {
        return this.connected;
    }

    @Override // com.badlogic.gdx.Input
    public float getAccelerometerX() {
        return this.accel[0];
    }

    @Override // com.badlogic.gdx.Input
    public float getAccelerometerY() {
        return this.accel[1];
    }

    @Override // com.badlogic.gdx.Input
    public float getAccelerometerZ() {
        return this.accel[2];
    }

    @Override // com.badlogic.gdx.Input
    public float getGyroscopeX() {
        return this.gyrate[0];
    }

    @Override // com.badlogic.gdx.Input
    public float getGyroscopeY() {
        return this.gyrate[1];
    }

    @Override // com.badlogic.gdx.Input
    public float getGyroscopeZ() {
        return this.gyrate[2];
    }

    @Override // com.badlogic.gdx.Input
    public int getMaxPointers() {
        return 20;
    }

    @Override // com.badlogic.gdx.Input
    public int getX() {
        return this.touchX[0];
    }

    @Override // com.badlogic.gdx.Input
    public int getX(int pointer) {
        return this.touchX[pointer];
    }

    @Override // com.badlogic.gdx.Input
    public int getY() {
        return this.touchY[0];
    }

    @Override // com.badlogic.gdx.Input
    public int getY(int pointer) {
        return this.touchY[pointer];
    }

    @Override // com.badlogic.gdx.Input
    public boolean isTouched() {
        return this.isTouched[0];
    }

    @Override // com.badlogic.gdx.Input
    public boolean justTouched() {
        return this.justTouched;
    }

    @Override // com.badlogic.gdx.Input
    public boolean isTouched(int pointer) {
        return this.isTouched[pointer];
    }

    @Override // com.badlogic.gdx.Input
    public float getPressure() {
        return getPressure(0);
    }

    @Override // com.badlogic.gdx.Input
    public float getPressure(int pointer) {
        return isTouched(pointer) ? 1.0f : 0.0f;
    }

    @Override // com.badlogic.gdx.Input
    public boolean isButtonPressed(int button) {
        if (button != 0) {
            return false;
        }
        int i = 0;
        while (true) {
            boolean[] zArr = this.isTouched;
            if (i >= zArr.length) {
                return false;
            }
            if (zArr[i]) {
                return true;
            }
            i++;
        }
    }

    @Override // com.badlogic.gdx.Input
    public boolean isButtonJustPressed(int button) {
        return button == 0 && this.justTouched;
    }

    @Override // com.badlogic.gdx.Input
    public boolean isKeyPressed(int key) {
        if (key == -1) {
            return this.keyCount > 0;
        } else if (key < 0 || key > 255) {
            return false;
        } else {
            return this.keys[key];
        }
    }

    @Override // com.badlogic.gdx.Input
    public boolean isKeyJustPressed(int key) {
        if (key == -1) {
            return this.keyJustPressed;
        }
        if (key < 0 || key > 255) {
            return false;
        }
        return this.justPressedKeys[key];
    }

    @Override // com.badlogic.gdx.Input
    public void getTextInput(Input.TextInputListener listener, String title, String text, String hint) {
        Gdx.app.getInput().getTextInput(listener, title, text, hint);
    }

    @Override // com.badlogic.gdx.Input
    public void getTextInput(Input.TextInputListener listener, String title, String text, String hint, Input.OnscreenKeyboardType type) {
        Gdx.app.getInput().getTextInput(listener, title, text, hint, type);
    }

    @Override // com.badlogic.gdx.Input
    public void setOnscreenKeyboardVisible(boolean visible) {
    }

    @Override // com.badlogic.gdx.Input
    public void setOnscreenKeyboardVisible(boolean visible, Input.OnscreenKeyboardType type) {
    }

    @Override // com.badlogic.gdx.Input
    public void vibrate(int milliseconds) {
    }

    @Override // com.badlogic.gdx.Input
    public void vibrate(long[] pattern, int repeat) {
    }

    @Override // com.badlogic.gdx.Input
    public void cancelVibrate() {
    }

    @Override // com.badlogic.gdx.Input
    public float getAzimuth() {
        return this.compass[0];
    }

    @Override // com.badlogic.gdx.Input
    public float getPitch() {
        return this.compass[1];
    }

    @Override // com.badlogic.gdx.Input
    public float getRoll() {
        return this.compass[2];
    }

    @Override // com.badlogic.gdx.Input
    public void setCatchBackKey(boolean catchBack) {
    }

    @Override // com.badlogic.gdx.Input
    public boolean isCatchBackKey() {
        return false;
    }

    @Override // com.badlogic.gdx.Input
    public void setCatchMenuKey(boolean catchMenu) {
    }

    @Override // com.badlogic.gdx.Input
    public boolean isCatchMenuKey() {
        return false;
    }

    @Override // com.badlogic.gdx.Input
    public void setCatchKey(int keycode, boolean catchKey) {
    }

    @Override // com.badlogic.gdx.Input
    public boolean isCatchKey(int keycode) {
        return false;
    }

    @Override // com.badlogic.gdx.Input
    public void setInputProcessor(InputProcessor processor) {
        this.processor = processor;
    }

    @Override // com.badlogic.gdx.Input
    public InputProcessor getInputProcessor() {
        return this.processor;
    }

    public String[] getIPs() {
        return this.ips;
    }

    @Override // com.badlogic.gdx.Input
    public boolean isPeripheralAvailable(Input.Peripheral peripheral) {
        if (peripheral == Input.Peripheral.Accelerometer || peripheral == Input.Peripheral.Compass) {
            return true;
        }
        if (peripheral == Input.Peripheral.MultitouchScreen) {
            return this.multiTouch;
        }
        return false;
    }

    @Override // com.badlogic.gdx.Input
    public int getRotation() {
        return 0;
    }

    @Override // com.badlogic.gdx.Input
    public Input.Orientation getNativeOrientation() {
        return Input.Orientation.Landscape;
    }

    @Override // com.badlogic.gdx.Input
    public void setCursorCatched(boolean catched) {
    }

    @Override // com.badlogic.gdx.Input
    public boolean isCursorCatched() {
        return false;
    }

    @Override // com.badlogic.gdx.Input
    public int getDeltaX() {
        return this.deltaX[0];
    }

    @Override // com.badlogic.gdx.Input
    public int getDeltaX(int pointer) {
        return this.deltaX[pointer];
    }

    @Override // com.badlogic.gdx.Input
    public int getDeltaY() {
        return this.deltaY[0];
    }

    @Override // com.badlogic.gdx.Input
    public int getDeltaY(int pointer) {
        return this.deltaY[pointer];
    }

    @Override // com.badlogic.gdx.Input
    public void setCursorPosition(int x, int y) {
    }

    @Override // com.badlogic.gdx.Input
    public long getCurrentEventTime() {
        return 0L;
    }

    @Override // com.badlogic.gdx.Input
    public void getRotationMatrix(float[] matrix) {
    }
}