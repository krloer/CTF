package com.badlogic.gdx.input;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.Input;
import com.badlogic.gdx.InputProcessor;
import java.io.DataOutputStream;
import java.net.Socket;

/* loaded from: classes.dex */
public class RemoteSender implements InputProcessor {
    public static final int ACCEL = 6;
    public static final int COMPASS = 7;
    public static final int GYRO = 9;
    public static final int KEY_DOWN = 0;
    public static final int KEY_TYPED = 2;
    public static final int KEY_UP = 1;
    public static final int SIZE = 8;
    public static final int TOUCH_DOWN = 3;
    public static final int TOUCH_DRAGGED = 5;
    public static final int TOUCH_UP = 4;
    private boolean connected;
    private DataOutputStream out;

    public RemoteSender(String ip, int port) {
        this.connected = false;
        try {
            Socket socket = new Socket(ip, port);
            socket.setTcpNoDelay(true);
            socket.setSoTimeout(3000);
            this.out = new DataOutputStream(socket.getOutputStream());
            this.out.writeBoolean(Gdx.input.isPeripheralAvailable(Input.Peripheral.MultitouchScreen));
            this.connected = true;
            Gdx.input.setInputProcessor(this);
        } catch (Exception e) {
            Application application = Gdx.app;
            application.log("RemoteSender", "couldn't connect to " + ip + ":" + port);
        }
    }

    public void sendUpdate() {
        synchronized (this) {
            if (this.connected) {
                try {
                    this.out.writeInt(6);
                    this.out.writeFloat(Gdx.input.getAccelerometerX());
                    this.out.writeFloat(Gdx.input.getAccelerometerY());
                    this.out.writeFloat(Gdx.input.getAccelerometerZ());
                    this.out.writeInt(7);
                    this.out.writeFloat(Gdx.input.getAzimuth());
                    this.out.writeFloat(Gdx.input.getPitch());
                    this.out.writeFloat(Gdx.input.getRoll());
                    this.out.writeInt(8);
                    this.out.writeFloat(Gdx.graphics.getWidth());
                    this.out.writeFloat(Gdx.graphics.getHeight());
                    this.out.writeInt(9);
                    this.out.writeFloat(Gdx.input.getGyroscopeX());
                    this.out.writeFloat(Gdx.input.getGyroscopeY());
                    this.out.writeFloat(Gdx.input.getGyroscopeZ());
                } catch (Throwable th) {
                    this.out = null;
                    this.connected = false;
                }
            }
        }
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean keyDown(int keycode) {
        synchronized (this) {
            if (this.connected) {
                try {
                    this.out.writeInt(0);
                    this.out.writeInt(keycode);
                } finally {
                    synchronized (this) {
                        return false;
                    }
                }
                return false;
            }
            return false;
        }
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean keyUp(int keycode) {
        synchronized (this) {
            if (this.connected) {
                try {
                    this.out.writeInt(1);
                    this.out.writeInt(keycode);
                } finally {
                    synchronized (this) {
                        return false;
                    }
                }
                return false;
            }
            return false;
        }
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean keyTyped(char character) {
        synchronized (this) {
            if (this.connected) {
                try {
                    this.out.writeInt(2);
                    this.out.writeChar(character);
                } finally {
                    synchronized (this) {
                        return false;
                    }
                }
                return false;
            }
            return false;
        }
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean touchDown(int x, int y, int pointer, int button) {
        synchronized (this) {
            if (this.connected) {
                try {
                    this.out.writeInt(3);
                    this.out.writeInt(x);
                    this.out.writeInt(y);
                    this.out.writeInt(pointer);
                } finally {
                    synchronized (this) {
                        return false;
                    }
                }
                return false;
            }
            return false;
        }
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean touchUp(int x, int y, int pointer, int button) {
        synchronized (this) {
            if (this.connected) {
                try {
                    this.out.writeInt(4);
                    this.out.writeInt(x);
                    this.out.writeInt(y);
                    this.out.writeInt(pointer);
                } finally {
                    synchronized (this) {
                        return false;
                    }
                }
                return false;
            }
            return false;
        }
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean touchDragged(int x, int y, int pointer) {
        synchronized (this) {
            if (this.connected) {
                try {
                    this.out.writeInt(5);
                    this.out.writeInt(x);
                    this.out.writeInt(y);
                    this.out.writeInt(pointer);
                } finally {
                    synchronized (this) {
                        return false;
                    }
                }
                return false;
            }
            return false;
        }
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean mouseMoved(int x, int y) {
        return false;
    }

    @Override // com.badlogic.gdx.InputProcessor
    public boolean scrolled(float amountX, float amountY) {
        return false;
    }

    public boolean isConnected() {
        boolean z;
        synchronized (this) {
            z = this.connected;
        }
        return z;
    }
}