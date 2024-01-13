package com.badlogic.gdx.graphics.g3d.utils;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.input.GestureDetector;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.math.Vector3;

/* loaded from: classes.dex */
public class CameraInputController extends GestureDetector {
    public int activateKey;
    protected boolean activatePressed;
    public boolean alwaysScroll;
    public boolean autoUpdate;
    public int backwardKey;
    protected boolean backwardPressed;
    protected int button;
    public Camera camera;
    public int forwardButton;
    public int forwardKey;
    protected boolean forwardPressed;
    public boolean forwardTarget;
    protected final CameraGestureListener gestureListener;
    private boolean multiTouch;
    public float pinchZoomFactor;
    public float rotateAngle;
    public int rotateButton;
    public int rotateLeftKey;
    protected boolean rotateLeftPressed;
    public int rotateRightKey;
    protected boolean rotateRightPressed;
    public float scrollFactor;
    public boolean scrollTarget;
    private float startX;
    private float startY;
    public Vector3 target;
    private final Vector3 tmpV1;
    private final Vector3 tmpV2;
    private int touched;
    public int translateButton;
    public boolean translateTarget;
    public float translateUnits;

    /* loaded from: classes.dex */
    protected static class CameraGestureListener extends GestureDetector.GestureAdapter {
        public CameraInputController controller;
        private float previousZoom;

        protected CameraGestureListener() {
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureAdapter, com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean touchDown(float x, float y, int pointer, int button) {
            this.previousZoom = 0.0f;
            return false;
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureAdapter, com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean tap(float x, float y, int count, int button) {
            return false;
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureAdapter, com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean longPress(float x, float y) {
            return false;
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureAdapter, com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean fling(float velocityX, float velocityY, int button) {
            return false;
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureAdapter, com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean pan(float x, float y, float deltaX, float deltaY) {
            return false;
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureAdapter, com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean zoom(float initialDistance, float distance) {
            float newZoom = distance - initialDistance;
            float amount = newZoom - this.previousZoom;
            this.previousZoom = newZoom;
            float w = Gdx.graphics.getWidth();
            float h = Gdx.graphics.getHeight();
            return this.controller.pinchZoom(amount / (w > h ? h : w));
        }

        @Override // com.badlogic.gdx.input.GestureDetector.GestureAdapter, com.badlogic.gdx.input.GestureDetector.GestureListener
        public boolean pinch(Vector2 initialPointer1, Vector2 initialPointer2, Vector2 pointer1, Vector2 pointer2) {
            return false;
        }
    }

    protected CameraInputController(CameraGestureListener gestureListener, Camera camera) {
        super(gestureListener);
        this.rotateButton = 0;
        this.rotateAngle = 360.0f;
        this.translateButton = 1;
        this.translateUnits = 10.0f;
        this.forwardButton = 2;
        this.activateKey = 0;
        this.alwaysScroll = true;
        this.scrollFactor = -0.1f;
        this.pinchZoomFactor = 10.0f;
        this.autoUpdate = true;
        this.target = new Vector3();
        this.translateTarget = true;
        this.forwardTarget = true;
        this.scrollTarget = false;
        this.forwardKey = 51;
        this.backwardKey = 47;
        this.rotateRightKey = 29;
        this.rotateLeftKey = 32;
        this.button = -1;
        this.tmpV1 = new Vector3();
        this.tmpV2 = new Vector3();
        this.gestureListener = gestureListener;
        this.gestureListener.controller = this;
        this.camera = camera;
    }

    public CameraInputController(Camera camera) {
        this(new CameraGestureListener(), camera);
    }

    public void update() {
        if (this.rotateRightPressed || this.rotateLeftPressed || this.forwardPressed || this.backwardPressed) {
            float delta = Gdx.graphics.getDeltaTime();
            if (this.rotateRightPressed) {
                Camera camera = this.camera;
                camera.rotate(camera.up, (-delta) * this.rotateAngle);
            }
            if (this.rotateLeftPressed) {
                Camera camera2 = this.camera;
                camera2.rotate(camera2.up, this.rotateAngle * delta);
            }
            if (this.forwardPressed) {
                Camera camera3 = this.camera;
                camera3.translate(this.tmpV1.set(camera3.direction).scl(this.translateUnits * delta));
                if (this.forwardTarget) {
                    this.target.add(this.tmpV1);
                }
            }
            if (this.backwardPressed) {
                Camera camera4 = this.camera;
                camera4.translate(this.tmpV1.set(camera4.direction).scl((-delta) * this.translateUnits));
                if (this.forwardTarget) {
                    this.target.add(this.tmpV1);
                }
            }
            if (this.autoUpdate) {
                this.camera.update();
            }
        }
    }

    @Override // com.badlogic.gdx.input.GestureDetector, com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean touchDown(int screenX, int screenY, int pointer, int button) {
        this.touched |= 1 << pointer;
        this.multiTouch = !MathUtils.isPowerOfTwo(this.touched);
        if (this.multiTouch) {
            this.button = -1;
        } else if (this.button < 0 && (this.activateKey == 0 || this.activatePressed)) {
            this.startX = screenX;
            this.startY = screenY;
            this.button = button;
        }
        return super.touchDown(screenX, screenY, pointer, button) || this.activateKey == 0 || this.activatePressed;
    }

    @Override // com.badlogic.gdx.input.GestureDetector, com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean touchUp(int screenX, int screenY, int pointer, int button) {
        this.touched &= (1 << pointer) ^ (-1);
        this.multiTouch = !MathUtils.isPowerOfTwo(this.touched);
        if (button == this.button) {
            this.button = -1;
        }
        return super.touchUp(screenX, screenY, pointer, button) || this.activatePressed;
    }

    protected boolean process(float deltaX, float deltaY, int button) {
        if (button == this.rotateButton) {
            this.tmpV1.set(this.camera.direction).crs(this.camera.up).y = 0.0f;
            this.camera.rotateAround(this.target, this.tmpV1.nor(), this.rotateAngle * deltaY);
            this.camera.rotateAround(this.target, Vector3.Y, (-this.rotateAngle) * deltaX);
        } else if (button == this.translateButton) {
            Camera camera = this.camera;
            camera.translate(this.tmpV1.set(camera.direction).crs(this.camera.up).nor().scl((-deltaX) * this.translateUnits));
            Camera camera2 = this.camera;
            camera2.translate(this.tmpV2.set(camera2.up).scl((-deltaY) * this.translateUnits));
            if (this.translateTarget) {
                this.target.add(this.tmpV1).add(this.tmpV2);
            }
        } else if (button == this.forwardButton) {
            Camera camera3 = this.camera;
            camera3.translate(this.tmpV1.set(camera3.direction).scl(this.translateUnits * deltaY));
            if (this.forwardTarget) {
                this.target.add(this.tmpV1);
            }
        }
        if (this.autoUpdate) {
            this.camera.update();
            return true;
        }
        return true;
    }

    @Override // com.badlogic.gdx.input.GestureDetector, com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean touchDragged(int screenX, int screenY, int pointer) {
        boolean result = super.touchDragged(screenX, screenY, pointer);
        if (result || this.button < 0) {
            return result;
        }
        float deltaX = (screenX - this.startX) / Gdx.graphics.getWidth();
        float deltaY = (this.startY - screenY) / Gdx.graphics.getHeight();
        this.startX = screenX;
        this.startY = screenY;
        return process(deltaX, deltaY, this.button);
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean scrolled(float amountX, float amountY) {
        return zoom(this.scrollFactor * amountY * this.translateUnits);
    }

    public boolean zoom(float amount) {
        if (this.alwaysScroll || this.activateKey == 0 || this.activatePressed) {
            Camera camera = this.camera;
            camera.translate(this.tmpV1.set(camera.direction).scl(amount));
            if (this.scrollTarget) {
                this.target.add(this.tmpV1);
            }
            if (this.autoUpdate) {
                this.camera.update();
                return true;
            }
            return true;
        }
        return false;
    }

    protected boolean pinchZoom(float amount) {
        return zoom(this.pinchZoomFactor * amount);
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean keyDown(int keycode) {
        if (keycode == this.activateKey) {
            this.activatePressed = true;
        }
        if (keycode == this.forwardKey) {
            this.forwardPressed = true;
            return false;
        } else if (keycode == this.backwardKey) {
            this.backwardPressed = true;
            return false;
        } else if (keycode == this.rotateRightKey) {
            this.rotateRightPressed = true;
            return false;
        } else if (keycode == this.rotateLeftKey) {
            this.rotateLeftPressed = true;
            return false;
        } else {
            return false;
        }
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean keyUp(int keycode) {
        if (keycode == this.activateKey) {
            this.activatePressed = false;
            this.button = -1;
        }
        if (keycode == this.forwardKey) {
            this.forwardPressed = false;
        } else if (keycode == this.backwardKey) {
            this.backwardPressed = false;
        } else if (keycode == this.rotateRightKey) {
            this.rotateRightPressed = false;
        } else if (keycode == this.rotateLeftKey) {
            this.rotateLeftPressed = false;
        }
        return false;
    }
}