package com.badlogic.gdx.scenes.scene2d.utils;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.glutils.HdpiUtils;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class ScissorStack {
    private static Array<Rectangle> scissors = new Array<>();
    static Vector3 tmp = new Vector3();
    static final Rectangle viewport = new Rectangle();

    public static boolean pushScissors(Rectangle scissor) {
        fix(scissor);
        if (scissors.size == 0) {
            if (scissor.width < 1.0f || scissor.height < 1.0f) {
                return false;
            }
            Gdx.gl.glEnable(GL20.GL_SCISSOR_TEST);
        } else {
            Array<Rectangle> array = scissors;
            Rectangle parent = array.get(array.size - 1);
            float minX = Math.max(parent.x, scissor.x);
            float maxX = Math.min(parent.x + parent.width, scissor.x + scissor.width);
            if (maxX - minX < 1.0f) {
                return false;
            }
            float minY = Math.max(parent.y, scissor.y);
            float maxY = Math.min(parent.y + parent.height, scissor.y + scissor.height);
            if (maxY - minY < 1.0f) {
                return false;
            }
            scissor.x = minX;
            scissor.y = minY;
            scissor.width = maxX - minX;
            scissor.height = Math.max(1.0f, maxY - minY);
        }
        scissors.add(scissor);
        HdpiUtils.glScissor((int) scissor.x, (int) scissor.y, (int) scissor.width, (int) scissor.height);
        return true;
    }

    public static Rectangle popScissors() {
        Rectangle old = scissors.pop();
        if (scissors.size == 0) {
            Gdx.gl.glDisable(GL20.GL_SCISSOR_TEST);
        } else {
            Rectangle scissor = scissors.peek();
            HdpiUtils.glScissor((int) scissor.x, (int) scissor.y, (int) scissor.width, (int) scissor.height);
        }
        return old;
    }

    public static Rectangle peekScissors() {
        if (scissors.size == 0) {
            return null;
        }
        return scissors.peek();
    }

    private static void fix(Rectangle rect) {
        rect.x = Math.round(rect.x);
        rect.y = Math.round(rect.y);
        rect.width = Math.round(rect.width);
        rect.height = Math.round(rect.height);
        if (rect.width < 0.0f) {
            rect.width = -rect.width;
            rect.x -= rect.width;
        }
        if (rect.height < 0.0f) {
            rect.height = -rect.height;
            rect.y -= rect.height;
        }
    }

    public static void calculateScissors(Camera camera, Matrix4 batchTransform, Rectangle area, Rectangle scissor) {
        calculateScissors(camera, 0.0f, 0.0f, Gdx.graphics.getWidth(), Gdx.graphics.getHeight(), batchTransform, area, scissor);
    }

    public static void calculateScissors(Camera camera, float viewportX, float viewportY, float viewportWidth, float viewportHeight, Matrix4 batchTransform, Rectangle area, Rectangle scissor) {
        tmp.set(area.x, area.y, 0.0f);
        tmp.mul(batchTransform);
        camera.project(tmp, viewportX, viewportY, viewportWidth, viewportHeight);
        scissor.x = tmp.x;
        scissor.y = tmp.y;
        tmp.set(area.x + area.width, area.y + area.height, 0.0f);
        tmp.mul(batchTransform);
        camera.project(tmp, viewportX, viewportY, viewportWidth, viewportHeight);
        scissor.width = tmp.x - scissor.x;
        scissor.height = tmp.y - scissor.y;
    }

    public static Rectangle getViewport() {
        if (scissors.size == 0) {
            viewport.set(0.0f, 0.0f, Gdx.graphics.getWidth(), Gdx.graphics.getHeight());
            return viewport;
        }
        Rectangle scissor = scissors.peek();
        viewport.set(scissor);
        return viewport;
    }
}