package com.kotcrab.vis.ui.util;

import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.graphics.OrthographicCamera;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Stage;

/* loaded from: classes.dex */
public class ActorUtils {
    public static void keepWithinStage(Actor actor) {
        Stage stage = actor.getStage();
        if (stage == null) {
            throw new IllegalStateException("keepWithinStage cannot be used on Actor that doesn't belong to any stage. ");
        }
        keepWithinStage(actor.getStage(), actor);
    }

    public static void keepWithinStage(Stage stage, Actor actor) {
        Camera camera = stage.getCamera();
        if (camera instanceof OrthographicCamera) {
            OrthographicCamera orthographicCamera = (OrthographicCamera) camera;
            float parentWidth = stage.getWidth();
            float parentHeight = stage.getHeight();
            if (actor.getX(16) - camera.position.x > (parentWidth / 2.0f) / orthographicCamera.zoom) {
                actor.setPosition(camera.position.x + ((parentWidth / 2.0f) / orthographicCamera.zoom), actor.getY(16), 16);
            }
            if (actor.getX(8) - camera.position.x < ((-parentWidth) / 2.0f) / orthographicCamera.zoom) {
                actor.setPosition(camera.position.x - ((parentWidth / 2.0f) / orthographicCamera.zoom), actor.getY(8), 8);
            }
            if (actor.getY(2) - camera.position.y > (parentHeight / 2.0f) / orthographicCamera.zoom) {
                actor.setPosition(actor.getX(2), camera.position.y + ((parentHeight / 2.0f) / orthographicCamera.zoom), 2);
            }
            if (actor.getY(4) - camera.position.y < ((-parentHeight) / 2.0f) / orthographicCamera.zoom) {
                actor.setPosition(actor.getX(4), camera.position.y - ((parentHeight / 2.0f) / orthographicCamera.zoom), 4);
            }
        } else if (actor.getParent() == stage.getRoot()) {
            float parentWidth2 = stage.getWidth();
            float parentHeight2 = stage.getHeight();
            if (actor.getX() < 0.0f) {
                actor.setX(0.0f);
            }
            if (actor.getRight() > parentWidth2) {
                actor.setX(parentWidth2 - actor.getWidth());
            }
            if (actor.getY() < 0.0f) {
                actor.setY(0.0f);
            }
            if (actor.getTop() > parentHeight2) {
                actor.setY(parentHeight2 - actor.getHeight());
            }
        }
    }
}