package com.badlogic.gdx.utils;

import com.badlogic.gdx.math.Vector2;

/* loaded from: classes.dex */
public abstract class Scaling {
    protected static final Vector2 temp = new Vector2();
    public static final Scaling fit = new Scaling() { // from class: com.badlogic.gdx.utils.Scaling.1
        @Override // com.badlogic.gdx.utils.Scaling
        public Vector2 apply(float sourceWidth, float sourceHeight, float targetWidth, float targetHeight) {
            float targetRatio = targetHeight / targetWidth;
            float sourceRatio = sourceHeight / sourceWidth;
            float scale = targetRatio > sourceRatio ? targetWidth / sourceWidth : targetHeight / sourceHeight;
            temp.x = sourceWidth * scale;
            temp.y = sourceHeight * scale;
            return temp;
        }
    };
    public static final Scaling fill = new Scaling() { // from class: com.badlogic.gdx.utils.Scaling.2
        @Override // com.badlogic.gdx.utils.Scaling
        public Vector2 apply(float sourceWidth, float sourceHeight, float targetWidth, float targetHeight) {
            float targetRatio = targetHeight / targetWidth;
            float sourceRatio = sourceHeight / sourceWidth;
            float scale = targetRatio < sourceRatio ? targetWidth / sourceWidth : targetHeight / sourceHeight;
            temp.x = sourceWidth * scale;
            temp.y = sourceHeight * scale;
            return temp;
        }
    };
    public static final Scaling fillX = new Scaling() { // from class: com.badlogic.gdx.utils.Scaling.3
        @Override // com.badlogic.gdx.utils.Scaling
        public Vector2 apply(float sourceWidth, float sourceHeight, float targetWidth, float targetHeight) {
            float scale = targetWidth / sourceWidth;
            temp.x = sourceWidth * scale;
            temp.y = sourceHeight * scale;
            return temp;
        }
    };
    public static final Scaling fillY = new Scaling() { // from class: com.badlogic.gdx.utils.Scaling.4
        @Override // com.badlogic.gdx.utils.Scaling
        public Vector2 apply(float sourceWidth, float sourceHeight, float targetWidth, float targetHeight) {
            float scale = targetHeight / sourceHeight;
            temp.x = sourceWidth * scale;
            temp.y = sourceHeight * scale;
            return temp;
        }
    };
    public static final Scaling stretch = new Scaling() { // from class: com.badlogic.gdx.utils.Scaling.5
        @Override // com.badlogic.gdx.utils.Scaling
        public Vector2 apply(float sourceWidth, float sourceHeight, float targetWidth, float targetHeight) {
            temp.x = targetWidth;
            temp.y = targetHeight;
            return temp;
        }
    };
    public static final Scaling stretchX = new Scaling() { // from class: com.badlogic.gdx.utils.Scaling.6
        @Override // com.badlogic.gdx.utils.Scaling
        public Vector2 apply(float sourceWidth, float sourceHeight, float targetWidth, float targetHeight) {
            temp.x = targetWidth;
            temp.y = sourceHeight;
            return temp;
        }
    };
    public static final Scaling stretchY = new Scaling() { // from class: com.badlogic.gdx.utils.Scaling.7
        @Override // com.badlogic.gdx.utils.Scaling
        public Vector2 apply(float sourceWidth, float sourceHeight, float targetWidth, float targetHeight) {
            temp.x = sourceWidth;
            temp.y = targetHeight;
            return temp;
        }
    };
    public static final Scaling none = new Scaling() { // from class: com.badlogic.gdx.utils.Scaling.8
        @Override // com.badlogic.gdx.utils.Scaling
        public Vector2 apply(float sourceWidth, float sourceHeight, float targetWidth, float targetHeight) {
            temp.x = sourceWidth;
            temp.y = sourceHeight;
            return temp;
        }
    };

    public abstract Vector2 apply(float f, float f2, float f3, float f4);
}