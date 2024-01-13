package com.badlogic.gdx.backends.android;

import android.view.View;

/* loaded from: classes.dex */
public class AndroidVisibilityListener {
    public void createListener(final AndroidApplicationBase application) {
        try {
            View rootView = application.getApplicationWindow().getDecorView();
            rootView.setOnSystemUiVisibilityChangeListener(new View.OnSystemUiVisibilityChangeListener() { // from class: com.badlogic.gdx.backends.android.AndroidVisibilityListener.1
                @Override // android.view.View.OnSystemUiVisibilityChangeListener
                public void onSystemUiVisibilityChange(int arg0) {
                    application.getHandler().post(new Runnable() { // from class: com.badlogic.gdx.backends.android.AndroidVisibilityListener.1.1
                        @Override // java.lang.Runnable
                        public void run() {
                            application.useImmersiveMode(true);
                        }
                    });
                }
            });
        } catch (Throwable t) {
            application.log("AndroidApplication", "Can't create OnSystemUiVisibilityChangeListener, unable to use immersive mode.", t);
        }
    }
}