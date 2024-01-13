package com.badlogic.gdx.backends.android;

import android.opengl.GLSurfaceView;
import android.util.Log;
import android.view.SurfaceHolder;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.backends.android.surfaceview.GLSurfaceView20;
import com.badlogic.gdx.backends.android.surfaceview.ResolutionStrategy;
import com.badlogic.gdx.utils.GdxRuntimeException;
import javax.microedition.khronos.opengles.GL10;

/* loaded from: classes.dex */
public final class AndroidGraphicsLiveWallpaper extends AndroidGraphics {
    public AndroidGraphicsLiveWallpaper(AndroidLiveWallpaper lwp, AndroidApplicationConfiguration config, ResolutionStrategy resolutionStrategy) {
        super(lwp, config, resolutionStrategy, false);
    }

    SurfaceHolder getSurfaceHolder() {
        SurfaceHolder surfaceHolder;
        synchronized (((AndroidLiveWallpaper) this.app).service.sync) {
            surfaceHolder = ((AndroidLiveWallpaper) this.app).service.getSurfaceHolder();
        }
        return surfaceHolder;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidGraphics
    protected GLSurfaceView20 createGLSurfaceView(AndroidApplicationBase application, ResolutionStrategy resolutionStrategy) {
        if (!checkGL20()) {
            throw new GdxRuntimeException("Libgdx requires OpenGL ES 2.0");
        }
        GLSurfaceView.EGLConfigChooser configChooser = getEglConfigChooser();
        GLSurfaceView20 view = new GLSurfaceView20(application.getContext(), resolutionStrategy) { // from class: com.badlogic.gdx.backends.android.AndroidGraphicsLiveWallpaper.1
            @Override // android.view.SurfaceView
            public SurfaceHolder getHolder() {
                return AndroidGraphicsLiveWallpaper.this.getSurfaceHolder();
            }
        };
        if (configChooser != null) {
            view.setEGLConfigChooser(configChooser);
        } else {
            view.setEGLConfigChooser(this.config.r, this.config.g, this.config.b, this.config.a, this.config.depth, this.config.stencil);
        }
        view.setRenderer(this);
        return view;
    }

    public void onDestroyGLSurfaceView() {
        if (this.view != null) {
            try {
                this.view.onDetachedFromWindow();
                if (AndroidLiveWallpaperService.DEBUG) {
                    Log.d("WallpaperService", " > AndroidLiveWallpaper - onDestroy() stopped GLThread managed by GLSurfaceView");
                }
            } catch (Throwable t) {
                Log.e("WallpaperService", "failed to destroy GLSurfaceView's thread! GLSurfaceView.onDetachedFromWindow impl changed since API lvl 16!");
                t.printStackTrace();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.badlogic.gdx.backends.android.AndroidGraphics
    public void resume() {
        synchronized (this.synch) {
            this.running = true;
            this.resume = true;
            while (this.resume) {
                try {
                    requestRendering();
                    this.synch.wait();
                } catch (InterruptedException e) {
                    Gdx.app.log("AndroidGraphics", "waiting for resume synchronization failed!");
                }
            }
        }
    }

    @Override // com.badlogic.gdx.backends.android.AndroidGraphics, android.opengl.GLSurfaceView.Renderer
    public void onDrawFrame(GL10 gl) {
        boolean lrunning;
        boolean lpause;
        boolean ldestroy;
        boolean lresume;
        long time = System.nanoTime();
        if (!this.resume) {
            this.deltaTime = ((float) (time - this.lastFrameTime)) / 1.0E9f;
        } else {
            this.deltaTime = 0.0f;
        }
        this.lastFrameTime = time;
        synchronized (this.synch) {
            lrunning = this.running;
            lpause = this.pause;
            ldestroy = this.destroy;
            lresume = this.resume;
            if (this.resume) {
                this.resume = false;
                this.synch.notifyAll();
            }
            if (this.pause) {
                this.pause = false;
                this.synch.notifyAll();
            }
            if (this.destroy) {
                this.destroy = false;
                this.synch.notifyAll();
            }
        }
        if (lresume) {
            this.app.getApplicationListener().resume();
            Gdx.app.log("AndroidGraphics", "resumed");
        }
        if (lrunning) {
            synchronized (this.app.getRunnables()) {
                this.app.getExecutedRunnables().clear();
                this.app.getExecutedRunnables().addAll(this.app.getRunnables());
                this.app.getRunnables().clear();
                for (int i = 0; i < this.app.getExecutedRunnables().size; i++) {
                    this.app.getExecutedRunnables().get(i).run();
                }
            }
            this.app.getInput().processEvents();
            this.frameId++;
            this.app.getApplicationListener().render();
        }
        if (lpause) {
            this.app.getApplicationListener().pause();
            Gdx.app.log("AndroidGraphics", "paused");
        }
        if (ldestroy) {
            this.app.getApplicationListener().dispose();
            Gdx.app.log("AndroidGraphics", "destroyed");
        }
        if (time - this.frameStart > 1000000000) {
            this.fps = this.frames;
            this.frames = 0;
            this.frameStart = time;
        }
        this.frames++;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.backends.android.AndroidGraphics
    public void logManagedCachesStatus() {
        if (AndroidLiveWallpaperService.DEBUG) {
            super.logManagedCachesStatus();
        }
    }
}