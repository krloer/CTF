package com.badlogic.gdx.graphics;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.Net;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.g2d.Gdx2DPixmap;
import com.badlogic.gdx.utils.BufferUtils;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.GdxRuntimeException;
import java.io.IOException;
import java.nio.ByteBuffer;

/* loaded from: classes.dex */
public class Pixmap implements Disposable {
    private boolean disposed;
    final Gdx2DPixmap pixmap;
    private Blending blending = Blending.SourceOver;
    private Filter filter = Filter.BiLinear;
    int color = 0;

    /* loaded from: classes.dex */
    public enum Blending {
        None,
        SourceOver
    }

    /* loaded from: classes.dex */
    public interface DownloadPixmapResponseListener {
        void downloadComplete(Pixmap pixmap);

        void downloadFailed(Throwable th);
    }

    /* loaded from: classes.dex */
    public enum Filter {
        NearestNeighbour,
        BiLinear
    }

    /* loaded from: classes.dex */
    public enum Format {
        Alpha,
        Intensity,
        LuminanceAlpha,
        RGB565,
        RGBA4444,
        RGB888,
        RGBA8888;

        public static int toGdx2DPixmapFormat(Format format) {
            if (format == Alpha || format == Intensity) {
                return 1;
            }
            if (format == LuminanceAlpha) {
                return 2;
            }
            if (format == RGB565) {
                return 5;
            }
            if (format == RGBA4444) {
                return 6;
            }
            if (format == RGB888) {
                return 3;
            }
            if (format == RGBA8888) {
                return 4;
            }
            throw new GdxRuntimeException("Unknown Format: " + format);
        }

        public static Format fromGdx2DPixmapFormat(int format) {
            if (format == 1) {
                return Alpha;
            }
            if (format == 2) {
                return LuminanceAlpha;
            }
            if (format == 5) {
                return RGB565;
            }
            if (format == 6) {
                return RGBA4444;
            }
            if (format == 3) {
                return RGB888;
            }
            if (format == 4) {
                return RGBA8888;
            }
            throw new GdxRuntimeException("Unknown Gdx2DPixmap Format: " + format);
        }

        public static int toGlFormat(Format format) {
            return Gdx2DPixmap.toGlFormat(toGdx2DPixmapFormat(format));
        }

        public static int toGlType(Format format) {
            return Gdx2DPixmap.toGlType(toGdx2DPixmapFormat(format));
        }
    }

    public static Pixmap createFromFrameBuffer(int x, int y, int w, int h) {
        Gdx.gl.glPixelStorei(GL20.GL_PACK_ALIGNMENT, 1);
        Pixmap pixmap = new Pixmap(w, h, Format.RGBA8888);
        ByteBuffer pixels = pixmap.getPixels();
        Gdx.gl.glReadPixels(x, y, w, h, GL20.GL_RGBA, GL20.GL_UNSIGNED_BYTE, pixels);
        return pixmap;
    }

    public void setBlending(Blending blending) {
        this.blending = blending;
        this.pixmap.setBlend(blending == Blending.None ? 0 : 1);
    }

    public void setFilter(Filter filter) {
        this.filter = filter;
        this.pixmap.setScale(filter == Filter.NearestNeighbour ? 0 : 1);
    }

    public Pixmap(int width, int height, Format format) {
        this.pixmap = new Gdx2DPixmap(width, height, Format.toGdx2DPixmapFormat(format));
        setColor(0.0f, 0.0f, 0.0f, 0.0f);
        fill();
    }

    public Pixmap(byte[] encodedData, int offset, int len) {
        try {
            this.pixmap = new Gdx2DPixmap(encodedData, offset, len, 0);
        } catch (IOException e) {
            throw new GdxRuntimeException("Couldn't load pixmap from image data", e);
        }
    }

    public Pixmap(FileHandle file) {
        try {
            byte[] bytes = file.readBytes();
            this.pixmap = new Gdx2DPixmap(bytes, 0, bytes.length, 0);
        } catch (Exception e) {
            throw new GdxRuntimeException("Couldn't load file: " + file, e);
        }
    }

    public Pixmap(Gdx2DPixmap pixmap) {
        this.pixmap = pixmap;
    }

    public static void downloadFromUrl(String url, DownloadPixmapResponseListener responseListener) {
        Net.HttpRequest request = new Net.HttpRequest(Net.HttpMethods.GET);
        request.setUrl(url);
        Gdx.net.sendHttpRequest(request, new AnonymousClass1(responseListener));
    }

    /* renamed from: com.badlogic.gdx.graphics.Pixmap$1  reason: invalid class name */
    /* loaded from: classes.dex */
    static class AnonymousClass1 implements Net.HttpResponseListener {
        final /* synthetic */ DownloadPixmapResponseListener val$responseListener;

        AnonymousClass1(DownloadPixmapResponseListener downloadPixmapResponseListener) {
            this.val$responseListener = downloadPixmapResponseListener;
        }

        @Override // com.badlogic.gdx.Net.HttpResponseListener
        public void handleHttpResponse(Net.HttpResponse httpResponse) {
            final byte[] result = httpResponse.getResult();
            Gdx.app.postRunnable(new Runnable() { // from class: com.badlogic.gdx.graphics.Pixmap.1.1
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        Pixmap pixmap = new Pixmap(result, 0, result.length);
                        AnonymousClass1.this.val$responseListener.downloadComplete(pixmap);
                    } catch (Throwable t) {
                        AnonymousClass1.this.failed(t);
                    }
                }
            });
        }

        @Override // com.badlogic.gdx.Net.HttpResponseListener
        public void failed(Throwable t) {
            this.val$responseListener.downloadFailed(t);
        }

        @Override // com.badlogic.gdx.Net.HttpResponseListener
        public void cancelled() {
        }
    }

    public void setColor(int color) {
        this.color = color;
    }

    public void setColor(float r, float g, float b, float a) {
        this.color = Color.rgba8888(r, g, b, a);
    }

    public void setColor(Color color) {
        this.color = Color.rgba8888(color.r, color.g, color.b, color.a);
    }

    public void fill() {
        this.pixmap.clear(this.color);
    }

    public void drawLine(int x, int y, int x2, int y2) {
        this.pixmap.drawLine(x, y, x2, y2, this.color);
    }

    public void drawRectangle(int x, int y, int width, int height) {
        this.pixmap.drawRect(x, y, width, height, this.color);
    }

    public void drawPixmap(Pixmap pixmap, int x, int y) {
        drawPixmap(pixmap, x, y, 0, 0, pixmap.getWidth(), pixmap.getHeight());
    }

    public void drawPixmap(Pixmap pixmap, int x, int y, int srcx, int srcy, int srcWidth, int srcHeight) {
        this.pixmap.drawPixmap(pixmap.pixmap, srcx, srcy, x, y, srcWidth, srcHeight);
    }

    public void drawPixmap(Pixmap pixmap, int srcx, int srcy, int srcWidth, int srcHeight, int dstx, int dsty, int dstWidth, int dstHeight) {
        this.pixmap.drawPixmap(pixmap.pixmap, srcx, srcy, srcWidth, srcHeight, dstx, dsty, dstWidth, dstHeight);
    }

    public void fillRectangle(int x, int y, int width, int height) {
        this.pixmap.fillRect(x, y, width, height, this.color);
    }

    public void drawCircle(int x, int y, int radius) {
        this.pixmap.drawCircle(x, y, radius, this.color);
    }

    public void fillCircle(int x, int y, int radius) {
        this.pixmap.fillCircle(x, y, radius, this.color);
    }

    public void fillTriangle(int x1, int y1, int x2, int y2, int x3, int y3) {
        this.pixmap.fillTriangle(x1, y1, x2, y2, x3, y3, this.color);
    }

    public int getPixel(int x, int y) {
        return this.pixmap.getPixel(x, y);
    }

    public int getWidth() {
        return this.pixmap.getWidth();
    }

    public int getHeight() {
        return this.pixmap.getHeight();
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        if (this.disposed) {
            throw new GdxRuntimeException("Pixmap already disposed!");
        }
        this.pixmap.dispose();
        this.disposed = true;
    }

    public boolean isDisposed() {
        return this.disposed;
    }

    public void drawPixel(int x, int y) {
        this.pixmap.setPixel(x, y, this.color);
    }

    public void drawPixel(int x, int y, int color) {
        this.pixmap.setPixel(x, y, color);
    }

    public int getGLFormat() {
        return this.pixmap.getGLFormat();
    }

    public int getGLInternalFormat() {
        return this.pixmap.getGLInternalFormat();
    }

    public int getGLType() {
        return this.pixmap.getGLType();
    }

    public ByteBuffer getPixels() {
        if (this.disposed) {
            throw new GdxRuntimeException("Pixmap already disposed");
        }
        return this.pixmap.getPixels();
    }

    public void setPixels(ByteBuffer pixels) {
        ByteBuffer dst = this.pixmap.getPixels();
        BufferUtils.copy(pixels, dst, dst.limit());
    }

    public Format getFormat() {
        return Format.fromGdx2DPixmapFormat(this.pixmap.getFormat());
    }

    public Blending getBlending() {
        return this.blending;
    }

    public Filter getFilter() {
        return this.filter;
    }
}