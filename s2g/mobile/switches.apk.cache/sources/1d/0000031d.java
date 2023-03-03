package com.badlogic.gdx.net;

import com.badlogic.gdx.Net;
import com.badlogic.gdx.utils.ObjectMap;
import com.badlogic.gdx.utils.StreamUtils;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.jvm.internal.IntCompanionObject;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class NetJavaImpl {
    final ObjectMap<Net.HttpRequest, HttpURLConnection> connections;
    private final ThreadPoolExecutor executorService;
    final ObjectMap<Net.HttpRequest, Net.HttpResponseListener> listeners;

    /* loaded from: classes.dex */
    static class HttpClientResponse implements Net.HttpResponse {
        private final HttpURLConnection connection;
        private HttpStatus status;

        public HttpClientResponse(HttpURLConnection connection) throws IOException {
            this.connection = connection;
            try {
                this.status = new HttpStatus(connection.getResponseCode());
            } catch (IOException e) {
                this.status = new HttpStatus(-1);
            }
        }

        @Override // com.badlogic.gdx.Net.HttpResponse
        public byte[] getResult() {
            InputStream input = getInputStream();
            if (input == null) {
                return StreamUtils.EMPTY_BYTES;
            }
            try {
                return StreamUtils.copyStreamToByteArray(input, this.connection.getContentLength());
            } catch (IOException e) {
                return StreamUtils.EMPTY_BYTES;
            } finally {
                StreamUtils.closeQuietly(input);
            }
        }

        @Override // com.badlogic.gdx.Net.HttpResponse
        public String getResultAsString() {
            InputStream input = getInputStream();
            if (input == null) {
                return BuildConfig.FLAVOR;
            }
            try {
                return StreamUtils.copyStreamToString(input, this.connection.getContentLength(), "UTF8");
            } catch (IOException e) {
                return BuildConfig.FLAVOR;
            } finally {
                StreamUtils.closeQuietly(input);
            }
        }

        @Override // com.badlogic.gdx.Net.HttpResponse
        public InputStream getResultAsStream() {
            return getInputStream();
        }

        @Override // com.badlogic.gdx.Net.HttpResponse
        public HttpStatus getStatus() {
            return this.status;
        }

        @Override // com.badlogic.gdx.Net.HttpResponse
        public String getHeader(String name) {
            return this.connection.getHeaderField(name);
        }

        @Override // com.badlogic.gdx.Net.HttpResponse
        public Map<String, List<String>> getHeaders() {
            return this.connection.getHeaderFields();
        }

        private InputStream getInputStream() {
            try {
                return this.connection.getInputStream();
            } catch (IOException e) {
                return this.connection.getErrorStream();
            }
        }
    }

    public NetJavaImpl() {
        this(IntCompanionObject.MAX_VALUE);
    }

    public NetJavaImpl(int maxThreads) {
        boolean isCachedPool = maxThreads == Integer.MAX_VALUE;
        this.executorService = new ThreadPoolExecutor(isCachedPool ? 0 : maxThreads, maxThreads, 60L, TimeUnit.SECONDS, isCachedPool ? new SynchronousQueue() : new LinkedBlockingQueue(), new ThreadFactory() { // from class: com.badlogic.gdx.net.NetJavaImpl.1
            AtomicInteger threadID = new AtomicInteger();

            @Override // java.util.concurrent.ThreadFactory
            public Thread newThread(Runnable r) {
                Thread thread = new Thread(r, "NetThread" + this.threadID.getAndIncrement());
                thread.setDaemon(true);
                return thread;
            }
        });
        this.executorService.allowCoreThreadTimeOut(isCachedPool ? false : true);
        this.connections = new ObjectMap<>();
        this.listeners = new ObjectMap<>();
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x00bc A[Catch: Exception -> 0x00f2, LOOP:0: B:32:0x00b6->B:34:0x00bc, LOOP_END, TryCatch #1 {Exception -> 0x00f2, blocks: (B:6:0x0015, B:10:0x0024, B:12:0x002c, B:14:0x0034, B:19:0x0040, B:21:0x0048, B:24:0x004f, B:31:0x0091, B:32:0x00b6, B:34:0x00bc, B:35:0x00d2, B:25:0x0059, B:27:0x0060, B:29:0x0066, B:30:0x0078), top: B:47:0x0015 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public void sendHttpRequest(final com.badlogic.gdx.Net.HttpRequest r14, final com.badlogic.gdx.Net.HttpResponseListener r15) {
        /*
            Method dump skipped, instructions count: 258
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.net.NetJavaImpl.sendHttpRequest(com.badlogic.gdx.Net$HttpRequest, com.badlogic.gdx.Net$HttpResponseListener):void");
    }

    public void cancelHttpRequest(Net.HttpRequest httpRequest) {
        Net.HttpResponseListener httpResponseListener = getFromListeners(httpRequest);
        if (httpResponseListener != null) {
            httpResponseListener.cancelled();
            removeFromConnectionsAndListeners(httpRequest);
        }
    }

    synchronized void removeFromConnectionsAndListeners(Net.HttpRequest httpRequest) {
        this.connections.remove(httpRequest);
        this.listeners.remove(httpRequest);
    }

    synchronized void putIntoConnectionsAndListeners(Net.HttpRequest httpRequest, Net.HttpResponseListener httpResponseListener, HttpURLConnection connection) {
        this.connections.put(httpRequest, connection);
        this.listeners.put(httpRequest, httpResponseListener);
    }

    synchronized Net.HttpResponseListener getFromListeners(Net.HttpRequest httpRequest) {
        Net.HttpResponseListener httpResponseListener;
        httpResponseListener = this.listeners.get(httpRequest);
        return httpResponseListener;
    }
}