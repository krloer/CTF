package com.badlogic.gdx;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.net.HttpStatus;
import com.badlogic.gdx.net.ServerSocket;
import com.badlogic.gdx.net.ServerSocketHints;
import com.badlogic.gdx.net.Socket;
import com.badlogic.gdx.net.SocketHints;
import com.badlogic.gdx.utils.Pool;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* loaded from: classes.dex */
public interface Net {

    /* loaded from: classes.dex */
    public interface HttpMethods {
        public static final String DELETE = "DELETE";
        public static final String GET = "GET";
        public static final String HEAD = "HEAD";
        public static final String PATCH = "PATCH";
        public static final String POST = "POST";
        public static final String PUT = "PUT";
    }

    /* loaded from: classes.dex */
    public interface HttpResponse {
        String getHeader(String str);

        Map<String, List<String>> getHeaders();

        byte[] getResult();

        InputStream getResultAsStream();

        String getResultAsString();

        HttpStatus getStatus();
    }

    /* loaded from: classes.dex */
    public interface HttpResponseListener {
        void cancelled();

        void failed(Throwable th);

        void handleHttpResponse(HttpResponse httpResponse);
    }

    /* loaded from: classes.dex */
    public enum Protocol {
        TCP
    }

    void cancelHttpRequest(HttpRequest httpRequest);

    Socket newClientSocket(Protocol protocol, String str, int i, SocketHints socketHints);

    ServerSocket newServerSocket(Protocol protocol, int i, ServerSocketHints serverSocketHints);

    ServerSocket newServerSocket(Protocol protocol, String str, int i, ServerSocketHints serverSocketHints);

    boolean openURI(String str);

    void sendHttpRequest(HttpRequest httpRequest, HttpResponseListener httpResponseListener);

    /* loaded from: classes.dex */
    public static class HttpRequest implements Pool.Poolable {
        private String content;
        private long contentLength;
        private InputStream contentStream;
        private boolean followRedirects;
        private Map<String, String> headers;
        private String httpMethod;
        private boolean includeCredentials;
        private int timeOut;
        private String url;

        public HttpRequest() {
            this.timeOut = 0;
            this.followRedirects = true;
            this.includeCredentials = false;
            this.headers = new HashMap();
        }

        public HttpRequest(String httpMethod) {
            this();
            this.httpMethod = httpMethod;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public void setHeader(String name, String value) {
            this.headers.put(name, value);
        }

        public void setContent(String content) {
            this.content = content;
        }

        public void setContent(InputStream contentStream, long contentLength) {
            this.contentStream = contentStream;
            this.contentLength = contentLength;
        }

        public void setTimeOut(int timeOut) {
            this.timeOut = timeOut;
        }

        public void setFollowRedirects(boolean followRedirects) throws IllegalArgumentException {
            if (followRedirects || Gdx.app.getType() != Application.ApplicationType.WebGL) {
                this.followRedirects = followRedirects;
                return;
            }
            throw new IllegalArgumentException("Following redirects can't be disabled using the GWT/WebGL backend!");
        }

        public void setIncludeCredentials(boolean includeCredentials) {
            this.includeCredentials = includeCredentials;
        }

        public void setMethod(String httpMethod) {
            this.httpMethod = httpMethod;
        }

        public int getTimeOut() {
            return this.timeOut;
        }

        public String getMethod() {
            return this.httpMethod;
        }

        public String getUrl() {
            return this.url;
        }

        public String getContent() {
            return this.content;
        }

        public InputStream getContentStream() {
            return this.contentStream;
        }

        public long getContentLength() {
            return this.contentLength;
        }

        public Map<String, String> getHeaders() {
            return this.headers;
        }

        public boolean getFollowRedirects() {
            return this.followRedirects;
        }

        public boolean getIncludeCredentials() {
            return this.includeCredentials;
        }

        @Override // com.badlogic.gdx.utils.Pool.Poolable
        public void reset() {
            this.httpMethod = null;
            this.url = null;
            this.headers.clear();
            this.timeOut = 0;
            this.content = null;
            this.contentStream = null;
            this.contentLength = 0L;
            this.followRedirects = true;
        }
    }
}