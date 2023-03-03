package com.badlogic.gdx.net;

import com.badlogic.gdx.Net;
import com.badlogic.gdx.utils.Base64Coder;
import com.badlogic.gdx.utils.Json;
import com.badlogic.gdx.utils.Pools;
import java.io.InputStream;
import java.util.Map;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class HttpRequestBuilder {
    public static String baseUrl = BuildConfig.FLAVOR;
    public static int defaultTimeout = 1000;
    public static Json json = new Json();
    private Net.HttpRequest httpRequest;

    public HttpRequestBuilder newRequest() {
        if (this.httpRequest != null) {
            throw new IllegalStateException("A new request has already been started. Call HttpRequestBuilder.build() first.");
        }
        this.httpRequest = (Net.HttpRequest) Pools.obtain(Net.HttpRequest.class);
        this.httpRequest.setTimeOut(defaultTimeout);
        return this;
    }

    public HttpRequestBuilder method(String httpMethod) {
        validate();
        this.httpRequest.setMethod(httpMethod);
        return this;
    }

    public HttpRequestBuilder url(String url) {
        validate();
        Net.HttpRequest httpRequest = this.httpRequest;
        httpRequest.setUrl(baseUrl + url);
        return this;
    }

    public HttpRequestBuilder timeout(int timeOut) {
        validate();
        this.httpRequest.setTimeOut(timeOut);
        return this;
    }

    public HttpRequestBuilder followRedirects(boolean followRedirects) {
        validate();
        this.httpRequest.setFollowRedirects(followRedirects);
        return this;
    }

    public HttpRequestBuilder includeCredentials(boolean includeCredentials) {
        validate();
        this.httpRequest.setIncludeCredentials(includeCredentials);
        return this;
    }

    public HttpRequestBuilder header(String name, String value) {
        validate();
        this.httpRequest.setHeader(name, value);
        return this;
    }

    public HttpRequestBuilder content(String content) {
        validate();
        this.httpRequest.setContent(content);
        return this;
    }

    public HttpRequestBuilder content(InputStream contentStream, long contentLength) {
        validate();
        this.httpRequest.setContent(contentStream, contentLength);
        return this;
    }

    public HttpRequestBuilder formEncodedContent(Map<String, String> content) {
        validate();
        this.httpRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");
        String formEncodedContent = HttpParametersUtils.convertHttpParameters(content);
        this.httpRequest.setContent(formEncodedContent);
        return this;
    }

    public HttpRequestBuilder jsonContent(Object content) {
        validate();
        this.httpRequest.setHeader("Content-Type", "application/json");
        String jsonContent = json.toJson(content);
        this.httpRequest.setContent(jsonContent);
        return this;
    }

    public HttpRequestBuilder basicAuthentication(String username, String password) {
        validate();
        Net.HttpRequest httpRequest = this.httpRequest;
        StringBuilder sb = new StringBuilder();
        sb.append("Basic ");
        sb.append(Base64Coder.encodeString(username + ":" + password));
        httpRequest.setHeader(HttpRequestHeader.Authorization, sb.toString());
        return this;
    }

    public Net.HttpRequest build() {
        validate();
        Net.HttpRequest request = this.httpRequest;
        this.httpRequest = null;
        return request;
    }

    private void validate() {
        if (this.httpRequest == null) {
            throw new IllegalStateException("A new request has not been started yet. Call HttpRequestBuilder.newRequest() first.");
        }
    }
}