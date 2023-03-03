package com.badlogic.gdx.backends.android;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import com.badlogic.gdx.Net;
import com.badlogic.gdx.net.NetJavaImpl;
import com.badlogic.gdx.net.NetJavaServerSocketImpl;
import com.badlogic.gdx.net.NetJavaSocketImpl;
import com.badlogic.gdx.net.ServerSocket;
import com.badlogic.gdx.net.ServerSocketHints;
import com.badlogic.gdx.net.Socket;
import com.badlogic.gdx.net.SocketHints;

/* loaded from: classes.dex */
public class AndroidNet implements Net {
    final AndroidApplicationBase app;
    NetJavaImpl netJavaImpl;

    public AndroidNet(AndroidApplicationBase app, AndroidApplicationConfiguration configuration) {
        this.app = app;
        this.netJavaImpl = new NetJavaImpl(configuration.maxNetThreads);
    }

    @Override // com.badlogic.gdx.Net
    public void sendHttpRequest(Net.HttpRequest httpRequest, Net.HttpResponseListener httpResponseListener) {
        this.netJavaImpl.sendHttpRequest(httpRequest, httpResponseListener);
    }

    @Override // com.badlogic.gdx.Net
    public void cancelHttpRequest(Net.HttpRequest httpRequest) {
        this.netJavaImpl.cancelHttpRequest(httpRequest);
    }

    @Override // com.badlogic.gdx.Net
    public ServerSocket newServerSocket(Net.Protocol protocol, String hostname, int port, ServerSocketHints hints) {
        return new NetJavaServerSocketImpl(protocol, hostname, port, hints);
    }

    @Override // com.badlogic.gdx.Net
    public ServerSocket newServerSocket(Net.Protocol protocol, int port, ServerSocketHints hints) {
        return new NetJavaServerSocketImpl(protocol, port, hints);
    }

    @Override // com.badlogic.gdx.Net
    public Socket newClientSocket(Net.Protocol protocol, String host, int port, SocketHints hints) {
        return new NetJavaSocketImpl(protocol, host, port, hints);
    }

    @Override // com.badlogic.gdx.Net
    public boolean openURI(String URI) {
        Uri uri = Uri.parse(URI);
        try {
            Intent intent = new Intent("android.intent.action.VIEW", uri);
            if (!(this.app.getContext() instanceof Activity)) {
                intent.addFlags(268435456);
            }
            this.app.startActivity(intent);
            return true;
        } catch (ActivityNotFoundException e) {
            return false;
        }
    }
}