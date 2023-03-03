package com.badlogic.gdx.graphics.profiling;

import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public interface GLErrorListener {
    public static final GLErrorListener LOGGING_LISTENER = new GLErrorListener() { // from class: com.badlogic.gdx.graphics.profiling.GLErrorListener.1
        /* JADX WARN: Code restructure failed: missing block: B:10:0x0020, code lost:
            r3 = r1[r2 + 1];
         */
        /* JADX WARN: Code restructure failed: missing block: B:11:0x0028, code lost:
            r0 = r3.getMethodName();
         */
        /* JADX WARN: Code restructure failed: missing block: B:9:0x001e, code lost:
            if ((r2 + 1) >= r1.length) goto L15;
         */
        @Override // com.badlogic.gdx.graphics.profiling.GLErrorListener
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct code enable 'Show inconsistent code' option in preferences
        */
        public void onError(int r6) {
            /*
                r5 = this;
                r0 = 0
                java.lang.Thread r1 = java.lang.Thread.currentThread()     // Catch: java.lang.Exception -> L2e
                java.lang.StackTraceElement[] r1 = r1.getStackTrace()     // Catch: java.lang.Exception -> L2e
                r2 = 0
            La:
                int r3 = r1.length     // Catch: java.lang.Exception -> L2e
                if (r2 >= r3) goto L2d
                java.lang.String r3 = "check"
                r4 = r1[r2]     // Catch: java.lang.Exception -> L2e
                java.lang.String r4 = r4.getMethodName()     // Catch: java.lang.Exception -> L2e
                boolean r3 = r3.equals(r4)     // Catch: java.lang.Exception -> L2e
                if (r3 == 0) goto L2a
                int r3 = r2 + 1
                int r4 = r1.length     // Catch: java.lang.Exception -> L2e
                if (r3 >= r4) goto L2d
                int r3 = r2 + 1
                r3 = r1[r3]     // Catch: java.lang.Exception -> L2e
                java.lang.String r4 = r3.getMethodName()     // Catch: java.lang.Exception -> L2e
                r0 = r4
                goto L2d
            L2a:
                int r2 = r2 + 1
                goto La
            L2d:
                goto L2f
            L2e:
                r1 = move-exception
            L2f:
                java.lang.String r1 = "Error "
                java.lang.String r2 = "GLProfiler"
                if (r0 == 0) goto L56
                com.badlogic.gdx.Application r3 = com.badlogic.gdx.Gdx.app
                java.lang.StringBuilder r4 = new java.lang.StringBuilder
                r4.<init>()
                r4.append(r1)
                java.lang.String r1 = com.badlogic.gdx.graphics.profiling.GLInterceptor.resolveErrorNumber(r6)
                r4.append(r1)
                java.lang.String r1 = " from "
                r4.append(r1)
                r4.append(r0)
                java.lang.String r1 = r4.toString()
                r3.error(r2, r1)
                goto L78
            L56:
                com.badlogic.gdx.Application r3 = com.badlogic.gdx.Gdx.app
                java.lang.StringBuilder r4 = new java.lang.StringBuilder
                r4.<init>()
                r4.append(r1)
                java.lang.String r1 = com.badlogic.gdx.graphics.profiling.GLInterceptor.resolveErrorNumber(r6)
                r4.append(r1)
                java.lang.String r1 = " at: "
                r4.append(r1)
                java.lang.String r1 = r4.toString()
                java.lang.Exception r4 = new java.lang.Exception
                r4.<init>()
                r3.error(r2, r1, r4)
            L78:
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.graphics.profiling.GLErrorListener.AnonymousClass1.onError(int):void");
        }
    };
    public static final GLErrorListener THROWING_LISTENER = new GLErrorListener() { // from class: com.badlogic.gdx.graphics.profiling.GLErrorListener.2
        @Override // com.badlogic.gdx.graphics.profiling.GLErrorListener
        public void onError(int error) {
            throw new GdxRuntimeException("GLProfiler: Got GL error " + GLInterceptor.resolveErrorNumber(error));
        }
    };

    void onError(int i);
}