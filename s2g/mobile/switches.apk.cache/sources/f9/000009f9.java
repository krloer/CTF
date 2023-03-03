package s2g.project.game;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: Configuration.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0010\u0007\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0002\b\b\bÆ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u001a\u0010\u0003\u001a\u00020\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0005\u0010\u0006\"\u0004\b\u0007\u0010\bR\u001a\u0010\t\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000eR\u001a\u0010\u000f\u001a\u00020\u0010X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0011\u0010\u0012\"\u0004\b\u0013\u0010\u0014R\u001a\u0010\u0015\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0016\u0010\f\"\u0004\b\u0017\u0010\u000e¨\u0006\u0018"}, d2 = {"Ls2g/project/game/Configuration;", BuildConfig.FLAVOR, "()V", BuildConfig.BUILD_TYPE, BuildConfig.FLAVOR, "getDebug", "()Z", "setDebug", "(Z)V", "gameHeight", BuildConfig.FLAVOR, "getGameHeight", "()F", "setGameHeight", "(F)V", "gameTitle", BuildConfig.FLAVOR, "getGameTitle", "()Ljava/lang/String;", "setGameTitle", "(Ljava/lang/String;)V", "gameWidth", "getGameWidth", "setGameWidth", "core"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class Configuration {
    private static boolean debug;
    public static final Configuration INSTANCE = new Configuration();
    private static float gameWidth = 960.0f;
    private static float gameHeight = 640.0f;
    private static String gameTitle = "Switches";

    private Configuration() {
    }

    public final float getGameWidth() {
        return gameWidth;
    }

    public final void setGameWidth(float f) {
        gameWidth = f;
    }

    public final float getGameHeight() {
        return gameHeight;
    }

    public final void setGameHeight(float f) {
        gameHeight = f;
    }

    public final String getGameTitle() {
        return gameTitle;
    }

    public final void setGameTitle(String str) {
        Intrinsics.checkParameterIsNotNull(str, "<set-?>");
        gameTitle = str;
    }

    public final boolean getDebug() {
        return debug;
    }

    public final void setDebug(boolean z) {
        debug = z;
    }
}