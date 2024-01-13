package com.badlogic.gdx.graphics.glutils;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class GLVersion {
    private final String TAG = "GLVersion";
    private int majorVersion;
    private int minorVersion;
    private int releaseVersion;
    private final String rendererString;
    private final Type type;
    private final String vendorString;

    /* loaded from: classes.dex */
    public enum Type {
        OpenGL,
        GLES,
        WebGL,
        NONE
    }

    public GLVersion(Application.ApplicationType appType, String versionString, String vendorString, String rendererString) {
        if (appType == Application.ApplicationType.Android) {
            this.type = Type.GLES;
        } else if (appType == Application.ApplicationType.iOS) {
            this.type = Type.GLES;
        } else if (appType == Application.ApplicationType.Desktop) {
            this.type = Type.OpenGL;
        } else if (appType == Application.ApplicationType.Applet) {
            this.type = Type.OpenGL;
        } else if (appType == Application.ApplicationType.WebGL) {
            this.type = Type.WebGL;
        } else {
            this.type = Type.NONE;
        }
        if (this.type == Type.GLES) {
            extractVersion("OpenGL ES (\\d(\\.\\d){0,2})", versionString);
        } else if (this.type == Type.WebGL) {
            extractVersion("WebGL (\\d(\\.\\d){0,2})", versionString);
        } else if (this.type == Type.OpenGL) {
            extractVersion("(\\d(\\.\\d){0,2})", versionString);
        } else {
            this.majorVersion = -1;
            this.minorVersion = -1;
            this.releaseVersion = -1;
            vendorString = BuildConfig.FLAVOR;
            rendererString = BuildConfig.FLAVOR;
        }
        this.vendorString = vendorString;
        this.rendererString = rendererString;
    }

    private void extractVersion(String patternString, String versionString) {
        Pattern pattern = Pattern.compile(patternString);
        Matcher matcher = pattern.matcher(versionString);
        boolean found = matcher.find();
        if (found) {
            String result = matcher.group(1);
            String[] resultSplit = result.split("\\.");
            this.majorVersion = parseInt(resultSplit[0], 2);
            this.minorVersion = resultSplit.length < 2 ? 0 : parseInt(resultSplit[1], 0);
            this.releaseVersion = resultSplit.length >= 3 ? parseInt(resultSplit[2], 0) : 0;
            return;
        }
        Application application = Gdx.app;
        application.log("GLVersion", "Invalid version string: " + versionString);
        this.majorVersion = 2;
        this.minorVersion = 0;
        this.releaseVersion = 0;
    }

    private int parseInt(String v, int defaultValue) {
        try {
            return Integer.parseInt(v);
        } catch (NumberFormatException e) {
            Application application = Gdx.app;
            application.error("LibGDX GL", "Error parsing number: " + v + ", assuming: " + defaultValue);
            return defaultValue;
        }
    }

    public Type getType() {
        return this.type;
    }

    public int getMajorVersion() {
        return this.majorVersion;
    }

    public int getMinorVersion() {
        return this.minorVersion;
    }

    public int getReleaseVersion() {
        return this.releaseVersion;
    }

    public String getVendorString() {
        return this.vendorString;
    }

    public String getRendererString() {
        return this.rendererString;
    }

    public boolean isVersionEqualToOrHigher(int testMajorVersion, int testMinorVersion) {
        int i = this.majorVersion;
        return i > testMajorVersion || (i == testMajorVersion && this.minorVersion >= testMinorVersion);
    }

    public String getDebugVersionString() {
        return "Type: " + this.type + "\nVersion: " + this.majorVersion + ":" + this.minorVersion + ":" + this.releaseVersion + "\nVendor: " + this.vendorString + "\nRenderer: " + this.rendererString;
    }
}