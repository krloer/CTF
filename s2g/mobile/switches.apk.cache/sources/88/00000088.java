package com.badlogic.gdx.backends.android;

import android.content.Context;
import android.os.Environment;
import java.io.File;
import java.io.IOException;
import java.util.Vector;

/* loaded from: classes.dex */
public class APKExpansionSupport {
    private static final String EXP_PATH = "/Android/obb/";

    static String[] getAPKExpansionFiles(Context ctx, int mainVersion, int patchVersion) {
        String packageName = ctx.getPackageName();
        Vector<String> ret = new Vector<>();
        if (Environment.getExternalStorageState().equals("mounted")) {
            File root = Environment.getExternalStorageDirectory();
            File expPath = new File(root.toString() + EXP_PATH + packageName);
            if (expPath.exists()) {
                if (mainVersion > 0) {
                    String strMainPath = expPath + File.separator + "main." + mainVersion + "." + packageName + ".obb";
                    File main = new File(strMainPath);
                    if (main.isFile()) {
                        ret.add(strMainPath);
                    }
                }
                if (patchVersion > 0) {
                    String strPatchPath = expPath + File.separator + "patch." + patchVersion + "." + packageName + ".obb";
                    File main2 = new File(strPatchPath);
                    if (main2.isFile()) {
                        ret.add(strPatchPath);
                    }
                }
            }
        }
        String[] retArray = new String[ret.size()];
        ret.toArray(retArray);
        return retArray;
    }

    public static ZipResourceFile getResourceZipFile(String[] expansionFiles) throws IOException {
        ZipResourceFile apkExpansionFile = null;
        for (String expansionFilePath : expansionFiles) {
            if (apkExpansionFile == null) {
                apkExpansionFile = new ZipResourceFile(expansionFilePath);
            } else {
                apkExpansionFile.addPatchFile(expansionFilePath);
            }
        }
        return apkExpansionFile;
    }

    public static ZipResourceFile getAPKExpansionZipFile(Context ctx, int mainVersion, int patchVersion) throws IOException {
        String[] expansionFiles = getAPKExpansionFiles(ctx, mainVersion, patchVersion);
        return getResourceZipFile(expansionFiles);
    }
}