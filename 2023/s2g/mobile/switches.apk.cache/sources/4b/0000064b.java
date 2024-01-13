package com.kotcrab.vis.ui.widget.file;

import com.apple.eio.FileManager;
import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.util.OsUtils;
import java.io.File;
import java.io.IOException;
import java.text.DecimalFormat;
import java.util.Comparator;

/* loaded from: classes.dex */
public class FileUtils {
    private static final String[] UNITS = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
    public static final Comparator<FileHandle> FILE_NAME_COMPARATOR = new Comparator<FileHandle>() { // from class: com.kotcrab.vis.ui.widget.file.FileUtils.1
        @Override // java.util.Comparator
        public int compare(FileHandle f1, FileHandle f2) {
            return f1.name().toLowerCase().compareTo(f2.name().toLowerCase());
        }
    };
    public static final Comparator<FileHandle> FILE_MODIFIED_DATE_COMPARATOR = new Comparator<FileHandle>() { // from class: com.kotcrab.vis.ui.widget.file.FileUtils.2
        @Override // java.util.Comparator
        public int compare(FileHandle f1, FileHandle f2) {
            long l1 = f1.lastModified();
            long l2 = f2.lastModified();
            if (l1 > l2) {
                return 1;
            }
            if (l1 == l2) {
                return FileUtils.FILE_NAME_COMPARATOR.compare(f1, f2);
            }
            return -1;
        }
    };
    public static final Comparator<FileHandle> FILE_SIZE_COMPARATOR = new Comparator<FileHandle>() { // from class: com.kotcrab.vis.ui.widget.file.FileUtils.3
        @Override // java.util.Comparator
        public int compare(FileHandle f1, FileHandle f2) {
            long l1 = f1.length();
            long l2 = f2.length();
            if (l1 > l2) {
                return -1;
            }
            if (l1 == l2) {
                return FileUtils.FILE_NAME_COMPARATOR.compare(f1, f2);
            }
            return 1;
        }
    };

    public static String readableFileSize(long size) {
        if (size <= 0) {
            return "0 B";
        }
        int digitGroups = (int) (Math.log10(size) / Math.log10(1024.0d));
        StringBuilder sb = new StringBuilder();
        DecimalFormat decimalFormat = new DecimalFormat("#,##0.#");
        double d = size;
        double pow = Math.pow(1024.0d, digitGroups);
        Double.isNaN(d);
        sb.append(decimalFormat.format(d / pow).replace(",", "."));
        sb.append(" ");
        sb.append(UNITS[digitGroups]);
        return sb.toString();
    }

    public static Array<FileHandle> sortFiles(FileHandle[] files) {
        return sortFiles(files, FILE_NAME_COMPARATOR);
    }

    public static Array<FileHandle> sortFiles(FileHandle[] files, Comparator<FileHandle> comparator) {
        return sortFiles(files, comparator, false);
    }

    public static Array<FileHandle> sortFiles(FileHandle[] files, Comparator<FileHandle> comparator, boolean descending) {
        Array<FileHandle> directoriesList = new Array<>();
        Array<FileHandle> filesList = new Array<>();
        for (FileHandle f : files) {
            if (f.isDirectory()) {
                directoriesList.add(f);
            } else {
                filesList.add(f);
            }
        }
        directoriesList.sort(comparator);
        filesList.sort(comparator);
        if (descending) {
            directoriesList.reverse();
            filesList.reverse();
        }
        directoriesList.addAll(filesList);
        return directoriesList;
    }

    public static boolean isValidFileName(String name) {
        try {
            if (OsUtils.isWindows()) {
                if (!name.contains(">") && !name.contains("<")) {
                    name = name.toLowerCase();
                }
                return false;
            }
            return new File(name).getCanonicalFile().getName().equals(name);
        } catch (Exception e) {
            return false;
        }
    }

    public static FileHandle toFileHandle(File file) {
        return Gdx.files.absolute(file.getAbsolutePath());
    }

    public static void showDirInExplorer(FileHandle dir) throws IOException {
        File dirToShow;
        if (dir.isDirectory()) {
            dirToShow = dir.file();
        } else {
            dirToShow = dir.parent().file();
        }
        if (OsUtils.isMac()) {
            FileManager.revealInFinder(dirToShow);
            return;
        }
        try {
            Class desktopClass = Class.forName("java.awt.Desktop");
            Object desktop = desktopClass.getMethod("getDesktop", new Class[0]).invoke(null, new Object[0]);
            desktopClass.getMethod("open", File.class).invoke(desktop, dirToShow);
        } catch (Exception e) {
            Application application = Gdx.app;
            application.log("VisUI", "Can't open file " + dirToShow.getPath(), e);
        }
    }
}