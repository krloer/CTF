package com.badlogic.gdx.utils;

import com.badlogic.gdx.math.MathUtils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.UUID;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class SharedLibraryLoader {
    public static boolean is64Bit;
    public static boolean isARM;
    public static boolean isAndroid;
    public static boolean isIos;
    public static boolean isLinux;
    public static boolean isMac;
    public static boolean isWindows;
    private static final HashSet<String> loadedLibraries;
    private String nativesJar;

    static {
        isWindows = System.getProperty("os.name").contains("Windows");
        isLinux = System.getProperty("os.name").contains("Linux");
        isMac = System.getProperty("os.name").contains("Mac");
        isIos = false;
        isAndroid = false;
        isARM = System.getProperty("os.arch").startsWith("arm") || System.getProperty("os.arch").startsWith("aarch64");
        is64Bit = System.getProperty("os.arch").contains("64") || System.getProperty("os.arch").startsWith("armv8");
        String vm = System.getProperty("java.runtime.name");
        if (vm != null && vm.contains("Android Runtime")) {
            isAndroid = true;
            isWindows = false;
            isLinux = false;
            isMac = false;
            is64Bit = false;
        }
        if (!isAndroid && !isWindows && !isLinux && !isMac) {
            isIos = true;
            isAndroid = false;
            isWindows = false;
            isLinux = false;
            isMac = false;
            is64Bit = false;
        }
        loadedLibraries = new HashSet<>();
    }

    public SharedLibraryLoader() {
    }

    static String randomUUID() {
        return new UUID(MathUtils.random.nextLong(), MathUtils.random.nextLong()).toString();
    }

    public SharedLibraryLoader(String nativesJar) {
        this.nativesJar = nativesJar;
    }

    public String crc(InputStream input) {
        if (input == null) {
            throw new IllegalArgumentException("input cannot be null.");
        }
        CRC32 crc = new CRC32();
        byte[] buffer = new byte[4096];
        while (true) {
            try {
                int length = input.read(buffer);
                if (length == -1) {
                    break;
                }
                crc.update(buffer, 0, length);
            } catch (Exception e) {
            } catch (Throwable th) {
                StreamUtils.closeQuietly(input);
                throw th;
            }
        }
        StreamUtils.closeQuietly(input);
        return Long.toString(crc.getValue(), 16);
    }

    public String mapLibraryName(String libraryName) {
        if (isWindows) {
            java.lang.StringBuilder sb = new java.lang.StringBuilder();
            sb.append(libraryName);
            sb.append(is64Bit ? "64.dll" : ".dll");
            return sb.toString();
        } else if (isLinux) {
            java.lang.StringBuilder sb2 = new java.lang.StringBuilder();
            sb2.append("lib");
            sb2.append(libraryName);
            sb2.append(isARM ? "arm" : BuildConfig.FLAVOR);
            sb2.append(is64Bit ? "64.so" : ".so");
            return sb2.toString();
        } else if (isMac) {
            java.lang.StringBuilder sb3 = new java.lang.StringBuilder();
            sb3.append("lib");
            sb3.append(libraryName);
            sb3.append(is64Bit ? "64.dylib" : ".dylib");
            return sb3.toString();
        } else {
            return libraryName;
        }
    }

    public void load(String libraryName) {
        if (isIos) {
            return;
        }
        synchronized (SharedLibraryLoader.class) {
            if (isLoaded(libraryName)) {
                return;
            }
            String platformName = mapLibraryName(libraryName);
            if (isAndroid) {
                System.loadLibrary(platformName);
            } else {
                loadFile(platformName);
            }
            setLoaded(libraryName);
        }
    }

    private InputStream readFile(String path) {
        String str = this.nativesJar;
        if (str == null) {
            InputStream input = SharedLibraryLoader.class.getResourceAsStream("/" + path);
            if (input == null) {
                throw new GdxRuntimeException("Unable to read file for extraction: " + path);
            }
            return input;
        }
        try {
            ZipFile file = new ZipFile(str);
            ZipEntry entry = file.getEntry(path);
            if (entry == null) {
                throw new GdxRuntimeException("Couldn't find '" + path + "' in JAR: " + this.nativesJar);
            }
            return file.getInputStream(entry);
        } catch (IOException ex) {
            throw new GdxRuntimeException("Error reading '" + path + "' in JAR: " + this.nativesJar, ex);
        }
    }

    public File extractFile(String sourcePath, String dirName) throws IOException {
        try {
            String sourceCrc = crc(readFile(sourcePath));
            if (dirName == null) {
                dirName = sourceCrc;
            }
            File extractedFile = getExtractedFile(dirName, new File(sourcePath).getName());
            if (extractedFile == null && (extractedFile = getExtractedFile(randomUUID().toString(), new File(sourcePath).getName())) == null) {
                throw new GdxRuntimeException("Unable to find writable path to extract file. Is the user home directory writable?");
            }
            return extractFile(sourcePath, sourceCrc, extractedFile);
        } catch (RuntimeException ex) {
            File file = new File(System.getProperty("java.library.path"), sourcePath);
            if (file.exists()) {
                return file;
            }
            throw ex;
        }
    }

    public void extractFileTo(String sourcePath, File dir) throws IOException {
        extractFile(sourcePath, crc(readFile(sourcePath)), new File(dir, new File(sourcePath).getName()));
    }

    private File getExtractedFile(String dirName, String fileName) {
        File idealFile = new File(System.getProperty("java.io.tmpdir") + "/libgdx" + System.getProperty("user.name") + "/" + dirName, fileName);
        if (canWrite(idealFile)) {
            return idealFile;
        }
        try {
            File file = File.createTempFile(dirName, null);
            if (file.delete()) {
                File file2 = new File(file, fileName);
                if (canWrite(file2)) {
                    return file2;
                }
            }
        } catch (IOException e) {
        }
        File file3 = new File(System.getProperty("user.home") + "/.libgdx/" + dirName, fileName);
        if (canWrite(file3)) {
            return file3;
        }
        File file4 = new File(".temp/" + dirName, fileName);
        if (canWrite(file4)) {
            return file4;
        }
        if (System.getenv("APP_SANDBOX_CONTAINER_ID") != null) {
            return idealFile;
        }
        return null;
    }

    private boolean canWrite(File file) {
        File testFile;
        File parent = file.getParentFile();
        if (file.exists()) {
            if (!file.canWrite() || !canExecute(file)) {
                return false;
            }
            testFile = new File(parent, randomUUID());
        } else {
            parent.mkdirs();
            if (!parent.isDirectory()) {
                return false;
            }
            testFile = file;
        }
        try {
            new FileOutputStream(testFile).close();
            if (!canExecute(testFile)) {
                testFile.delete();
                return false;
            }
            testFile.delete();
            return true;
        } catch (Throwable th) {
            testFile.delete();
            return false;
        }
    }

    private boolean canExecute(File file) {
        try {
            Method canExecute = File.class.getMethod("canExecute", new Class[0]);
            if (((Boolean) canExecute.invoke(file, new Object[0])).booleanValue()) {
                return true;
            }
            Method setExecutable = File.class.getMethod("setExecutable", Boolean.TYPE, Boolean.TYPE);
            setExecutable.invoke(file, true, false);
            return ((Boolean) canExecute.invoke(file, new Object[0])).booleanValue();
        } catch (Exception e) {
            return false;
        }
    }

    private File extractFile(String sourcePath, String sourceCrc, File extractedFile) throws IOException {
        String extractedCrc = null;
        if (extractedFile.exists()) {
            try {
                extractedCrc = crc(new FileInputStream(extractedFile));
            } catch (FileNotFoundException e) {
            }
        }
        if (extractedCrc == null || !extractedCrc.equals(sourceCrc)) {
            InputStream input = null;
            FileOutputStream output = null;
            try {
                try {
                    input = readFile(sourcePath);
                    extractedFile.getParentFile().mkdirs();
                    output = new FileOutputStream(extractedFile);
                    byte[] buffer = new byte[4096];
                    while (true) {
                        int length = input.read(buffer);
                        if (length == -1) {
                            break;
                        }
                        output.write(buffer, 0, length);
                    }
                } finally {
                    StreamUtils.closeQuietly(input);
                    StreamUtils.closeQuietly(output);
                }
            } catch (IOException ex) {
                throw new GdxRuntimeException("Error extracting file: " + sourcePath + "\nTo: " + extractedFile.getAbsolutePath(), ex);
            }
        }
        return extractedFile;
    }

    private void loadFile(String sourcePath) {
        String sourceCrc = crc(readFile(sourcePath));
        String fileName = new File(sourcePath).getName();
        File file = new File(System.getProperty("java.io.tmpdir") + "/libgdx" + System.getProperty("user.name") + "/" + sourceCrc, fileName);
        Throwable ex = loadFile(sourcePath, sourceCrc, file);
        if (ex == null) {
            return;
        }
        try {
            File file2 = File.createTempFile(sourceCrc, null);
            if (file2.delete()) {
                if (loadFile(sourcePath, sourceCrc, file2) == null) {
                    return;
                }
            }
        } catch (Throwable th) {
        }
        File file3 = new File(System.getProperty("user.home") + "/.libgdx/" + sourceCrc, fileName);
        if (loadFile(sourcePath, sourceCrc, file3) == null) {
            return;
        }
        File file4 = new File(".temp/" + sourceCrc, fileName);
        if (loadFile(sourcePath, sourceCrc, file4) == null) {
            return;
        }
        File file5 = new File(System.getProperty("java.library.path"), sourcePath);
        if (file5.exists()) {
            System.load(file5.getAbsolutePath());
            return;
        }
        throw new GdxRuntimeException(ex);
    }

    private Throwable loadFile(String sourcePath, String sourceCrc, File extractedFile) {
        try {
            System.load(extractFile(sourcePath, sourceCrc, extractedFile).getAbsolutePath());
            return null;
        } catch (Throwable ex) {
            return ex;
        }
    }

    public static synchronized void setLoaded(String libraryName) {
        synchronized (SharedLibraryLoader.class) {
            loadedLibraries.add(libraryName);
        }
    }

    public static synchronized boolean isLoaded(String libraryName) {
        boolean contains;
        synchronized (SharedLibraryLoader.class) {
            contains = loadedLibraries.contains(libraryName);
        }
        return contains;
    }
}