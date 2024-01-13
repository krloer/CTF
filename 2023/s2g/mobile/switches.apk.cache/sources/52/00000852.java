package kotlin.io;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.Sequence;
import kotlin.text.StringsKt;
import s2g.project.game.BuildConfig;

/* compiled from: Utils.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000<\n\u0000\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0010 \n\u0000\n\u0002\u0018\u0002\n\u0002\b\f\u001a(\u0010\t\u001a\u00020\u00022\b\b\u0002\u0010\n\u001a\u00020\u00012\n\b\u0002\u0010\u000b\u001a\u0004\u0018\u00010\u00012\n\b\u0002\u0010\f\u001a\u0004\u0018\u00010\u0002\u001a(\u0010\r\u001a\u00020\u00022\b\b\u0002\u0010\n\u001a\u00020\u00012\n\b\u0002\u0010\u000b\u001a\u0004\u0018\u00010\u00012\n\b\u0002\u0010\f\u001a\u0004\u0018\u00010\u0002\u001a8\u0010\u000e\u001a\u00020\u000f*\u00020\u00022\u0006\u0010\u0010\u001a\u00020\u00022\b\b\u0002\u0010\u0011\u001a\u00020\u000f2\u001a\b\u0002\u0010\u0012\u001a\u0014\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0014\u0012\u0004\u0012\u00020\u00150\u0013\u001a&\u0010\u0016\u001a\u00020\u0002*\u00020\u00022\u0006\u0010\u0010\u001a\u00020\u00022\b\b\u0002\u0010\u0011\u001a\u00020\u000f2\b\b\u0002\u0010\u0017\u001a\u00020\u0018\u001a\n\u0010\u0019\u001a\u00020\u000f*\u00020\u0002\u001a\u0012\u0010\u001a\u001a\u00020\u000f*\u00020\u00022\u0006\u0010\u001b\u001a\u00020\u0002\u001a\u0012\u0010\u001a\u001a\u00020\u000f*\u00020\u00022\u0006\u0010\u001b\u001a\u00020\u0001\u001a\n\u0010\u001c\u001a\u00020\u0002*\u00020\u0002\u001a\u001d\u0010\u001c\u001a\b\u0012\u0004\u0012\u00020\u00020\u001d*\b\u0012\u0004\u0012\u00020\u00020\u001dH\u0002¢\u0006\u0002\b\u001e\u001a\u0011\u0010\u001c\u001a\u00020\u001f*\u00020\u001fH\u0002¢\u0006\u0002\b\u001e\u001a\u0012\u0010 \u001a\u00020\u0002*\u00020\u00022\u0006\u0010!\u001a\u00020\u0002\u001a\u0014\u0010\"\u001a\u0004\u0018\u00010\u0002*\u00020\u00022\u0006\u0010!\u001a\u00020\u0002\u001a\u0012\u0010#\u001a\u00020\u0002*\u00020\u00022\u0006\u0010!\u001a\u00020\u0002\u001a\u0012\u0010$\u001a\u00020\u0002*\u00020\u00022\u0006\u0010%\u001a\u00020\u0002\u001a\u0012\u0010$\u001a\u00020\u0002*\u00020\u00022\u0006\u0010%\u001a\u00020\u0001\u001a\u0012\u0010&\u001a\u00020\u0002*\u00020\u00022\u0006\u0010%\u001a\u00020\u0002\u001a\u0012\u0010&\u001a\u00020\u0002*\u00020\u00022\u0006\u0010%\u001a\u00020\u0001\u001a\u0012\u0010'\u001a\u00020\u000f*\u00020\u00022\u0006\u0010\u001b\u001a\u00020\u0002\u001a\u0012\u0010'\u001a\u00020\u000f*\u00020\u00022\u0006\u0010\u001b\u001a\u00020\u0001\u001a\u0012\u0010(\u001a\u00020\u0001*\u00020\u00022\u0006\u0010!\u001a\u00020\u0002\u001a\u001b\u0010)\u001a\u0004\u0018\u00010\u0001*\u00020\u00022\u0006\u0010!\u001a\u00020\u0002H\u0002¢\u0006\u0002\b*\"\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00028F¢\u0006\u0006\u001a\u0004\b\u0003\u0010\u0004\"\u0015\u0010\u0005\u001a\u00020\u0001*\u00020\u00028F¢\u0006\u0006\u001a\u0004\b\u0006\u0010\u0004\"\u0015\u0010\u0007\u001a\u00020\u0001*\u00020\u00028F¢\u0006\u0006\u001a\u0004\b\b\u0010\u0004¨\u0006+"}, d2 = {"extension", BuildConfig.FLAVOR, "Ljava/io/File;", "getExtension", "(Ljava/io/File;)Ljava/lang/String;", "invariantSeparatorsPath", "getInvariantSeparatorsPath", "nameWithoutExtension", "getNameWithoutExtension", "createTempDir", "prefix", "suffix", "directory", "createTempFile", "copyRecursively", BuildConfig.FLAVOR, "target", "overwrite", "onError", "Lkotlin/Function2;", "Ljava/io/IOException;", "Lkotlin/io/OnErrorAction;", "copyTo", "bufferSize", BuildConfig.FLAVOR, "deleteRecursively", "endsWith", "other", "normalize", BuildConfig.FLAVOR, "normalize$FilesKt__UtilsKt", "Lkotlin/io/FilePathComponents;", "relativeTo", "base", "relativeToOrNull", "relativeToOrSelf", "resolve", "relative", "resolveSibling", "startsWith", "toRelativeString", "toRelativeStringOrNull", "toRelativeStringOrNull$FilesKt__UtilsKt", "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/io/FilesKt")
/* loaded from: classes.dex */
class FilesKt__UtilsKt extends FilesKt__FileTreeWalkKt {
    public static /* synthetic */ File createTempDir$default(String str, String str2, File file, int i, Object obj) {
        if ((i & 1) != 0) {
            str = "tmp";
        }
        if ((i & 2) != 0) {
            str2 = null;
        }
        if ((i & 4) != 0) {
            file = null;
        }
        return FilesKt.createTempDir(str, str2, file);
    }

    public static final File createTempDir(String prefix, String suffix, File directory) {
        Intrinsics.checkParameterIsNotNull(prefix, "prefix");
        File dir = File.createTempFile(prefix, suffix, directory);
        dir.delete();
        if (dir.mkdir()) {
            Intrinsics.checkExpressionValueIsNotNull(dir, "dir");
            return dir;
        }
        throw new IOException("Unable to create temporary directory " + dir + '.');
    }

    public static /* synthetic */ File createTempFile$default(String str, String str2, File file, int i, Object obj) {
        if ((i & 1) != 0) {
            str = "tmp";
        }
        if ((i & 2) != 0) {
            str2 = null;
        }
        if ((i & 4) != 0) {
            file = null;
        }
        return FilesKt.createTempFile(str, str2, file);
    }

    public static final File createTempFile(String prefix, String suffix, File directory) {
        Intrinsics.checkParameterIsNotNull(prefix, "prefix");
        File createTempFile = File.createTempFile(prefix, suffix, directory);
        Intrinsics.checkExpressionValueIsNotNull(createTempFile, "File.createTempFile(prefix, suffix, directory)");
        return createTempFile;
    }

    public static final String getExtension(File extension) {
        Intrinsics.checkParameterIsNotNull(extension, "$this$extension");
        String name = extension.getName();
        Intrinsics.checkExpressionValueIsNotNull(name, "name");
        return StringsKt.substringAfterLast(name, '.', BuildConfig.FLAVOR);
    }

    public static final String getInvariantSeparatorsPath(File invariantSeparatorsPath) {
        Intrinsics.checkParameterIsNotNull(invariantSeparatorsPath, "$this$invariantSeparatorsPath");
        if (File.separatorChar != '/') {
            String path = invariantSeparatorsPath.getPath();
            Intrinsics.checkExpressionValueIsNotNull(path, "path");
            return StringsKt.replace$default(path, File.separatorChar, '/', false, 4, (Object) null);
        }
        String path2 = invariantSeparatorsPath.getPath();
        Intrinsics.checkExpressionValueIsNotNull(path2, "path");
        return path2;
    }

    public static final String getNameWithoutExtension(File nameWithoutExtension) {
        Intrinsics.checkParameterIsNotNull(nameWithoutExtension, "$this$nameWithoutExtension");
        String name = nameWithoutExtension.getName();
        Intrinsics.checkExpressionValueIsNotNull(name, "name");
        return StringsKt.substringBeforeLast$default(name, ".", (String) null, 2, (Object) null);
    }

    public static final String toRelativeString(File toRelativeString, File base) {
        Intrinsics.checkParameterIsNotNull(toRelativeString, "$this$toRelativeString");
        Intrinsics.checkParameterIsNotNull(base, "base");
        String relativeStringOrNull$FilesKt__UtilsKt = toRelativeStringOrNull$FilesKt__UtilsKt(toRelativeString, base);
        if (relativeStringOrNull$FilesKt__UtilsKt != null) {
            return relativeStringOrNull$FilesKt__UtilsKt;
        }
        throw new IllegalArgumentException("this and base files have different roots: " + toRelativeString + " and " + base + '.');
    }

    public static final File relativeTo(File relativeTo, File base) {
        Intrinsics.checkParameterIsNotNull(relativeTo, "$this$relativeTo");
        Intrinsics.checkParameterIsNotNull(base, "base");
        return new File(FilesKt.toRelativeString(relativeTo, base));
    }

    public static final File relativeToOrSelf(File relativeToOrSelf, File base) {
        Intrinsics.checkParameterIsNotNull(relativeToOrSelf, "$this$relativeToOrSelf");
        Intrinsics.checkParameterIsNotNull(base, "base");
        String p1 = toRelativeStringOrNull$FilesKt__UtilsKt(relativeToOrSelf, base);
        return p1 != null ? new File(p1) : relativeToOrSelf;
    }

    public static final File relativeToOrNull(File relativeToOrNull, File base) {
        Intrinsics.checkParameterIsNotNull(relativeToOrNull, "$this$relativeToOrNull");
        Intrinsics.checkParameterIsNotNull(base, "base");
        String p1 = toRelativeStringOrNull$FilesKt__UtilsKt(relativeToOrNull, base);
        if (p1 != null) {
            return new File(p1);
        }
        return null;
    }

    private static final String toRelativeStringOrNull$FilesKt__UtilsKt(File $this$toRelativeStringOrNull, File base) {
        FilePathComponents thisComponents = normalize$FilesKt__UtilsKt(FilesKt.toComponents($this$toRelativeStringOrNull));
        FilePathComponents baseComponents = normalize$FilesKt__UtilsKt(FilesKt.toComponents(base));
        if (!Intrinsics.areEqual(thisComponents.getRoot(), baseComponents.getRoot())) {
            return null;
        }
        int baseCount = baseComponents.getSize();
        int thisCount = thisComponents.getSize();
        int i = 0;
        int maxSameCount = Math.min(thisCount, baseCount);
        while (i < maxSameCount && Intrinsics.areEqual(thisComponents.getSegments().get(i), baseComponents.getSegments().get(i))) {
            i++;
        }
        int sameCount = i;
        StringBuilder res = new StringBuilder();
        int i2 = baseCount - 1;
        if (i2 >= sameCount) {
            while (!Intrinsics.areEqual(baseComponents.getSegments().get(i2).getName(), "..")) {
                res.append("..");
                if (i2 != sameCount) {
                    res.append(File.separatorChar);
                }
                if (i2 != sameCount) {
                    i2--;
                }
            }
            return null;
        }
        if (sameCount < thisCount) {
            if (sameCount < baseCount) {
                res.append(File.separatorChar);
            }
            String str = File.separator;
            Intrinsics.checkExpressionValueIsNotNull(str, "File.separator");
            CollectionsKt.joinTo(CollectionsKt.drop(thisComponents.getSegments(), sameCount), res, (r14 & 2) != 0 ? ", " : str, (r14 & 4) != 0 ? BuildConfig.FLAVOR : null, (r14 & 8) != 0 ? BuildConfig.FLAVOR : null, (r14 & 16) != 0 ? -1 : 0, (r14 & 32) != 0 ? "..." : null, (r14 & 64) != 0 ? null : null);
        }
        return res.toString();
    }

    public static /* synthetic */ File copyTo$default(File file, File file2, boolean z, int i, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = false;
        }
        if ((i2 & 4) != 0) {
            i = ConstantsKt.DEFAULT_BUFFER_SIZE;
        }
        return FilesKt.copyTo(file, file2, z, i);
    }

    public static final File copyTo(File copyTo, File target, boolean overwrite, int bufferSize) {
        Intrinsics.checkParameterIsNotNull(copyTo, "$this$copyTo");
        Intrinsics.checkParameterIsNotNull(target, "target");
        if (!copyTo.exists()) {
            throw new NoSuchFileException(copyTo, null, "The source file doesn't exist.", 2, null);
        }
        if (target.exists()) {
            boolean stillExists = true;
            if (overwrite && target.delete()) {
                stillExists = false;
            }
            if (stillExists) {
                throw new FileAlreadyExistsException(copyTo, target, "The destination file already exists.");
            }
        }
        if (copyTo.isDirectory()) {
            if (!target.mkdirs()) {
                throw new FileSystemException(copyTo, target, "Failed to create target directory.");
            }
        } else {
            File parentFile = target.getParentFile();
            if (parentFile != null) {
                parentFile.mkdirs();
            }
            FileInputStream fileInputStream = new FileInputStream(copyTo);
            Throwable th = null;
            try {
                FileInputStream input = fileInputStream;
                FileOutputStream fileOutputStream = new FileOutputStream(target);
                Throwable th2 = null;
                FileOutputStream output = fileOutputStream;
                ByteStreamsKt.copyTo(input, output, bufferSize);
                CloseableKt.closeFinally(fileOutputStream, th2);
                CloseableKt.closeFinally(fileInputStream, th);
            } finally {
            }
        }
        return target;
    }

    public static /* synthetic */ boolean copyRecursively$default(File file, File file2, boolean z, Function2 function2, int i, Object obj) {
        if ((i & 2) != 0) {
            z = false;
        }
        if ((i & 4) != 0) {
            function2 = FilesKt__UtilsKt$copyRecursively$1.INSTANCE;
        }
        return FilesKt.copyRecursively(file, file2, z, function2);
    }

    public static final boolean copyRecursively(File copyRecursively, File target, boolean overwrite, Function2<? super File, ? super IOException, ? extends OnErrorAction> onError) {
        boolean stillExists;
        Intrinsics.checkParameterIsNotNull(copyRecursively, "$this$copyRecursively");
        Intrinsics.checkParameterIsNotNull(target, "target");
        Intrinsics.checkParameterIsNotNull(onError, "onError");
        if (!copyRecursively.exists()) {
            return onError.invoke(copyRecursively, new NoSuchFileException(copyRecursively, null, "The source file doesn't exist.", 2, null)) != OnErrorAction.TERMINATE;
        }
        try {
            Iterator<File> it = FilesKt.walkTopDown(copyRecursively).onFail(new FilesKt__UtilsKt$copyRecursively$2(onError)).iterator();
            while (it.hasNext()) {
                File src = it.next();
                if (!src.exists()) {
                    if (onError.invoke(src, new NoSuchFileException(src, null, "The source file doesn't exist.", 2, null)) == OnErrorAction.TERMINATE) {
                        return false;
                    }
                } else {
                    String relPath = FilesKt.toRelativeString(src, copyRecursively);
                    File dstFile = new File(target, relPath);
                    if (dstFile.exists() && (!src.isDirectory() || !dstFile.isDirectory())) {
                        if (!overwrite) {
                            stillExists = true;
                        } else if (dstFile.isDirectory()) {
                            stillExists = !FilesKt.deleteRecursively(dstFile);
                        } else {
                            stillExists = !dstFile.delete();
                        }
                        if (stillExists) {
                            if (onError.invoke(dstFile, new FileAlreadyExistsException(src, dstFile, "The destination file already exists.")) == OnErrorAction.TERMINATE) {
                                return false;
                            }
                        }
                    }
                    boolean stillExists2 = src.isDirectory();
                    if (stillExists2) {
                        dstFile.mkdirs();
                    } else if (FilesKt.copyTo$default(src, dstFile, overwrite, 0, 4, null).length() != src.length() && onError.invoke(src, new IOException("Source file wasn't copied completely, length of destination file differs.")) == OnErrorAction.TERMINATE) {
                        return false;
                    }
                }
            }
            return true;
        } catch (TerminateException e) {
            return false;
        }
    }

    public static final boolean deleteRecursively(File deleteRecursively) {
        Intrinsics.checkParameterIsNotNull(deleteRecursively, "$this$deleteRecursively");
        Sequence $this$fold$iv = FilesKt.walkBottomUp(deleteRecursively);
        boolean accumulator$iv = true;
        for (Object element$iv : $this$fold$iv) {
            File it = (File) element$iv;
            boolean res = accumulator$iv;
            accumulator$iv = (it.delete() || !it.exists()) && res;
        }
        return accumulator$iv;
    }

    public static final boolean startsWith(File startsWith, File other) {
        Intrinsics.checkParameterIsNotNull(startsWith, "$this$startsWith");
        Intrinsics.checkParameterIsNotNull(other, "other");
        FilePathComponents components = FilesKt.toComponents(startsWith);
        FilePathComponents otherComponents = FilesKt.toComponents(other);
        if (!(!Intrinsics.areEqual(components.getRoot(), otherComponents.getRoot())) && components.getSize() >= otherComponents.getSize()) {
            return components.getSegments().subList(0, otherComponents.getSize()).equals(otherComponents.getSegments());
        }
        return false;
    }

    public static final boolean startsWith(File startsWith, String other) {
        Intrinsics.checkParameterIsNotNull(startsWith, "$this$startsWith");
        Intrinsics.checkParameterIsNotNull(other, "other");
        return FilesKt.startsWith(startsWith, new File(other));
    }

    public static final boolean endsWith(File endsWith, File other) {
        Intrinsics.checkParameterIsNotNull(endsWith, "$this$endsWith");
        Intrinsics.checkParameterIsNotNull(other, "other");
        FilePathComponents components = FilesKt.toComponents(endsWith);
        FilePathComponents otherComponents = FilesKt.toComponents(other);
        if (otherComponents.isRooted()) {
            return Intrinsics.areEqual(endsWith, other);
        }
        int shift = components.getSize() - otherComponents.getSize();
        if (shift < 0) {
            return false;
        }
        return components.getSegments().subList(shift, components.getSize()).equals(otherComponents.getSegments());
    }

    public static final boolean endsWith(File endsWith, String other) {
        Intrinsics.checkParameterIsNotNull(endsWith, "$this$endsWith");
        Intrinsics.checkParameterIsNotNull(other, "other");
        return FilesKt.endsWith(endsWith, new File(other));
    }

    public static final File normalize(File normalize) {
        Intrinsics.checkParameterIsNotNull(normalize, "$this$normalize");
        FilePathComponents $this$with = FilesKt.toComponents(normalize);
        File root = $this$with.getRoot();
        List<File> normalize$FilesKt__UtilsKt = normalize$FilesKt__UtilsKt($this$with.getSegments());
        String str = File.separator;
        Intrinsics.checkExpressionValueIsNotNull(str, "File.separator");
        return FilesKt.resolve(root, CollectionsKt.joinToString$default(normalize$FilesKt__UtilsKt, str, null, null, 0, null, null, 62, null));
    }

    private static final FilePathComponents normalize$FilesKt__UtilsKt(FilePathComponents $this$normalize) {
        return new FilePathComponents($this$normalize.getRoot(), normalize$FilesKt__UtilsKt($this$normalize.getSegments()));
    }

    private static final List<File> normalize$FilesKt__UtilsKt(List<? extends File> list) {
        List list2 = new ArrayList(list.size());
        for (File file : list) {
            String name = file.getName();
            if (name != null) {
                int hashCode = name.hashCode();
                if (hashCode != 46) {
                    if (hashCode == 1472 && name.equals("..")) {
                        if (list2.isEmpty() || !(!Intrinsics.areEqual(((File) CollectionsKt.last((List<? extends Object>) list2)).getName(), ".."))) {
                            list2.add(file);
                        } else {
                            list2.remove(list2.size() - 1);
                        }
                    }
                } else if (name.equals(".")) {
                }
            }
            list2.add(file);
        }
        return list2;
    }

    public static final File resolve(File resolve, File relative) {
        Intrinsics.checkParameterIsNotNull(resolve, "$this$resolve");
        Intrinsics.checkParameterIsNotNull(relative, "relative");
        if (FilesKt.isRooted(relative)) {
            return relative;
        }
        String baseName = resolve.toString();
        Intrinsics.checkExpressionValueIsNotNull(baseName, "this.toString()");
        if ((baseName.length() == 0) || StringsKt.endsWith$default((CharSequence) baseName, File.separatorChar, false, 2, (Object) null)) {
            return new File(baseName + relative);
        }
        return new File(baseName + File.separatorChar + relative);
    }

    public static final File resolve(File resolve, String relative) {
        Intrinsics.checkParameterIsNotNull(resolve, "$this$resolve");
        Intrinsics.checkParameterIsNotNull(relative, "relative");
        return FilesKt.resolve(resolve, new File(relative));
    }

    public static final File resolveSibling(File resolveSibling, File relative) {
        Intrinsics.checkParameterIsNotNull(resolveSibling, "$this$resolveSibling");
        Intrinsics.checkParameterIsNotNull(relative, "relative");
        FilePathComponents components = FilesKt.toComponents(resolveSibling);
        File parentSubPath = components.getSize() == 0 ? new File("..") : components.subPath(0, components.getSize() - 1);
        return FilesKt.resolve(FilesKt.resolve(components.getRoot(), parentSubPath), relative);
    }

    public static final File resolveSibling(File resolveSibling, String relative) {
        Intrinsics.checkParameterIsNotNull(resolveSibling, "$this$resolveSibling");
        Intrinsics.checkParameterIsNotNull(relative, "relative");
        return FilesKt.resolveSibling(resolveSibling, new File(relative));
    }
}