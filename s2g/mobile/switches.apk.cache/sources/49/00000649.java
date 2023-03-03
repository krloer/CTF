package com.kotcrab.vis.ui.widget.file;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class FileTypeFilter {
    private boolean allTypesAllowed;
    private Array<Rule> rules;

    public FileTypeFilter(FileTypeFilter other) {
        this.rules = new Array<>();
        this.allTypesAllowed = other.allTypesAllowed;
        this.rules = new Array<>(other.rules);
    }

    public FileTypeFilter(boolean allTypesAllowed) {
        this.rules = new Array<>();
        this.allTypesAllowed = allTypesAllowed;
    }

    public void addRule(String description, String... extensions) {
        this.rules.add(new Rule(description, extensions));
    }

    public Array<Rule> getRules() {
        return this.rules;
    }

    public void setAllTypesAllowed(boolean allTypesAllowed) {
        this.allTypesAllowed = allTypesAllowed;
    }

    public boolean isAllTypesAllowed() {
        return this.allTypesAllowed;
    }

    /* loaded from: classes.dex */
    public static class Rule {
        private final boolean allowAll;
        private final String description;
        private final Array<String> extensions = new Array<>();

        public Rule(String description) {
            if (description == null) {
                throw new IllegalArgumentException("description can't be null");
            }
            this.description = description;
            this.allowAll = true;
        }

        public Rule(String description, String... extensionList) {
            if (description == null) {
                throw new IllegalArgumentException("description can't be null");
            }
            if (extensionList == null || extensionList.length == 0) {
                throw new IllegalArgumentException("extensionList can't be null nor empty");
            }
            this.description = description;
            this.allowAll = false;
            for (String ext : extensionList) {
                if (ext.startsWith(".")) {
                    ext = ext.substring(1);
                }
                this.extensions.add(ext.toLowerCase());
            }
        }

        public boolean accept(FileHandle file) {
            if (this.allowAll) {
                return true;
            }
            String ext = file.extension().toLowerCase();
            return this.extensions.contains(ext, false);
        }

        public String getDescription() {
            return this.description;
        }

        public Array<String> getExtensions() {
            return new Array<>(this.extensions);
        }

        public String toString() {
            return this.description;
        }
    }
}