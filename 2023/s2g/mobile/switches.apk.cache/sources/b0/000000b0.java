package com.badlogic.gdx.backends.android;

import android.content.SharedPreferences;
import com.badlogic.gdx.Preferences;
import java.util.Map;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class AndroidPreferences implements Preferences {
    SharedPreferences.Editor editor;
    SharedPreferences sharedPrefs;

    public AndroidPreferences(SharedPreferences preferences) {
        this.sharedPrefs = preferences;
    }

    @Override // com.badlogic.gdx.Preferences
    public Preferences putBoolean(String key, boolean val) {
        edit();
        this.editor.putBoolean(key, val);
        return this;
    }

    @Override // com.badlogic.gdx.Preferences
    public Preferences putInteger(String key, int val) {
        edit();
        this.editor.putInt(key, val);
        return this;
    }

    @Override // com.badlogic.gdx.Preferences
    public Preferences putLong(String key, long val) {
        edit();
        this.editor.putLong(key, val);
        return this;
    }

    @Override // com.badlogic.gdx.Preferences
    public Preferences putFloat(String key, float val) {
        edit();
        this.editor.putFloat(key, val);
        return this;
    }

    @Override // com.badlogic.gdx.Preferences
    public Preferences putString(String key, String val) {
        edit();
        this.editor.putString(key, val);
        return this;
    }

    @Override // com.badlogic.gdx.Preferences
    public Preferences put(Map<String, ?> vals) {
        edit();
        for (Map.Entry<String, ?> val : vals.entrySet()) {
            if (val.getValue() instanceof Boolean) {
                putBoolean(val.getKey(), ((Boolean) val.getValue()).booleanValue());
            }
            if (val.getValue() instanceof Integer) {
                putInteger(val.getKey(), ((Integer) val.getValue()).intValue());
            }
            if (val.getValue() instanceof Long) {
                putLong(val.getKey(), ((Long) val.getValue()).longValue());
            }
            if (val.getValue() instanceof String) {
                putString(val.getKey(), (String) val.getValue());
            }
            if (val.getValue() instanceof Float) {
                putFloat(val.getKey(), ((Float) val.getValue()).floatValue());
            }
        }
        return this;
    }

    @Override // com.badlogic.gdx.Preferences
    public boolean getBoolean(String key) {
        return this.sharedPrefs.getBoolean(key, false);
    }

    @Override // com.badlogic.gdx.Preferences
    public int getInteger(String key) {
        return this.sharedPrefs.getInt(key, 0);
    }

    @Override // com.badlogic.gdx.Preferences
    public long getLong(String key) {
        return this.sharedPrefs.getLong(key, 0L);
    }

    @Override // com.badlogic.gdx.Preferences
    public float getFloat(String key) {
        return this.sharedPrefs.getFloat(key, 0.0f);
    }

    @Override // com.badlogic.gdx.Preferences
    public String getString(String key) {
        return this.sharedPrefs.getString(key, BuildConfig.FLAVOR);
    }

    @Override // com.badlogic.gdx.Preferences
    public boolean getBoolean(String key, boolean defValue) {
        return this.sharedPrefs.getBoolean(key, defValue);
    }

    @Override // com.badlogic.gdx.Preferences
    public int getInteger(String key, int defValue) {
        return this.sharedPrefs.getInt(key, defValue);
    }

    @Override // com.badlogic.gdx.Preferences
    public long getLong(String key, long defValue) {
        return this.sharedPrefs.getLong(key, defValue);
    }

    @Override // com.badlogic.gdx.Preferences
    public float getFloat(String key, float defValue) {
        return this.sharedPrefs.getFloat(key, defValue);
    }

    @Override // com.badlogic.gdx.Preferences
    public String getString(String key, String defValue) {
        return this.sharedPrefs.getString(key, defValue);
    }

    @Override // com.badlogic.gdx.Preferences
    public Map<String, ?> get() {
        return this.sharedPrefs.getAll();
    }

    @Override // com.badlogic.gdx.Preferences
    public boolean contains(String key) {
        return this.sharedPrefs.contains(key);
    }

    @Override // com.badlogic.gdx.Preferences
    public void clear() {
        edit();
        this.editor.clear();
    }

    @Override // com.badlogic.gdx.Preferences
    public void flush() {
        SharedPreferences.Editor editor = this.editor;
        if (editor != null) {
            editor.apply();
            this.editor = null;
        }
    }

    @Override // com.badlogic.gdx.Preferences
    public void remove(String key) {
        edit();
        this.editor.remove(key);
    }

    private void edit() {
        if (this.editor == null) {
            this.editor = this.sharedPrefs.edit();
        }
    }
}