package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.graphics.g2d.NinePatch;
import com.badlogic.gdx.graphics.g2d.Sprite;
import com.badlogic.gdx.graphics.g2d.TextureAtlas;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.ui.Button;
import com.badlogic.gdx.scenes.scene2d.ui.CheckBox;
import com.badlogic.gdx.scenes.scene2d.ui.ImageButton;
import com.badlogic.gdx.scenes.scene2d.ui.ImageTextButton;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.badlogic.gdx.scenes.scene2d.ui.List;
import com.badlogic.gdx.scenes.scene2d.ui.ProgressBar;
import com.badlogic.gdx.scenes.scene2d.ui.ScrollPane;
import com.badlogic.gdx.scenes.scene2d.ui.SelectBox;
import com.badlogic.gdx.scenes.scene2d.ui.Slider;
import com.badlogic.gdx.scenes.scene2d.ui.SplitPane;
import com.badlogic.gdx.scenes.scene2d.ui.TextButton;
import com.badlogic.gdx.scenes.scene2d.ui.TextField;
import com.badlogic.gdx.scenes.scene2d.ui.TextTooltip;
import com.badlogic.gdx.scenes.scene2d.ui.Touchpad;
import com.badlogic.gdx.scenes.scene2d.ui.Tree;
import com.badlogic.gdx.scenes.scene2d.ui.Window;
import com.badlogic.gdx.scenes.scene2d.utils.BaseDrawable;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.NinePatchDrawable;
import com.badlogic.gdx.scenes.scene2d.utils.SpriteDrawable;
import com.badlogic.gdx.scenes.scene2d.utils.TextureRegionDrawable;
import com.badlogic.gdx.scenes.scene2d.utils.TiledDrawable;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.Json;
import com.badlogic.gdx.utils.JsonValue;
import com.badlogic.gdx.utils.ObjectMap;
import com.badlogic.gdx.utils.SerializationException;
import com.badlogic.gdx.utils.reflect.ClassReflection;
import com.badlogic.gdx.utils.reflect.Method;
import com.badlogic.gdx.utils.reflect.ReflectionException;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class Skin implements Disposable {
    private static final Class[] defaultTagClasses = {BitmapFont.class, Color.class, TintedDrawable.class, NinePatchDrawable.class, SpriteDrawable.class, TextureRegionDrawable.class, TiledDrawable.class, Button.ButtonStyle.class, CheckBox.CheckBoxStyle.class, ImageButton.ImageButtonStyle.class, ImageTextButton.ImageTextButtonStyle.class, Label.LabelStyle.class, List.ListStyle.class, ProgressBar.ProgressBarStyle.class, ScrollPane.ScrollPaneStyle.class, SelectBox.SelectBoxStyle.class, Slider.SliderStyle.class, SplitPane.SplitPaneStyle.class, TextButton.TextButtonStyle.class, TextField.TextFieldStyle.class, TextTooltip.TextTooltipStyle.class, Touchpad.TouchpadStyle.class, Tree.TreeStyle.class, Window.WindowStyle.class};
    TextureAtlas atlas;
    ObjectMap<Class, ObjectMap<String, Object>> resources = new ObjectMap<>();
    float scale = 1.0f;
    private final ObjectMap<String, Class> jsonClassTags = new ObjectMap<>(defaultTagClasses.length);

    /* loaded from: classes.dex */
    public static class TintedDrawable {
        public Color color;
        public String name;
    }

    public Skin() {
        Class[] clsArr;
        for (Class c : defaultTagClasses) {
            this.jsonClassTags.put(c.getSimpleName(), c);
        }
    }

    public Skin(FileHandle skinFile) {
        Class[] clsArr;
        for (Class c : defaultTagClasses) {
            this.jsonClassTags.put(c.getSimpleName(), c);
        }
        FileHandle atlasFile = skinFile.sibling(skinFile.nameWithoutExtension() + ".atlas");
        if (atlasFile.exists()) {
            this.atlas = new TextureAtlas(atlasFile);
            addRegions(this.atlas);
        }
        load(skinFile);
    }

    public Skin(FileHandle skinFile, TextureAtlas atlas) {
        Class[] clsArr;
        for (Class c : defaultTagClasses) {
            this.jsonClassTags.put(c.getSimpleName(), c);
        }
        this.atlas = atlas;
        addRegions(atlas);
        load(skinFile);
    }

    public Skin(TextureAtlas atlas) {
        Class[] clsArr;
        for (Class c : defaultTagClasses) {
            this.jsonClassTags.put(c.getSimpleName(), c);
        }
        this.atlas = atlas;
        addRegions(atlas);
    }

    public void load(FileHandle skinFile) {
        try {
            getJsonLoader(skinFile).fromJson(Skin.class, skinFile);
        } catch (SerializationException ex) {
            throw new SerializationException("Error reading file: " + skinFile, ex);
        }
    }

    public void addRegions(TextureAtlas atlas) {
        Array<TextureAtlas.AtlasRegion> regions = atlas.getRegions();
        int n = regions.size;
        for (int i = 0; i < n; i++) {
            TextureAtlas.AtlasRegion region = regions.get(i);
            String name = region.name;
            if (region.index != -1) {
                name = name + "_" + region.index;
            }
            add(name, region, TextureRegion.class);
        }
    }

    public void add(String name, Object resource) {
        add(name, resource, resource.getClass());
    }

    public void add(String name, Object resource, Class type) {
        if (name == null) {
            throw new IllegalArgumentException("name cannot be null.");
        }
        if (resource == null) {
            throw new IllegalArgumentException("resource cannot be null.");
        }
        ObjectMap<String, Object> typeResources = this.resources.get(type);
        if (typeResources == null) {
            typeResources = new ObjectMap<>((type == TextureRegion.class || type == Drawable.class || type == Sprite.class) ? 256 : 64);
            this.resources.put(type, typeResources);
        }
        typeResources.put(name, resource);
    }

    public void remove(String name, Class type) {
        if (name == null) {
            throw new IllegalArgumentException("name cannot be null.");
        }
        ObjectMap<String, Object> typeResources = this.resources.get(type);
        typeResources.remove(name);
    }

    public <T> T get(Class<T> type) {
        return (T) get("default", type);
    }

    public <T> T get(String name, Class<T> type) {
        if (name == null) {
            throw new IllegalArgumentException("name cannot be null.");
        }
        if (type == null) {
            throw new IllegalArgumentException("type cannot be null.");
        }
        if (type == Drawable.class) {
            return (T) getDrawable(name);
        }
        if (type == TextureRegion.class) {
            return (T) getRegion(name);
        }
        if (type == NinePatch.class) {
            return (T) getPatch(name);
        }
        if (type == Sprite.class) {
            return (T) getSprite(name);
        }
        ObjectMap<String, Object> typeResources = this.resources.get(type);
        if (typeResources == null) {
            throw new GdxRuntimeException("No " + type.getName() + " registered with name: " + name);
        }
        T t = (T) typeResources.get(name);
        if (t == null) {
            throw new GdxRuntimeException("No " + type.getName() + " registered with name: " + name);
        }
        return t;
    }

    public <T> T optional(String name, Class<T> type) {
        if (name == null) {
            throw new IllegalArgumentException("name cannot be null.");
        }
        if (type == null) {
            throw new IllegalArgumentException("type cannot be null.");
        }
        ObjectMap<String, Object> typeResources = this.resources.get(type);
        if (typeResources == null) {
            return null;
        }
        return (T) typeResources.get(name);
    }

    public boolean has(String name, Class type) {
        ObjectMap<String, Object> typeResources = this.resources.get(type);
        if (typeResources == null) {
            return false;
        }
        return typeResources.containsKey(name);
    }

    public <T> ObjectMap<String, T> getAll(Class<T> type) {
        return (ObjectMap<String, T>) this.resources.get(type);
    }

    public Color getColor(String name) {
        return (Color) get(name, Color.class);
    }

    public BitmapFont getFont(String name) {
        return (BitmapFont) get(name, BitmapFont.class);
    }

    public TextureRegion getRegion(String name) {
        TextureRegion region = (TextureRegion) optional(name, TextureRegion.class);
        if (region != null) {
            return region;
        }
        Texture texture = (Texture) optional(name, Texture.class);
        if (texture == null) {
            throw new GdxRuntimeException("No TextureRegion or Texture registered with name: " + name);
        }
        TextureRegion region2 = new TextureRegion(texture);
        add(name, region2, TextureRegion.class);
        return region2;
    }

    public Array<TextureRegion> getRegions(String regionName) {
        Array<TextureRegion> regions = null;
        StringBuilder sb = new StringBuilder();
        sb.append(regionName);
        sb.append("_");
        int i = 0 + 1;
        sb.append(0);
        TextureRegion region = (TextureRegion) optional(sb.toString(), TextureRegion.class);
        if (region != null) {
            regions = new Array<>();
            while (region != null) {
                regions.add(region);
                region = (TextureRegion) optional(regionName + "_" + i, TextureRegion.class);
                i++;
            }
        }
        return regions;
    }

    public TiledDrawable getTiledDrawable(String name) {
        TiledDrawable tiled = (TiledDrawable) optional(name, TiledDrawable.class);
        if (tiled != null) {
            return tiled;
        }
        TiledDrawable tiled2 = new TiledDrawable(getRegion(name));
        tiled2.setName(name);
        if (this.scale != 1.0f) {
            scale(tiled2);
            tiled2.setScale(this.scale);
        }
        add(name, tiled2, TiledDrawable.class);
        return tiled2;
    }

    public NinePatch getPatch(String name) {
        int[] splits;
        NinePatch patch = (NinePatch) optional(name, NinePatch.class);
        if (patch != null) {
            return patch;
        }
        try {
            TextureRegion region = getRegion(name);
            if ((region instanceof TextureAtlas.AtlasRegion) && (splits = ((TextureAtlas.AtlasRegion) region).findValue("split")) != null) {
                patch = new NinePatch(region, splits[0], splits[1], splits[2], splits[3]);
                int[] pads = ((TextureAtlas.AtlasRegion) region).findValue("pad");
                if (pads != null) {
                    patch.setPadding(pads[0], pads[1], pads[2], pads[3]);
                }
            }
            if (patch == null) {
                patch = new NinePatch(region);
            }
            if (this.scale != 1.0f) {
                patch.scale(this.scale, this.scale);
            }
            add(name, patch, NinePatch.class);
            return patch;
        } catch (GdxRuntimeException e) {
            throw new GdxRuntimeException("No NinePatch, TextureRegion, or Texture registered with name: " + name);
        }
    }

    public Sprite getSprite(String name) {
        Sprite sprite = (Sprite) optional(name, Sprite.class);
        if (sprite != null) {
            return sprite;
        }
        try {
            TextureRegion textureRegion = getRegion(name);
            if (textureRegion instanceof TextureAtlas.AtlasRegion) {
                TextureAtlas.AtlasRegion region = (TextureAtlas.AtlasRegion) textureRegion;
                if (region.rotate || region.packedWidth != region.originalWidth || region.packedHeight != region.originalHeight) {
                    sprite = new TextureAtlas.AtlasSprite(region);
                }
            }
            if (sprite == null) {
                sprite = new Sprite(textureRegion);
            }
            if (this.scale != 1.0f) {
                sprite.setSize(sprite.getWidth() * this.scale, sprite.getHeight() * this.scale);
            }
            add(name, sprite, Sprite.class);
            return sprite;
        } catch (GdxRuntimeException e) {
            throw new GdxRuntimeException("No NinePatch, TextureRegion, or Texture registered with name: " + name);
        }
    }

    public Drawable getDrawable(String name) {
        Drawable drawable = (Drawable) optional(name, Drawable.class);
        if (drawable != null) {
            return drawable;
        }
        try {
            TextureRegion textureRegion = getRegion(name);
            if (textureRegion instanceof TextureAtlas.AtlasRegion) {
                TextureAtlas.AtlasRegion region = (TextureAtlas.AtlasRegion) textureRegion;
                if (region.findValue("split") != null) {
                    drawable = new NinePatchDrawable(getPatch(name));
                } else if (region.rotate || region.packedWidth != region.originalWidth || region.packedHeight != region.originalHeight) {
                    drawable = new SpriteDrawable(getSprite(name));
                }
            }
            if (drawable == null) {
                drawable = new TextureRegionDrawable(textureRegion);
                if (this.scale != 1.0f) {
                    scale(drawable);
                }
            }
        } catch (GdxRuntimeException e) {
        }
        if (drawable == null) {
            NinePatch patch = (NinePatch) optional(name, NinePatch.class);
            if (patch != null) {
                drawable = new NinePatchDrawable(patch);
            } else {
                Sprite sprite = (Sprite) optional(name, Sprite.class);
                if (sprite != null) {
                    drawable = new SpriteDrawable(sprite);
                } else {
                    throw new GdxRuntimeException("No Drawable, NinePatch, TextureRegion, Texture, or Sprite registered with name: " + name);
                }
            }
        }
        if (drawable instanceof BaseDrawable) {
            ((BaseDrawable) drawable).setName(name);
        }
        add(name, drawable, Drawable.class);
        return drawable;
    }

    public String find(Object resource) {
        if (resource == null) {
            throw new IllegalArgumentException("style cannot be null.");
        }
        ObjectMap<String, Object> typeResources = this.resources.get(resource.getClass());
        if (typeResources == null) {
            return null;
        }
        return typeResources.findKey(resource, true);
    }

    public Drawable newDrawable(String name) {
        return newDrawable(getDrawable(name));
    }

    public Drawable newDrawable(String name, float r, float g, float b, float a) {
        return newDrawable(getDrawable(name), new Color(r, g, b, a));
    }

    public Drawable newDrawable(String name, Color tint) {
        return newDrawable(getDrawable(name), tint);
    }

    public Drawable newDrawable(Drawable drawable) {
        if (drawable instanceof TiledDrawable) {
            return new TiledDrawable((TiledDrawable) drawable);
        }
        if (drawable instanceof TextureRegionDrawable) {
            return new TextureRegionDrawable((TextureRegionDrawable) drawable);
        }
        if (drawable instanceof NinePatchDrawable) {
            return new NinePatchDrawable((NinePatchDrawable) drawable);
        }
        if (drawable instanceof SpriteDrawable) {
            return new SpriteDrawable((SpriteDrawable) drawable);
        }
        throw new GdxRuntimeException("Unable to copy, unknown drawable type: " + drawable.getClass());
    }

    public Drawable newDrawable(Drawable drawable, float r, float g, float b, float a) {
        return newDrawable(drawable, new Color(r, g, b, a));
    }

    public Drawable newDrawable(Drawable drawable, Color tint) {
        Drawable newDrawable;
        if (drawable instanceof TextureRegionDrawable) {
            newDrawable = ((TextureRegionDrawable) drawable).tint(tint);
        } else if (drawable instanceof NinePatchDrawable) {
            newDrawable = ((NinePatchDrawable) drawable).tint(tint);
        } else if (drawable instanceof SpriteDrawable) {
            newDrawable = ((SpriteDrawable) drawable).tint(tint);
        } else {
            throw new GdxRuntimeException("Unable to copy, unknown drawable type: " + drawable.getClass());
        }
        if (newDrawable instanceof BaseDrawable) {
            BaseDrawable named = (BaseDrawable) newDrawable;
            if (drawable instanceof BaseDrawable) {
                named.setName(((BaseDrawable) drawable).getName() + " (" + tint + ")");
            } else {
                named.setName(" (" + tint + ")");
            }
        }
        return newDrawable;
    }

    public void scale(Drawable drawble) {
        drawble.setLeftWidth(drawble.getLeftWidth() * this.scale);
        drawble.setRightWidth(drawble.getRightWidth() * this.scale);
        drawble.setBottomHeight(drawble.getBottomHeight() * this.scale);
        drawble.setTopHeight(drawble.getTopHeight() * this.scale);
        drawble.setMinWidth(drawble.getMinWidth() * this.scale);
        drawble.setMinHeight(drawble.getMinHeight() * this.scale);
    }

    public void setScale(float scale) {
        this.scale = scale;
    }

    public void setEnabled(Actor actor, boolean enabled) {
        Method method = findMethod(actor.getClass(), "getStyle");
        if (method == null) {
            return;
        }
        try {
            Object style = method.invoke(actor, new Object[0]);
            String name = find(style);
            if (name == null) {
                return;
            }
            StringBuilder sb = new StringBuilder();
            String str = BuildConfig.FLAVOR;
            sb.append(name.replace("-disabled", BuildConfig.FLAVOR));
            if (!enabled) {
                str = "-disabled";
            }
            sb.append(str);
            Object style2 = get(sb.toString(), style.getClass());
            Method method2 = findMethod(actor.getClass(), "setStyle");
            if (method2 == null) {
                return;
            }
            try {
                method2.invoke(actor, style2);
            } catch (Exception e) {
            }
        } catch (Exception e2) {
        }
    }

    public TextureAtlas getAtlas() {
        return this.atlas;
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        TextureAtlas textureAtlas = this.atlas;
        if (textureAtlas != null) {
            textureAtlas.dispose();
        }
        ObjectMap.Values<ObjectMap<String, Object>> it = this.resources.values().iterator();
        while (it.hasNext()) {
            ObjectMap<String, Object> entry = it.next();
            ObjectMap.Values<Object> it2 = entry.values().iterator();
            while (it2.hasNext()) {
                Object resource = it2.next();
                if (resource instanceof Disposable) {
                    ((Disposable) resource).dispose();
                }
            }
        }
    }

    protected Json getJsonLoader(final FileHandle skinFile) {
        Json json = new Json() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Skin.1
            private static final String parentFieldName = "parent";

            @Override // com.badlogic.gdx.utils.Json
            public <T> T readValue(Class<T> type, Class elementType, JsonValue jsonData) {
                if (jsonData != null && jsonData.isString() && !ClassReflection.isAssignableFrom(CharSequence.class, type)) {
                    return (T) Skin.this.get(jsonData.asString(), type);
                }
                return (T) super.readValue(type, elementType, jsonData);
            }

            @Override // com.badlogic.gdx.utils.Json
            protected boolean ignoreUnknownField(Class type, String fieldName) {
                return fieldName.equals(parentFieldName);
            }

            @Override // com.badlogic.gdx.utils.Json
            public void readFields(Object object, JsonValue jsonMap) {
                if (jsonMap.has(parentFieldName)) {
                    String parentName = (String) readValue(parentFieldName, String.class, jsonMap);
                    Class parentType = object.getClass();
                    do {
                        try {
                            copyFields(Skin.this.get(parentName, parentType), object);
                        } catch (GdxRuntimeException e) {
                            parentType = parentType.getSuperclass();
                            if (parentType == Object.class) {
                                SerializationException se = new SerializationException("Unable to find parent resource with name: " + parentName);
                                se.addTrace(jsonMap.child.trace());
                                throw se;
                            }
                        }
                    } while (parentType == Object.class);
                    SerializationException se2 = new SerializationException("Unable to find parent resource with name: " + parentName);
                    se2.addTrace(jsonMap.child.trace());
                    throw se2;
                }
                super.readFields(object, jsonMap);
            }
        };
        json.setTypeName(null);
        json.setUsePrototypes(false);
        json.setSerializer(Skin.class, new Json.ReadOnlySerializer<Skin>() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Skin.2
            @Override // com.badlogic.gdx.utils.Json.ReadOnlySerializer, com.badlogic.gdx.utils.Json.Serializer
            public Skin read(Json json2, JsonValue typeToValueMap, Class ignored) {
                for (JsonValue valueMap = typeToValueMap.child; valueMap != null; valueMap = valueMap.next) {
                    try {
                        Class type = json2.getClass(valueMap.name());
                        if (type == null) {
                            type = ClassReflection.forName(valueMap.name());
                        }
                        readNamedObjects(json2, type, valueMap);
                    } catch (ReflectionException ex) {
                        throw new SerializationException(ex);
                    }
                }
                return skin;
            }

            private void readNamedObjects(Json json2, Class type, JsonValue valueMap) {
                Class addType = type == TintedDrawable.class ? Drawable.class : type;
                for (JsonValue valueEntry = valueMap.child; valueEntry != null; valueEntry = valueEntry.next) {
                    Object object = json2.readValue(type, valueEntry);
                    if (object != null) {
                        try {
                            Skin.this.add(valueEntry.name, object, addType);
                            if (addType != Drawable.class && ClassReflection.isAssignableFrom(Drawable.class, addType)) {
                                Skin.this.add(valueEntry.name, object, Drawable.class);
                            }
                        } catch (Exception ex) {
                            throw new SerializationException("Error reading " + ClassReflection.getSimpleName(type) + ": " + valueEntry.name, ex);
                        }
                    }
                }
            }
        });
        json.setSerializer(BitmapFont.class, new Json.ReadOnlySerializer<BitmapFont>() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Skin.3
            @Override // com.badlogic.gdx.utils.Json.ReadOnlySerializer, com.badlogic.gdx.utils.Json.Serializer
            public BitmapFont read(Json json2, JsonValue jsonData, Class type) {
                BitmapFont font;
                String path = (String) json2.readValue("file", String.class, jsonData);
                int scaledSize = ((Integer) json2.readValue("scaledSize", (Class<Class>) Integer.TYPE, (Class) (-1), jsonData)).intValue();
                Boolean flip = (Boolean) json2.readValue("flip", (Class<Class>) Boolean.class, (Class) false, jsonData);
                Boolean markupEnabled = (Boolean) json2.readValue("markupEnabled", (Class<Class>) Boolean.class, (Class) false, jsonData);
                FileHandle fontFile = skinFile.parent().child(path);
                if (!fontFile.exists()) {
                    fontFile = Gdx.files.internal(path);
                }
                if (!fontFile.exists()) {
                    throw new SerializationException("Font file not found: " + fontFile);
                }
                String regionName = fontFile.nameWithoutExtension();
                try {
                    Array<TextureRegion> regions = skin.getRegions(regionName);
                    if (regions != null) {
                        font = new BitmapFont(new BitmapFont.BitmapFontData(fontFile, flip.booleanValue()), regions, true);
                    } else {
                        TextureRegion region = (TextureRegion) skin.optional(regionName, TextureRegion.class);
                        if (region != null) {
                            font = new BitmapFont(fontFile, region, flip.booleanValue());
                        } else {
                            FileHandle parent = fontFile.parent();
                            FileHandle imageFile = parent.child(regionName + ".png");
                            if (imageFile.exists()) {
                                font = new BitmapFont(fontFile, imageFile, flip.booleanValue());
                            } else {
                                font = new BitmapFont(fontFile, flip.booleanValue());
                            }
                        }
                    }
                    font.getData().markupEnabled = markupEnabled.booleanValue();
                    if (scaledSize != -1) {
                        font.getData().setScale(scaledSize / font.getCapHeight());
                    }
                    return font;
                } catch (RuntimeException ex) {
                    throw new SerializationException("Error loading bitmap font: " + fontFile, ex);
                }
            }
        });
        json.setSerializer(Color.class, new Json.ReadOnlySerializer<Color>() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Skin.4
            @Override // com.badlogic.gdx.utils.Json.ReadOnlySerializer, com.badlogic.gdx.utils.Json.Serializer
            public Color read(Json json2, JsonValue jsonData, Class type) {
                if (jsonData.isString()) {
                    return (Color) Skin.this.get(jsonData.asString(), Color.class);
                }
                String hex = (String) json2.readValue("hex", (Class<Class>) String.class, (Class) null, jsonData);
                if (hex != null) {
                    return Color.valueOf(hex);
                }
                float r = ((Float) json2.readValue("r", (Class<Class>) Float.TYPE, (Class) Float.valueOf(0.0f), jsonData)).floatValue();
                float g = ((Float) json2.readValue("g", (Class<Class>) Float.TYPE, (Class) Float.valueOf(0.0f), jsonData)).floatValue();
                float b = ((Float) json2.readValue("b", (Class<Class>) Float.TYPE, (Class) Float.valueOf(0.0f), jsonData)).floatValue();
                float a = ((Float) json2.readValue("a", (Class<Class>) Float.TYPE, (Class) Float.valueOf(1.0f), jsonData)).floatValue();
                return new Color(r, g, b, a);
            }
        });
        json.setSerializer(TintedDrawable.class, new Json.ReadOnlySerializer() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Skin.5
            @Override // com.badlogic.gdx.utils.Json.ReadOnlySerializer, com.badlogic.gdx.utils.Json.Serializer
            public Object read(Json json2, JsonValue jsonData, Class type) {
                String name = (String) json2.readValue("name", String.class, jsonData);
                Color color = (Color) json2.readValue("color", Color.class, jsonData);
                if (color == null) {
                    throw new SerializationException("TintedDrawable missing color: " + jsonData);
                }
                Drawable drawable = Skin.this.newDrawable(name, color);
                if (drawable instanceof BaseDrawable) {
                    BaseDrawable named = (BaseDrawable) drawable;
                    named.setName(jsonData.name + " (" + name + ", " + color + ")");
                }
                return drawable;
            }
        });
        ObjectMap.Entries<String, Class> it = this.jsonClassTags.iterator();
        while (it.hasNext()) {
            ObjectMap.Entry entry = it.next();
            json.addClassTag((String) entry.key, (Class) entry.value);
        }
        return json;
    }

    public ObjectMap<String, Class> getJsonClassTags() {
        return this.jsonClassTags;
    }

    private static Method findMethod(Class type, String name) {
        Method[] methods = ClassReflection.getMethods(type);
        for (Method method : methods) {
            if (method.getName().equals(name)) {
                return method;
            }
        }
        return null;
    }
}