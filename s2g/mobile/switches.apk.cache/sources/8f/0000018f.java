package com.badlogic.gdx.graphics.g3d.loader;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g3d.model.data.ModelMaterial;
import com.badlogic.gdx.graphics.g3d.model.data.ModelTexture;
import com.badlogic.gdx.utils.Array;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/* compiled from: ObjLoader.java */
/* loaded from: classes.dex */
class MtlLoader {
    public Array<ModelMaterial> materials = new Array<>();

    public void load(FileHandle file) {
        String curMatName = "default";
        Color difcolor = Color.WHITE;
        Color speccolor = Color.WHITE;
        float opacity = 1.0f;
        float shininess = 0.0f;
        String texFilename = null;
        if (file == null || !file.exists()) {
            return;
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(file.read()), 4096);
        while (true) {
            try {
                String readLine = reader.readLine();
                String line = readLine;
                if (readLine == null) {
                    break;
                }
                if (line.length() > 0 && line.charAt(0) == '\t') {
                    line = line.substring(1).trim();
                }
                String[] tokens = line.split("\\s+");
                if (tokens[0].length() != 0 && tokens[0].charAt(0) != '#') {
                    String key = tokens[0].toLowerCase();
                    if (key.equals("newmtl")) {
                        ModelMaterial mat = new ModelMaterial();
                        mat.id = curMatName;
                        mat.diffuse = new Color(difcolor);
                        mat.specular = new Color(speccolor);
                        mat.opacity = opacity;
                        mat.shininess = shininess;
                        if (texFilename != null) {
                            ModelTexture tex = new ModelTexture();
                            tex.usage = 2;
                            tex.fileName = new String(texFilename);
                            if (mat.textures == null) {
                                mat.textures = new Array<>(1);
                            }
                            mat.textures.add(tex);
                        }
                        this.materials.add(mat);
                        if (tokens.length > 1) {
                            String curMatName2 = tokens[1];
                            curMatName = curMatName2.replace('.', '_');
                        } else {
                            curMatName = "default";
                        }
                        difcolor = Color.WHITE;
                        speccolor = Color.WHITE;
                        opacity = 1.0f;
                        shininess = 0.0f;
                    } else {
                        if (!key.equals("kd") && !key.equals("ks")) {
                            if (!key.equals("tr") && !key.equals("d")) {
                                if (key.equals("ns")) {
                                    shininess = Float.parseFloat(tokens[1]);
                                } else if (key.equals("map_kd")) {
                                    texFilename = file.parent().child(tokens[1]).path();
                                }
                            }
                            opacity = Float.parseFloat(tokens[1]);
                        }
                        float r = Float.parseFloat(tokens[1]);
                        float g = Float.parseFloat(tokens[2]);
                        float b = Float.parseFloat(tokens[3]);
                        float a = tokens.length > 4 ? Float.parseFloat(tokens[4]) : 1.0f;
                        if (tokens[0].toLowerCase().equals("kd")) {
                            difcolor = new Color();
                            difcolor.set(r, g, b, a);
                        } else {
                            speccolor = new Color();
                            speccolor.set(r, g, b, a);
                        }
                    }
                }
            } catch (IOException e) {
                return;
            }
        }
        reader.close();
        ModelMaterial mat2 = new ModelMaterial();
        mat2.id = curMatName;
        mat2.diffuse = new Color(difcolor);
        mat2.specular = new Color(speccolor);
        mat2.opacity = opacity;
        mat2.shininess = shininess;
        if (texFilename != null) {
            ModelTexture tex2 = new ModelTexture();
            tex2.usage = 2;
            tex2.fileName = new String(texFilename);
            if (mat2.textures == null) {
                mat2.textures = new Array<>(1);
            }
            mat2.textures.add(tex2);
        }
        this.materials.add(mat2);
    }

    public ModelMaterial getMaterial(String name) {
        Array.ArrayIterator<ModelMaterial> it = this.materials.iterator();
        while (it.hasNext()) {
            ModelMaterial m = it.next();
            if (m.id.equals(name)) {
                return m;
            }
        }
        ModelMaterial mat = new ModelMaterial();
        mat.id = name;
        mat.diffuse = new Color(Color.WHITE);
        this.materials.add(mat);
        return mat;
    }
}