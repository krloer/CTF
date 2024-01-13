package com.kotcrab.vis.ui.widget.color.internal;

import com.badlogic.gdx.Files;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.utils.Disposable;
import com.kotcrab.vis.ui.Sizes;
import com.kotcrab.vis.ui.widget.color.ColorPickerWidgetStyle;

/* loaded from: classes.dex */
public class PickerCommons implements Disposable {
    ShaderProgram gridShader;
    ShaderProgram hsvShader;
    private boolean loadExtendedShaders;
    ShaderProgram paletteShader;
    ShaderProgram rgbShader;
    final Sizes sizes;
    final ColorPickerWidgetStyle style;
    ShaderProgram verticalChannelShader;
    Texture whiteTexture;

    public PickerCommons(ColorPickerWidgetStyle style, Sizes sizes, boolean loadExtendedShaders) {
        this.style = style;
        this.sizes = sizes;
        this.loadExtendedShaders = loadExtendedShaders;
        createPixmap();
        loadShaders();
    }

    private void createPixmap() {
        Pixmap whitePixmap = new Pixmap(2, 2, Pixmap.Format.RGB888);
        whitePixmap.setColor(Color.WHITE);
        whitePixmap.drawRectangle(0, 0, 2, 2);
        this.whiteTexture = new Texture(whitePixmap);
        this.whiteTexture.setWrap(Texture.TextureWrap.Repeat, Texture.TextureWrap.Repeat);
        whitePixmap.dispose();
    }

    private void loadShaders() {
        this.paletteShader = loadShader("default.vert", "palette.frag");
        this.verticalChannelShader = loadShader("default.vert", "verticalBar.frag");
        this.gridShader = loadShader("default.vert", "checkerboard.frag");
        if (this.loadExtendedShaders) {
            this.hsvShader = loadShader("default.vert", "hsv.frag");
            this.rgbShader = loadShader("default.vert", "rgb.frag");
        }
    }

    private ShaderProgram loadShader(String vertFile, String fragFile) {
        Files files = Gdx.files;
        FileHandle classpath = files.classpath("com/kotcrab/vis/ui/widget/color/internal/" + vertFile);
        Files files2 = Gdx.files;
        ShaderProgram program = new ShaderProgram(classpath, files2.classpath("com/kotcrab/vis/ui/widget/color/internal/" + fragFile));
        if (!program.isCompiled()) {
            throw new IllegalStateException("ColorPicker shader compilation failed. Shader: " + vertFile + ", " + fragFile + ": " + program.getLog());
        }
        return program;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ShaderProgram getBarShader(int mode) {
        switch (mode) {
            case 0:
            case 1:
            case 2:
            case 3:
                return this.rgbShader;
            case 4:
            case 5:
            case 6:
                return this.hsvShader;
            default:
                throw new IllegalStateException("Unsupported mode: " + mode);
        }
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        this.whiteTexture.dispose();
        this.paletteShader.dispose();
        this.verticalChannelShader.dispose();
        this.gridShader.dispose();
        if (this.loadExtendedShaders) {
            this.hsvShader.dispose();
            this.rgbShader.dispose();
        }
    }
}