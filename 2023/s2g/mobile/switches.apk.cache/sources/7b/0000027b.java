package com.badlogic.gdx.graphics.glutils;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Mesh;
import com.badlogic.gdx.graphics.VertexAttribute;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class ImmediateModeRenderer20 implements ImmediateModeRenderer {
    private final int colorOffset;
    private final int maxVertices;
    private final Mesh mesh;
    private final int normalOffset;
    private int numSetTexCoords;
    private final int numTexCoords;
    private int numVertices;
    private boolean ownsShader;
    private int primitiveType;
    private final Matrix4 projModelView;
    private ShaderProgram shader;
    private final String[] shaderUniformNames;
    private final int texCoordOffset;
    private int vertexIdx;
    private final int vertexSize;
    private final float[] vertices;

    public ImmediateModeRenderer20(boolean hasNormals, boolean hasColors, int numTexCoords) {
        this(5000, hasNormals, hasColors, numTexCoords, createDefaultShader(hasNormals, hasColors, numTexCoords));
        this.ownsShader = true;
    }

    public ImmediateModeRenderer20(int maxVertices, boolean hasNormals, boolean hasColors, int numTexCoords) {
        this(maxVertices, hasNormals, hasColors, numTexCoords, createDefaultShader(hasNormals, hasColors, numTexCoords));
        this.ownsShader = true;
    }

    public ImmediateModeRenderer20(int maxVertices, boolean hasNormals, boolean hasColors, int numTexCoords, ShaderProgram shader) {
        this.projModelView = new Matrix4();
        this.maxVertices = maxVertices;
        this.numTexCoords = numTexCoords;
        this.shader = shader;
        VertexAttribute[] attribs = buildVertexAttributes(hasNormals, hasColors, numTexCoords);
        this.mesh = new Mesh(false, maxVertices, 0, attribs);
        this.vertices = new float[(this.mesh.getVertexAttributes().vertexSize / 4) * maxVertices];
        this.vertexSize = this.mesh.getVertexAttributes().vertexSize / 4;
        this.normalOffset = this.mesh.getVertexAttribute(8) != null ? this.mesh.getVertexAttribute(8).offset / 4 : 0;
        this.colorOffset = this.mesh.getVertexAttribute(4) != null ? this.mesh.getVertexAttribute(4).offset / 4 : 0;
        this.texCoordOffset = this.mesh.getVertexAttribute(16) != null ? this.mesh.getVertexAttribute(16).offset / 4 : 0;
        this.shaderUniformNames = new String[numTexCoords];
        for (int i = 0; i < numTexCoords; i++) {
            String[] strArr = this.shaderUniformNames;
            strArr[i] = "u_sampler" + i;
        }
    }

    private VertexAttribute[] buildVertexAttributes(boolean hasNormals, boolean hasColor, int numTexCoords) {
        Array<VertexAttribute> attribs = new Array<>();
        attribs.add(new VertexAttribute(1, 3, ShaderProgram.POSITION_ATTRIBUTE));
        if (hasNormals) {
            attribs.add(new VertexAttribute(8, 3, ShaderProgram.NORMAL_ATTRIBUTE));
        }
        if (hasColor) {
            attribs.add(new VertexAttribute(4, 4, ShaderProgram.COLOR_ATTRIBUTE));
        }
        for (int i = 0; i < numTexCoords; i++) {
            attribs.add(new VertexAttribute(16, 2, ShaderProgram.TEXCOORD_ATTRIBUTE + i));
        }
        int i2 = attribs.size;
        VertexAttribute[] array = new VertexAttribute[i2];
        for (int i3 = 0; i3 < attribs.size; i3++) {
            array[i3] = attribs.get(i3);
        }
        return array;
    }

    public void setShader(ShaderProgram shader) {
        if (this.ownsShader) {
            this.shader.dispose();
        }
        this.shader = shader;
        this.ownsShader = false;
    }

    public ShaderProgram getShader() {
        return this.shader;
    }

    @Override // com.badlogic.gdx.graphics.glutils.ImmediateModeRenderer
    public void begin(Matrix4 projModelView, int primitiveType) {
        this.projModelView.set(projModelView);
        this.primitiveType = primitiveType;
    }

    @Override // com.badlogic.gdx.graphics.glutils.ImmediateModeRenderer
    public void color(Color color) {
        this.vertices[this.vertexIdx + this.colorOffset] = color.toFloatBits();
    }

    @Override // com.badlogic.gdx.graphics.glutils.ImmediateModeRenderer
    public void color(float r, float g, float b, float a) {
        this.vertices[this.vertexIdx + this.colorOffset] = Color.toFloatBits(r, g, b, a);
    }

    @Override // com.badlogic.gdx.graphics.glutils.ImmediateModeRenderer
    public void color(float colorBits) {
        this.vertices[this.vertexIdx + this.colorOffset] = colorBits;
    }

    @Override // com.badlogic.gdx.graphics.glutils.ImmediateModeRenderer
    public void texCoord(float u, float v) {
        int idx = this.vertexIdx + this.texCoordOffset;
        float[] fArr = this.vertices;
        int i = this.numSetTexCoords;
        fArr[idx + i] = u;
        fArr[idx + i + 1] = v;
        this.numSetTexCoords = i + 2;
    }

    @Override // com.badlogic.gdx.graphics.glutils.ImmediateModeRenderer
    public void normal(float x, float y, float z) {
        int idx = this.vertexIdx + this.normalOffset;
        float[] fArr = this.vertices;
        fArr[idx] = x;
        fArr[idx + 1] = y;
        fArr[idx + 2] = z;
    }

    @Override // com.badlogic.gdx.graphics.glutils.ImmediateModeRenderer
    public void vertex(float x, float y, float z) {
        int idx = this.vertexIdx;
        float[] fArr = this.vertices;
        fArr[idx] = x;
        fArr[idx + 1] = y;
        fArr[idx + 2] = z;
        this.numSetTexCoords = 0;
        this.vertexIdx += this.vertexSize;
        this.numVertices++;
    }

    @Override // com.badlogic.gdx.graphics.glutils.ImmediateModeRenderer
    public void flush() {
        if (this.numVertices == 0) {
            return;
        }
        this.shader.bind();
        this.shader.setUniformMatrix("u_projModelView", this.projModelView);
        for (int i = 0; i < this.numTexCoords; i++) {
            this.shader.setUniformi(this.shaderUniformNames[i], i);
        }
        this.mesh.setVertices(this.vertices, 0, this.vertexIdx);
        this.mesh.render(this.shader, this.primitiveType);
        this.numSetTexCoords = 0;
        this.vertexIdx = 0;
        this.numVertices = 0;
    }

    @Override // com.badlogic.gdx.graphics.glutils.ImmediateModeRenderer
    public void end() {
        flush();
    }

    @Override // com.badlogic.gdx.graphics.glutils.ImmediateModeRenderer
    public int getNumVertices() {
        return this.numVertices;
    }

    @Override // com.badlogic.gdx.graphics.glutils.ImmediateModeRenderer
    public int getMaxVertices() {
        return this.maxVertices;
    }

    @Override // com.badlogic.gdx.graphics.glutils.ImmediateModeRenderer
    public void dispose() {
        ShaderProgram shaderProgram;
        if (this.ownsShader && (shaderProgram = this.shader) != null) {
            shaderProgram.dispose();
        }
        this.mesh.dispose();
    }

    private static String createVertexShader(boolean hasNormals, boolean hasColors, int numTexCoords) {
        StringBuilder sb = new StringBuilder();
        sb.append("attribute vec4 a_position;\n");
        String str = BuildConfig.FLAVOR;
        sb.append(hasNormals ? "attribute vec3 a_normal;\n" : BuildConfig.FLAVOR);
        sb.append(hasColors ? "attribute vec4 a_color;\n" : BuildConfig.FLAVOR);
        String shader = sb.toString();
        for (int i = 0; i < numTexCoords; i++) {
            shader = shader + "attribute vec2 a_texCoord" + i + ";\n";
        }
        StringBuilder sb2 = new StringBuilder();
        sb2.append(shader);
        sb2.append("uniform mat4 u_projModelView;\n");
        if (hasColors) {
            str = "varying vec4 v_col;\n";
        }
        sb2.append(str);
        String shader2 = sb2.toString();
        for (int i2 = 0; i2 < numTexCoords; i2++) {
            shader2 = shader2 + "varying vec2 v_tex" + i2 + ";\n";
        }
        String shader3 = shader2 + "void main() {\n   gl_Position = u_projModelView * a_position;\n";
        if (hasColors) {
            shader3 = shader3 + "   v_col = a_color;\n   v_col.a *= 255.0 / 254.0;\n";
        }
        for (int i3 = 0; i3 < numTexCoords; i3++) {
            shader3 = shader3 + "   v_tex" + i3 + " = " + ShaderProgram.TEXCOORD_ATTRIBUTE + i3 + ";\n";
        }
        return shader3 + "   gl_PointSize = 1.0;\n}\n";
    }

    private static String createFragmentShader(boolean hasNormals, boolean hasColors, int numTexCoords) {
        String shader = hasColors ? "#ifdef GL_ES\nprecision mediump float;\n#endif\nvarying vec4 v_col;\n" : "#ifdef GL_ES\nprecision mediump float;\n#endif\n";
        for (int i = 0; i < numTexCoords; i++) {
            shader = (shader + "varying vec2 v_tex" + i + ";\n") + "uniform sampler2D u_sampler" + i + ";\n";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(shader);
        sb.append("void main() {\n   gl_FragColor = ");
        sb.append(hasColors ? "v_col" : "vec4(1, 1, 1, 1)");
        String shader2 = sb.toString();
        if (numTexCoords > 0) {
            shader2 = shader2 + " * ";
        }
        for (int i2 = 0; i2 < numTexCoords; i2++) {
            shader2 = i2 == numTexCoords - 1 ? shader2 + " texture2D(u_sampler" + i2 + ",  v_tex" + i2 + ")" : shader2 + " texture2D(u_sampler" + i2 + ",  v_tex" + i2 + ") *";
        }
        return shader2 + ";\n}";
    }

    public static ShaderProgram createDefaultShader(boolean hasNormals, boolean hasColors, int numTexCoords) {
        String vertexShader = createVertexShader(hasNormals, hasColors, numTexCoords);
        String fragmentShader = createFragmentShader(hasNormals, hasColors, numTexCoords);
        ShaderProgram program = new ShaderProgram(vertexShader, fragmentShader);
        if (!program.isCompiled()) {
            throw new GdxRuntimeException("Error compiling shader: " + program.getLog());
        }
        return program;
    }
}