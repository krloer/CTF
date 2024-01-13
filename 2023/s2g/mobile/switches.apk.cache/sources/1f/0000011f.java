package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.math.collision.BoundingBox;
import com.badlogic.gdx.utils.Array;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.Writer;
import java.util.Arrays;

/* loaded from: classes.dex */
public class ParticleEmitter {
    private static final int UPDATE_ANGLE = 2;
    private static final int UPDATE_GRAVITY = 32;
    private static final int UPDATE_ROTATION = 4;
    private static final int UPDATE_SCALE = 1;
    private static final int UPDATE_SPRITE = 128;
    private static final int UPDATE_TINT = 64;
    private static final int UPDATE_VELOCITY = 8;
    private static final int UPDATE_WIND = 16;
    private float accumulator;
    private boolean[] active;
    private int activeCount;
    private boolean additive;
    private boolean aligned;
    private boolean allowCompletion;
    private ScaledNumericValue angleValue;
    private boolean attached;
    private boolean behind;
    private BoundingBox bounds;
    boolean cleansUpBlendFunction;
    private boolean continuous;
    private float delay;
    private float delayTimer;
    private RangedNumericValue delayValue;
    public float duration;
    public float durationTimer;
    private RangedNumericValue durationValue;
    private int emission;
    private int emissionDelta;
    private int emissionDiff;
    private ScaledNumericValue emissionValue;
    private boolean firstUpdate;
    private boolean flipX;
    private boolean flipY;
    private ScaledNumericValue gravityValue;
    private Array<String> imagePaths;
    private int life;
    private int lifeDiff;
    private int lifeOffset;
    private int lifeOffsetDiff;
    private IndependentScaledNumericValue lifeOffsetValue;
    private IndependentScaledNumericValue lifeValue;
    private int maxParticleCount;
    private int minParticleCount;
    private RangedNumericValue[] motionValues;
    private String name;
    private Particle[] particles;
    private boolean premultipliedAlpha;
    private ScaledNumericValue rotationValue;
    private float spawnHeight;
    private float spawnHeightDiff;
    private ScaledNumericValue spawnHeightValue;
    private SpawnShapeValue spawnShapeValue;
    private float spawnWidth;
    private float spawnWidthDiff;
    private ScaledNumericValue spawnWidthValue;
    private SpriteMode spriteMode;
    private Array<Sprite> sprites;
    private GradientColorValue tintValue;
    private ScaledNumericValue transparencyValue;
    private int updateFlags;
    private ScaledNumericValue velocityValue;
    private ScaledNumericValue windValue;
    private float x;
    private RangedNumericValue xOffsetValue;
    private ScaledNumericValue xScaleValue;
    private RangedNumericValue[] xSizeValues;
    private float y;
    private RangedNumericValue yOffsetValue;
    private ScaledNumericValue yScaleValue;
    private RangedNumericValue[] ySizeValues;

    /* loaded from: classes.dex */
    public enum SpawnEllipseSide {
        both,
        top,
        bottom
    }

    /* loaded from: classes.dex */
    public enum SpawnShape {
        point,
        line,
        square,
        ellipse
    }

    /* loaded from: classes.dex */
    public enum SpriteMode {
        single,
        random,
        animated
    }

    public ParticleEmitter() {
        this.delayValue = new RangedNumericValue();
        this.lifeOffsetValue = new IndependentScaledNumericValue();
        this.durationValue = new RangedNumericValue();
        this.lifeValue = new IndependentScaledNumericValue();
        this.emissionValue = new ScaledNumericValue();
        this.xScaleValue = new ScaledNumericValue();
        this.yScaleValue = new ScaledNumericValue();
        this.rotationValue = new ScaledNumericValue();
        this.velocityValue = new ScaledNumericValue();
        this.angleValue = new ScaledNumericValue();
        this.windValue = new ScaledNumericValue();
        this.gravityValue = new ScaledNumericValue();
        this.transparencyValue = new ScaledNumericValue();
        this.tintValue = new GradientColorValue();
        this.xOffsetValue = new ScaledNumericValue();
        this.yOffsetValue = new ScaledNumericValue();
        this.spawnWidthValue = new ScaledNumericValue();
        this.spawnHeightValue = new ScaledNumericValue();
        this.spawnShapeValue = new SpawnShapeValue();
        this.spriteMode = SpriteMode.single;
        this.maxParticleCount = 4;
        this.duration = 1.0f;
        this.additive = true;
        this.premultipliedAlpha = false;
        this.cleansUpBlendFunction = true;
        initialize();
    }

    public ParticleEmitter(BufferedReader reader) throws IOException {
        this.delayValue = new RangedNumericValue();
        this.lifeOffsetValue = new IndependentScaledNumericValue();
        this.durationValue = new RangedNumericValue();
        this.lifeValue = new IndependentScaledNumericValue();
        this.emissionValue = new ScaledNumericValue();
        this.xScaleValue = new ScaledNumericValue();
        this.yScaleValue = new ScaledNumericValue();
        this.rotationValue = new ScaledNumericValue();
        this.velocityValue = new ScaledNumericValue();
        this.angleValue = new ScaledNumericValue();
        this.windValue = new ScaledNumericValue();
        this.gravityValue = new ScaledNumericValue();
        this.transparencyValue = new ScaledNumericValue();
        this.tintValue = new GradientColorValue();
        this.xOffsetValue = new ScaledNumericValue();
        this.yOffsetValue = new ScaledNumericValue();
        this.spawnWidthValue = new ScaledNumericValue();
        this.spawnHeightValue = new ScaledNumericValue();
        this.spawnShapeValue = new SpawnShapeValue();
        this.spriteMode = SpriteMode.single;
        this.maxParticleCount = 4;
        this.duration = 1.0f;
        this.additive = true;
        this.premultipliedAlpha = false;
        this.cleansUpBlendFunction = true;
        initialize();
        load(reader);
    }

    public ParticleEmitter(ParticleEmitter emitter) {
        this.delayValue = new RangedNumericValue();
        this.lifeOffsetValue = new IndependentScaledNumericValue();
        this.durationValue = new RangedNumericValue();
        this.lifeValue = new IndependentScaledNumericValue();
        this.emissionValue = new ScaledNumericValue();
        this.xScaleValue = new ScaledNumericValue();
        this.yScaleValue = new ScaledNumericValue();
        this.rotationValue = new ScaledNumericValue();
        this.velocityValue = new ScaledNumericValue();
        this.angleValue = new ScaledNumericValue();
        this.windValue = new ScaledNumericValue();
        this.gravityValue = new ScaledNumericValue();
        this.transparencyValue = new ScaledNumericValue();
        this.tintValue = new GradientColorValue();
        this.xOffsetValue = new ScaledNumericValue();
        this.yOffsetValue = new ScaledNumericValue();
        this.spawnWidthValue = new ScaledNumericValue();
        this.spawnHeightValue = new ScaledNumericValue();
        this.spawnShapeValue = new SpawnShapeValue();
        this.spriteMode = SpriteMode.single;
        this.maxParticleCount = 4;
        this.duration = 1.0f;
        this.additive = true;
        this.premultipliedAlpha = false;
        this.cleansUpBlendFunction = true;
        this.sprites = new Array<>(emitter.sprites);
        this.name = emitter.name;
        this.imagePaths = new Array<>(emitter.imagePaths);
        setMaxParticleCount(emitter.maxParticleCount);
        this.minParticleCount = emitter.minParticleCount;
        this.delayValue.load(emitter.delayValue);
        this.durationValue.load(emitter.durationValue);
        this.emissionValue.load(emitter.emissionValue);
        this.lifeValue.load(emitter.lifeValue);
        this.lifeOffsetValue.load(emitter.lifeOffsetValue);
        this.xScaleValue.load(emitter.xScaleValue);
        this.yScaleValue.load(emitter.yScaleValue);
        this.rotationValue.load(emitter.rotationValue);
        this.velocityValue.load(emitter.velocityValue);
        this.angleValue.load(emitter.angleValue);
        this.windValue.load(emitter.windValue);
        this.gravityValue.load(emitter.gravityValue);
        this.transparencyValue.load(emitter.transparencyValue);
        this.tintValue.load(emitter.tintValue);
        this.xOffsetValue.load(emitter.xOffsetValue);
        this.yOffsetValue.load(emitter.yOffsetValue);
        this.spawnWidthValue.load(emitter.spawnWidthValue);
        this.spawnHeightValue.load(emitter.spawnHeightValue);
        this.spawnShapeValue.load(emitter.spawnShapeValue);
        this.attached = emitter.attached;
        this.continuous = emitter.continuous;
        this.aligned = emitter.aligned;
        this.behind = emitter.behind;
        this.additive = emitter.additive;
        this.premultipliedAlpha = emitter.premultipliedAlpha;
        this.cleansUpBlendFunction = emitter.cleansUpBlendFunction;
        this.spriteMode = emitter.spriteMode;
        setPosition(emitter.getX(), emitter.getY());
    }

    private void initialize() {
        this.sprites = new Array<>();
        this.imagePaths = new Array<>();
        this.durationValue.setAlwaysActive(true);
        this.emissionValue.setAlwaysActive(true);
        this.lifeValue.setAlwaysActive(true);
        this.xScaleValue.setAlwaysActive(true);
        this.transparencyValue.setAlwaysActive(true);
        this.spawnShapeValue.setAlwaysActive(true);
        this.spawnWidthValue.setAlwaysActive(true);
        this.spawnHeightValue.setAlwaysActive(true);
    }

    public void setMaxParticleCount(int maxParticleCount) {
        this.maxParticleCount = maxParticleCount;
        this.active = new boolean[maxParticleCount];
        this.activeCount = 0;
        this.particles = new Particle[maxParticleCount];
    }

    public void addParticle() {
        int activeCount = this.activeCount;
        if (activeCount == this.maxParticleCount) {
            return;
        }
        boolean[] active = this.active;
        int n = active.length;
        for (int i = 0; i < n; i++) {
            if (!active[i]) {
                activateParticle(i);
                active[i] = true;
                this.activeCount = activeCount + 1;
                return;
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:10:0x0019, code lost:
        activateParticle(r1);
        r0[r1] = true;
        r3 = r3 + 1;
        r1 = r1 + 1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public void addParticles(int r7) {
        /*
            r6 = this;
            int r0 = r6.maxParticleCount
            int r1 = r6.activeCount
            int r0 = r0 - r1
            int r7 = java.lang.Math.min(r7, r0)
            if (r7 != 0) goto Lc
            return
        Lc:
            boolean[] r0 = r6.active
            r1 = 0
            int r2 = r0.length
            r3 = 0
        L11:
            if (r3 >= r7) goto L29
        L13:
            if (r1 >= r2) goto L29
            boolean r4 = r0[r1]
            if (r4 != 0) goto L26
            r6.activateParticle(r1)
            int r4 = r1 + 1
            r5 = 1
            r0[r1] = r5
            int r3 = r3 + 1
            r1 = r4
            goto L11
        L26:
            int r1 = r1 + 1
            goto L13
        L29:
            int r3 = r6.activeCount
            int r3 = r3 + r7
            r6.activeCount = r3
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.graphics.g2d.ParticleEmitter.addParticles(int):void");
    }

    public void update(float delta) {
        this.accumulator += delta * 1000.0f;
        float f = this.accumulator;
        if (f < 1.0f) {
            return;
        }
        int deltaMillis = (int) f;
        this.accumulator = f - deltaMillis;
        float f2 = this.delayTimer;
        if (f2 < this.delay) {
            this.delayTimer = f2 + deltaMillis;
        } else {
            boolean done = false;
            if (this.firstUpdate) {
                this.firstUpdate = false;
                addParticle();
            }
            float f3 = this.durationTimer;
            if (f3 < this.duration) {
                this.durationTimer = f3 + deltaMillis;
            } else if (!this.continuous || this.allowCompletion) {
                done = true;
            } else {
                restart();
            }
            if (!done) {
                this.emissionDelta += deltaMillis;
                float emissionTime = this.emission + (this.emissionDiff * this.emissionValue.getScale(this.durationTimer / this.duration));
                if (emissionTime > 0.0f) {
                    float emissionTime2 = 1000.0f / emissionTime;
                    int i = this.emissionDelta;
                    if (i >= emissionTime2) {
                        int emitCount = Math.min((int) (i / emissionTime2), this.maxParticleCount - this.activeCount);
                        this.emissionDelta = (int) (this.emissionDelta - (emitCount * emissionTime2));
                        this.emissionDelta = (int) (this.emissionDelta % emissionTime2);
                        addParticles(emitCount);
                    }
                }
                int emitCount2 = this.activeCount;
                int i2 = this.minParticleCount;
                if (emitCount2 < i2) {
                    addParticles(i2 - emitCount2);
                }
            }
        }
        boolean[] active = this.active;
        int activeCount = this.activeCount;
        Particle[] particles = this.particles;
        int n = active.length;
        for (int i3 = 0; i3 < n; i3++) {
            if (active[i3] && !updateParticle(particles[i3], delta, deltaMillis)) {
                active[i3] = false;
                activeCount--;
            }
        }
        this.activeCount = activeCount;
    }

    public void draw(Batch batch) {
        if (this.premultipliedAlpha) {
            batch.setBlendFunction(1, GL20.GL_ONE_MINUS_SRC_ALPHA);
        } else if (this.additive) {
            batch.setBlendFunction(GL20.GL_SRC_ALPHA, 1);
        } else {
            batch.setBlendFunction(GL20.GL_SRC_ALPHA, GL20.GL_ONE_MINUS_SRC_ALPHA);
        }
        Particle[] particles = this.particles;
        boolean[] active = this.active;
        int n = active.length;
        for (int i = 0; i < n; i++) {
            if (active[i]) {
                particles[i].draw(batch);
            }
        }
        if (this.cleansUpBlendFunction) {
            if (this.additive || this.premultipliedAlpha) {
                batch.setBlendFunction(GL20.GL_SRC_ALPHA, GL20.GL_ONE_MINUS_SRC_ALPHA);
            }
        }
    }

    public void draw(Batch batch, float delta) {
        this.accumulator += delta * 1000.0f;
        float f = this.accumulator;
        if (f < 1.0f) {
            draw(batch);
            return;
        }
        int deltaMillis = (int) f;
        this.accumulator = f - deltaMillis;
        if (this.premultipliedAlpha) {
            batch.setBlendFunction(1, GL20.GL_ONE_MINUS_SRC_ALPHA);
        } else if (this.additive) {
            batch.setBlendFunction(GL20.GL_SRC_ALPHA, 1);
        } else {
            batch.setBlendFunction(GL20.GL_SRC_ALPHA, GL20.GL_ONE_MINUS_SRC_ALPHA);
        }
        Particle[] particles = this.particles;
        boolean[] active = this.active;
        int activeCount = this.activeCount;
        int n = active.length;
        for (int i = 0; i < n; i++) {
            if (active[i]) {
                Particle particle = particles[i];
                if (updateParticle(particle, delta, deltaMillis)) {
                    particle.draw(batch);
                } else {
                    active[i] = false;
                    activeCount--;
                }
            }
        }
        this.activeCount = activeCount;
        if (this.cleansUpBlendFunction && (this.additive || this.premultipliedAlpha)) {
            batch.setBlendFunction(GL20.GL_SRC_ALPHA, GL20.GL_ONE_MINUS_SRC_ALPHA);
        }
        float f2 = this.delayTimer;
        if (f2 < this.delay) {
            this.delayTimer = f2 + deltaMillis;
            return;
        }
        if (this.firstUpdate) {
            this.firstUpdate = false;
            addParticle();
        }
        float f3 = this.durationTimer;
        if (f3 < this.duration) {
            this.durationTimer = f3 + deltaMillis;
        } else if (!this.continuous || this.allowCompletion) {
            return;
        } else {
            restart();
        }
        this.emissionDelta += deltaMillis;
        float emissionTime = this.emission + (this.emissionDiff * this.emissionValue.getScale(this.durationTimer / this.duration));
        if (emissionTime > 0.0f) {
            float emissionTime2 = 1000.0f / emissionTime;
            int i2 = this.emissionDelta;
            if (i2 >= emissionTime2) {
                int emitCount = Math.min((int) (i2 / emissionTime2), this.maxParticleCount - activeCount);
                this.emissionDelta = (int) (this.emissionDelta - (emitCount * emissionTime2));
                this.emissionDelta = (int) (this.emissionDelta % emissionTime2);
                addParticles(emitCount);
            }
        }
        int emitCount2 = this.minParticleCount;
        if (activeCount < emitCount2) {
            addParticles(emitCount2 - activeCount);
        }
    }

    public void start() {
        this.firstUpdate = true;
        this.allowCompletion = false;
        restart();
    }

    public void reset() {
        this.emissionDelta = 0;
        this.durationTimer = this.duration;
        boolean[] active = this.active;
        int n = active.length;
        for (int i = 0; i < n; i++) {
            active[i] = false;
        }
        this.activeCount = 0;
        start();
    }

    private void restart() {
        this.delay = this.delayValue.active ? this.delayValue.newLowValue() : 0.0f;
        this.delayTimer = 0.0f;
        this.durationTimer -= this.duration;
        this.duration = this.durationValue.newLowValue();
        this.emission = (int) this.emissionValue.newLowValue();
        this.emissionDiff = (int) this.emissionValue.newHighValue();
        if (!this.emissionValue.isRelative()) {
            this.emissionDiff -= this.emission;
        }
        if (!this.lifeValue.independent) {
            generateLifeValues();
        }
        if (!this.lifeOffsetValue.independent) {
            generateLifeOffsetValues();
        }
        this.spawnWidth = this.spawnWidthValue.newLowValue();
        this.spawnWidthDiff = this.spawnWidthValue.newHighValue();
        if (!this.spawnWidthValue.isRelative()) {
            this.spawnWidthDiff -= this.spawnWidth;
        }
        this.spawnHeight = this.spawnHeightValue.newLowValue();
        this.spawnHeightDiff = this.spawnHeightValue.newHighValue();
        if (!this.spawnHeightValue.isRelative()) {
            this.spawnHeightDiff -= this.spawnHeight;
        }
        this.updateFlags = 0;
        if (this.angleValue.active && this.angleValue.timeline.length > 1) {
            this.updateFlags |= 2;
        }
        if (this.velocityValue.active) {
            this.updateFlags |= 8;
        }
        if (this.xScaleValue.timeline.length > 1) {
            this.updateFlags |= 1;
        }
        if (this.yScaleValue.active && this.yScaleValue.timeline.length > 1) {
            this.updateFlags |= 1;
        }
        if (this.rotationValue.active && this.rotationValue.timeline.length > 1) {
            this.updateFlags |= 4;
        }
        if (this.windValue.active) {
            this.updateFlags |= 16;
        }
        if (this.gravityValue.active) {
            this.updateFlags |= 32;
        }
        if (this.tintValue.timeline.length > 1) {
            this.updateFlags |= 64;
        }
        if (this.spriteMode == SpriteMode.animated) {
            this.updateFlags |= 128;
        }
    }

    protected Particle newParticle(Sprite sprite) {
        return new Particle(sprite);
    }

    protected Particle[] getParticles() {
        return this.particles;
    }

    private void activateParticle(int index) {
        float scaleY;
        float px;
        float py;
        float spawnAngle;
        Sprite sprite = null;
        int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpriteMode[this.spriteMode.ordinal()];
        if (i == 1 || i == 2) {
            Sprite sprite2 = this.sprites.first();
            sprite = sprite2;
        } else if (i == 3) {
            Sprite sprite3 = this.sprites.random();
            sprite = sprite3;
        }
        Particle[] particleArr = this.particles;
        Particle particle = particleArr[index];
        if (particle == null) {
            Particle newParticle = newParticle(sprite);
            particle = newParticle;
            particleArr[index] = newParticle;
            particle.flip(this.flipX, this.flipY);
        } else {
            particle.set(sprite);
        }
        float percent = this.durationTimer / this.duration;
        int updateFlags = this.updateFlags;
        if (this.lifeValue.independent) {
            generateLifeValues();
        }
        if (this.lifeOffsetValue.independent) {
            generateLifeOffsetValues();
        }
        int scale = this.life + ((int) (this.lifeDiff * this.lifeValue.getScale(percent)));
        particle.life = scale;
        particle.currentLife = scale;
        if (this.velocityValue.active) {
            particle.velocity = this.velocityValue.newLowValue();
            particle.velocityDiff = this.velocityValue.newHighValue();
            if (!this.velocityValue.isRelative()) {
                particle.velocityDiff -= particle.velocity;
            }
        }
        particle.angle = this.angleValue.newLowValue();
        particle.angleDiff = this.angleValue.newHighValue();
        if (!this.angleValue.isRelative()) {
            particle.angleDiff -= particle.angle;
        }
        float angle = 0.0f;
        if ((updateFlags & 2) == 0) {
            angle = particle.angle + (particle.angleDiff * this.angleValue.getScale(0.0f));
            particle.angle = angle;
            particle.angleCos = MathUtils.cosDeg(angle);
            particle.angleSin = MathUtils.sinDeg(angle);
        }
        float spriteWidth = sprite.getWidth();
        float spriteHeight = sprite.getHeight();
        particle.xScale = this.xScaleValue.newLowValue() / spriteWidth;
        particle.xScaleDiff = this.xScaleValue.newHighValue() / spriteWidth;
        if (!this.xScaleValue.isRelative()) {
            particle.xScaleDiff -= particle.xScale;
        }
        if (!this.yScaleValue.active) {
            particle.setScale(particle.xScale + (particle.xScaleDiff * this.xScaleValue.getScale(0.0f)));
        } else {
            particle.yScale = this.yScaleValue.newLowValue() / spriteHeight;
            particle.yScaleDiff = this.yScaleValue.newHighValue() / spriteHeight;
            if (!this.yScaleValue.isRelative()) {
                particle.yScaleDiff -= particle.yScale;
            }
            particle.setScale(particle.xScale + (particle.xScaleDiff * this.xScaleValue.getScale(0.0f)), particle.yScale + (particle.yScaleDiff * this.yScaleValue.getScale(0.0f)));
        }
        if (this.rotationValue.active) {
            particle.rotation = this.rotationValue.newLowValue();
            particle.rotationDiff = this.rotationValue.newHighValue();
            if (!this.rotationValue.isRelative()) {
                particle.rotationDiff -= particle.rotation;
            }
            float rotation = particle.rotation + (particle.rotationDiff * this.rotationValue.getScale(0.0f));
            if (this.aligned) {
                rotation += angle;
            }
            particle.setRotation(rotation);
        }
        if (this.windValue.active) {
            particle.wind = this.windValue.newLowValue();
            particle.windDiff = this.windValue.newHighValue();
            if (!this.windValue.isRelative()) {
                particle.windDiff -= particle.wind;
            }
        }
        if (this.gravityValue.active) {
            particle.gravity = this.gravityValue.newLowValue();
            particle.gravityDiff = this.gravityValue.newHighValue();
            if (!this.gravityValue.isRelative()) {
                particle.gravityDiff -= particle.gravity;
            }
        }
        float[] color = particle.tint;
        if (color == null) {
            float[] fArr = new float[3];
            color = fArr;
            particle.tint = fArr;
        }
        float[] temp = this.tintValue.getColor(0.0f);
        color[0] = temp[0];
        color[1] = temp[1];
        color[2] = temp[2];
        particle.transparency = this.transparencyValue.newLowValue();
        particle.transparencyDiff = this.transparencyValue.newHighValue() - particle.transparency;
        float x = this.x;
        if (this.xOffsetValue.active) {
            x += this.xOffsetValue.newLowValue();
        }
        float y = this.y;
        if (this.yOffsetValue.active) {
            y += this.yOffsetValue.newLowValue();
        }
        int i2 = AnonymousClass1.$SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpawnShape[this.spawnShapeValue.shape.ordinal()];
        if (i2 == 1) {
            float width = this.spawnWidth + (this.spawnWidthDiff * this.spawnWidthValue.getScale(percent));
            float height = this.spawnHeight + (this.spawnHeightDiff * this.spawnHeightValue.getScale(percent));
            scaleY = 2.0f;
            x += MathUtils.random(width) - (width / 2.0f);
            y += MathUtils.random(height) - (height / 2.0f);
        } else if (i2 == 2) {
            float width2 = this.spawnWidth + (this.spawnWidthDiff * this.spawnWidthValue.getScale(percent));
            float radiusX = width2 / 2.0f;
            float radiusY = (this.spawnHeight + (this.spawnHeightDiff * this.spawnHeightValue.getScale(percent))) / 2.0f;
            if (radiusX != 0.0f && radiusY != 0.0f) {
                float scaleY2 = radiusX / radiusY;
                if (this.spawnShapeValue.edges) {
                    int i3 = AnonymousClass1.$SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpawnEllipseSide[this.spawnShapeValue.side.ordinal()];
                    if (i3 == 1) {
                        spawnAngle = -MathUtils.random(179.0f);
                    } else if (i3 == 2) {
                        spawnAngle = MathUtils.random(179.0f);
                    } else {
                        spawnAngle = MathUtils.random(360.0f);
                    }
                    float cosDeg = MathUtils.cosDeg(spawnAngle);
                    float sinDeg = MathUtils.sinDeg(spawnAngle);
                    x += cosDeg * radiusX;
                    y += (sinDeg * radiusX) / scaleY2;
                    if ((updateFlags & 2) == 0) {
                        particle.angle = spawnAngle;
                        particle.angleCos = cosDeg;
                        particle.angleSin = sinDeg;
                    }
                    scaleY = 2.0f;
                } else {
                    float radius2 = radiusX * radiusX;
                    do {
                        px = MathUtils.random(width2) - radiusX;
                        py = MathUtils.random(width2) - radiusX;
                    } while ((px * px) + (py * py) > radius2);
                    x += px;
                    y += py / scaleY2;
                    scaleY = 2.0f;
                }
            }
            scaleY = 2.0f;
        } else if (i2 == 3) {
            float width3 = this.spawnWidth + (this.spawnWidthDiff * this.spawnWidthValue.getScale(percent));
            float height2 = this.spawnHeight + (this.spawnHeightDiff * this.spawnHeightValue.getScale(percent));
            if (width3 != 0.0f) {
                float lineX = MathUtils.random() * width3;
                x += lineX;
                y += (height2 / width3) * lineX;
                scaleY = 2.0f;
            } else {
                y += MathUtils.random() * height2;
                scaleY = 2.0f;
            }
        } else {
            scaleY = 2.0f;
        }
        particle.setBounds(x - (spriteWidth / scaleY), y - (spriteHeight / scaleY), spriteWidth, spriteHeight);
        int offsetTime = (int) (this.lifeOffset + (this.lifeOffsetDiff * this.lifeOffsetValue.getScale(percent)));
        if (offsetTime > 0) {
            if (offsetTime >= particle.currentLife) {
                offsetTime = particle.currentLife - 1;
            }
            updateParticle(particle, offsetTime / 1000.0f, offsetTime);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: com.badlogic.gdx.graphics.g2d.ParticleEmitter$1  reason: invalid class name */
    /* loaded from: classes.dex */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpawnEllipseSide;
        static final /* synthetic */ int[] $SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpawnShape = new int[SpawnShape.values().length];
        static final /* synthetic */ int[] $SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpriteMode;

        static {
            try {
                $SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpawnShape[SpawnShape.square.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpawnShape[SpawnShape.ellipse.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpawnShape[SpawnShape.line.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            $SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpawnEllipseSide = new int[SpawnEllipseSide.values().length];
            try {
                $SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpawnEllipseSide[SpawnEllipseSide.top.ordinal()] = 1;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpawnEllipseSide[SpawnEllipseSide.bottom.ordinal()] = 2;
            } catch (NoSuchFieldError e5) {
            }
            $SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpriteMode = new int[SpriteMode.values().length];
            try {
                $SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpriteMode[SpriteMode.single.ordinal()] = 1;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpriteMode[SpriteMode.animated.ordinal()] = 2;
            } catch (NoSuchFieldError e7) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpriteMode[SpriteMode.random.ordinal()] = 3;
            } catch (NoSuchFieldError e8) {
            }
        }
    }

    private boolean updateParticle(Particle particle, float delta, int deltaMillis) {
        float[] color;
        int frame;
        float velocityX;
        float velocityY;
        int life = particle.currentLife - deltaMillis;
        if (life <= 0) {
            return false;
        }
        particle.currentLife = life;
        float percent = 1.0f - (particle.currentLife / particle.life);
        int updateFlags = this.updateFlags;
        if ((updateFlags & 1) != 0) {
            if (this.yScaleValue.active) {
                particle.setScale(particle.xScale + (particle.xScaleDiff * this.xScaleValue.getScale(percent)), particle.yScale + (particle.yScaleDiff * this.yScaleValue.getScale(percent)));
            } else {
                particle.setScale(particle.xScale + (particle.xScaleDiff * this.xScaleValue.getScale(percent)));
            }
        }
        if ((updateFlags & 8) != 0) {
            float velocity = (particle.velocity + (particle.velocityDiff * this.velocityValue.getScale(percent))) * delta;
            if ((updateFlags & 2) != 0) {
                float angle = particle.angle + (particle.angleDiff * this.angleValue.getScale(percent));
                velocityX = MathUtils.cosDeg(angle) * velocity;
                velocityY = MathUtils.sinDeg(angle) * velocity;
                if ((updateFlags & 4) != 0) {
                    float rotation = particle.rotation + (particle.rotationDiff * this.rotationValue.getScale(percent));
                    if (this.aligned) {
                        rotation += angle;
                    }
                    particle.setRotation(rotation);
                }
            } else {
                velocityX = velocity * particle.angleCos;
                velocityY = velocity * particle.angleSin;
                if (this.aligned || (updateFlags & 4) != 0) {
                    float rotation2 = particle.rotation + (particle.rotationDiff * this.rotationValue.getScale(percent));
                    if (this.aligned) {
                        rotation2 += particle.angle;
                    }
                    particle.setRotation(rotation2);
                }
            }
            if ((updateFlags & 16) != 0) {
                velocityX += (particle.wind + (particle.windDiff * this.windValue.getScale(percent))) * delta;
            }
            if ((updateFlags & 32) != 0) {
                velocityY += (particle.gravity + (particle.gravityDiff * this.gravityValue.getScale(percent))) * delta;
            }
            particle.translate(velocityX, velocityY);
        } else if ((updateFlags & 4) != 0) {
            particle.setRotation(particle.rotation + (particle.rotationDiff * this.rotationValue.getScale(percent)));
        }
        if ((updateFlags & 64) != 0) {
            color = this.tintValue.getColor(percent);
        } else {
            color = particle.tint;
        }
        if (this.premultipliedAlpha) {
            float alphaMultiplier = this.additive ? 0.0f : 1.0f;
            float a = particle.transparency + (particle.transparencyDiff * this.transparencyValue.getScale(percent));
            particle.setColor(color[0] * a, color[1] * a, color[2] * a, a * alphaMultiplier);
        } else {
            particle.setColor(color[0], color[1], color[2], particle.transparency + (particle.transparencyDiff * this.transparencyValue.getScale(percent)));
        }
        if ((updateFlags & 128) != 0 && particle.frame != (frame = Math.min((int) (this.sprites.size * percent), this.sprites.size - 1))) {
            Sprite sprite = this.sprites.get(frame);
            float prevSpriteWidth = particle.getWidth();
            float prevSpriteHeight = particle.getHeight();
            particle.setRegion(sprite);
            particle.setSize(sprite.getWidth(), sprite.getHeight());
            particle.setOrigin(sprite.getOriginX(), sprite.getOriginY());
            particle.translate((prevSpriteWidth - sprite.getWidth()) / 2.0f, (prevSpriteHeight - sprite.getHeight()) / 2.0f);
            particle.frame = frame;
        }
        return true;
    }

    private void generateLifeValues() {
        this.life = (int) this.lifeValue.newLowValue();
        this.lifeDiff = (int) this.lifeValue.newHighValue();
        if (!this.lifeValue.isRelative()) {
            this.lifeDiff -= this.life;
        }
    }

    private void generateLifeOffsetValues() {
        this.lifeOffset = this.lifeOffsetValue.active ? (int) this.lifeOffsetValue.newLowValue() : 0;
        this.lifeOffsetDiff = (int) this.lifeOffsetValue.newHighValue();
        if (!this.lifeOffsetValue.isRelative()) {
            this.lifeOffsetDiff -= this.lifeOffset;
        }
    }

    public void setPosition(float x, float y) {
        if (this.attached) {
            float xAmount = x - this.x;
            float yAmount = y - this.y;
            boolean[] active = this.active;
            int n = active.length;
            for (int i = 0; i < n; i++) {
                if (active[i]) {
                    this.particles[i].translate(xAmount, yAmount);
                }
            }
        }
        this.x = x;
        this.y = y;
    }

    public void setSprites(Array<Sprite> sprites) {
        this.sprites = sprites;
        if (sprites.size == 0) {
            return;
        }
        int n = this.particles.length;
        for (int i = 0; i < n; i++) {
            Particle particle = this.particles[i];
            if (particle != null) {
                Sprite sprite = null;
                int i2 = AnonymousClass1.$SwitchMap$com$badlogic$gdx$graphics$g2d$ParticleEmitter$SpriteMode[this.spriteMode.ordinal()];
                if (i2 == 1) {
                    Sprite sprite2 = sprites.first();
                    sprite = sprite2;
                } else if (i2 == 2) {
                    float percent = 1.0f - (particle.currentLife / particle.life);
                    particle.frame = Math.min((int) (sprites.size * percent), sprites.size - 1);
                    Sprite sprite3 = sprites.get(particle.frame);
                    sprite = sprite3;
                } else if (i2 == 3) {
                    Sprite sprite4 = sprites.random();
                    sprite = sprite4;
                }
                particle.setRegion(sprite);
                particle.setOrigin(sprite.getOriginX(), sprite.getOriginY());
            } else {
                return;
            }
        }
    }

    public void setSpriteMode(SpriteMode spriteMode) {
        this.spriteMode = spriteMode;
    }

    public void preAllocateParticles() {
        if (this.sprites.isEmpty()) {
            throw new IllegalStateException("ParticleEmitter.setSprites() must have been called before preAllocateParticles()");
        }
        int index = 0;
        while (true) {
            Particle[] particleArr = this.particles;
            if (index < particleArr.length) {
                if (particleArr[index] == null) {
                    Particle particle = newParticle(this.sprites.first());
                    particleArr[index] = particle;
                    particle.flip(this.flipX, this.flipY);
                }
                index++;
            } else {
                return;
            }
        }
    }

    public void allowCompletion() {
        this.allowCompletion = true;
        this.durationTimer = this.duration;
    }

    public Array<Sprite> getSprites() {
        return this.sprites;
    }

    public SpriteMode getSpriteMode() {
        return this.spriteMode;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public ScaledNumericValue getLife() {
        return this.lifeValue;
    }

    public ScaledNumericValue getXScale() {
        return this.xScaleValue;
    }

    public ScaledNumericValue getYScale() {
        return this.yScaleValue;
    }

    public ScaledNumericValue getRotation() {
        return this.rotationValue;
    }

    public GradientColorValue getTint() {
        return this.tintValue;
    }

    public ScaledNumericValue getVelocity() {
        return this.velocityValue;
    }

    public ScaledNumericValue getWind() {
        return this.windValue;
    }

    public ScaledNumericValue getGravity() {
        return this.gravityValue;
    }

    public ScaledNumericValue getAngle() {
        return this.angleValue;
    }

    public ScaledNumericValue getEmission() {
        return this.emissionValue;
    }

    public ScaledNumericValue getTransparency() {
        return this.transparencyValue;
    }

    public RangedNumericValue getDuration() {
        return this.durationValue;
    }

    public RangedNumericValue getDelay() {
        return this.delayValue;
    }

    public ScaledNumericValue getLifeOffset() {
        return this.lifeOffsetValue;
    }

    public RangedNumericValue getXOffsetValue() {
        return this.xOffsetValue;
    }

    public RangedNumericValue getYOffsetValue() {
        return this.yOffsetValue;
    }

    public ScaledNumericValue getSpawnWidth() {
        return this.spawnWidthValue;
    }

    public ScaledNumericValue getSpawnHeight() {
        return this.spawnHeightValue;
    }

    public SpawnShapeValue getSpawnShape() {
        return this.spawnShapeValue;
    }

    public boolean isAttached() {
        return this.attached;
    }

    public void setAttached(boolean attached) {
        this.attached = attached;
    }

    public boolean isContinuous() {
        return this.continuous;
    }

    public void setContinuous(boolean continuous) {
        this.continuous = continuous;
    }

    public boolean isAligned() {
        return this.aligned;
    }

    public void setAligned(boolean aligned) {
        this.aligned = aligned;
    }

    public boolean isAdditive() {
        return this.additive;
    }

    public void setAdditive(boolean additive) {
        this.additive = additive;
    }

    public boolean cleansUpBlendFunction() {
        return this.cleansUpBlendFunction;
    }

    public void setCleansUpBlendFunction(boolean cleansUpBlendFunction) {
        this.cleansUpBlendFunction = cleansUpBlendFunction;
    }

    public boolean isBehind() {
        return this.behind;
    }

    public void setBehind(boolean behind) {
        this.behind = behind;
    }

    public boolean isPremultipliedAlpha() {
        return this.premultipliedAlpha;
    }

    public void setPremultipliedAlpha(boolean premultipliedAlpha) {
        this.premultipliedAlpha = premultipliedAlpha;
    }

    public int getMinParticleCount() {
        return this.minParticleCount;
    }

    public void setMinParticleCount(int minParticleCount) {
        this.minParticleCount = minParticleCount;
    }

    public int getMaxParticleCount() {
        return this.maxParticleCount;
    }

    public boolean isComplete() {
        return (!this.continuous || this.allowCompletion) && this.delayTimer >= this.delay && this.durationTimer >= this.duration && this.activeCount == 0;
    }

    public float getPercentComplete() {
        if (this.delayTimer < this.delay) {
            return 0.0f;
        }
        return Math.min(1.0f, this.durationTimer / this.duration);
    }

    public float getX() {
        return this.x;
    }

    public float getY() {
        return this.y;
    }

    public int getActiveCount() {
        return this.activeCount;
    }

    public Array<String> getImagePaths() {
        return this.imagePaths;
    }

    public void setImagePaths(Array<String> imagePaths) {
        this.imagePaths = imagePaths;
    }

    public void setFlip(boolean flipX, boolean flipY) {
        this.flipX = flipX;
        this.flipY = flipY;
        Particle[] particleArr = this.particles;
        if (particleArr == null) {
            return;
        }
        int n = particleArr.length;
        for (int i = 0; i < n; i++) {
            Particle particle = this.particles[i];
            if (particle != null) {
                particle.flip(flipX, flipY);
            }
        }
    }

    public void flipY() {
        ScaledNumericValue scaledNumericValue = this.angleValue;
        scaledNumericValue.setHigh(-scaledNumericValue.getHighMin(), -this.angleValue.getHighMax());
        ScaledNumericValue scaledNumericValue2 = this.angleValue;
        scaledNumericValue2.setLow(-scaledNumericValue2.getLowMin(), -this.angleValue.getLowMax());
        ScaledNumericValue scaledNumericValue3 = this.gravityValue;
        scaledNumericValue3.setHigh(-scaledNumericValue3.getHighMin(), -this.gravityValue.getHighMax());
        ScaledNumericValue scaledNumericValue4 = this.gravityValue;
        scaledNumericValue4.setLow(-scaledNumericValue4.getLowMin(), -this.gravityValue.getLowMax());
        ScaledNumericValue scaledNumericValue5 = this.windValue;
        scaledNumericValue5.setHigh(-scaledNumericValue5.getHighMin(), -this.windValue.getHighMax());
        ScaledNumericValue scaledNumericValue6 = this.windValue;
        scaledNumericValue6.setLow(-scaledNumericValue6.getLowMin(), -this.windValue.getLowMax());
        ScaledNumericValue scaledNumericValue7 = this.rotationValue;
        scaledNumericValue7.setHigh(-scaledNumericValue7.getHighMin(), -this.rotationValue.getHighMax());
        ScaledNumericValue scaledNumericValue8 = this.rotationValue;
        scaledNumericValue8.setLow(-scaledNumericValue8.getLowMin(), -this.rotationValue.getLowMax());
        RangedNumericValue rangedNumericValue = this.yOffsetValue;
        rangedNumericValue.setLow(-rangedNumericValue.getLowMin(), -this.yOffsetValue.getLowMax());
    }

    public BoundingBox getBoundingBox() {
        if (this.bounds == null) {
            this.bounds = new BoundingBox();
        }
        Particle[] particles = this.particles;
        boolean[] active = this.active;
        BoundingBox bounds = this.bounds;
        bounds.inf();
        int n = active.length;
        for (int i = 0; i < n; i++) {
            if (active[i]) {
                Rectangle r = particles[i].getBoundingRectangle();
                bounds.ext(r.x, r.y, 0.0f);
                bounds.ext(r.x + r.width, r.y + r.height, 0.0f);
            }
        }
        return bounds;
    }

    protected RangedNumericValue[] getXSizeValues() {
        if (this.xSizeValues == null) {
            this.xSizeValues = new RangedNumericValue[3];
            RangedNumericValue[] rangedNumericValueArr = this.xSizeValues;
            rangedNumericValueArr[0] = this.xScaleValue;
            rangedNumericValueArr[1] = this.spawnWidthValue;
            rangedNumericValueArr[2] = this.xOffsetValue;
        }
        return this.xSizeValues;
    }

    protected RangedNumericValue[] getYSizeValues() {
        if (this.ySizeValues == null) {
            this.ySizeValues = new RangedNumericValue[3];
            RangedNumericValue[] rangedNumericValueArr = this.ySizeValues;
            rangedNumericValueArr[0] = this.yScaleValue;
            rangedNumericValueArr[1] = this.spawnHeightValue;
            rangedNumericValueArr[2] = this.yOffsetValue;
        }
        return this.ySizeValues;
    }

    protected RangedNumericValue[] getMotionValues() {
        if (this.motionValues == null) {
            this.motionValues = new RangedNumericValue[3];
            RangedNumericValue[] rangedNumericValueArr = this.motionValues;
            rangedNumericValueArr[0] = this.velocityValue;
            rangedNumericValueArr[1] = this.windValue;
            rangedNumericValueArr[2] = this.gravityValue;
        }
        return this.motionValues;
    }

    public void scaleSize(float scale) {
        if (scale == 1.0f) {
            return;
        }
        scaleSize(scale, scale);
    }

    public void scaleSize(float scaleX, float scaleY) {
        RangedNumericValue[] xSizeValues;
        RangedNumericValue[] ySizeValues;
        if (scaleX == 1.0f && scaleY == 1.0f) {
            return;
        }
        for (RangedNumericValue value : getXSizeValues()) {
            value.scale(scaleX);
        }
        for (RangedNumericValue value2 : getYSizeValues()) {
            value2.scale(scaleY);
        }
    }

    public void scaleMotion(float scale) {
        RangedNumericValue[] motionValues;
        if (scale == 1.0f) {
            return;
        }
        for (RangedNumericValue value : getMotionValues()) {
            value.scale(scale);
        }
    }

    public void matchSize(ParticleEmitter template) {
        matchXSize(template);
        matchYSize(template);
    }

    public void matchXSize(ParticleEmitter template) {
        RangedNumericValue[] values = getXSizeValues();
        RangedNumericValue[] templateValues = template.getXSizeValues();
        for (int i = 0; i < values.length; i++) {
            values[i].set(templateValues[i]);
        }
    }

    public void matchYSize(ParticleEmitter template) {
        RangedNumericValue[] values = getYSizeValues();
        RangedNumericValue[] templateValues = template.getYSizeValues();
        for (int i = 0; i < values.length; i++) {
            values[i].set(templateValues[i]);
        }
    }

    public void matchMotion(ParticleEmitter template) {
        RangedNumericValue[] values = getMotionValues();
        RangedNumericValue[] templateValues = template.getMotionValues();
        for (int i = 0; i < values.length; i++) {
            values[i].set(templateValues[i]);
        }
    }

    public void save(Writer output) throws IOException {
        output.write(this.name + "\n");
        output.write("- Delay -\n");
        this.delayValue.save(output);
        output.write("- Duration - \n");
        this.durationValue.save(output);
        output.write("- Count - \n");
        output.write("min: " + this.minParticleCount + "\n");
        output.write("max: " + this.maxParticleCount + "\n");
        output.write("- Emission - \n");
        this.emissionValue.save(output);
        output.write("- Life - \n");
        this.lifeValue.save(output);
        output.write("- Life Offset - \n");
        this.lifeOffsetValue.save(output);
        output.write("- X Offset - \n");
        this.xOffsetValue.save(output);
        output.write("- Y Offset - \n");
        this.yOffsetValue.save(output);
        output.write("- Spawn Shape - \n");
        this.spawnShapeValue.save(output);
        output.write("- Spawn Width - \n");
        this.spawnWidthValue.save(output);
        output.write("- Spawn Height - \n");
        this.spawnHeightValue.save(output);
        output.write("- X Scale - \n");
        this.xScaleValue.save(output);
        output.write("- Y Scale - \n");
        this.yScaleValue.save(output);
        output.write("- Velocity - \n");
        this.velocityValue.save(output);
        output.write("- Angle - \n");
        this.angleValue.save(output);
        output.write("- Rotation - \n");
        this.rotationValue.save(output);
        output.write("- Wind - \n");
        this.windValue.save(output);
        output.write("- Gravity - \n");
        this.gravityValue.save(output);
        output.write("- Tint - \n");
        this.tintValue.save(output);
        output.write("- Transparency - \n");
        this.transparencyValue.save(output);
        output.write("- Options - \n");
        output.write("attached: " + this.attached + "\n");
        output.write("continuous: " + this.continuous + "\n");
        output.write("aligned: " + this.aligned + "\n");
        output.write("additive: " + this.additive + "\n");
        output.write("behind: " + this.behind + "\n");
        output.write("premultipliedAlpha: " + this.premultipliedAlpha + "\n");
        output.write("spriteMode: " + this.spriteMode.toString() + "\n");
        output.write("- Image Paths -\n");
        Array.ArrayIterator<String> it = this.imagePaths.iterator();
        while (it.hasNext()) {
            String imagePath = it.next();
            output.write(imagePath + "\n");
        }
        output.write("\n");
    }

    public void load(BufferedReader reader) throws IOException {
        try {
            this.name = readString(reader, "name");
            reader.readLine();
            this.delayValue.load(reader);
            reader.readLine();
            this.durationValue.load(reader);
            reader.readLine();
            setMinParticleCount(readInt(reader, "minParticleCount"));
            setMaxParticleCount(readInt(reader, "maxParticleCount"));
            reader.readLine();
            this.emissionValue.load(reader);
            reader.readLine();
            this.lifeValue.load(reader);
            reader.readLine();
            this.lifeOffsetValue.load(reader);
            reader.readLine();
            this.xOffsetValue.load(reader);
            reader.readLine();
            this.yOffsetValue.load(reader);
            reader.readLine();
            this.spawnShapeValue.load(reader);
            reader.readLine();
            this.spawnWidthValue.load(reader);
            reader.readLine();
            this.spawnHeightValue.load(reader);
            if (reader.readLine().trim().equals("- Scale -")) {
                this.xScaleValue.load(reader);
                this.yScaleValue.setActive(false);
            } else {
                this.xScaleValue.load(reader);
                reader.readLine();
                this.yScaleValue.load(reader);
            }
            reader.readLine();
            this.velocityValue.load(reader);
            reader.readLine();
            this.angleValue.load(reader);
            reader.readLine();
            this.rotationValue.load(reader);
            reader.readLine();
            this.windValue.load(reader);
            reader.readLine();
            this.gravityValue.load(reader);
            reader.readLine();
            this.tintValue.load(reader);
            reader.readLine();
            this.transparencyValue.load(reader);
            reader.readLine();
            this.attached = readBoolean(reader, "attached");
            this.continuous = readBoolean(reader, "continuous");
            this.aligned = readBoolean(reader, "aligned");
            this.additive = readBoolean(reader, "additive");
            this.behind = readBoolean(reader, "behind");
            String line = reader.readLine();
            if (line.startsWith("premultipliedAlpha")) {
                this.premultipliedAlpha = readBoolean(line);
                line = reader.readLine();
            }
            if (line.startsWith("spriteMode")) {
                this.spriteMode = SpriteMode.valueOf(readString(line));
                reader.readLine();
            }
            Array<String> imagePaths = new Array<>();
            while (true) {
                String line2 = reader.readLine();
                if (line2 == null || line2.isEmpty()) {
                    break;
                }
                imagePaths.add(line2);
            }
            setImagePaths(imagePaths);
        } catch (RuntimeException ex) {
            if (this.name == null) {
                throw ex;
            }
            throw new RuntimeException("Error parsing emitter: " + this.name, ex);
        }
    }

    static String readString(String line) throws IOException {
        return line.substring(line.indexOf(":") + 1).trim();
    }

    static String readString(BufferedReader reader, String name) throws IOException {
        String line = reader.readLine();
        if (line == null) {
            throw new IOException("Missing value: " + name);
        }
        return readString(line);
    }

    static boolean readBoolean(String line) throws IOException {
        return Boolean.parseBoolean(readString(line));
    }

    static boolean readBoolean(BufferedReader reader, String name) throws IOException {
        return Boolean.parseBoolean(readString(reader, name));
    }

    static int readInt(BufferedReader reader, String name) throws IOException {
        return Integer.parseInt(readString(reader, name));
    }

    static float readFloat(BufferedReader reader, String name) throws IOException {
        return Float.parseFloat(readString(reader, name));
    }

    /* loaded from: classes.dex */
    public static class Particle extends Sprite {
        protected float angle;
        protected float angleCos;
        protected float angleDiff;
        protected float angleSin;
        protected int currentLife;
        protected int frame;
        protected float gravity;
        protected float gravityDiff;
        protected int life;
        protected float rotation;
        protected float rotationDiff;
        protected float[] tint;
        protected float transparency;
        protected float transparencyDiff;
        protected float velocity;
        protected float velocityDiff;
        protected float wind;
        protected float windDiff;
        protected float xScale;
        protected float xScaleDiff;
        protected float yScale;
        protected float yScaleDiff;

        public Particle(Sprite sprite) {
            super(sprite);
        }
    }

    /* loaded from: classes.dex */
    public static class ParticleValue {
        boolean active;
        boolean alwaysActive;

        public void setAlwaysActive(boolean alwaysActive) {
            this.alwaysActive = alwaysActive;
        }

        public boolean isAlwaysActive() {
            return this.alwaysActive;
        }

        public boolean isActive() {
            return this.alwaysActive || this.active;
        }

        public void setActive(boolean active) {
            this.active = active;
        }

        public void save(Writer output) throws IOException {
            if (!this.alwaysActive) {
                output.write("active: " + this.active + "\n");
                return;
            }
            this.active = true;
        }

        public void load(BufferedReader reader) throws IOException {
            if (!this.alwaysActive) {
                this.active = ParticleEmitter.readBoolean(reader, "active");
            } else {
                this.active = true;
            }
        }

        public void load(ParticleValue value) {
            this.active = value.active;
            this.alwaysActive = value.alwaysActive;
        }
    }

    /* loaded from: classes.dex */
    public static class NumericValue extends ParticleValue {
        private float value;

        public float getValue() {
            return this.value;
        }

        public void setValue(float value) {
            this.value = value;
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.ParticleValue
        public void save(Writer output) throws IOException {
            super.save(output);
            if (this.active) {
                output.write("value: " + this.value + "\n");
            }
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.ParticleValue
        public void load(BufferedReader reader) throws IOException {
            super.load(reader);
            if (this.active) {
                this.value = ParticleEmitter.readFloat(reader, "value");
            }
        }

        public void load(NumericValue value) {
            super.load((ParticleValue) value);
            this.value = value.value;
        }
    }

    /* loaded from: classes.dex */
    public static class RangedNumericValue extends ParticleValue {
        private float lowMax;
        private float lowMin;

        public float newLowValue() {
            float f = this.lowMin;
            return f + ((this.lowMax - f) * MathUtils.random());
        }

        public void setLow(float value) {
            this.lowMin = value;
            this.lowMax = value;
        }

        public void setLow(float min, float max) {
            this.lowMin = min;
            this.lowMax = max;
        }

        public float getLowMin() {
            return this.lowMin;
        }

        public void setLowMin(float lowMin) {
            this.lowMin = lowMin;
        }

        public float getLowMax() {
            return this.lowMax;
        }

        public void setLowMax(float lowMax) {
            this.lowMax = lowMax;
        }

        public void scale(float scale) {
            this.lowMin *= scale;
            this.lowMax *= scale;
        }

        public void set(RangedNumericValue value) {
            this.lowMin = value.lowMin;
            this.lowMax = value.lowMax;
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.ParticleValue
        public void save(Writer output) throws IOException {
            super.save(output);
            if (this.active) {
                output.write("lowMin: " + this.lowMin + "\n");
                output.write("lowMax: " + this.lowMax + "\n");
            }
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.ParticleValue
        public void load(BufferedReader reader) throws IOException {
            super.load(reader);
            if (this.active) {
                this.lowMin = ParticleEmitter.readFloat(reader, "lowMin");
                this.lowMax = ParticleEmitter.readFloat(reader, "lowMax");
            }
        }

        public void load(RangedNumericValue value) {
            super.load((ParticleValue) value);
            this.lowMax = value.lowMax;
            this.lowMin = value.lowMin;
        }
    }

    /* loaded from: classes.dex */
    public static class ScaledNumericValue extends RangedNumericValue {
        private float highMax;
        private float highMin;
        private boolean relative;
        private float[] scaling = {1.0f};
        float[] timeline = {0.0f};

        public float newHighValue() {
            float f = this.highMin;
            return f + ((this.highMax - f) * MathUtils.random());
        }

        public void setHigh(float value) {
            this.highMin = value;
            this.highMax = value;
        }

        public void setHigh(float min, float max) {
            this.highMin = min;
            this.highMax = max;
        }

        public float getHighMin() {
            return this.highMin;
        }

        public void setHighMin(float highMin) {
            this.highMin = highMin;
        }

        public float getHighMax() {
            return this.highMax;
        }

        public void setHighMax(float highMax) {
            this.highMax = highMax;
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.RangedNumericValue
        public void scale(float scale) {
            super.scale(scale);
            this.highMin *= scale;
            this.highMax *= scale;
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.RangedNumericValue
        public void set(RangedNumericValue value) {
            if (value instanceof ScaledNumericValue) {
                set((ScaledNumericValue) value);
            } else {
                super.set(value);
            }
        }

        public void set(ScaledNumericValue value) {
            super.set((RangedNumericValue) value);
            this.highMin = value.highMin;
            this.highMax = value.highMax;
            float[] fArr = this.scaling;
            int length = fArr.length;
            float[] fArr2 = value.scaling;
            if (length != fArr2.length) {
                this.scaling = Arrays.copyOf(fArr2, fArr2.length);
            } else {
                System.arraycopy(fArr2, 0, fArr, 0, fArr.length);
            }
            float[] fArr3 = this.timeline;
            int length2 = fArr3.length;
            float[] fArr4 = value.timeline;
            if (length2 != fArr4.length) {
                this.timeline = Arrays.copyOf(fArr4, fArr4.length);
            } else {
                System.arraycopy(fArr4, 0, fArr3, 0, fArr3.length);
            }
            this.relative = value.relative;
        }

        public float[] getScaling() {
            return this.scaling;
        }

        public void setScaling(float[] values) {
            this.scaling = values;
        }

        public float[] getTimeline() {
            return this.timeline;
        }

        public void setTimeline(float[] timeline) {
            this.timeline = timeline;
        }

        public boolean isRelative() {
            return this.relative;
        }

        public void setRelative(boolean relative) {
            this.relative = relative;
        }

        public float getScale(float percent) {
            int endIndex = -1;
            float[] timeline = this.timeline;
            int n = timeline.length;
            int i = 1;
            while (true) {
                if (i >= n) {
                    break;
                }
                float t = timeline[i];
                if (t <= percent) {
                    i++;
                } else {
                    endIndex = i;
                    break;
                }
            }
            if (endIndex == -1) {
                return this.scaling[n - 1];
            }
            float[] scaling = this.scaling;
            int startIndex = endIndex - 1;
            float startValue = scaling[startIndex];
            float startTime = timeline[startIndex];
            return ((scaling[endIndex] - startValue) * ((percent - startTime) / (timeline[endIndex] - startTime))) + startValue;
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.RangedNumericValue, com.badlogic.gdx.graphics.g2d.ParticleEmitter.ParticleValue
        public void save(Writer output) throws IOException {
            super.save(output);
            if (this.active) {
                output.write("highMin: " + this.highMin + "\n");
                output.write("highMax: " + this.highMax + "\n");
                output.write("relative: " + this.relative + "\n");
                output.write("scalingCount: " + this.scaling.length + "\n");
                for (int i = 0; i < this.scaling.length; i++) {
                    output.write("scaling" + i + ": " + this.scaling[i] + "\n");
                }
                output.write("timelineCount: " + this.timeline.length + "\n");
                for (int i2 = 0; i2 < this.timeline.length; i2++) {
                    output.write("timeline" + i2 + ": " + this.timeline[i2] + "\n");
                }
            }
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.RangedNumericValue, com.badlogic.gdx.graphics.g2d.ParticleEmitter.ParticleValue
        public void load(BufferedReader reader) throws IOException {
            super.load(reader);
            if (!this.active) {
                return;
            }
            this.highMin = ParticleEmitter.readFloat(reader, "highMin");
            this.highMax = ParticleEmitter.readFloat(reader, "highMax");
            this.relative = ParticleEmitter.readBoolean(reader, "relative");
            this.scaling = new float[ParticleEmitter.readInt(reader, "scalingCount")];
            int i = 0;
            while (true) {
                float[] fArr = this.scaling;
                if (i >= fArr.length) {
                    break;
                }
                fArr[i] = ParticleEmitter.readFloat(reader, "scaling" + i);
                i++;
            }
            this.timeline = new float[ParticleEmitter.readInt(reader, "timelineCount")];
            int i2 = 0;
            while (true) {
                float[] fArr2 = this.timeline;
                if (i2 < fArr2.length) {
                    fArr2[i2] = ParticleEmitter.readFloat(reader, "timeline" + i2);
                    i2++;
                } else {
                    return;
                }
            }
        }

        public void load(ScaledNumericValue value) {
            super.load((RangedNumericValue) value);
            this.highMax = value.highMax;
            this.highMin = value.highMin;
            this.scaling = new float[value.scaling.length];
            float[] fArr = value.scaling;
            float[] fArr2 = this.scaling;
            System.arraycopy(fArr, 0, fArr2, 0, fArr2.length);
            this.timeline = new float[value.timeline.length];
            float[] fArr3 = value.timeline;
            float[] fArr4 = this.timeline;
            System.arraycopy(fArr3, 0, fArr4, 0, fArr4.length);
            this.relative = value.relative;
        }
    }

    /* loaded from: classes.dex */
    public static class IndependentScaledNumericValue extends ScaledNumericValue {
        boolean independent;

        public boolean isIndependent() {
            return this.independent;
        }

        public void setIndependent(boolean independent) {
            this.independent = independent;
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.ScaledNumericValue, com.badlogic.gdx.graphics.g2d.ParticleEmitter.RangedNumericValue
        public void set(RangedNumericValue value) {
            if (value instanceof IndependentScaledNumericValue) {
                set((IndependentScaledNumericValue) value);
            } else {
                super.set(value);
            }
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.ScaledNumericValue
        public void set(ScaledNumericValue value) {
            if (value instanceof IndependentScaledNumericValue) {
                set((IndependentScaledNumericValue) value);
            } else {
                super.set(value);
            }
        }

        public void set(IndependentScaledNumericValue value) {
            super.set((ScaledNumericValue) value);
            this.independent = value.independent;
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.ScaledNumericValue, com.badlogic.gdx.graphics.g2d.ParticleEmitter.RangedNumericValue, com.badlogic.gdx.graphics.g2d.ParticleEmitter.ParticleValue
        public void save(Writer output) throws IOException {
            super.save(output);
            output.write("independent: " + this.independent + "\n");
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.ScaledNumericValue, com.badlogic.gdx.graphics.g2d.ParticleEmitter.RangedNumericValue, com.badlogic.gdx.graphics.g2d.ParticleEmitter.ParticleValue
        public void load(BufferedReader reader) throws IOException {
            super.load(reader);
            if (reader.markSupported()) {
                reader.mark(100);
            }
            String line = reader.readLine();
            if (line == null) {
                throw new IOException("Missing value: independent");
            }
            if (line.contains("independent")) {
                this.independent = Boolean.parseBoolean(ParticleEmitter.readString(line));
            } else if (reader.markSupported()) {
                reader.reset();
            } else {
                Gdx.app.error("ParticleEmitter", "The loaded particle effect descriptor file uses an old invalid format. Please download the latest version of the Particle Editor tool and recreate the file by loading and saving it again.");
                throw new IOException("The loaded particle effect descriptor file uses an old invalid format. Please download the latest version of the Particle Editor tool and recreate the file by loading and saving it again.");
            }
        }

        public void load(IndependentScaledNumericValue value) {
            super.load((ScaledNumericValue) value);
            this.independent = value.independent;
        }
    }

    /* loaded from: classes.dex */
    public static class GradientColorValue extends ParticleValue {
        private static float[] temp = new float[4];
        private float[] colors = {1.0f, 1.0f, 1.0f};
        float[] timeline = {0.0f};

        public GradientColorValue() {
            this.alwaysActive = true;
        }

        public float[] getTimeline() {
            return this.timeline;
        }

        public void setTimeline(float[] timeline) {
            this.timeline = timeline;
        }

        public float[] getColors() {
            return this.colors;
        }

        public void setColors(float[] colors) {
            this.colors = colors;
        }

        public float[] getColor(float percent) {
            int startIndex = 0;
            int endIndex = -1;
            float[] timeline = this.timeline;
            int n = timeline.length;
            int i = 1;
            while (true) {
                if (i >= n) {
                    break;
                }
                float t = timeline[i];
                if (t > percent) {
                    endIndex = i;
                    break;
                }
                startIndex = i;
                i++;
            }
            float startTime = timeline[startIndex];
            int startIndex2 = startIndex * 3;
            float[] fArr = this.colors;
            float r1 = fArr[startIndex2];
            float g1 = fArr[startIndex2 + 1];
            float b1 = fArr[startIndex2 + 2];
            if (endIndex == -1) {
                float[] fArr2 = temp;
                fArr2[0] = r1;
                fArr2[1] = g1;
                fArr2[2] = b1;
                return fArr2;
            }
            float factor = (percent - startTime) / (timeline[endIndex] - startTime);
            int endIndex2 = endIndex * 3;
            float[] fArr3 = temp;
            fArr3[0] = ((fArr[endIndex2] - r1) * factor) + r1;
            fArr3[1] = ((fArr[endIndex2 + 1] - g1) * factor) + g1;
            fArr3[2] = ((fArr[endIndex2 + 2] - b1) * factor) + b1;
            return fArr3;
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.ParticleValue
        public void save(Writer output) throws IOException {
            super.save(output);
            if (this.active) {
                output.write("colorsCount: " + this.colors.length + "\n");
                for (int i = 0; i < this.colors.length; i++) {
                    output.write("colors" + i + ": " + this.colors[i] + "\n");
                }
                output.write("timelineCount: " + this.timeline.length + "\n");
                for (int i2 = 0; i2 < this.timeline.length; i2++) {
                    output.write("timeline" + i2 + ": " + this.timeline[i2] + "\n");
                }
            }
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.ParticleValue
        public void load(BufferedReader reader) throws IOException {
            super.load(reader);
            if (!this.active) {
                return;
            }
            this.colors = new float[ParticleEmitter.readInt(reader, "colorsCount")];
            int i = 0;
            while (true) {
                float[] fArr = this.colors;
                if (i >= fArr.length) {
                    break;
                }
                fArr[i] = ParticleEmitter.readFloat(reader, "colors" + i);
                i++;
            }
            this.timeline = new float[ParticleEmitter.readInt(reader, "timelineCount")];
            int i2 = 0;
            while (true) {
                float[] fArr2 = this.timeline;
                if (i2 < fArr2.length) {
                    fArr2[i2] = ParticleEmitter.readFloat(reader, "timeline" + i2);
                    i2++;
                } else {
                    return;
                }
            }
        }

        public void load(GradientColorValue value) {
            super.load((ParticleValue) value);
            this.colors = new float[value.colors.length];
            float[] fArr = value.colors;
            float[] fArr2 = this.colors;
            System.arraycopy(fArr, 0, fArr2, 0, fArr2.length);
            this.timeline = new float[value.timeline.length];
            float[] fArr3 = value.timeline;
            float[] fArr4 = this.timeline;
            System.arraycopy(fArr3, 0, fArr4, 0, fArr4.length);
        }
    }

    /* loaded from: classes.dex */
    public static class SpawnShapeValue extends ParticleValue {
        boolean edges;
        SpawnShape shape = SpawnShape.point;
        SpawnEllipseSide side = SpawnEllipseSide.both;

        public SpawnShape getShape() {
            return this.shape;
        }

        public void setShape(SpawnShape shape) {
            this.shape = shape;
        }

        public boolean isEdges() {
            return this.edges;
        }

        public void setEdges(boolean edges) {
            this.edges = edges;
        }

        public SpawnEllipseSide getSide() {
            return this.side;
        }

        public void setSide(SpawnEllipseSide side) {
            this.side = side;
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.ParticleValue
        public void save(Writer output) throws IOException {
            super.save(output);
            if (this.active) {
                output.write("shape: " + this.shape + "\n");
                if (this.shape == SpawnShape.ellipse) {
                    output.write("edges: " + this.edges + "\n");
                    output.write("side: " + this.side + "\n");
                }
            }
        }

        @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter.ParticleValue
        public void load(BufferedReader reader) throws IOException {
            super.load(reader);
            if (this.active) {
                this.shape = SpawnShape.valueOf(ParticleEmitter.readString(reader, "shape"));
                if (this.shape == SpawnShape.ellipse) {
                    this.edges = ParticleEmitter.readBoolean(reader, "edges");
                    this.side = SpawnEllipseSide.valueOf(ParticleEmitter.readString(reader, "side"));
                }
            }
        }

        public void load(SpawnShapeValue value) {
            super.load((ParticleValue) value);
            this.shape = value.shape;
            this.edges = value.edges;
            this.side = value.side;
        }
    }
}