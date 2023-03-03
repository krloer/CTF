package com.badlogic.gdx.physics.box2d.graphics;

import com.badlogic.gdx.graphics.g2d.ParticleEmitter;
import com.badlogic.gdx.graphics.g2d.Sprite;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Fixture;
import com.badlogic.gdx.physics.box2d.RayCastCallback;
import com.badlogic.gdx.physics.box2d.World;
import java.io.BufferedReader;
import java.io.IOException;

/* loaded from: classes.dex */
public class ParticleEmitterBox2D extends ParticleEmitter {
    private static final float EPSILON = 0.001f;
    final Vector2 endPoint;
    float normalAngle;
    boolean particleCollided;
    final RayCastCallback rayCallBack;
    final Vector2 startPoint;
    final World world;

    public ParticleEmitterBox2D(World world) {
        this.startPoint = new Vector2();
        this.endPoint = new Vector2();
        this.rayCallBack = new RayCastCallback() { // from class: com.badlogic.gdx.physics.box2d.graphics.ParticleEmitterBox2D.1
            @Override // com.badlogic.gdx.physics.box2d.RayCastCallback
            public float reportRayFixture(Fixture fixture, Vector2 point, Vector2 normal, float fraction) {
                ParticleEmitterBox2D particleEmitterBox2D = ParticleEmitterBox2D.this;
                particleEmitterBox2D.particleCollided = true;
                particleEmitterBox2D.normalAngle = MathUtils.atan2(normal.y, normal.x) * 57.295776f;
                return fraction;
            }
        };
        this.world = world;
    }

    public ParticleEmitterBox2D(World world, BufferedReader reader) throws IOException {
        super(reader);
        this.startPoint = new Vector2();
        this.endPoint = new Vector2();
        this.rayCallBack = new RayCastCallback() { // from class: com.badlogic.gdx.physics.box2d.graphics.ParticleEmitterBox2D.1
            @Override // com.badlogic.gdx.physics.box2d.RayCastCallback
            public float reportRayFixture(Fixture fixture, Vector2 point, Vector2 normal, float fraction) {
                ParticleEmitterBox2D particleEmitterBox2D = ParticleEmitterBox2D.this;
                particleEmitterBox2D.particleCollided = true;
                particleEmitterBox2D.normalAngle = MathUtils.atan2(normal.y, normal.x) * 57.295776f;
                return fraction;
            }
        };
        this.world = world;
    }

    public ParticleEmitterBox2D(World world, ParticleEmitter emitter) {
        super(emitter);
        this.startPoint = new Vector2();
        this.endPoint = new Vector2();
        this.rayCallBack = new RayCastCallback() { // from class: com.badlogic.gdx.physics.box2d.graphics.ParticleEmitterBox2D.1
            @Override // com.badlogic.gdx.physics.box2d.RayCastCallback
            public float reportRayFixture(Fixture fixture, Vector2 point, Vector2 normal, float fraction) {
                ParticleEmitterBox2D particleEmitterBox2D = ParticleEmitterBox2D.this;
                particleEmitterBox2D.particleCollided = true;
                particleEmitterBox2D.normalAngle = MathUtils.atan2(normal.y, normal.x) * 57.295776f;
                return fraction;
            }
        };
        this.world = world;
    }

    @Override // com.badlogic.gdx.graphics.g2d.ParticleEmitter
    protected ParticleEmitter.Particle newParticle(Sprite sprite) {
        return new ParticleBox2D(sprite);
    }

    /* loaded from: classes.dex */
    private class ParticleBox2D extends ParticleEmitter.Particle {
        public ParticleBox2D(Sprite sprite) {
            super(sprite);
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public void translate(float velocityX, float velocityY) {
            if ((velocityX * velocityX) + (velocityY * velocityY) < ParticleEmitterBox2D.EPSILON) {
                return;
            }
            float x = getX() + (getWidth() / 2.0f);
            float y = getY() + (getHeight() / 2.0f);
            ParticleEmitterBox2D particleEmitterBox2D = ParticleEmitterBox2D.this;
            particleEmitterBox2D.particleCollided = false;
            particleEmitterBox2D.startPoint.set(x, y);
            ParticleEmitterBox2D.this.endPoint.set(x + velocityX, y + velocityY);
            if (ParticleEmitterBox2D.this.world != null) {
                ParticleEmitterBox2D.this.world.rayCast(ParticleEmitterBox2D.this.rayCallBack, ParticleEmitterBox2D.this.startPoint, ParticleEmitterBox2D.this.endPoint);
            }
            if (ParticleEmitterBox2D.this.particleCollided) {
                this.angle = ((ParticleEmitterBox2D.this.normalAngle * 2.0f) - this.angle) - 180.0f;
                this.angleCos = MathUtils.cosDeg(this.angle);
                this.angleSin = MathUtils.sinDeg(this.angle);
                velocityX *= this.angleCos;
                velocityY *= this.angleSin;
            }
            super.translate(velocityX, velocityY);
        }
    }
}