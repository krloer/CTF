package com.badlogic.gdx.physics.box2d;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.BodyDef;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class Body {
    protected long addr;
    private Object userData;
    private final World world;
    private final float[] tmp = new float[4];
    private Array<Fixture> fixtures = new Array<>(2);
    protected Array<JointEdge> joints = new Array<>(2);
    private final Transform transform = new Transform();
    private final Vector2 position = new Vector2();
    private final Vector2 worldCenter = new Vector2();
    private final Vector2 localCenter = new Vector2();
    private final Vector2 linearVelocity = new Vector2();
    private final MassData massData = new MassData();
    private final Vector2 localPoint = new Vector2();
    private final Vector2 worldVector = new Vector2();
    public final Vector2 localPoint2 = new Vector2();
    public final Vector2 localVector = new Vector2();
    public final Vector2 linVelWorld = new Vector2();
    public final Vector2 linVelLoc = new Vector2();

    private native void jniApplyAngularImpulse(long j, float f, boolean z);

    private native void jniApplyForce(long j, float f, float f2, float f3, float f4, boolean z);

    private native void jniApplyForceToCenter(long j, float f, float f2, boolean z);

    private native void jniApplyLinearImpulse(long j, float f, float f2, float f3, float f4, boolean z);

    private native void jniApplyTorque(long j, float f, boolean z);

    private native long jniCreateFixture(long j, long j2, float f);

    private native long jniCreateFixture(long j, long j2, float f, float f2, float f3, boolean z, short s, short s2, short s3);

    private native float jniGetAngle(long j);

    private native float jniGetAngularDamping(long j);

    private native float jniGetAngularVelocity(long j);

    private native float jniGetGravityScale(long j);

    private native float jniGetInertia(long j);

    private native float jniGetLinearDamping(long j);

    private native void jniGetLinearVelocity(long j, float[] fArr);

    private native void jniGetLinearVelocityFromLocalPoint(long j, float f, float f2, float[] fArr);

    private native void jniGetLinearVelocityFromWorldPoint(long j, float f, float f2, float[] fArr);

    private native void jniGetLocalCenter(long j, float[] fArr);

    private native void jniGetLocalPoint(long j, float f, float f2, float[] fArr);

    private native void jniGetLocalVector(long j, float f, float f2, float[] fArr);

    private native float jniGetMass(long j);

    private native void jniGetMassData(long j, float[] fArr);

    private native void jniGetPosition(long j, float[] fArr);

    private native void jniGetTransform(long j, float[] fArr);

    private native int jniGetType(long j);

    private native void jniGetWorldCenter(long j, float[] fArr);

    private native void jniGetWorldPoint(long j, float f, float f2, float[] fArr);

    private native void jniGetWorldVector(long j, float f, float f2, float[] fArr);

    private native boolean jniIsActive(long j);

    private native boolean jniIsAwake(long j);

    private native boolean jniIsBullet(long j);

    private native boolean jniIsFixedRotation(long j);

    private native boolean jniIsSleepingAllowed(long j);

    private native void jniResetMassData(long j);

    private native void jniSetActive(long j, boolean z);

    private native void jniSetAngularDamping(long j, float f);

    private native void jniSetAngularVelocity(long j, float f);

    private native void jniSetAwake(long j, boolean z);

    private native void jniSetBullet(long j, boolean z);

    private native void jniSetFixedRotation(long j, boolean z);

    private native void jniSetGravityScale(long j, float f);

    private native void jniSetLinearDamping(long j, float f);

    private native void jniSetLinearVelocity(long j, float f, float f2);

    private native void jniSetMassData(long j, float f, float f2, float f3, float f4);

    private native void jniSetSleepingAllowed(long j, boolean z);

    private native void jniSetTransform(long j, float f, float f2, float f3);

    private native void jniSetType(long j, int i);

    /* JADX INFO: Access modifiers changed from: protected */
    public Body(World world, long addr) {
        this.world = world;
        this.addr = addr;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void reset(long addr) {
        this.addr = addr;
        this.userData = null;
        for (int i = 0; i < this.fixtures.size; i++) {
            this.world.freeFixtures.free(this.fixtures.get(i));
        }
        this.fixtures.clear();
        this.joints.clear();
    }

    public Fixture createFixture(FixtureDef def) {
        long fixtureAddr = jniCreateFixture(this.addr, def.shape.addr, def.friction, def.restitution, def.density, def.isSensor, def.filter.categoryBits, def.filter.maskBits, def.filter.groupIndex);
        Fixture fixture = this.world.freeFixtures.obtain();
        fixture.reset(this, fixtureAddr);
        this.world.fixtures.put(fixture.addr, fixture);
        this.fixtures.add(fixture);
        return fixture;
    }

    public Fixture createFixture(Shape shape, float density) {
        long fixtureAddr = jniCreateFixture(this.addr, shape.addr, density);
        Fixture fixture = this.world.freeFixtures.obtain();
        fixture.reset(this, fixtureAddr);
        this.world.fixtures.put(fixture.addr, fixture);
        this.fixtures.add(fixture);
        return fixture;
    }

    public void destroyFixture(Fixture fixture) {
        this.world.destroyFixture(this, fixture);
        fixture.setUserData(null);
        this.world.fixtures.remove(fixture.addr);
        this.fixtures.removeValue(fixture, true);
        this.world.freeFixtures.free(fixture);
    }

    public void setTransform(Vector2 position, float angle) {
        jniSetTransform(this.addr, position.x, position.y, angle);
    }

    public void setTransform(float x, float y, float angle) {
        jniSetTransform(this.addr, x, y, angle);
    }

    public Transform getTransform() {
        jniGetTransform(this.addr, this.transform.vals);
        return this.transform;
    }

    public Vector2 getPosition() {
        jniGetPosition(this.addr, this.tmp);
        Vector2 vector2 = this.position;
        float[] fArr = this.tmp;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public float getAngle() {
        return jniGetAngle(this.addr);
    }

    public Vector2 getWorldCenter() {
        jniGetWorldCenter(this.addr, this.tmp);
        Vector2 vector2 = this.worldCenter;
        float[] fArr = this.tmp;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public Vector2 getLocalCenter() {
        jniGetLocalCenter(this.addr, this.tmp);
        Vector2 vector2 = this.localCenter;
        float[] fArr = this.tmp;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public void setLinearVelocity(Vector2 v) {
        jniSetLinearVelocity(this.addr, v.x, v.y);
    }

    public void setLinearVelocity(float vX, float vY) {
        jniSetLinearVelocity(this.addr, vX, vY);
    }

    public Vector2 getLinearVelocity() {
        jniGetLinearVelocity(this.addr, this.tmp);
        Vector2 vector2 = this.linearVelocity;
        float[] fArr = this.tmp;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public void setAngularVelocity(float omega) {
        jniSetAngularVelocity(this.addr, omega);
    }

    public float getAngularVelocity() {
        return jniGetAngularVelocity(this.addr);
    }

    public void applyForce(Vector2 force, Vector2 point, boolean wake) {
        jniApplyForce(this.addr, force.x, force.y, point.x, point.y, wake);
    }

    public void applyForce(float forceX, float forceY, float pointX, float pointY, boolean wake) {
        jniApplyForce(this.addr, forceX, forceY, pointX, pointY, wake);
    }

    public void applyForceToCenter(Vector2 force, boolean wake) {
        jniApplyForceToCenter(this.addr, force.x, force.y, wake);
    }

    public void applyForceToCenter(float forceX, float forceY, boolean wake) {
        jniApplyForceToCenter(this.addr, forceX, forceY, wake);
    }

    public void applyTorque(float torque, boolean wake) {
        jniApplyTorque(this.addr, torque, wake);
    }

    public void applyLinearImpulse(Vector2 impulse, Vector2 point, boolean wake) {
        jniApplyLinearImpulse(this.addr, impulse.x, impulse.y, point.x, point.y, wake);
    }

    public void applyLinearImpulse(float impulseX, float impulseY, float pointX, float pointY, boolean wake) {
        jniApplyLinearImpulse(this.addr, impulseX, impulseY, pointX, pointY, wake);
    }

    public void applyAngularImpulse(float impulse, boolean wake) {
        jniApplyAngularImpulse(this.addr, impulse, wake);
    }

    public float getMass() {
        return jniGetMass(this.addr);
    }

    public float getInertia() {
        return jniGetInertia(this.addr);
    }

    public MassData getMassData() {
        jniGetMassData(this.addr, this.tmp);
        MassData massData = this.massData;
        massData.mass = this.tmp[0];
        massData.center.x = this.tmp[1];
        Vector2 vector2 = this.massData.center;
        float[] fArr = this.tmp;
        vector2.y = fArr[2];
        MassData massData2 = this.massData;
        massData2.I = fArr[3];
        return massData2;
    }

    public void setMassData(MassData data) {
        jniSetMassData(this.addr, data.mass, data.center.x, data.center.y, data.I);
    }

    public void resetMassData() {
        jniResetMassData(this.addr);
    }

    public Vector2 getWorldPoint(Vector2 localPoint) {
        jniGetWorldPoint(this.addr, localPoint.x, localPoint.y, this.tmp);
        Vector2 vector2 = this.localPoint;
        float[] fArr = this.tmp;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public Vector2 getWorldVector(Vector2 localVector) {
        jniGetWorldVector(this.addr, localVector.x, localVector.y, this.tmp);
        Vector2 vector2 = this.worldVector;
        float[] fArr = this.tmp;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public Vector2 getLocalPoint(Vector2 worldPoint) {
        jniGetLocalPoint(this.addr, worldPoint.x, worldPoint.y, this.tmp);
        Vector2 vector2 = this.localPoint2;
        float[] fArr = this.tmp;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public Vector2 getLocalVector(Vector2 worldVector) {
        jniGetLocalVector(this.addr, worldVector.x, worldVector.y, this.tmp);
        Vector2 vector2 = this.localVector;
        float[] fArr = this.tmp;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public Vector2 getLinearVelocityFromWorldPoint(Vector2 worldPoint) {
        jniGetLinearVelocityFromWorldPoint(this.addr, worldPoint.x, worldPoint.y, this.tmp);
        Vector2 vector2 = this.linVelWorld;
        float[] fArr = this.tmp;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public Vector2 getLinearVelocityFromLocalPoint(Vector2 localPoint) {
        jniGetLinearVelocityFromLocalPoint(this.addr, localPoint.x, localPoint.y, this.tmp);
        Vector2 vector2 = this.linVelLoc;
        float[] fArr = this.tmp;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public float getLinearDamping() {
        return jniGetLinearDamping(this.addr);
    }

    public void setLinearDamping(float linearDamping) {
        jniSetLinearDamping(this.addr, linearDamping);
    }

    public float getAngularDamping() {
        return jniGetAngularDamping(this.addr);
    }

    public void setAngularDamping(float angularDamping) {
        jniSetAngularDamping(this.addr, angularDamping);
    }

    public void setType(BodyDef.BodyType type) {
        jniSetType(this.addr, type.getValue());
    }

    public BodyDef.BodyType getType() {
        int type = jniGetType(this.addr);
        return type == 0 ? BodyDef.BodyType.StaticBody : type == 1 ? BodyDef.BodyType.KinematicBody : type == 2 ? BodyDef.BodyType.DynamicBody : BodyDef.BodyType.StaticBody;
    }

    public void setBullet(boolean flag) {
        jniSetBullet(this.addr, flag);
    }

    public boolean isBullet() {
        return jniIsBullet(this.addr);
    }

    public void setSleepingAllowed(boolean flag) {
        jniSetSleepingAllowed(this.addr, flag);
    }

    public boolean isSleepingAllowed() {
        return jniIsSleepingAllowed(this.addr);
    }

    public void setAwake(boolean flag) {
        jniSetAwake(this.addr, flag);
    }

    public boolean isAwake() {
        return jniIsAwake(this.addr);
    }

    public void setActive(boolean flag) {
        if (flag) {
            jniSetActive(this.addr, flag);
        } else {
            this.world.deactivateBody(this);
        }
    }

    public boolean isActive() {
        return jniIsActive(this.addr);
    }

    public void setFixedRotation(boolean flag) {
        jniSetFixedRotation(this.addr, flag);
    }

    public boolean isFixedRotation() {
        return jniIsFixedRotation(this.addr);
    }

    public Array<Fixture> getFixtureList() {
        return this.fixtures;
    }

    public Array<JointEdge> getJointList() {
        return this.joints;
    }

    public float getGravityScale() {
        return jniGetGravityScale(this.addr);
    }

    public void setGravityScale(float scale) {
        jniSetGravityScale(this.addr, scale);
    }

    public World getWorld() {
        return this.world;
    }

    public Object getUserData() {
        return this.userData;
    }

    public void setUserData(Object userData) {
        this.userData = userData;
    }
}