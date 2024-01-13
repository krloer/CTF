package com.badlogic.gdx.physics.box2d;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.net.HttpStatus;
import com.badlogic.gdx.physics.box2d.JointDef;
import com.badlogic.gdx.physics.box2d.joints.DistanceJoint;
import com.badlogic.gdx.physics.box2d.joints.DistanceJointDef;
import com.badlogic.gdx.physics.box2d.joints.FrictionJoint;
import com.badlogic.gdx.physics.box2d.joints.FrictionJointDef;
import com.badlogic.gdx.physics.box2d.joints.GearJoint;
import com.badlogic.gdx.physics.box2d.joints.GearJointDef;
import com.badlogic.gdx.physics.box2d.joints.MotorJoint;
import com.badlogic.gdx.physics.box2d.joints.MotorJointDef;
import com.badlogic.gdx.physics.box2d.joints.MouseJoint;
import com.badlogic.gdx.physics.box2d.joints.MouseJointDef;
import com.badlogic.gdx.physics.box2d.joints.PrismaticJoint;
import com.badlogic.gdx.physics.box2d.joints.PrismaticJointDef;
import com.badlogic.gdx.physics.box2d.joints.PulleyJoint;
import com.badlogic.gdx.physics.box2d.joints.PulleyJointDef;
import com.badlogic.gdx.physics.box2d.joints.RevoluteJoint;
import com.badlogic.gdx.physics.box2d.joints.RevoluteJointDef;
import com.badlogic.gdx.physics.box2d.joints.RopeJoint;
import com.badlogic.gdx.physics.box2d.joints.RopeJointDef;
import com.badlogic.gdx.physics.box2d.joints.WeldJoint;
import com.badlogic.gdx.physics.box2d.joints.WeldJointDef;
import com.badlogic.gdx.physics.box2d.joints.WheelJoint;
import com.badlogic.gdx.physics.box2d.joints.WheelJointDef;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.LongMap;
import com.badlogic.gdx.utils.Pool;
import com.badlogic.gdx.utils.SharedLibraryLoader;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class World implements Disposable {
    protected final long addr;
    protected final Pool<Body> freeBodies = new Pool<Body>(100, HttpStatus.SC_OK) { // from class: com.badlogic.gdx.physics.box2d.World.1
        /* JADX INFO: Access modifiers changed from: protected */
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // com.badlogic.gdx.utils.Pool
        public Body newObject() {
            return new Body(World.this, 0L);
        }
    };
    protected final Pool<Fixture> freeFixtures = new Pool<Fixture>(100, HttpStatus.SC_OK) { // from class: com.badlogic.gdx.physics.box2d.World.2
        /* JADX INFO: Access modifiers changed from: protected */
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // com.badlogic.gdx.utils.Pool
        public Fixture newObject() {
            return new Fixture(null, 0L);
        }
    };
    protected final LongMap<Body> bodies = new LongMap<>(100);
    protected final LongMap<Fixture> fixtures = new LongMap<>(100);
    protected final LongMap<Joint> joints = new LongMap<>(100);
    protected ContactFilter contactFilter = null;
    protected ContactListener contactListener = null;
    final float[] tmpGravity = new float[2];
    final Vector2 gravity = new Vector2();
    private QueryCallback queryCallback = null;
    private long[] contactAddrs = new long[HttpStatus.SC_OK];
    private final Array<Contact> contacts = new Array<>();
    private final Array<Contact> freeContacts = new Array<>();
    private final Contact contact = new Contact(this, 0);
    private final Manifold manifold = new Manifold(0);
    private final ContactImpulse impulse = new ContactImpulse(this, 0);
    private RayCastCallback rayCastCallback = null;
    private Vector2 rayPoint = new Vector2();
    private Vector2 rayNormal = new Vector2();

    public static native float getVelocityThreshold();

    private native void jniClearForces(long j);

    private native long jniCreateBody(long j, int i, float f, float f2, float f3, float f4, float f5, float f6, float f7, float f8, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, float f9);

    private native long jniCreateDistanceJoint(long j, long j2, long j3, boolean z, float f, float f2, float f3, float f4, float f5, float f6, float f7);

    private native long jniCreateFrictionJoint(long j, long j2, long j3, boolean z, float f, float f2, float f3, float f4, float f5, float f6);

    private native long jniCreateGearJoint(long j, long j2, long j3, boolean z, long j4, long j5, float f);

    private native long jniCreateMotorJoint(long j, long j2, long j3, boolean z, float f, float f2, float f3, float f4, float f5, float f6);

    private native long jniCreateMouseJoint(long j, long j2, long j3, boolean z, float f, float f2, float f3, float f4, float f5);

    private native long jniCreatePrismaticJoint(long j, long j2, long j3, boolean z, float f, float f2, float f3, float f4, float f5, float f6, float f7, boolean z2, float f8, float f9, boolean z3, float f10, float f11);

    private native long jniCreatePulleyJoint(long j, long j2, long j3, boolean z, float f, float f2, float f3, float f4, float f5, float f6, float f7, float f8, float f9, float f10, float f11);

    private native long jniCreateRevoluteJoint(long j, long j2, long j3, boolean z, float f, float f2, float f3, float f4, float f5, boolean z2, float f6, float f7, boolean z3, float f8, float f9);

    private native long jniCreateRopeJoint(long j, long j2, long j3, boolean z, float f, float f2, float f3, float f4, float f5);

    private native long jniCreateWeldJoint(long j, long j2, long j3, boolean z, float f, float f2, float f3, float f4, float f5, float f6, float f7);

    private native long jniCreateWheelJoint(long j, long j2, long j3, boolean z, float f, float f2, float f3, float f4, float f5, float f6, boolean z2, float f7, float f8, float f9, float f10);

    private native void jniDeactivateBody(long j, long j2);

    private native void jniDestroyBody(long j, long j2);

    private native void jniDestroyFixture(long j, long j2, long j3);

    private native void jniDestroyJoint(long j, long j2);

    private native void jniDispose(long j);

    private native boolean jniGetAutoClearForces(long j);

    private native int jniGetBodyCount(long j);

    private native int jniGetContactCount(long j);

    private native void jniGetContactList(long j, long[] jArr);

    private native void jniGetGravity(long j, float[] fArr);

    private native int jniGetJointcount(long j);

    private native int jniGetProxyCount(long j);

    private native boolean jniIsLocked(long j);

    private native void jniQueryAABB(long j, float f, float f2, float f3, float f4);

    private native void jniRayCast(long j, float f, float f2, float f3, float f4);

    private native void jniSetAutoClearForces(long j, boolean z);

    private native void jniSetContiousPhysics(long j, boolean z);

    private native void jniSetGravity(long j, float f, float f2);

    private native void jniSetWarmStarting(long j, boolean z);

    private native void jniStep(long j, float f, int i, int i2);

    private native long newWorld(float f, float f2, boolean z);

    private native void setUseDefaultContactFilter(boolean z);

    public static native void setVelocityThreshold(float f);

    static {
        new SharedLibraryLoader().load("gdx-box2d");
    }

    public World(Vector2 gravity, boolean doSleep) {
        this.addr = newWorld(gravity.x, gravity.y, doSleep);
        this.contacts.ensureCapacity(this.contactAddrs.length);
        this.freeContacts.ensureCapacity(this.contactAddrs.length);
        for (int i = 0; i < this.contactAddrs.length; i++) {
            this.freeContacts.add(new Contact(this, 0L));
        }
    }

    public void setDestructionListener(DestructionListener listener) {
    }

    public void setContactFilter(ContactFilter filter) {
        this.contactFilter = filter;
        setUseDefaultContactFilter(filter == null);
    }

    public void setContactListener(ContactListener listener) {
        this.contactListener = listener;
    }

    public Body createBody(BodyDef def) {
        long bodyAddr = jniCreateBody(this.addr, def.type.getValue(), def.position.x, def.position.y, def.angle, def.linearVelocity.x, def.linearVelocity.y, def.angularVelocity, def.linearDamping, def.angularDamping, def.allowSleep, def.awake, def.fixedRotation, def.bullet, def.active, def.gravityScale);
        Body body = this.freeBodies.obtain();
        body.reset(bodyAddr);
        this.bodies.put(body.addr, body);
        return body;
    }

    public void destroyBody(Body body) {
        Array<JointEdge> jointList = body.getJointList();
        while (jointList.size > 0) {
            destroyJoint(body.getJointList().get(0).joint);
        }
        jniDestroyBody(this.addr, body.addr);
        body.setUserData(null);
        this.bodies.remove(body.addr);
        Array<Fixture> fixtureList = body.getFixtureList();
        while (fixtureList.size > 0) {
            Fixture fixtureToDelete = fixtureList.removeIndex(0);
            this.fixtures.remove(fixtureToDelete.addr).setUserData(null);
            this.freeFixtures.free(fixtureToDelete);
        }
        this.freeBodies.free(body);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void destroyFixture(Body body, Fixture fixture) {
        jniDestroyFixture(this.addr, body.addr, fixture.addr);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void deactivateBody(Body body) {
        jniDeactivateBody(this.addr, body.addr);
    }

    public Joint createJoint(JointDef def) {
        long jointAddr = createProperJoint(def);
        Joint joint = def.type == JointDef.JointType.DistanceJoint ? new DistanceJoint(this, jointAddr) : null;
        if (def.type == JointDef.JointType.FrictionJoint) {
            joint = new FrictionJoint(this, jointAddr);
        }
        Joint joint2 = joint;
        if (def.type == JointDef.JointType.GearJoint) {
            joint2 = new GearJoint(this, jointAddr, ((GearJointDef) def).joint1, ((GearJointDef) def).joint2);
        }
        if (def.type == JointDef.JointType.MotorJoint) {
            joint2 = new MotorJoint(this, jointAddr);
        }
        if (def.type == JointDef.JointType.MouseJoint) {
            joint2 = new MouseJoint(this, jointAddr);
        }
        if (def.type == JointDef.JointType.PrismaticJoint) {
            joint2 = new PrismaticJoint(this, jointAddr);
        }
        if (def.type == JointDef.JointType.PulleyJoint) {
            joint2 = new PulleyJoint(this, jointAddr);
        }
        if (def.type == JointDef.JointType.RevoluteJoint) {
            joint2 = new RevoluteJoint(this, jointAddr);
        }
        if (def.type == JointDef.JointType.RopeJoint) {
            joint2 = new RopeJoint(this, jointAddr);
        }
        if (def.type == JointDef.JointType.WeldJoint) {
            joint2 = new WeldJoint(this, jointAddr);
        }
        if (def.type == JointDef.JointType.WheelJoint) {
            joint2 = new WheelJoint(this, jointAddr);
        }
        if (joint2 == null) {
            throw new GdxRuntimeException("Unknown joint type: " + def.type);
        }
        this.joints.put(joint2.addr, joint2);
        JointEdge jointEdgeA = new JointEdge(def.bodyB, joint2);
        JointEdge jointEdgeB = new JointEdge(def.bodyA, joint2);
        joint2.jointEdgeA = jointEdgeA;
        joint2.jointEdgeB = jointEdgeB;
        def.bodyA.joints.add(jointEdgeA);
        def.bodyB.joints.add(jointEdgeB);
        return joint2;
    }

    private long createProperJoint(JointDef def) {
        if (def.type == JointDef.JointType.DistanceJoint) {
            DistanceJointDef d = (DistanceJointDef) def;
            return jniCreateDistanceJoint(this.addr, d.bodyA.addr, d.bodyB.addr, d.collideConnected, d.localAnchorA.x, d.localAnchorA.y, d.localAnchorB.x, d.localAnchorB.y, d.length, d.frequencyHz, d.dampingRatio);
        } else if (def.type == JointDef.JointType.FrictionJoint) {
            FrictionJointDef d2 = (FrictionJointDef) def;
            return jniCreateFrictionJoint(this.addr, d2.bodyA.addr, d2.bodyB.addr, d2.collideConnected, d2.localAnchorA.x, d2.localAnchorA.y, d2.localAnchorB.x, d2.localAnchorB.y, d2.maxForce, d2.maxTorque);
        } else if (def.type == JointDef.JointType.GearJoint) {
            GearJointDef d3 = (GearJointDef) def;
            return jniCreateGearJoint(this.addr, d3.bodyA.addr, d3.bodyB.addr, d3.collideConnected, d3.joint1.addr, d3.joint2.addr, d3.ratio);
        } else if (def.type == JointDef.JointType.MotorJoint) {
            MotorJointDef d4 = (MotorJointDef) def;
            return jniCreateMotorJoint(this.addr, d4.bodyA.addr, d4.bodyB.addr, d4.collideConnected, d4.linearOffset.x, d4.linearOffset.y, d4.angularOffset, d4.maxForce, d4.maxTorque, d4.correctionFactor);
        } else if (def.type == JointDef.JointType.MouseJoint) {
            MouseJointDef d5 = (MouseJointDef) def;
            return jniCreateMouseJoint(this.addr, d5.bodyA.addr, d5.bodyB.addr, d5.collideConnected, d5.target.x, d5.target.y, d5.maxForce, d5.frequencyHz, d5.dampingRatio);
        } else if (def.type == JointDef.JointType.PrismaticJoint) {
            PrismaticJointDef d6 = (PrismaticJointDef) def;
            return jniCreatePrismaticJoint(this.addr, d6.bodyA.addr, d6.bodyB.addr, d6.collideConnected, d6.localAnchorA.x, d6.localAnchorA.y, d6.localAnchorB.x, d6.localAnchorB.y, d6.localAxisA.x, d6.localAxisA.y, d6.referenceAngle, d6.enableLimit, d6.lowerTranslation, d6.upperTranslation, d6.enableMotor, d6.maxMotorForce, d6.motorSpeed);
        } else if (def.type == JointDef.JointType.PulleyJoint) {
            PulleyJointDef d7 = (PulleyJointDef) def;
            return jniCreatePulleyJoint(this.addr, d7.bodyA.addr, d7.bodyB.addr, d7.collideConnected, d7.groundAnchorA.x, d7.groundAnchorA.y, d7.groundAnchorB.x, d7.groundAnchorB.y, d7.localAnchorA.x, d7.localAnchorA.y, d7.localAnchorB.x, d7.localAnchorB.y, d7.lengthA, d7.lengthB, d7.ratio);
        } else if (def.type == JointDef.JointType.RevoluteJoint) {
            RevoluteJointDef d8 = (RevoluteJointDef) def;
            return jniCreateRevoluteJoint(this.addr, d8.bodyA.addr, d8.bodyB.addr, d8.collideConnected, d8.localAnchorA.x, d8.localAnchorA.y, d8.localAnchorB.x, d8.localAnchorB.y, d8.referenceAngle, d8.enableLimit, d8.lowerAngle, d8.upperAngle, d8.enableMotor, d8.motorSpeed, d8.maxMotorTorque);
        } else if (def.type != JointDef.JointType.RopeJoint) {
            if (def.type == JointDef.JointType.WeldJoint) {
                WeldJointDef d9 = (WeldJointDef) def;
                return jniCreateWeldJoint(this.addr, d9.bodyA.addr, d9.bodyB.addr, d9.collideConnected, d9.localAnchorA.x, d9.localAnchorA.y, d9.localAnchorB.x, d9.localAnchorB.y, d9.referenceAngle, d9.frequencyHz, d9.dampingRatio);
            } else if (def.type == JointDef.JointType.WheelJoint) {
                WheelJointDef d10 = (WheelJointDef) def;
                return jniCreateWheelJoint(this.addr, d10.bodyA.addr, d10.bodyB.addr, d10.collideConnected, d10.localAnchorA.x, d10.localAnchorA.y, d10.localAnchorB.x, d10.localAnchorB.y, d10.localAxisA.x, d10.localAxisA.y, d10.enableMotor, d10.maxMotorTorque, d10.motorSpeed, d10.frequencyHz, d10.dampingRatio);
            } else {
                return 0L;
            }
        } else {
            RopeJointDef d11 = (RopeJointDef) def;
            return jniCreateRopeJoint(this.addr, d11.bodyA.addr, d11.bodyB.addr, d11.collideConnected, d11.localAnchorA.x, d11.localAnchorA.y, d11.localAnchorB.x, d11.localAnchorB.y, d11.maxLength);
        }
    }

    public void destroyJoint(Joint joint) {
        joint.setUserData(null);
        this.joints.remove(joint.addr);
        joint.jointEdgeA.other.joints.removeValue(joint.jointEdgeB, true);
        joint.jointEdgeB.other.joints.removeValue(joint.jointEdgeA, true);
        jniDestroyJoint(this.addr, joint.addr);
    }

    public void step(float timeStep, int velocityIterations, int positionIterations) {
        jniStep(this.addr, timeStep, velocityIterations, positionIterations);
    }

    public void clearForces() {
        jniClearForces(this.addr);
    }

    public void setWarmStarting(boolean flag) {
        jniSetWarmStarting(this.addr, flag);
    }

    public void setContinuousPhysics(boolean flag) {
        jniSetContiousPhysics(this.addr, flag);
    }

    public int getProxyCount() {
        return jniGetProxyCount(this.addr);
    }

    public int getBodyCount() {
        return jniGetBodyCount(this.addr);
    }

    public int getFixtureCount() {
        return this.fixtures.size;
    }

    public int getJointCount() {
        return jniGetJointcount(this.addr);
    }

    public int getContactCount() {
        return jniGetContactCount(this.addr);
    }

    public void setGravity(Vector2 gravity) {
        jniSetGravity(this.addr, gravity.x, gravity.y);
    }

    public Vector2 getGravity() {
        jniGetGravity(this.addr, this.tmpGravity);
        Vector2 vector2 = this.gravity;
        float[] fArr = this.tmpGravity;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public boolean isLocked() {
        return jniIsLocked(this.addr);
    }

    public void setAutoClearForces(boolean flag) {
        jniSetAutoClearForces(this.addr, flag);
    }

    public boolean getAutoClearForces() {
        return jniGetAutoClearForces(this.addr);
    }

    public void QueryAABB(QueryCallback callback, float lowerX, float lowerY, float upperX, float upperY) {
        this.queryCallback = callback;
        jniQueryAABB(this.addr, lowerX, lowerY, upperX, upperY);
    }

    public Array<Contact> getContactList() {
        int numContacts = getContactCount();
        if (numContacts > this.contactAddrs.length) {
            int newSize = numContacts * 2;
            this.contactAddrs = new long[newSize];
            this.contacts.ensureCapacity(newSize);
            this.freeContacts.ensureCapacity(newSize);
        }
        if (numContacts > this.freeContacts.size) {
            int freeConts = this.freeContacts.size;
            for (int i = 0; i < numContacts - freeConts; i++) {
                this.freeContacts.add(new Contact(this, 0L));
            }
        }
        jniGetContactList(this.addr, this.contactAddrs);
        this.contacts.clear();
        for (int i2 = 0; i2 < numContacts; i2++) {
            Contact contact = this.freeContacts.get(i2);
            contact.addr = this.contactAddrs[i2];
            this.contacts.add(contact);
        }
        return this.contacts;
    }

    public void getBodies(Array<Body> bodies) {
        bodies.clear();
        bodies.ensureCapacity(this.bodies.size);
        Iterator<Body> iter = this.bodies.values();
        while (iter.hasNext()) {
            bodies.add(iter.next());
        }
    }

    public void getFixtures(Array<Fixture> fixtures) {
        fixtures.clear();
        fixtures.ensureCapacity(this.fixtures.size);
        Iterator<Fixture> iter = this.fixtures.values();
        while (iter.hasNext()) {
            fixtures.add(iter.next());
        }
    }

    public void getJoints(Array<Joint> joints) {
        joints.clear();
        joints.ensureCapacity(this.joints.size);
        Iterator<Joint> iter = this.joints.values();
        while (iter.hasNext()) {
            joints.add(iter.next());
        }
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        jniDispose(this.addr);
    }

    private boolean contactFilter(long fixtureA, long fixtureB) {
        ContactFilter contactFilter = this.contactFilter;
        if (contactFilter != null) {
            return contactFilter.shouldCollide(this.fixtures.get(fixtureA), this.fixtures.get(fixtureB));
        }
        Filter filterA = this.fixtures.get(fixtureA).getFilterData();
        Filter filterB = this.fixtures.get(fixtureB).getFilterData();
        boolean z = true;
        if (filterA.groupIndex == filterB.groupIndex && filterA.groupIndex != 0) {
            return filterA.groupIndex > 0;
        }
        boolean collide = ((filterA.maskBits & filterB.categoryBits) == 0 || (filterA.categoryBits & filterB.maskBits) == 0) ? false : false;
        return collide;
    }

    private void beginContact(long contactAddr) {
        ContactListener contactListener = this.contactListener;
        if (contactListener != null) {
            Contact contact = this.contact;
            contact.addr = contactAddr;
            contactListener.beginContact(contact);
        }
    }

    private void endContact(long contactAddr) {
        ContactListener contactListener = this.contactListener;
        if (contactListener != null) {
            Contact contact = this.contact;
            contact.addr = contactAddr;
            contactListener.endContact(contact);
        }
    }

    private void preSolve(long contactAddr, long manifoldAddr) {
        ContactListener contactListener = this.contactListener;
        if (contactListener != null) {
            Contact contact = this.contact;
            contact.addr = contactAddr;
            Manifold manifold = this.manifold;
            manifold.addr = manifoldAddr;
            contactListener.preSolve(contact, manifold);
        }
    }

    private void postSolve(long contactAddr, long impulseAddr) {
        ContactListener contactListener = this.contactListener;
        if (contactListener != null) {
            Contact contact = this.contact;
            contact.addr = contactAddr;
            ContactImpulse contactImpulse = this.impulse;
            contactImpulse.addr = impulseAddr;
            contactListener.postSolve(contact, contactImpulse);
        }
    }

    private boolean reportFixture(long addr) {
        QueryCallback queryCallback = this.queryCallback;
        if (queryCallback != null) {
            return queryCallback.reportFixture(this.fixtures.get(addr));
        }
        return false;
    }

    public void rayCast(RayCastCallback callback, Vector2 point1, Vector2 point2) {
        rayCast(callback, point1.x, point1.y, point2.x, point2.y);
    }

    public void rayCast(RayCastCallback callback, float point1X, float point1Y, float point2X, float point2Y) {
        this.rayCastCallback = callback;
        jniRayCast(this.addr, point1X, point1Y, point2X, point2Y);
    }

    private float reportRayFixture(long addr, float pX, float pY, float nX, float nY, float fraction) {
        RayCastCallback rayCastCallback = this.rayCastCallback;
        if (rayCastCallback != null) {
            Vector2 vector2 = this.rayPoint;
            vector2.x = pX;
            vector2.y = pY;
            Vector2 vector22 = this.rayNormal;
            vector22.x = nX;
            vector22.y = nY;
            return rayCastCallback.reportRayFixture(this.fixtures.get(addr), this.rayPoint, this.rayNormal, fraction);
        }
        return 0.0f;
    }
}