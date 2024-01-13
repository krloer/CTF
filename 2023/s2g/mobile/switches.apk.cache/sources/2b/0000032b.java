package com.badlogic.gdx.physics.box2d;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.glutils.ShapeRenderer;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.BodyDef;
import com.badlogic.gdx.physics.box2d.JointDef;
import com.badlogic.gdx.physics.box2d.Shape;
import com.badlogic.gdx.physics.box2d.joints.PulleyJoint;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import java.util.Iterator;

/* loaded from: classes.dex */
public class Box2DDebugRenderer implements Disposable {
    public final Color AABB_COLOR;
    public final Color JOINT_COLOR;
    public final Color SHAPE_AWAKE;
    public final Color SHAPE_KINEMATIC;
    public final Color SHAPE_NOT_ACTIVE;
    public final Color SHAPE_NOT_AWAKE;
    public final Color SHAPE_STATIC;
    public final Color VELOCITY_COLOR;
    private boolean drawAABBs;
    private boolean drawBodies;
    private boolean drawContacts;
    private boolean drawInactiveBodies;
    private boolean drawJoints;
    private boolean drawVelocities;
    private final Vector2 f;
    private final Vector2 lv;
    protected ShapeRenderer renderer;
    private final Vector2 v;
    private static final Vector2[] vertices = new Vector2[1000];
    private static final Vector2 lower = new Vector2();
    private static final Vector2 upper = new Vector2();
    private static final Array<Body> bodies = new Array<>();
    private static final Array<Joint> joints = new Array<>();
    private static Vector2 t = new Vector2();
    private static Vector2 axis = new Vector2();

    public Box2DDebugRenderer() {
        this(true, true, false, true, false, true);
    }

    public Box2DDebugRenderer(boolean drawBodies, boolean drawJoints, boolean drawAABBs, boolean drawInactiveBodies, boolean drawVelocities, boolean drawContacts) {
        this.SHAPE_NOT_ACTIVE = new Color(0.5f, 0.5f, 0.3f, 1.0f);
        this.SHAPE_STATIC = new Color(0.5f, 0.9f, 0.5f, 1.0f);
        this.SHAPE_KINEMATIC = new Color(0.5f, 0.5f, 0.9f, 1.0f);
        this.SHAPE_NOT_AWAKE = new Color(0.6f, 0.6f, 0.6f, 1.0f);
        this.SHAPE_AWAKE = new Color(0.9f, 0.7f, 0.7f, 1.0f);
        this.JOINT_COLOR = new Color(0.5f, 0.8f, 0.8f, 1.0f);
        this.AABB_COLOR = new Color(1.0f, 0.0f, 1.0f, 1.0f);
        this.VELOCITY_COLOR = new Color(1.0f, 0.0f, 0.0f, 1.0f);
        this.f = new Vector2();
        this.v = new Vector2();
        this.lv = new Vector2();
        this.renderer = new ShapeRenderer();
        int i = 0;
        while (true) {
            Vector2[] vector2Arr = vertices;
            if (i < vector2Arr.length) {
                vector2Arr[i] = new Vector2();
                i++;
            } else {
                this.drawBodies = drawBodies;
                this.drawJoints = drawJoints;
                this.drawAABBs = drawAABBs;
                this.drawInactiveBodies = drawInactiveBodies;
                this.drawVelocities = drawVelocities;
                this.drawContacts = drawContacts;
                return;
            }
        }
    }

    public void render(World world, Matrix4 projMatrix) {
        this.renderer.setProjectionMatrix(projMatrix);
        renderBodies(world);
    }

    private void renderBodies(World world) {
        this.renderer.begin(ShapeRenderer.ShapeType.Line);
        if (this.drawBodies || this.drawAABBs) {
            world.getBodies(bodies);
            Iterator<Body> iter = bodies.iterator();
            while (iter.hasNext()) {
                Body body = iter.next();
                if (body.isActive() || this.drawInactiveBodies) {
                    renderBody(body);
                }
            }
        }
        if (this.drawJoints) {
            world.getJoints(joints);
            Iterator<Joint> iter2 = joints.iterator();
            while (iter2.hasNext()) {
                Joint joint = iter2.next();
                drawJoint(joint);
            }
        }
        this.renderer.end();
        if (this.drawContacts) {
            this.renderer.begin(ShapeRenderer.ShapeType.Point);
            Array.ArrayIterator<Contact> it = world.getContactList().iterator();
            while (it.hasNext()) {
                Contact contact = it.next();
                drawContact(contact);
            }
            this.renderer.end();
        }
    }

    protected void renderBody(Body body) {
        Transform transform = body.getTransform();
        Array.ArrayIterator<Fixture> it = body.getFixtureList().iterator();
        while (it.hasNext()) {
            Fixture fixture = it.next();
            if (this.drawBodies) {
                drawShape(fixture, transform, getColorByBody(body));
                if (this.drawVelocities) {
                    Vector2 position = body.getPosition();
                    drawSegment(position, body.getLinearVelocity().add(position), this.VELOCITY_COLOR);
                }
            }
            if (this.drawAABBs) {
                drawAABB(fixture, transform);
            }
        }
    }

    private Color getColorByBody(Body body) {
        if (!body.isActive()) {
            return this.SHAPE_NOT_ACTIVE;
        }
        if (body.getType() == BodyDef.BodyType.StaticBody) {
            return this.SHAPE_STATIC;
        }
        if (body.getType() == BodyDef.BodyType.KinematicBody) {
            return this.SHAPE_KINEMATIC;
        }
        if (!body.isAwake()) {
            return this.SHAPE_NOT_AWAKE;
        }
        return this.SHAPE_AWAKE;
    }

    private void drawAABB(Fixture fixture, Transform transform) {
        if (fixture.getType() == Shape.Type.Circle) {
            CircleShape shape = (CircleShape) fixture.getShape();
            float radius = shape.getRadius();
            vertices[0].set(shape.getPosition());
            transform.mul(vertices[0]);
            lower.set(vertices[0].x - radius, vertices[0].y - radius);
            upper.set(vertices[0].x + radius, vertices[0].y + radius);
            vertices[0].set(lower.x, lower.y);
            vertices[1].set(upper.x, lower.y);
            vertices[2].set(upper.x, upper.y);
            vertices[3].set(lower.x, upper.y);
            drawSolidPolygon(vertices, 4, this.AABB_COLOR, true);
        } else if (fixture.getType() == Shape.Type.Polygon) {
            PolygonShape shape2 = (PolygonShape) fixture.getShape();
            int vertexCount = shape2.getVertexCount();
            shape2.getVertex(0, vertices[0]);
            lower.set(transform.mul(vertices[0]));
            upper.set(lower);
            for (int i = 1; i < vertexCount; i++) {
                shape2.getVertex(i, vertices[i]);
                transform.mul(vertices[i]);
                Vector2 vector2 = lower;
                vector2.x = Math.min(vector2.x, vertices[i].x);
                Vector2 vector22 = lower;
                vector22.y = Math.min(vector22.y, vertices[i].y);
                Vector2 vector23 = upper;
                vector23.x = Math.max(vector23.x, vertices[i].x);
                Vector2 vector24 = upper;
                vector24.y = Math.max(vector24.y, vertices[i].y);
            }
            vertices[0].set(lower.x, lower.y);
            vertices[1].set(upper.x, lower.y);
            vertices[2].set(upper.x, upper.y);
            vertices[3].set(lower.x, upper.y);
            drawSolidPolygon(vertices, 4, this.AABB_COLOR, true);
        }
    }

    private void drawShape(Fixture fixture, Transform transform, Color color) {
        if (fixture.getType() == Shape.Type.Circle) {
            CircleShape circle = (CircleShape) fixture.getShape();
            t.set(circle.getPosition());
            transform.mul(t);
            drawSolidCircle(t, circle.getRadius(), axis.set(transform.vals[2], transform.vals[3]), color);
        } else if (fixture.getType() == Shape.Type.Edge) {
            EdgeShape edge = (EdgeShape) fixture.getShape();
            edge.getVertex1(vertices[0]);
            edge.getVertex2(vertices[1]);
            transform.mul(vertices[0]);
            transform.mul(vertices[1]);
            drawSolidPolygon(vertices, 2, color, true);
        } else if (fixture.getType() == Shape.Type.Polygon) {
            PolygonShape chain = (PolygonShape) fixture.getShape();
            int vertexCount = chain.getVertexCount();
            for (int i = 0; i < vertexCount; i++) {
                chain.getVertex(i, vertices[i]);
                transform.mul(vertices[i]);
            }
            drawSolidPolygon(vertices, vertexCount, color, true);
        } else if (fixture.getType() == Shape.Type.Chain) {
            ChainShape chain2 = (ChainShape) fixture.getShape();
            int vertexCount2 = chain2.getVertexCount();
            for (int i2 = 0; i2 < vertexCount2; i2++) {
                chain2.getVertex(i2, vertices[i2]);
                transform.mul(vertices[i2]);
            }
            drawSolidPolygon(vertices, vertexCount2, color, false);
        }
    }

    private void drawSolidCircle(Vector2 center, float radius, Vector2 axis2, Color color) {
        float angle = 0.0f;
        this.renderer.setColor(color.r, color.g, color.b, color.a);
        int i = 0;
        while (i < 20) {
            this.v.set((((float) Math.cos(angle)) * radius) + center.x, (((float) Math.sin(angle)) * radius) + center.y);
            if (i == 0) {
                this.lv.set(this.v);
                this.f.set(this.v);
            } else {
                this.renderer.line(this.lv.x, this.lv.y, this.v.x, this.v.y);
                this.lv.set(this.v);
            }
            i++;
            angle += 0.31415927f;
        }
        this.renderer.line(this.f.x, this.f.y, this.lv.x, this.lv.y);
        this.renderer.line(center.x, center.y, 0.0f, center.x + (axis2.x * radius), center.y + (axis2.y * radius), 0.0f);
    }

    private void drawSolidPolygon(Vector2[] vertices2, int vertexCount, Color color, boolean closed) {
        this.renderer.setColor(color.r, color.g, color.b, color.a);
        this.lv.set(vertices2[0]);
        this.f.set(vertices2[0]);
        for (int i = 1; i < vertexCount; i++) {
            Vector2 v = vertices2[i];
            this.renderer.line(this.lv.x, this.lv.y, v.x, v.y);
            this.lv.set(v);
        }
        if (closed) {
            this.renderer.line(this.f.x, this.f.y, this.lv.x, this.lv.y);
        }
    }

    private void drawJoint(Joint joint) {
        Body bodyA = joint.getBodyA();
        Body bodyB = joint.getBodyB();
        Transform xf1 = bodyA.getTransform();
        Transform xf2 = bodyB.getTransform();
        Vector2 x1 = xf1.getPosition();
        Vector2 x2 = xf2.getPosition();
        Vector2 p1 = joint.getAnchorA();
        Vector2 p2 = joint.getAnchorB();
        if (joint.getType() == JointDef.JointType.DistanceJoint) {
            drawSegment(p1, p2, this.JOINT_COLOR);
        } else if (joint.getType() == JointDef.JointType.PulleyJoint) {
            PulleyJoint pulley = (PulleyJoint) joint;
            Vector2 s1 = pulley.getGroundAnchorA();
            Vector2 s2 = pulley.getGroundAnchorB();
            drawSegment(s1, p1, this.JOINT_COLOR);
            drawSegment(s2, p2, this.JOINT_COLOR);
            drawSegment(s1, s2, this.JOINT_COLOR);
        } else if (joint.getType() == JointDef.JointType.MouseJoint) {
            drawSegment(joint.getAnchorA(), joint.getAnchorB(), this.JOINT_COLOR);
        } else {
            drawSegment(x1, p1, this.JOINT_COLOR);
            drawSegment(p1, p2, this.JOINT_COLOR);
            drawSegment(x2, p2, this.JOINT_COLOR);
        }
    }

    private void drawSegment(Vector2 x1, Vector2 x2, Color color) {
        this.renderer.setColor(color);
        this.renderer.line(x1.x, x1.y, x2.x, x2.y);
    }

    private void drawContact(Contact contact) {
        WorldManifold worldManifold = contact.getWorldManifold();
        if (worldManifold.getNumberOfContactPoints() == 0) {
            return;
        }
        Vector2 point = worldManifold.getPoints()[0];
        this.renderer.setColor(getColorByBody(contact.getFixtureA().getBody()));
        this.renderer.point(point.x, point.y, 0.0f);
    }

    public boolean isDrawBodies() {
        return this.drawBodies;
    }

    public void setDrawBodies(boolean drawBodies) {
        this.drawBodies = drawBodies;
    }

    public boolean isDrawJoints() {
        return this.drawJoints;
    }

    public void setDrawJoints(boolean drawJoints) {
        this.drawJoints = drawJoints;
    }

    public boolean isDrawAABBs() {
        return this.drawAABBs;
    }

    public void setDrawAABBs(boolean drawAABBs) {
        this.drawAABBs = drawAABBs;
    }

    public boolean isDrawInactiveBodies() {
        return this.drawInactiveBodies;
    }

    public void setDrawInactiveBodies(boolean drawInactiveBodies) {
        this.drawInactiveBodies = drawInactiveBodies;
    }

    public boolean isDrawVelocities() {
        return this.drawVelocities;
    }

    public void setDrawVelocities(boolean drawVelocities) {
        this.drawVelocities = drawVelocities;
    }

    public boolean isDrawContacts() {
        return this.drawContacts;
    }

    public void setDrawContacts(boolean drawContacts) {
        this.drawContacts = drawContacts;
    }

    public static Vector2 getAxis() {
        return axis;
    }

    public static void setAxis(Vector2 axis2) {
        axis = axis2;
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        this.renderer.dispose();
    }
}