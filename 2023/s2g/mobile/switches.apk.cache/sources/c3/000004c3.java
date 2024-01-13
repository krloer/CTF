package com.badlogic.gdx.utils;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Files;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.LifecycleListener;

/* loaded from: classes.dex */
public class Timer {
    static TimerThread thread;
    static final Object threadLock = new Object();
    final Array<Task> tasks = new Array<>(false, 8);

    public static Timer instance() {
        Timer timer;
        synchronized (threadLock) {
            TimerThread thread2 = thread();
            if (thread2.instance == null) {
                thread2.instance = new Timer();
            }
            timer = thread2.instance;
        }
        return timer;
    }

    private static TimerThread thread() {
        TimerThread timerThread;
        synchronized (threadLock) {
            if (thread == null || thread.files != Gdx.files) {
                if (thread != null) {
                    thread.dispose();
                }
                thread = new TimerThread();
            }
            timerThread = thread;
        }
        return timerThread;
    }

    public Timer() {
        start();
    }

    public Task postTask(Task task) {
        return scheduleTask(task, 0.0f, 0.0f, 0);
    }

    public Task scheduleTask(Task task, float delaySeconds) {
        return scheduleTask(task, delaySeconds, 0.0f, 0);
    }

    public Task scheduleTask(Task task, float delaySeconds, float intervalSeconds) {
        return scheduleTask(task, delaySeconds, intervalSeconds, -1);
    }

    public Task scheduleTask(Task task, float delaySeconds, float intervalSeconds, int repeatCount) {
        synchronized (threadLock) {
            synchronized (this) {
                synchronized (task) {
                    if (task.timer != null) {
                        throw new IllegalArgumentException("The same task may not be scheduled twice.");
                    }
                    task.timer = this;
                    long timeMillis = System.nanoTime() / 1000000;
                    long executeTimeMillis = (delaySeconds * 1000.0f) + timeMillis;
                    if (thread.pauseTimeMillis > 0) {
                        executeTimeMillis -= timeMillis - thread.pauseTimeMillis;
                    }
                    task.executeTimeMillis = executeTimeMillis;
                    task.intervalMillis = 1000.0f * intervalSeconds;
                    task.repeatCount = repeatCount;
                    this.tasks.add(task);
                }
            }
            threadLock.notifyAll();
        }
        return task;
    }

    public void stop() {
        synchronized (threadLock) {
            thread().instances.removeValue(this, true);
        }
    }

    public void start() {
        synchronized (threadLock) {
            TimerThread thread2 = thread();
            Array<Timer> instances = thread2.instances;
            if (instances.contains(this, true)) {
                return;
            }
            instances.add(this);
            threadLock.notifyAll();
        }
    }

    public synchronized void clear() {
        int n = this.tasks.size;
        for (int i = 0; i < n; i++) {
            Task task = this.tasks.get(i);
            synchronized (task) {
                task.executeTimeMillis = 0L;
                task.timer = null;
            }
        }
        this.tasks.clear();
    }

    public synchronized boolean isEmpty() {
        return this.tasks.size == 0;
    }

    synchronized long update(long timeMillis, long waitMillis) {
        int i = 0;
        int n = this.tasks.size;
        while (i < n) {
            Task task = this.tasks.get(i);
            synchronized (task) {
                if (task.executeTimeMillis > timeMillis) {
                    waitMillis = Math.min(waitMillis, task.executeTimeMillis - timeMillis);
                } else {
                    if (task.repeatCount == 0) {
                        task.timer = null;
                        this.tasks.removeIndex(i);
                        i--;
                        n--;
                    } else {
                        task.executeTimeMillis = task.intervalMillis + timeMillis;
                        waitMillis = Math.min(waitMillis, task.intervalMillis);
                        if (task.repeatCount > 0) {
                            task.repeatCount--;
                        }
                    }
                    task.app.postRunnable(task);
                }
            }
            i++;
        }
        return waitMillis;
    }

    public synchronized void delay(long delayMillis) {
        int n = this.tasks.size;
        for (int i = 0; i < n; i++) {
            Task task = this.tasks.get(i);
            synchronized (task) {
                task.executeTimeMillis += delayMillis;
            }
        }
    }

    public static Task post(Task task) {
        return instance().postTask(task);
    }

    public static Task schedule(Task task, float delaySeconds) {
        return instance().scheduleTask(task, delaySeconds);
    }

    public static Task schedule(Task task, float delaySeconds, float intervalSeconds) {
        return instance().scheduleTask(task, delaySeconds, intervalSeconds);
    }

    public static Task schedule(Task task, float delaySeconds, float intervalSeconds, int repeatCount) {
        return instance().scheduleTask(task, delaySeconds, intervalSeconds, repeatCount);
    }

    /* loaded from: classes.dex */
    public static abstract class Task implements Runnable {
        final Application app = Gdx.app;
        long executeTimeMillis;
        long intervalMillis;
        int repeatCount;
        volatile Timer timer;

        @Override // java.lang.Runnable
        public abstract void run();

        public Task() {
            if (this.app == null) {
                throw new IllegalStateException("Gdx.app not available.");
            }
        }

        public void cancel() {
            Timer timer = this.timer;
            if (timer != null) {
                synchronized (timer) {
                    synchronized (this) {
                        this.executeTimeMillis = 0L;
                        this.timer = null;
                        timer.tasks.removeValue(this, true);
                    }
                }
                return;
            }
            synchronized (this) {
                this.executeTimeMillis = 0L;
                this.timer = null;
            }
        }

        public boolean isScheduled() {
            return this.timer != null;
        }

        public synchronized long getExecuteTimeMillis() {
            return this.executeTimeMillis;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class TimerThread implements Runnable, LifecycleListener {
        Timer instance;
        long pauseTimeMillis;
        final Array<Timer> instances = new Array<>(1);
        final Files files = Gdx.files;
        final Application app = Gdx.app;

        public TimerThread() {
            this.app.addLifecycleListener(this);
            resume();
            Thread thread = new Thread(this, "Timer");
            thread.setDaemon(true);
            thread.start();
        }

        @Override // java.lang.Runnable
        public void run() {
            while (true) {
                synchronized (Timer.threadLock) {
                    if (Timer.thread != this || this.files != Gdx.files) {
                        break;
                    }
                    long waitMillis = 5000;
                    if (this.pauseTimeMillis == 0) {
                        long timeMillis = System.nanoTime() / 1000000;
                        int n = this.instances.size;
                        for (int i = 0; i < n; i++) {
                            waitMillis = this.instances.get(i).update(timeMillis, waitMillis);
                        }
                    }
                    if (Timer.thread != this || this.files != Gdx.files) {
                        break;
                    } else if (waitMillis > 0) {
                        try {
                            Timer.threadLock.wait(waitMillis);
                        } catch (InterruptedException e) {
                        }
                    }
                }
            }
            dispose();
        }

        @Override // com.badlogic.gdx.LifecycleListener
        public void resume() {
            synchronized (Timer.threadLock) {
                long delayMillis = (System.nanoTime() / 1000000) - this.pauseTimeMillis;
                int n = this.instances.size;
                for (int i = 0; i < n; i++) {
                    this.instances.get(i).delay(delayMillis);
                }
                this.pauseTimeMillis = 0L;
                Timer.threadLock.notifyAll();
            }
        }

        @Override // com.badlogic.gdx.LifecycleListener
        public void pause() {
            synchronized (Timer.threadLock) {
                this.pauseTimeMillis = System.nanoTime() / 1000000;
                Timer.threadLock.notifyAll();
            }
        }

        @Override // com.badlogic.gdx.LifecycleListener
        public void dispose() {
            synchronized (Timer.threadLock) {
                if (Timer.thread == this) {
                    Timer.thread = null;
                }
                this.instances.clear();
                Timer.threadLock.notifyAll();
            }
            this.app.removeLifecycleListener(this);
        }
    }
}