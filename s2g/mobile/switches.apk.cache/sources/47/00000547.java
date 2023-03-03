package com.kotcrab.vis.ui.util.async;

/* loaded from: classes.dex */
public abstract class SteppedAsyncTask extends AsyncTask {
    private int step;
    private int totalSteps;

    public SteppedAsyncTask(String threadName) {
        super(threadName);
    }

    protected void setTotalSteps(int totalSteps) {
        this.totalSteps = totalSteps;
        this.step = 0;
        setProgressPercent(0);
    }

    protected void nextStep() {
        int i = this.step + 1;
        this.step = i;
        setProgressPercent((i * 100) / this.totalSteps);
    }
}