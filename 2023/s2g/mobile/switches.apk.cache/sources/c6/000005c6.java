package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.scenes.scene2d.ui.ProgressBar;
import com.kotcrab.vis.ui.VisUI;

/* loaded from: classes.dex */
public class VisProgressBar extends ProgressBar {
    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public VisProgressBar(float r8, float r9, float r10, boolean r11) {
        /*
            r7 = this;
            com.badlogic.gdx.scenes.scene2d.ui.Skin r0 = com.kotcrab.vis.ui.VisUI.getSkin()
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            java.lang.String r2 = "default-"
            r1.append(r2)
            if (r11 == 0) goto L13
            java.lang.String r2 = "vertical"
            goto L15
        L13:
            java.lang.String r2 = "horizontal"
        L15:
            r1.append(r2)
            java.lang.String r1 = r1.toString()
            java.lang.Class<com.badlogic.gdx.scenes.scene2d.ui.ProgressBar$ProgressBarStyle> r2 = com.badlogic.gdx.scenes.scene2d.ui.ProgressBar.ProgressBarStyle.class
            java.lang.Object r0 = r0.get(r1, r2)
            r6 = r0
            com.badlogic.gdx.scenes.scene2d.ui.ProgressBar$ProgressBarStyle r6 = (com.badlogic.gdx.scenes.scene2d.ui.ProgressBar.ProgressBarStyle) r6
            r1 = r7
            r2 = r8
            r3 = r9
            r4 = r10
            r5 = r11
            r1.<init>(r2, r3, r4, r5, r6)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.kotcrab.vis.ui.widget.VisProgressBar.<init>(float, float, float, boolean):void");
    }

    public VisProgressBar(float min, float max, float stepSize, boolean vertical, String styleName) {
        this(min, max, stepSize, vertical, (ProgressBar.ProgressBarStyle) VisUI.getSkin().get(styleName, ProgressBar.ProgressBarStyle.class));
    }

    public VisProgressBar(float min, float max, float stepSize, boolean vertical, ProgressBar.ProgressBarStyle style) {
        super(min, max, stepSize, vertical, style);
    }
}