package com.uithack.spaceinvaders;

/* loaded from: Space Infiltration/classes */
public class Flag {
    public static char[] str = {'x', 'D', 'y', 'e', 'L', 'N', 'F', 31, 25, 'V', 'z', 'E', 30, '_', 30, 'r', 28, 24, 'r', '@', 'T', 'r', 'N', 'X', ']', 'r', 29, 'K', 'r', 'G', 25, '[', 25, 18, 'P'};

    public static void show() {
        for (int i = 0; i < 35; i++) {
            System.out.print(str[i] ^ '-');
        }
    }
}