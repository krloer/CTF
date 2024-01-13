package com.badlogic.gdx;

import com.badlogic.gdx.utils.ObjectIntMap;

/* loaded from: classes.dex */
public interface Input {

    /* loaded from: classes.dex */
    public static class Buttons {
        public static final int BACK = 3;
        public static final int FORWARD = 4;
        public static final int LEFT = 0;
        public static final int MIDDLE = 2;
        public static final int RIGHT = 1;
    }

    /* loaded from: classes.dex */
    public enum OnscreenKeyboardType {
        Default,
        NumberPad,
        PhonePad,
        Email,
        Password,
        URI
    }

    /* loaded from: classes.dex */
    public enum Orientation {
        Landscape,
        Portrait
    }

    /* loaded from: classes.dex */
    public enum Peripheral {
        HardwareKeyboard,
        OnscreenKeyboard,
        MultitouchScreen,
        Accelerometer,
        Compass,
        Vibrator,
        Gyroscope,
        RotationVector,
        Pressure
    }

    /* loaded from: classes.dex */
    public interface TextInputListener {
        void canceled();

        void input(String str);
    }

    void cancelVibrate();

    float getAccelerometerX();

    float getAccelerometerY();

    float getAccelerometerZ();

    float getAzimuth();

    long getCurrentEventTime();

    int getDeltaX();

    int getDeltaX(int i);

    int getDeltaY();

    int getDeltaY(int i);

    float getGyroscopeX();

    float getGyroscopeY();

    float getGyroscopeZ();

    InputProcessor getInputProcessor();

    int getMaxPointers();

    Orientation getNativeOrientation();

    float getPitch();

    float getPressure();

    float getPressure(int i);

    float getRoll();

    int getRotation();

    void getRotationMatrix(float[] fArr);

    void getTextInput(TextInputListener textInputListener, String str, String str2, String str3);

    void getTextInput(TextInputListener textInputListener, String str, String str2, String str3, OnscreenKeyboardType onscreenKeyboardType);

    int getX();

    int getX(int i);

    int getY();

    int getY(int i);

    boolean isButtonJustPressed(int i);

    boolean isButtonPressed(int i);

    @Deprecated
    boolean isCatchBackKey();

    boolean isCatchKey(int i);

    @Deprecated
    boolean isCatchMenuKey();

    boolean isCursorCatched();

    boolean isKeyJustPressed(int i);

    boolean isKeyPressed(int i);

    boolean isPeripheralAvailable(Peripheral peripheral);

    boolean isTouched();

    boolean isTouched(int i);

    boolean justTouched();

    @Deprecated
    void setCatchBackKey(boolean z);

    void setCatchKey(int i, boolean z);

    @Deprecated
    void setCatchMenuKey(boolean z);

    void setCursorCatched(boolean z);

    void setCursorPosition(int i, int i2);

    void setInputProcessor(InputProcessor inputProcessor);

    void setOnscreenKeyboardVisible(boolean z);

    void setOnscreenKeyboardVisible(boolean z, OnscreenKeyboardType onscreenKeyboardType);

    void vibrate(int i);

    void vibrate(long[] jArr, int i);

    /* loaded from: classes.dex */
    public static class Keys {
        public static final int A = 29;
        public static final int ALT_LEFT = 57;
        public static final int ALT_RIGHT = 58;
        public static final int ANY_KEY = -1;
        public static final int APOSTROPHE = 75;
        public static final int AT = 77;
        public static final int B = 30;
        public static final int BACK = 4;
        public static final int BACKSLASH = 73;
        public static final int BACKSPACE = 67;
        public static final int BUTTON_A = 96;
        public static final int BUTTON_B = 97;
        public static final int BUTTON_C = 98;
        public static final int BUTTON_CIRCLE = 255;
        public static final int BUTTON_L1 = 102;
        public static final int BUTTON_L2 = 104;
        public static final int BUTTON_MODE = 110;
        public static final int BUTTON_R1 = 103;
        public static final int BUTTON_R2 = 105;
        public static final int BUTTON_SELECT = 109;
        public static final int BUTTON_START = 108;
        public static final int BUTTON_THUMBL = 106;
        public static final int BUTTON_THUMBR = 107;
        public static final int BUTTON_X = 99;
        public static final int BUTTON_Y = 100;
        public static final int BUTTON_Z = 101;
        public static final int C = 31;
        public static final int CALL = 5;
        public static final int CAMERA = 27;
        public static final int CAPS_LOCK = 115;
        public static final int CENTER = 23;
        public static final int CLEAR = 28;
        public static final int COLON = 243;
        public static final int COMMA = 55;
        public static final int CONTROL_LEFT = 129;
        public static final int CONTROL_RIGHT = 130;
        public static final int D = 32;
        public static final int DEL = 67;
        public static final int DOWN = 20;
        public static final int DPAD_CENTER = 23;
        public static final int DPAD_DOWN = 20;
        public static final int DPAD_LEFT = 21;
        public static final int DPAD_RIGHT = 22;
        public static final int DPAD_UP = 19;
        public static final int E = 33;
        public static final int END = 123;
        public static final int ENDCALL = 6;
        public static final int ENTER = 66;
        public static final int ENVELOPE = 65;
        public static final int EQUALS = 70;
        public static final int ESCAPE = 111;
        public static final int EXPLORER = 64;
        public static final int F = 34;
        public static final int F1 = 131;
        public static final int F10 = 140;
        public static final int F11 = 141;
        public static final int F12 = 142;
        public static final int F13 = 183;
        public static final int F14 = 184;
        public static final int F15 = 185;
        public static final int F16 = 186;
        public static final int F17 = 187;
        public static final int F18 = 188;
        public static final int F19 = 189;
        public static final int F2 = 132;
        public static final int F20 = 190;
        public static final int F21 = 191;
        public static final int F22 = 192;
        public static final int F23 = 193;
        public static final int F24 = 194;
        public static final int F3 = 133;
        public static final int F4 = 134;
        public static final int F5 = 135;
        public static final int F6 = 136;
        public static final int F7 = 137;
        public static final int F8 = 138;
        public static final int F9 = 139;
        public static final int FOCUS = 80;
        public static final int FORWARD_DEL = 112;
        public static final int G = 35;
        public static final int GRAVE = 68;
        public static final int H = 36;
        public static final int HEADSETHOOK = 79;
        public static final int HOME = 3;
        public static final int I = 37;
        public static final int INSERT = 124;
        public static final int J = 38;
        public static final int K = 39;
        public static final int L = 40;
        public static final int LEFT = 21;
        public static final int LEFT_BRACKET = 71;
        public static final int M = 41;
        public static final int MAX_KEYCODE = 255;
        public static final int MEDIA_FAST_FORWARD = 90;
        public static final int MEDIA_NEXT = 87;
        public static final int MEDIA_PLAY_PAUSE = 85;
        public static final int MEDIA_PREVIOUS = 88;
        public static final int MEDIA_REWIND = 89;
        public static final int MEDIA_STOP = 86;
        public static final int MENU = 82;
        public static final int META_ALT_LEFT_ON = 16;
        public static final int META_ALT_ON = 2;
        public static final int META_ALT_RIGHT_ON = 32;
        public static final int META_SHIFT_LEFT_ON = 64;
        public static final int META_SHIFT_ON = 1;
        public static final int META_SHIFT_RIGHT_ON = 128;
        public static final int META_SYM_ON = 4;
        public static final int MINUS = 69;
        public static final int MUTE = 91;
        public static final int N = 42;
        public static final int NOTIFICATION = 83;
        public static final int NUM = 78;
        public static final int NUMPAD_0 = 144;
        public static final int NUMPAD_1 = 145;
        public static final int NUMPAD_2 = 146;
        public static final int NUMPAD_3 = 147;
        public static final int NUMPAD_4 = 148;
        public static final int NUMPAD_5 = 149;
        public static final int NUMPAD_6 = 150;
        public static final int NUMPAD_7 = 151;
        public static final int NUMPAD_8 = 152;
        public static final int NUMPAD_9 = 153;
        public static final int NUMPAD_ADD = 157;
        public static final int NUMPAD_COMMA = 159;
        public static final int NUMPAD_DIVIDE = 154;
        public static final int NUMPAD_DOT = 158;
        public static final int NUMPAD_ENTER = 160;
        public static final int NUMPAD_EQUALS = 161;
        public static final int NUMPAD_LEFT_PAREN = 162;
        public static final int NUMPAD_MULTIPLY = 155;
        public static final int NUMPAD_RIGHT_PAREN = 163;
        public static final int NUMPAD_SUBTRACT = 156;
        public static final int NUM_0 = 7;
        public static final int NUM_1 = 8;
        public static final int NUM_2 = 9;
        public static final int NUM_3 = 10;
        public static final int NUM_4 = 11;
        public static final int NUM_5 = 12;
        public static final int NUM_6 = 13;
        public static final int NUM_7 = 14;
        public static final int NUM_8 = 15;
        public static final int NUM_9 = 16;
        public static final int NUM_LOCK = 143;
        public static final int O = 43;
        public static final int P = 44;
        public static final int PAGE_DOWN = 93;
        public static final int PAGE_UP = 92;
        public static final int PAUSE = 121;
        public static final int PERIOD = 56;
        public static final int PICTSYMBOLS = 94;
        public static final int PLUS = 81;
        public static final int POUND = 18;
        public static final int POWER = 26;
        public static final int PRINT_SCREEN = 120;
        public static final int Q = 45;
        public static final int R = 46;
        public static final int RIGHT = 22;
        public static final int RIGHT_BRACKET = 72;
        public static final int S = 47;
        public static final int SCROLL_LOCK = 116;
        public static final int SEARCH = 84;
        public static final int SEMICOLON = 74;
        public static final int SHIFT_LEFT = 59;
        public static final int SHIFT_RIGHT = 60;
        public static final int SLASH = 76;
        public static final int SOFT_LEFT = 1;
        public static final int SOFT_RIGHT = 2;
        public static final int SPACE = 62;
        public static final int STAR = 17;
        public static final int SWITCH_CHARSET = 95;
        public static final int SYM = 63;
        public static final int T = 48;
        public static final int TAB = 61;
        public static final int U = 49;
        public static final int UNKNOWN = 0;
        public static final int UP = 19;
        public static final int V = 50;
        public static final int VOLUME_DOWN = 25;
        public static final int VOLUME_UP = 24;
        public static final int W = 51;
        public static final int X = 52;
        public static final int Y = 53;
        public static final int Z = 54;
        private static ObjectIntMap<String> keyNames;

        public static String toString(int keycode) {
            if (keycode < 0) {
                throw new IllegalArgumentException("keycode cannot be negative, keycode: " + keycode);
            } else if (keycode > 255) {
                throw new IllegalArgumentException("keycode cannot be greater than 255, keycode: " + keycode);
            } else if (keycode != 115) {
                if (keycode != 116) {
                    if (keycode != 120) {
                        if (keycode != 121) {
                            if (keycode != 123) {
                                if (keycode != 124) {
                                    if (keycode != 243) {
                                        switch (keycode) {
                                            case 0:
                                                return "Unknown";
                                            case 1:
                                                return "Soft Left";
                                            case 2:
                                                return "Soft Right";
                                            case 3:
                                                return "Home";
                                            case 4:
                                                return "Back";
                                            case 5:
                                                return "Call";
                                            case 6:
                                                return "End Call";
                                            case 7:
                                                return "0";
                                            case 8:
                                                return "1";
                                            case 9:
                                                return "2";
                                            case 10:
                                                return "3";
                                            case 11:
                                                return "4";
                                            case 12:
                                                return "5";
                                            case 13:
                                                return "6";
                                            case 14:
                                                return "7";
                                            case 15:
                                                return "8";
                                            case 16:
                                                return "9";
                                            case 17:
                                                return "*";
                                            case 18:
                                                return "#";
                                            case 19:
                                                return "Up";
                                            case 20:
                                                return "Down";
                                            case 21:
                                                return "Left";
                                            case 22:
                                                return "Right";
                                            case 23:
                                                return "Center";
                                            case 24:
                                                return "Volume Up";
                                            case VOLUME_DOWN /* 25 */:
                                                return "Volume Down";
                                            case POWER /* 26 */:
                                                return "Power";
                                            case CAMERA /* 27 */:
                                                return "Camera";
                                            case CLEAR /* 28 */:
                                                return "Clear";
                                            case A /* 29 */:
                                                return "A";
                                            case B /* 30 */:
                                                return "B";
                                            case C /* 31 */:
                                                return "C";
                                            case 32:
                                                return "D";
                                            case E /* 33 */:
                                                return "E";
                                            case F /* 34 */:
                                                return "F";
                                            case G /* 35 */:
                                                return "G";
                                            case H /* 36 */:
                                                return "H";
                                            case I /* 37 */:
                                                return "I";
                                            case J /* 38 */:
                                                return "J";
                                            case K /* 39 */:
                                                return "K";
                                            case L /* 40 */:
                                                return "L";
                                            case M /* 41 */:
                                                return "M";
                                            case N /* 42 */:
                                                return "N";
                                            case O /* 43 */:
                                                return "O";
                                            case P /* 44 */:
                                                return "P";
                                            case Q /* 45 */:
                                                return "Q";
                                            case R /* 46 */:
                                                return "R";
                                            case S /* 47 */:
                                                return "S";
                                            case T /* 48 */:
                                                return "T";
                                            case U /* 49 */:
                                                return "U";
                                            case 50:
                                                return "V";
                                            case W /* 51 */:
                                                return "W";
                                            case X /* 52 */:
                                                return "X";
                                            case Y /* 53 */:
                                                return "Y";
                                            case Z /* 54 */:
                                                return "Z";
                                            case COMMA /* 55 */:
                                                return ",";
                                            case PERIOD /* 56 */:
                                                return ".";
                                            case ALT_LEFT /* 57 */:
                                                return "L-Alt";
                                            case ALT_RIGHT /* 58 */:
                                                return "R-Alt";
                                            case SHIFT_LEFT /* 59 */:
                                                return "L-Shift";
                                            case SHIFT_RIGHT /* 60 */:
                                                return "R-Shift";
                                            case TAB /* 61 */:
                                                return "Tab";
                                            case SPACE /* 62 */:
                                                return "Space";
                                            case SYM /* 63 */:
                                                return "SYM";
                                            case 64:
                                                return "Explorer";
                                            case ENVELOPE /* 65 */:
                                                return "Envelope";
                                            case ENTER /* 66 */:
                                                return "Enter";
                                            case 67:
                                                return "Delete";
                                            case GRAVE /* 68 */:
                                                return "`";
                                            case MINUS /* 69 */:
                                                return "-";
                                            case EQUALS /* 70 */:
                                                return "=";
                                            case LEFT_BRACKET /* 71 */:
                                                return "[";
                                            case RIGHT_BRACKET /* 72 */:
                                                return "]";
                                            case BACKSLASH /* 73 */:
                                                return "\\";
                                            case SEMICOLON /* 74 */:
                                                return ";";
                                            case APOSTROPHE /* 75 */:
                                                return "'";
                                            case SLASH /* 76 */:
                                                return "/";
                                            case AT /* 77 */:
                                                return "@";
                                            case NUM /* 78 */:
                                                return "Num";
                                            case HEADSETHOOK /* 79 */:
                                                return "Headset Hook";
                                            case FOCUS /* 80 */:
                                                return "Focus";
                                            case PLUS /* 81 */:
                                                return "Plus";
                                            case MENU /* 82 */:
                                                return "Menu";
                                            case NOTIFICATION /* 83 */:
                                                return "Notification";
                                            case SEARCH /* 84 */:
                                                return "Search";
                                            case MEDIA_PLAY_PAUSE /* 85 */:
                                                return "Play/Pause";
                                            case MEDIA_STOP /* 86 */:
                                                return "Stop Media";
                                            case MEDIA_NEXT /* 87 */:
                                                return "Next Media";
                                            case MEDIA_PREVIOUS /* 88 */:
                                                return "Prev Media";
                                            case MEDIA_REWIND /* 89 */:
                                                return "Rewind";
                                            case MEDIA_FAST_FORWARD /* 90 */:
                                                return "Fast Forward";
                                            case MUTE /* 91 */:
                                                return "Mute";
                                            case PAGE_UP /* 92 */:
                                                return "Page Up";
                                            case PAGE_DOWN /* 93 */:
                                                return "Page Down";
                                            case PICTSYMBOLS /* 94 */:
                                                return "PICTSYMBOLS";
                                            case SWITCH_CHARSET /* 95 */:
                                                return "SWITCH_CHARSET";
                                            case BUTTON_A /* 96 */:
                                                return "A Button";
                                            case BUTTON_B /* 97 */:
                                                return "B Button";
                                            case BUTTON_C /* 98 */:
                                                return "C Button";
                                            case BUTTON_X /* 99 */:
                                                return "X Button";
                                            case 100:
                                                return "Y Button";
                                            case 101:
                                                return "Z Button";
                                            case 102:
                                                return "L1 Button";
                                            case BUTTON_R1 /* 103 */:
                                                return "R1 Button";
                                            case BUTTON_L2 /* 104 */:
                                                return "L2 Button";
                                            case BUTTON_R2 /* 105 */:
                                                return "R2 Button";
                                            case BUTTON_THUMBL /* 106 */:
                                                return "Left Thumb";
                                            case BUTTON_THUMBR /* 107 */:
                                                return "Right Thumb";
                                            case BUTTON_START /* 108 */:
                                                return "Start";
                                            case BUTTON_SELECT /* 109 */:
                                                return "Select";
                                            case BUTTON_MODE /* 110 */:
                                                return "Button Mode";
                                            case ESCAPE /* 111 */:
                                                return "Escape";
                                            case FORWARD_DEL /* 112 */:
                                                return "Forward Delete";
                                            default:
                                                switch (keycode) {
                                                    case CONTROL_LEFT /* 129 */:
                                                        return "L-Ctrl";
                                                    case 130:
                                                        return "R-Ctrl";
                                                    case F1 /* 131 */:
                                                        return "F1";
                                                    case F2 /* 132 */:
                                                        return "F2";
                                                    case F3 /* 133 */:
                                                        return "F3";
                                                    case F4 /* 134 */:
                                                        return "F4";
                                                    case F5 /* 135 */:
                                                        return "F5";
                                                    case F6 /* 136 */:
                                                        return "F6";
                                                    case F7 /* 137 */:
                                                        return "F7";
                                                    case F8 /* 138 */:
                                                        return "F8";
                                                    case F9 /* 139 */:
                                                        return "F9";
                                                    case F10 /* 140 */:
                                                        return "F10";
                                                    case F11 /* 141 */:
                                                        return "F11";
                                                    case F12 /* 142 */:
                                                        return "F12";
                                                    case NUM_LOCK /* 143 */:
                                                        return "Num Lock";
                                                    case NUMPAD_0 /* 144 */:
                                                        return "Numpad 0";
                                                    case NUMPAD_1 /* 145 */:
                                                        return "Numpad 1";
                                                    case NUMPAD_2 /* 146 */:
                                                        return "Numpad 2";
                                                    case NUMPAD_3 /* 147 */:
                                                        return "Numpad 3";
                                                    case NUMPAD_4 /* 148 */:
                                                        return "Numpad 4";
                                                    case NUMPAD_5 /* 149 */:
                                                        return "Numpad 5";
                                                    case NUMPAD_6 /* 150 */:
                                                        return "Numpad 6";
                                                    case NUMPAD_7 /* 151 */:
                                                        return "Numpad 7";
                                                    case NUMPAD_8 /* 152 */:
                                                        return "Numpad 8";
                                                    case NUMPAD_9 /* 153 */:
                                                        return "Numpad 9";
                                                    case NUMPAD_DIVIDE /* 154 */:
                                                        return "Num /";
                                                    case NUMPAD_MULTIPLY /* 155 */:
                                                        return "Num *";
                                                    case NUMPAD_SUBTRACT /* 156 */:
                                                        return "Num -";
                                                    case NUMPAD_ADD /* 157 */:
                                                        return "Num +";
                                                    case NUMPAD_DOT /* 158 */:
                                                        return "Num .";
                                                    case NUMPAD_COMMA /* 159 */:
                                                        return "Num ,";
                                                    case 160:
                                                        return "Num Enter";
                                                    case NUMPAD_EQUALS /* 161 */:
                                                        return "Num =";
                                                    case NUMPAD_LEFT_PAREN /* 162 */:
                                                        return "Num (";
                                                    case NUMPAD_RIGHT_PAREN /* 163 */:
                                                        return "Num )";
                                                    default:
                                                        switch (keycode) {
                                                            case F13 /* 183 */:
                                                                return "F13";
                                                            case F14 /* 184 */:
                                                                return "F14";
                                                            case F15 /* 185 */:
                                                                return "F15";
                                                            case F16 /* 186 */:
                                                                return "F16";
                                                            case F17 /* 187 */:
                                                                return "F17";
                                                            case F18 /* 188 */:
                                                                return "F18";
                                                            case F19 /* 189 */:
                                                                return "F19";
                                                            case F20 /* 190 */:
                                                                return "F20";
                                                            case F21 /* 191 */:
                                                                return "F21";
                                                            case F22 /* 192 */:
                                                                return "F22";
                                                            case F23 /* 193 */:
                                                                return "F23";
                                                            case F24 /* 194 */:
                                                                return "F24";
                                                            default:
                                                                return null;
                                                        }
                                                }
                                        }
                                    }
                                    return ":";
                                }
                                return "Insert";
                            }
                            return "End";
                        }
                        return "Pause";
                    }
                    return "Print";
                }
                return "Scroll Lock";
            } else {
                return "Caps Lock";
            }
        }

        public static int valueOf(String keyname) {
            if (keyNames == null) {
                initializeKeyNames();
            }
            return keyNames.get(keyname, -1);
        }

        private static void initializeKeyNames() {
            keyNames = new ObjectIntMap<>();
            for (int i = 0; i < 256; i++) {
                String name = toString(i);
                if (name != null) {
                    keyNames.put(name, i);
                }
            }
        }
    }
}