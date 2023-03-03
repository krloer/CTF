package com.badlogic.gdx.utils.compression.lzma;

import com.badlogic.gdx.Input;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.utils.compression.ICodeProgress;
import com.badlogic.gdx.utils.compression.lz.BinTree;
import com.badlogic.gdx.utils.compression.rangecoder.BitTreeEncoder;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import kotlin.UByte;

/* loaded from: classes.dex */
public class Encoder {
    public static final int EMatchFinderTypeBT2 = 0;
    public static final int EMatchFinderTypeBT4 = 1;
    static byte[] g_FastPos = new byte[2048];
    static final int kDefaultDictionaryLogSize = 22;
    static final int kIfinityPrice = 268435455;
    static final int kNumFastBytesDefault = 32;
    public static final int kNumLenSpecSymbols = 16;
    static final int kNumOpts = 4096;
    public static final int kPropSize = 5;
    int _additionalOffset;
    int _alignPriceCount;
    boolean _finished;
    InputStream _inStream;
    int _longestMatchLength;
    boolean _longestMatchWasFound;
    int _matchPriceCount;
    int _numDistancePairs;
    int _optimumCurrentIndex;
    int _optimumEndIndex;
    byte _previousByte;
    int backRes;
    long nowPos64;
    int _state = Base.StateInit();
    int[] _repDistances = new int[4];
    Optimal[] _optimum = new Optimal[4096];
    BinTree _matchFinder = null;
    com.badlogic.gdx.utils.compression.rangecoder.Encoder _rangeEncoder = new com.badlogic.gdx.utils.compression.rangecoder.Encoder();
    short[] _isMatch = new short[Input.Keys.F22];
    short[] _isRep = new short[12];
    short[] _isRepG0 = new short[12];
    short[] _isRepG1 = new short[12];
    short[] _isRepG2 = new short[12];
    short[] _isRep0Long = new short[Input.Keys.F22];
    BitTreeEncoder[] _posSlotEncoder = new BitTreeEncoder[4];
    short[] _posEncoders = new short[114];
    BitTreeEncoder _posAlignEncoder = new BitTreeEncoder(4);
    LenPriceTableEncoder _lenEncoder = new LenPriceTableEncoder();
    LenPriceTableEncoder _repMatchLenEncoder = new LenPriceTableEncoder();
    LiteralEncoder _literalEncoder = new LiteralEncoder();
    int[] _matchDistances = new int[548];
    int _numFastBytes = 32;
    int[] _posSlotPrices = new int[256];
    int[] _distancesPrices = new int[512];
    int[] _alignPrices = new int[16];
    int _distTableSize = 44;
    int _posStateBits = 2;
    int _posStateMask = 3;
    int _numLiteralPosStateBits = 0;
    int _numLiteralContextBits = 3;
    int _dictionarySize = 4194304;
    int _dictionarySizePrev = -1;
    int _numFastBytesPrev = -1;
    int _matchFinderType = 1;
    boolean _writeEndMark = false;
    boolean _needReleaseMFStream = false;
    int[] reps = new int[4];
    int[] repLens = new int[4];
    long[] processedInSize = new long[1];
    long[] processedOutSize = new long[1];
    boolean[] finished = new boolean[1];
    byte[] properties = new byte[5];
    int[] tempPrices = new int[128];

    static {
        int c = 2;
        byte[] bArr = g_FastPos;
        bArr[0] = 0;
        bArr[1] = 1;
        for (int slotFast = 2; slotFast < 22; slotFast++) {
            int k = 1 << ((slotFast >> 1) - 1);
            int j = 0;
            while (j < k) {
                g_FastPos[c] = (byte) slotFast;
                j++;
                c++;
            }
        }
    }

    static int GetPosSlot(int pos) {
        return pos < 2048 ? g_FastPos[pos] : pos < 2097152 ? g_FastPos[pos >> 10] + 20 : g_FastPos[pos >> 20] + 40;
    }

    static int GetPosSlot2(int pos) {
        return pos < 131072 ? g_FastPos[pos >> 6] + 12 : pos < 134217728 ? g_FastPos[pos >> 16] + 32 : g_FastPos[pos >> 26] + 52;
    }

    void BaseInit() {
        this._state = Base.StateInit();
        this._previousByte = (byte) 0;
        for (int i = 0; i < 4; i++) {
            this._repDistances[i] = 0;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class LiteralEncoder {
        Encoder2[] m_Coders;
        int m_NumPosBits;
        int m_NumPrevBits;
        int m_PosMask;

        /* JADX INFO: Access modifiers changed from: package-private */
        /* loaded from: classes.dex */
        public class Encoder2 {
            short[] m_Encoders = new short[GL20.GL_SRC_COLOR];

            Encoder2() {
            }

            public void Init() {
                com.badlogic.gdx.utils.compression.rangecoder.Encoder.InitBitModels(this.m_Encoders);
            }

            public void Encode(com.badlogic.gdx.utils.compression.rangecoder.Encoder rangeEncoder, byte symbol) throws IOException {
                int context = 1;
                for (int i = 7; i >= 0; i--) {
                    int bit = (symbol >> i) & 1;
                    rangeEncoder.Encode(this.m_Encoders, context, bit);
                    context = (context << 1) | bit;
                }
            }

            public void EncodeMatched(com.badlogic.gdx.utils.compression.rangecoder.Encoder rangeEncoder, byte matchByte, byte symbol) throws IOException {
                int context = 1;
                boolean same = true;
                for (int i = 7; i >= 0; i--) {
                    int bit = (symbol >> i) & 1;
                    int state = context;
                    if (same) {
                        int matchBit = (matchByte >> i) & 1;
                        state += (matchBit + 1) << 8;
                        same = matchBit == bit;
                    }
                    rangeEncoder.Encode(this.m_Encoders, state, bit);
                    context = (context << 1) | bit;
                }
            }

            public int GetPrice(boolean matchMode, byte matchByte, byte symbol) {
                int price = 0;
                int context = 1;
                int i = 7;
                if (matchMode) {
                    while (true) {
                        if (i < 0) {
                            break;
                        }
                        int matchBit = (matchByte >> i) & 1;
                        int bit = (symbol >> i) & 1;
                        price += com.badlogic.gdx.utils.compression.rangecoder.Encoder.GetPrice(this.m_Encoders[((matchBit + 1) << 8) + context], bit);
                        context = (context << 1) | bit;
                        if (matchBit == bit) {
                            i--;
                        } else {
                            i--;
                            break;
                        }
                    }
                }
                while (i >= 0) {
                    int bit2 = (symbol >> i) & 1;
                    price += com.badlogic.gdx.utils.compression.rangecoder.Encoder.GetPrice(this.m_Encoders[context], bit2);
                    context = (context << 1) | bit2;
                    i--;
                }
                return price;
            }
        }

        LiteralEncoder() {
        }

        public void Create(int numPosBits, int numPrevBits) {
            if (this.m_Coders != null && this.m_NumPrevBits == numPrevBits && this.m_NumPosBits == numPosBits) {
                return;
            }
            this.m_NumPosBits = numPosBits;
            this.m_PosMask = (1 << numPosBits) - 1;
            this.m_NumPrevBits = numPrevBits;
            int numStates = 1 << (this.m_NumPrevBits + this.m_NumPosBits);
            this.m_Coders = new Encoder2[numStates];
            for (int i = 0; i < numStates; i++) {
                this.m_Coders[i] = new Encoder2();
            }
        }

        public void Init() {
            int numStates = 1 << (this.m_NumPrevBits + this.m_NumPosBits);
            for (int i = 0; i < numStates; i++) {
                this.m_Coders[i].Init();
            }
        }

        public Encoder2 GetSubCoder(int pos, byte prevByte) {
            Encoder2[] encoder2Arr = this.m_Coders;
            int i = this.m_NumPrevBits;
            return encoder2Arr[((this.m_PosMask & pos) << i) + ((prevByte & UByte.MAX_VALUE) >>> (8 - i))];
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class LenEncoder {
        short[] _choice = new short[2];
        BitTreeEncoder[] _lowCoder = new BitTreeEncoder[16];
        BitTreeEncoder[] _midCoder = new BitTreeEncoder[16];
        BitTreeEncoder _highCoder = new BitTreeEncoder(8);

        public LenEncoder() {
            for (int posState = 0; posState < 16; posState++) {
                this._lowCoder[posState] = new BitTreeEncoder(3);
                this._midCoder[posState] = new BitTreeEncoder(3);
            }
        }

        public void Init(int numPosStates) {
            com.badlogic.gdx.utils.compression.rangecoder.Encoder.InitBitModels(this._choice);
            for (int posState = 0; posState < numPosStates; posState++) {
                this._lowCoder[posState].Init();
                this._midCoder[posState].Init();
            }
            this._highCoder.Init();
        }

        public void Encode(com.badlogic.gdx.utils.compression.rangecoder.Encoder rangeEncoder, int symbol, int posState) throws IOException {
            if (symbol < 8) {
                rangeEncoder.Encode(this._choice, 0, 0);
                this._lowCoder[posState].Encode(rangeEncoder, symbol);
                return;
            }
            int symbol2 = symbol - 8;
            rangeEncoder.Encode(this._choice, 0, 1);
            if (symbol2 < 8) {
                rangeEncoder.Encode(this._choice, 1, 0);
                this._midCoder[posState].Encode(rangeEncoder, symbol2);
                return;
            }
            rangeEncoder.Encode(this._choice, 1, 1);
            this._highCoder.Encode(rangeEncoder, symbol2 - 8);
        }

        public void SetPrices(int posState, int numSymbols, int[] prices, int st) {
            int a0 = com.badlogic.gdx.utils.compression.rangecoder.Encoder.GetPrice0(this._choice[0]);
            int a1 = com.badlogic.gdx.utils.compression.rangecoder.Encoder.GetPrice1(this._choice[0]);
            int b0 = com.badlogic.gdx.utils.compression.rangecoder.Encoder.GetPrice0(this._choice[1]) + a1;
            int b1 = com.badlogic.gdx.utils.compression.rangecoder.Encoder.GetPrice1(this._choice[1]) + a1;
            int i = 0;
            while (i < 8) {
                if (i >= numSymbols) {
                    return;
                }
                prices[st + i] = this._lowCoder[posState].GetPrice(i) + a0;
                i++;
            }
            while (i < 16) {
                if (i >= numSymbols) {
                    return;
                }
                prices[st + i] = this._midCoder[posState].GetPrice(i - 8) + b0;
                i++;
            }
            while (i < numSymbols) {
                prices[st + i] = this._highCoder.GetPrice((i - 8) - 8) + b1;
                i++;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class LenPriceTableEncoder extends LenEncoder {
        int[] _counters;
        int[] _prices;
        int _tableSize;

        LenPriceTableEncoder() {
            super();
            this._prices = new int[GL20.GL_DONT_CARE];
            this._counters = new int[16];
        }

        public void SetTableSize(int tableSize) {
            this._tableSize = tableSize;
        }

        public int GetPrice(int symbol, int posState) {
            return this._prices[(posState * Base.kNumLenSymbols) + symbol];
        }

        void UpdateTable(int posState) {
            SetPrices(posState, this._tableSize, this._prices, posState * Base.kNumLenSymbols);
            this._counters[posState] = this._tableSize;
        }

        public void UpdateTables(int numPosStates) {
            for (int posState = 0; posState < numPosStates; posState++) {
                UpdateTable(posState);
            }
        }

        @Override // com.badlogic.gdx.utils.compression.lzma.Encoder.LenEncoder
        public void Encode(com.badlogic.gdx.utils.compression.rangecoder.Encoder rangeEncoder, int symbol, int posState) throws IOException {
            super.Encode(rangeEncoder, symbol, posState);
            int[] iArr = this._counters;
            int i = iArr[posState] - 1;
            iArr[posState] = i;
            if (i == 0) {
                UpdateTable(posState);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class Optimal {
        public int BackPrev;
        public int BackPrev2;
        public int Backs0;
        public int Backs1;
        public int Backs2;
        public int Backs3;
        public int PosPrev;
        public int PosPrev2;
        public boolean Prev1IsChar;
        public boolean Prev2;
        public int Price;
        public int State;

        Optimal() {
        }

        public void MakeAsChar() {
            this.BackPrev = -1;
            this.Prev1IsChar = false;
        }

        public void MakeAsShortRep() {
            this.BackPrev = 0;
            this.Prev1IsChar = false;
        }

        public boolean IsShortRep() {
            return this.BackPrev == 0;
        }
    }

    void Create() {
        if (this._matchFinder == null) {
            BinTree bt = new BinTree();
            int numHashBytes = this._matchFinderType == 0 ? 2 : 4;
            bt.SetType(numHashBytes);
            this._matchFinder = bt;
        }
        this._literalEncoder.Create(this._numLiteralPosStateBits, this._numLiteralContextBits);
        if (this._dictionarySize == this._dictionarySizePrev && this._numFastBytesPrev == this._numFastBytes) {
            return;
        }
        this._matchFinder.Create(this._dictionarySize, 4096, this._numFastBytes, 274);
        this._dictionarySizePrev = this._dictionarySize;
        this._numFastBytesPrev = this._numFastBytes;
    }

    public Encoder() {
        for (int i = 0; i < 4096; i++) {
            this._optimum[i] = new Optimal();
        }
        for (int i2 = 0; i2 < 4; i2++) {
            this._posSlotEncoder[i2] = new BitTreeEncoder(6);
        }
    }

    void SetWriteEndMarkerMode(boolean writeEndMarker) {
        this._writeEndMark = writeEndMarker;
    }

    void Init() {
        BaseInit();
        this._rangeEncoder.Init();
        com.badlogic.gdx.utils.compression.rangecoder.Encoder.InitBitModels(this._isMatch);
        com.badlogic.gdx.utils.compression.rangecoder.Encoder.InitBitModels(this._isRep0Long);
        com.badlogic.gdx.utils.compression.rangecoder.Encoder.InitBitModels(this._isRep);
        com.badlogic.gdx.utils.compression.rangecoder.Encoder.InitBitModels(this._isRepG0);
        com.badlogic.gdx.utils.compression.rangecoder.Encoder.InitBitModels(this._isRepG1);
        com.badlogic.gdx.utils.compression.rangecoder.Encoder.InitBitModels(this._isRepG2);
        com.badlogic.gdx.utils.compression.rangecoder.Encoder.InitBitModels(this._posEncoders);
        this._literalEncoder.Init();
        for (int i = 0; i < 4; i++) {
            this._posSlotEncoder[i].Init();
        }
        this._lenEncoder.Init(1 << this._posStateBits);
        this._repMatchLenEncoder.Init(1 << this._posStateBits);
        this._posAlignEncoder.Init();
        this._longestMatchWasFound = false;
        this._optimumEndIndex = 0;
        this._optimumCurrentIndex = 0;
        this._additionalOffset = 0;
    }

    int ReadMatchDistances() throws IOException {
        int[] iArr;
        int lenRes = 0;
        this._numDistancePairs = this._matchFinder.GetMatches(this._matchDistances);
        int i = this._numDistancePairs;
        if (i > 0 && (lenRes = (iArr = this._matchDistances)[i - 2]) == this._numFastBytes) {
            lenRes += this._matchFinder.GetMatchLen(lenRes - 1, iArr[i - 1], 273 - lenRes);
        }
        this._additionalOffset++;
        return lenRes;
    }

    void MovePos(int num) throws IOException {
        if (num > 0) {
            this._matchFinder.Skip(num);
            this._additionalOffset += num;
        }
    }

    int GetRepLen1Price(int state, int posState) {
        return com.badlogic.gdx.utils.compression.rangecoder.Encoder.GetPrice0(this._isRepG0[state]) + com.badlogic.gdx.utils.compression.rangecoder.Encoder.GetPrice0(this._isRep0Long[(state << 4) + posState]);
    }

    int GetPureRepPrice(int repIndex, int state, int posState) {
        if (repIndex == 0) {
            return com.badlogic.gdx.utils.compression.rangecoder.Encoder.GetPrice0(this._isRepG0[state]) + com.badlogic.gdx.utils.compression.rangecoder.Encoder.GetPrice1(this._isRep0Long[(state << 4) + posState]);
        }
        int price = com.badlogic.gdx.utils.compression.rangecoder.Encoder.GetPrice1(this._isRepG0[state]);
        if (repIndex == 1) {
            return price + com.badlogic.gdx.utils.compression.rangecoder.Encoder.GetPrice0(this._isRepG1[state]);
        }
        return price + com.badlogic.gdx.utils.compression.rangecoder.Encoder.GetPrice1(this._isRepG1[state]) + com.badlogic.gdx.utils.compression.rangecoder.Encoder.GetPrice(this._isRepG2[state], repIndex - 2);
    }

    int GetRepPrice(int repIndex, int len, int state, int posState) {
        int price = this._repMatchLenEncoder.GetPrice(len - 2, posState);
        return GetPureRepPrice(repIndex, state, posState) + price;
    }

    int GetPosLenPrice(int pos, int len, int posState) {
        int price;
        int lenToPosState = Base.GetLenToPosState(len);
        if (pos < 128) {
            price = this._distancesPrices[(lenToPosState * 128) + pos];
        } else {
            price = this._posSlotPrices[(lenToPosState << 6) + GetPosSlot2(pos)] + this._alignPrices[pos & 15];
        }
        return this._lenEncoder.GetPrice(len - 2, posState) + price;
    }

    int Backward(int cur) {
        Optimal[] optimalArr;
        this._optimumEndIndex = cur;
        int posMem = this._optimum[cur].PosPrev;
        int backMem = this._optimum[cur].BackPrev;
        do {
            if (this._optimum[cur].Prev1IsChar) {
                this._optimum[posMem].MakeAsChar();
                Optimal[] optimalArr2 = this._optimum;
                optimalArr2[posMem].PosPrev = posMem - 1;
                if (optimalArr2[cur].Prev2) {
                    Optimal[] optimalArr3 = this._optimum;
                    optimalArr3[posMem - 1].Prev1IsChar = false;
                    optimalArr3[posMem - 1].PosPrev = optimalArr3[cur].PosPrev2;
                    Optimal[] optimalArr4 = this._optimum;
                    optimalArr4[posMem - 1].BackPrev = optimalArr4[cur].BackPrev2;
                }
            }
            int posPrev = posMem;
            int backCur = backMem;
            backMem = this._optimum[posPrev].BackPrev;
            posMem = this._optimum[posPrev].PosPrev;
            optimalArr = this._optimum;
            optimalArr[posPrev].BackPrev = backCur;
            optimalArr[posPrev].PosPrev = cur;
            cur = posPrev;
        } while (cur > 0);
        this.backRes = optimalArr[0].BackPrev;
        this._optimumCurrentIndex = this._optimum[0].PosPrev;
        return this._optimumCurrentIndex;
    }

    /* JADX WARN: Removed duplicated region for block: B:247:0x07db  */
    /* JADX WARN: Removed duplicated region for block: B:286:0x07d6 A[EDGE_INSN: B:286:0x07d6->B:246:0x07d6 ?: BREAK  , SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    int GetOptimum(int r46) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 2099
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.compression.lzma.Encoder.GetOptimum(int):int");
    }

    boolean ChangePair(int smallDist, int bigDist) {
        return smallDist < (1 << (32 - 7)) && bigDist >= (smallDist << 7);
    }

    void WriteEndMarker(int posState) throws IOException {
        if (this._writeEndMark) {
            this._rangeEncoder.Encode(this._isMatch, (this._state << 4) + posState, 1);
            this._rangeEncoder.Encode(this._isRep, this._state, 0);
            this._state = Base.StateUpdateMatch(this._state);
            this._lenEncoder.Encode(this._rangeEncoder, 2 - 2, posState);
            int lenToPosState = Base.GetLenToPosState(2);
            this._posSlotEncoder[lenToPosState].Encode(this._rangeEncoder, 63);
            int posReduced = (1 << 30) - 1;
            this._rangeEncoder.EncodeDirectBits(posReduced >> 4, 30 - 4);
            this._posAlignEncoder.ReverseEncode(this._rangeEncoder, posReduced & 15);
        }
    }

    void Flush(int nowPos) throws IOException {
        ReleaseMFStream();
        WriteEndMarker(this._posStateMask & nowPos);
        this._rangeEncoder.FlushData();
        this._rangeEncoder.FlushStream();
    }

    public void CodeOneBlock(long[] inSize, long[] outSize, boolean[] finished) throws IOException {
        int i = 0;
        inSize[0] = 0;
        outSize[0] = 0;
        finished[0] = true;
        InputStream inputStream = this._inStream;
        if (inputStream != null) {
            this._matchFinder.SetStream(inputStream);
            this._matchFinder.Init();
            this._needReleaseMFStream = true;
            this._inStream = null;
        }
        if (this._finished) {
            return;
        }
        this._finished = true;
        long progressPosValuePrev = this.nowPos64;
        int i2 = 4;
        if (this.nowPos64 == 0) {
            if (this._matchFinder.GetNumAvailableBytes() == 0) {
                Flush((int) this.nowPos64);
                return;
            }
            ReadMatchDistances();
            this._rangeEncoder.Encode(this._isMatch, (this._state << 4) + (this._posStateMask & ((int) this.nowPos64)), 0);
            this._state = Base.StateUpdateChar(this._state);
            byte curByte = this._matchFinder.GetIndexByte(0 - this._additionalOffset);
            this._literalEncoder.GetSubCoder((int) this.nowPos64, this._previousByte).Encode(this._rangeEncoder, curByte);
            this._previousByte = curByte;
            this._additionalOffset--;
            this.nowPos64++;
        }
        if (this._matchFinder.GetNumAvailableBytes() == 0) {
            Flush((int) this.nowPos64);
            return;
        }
        while (true) {
            int len = GetOptimum((int) this.nowPos64);
            int pos = this.backRes;
            int posState = this._posStateMask & ((int) this.nowPos64);
            int complexState = (this._state << i2) + posState;
            if (len == 1 && pos == -1) {
                this._rangeEncoder.Encode(this._isMatch, complexState, i);
                byte curByte2 = this._matchFinder.GetIndexByte(0 - this._additionalOffset);
                LiteralEncoder.Encoder2 subCoder = this._literalEncoder.GetSubCoder((int) this.nowPos64, this._previousByte);
                if (!Base.StateIsCharState(this._state)) {
                    byte matchByte = this._matchFinder.GetIndexByte(((0 - this._repDistances[i]) - 1) - this._additionalOffset);
                    subCoder.EncodeMatched(this._rangeEncoder, matchByte, curByte2);
                } else {
                    subCoder.Encode(this._rangeEncoder, curByte2);
                }
                this._previousByte = curByte2;
                this._state = Base.StateUpdateChar(this._state);
            } else {
                this._rangeEncoder.Encode(this._isMatch, complexState, 1);
                if (pos >= i2) {
                    this._rangeEncoder.Encode(this._isRep, this._state, i);
                    this._state = Base.StateUpdateMatch(this._state);
                    this._lenEncoder.Encode(this._rangeEncoder, len - 2, posState);
                    int pos2 = pos - 4;
                    int posSlot = GetPosSlot(pos2);
                    int lenToPosState = Base.GetLenToPosState(len);
                    this._posSlotEncoder[lenToPosState].Encode(this._rangeEncoder, posSlot);
                    if (posSlot >= i2) {
                        int footerBits = (posSlot >> 1) - 1;
                        int baseVal = ((posSlot & 1) | 2) << footerBits;
                        int posReduced = pos2 - baseVal;
                        if (posSlot < 14) {
                            BitTreeEncoder.ReverseEncode(this._posEncoders, (baseVal - posSlot) - 1, this._rangeEncoder, footerBits, posReduced);
                        } else {
                            this._rangeEncoder.EncodeDirectBits(posReduced >> 4, footerBits - 4);
                            this._posAlignEncoder.ReverseEncode(this._rangeEncoder, posReduced & 15);
                            this._alignPriceCount++;
                        }
                    }
                    for (int i3 = 3; i3 >= 1; i3--) {
                        int[] iArr = this._repDistances;
                        iArr[i3] = iArr[i3 - 1];
                    }
                    this._repDistances[0] = pos2;
                    this._matchPriceCount++;
                } else {
                    this._rangeEncoder.Encode(this._isRep, this._state, 1);
                    if (pos == 0) {
                        this._rangeEncoder.Encode(this._isRepG0, this._state, i);
                        if (len == 1) {
                            this._rangeEncoder.Encode(this._isRep0Long, complexState, i);
                        } else {
                            this._rangeEncoder.Encode(this._isRep0Long, complexState, 1);
                        }
                    } else {
                        this._rangeEncoder.Encode(this._isRepG0, this._state, 1);
                        if (pos == 1) {
                            this._rangeEncoder.Encode(this._isRepG1, this._state, i);
                        } else {
                            this._rangeEncoder.Encode(this._isRepG1, this._state, 1);
                            this._rangeEncoder.Encode(this._isRepG2, this._state, pos - 2);
                        }
                    }
                    if (len == 1) {
                        this._state = Base.StateUpdateShortRep(this._state);
                    } else {
                        this._repMatchLenEncoder.Encode(this._rangeEncoder, len - 2, posState);
                        this._state = Base.StateUpdateRep(this._state);
                    }
                    int distance = this._repDistances[pos];
                    if (pos != 0) {
                        for (int i4 = pos; i4 >= 1; i4--) {
                            int[] iArr2 = this._repDistances;
                            iArr2[i4] = iArr2[i4 - 1];
                        }
                        this._repDistances[i] = distance;
                    }
                }
                this._previousByte = this._matchFinder.GetIndexByte((len - 1) - this._additionalOffset);
            }
            this._additionalOffset -= len;
            this.nowPos64 += len;
            if (this._additionalOffset == 0) {
                if (this._matchPriceCount >= 128) {
                    FillDistancesPrices();
                }
                if (this._alignPriceCount >= 16) {
                    FillAlignPrices();
                }
                inSize[0] = this.nowPos64;
                outSize[0] = this._rangeEncoder.GetProcessedSizeAdd();
                if (this._matchFinder.GetNumAvailableBytes() == 0) {
                    Flush((int) this.nowPos64);
                    return;
                } else if (this.nowPos64 - progressPosValuePrev >= 4096) {
                    this._finished = false;
                    finished[0] = false;
                    return;
                }
            }
            i = 0;
            i2 = 4;
        }
    }

    void ReleaseMFStream() {
        BinTree binTree = this._matchFinder;
        if (binTree != null && this._needReleaseMFStream) {
            binTree.ReleaseStream();
            this._needReleaseMFStream = false;
        }
    }

    void SetOutStream(OutputStream outStream) {
        this._rangeEncoder.SetStream(outStream);
    }

    void ReleaseOutStream() {
        this._rangeEncoder.ReleaseStream();
    }

    void ReleaseStreams() {
        ReleaseMFStream();
        ReleaseOutStream();
    }

    void SetStreams(InputStream inStream, OutputStream outStream, long inSize, long outSize) {
        this._inStream = inStream;
        this._finished = false;
        Create();
        SetOutStream(outStream);
        Init();
        FillDistancesPrices();
        FillAlignPrices();
        this._lenEncoder.SetTableSize((this._numFastBytes + 1) - 2);
        this._lenEncoder.UpdateTables(1 << this._posStateBits);
        this._repMatchLenEncoder.SetTableSize((this._numFastBytes + 1) - 2);
        this._repMatchLenEncoder.UpdateTables(1 << this._posStateBits);
        this.nowPos64 = 0L;
    }

    public void Code(InputStream inStream, OutputStream outStream, long inSize, long outSize, ICodeProgress progress) throws IOException {
        this._needReleaseMFStream = false;
        try {
            SetStreams(inStream, outStream, inSize, outSize);
            while (true) {
                CodeOneBlock(this.processedInSize, this.processedOutSize, this.finished);
                if (this.finished[0]) {
                    return;
                }
                if (progress != null) {
                    progress.SetProgress(this.processedInSize[0], this.processedOutSize[0]);
                }
            }
        } finally {
            ReleaseStreams();
        }
    }

    public void WriteCoderProperties(OutputStream outStream) throws IOException {
        this.properties[0] = (byte) ((((this._posStateBits * 5) + this._numLiteralPosStateBits) * 9) + this._numLiteralContextBits);
        for (int i = 0; i < 4; i++) {
            this.properties[i + 1] = (byte) (this._dictionarySize >> (i * 8));
        }
        outStream.write(this.properties, 0, 5);
    }

    void FillDistancesPrices() {
        for (int i = 4; i < 128; i++) {
            int posSlot = GetPosSlot(i);
            int footerBits = (posSlot >> 1) - 1;
            int baseVal = ((posSlot & 1) | 2) << footerBits;
            this.tempPrices[i] = BitTreeEncoder.ReverseGetPrice(this._posEncoders, (baseVal - posSlot) - 1, footerBits, i - baseVal);
        }
        for (int lenToPosState = 0; lenToPosState < 4; lenToPosState++) {
            BitTreeEncoder encoder = this._posSlotEncoder[lenToPosState];
            int st = lenToPosState << 6;
            for (int posSlot2 = 0; posSlot2 < this._distTableSize; posSlot2++) {
                this._posSlotPrices[st + posSlot2] = encoder.GetPrice(posSlot2);
            }
            for (int posSlot3 = 14; posSlot3 < this._distTableSize; posSlot3++) {
                int[] iArr = this._posSlotPrices;
                int i2 = st + posSlot3;
                iArr[i2] = iArr[i2] + ((((posSlot3 >> 1) - 1) - 4) << 6);
            }
            int st2 = lenToPosState * 128;
            int i3 = 0;
            while (i3 < 4) {
                this._distancesPrices[st2 + i3] = this._posSlotPrices[st + i3];
                i3++;
            }
            while (i3 < 128) {
                this._distancesPrices[st2 + i3] = this._posSlotPrices[GetPosSlot(i3) + st] + this.tempPrices[i3];
                i3++;
            }
        }
        this._matchPriceCount = 0;
    }

    void FillAlignPrices() {
        for (int i = 0; i < 16; i++) {
            this._alignPrices[i] = this._posAlignEncoder.ReverseGetPrice(i);
        }
        this._alignPriceCount = 0;
    }

    public boolean SetAlgorithm(int algorithm) {
        return true;
    }

    public boolean SetDictionarySize(int dictionarySize) {
        if (dictionarySize < 1 || dictionarySize > (1 << 29)) {
            return false;
        }
        this._dictionarySize = dictionarySize;
        int dicLogSize = 0;
        while (dictionarySize > (1 << dicLogSize)) {
            dicLogSize++;
        }
        this._distTableSize = dicLogSize * 2;
        return true;
    }

    public boolean SetNumFastBytes(int numFastBytes) {
        if (numFastBytes < 5 || numFastBytes > 273) {
            return false;
        }
        this._numFastBytes = numFastBytes;
        return true;
    }

    public boolean SetMatchFinder(int matchFinderIndex) {
        if (matchFinderIndex < 0 || matchFinderIndex > 2) {
            return false;
        }
        int matchFinderIndexPrev = this._matchFinderType;
        this._matchFinderType = matchFinderIndex;
        if (this._matchFinder != null && matchFinderIndexPrev != this._matchFinderType) {
            this._dictionarySizePrev = -1;
            this._matchFinder = null;
            return true;
        }
        return true;
    }

    public boolean SetLcLpPb(int lc, int lp, int pb) {
        if (lp < 0 || lp > 4 || lc < 0 || lc > 8 || pb < 0 || pb > 4) {
            return false;
        }
        this._numLiteralPosStateBits = lp;
        this._numLiteralContextBits = lc;
        this._posStateBits = pb;
        this._posStateMask = (1 << this._posStateBits) - 1;
        return true;
    }

    public void SetEndMarkerMode(boolean endMarkerMode) {
        this._writeEndMark = endMarkerMode;
    }
}