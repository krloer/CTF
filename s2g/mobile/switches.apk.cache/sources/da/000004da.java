package com.badlogic.gdx.utils.compression.lzma;

import com.badlogic.gdx.Input;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.utils.compression.lz.OutWindow;
import com.badlogic.gdx.utils.compression.rangecoder.BitTreeDecoder;
import java.io.IOException;
import kotlin.UByte;

/* loaded from: classes.dex */
public class Decoder {
    int m_PosStateMask;
    OutWindow m_OutWindow = new OutWindow();
    com.badlogic.gdx.utils.compression.rangecoder.Decoder m_RangeDecoder = new com.badlogic.gdx.utils.compression.rangecoder.Decoder();
    short[] m_IsMatchDecoders = new short[Input.Keys.F22];
    short[] m_IsRepDecoders = new short[12];
    short[] m_IsRepG0Decoders = new short[12];
    short[] m_IsRepG1Decoders = new short[12];
    short[] m_IsRepG2Decoders = new short[12];
    short[] m_IsRep0LongDecoders = new short[Input.Keys.F22];
    BitTreeDecoder[] m_PosSlotDecoder = new BitTreeDecoder[4];
    short[] m_PosDecoders = new short[114];
    BitTreeDecoder m_PosAlignDecoder = new BitTreeDecoder(4);
    LenDecoder m_LenDecoder = new LenDecoder();
    LenDecoder m_RepLenDecoder = new LenDecoder();
    LiteralDecoder m_LiteralDecoder = new LiteralDecoder();
    int m_DictionarySize = -1;
    int m_DictionarySizeCheck = -1;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class LenDecoder {
        short[] m_Choice = new short[2];
        BitTreeDecoder[] m_LowCoder = new BitTreeDecoder[16];
        BitTreeDecoder[] m_MidCoder = new BitTreeDecoder[16];
        BitTreeDecoder m_HighCoder = new BitTreeDecoder(8);
        int m_NumPosStates = 0;

        LenDecoder() {
        }

        public void Create(int numPosStates) {
            while (true) {
                int i = this.m_NumPosStates;
                if (i < numPosStates) {
                    this.m_LowCoder[i] = new BitTreeDecoder(3);
                    this.m_MidCoder[this.m_NumPosStates] = new BitTreeDecoder(3);
                    this.m_NumPosStates++;
                } else {
                    return;
                }
            }
        }

        public void Init() {
            com.badlogic.gdx.utils.compression.rangecoder.Decoder.InitBitModels(this.m_Choice);
            for (int posState = 0; posState < this.m_NumPosStates; posState++) {
                this.m_LowCoder[posState].Init();
                this.m_MidCoder[posState].Init();
            }
            this.m_HighCoder.Init();
        }

        public int Decode(com.badlogic.gdx.utils.compression.rangecoder.Decoder rangeDecoder, int posState) throws IOException {
            if (rangeDecoder.DecodeBit(this.m_Choice, 0) == 0) {
                return this.m_LowCoder[posState].Decode(rangeDecoder);
            }
            if (rangeDecoder.DecodeBit(this.m_Choice, 1) == 0) {
                int symbol = 8 + this.m_MidCoder[posState].Decode(rangeDecoder);
                return symbol;
            }
            int symbol2 = 8 + this.m_HighCoder.Decode(rangeDecoder) + 8;
            return symbol2;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class LiteralDecoder {
        Decoder2[] m_Coders;
        int m_NumPosBits;
        int m_NumPrevBits;
        int m_PosMask;

        /* JADX INFO: Access modifiers changed from: package-private */
        /* loaded from: classes.dex */
        public class Decoder2 {
            short[] m_Decoders = new short[GL20.GL_SRC_COLOR];

            Decoder2() {
            }

            public void Init() {
                com.badlogic.gdx.utils.compression.rangecoder.Decoder.InitBitModels(this.m_Decoders);
            }

            public byte DecodeNormal(com.badlogic.gdx.utils.compression.rangecoder.Decoder rangeDecoder) throws IOException {
                int symbol = 1;
                do {
                    symbol = (symbol << 1) | rangeDecoder.DecodeBit(this.m_Decoders, symbol);
                } while (symbol < 256);
                return (byte) symbol;
            }

            public byte DecodeWithMatchByte(com.badlogic.gdx.utils.compression.rangecoder.Decoder rangeDecoder, byte matchByte) throws IOException {
                int symbol = 1;
                while (true) {
                    int matchBit = (matchByte >> 7) & 1;
                    matchByte = (byte) (matchByte << 1);
                    int bit = rangeDecoder.DecodeBit(this.m_Decoders, ((matchBit + 1) << 8) + symbol);
                    symbol = (symbol << 1) | bit;
                    if (matchBit != bit) {
                        while (symbol < 256) {
                            symbol = (symbol << 1) | rangeDecoder.DecodeBit(this.m_Decoders, symbol);
                        }
                    } else if (symbol >= 256) {
                        break;
                    }
                }
                return (byte) symbol;
            }
        }

        LiteralDecoder() {
        }

        public void Create(int numPosBits, int numPrevBits) {
            if (this.m_Coders != null && this.m_NumPrevBits == numPrevBits && this.m_NumPosBits == numPosBits) {
                return;
            }
            this.m_NumPosBits = numPosBits;
            this.m_PosMask = (1 << numPosBits) - 1;
            this.m_NumPrevBits = numPrevBits;
            int numStates = 1 << (this.m_NumPrevBits + this.m_NumPosBits);
            this.m_Coders = new Decoder2[numStates];
            for (int i = 0; i < numStates; i++) {
                this.m_Coders[i] = new Decoder2();
            }
        }

        public void Init() {
            int numStates = 1 << (this.m_NumPrevBits + this.m_NumPosBits);
            for (int i = 0; i < numStates; i++) {
                this.m_Coders[i].Init();
            }
        }

        Decoder2 GetDecoder(int pos, byte prevByte) {
            Decoder2[] decoder2Arr = this.m_Coders;
            int i = this.m_NumPrevBits;
            return decoder2Arr[((this.m_PosMask & pos) << i) + ((prevByte & UByte.MAX_VALUE) >>> (8 - i))];
        }
    }

    public Decoder() {
        for (int i = 0; i < 4; i++) {
            this.m_PosSlotDecoder[i] = new BitTreeDecoder(6);
        }
    }

    boolean SetDictionarySize(int dictionarySize) {
        if (dictionarySize < 0) {
            return false;
        }
        if (this.m_DictionarySize != dictionarySize) {
            this.m_DictionarySize = dictionarySize;
            this.m_DictionarySizeCheck = Math.max(this.m_DictionarySize, 1);
            this.m_OutWindow.Create(Math.max(this.m_DictionarySizeCheck, 4096));
        }
        return true;
    }

    boolean SetLcLpPb(int lc, int lp, int pb) {
        if (lc > 8 || lp > 4 || pb > 4) {
            return false;
        }
        this.m_LiteralDecoder.Create(lp, lc);
        int numPosStates = 1 << pb;
        this.m_LenDecoder.Create(numPosStates);
        this.m_RepLenDecoder.Create(numPosStates);
        this.m_PosStateMask = numPosStates - 1;
        return true;
    }

    void Init() throws IOException {
        this.m_OutWindow.Init(false);
        com.badlogic.gdx.utils.compression.rangecoder.Decoder.InitBitModels(this.m_IsMatchDecoders);
        com.badlogic.gdx.utils.compression.rangecoder.Decoder.InitBitModels(this.m_IsRep0LongDecoders);
        com.badlogic.gdx.utils.compression.rangecoder.Decoder.InitBitModels(this.m_IsRepDecoders);
        com.badlogic.gdx.utils.compression.rangecoder.Decoder.InitBitModels(this.m_IsRepG0Decoders);
        com.badlogic.gdx.utils.compression.rangecoder.Decoder.InitBitModels(this.m_IsRepG1Decoders);
        com.badlogic.gdx.utils.compression.rangecoder.Decoder.InitBitModels(this.m_IsRepG2Decoders);
        com.badlogic.gdx.utils.compression.rangecoder.Decoder.InitBitModels(this.m_PosDecoders);
        this.m_LiteralDecoder.Init();
        for (int i = 0; i < 4; i++) {
            this.m_PosSlotDecoder[i].Init();
        }
        this.m_LenDecoder.Init();
        this.m_RepLenDecoder.Init();
        this.m_PosAlignDecoder.Init();
        this.m_RangeDecoder.Init();
    }

    /* JADX WARN: Code restructure failed: missing block: B:42:0x011f, code lost:
        r19.m_OutWindow.Flush();
        r19.m_OutWindow.ReleaseStream();
        r19.m_RangeDecoder.ReleaseStream();
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x012f, code lost:
        return true;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public boolean Code(java.io.InputStream r20, java.io.OutputStream r21, long r22) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 344
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.compression.lzma.Decoder.Code(java.io.InputStream, java.io.OutputStream, long):boolean");
    }

    public boolean SetDecoderProperties(byte[] properties) {
        if (properties.length < 5) {
            return false;
        }
        int val = properties[0] & UByte.MAX_VALUE;
        int lc = val % 9;
        int remainder = val / 9;
        int lp = remainder % 5;
        int pb = remainder / 5;
        int dictionarySize = 0;
        for (int i = 0; i < 4; i++) {
            dictionarySize += (properties[i + 1] & UByte.MAX_VALUE) << (i * 8);
        }
        if (SetLcLpPb(lc, lp, pb)) {
            return SetDictionarySize(dictionarySize);
        }
        return false;
    }
}