package com.badlogic.gdx.utils.compression.lz;

import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.g3d.utils.MeshBuilder;
import java.io.IOException;
import kotlin.UByte;

/* loaded from: classes.dex */
public class BinTree extends InWindow {
    private static final int[] CrcTable = new int[256];
    static final int kBT2HashSize = 65536;
    static final int kEmptyHashValue = 0;
    static final int kHash2Size = 1024;
    static final int kHash3Offset = 1024;
    static final int kHash3Size = 65536;
    static final int kMaxValForNormalize = 1073741823;
    static final int kStartMaxLen = 1;
    int _cyclicBufferPos;
    int[] _hash;
    int _hashMask;
    int _matchMaxLen;
    int[] _son;
    int _cyclicBufferSize = 0;
    int _cutValue = 255;
    int _hashSizeSum = 0;
    boolean HASH_ARRAY = true;
    int kNumHashDirectBytes = 0;
    int kMinMatchCheck = 4;
    int kFixHashSize = 66560;

    public void SetType(int numHashBytes) {
        this.HASH_ARRAY = numHashBytes > 2;
        if (this.HASH_ARRAY) {
            this.kNumHashDirectBytes = 0;
            this.kMinMatchCheck = 4;
            this.kFixHashSize = 66560;
            return;
        }
        this.kNumHashDirectBytes = 2;
        this.kMinMatchCheck = 3;
        this.kFixHashSize = 0;
    }

    @Override // com.badlogic.gdx.utils.compression.lz.InWindow
    public void Init() throws IOException {
        super.Init();
        for (int i = 0; i < this._hashSizeSum; i++) {
            this._hash[i] = 0;
        }
        this._cyclicBufferPos = 0;
        ReduceOffsets(-1);
    }

    @Override // com.badlogic.gdx.utils.compression.lz.InWindow
    public void MovePos() throws IOException {
        int i = this._cyclicBufferPos + 1;
        this._cyclicBufferPos = i;
        if (i >= this._cyclicBufferSize) {
            this._cyclicBufferPos = 0;
        }
        super.MovePos();
        if (this._pos == kMaxValForNormalize) {
            Normalize();
        }
    }

    public boolean Create(int historySize, int keepAddBufferBefore, int matchMaxLen, int keepAddBufferAfter) {
        if (historySize > 1073741567) {
            return false;
        }
        this._cutValue = (matchMaxLen >> 1) + 16;
        int windowReservSize = ((((historySize + keepAddBufferBefore) + matchMaxLen) + keepAddBufferAfter) / 2) + 256;
        super.Create(historySize + keepAddBufferBefore, matchMaxLen + keepAddBufferAfter, windowReservSize);
        this._matchMaxLen = matchMaxLen;
        int cyclicBufferSize = historySize + 1;
        if (this._cyclicBufferSize != cyclicBufferSize) {
            this._cyclicBufferSize = cyclicBufferSize;
            this._son = new int[cyclicBufferSize * 2];
        }
        int hs = MeshBuilder.MAX_VERTICES;
        if (this.HASH_ARRAY) {
            int hs2 = historySize - 1;
            int hs3 = hs2 | (hs2 >> 1);
            int hs4 = hs3 | (hs3 >> 2);
            int hs5 = hs4 | (hs4 >> 4);
            int hs6 = ((hs5 | (hs5 >> 8)) >> 1) | MeshBuilder.MAX_INDEX;
            if (hs6 > 16777216) {
                hs6 >>= 1;
            }
            this._hashMask = hs6;
            hs = hs6 + 1 + this.kFixHashSize;
        }
        if (hs != this._hashSizeSum) {
            this._hashSizeSum = hs;
            this._hash = new int[hs];
        }
        return true;
    }

    public int GetMatches(int[] distances) throws IOException {
        int lenLimit;
        int temp;
        int maxLen;
        int count;
        int hash2Value;
        int i;
        int count2;
        int len;
        int curMatch;
        if (this._pos + this._matchMaxLen > this._streamPos) {
            lenLimit = this._streamPos - this._pos;
            if (lenLimit < this.kMinMatchCheck) {
                MovePos();
                return 0;
            }
        } else {
            lenLimit = this._matchMaxLen;
        }
        int offset = 0;
        int matchMinPos = this._pos > this._cyclicBufferSize ? this._pos - this._cyclicBufferSize : 0;
        int cur = this._bufferOffset + this._pos;
        int maxLen2 = 1;
        int hash2Value2 = 0;
        int hash3Value = 0;
        if (this.HASH_ARRAY) {
            int temp2 = CrcTable[this._bufferBase[cur] & UByte.MAX_VALUE] ^ (this._bufferBase[cur + 1] & UByte.MAX_VALUE);
            hash2Value2 = temp2 & 1023;
            int temp3 = temp2 ^ ((this._bufferBase[cur + 2] & UByte.MAX_VALUE) << 8);
            hash3Value = temp3 & MeshBuilder.MAX_INDEX;
            temp = ((CrcTable[this._bufferBase[cur + 3] & UByte.MAX_VALUE] << 5) ^ temp3) & this._hashMask;
        } else {
            temp = (this._bufferBase[cur] & UByte.MAX_VALUE) ^ ((this._bufferBase[cur + 1] & UByte.MAX_VALUE) << 8);
        }
        int[] iArr = this._hash;
        int curMatch2 = iArr[this.kFixHashSize + temp];
        if (this.HASH_ARRAY) {
            int curMatch22 = iArr[hash2Value2];
            int curMatch3 = iArr[hash3Value + GL20.GL_STENCIL_BUFFER_BIT];
            iArr[hash2Value2] = this._pos;
            this._hash[hash3Value + GL20.GL_STENCIL_BUFFER_BIT] = this._pos;
            if (curMatch22 > matchMinPos && this._bufferBase[this._bufferOffset + curMatch22] == this._bufferBase[cur]) {
                int offset2 = 0 + 1;
                maxLen2 = 2;
                distances[0] = 2;
                offset = offset2 + 1;
                distances[offset2] = (this._pos - curMatch22) - 1;
            }
            if (curMatch3 > matchMinPos && this._bufferBase[this._bufferOffset + curMatch3] == this._bufferBase[cur]) {
                if (curMatch3 == curMatch22) {
                    offset -= 2;
                }
                int offset3 = offset + 1;
                maxLen2 = 3;
                distances[offset] = 3;
                offset = offset3 + 1;
                distances[offset3] = (this._pos - curMatch3) - 1;
                curMatch22 = curMatch3;
            }
            if (offset != 0 && curMatch22 == curMatch2) {
                offset -= 2;
                maxLen2 = 1;
            }
        }
        this._hash[this.kFixHashSize + temp] = this._pos;
        int i2 = this._cyclicBufferPos;
        int ptr0 = (i2 << 1) + 1;
        int ptr1 = i2 << 1;
        int i3 = this.kNumHashDirectBytes;
        int len1 = i3;
        int len0 = i3;
        if (i3 == 0) {
            maxLen = maxLen2;
        } else if (curMatch2 > matchMinPos) {
            maxLen = maxLen2;
            byte b = this._bufferBase[this._bufferOffset + curMatch2 + this.kNumHashDirectBytes];
            byte[] bArr = this._bufferBase;
            int maxLen3 = this.kNumHashDirectBytes;
            if (b != bArr[cur + maxLen3]) {
                int offset4 = offset + 1;
                distances[offset] = maxLen3;
                offset = offset4 + 1;
                distances[offset4] = (this._pos - curMatch2) - 1;
                maxLen = maxLen3;
            }
        } else {
            maxLen = maxLen2;
        }
        int count3 = this._cutValue;
        int maxLen4 = maxLen;
        while (true) {
            if (curMatch2 <= matchMinPos) {
                count = count3;
                break;
            }
            count = count3 - 1;
            if (count3 == 0) {
                break;
            }
            int delta = this._pos - curMatch2;
            int matchMinPos2 = matchMinPos;
            int matchMinPos3 = this._cyclicBufferPos;
            if (delta <= matchMinPos3) {
                i = matchMinPos3 - delta;
                hash2Value = hash2Value2;
            } else {
                hash2Value = hash2Value2;
                int hash2Value3 = this._cyclicBufferSize;
                i = (matchMinPos3 - delta) + hash2Value3;
            }
            int cyclicPos = i << 1;
            int pby1 = this._bufferOffset + curMatch2;
            int len2 = Math.min(len0, len1);
            int hash3Value2 = hash3Value;
            int hashValue = temp;
            if (this._bufferBase[pby1 + len2] != this._bufferBase[cur + len2]) {
                count2 = count;
                len = len2;
            } else {
                while (true) {
                    len = len2 + 1;
                    if (len != lenLimit) {
                        count2 = count;
                        if (this._bufferBase[pby1 + len] != this._bufferBase[cur + len]) {
                            break;
                        }
                        len2 = len;
                        count = count2;
                    } else {
                        count2 = count;
                        break;
                    }
                }
                if (maxLen4 < len) {
                    int offset5 = offset + 1;
                    maxLen4 = len;
                    distances[offset] = len;
                    offset = offset5 + 1;
                    distances[offset5] = delta - 1;
                    if (len == lenLimit) {
                        int[] iArr2 = this._son;
                        iArr2[ptr1] = iArr2[cyclicPos];
                        iArr2[ptr0] = iArr2[cyclicPos + 1];
                        break;
                    }
                }
            }
            if ((this._bufferBase[pby1 + len] & UByte.MAX_VALUE) < (this._bufferBase[cur + len] & UByte.MAX_VALUE)) {
                int[] iArr3 = this._son;
                iArr3[ptr1] = curMatch2;
                ptr1 = cyclicPos + 1;
                curMatch = iArr3[ptr1];
                len1 = len;
            } else {
                int[] iArr4 = this._son;
                iArr4[ptr0] = curMatch2;
                ptr0 = cyclicPos;
                curMatch = iArr4[ptr0];
                len0 = len;
            }
            curMatch2 = curMatch;
            matchMinPos = matchMinPos2;
            hash2Value2 = hash2Value;
            hash3Value = hash3Value2;
            temp = hashValue;
            count3 = count2;
        }
        int[] iArr5 = this._son;
        iArr5[ptr1] = 0;
        iArr5[ptr0] = 0;
        MovePos();
        return offset;
    }

    public void Skip(int num) throws IOException {
        int lenLimit;
        int temp;
        int hashValue;
        int len;
        int num2 = num;
        do {
            if (this._pos + this._matchMaxLen <= this._streamPos) {
                lenLimit = this._matchMaxLen;
            } else {
                lenLimit = this._streamPos - this._pos;
                if (lenLimit < this.kMinMatchCheck) {
                    MovePos();
                    num2--;
                }
            }
            int matchMinPos = this._pos > this._cyclicBufferSize ? this._pos - this._cyclicBufferSize : 0;
            int cur = this._bufferOffset + this._pos;
            if (this.HASH_ARRAY) {
                int temp2 = CrcTable[this._bufferBase[cur] & UByte.MAX_VALUE] ^ (this._bufferBase[cur + 1] & UByte.MAX_VALUE);
                int hash2Value = temp2 & 1023;
                this._hash[hash2Value] = this._pos;
                int temp3 = temp2 ^ ((this._bufferBase[cur + 2] & UByte.MAX_VALUE) << 8);
                int hash3Value = 65535 & temp3;
                this._hash[hash3Value + GL20.GL_STENCIL_BUFFER_BIT] = this._pos;
                temp = ((CrcTable[this._bufferBase[cur + 3] & UByte.MAX_VALUE] << 5) ^ temp3) & this._hashMask;
            } else {
                temp = (this._bufferBase[cur] & UByte.MAX_VALUE) ^ ((this._bufferBase[cur + 1] & UByte.MAX_VALUE) << 8);
            }
            int[] iArr = this._hash;
            int i = this.kFixHashSize;
            int curMatch = iArr[i + temp];
            iArr[i + temp] = this._pos;
            int i2 = this._cyclicBufferPos;
            int ptr0 = (i2 << 1) + 1;
            int ptr1 = i2 << 1;
            int len0 = this.kNumHashDirectBytes;
            int len1 = len0;
            int delta = this._cutValue;
            while (curMatch > matchMinPos) {
                int count = delta - 1;
                if (delta == 0) {
                    break;
                }
                int delta2 = this._pos - curMatch;
                int i3 = this._cyclicBufferPos;
                int cyclicPos = (delta2 <= i3 ? i3 - delta2 : (i3 - delta2) + this._cyclicBufferSize) << 1;
                int pby1 = this._bufferOffset + curMatch;
                int len2 = Math.min(len0, len1);
                int matchMinPos2 = matchMinPos;
                if (this._bufferBase[pby1 + len2] != this._bufferBase[cur + len2]) {
                    hashValue = temp;
                } else {
                    while (true) {
                        len = len2 + 1;
                        if (len == lenLimit) {
                            hashValue = temp;
                            break;
                        }
                        hashValue = temp;
                        if (this._bufferBase[pby1 + len] != this._bufferBase[cur + len]) {
                            break;
                        }
                        len2 = len;
                        temp = hashValue;
                    }
                    if (len != lenLimit) {
                        len2 = len;
                    } else {
                        int[] iArr2 = this._son;
                        iArr2[ptr1] = iArr2[cyclicPos];
                        iArr2[ptr0] = iArr2[cyclicPos + 1];
                        break;
                    }
                }
                if ((this._bufferBase[pby1 + len2] & UByte.MAX_VALUE) < (this._bufferBase[cur + len2] & UByte.MAX_VALUE)) {
                    int[] iArr3 = this._son;
                    iArr3[ptr1] = curMatch;
                    int ptr12 = cyclicPos + 1;
                    int curMatch2 = iArr3[ptr12];
                    curMatch = curMatch2;
                    ptr1 = ptr12;
                    len1 = len2;
                } else {
                    int[] iArr4 = this._son;
                    iArr4[ptr0] = curMatch;
                    int curMatch3 = iArr4[cyclicPos];
                    curMatch = curMatch3;
                    ptr0 = cyclicPos;
                    len0 = len2;
                }
                delta = count;
                matchMinPos = matchMinPos2;
                temp = hashValue;
            }
            int[] iArr5 = this._son;
            iArr5[ptr1] = 0;
            iArr5[ptr0] = 0;
            MovePos();
            num2--;
        } while (num2 != 0);
    }

    void NormalizeLinks(int[] items, int numItems, int subValue) {
        int value;
        for (int i = 0; i < numItems; i++) {
            int value2 = items[i];
            if (value2 <= subValue) {
                value = 0;
            } else {
                value = value2 - subValue;
            }
            items[i] = value;
        }
    }

    void Normalize() {
        int i = this._pos;
        int i2 = this._cyclicBufferSize;
        int subValue = i - i2;
        NormalizeLinks(this._son, i2 * 2, subValue);
        NormalizeLinks(this._hash, this._hashSizeSum, subValue);
        ReduceOffsets(subValue);
    }

    public void SetCutValue(int cutValue) {
        this._cutValue = cutValue;
    }

    static {
        for (int i = 0; i < 256; i++) {
            int r = i;
            for (int j = 0; j < 8; j++) {
                if ((r & 1) != 0) {
                    r = (r >>> 1) ^ (-306674912);
                } else {
                    r >>>= 1;
                }
            }
            CrcTable[i] = r;
        }
    }
}