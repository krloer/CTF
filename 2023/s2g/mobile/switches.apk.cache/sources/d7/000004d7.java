package com.badlogic.gdx.utils.compression.lz;

import java.io.IOException;
import java.io.InputStream;

/* loaded from: classes.dex */
public class InWindow {
    public int _blockSize;
    public byte[] _bufferBase;
    public int _bufferOffset;
    int _keepSizeAfter;
    int _keepSizeBefore;
    int _pointerToLastSafePosition;
    public int _pos;
    int _posLimit;
    InputStream _stream;
    boolean _streamEndWasReached;
    public int _streamPos;

    public void MoveBlock() {
        int offset = (this._bufferOffset + this._pos) - this._keepSizeBefore;
        if (offset > 0) {
            offset--;
        }
        int numBytes = (this._bufferOffset + this._streamPos) - offset;
        for (int i = 0; i < numBytes; i++) {
            byte[] bArr = this._bufferBase;
            bArr[i] = bArr[offset + i];
        }
        int i2 = this._bufferOffset;
        this._bufferOffset = i2 - offset;
    }

    public void ReadBlock() throws IOException {
        if (this._streamEndWasReached) {
            return;
        }
        while (true) {
            int i = this._bufferOffset;
            int i2 = (0 - i) + this._blockSize;
            int i3 = this._streamPos;
            int size = i2 - i3;
            if (size == 0) {
                return;
            }
            int numReadBytes = this._stream.read(this._bufferBase, i + i3, size);
            if (numReadBytes == -1) {
                this._posLimit = this._streamPos;
                int i4 = this._bufferOffset;
                int pointerToPostion = this._posLimit + i4;
                int i5 = this._pointerToLastSafePosition;
                if (pointerToPostion > i5) {
                    this._posLimit = i5 - i4;
                }
                this._streamEndWasReached = true;
                return;
            }
            this._streamPos += numReadBytes;
            int i6 = this._streamPos;
            int i7 = this._pos;
            int i8 = this._keepSizeAfter;
            if (i6 >= i7 + i8) {
                this._posLimit = i6 - i8;
            }
        }
    }

    void Free() {
        this._bufferBase = null;
    }

    public void Create(int keepSizeBefore, int keepSizeAfter, int keepSizeReserv) {
        this._keepSizeBefore = keepSizeBefore;
        this._keepSizeAfter = keepSizeAfter;
        int blockSize = keepSizeBefore + keepSizeAfter + keepSizeReserv;
        if (this._bufferBase == null || this._blockSize != blockSize) {
            Free();
            this._blockSize = blockSize;
            this._bufferBase = new byte[this._blockSize];
        }
        this._pointerToLastSafePosition = this._blockSize - keepSizeAfter;
    }

    public void SetStream(InputStream stream) {
        this._stream = stream;
    }

    public void ReleaseStream() {
        this._stream = null;
    }

    public void Init() throws IOException {
        this._bufferOffset = 0;
        this._pos = 0;
        this._streamPos = 0;
        this._streamEndWasReached = false;
        ReadBlock();
    }

    public void MovePos() throws IOException {
        this._pos++;
        int i = this._pos;
        if (i > this._posLimit) {
            int pointerToPostion = this._bufferOffset + i;
            if (pointerToPostion > this._pointerToLastSafePosition) {
                MoveBlock();
            }
            ReadBlock();
        }
    }

    public byte GetIndexByte(int index) {
        return this._bufferBase[this._bufferOffset + this._pos + index];
    }

    public int GetMatchLen(int index, int distance, int limit) {
        if (this._streamEndWasReached) {
            int i = this._pos;
            int i2 = i + index + limit;
            int i3 = this._streamPos;
            if (i2 > i3) {
                limit = i3 - (i + index);
            }
        }
        int distance2 = distance + 1;
        int pby = this._bufferOffset + this._pos + index;
        int i4 = 0;
        while (i4 < limit) {
            byte[] bArr = this._bufferBase;
            if (bArr[pby + i4] != bArr[(pby + i4) - distance2]) {
                break;
            }
            i4++;
        }
        return i4;
    }

    public int GetNumAvailableBytes() {
        return this._streamPos - this._pos;
    }

    public void ReduceOffsets(int subValue) {
        this._bufferOffset += subValue;
        this._posLimit -= subValue;
        this._pos -= subValue;
        this._streamPos -= subValue;
    }
}