package com.badlogic.gdx.utils.compression;

import com.badlogic.gdx.utils.compression.lzma.Decoder;
import com.badlogic.gdx.utils.compression.lzma.Encoder;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/* loaded from: classes.dex */
public class Lzma {

    /* loaded from: classes.dex */
    static class CommandLine {
        public static final int kBenchmak = 2;
        public static final int kDecode = 1;
        public static final int kEncode = 0;
        public String InFile;
        public String OutFile;
        public int Command = -1;
        public int NumBenchmarkPasses = 10;
        public int DictionarySize = 8388608;
        public boolean DictionarySizeIsDefined = false;
        public int Lc = 3;
        public int Lp = 0;
        public int Pb = 2;
        public int Fb = 128;
        public boolean FbIsDefined = false;
        public boolean Eos = false;
        public int Algorithm = 2;
        public int MatchFinder = 1;

        CommandLine() {
        }
    }

    public static void compress(InputStream in, OutputStream out) throws IOException {
        long fileSize;
        CommandLine params = new CommandLine();
        boolean eos = params.Eos;
        Encoder encoder = new Encoder();
        if (!encoder.SetAlgorithm(params.Algorithm)) {
            throw new RuntimeException("Incorrect compression mode");
        }
        if (!encoder.SetDictionarySize(params.DictionarySize)) {
            throw new RuntimeException("Incorrect dictionary size");
        }
        if (!encoder.SetNumFastBytes(params.Fb)) {
            throw new RuntimeException("Incorrect -fb value");
        }
        if (!encoder.SetMatchFinder(params.MatchFinder)) {
            throw new RuntimeException("Incorrect -mf value");
        }
        if (!encoder.SetLcLpPb(params.Lc, params.Lp, params.Pb)) {
            throw new RuntimeException("Incorrect -lc or -lp or -pb value");
        }
        encoder.SetEndMarkerMode(eos);
        encoder.WriteCoderProperties(out);
        if (eos) {
            fileSize = -1;
        } else {
            long fileSize2 = in.available();
            if (fileSize2 != 0) {
                fileSize = fileSize2;
            } else {
                fileSize = -1;
            }
        }
        for (int i = 0; i < 8; i++) {
            out.write(((int) (fileSize >>> (i * 8))) & 255);
        }
        encoder.Code(in, out, -1L, -1L, null);
    }

    public static void decompress(InputStream in, OutputStream out) throws IOException {
        byte[] properties = new byte[5];
        if (in.read(properties, 0, 5) != 5) {
            throw new RuntimeException("input .lzma file is too short");
        }
        Decoder decoder = new Decoder();
        if (!decoder.SetDecoderProperties(properties)) {
            throw new RuntimeException("Incorrect stream properties");
        }
        long outSize = 0;
        for (int i = 0; i < 8; i++) {
            int v = in.read();
            if (v < 0) {
                throw new RuntimeException("Can't read stream size");
            }
            outSize |= v << (i * 8);
        }
        if (!decoder.Code(in, out, outSize)) {
            throw new RuntimeException("Error in data stream");
        }
    }
}