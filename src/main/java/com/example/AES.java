package com.example;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public class AES {
    private int actual; 
    private static int Nb = 4;
    private int Nk;
    private int Nr;
    private int[][][] state;
    private int[] w;
    private int[] key;
    private long encryptionTime;
    private long decryptionTime;

    private static final int[] sBox = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    private static final int[] rsBox = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    private static final int[] rCon = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
    };

    public AES(String textKey) {
        byte[] key = textKey.getBytes();
        init(key);
    }

    private void init(byte[] key) {
        this.key = new int[key.length];
        for (int i = 0; i < key.length; i++) {
            this.key[i] = key[i] & 0xff;
        }

        Nb = 4;
        switch (key.length) {
            case 16: Nr = 10; Nk = 4; break;
            case 24: Nr = 12; Nk = 6; break;
            case 32: Nr = 14; Nk = 8; break;
            default: throw new IllegalArgumentException("Only 128, 192 and 256 bit keys are supported!");
        }

        state = new int[2][4][Nb];
        w = new int[Nb * (Nr + 1)];
        expandKey();
    }

    private int[][] addRoundKey(int[][] s, int round) {
        for (int c = 0; c < Nb; c++) {
            for (int r = 0; r < 4; r++) {
                s[r][c] = s[r][c] ^ ((w[round * Nb + c] << (r * 8)) >>> 24);
            }
        }
        return s;
    }

    private int[][] cipher(int[][] in, int[][] out) {
        for (int i = 0; i < in.length; i++) {
            for (int j = 0; j < in.length; j++) {
                out[i][j] = in[i][j];
            }
        }
        actual = 0;
        addRoundKey(out, actual);

        for (actual = 1; actual < Nr; actual++) {
            subBytes(out);
            shiftRows(out);
            mixColumns(out);
            addRoundKey(out, actual);
        }

        subBytes(out);
        shiftRows(out);
        addRoundKey(out, actual);
        return out;
    }

    private int[][] decipher(int[][] in, int[][] out) {
        for (int i = 0; i < in.length; i++) {
            for (int j = 0; j < in.length; j++) {
                out[i][j] = in[i][j];
            }
        }
        actual = Nr;
        addRoundKey(out, actual);

        for (actual = Nr - 1; actual > 0; actual--) {
            invShiftRows(out);
            invSubBytes(out);
            addRoundKey(out, actual);
            invMixColumns(out);
        }
        invShiftRows(out);
        invSubBytes(out);
        addRoundKey(out, actual);
        return out;
    }

    private byte[] encrypt(byte[] text) {
        if (text.length != 16) {
            throw new IllegalArgumentException("Only 16-byte blocks can be encrypted");
        }
        byte[] out = new byte[text.length];

        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                state[0][j][i] = text[i * Nb + j] & 0xff;
            }
        }

        cipher(state[0], state[1]);
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                out[i * Nb + j] = (byte) (state[1][j][i] & 0xff);
            }
        }
        return out;
    }

    private byte[] decrypt(byte[] text) {
        if (text.length != 16) {
            throw new IllegalArgumentException("Only 16-byte blocks can be decrypted");
        }
        byte[] out = new byte[text.length];

        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                state[0][j][i] = text[i * Nb + j] & 0xff;
            }
        }

        decipher(state[0], state[1]);
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                out[i * Nb + j] = (byte) (state[1][j][i] & 0xff);
            }
        }
        return out;
    }

    private int[][] invMixColumns(int[][] state) {
        int temp0, temp1, temp2, temp3;
        for (int c = 0; c < Nb; c++) {
            temp0 = mult(0x0e, state[0][c]) ^ mult(0x0b, state[1][c]) ^ mult(0x0d, state[2][c]) ^ mult(0x09, state[3][c]);
            temp1 = mult(0x09, state[0][c]) ^ mult(0x0e, state[1][c]) ^ mult(0x0b, state[2][c]) ^ mult(0x0d, state[3][c]);
            temp2 = mult(0x0d, state[0][c]) ^ mult(0x09, state[1][c]) ^ mult(0x0e, state[2][c]) ^ mult(0x0b, state[3][c]);
            temp3 = mult(0x0b, state[0][c]) ^ mult(0x0d, state[1][c]) ^ mult(0x09, state[2][c]) ^ mult(0x0e, state[3][c]);

            state[0][c] = temp0;
            state[1][c] = temp1;
            state[2][c] = temp2;
            state[3][c] = temp3;
        }
        return state;
    }

    private int[][] invShiftRows(int[][] state) {
        int temp1, temp2, temp3, i;

        // row 1
        temp1 = state[1][Nb - 1];
        for (i = Nb - 1; i > 0; i--) {
            state[1][i] = state[1][(i - 1) % Nb];
        }
        state[1][0] = temp1;

        // row 2
        temp1 = state[2][Nb - 1];
        temp2 = state[2][Nb - 2];
        for (i = Nb - 1; i > 1; i--) {
            state[2][i] = state[2][(i - 2) % Nb];
        }
        state[2][1] = temp1;
        state[2][0] = temp2;

        // row 3
        temp1 = state[3][Nb - 3];
        temp2 = state[3][Nb - 2];
        temp3 = state[3][Nb - 1];
        for (i = Nb - 1; i > 2; i--) {
            state[3][i] = state[3][(i - 3) % Nb];
        }
        state[3][0] = temp1;
        state[3][1] = temp2;
        state[3][2] = temp3;

        return state;
    }

    private int[][] invSubBytes(int[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] = invSubWord(state[i][j]) & 0xFF;
            }
        }
        return state;
    }

    private static int invSubWord(int word) {
        int subWord = 0;
        for (int i = 24; i >= 0; i -= 8) {
            int in = word << i >>> 24;
            subWord |= rsBox[in] << (24 - i);
        }
        return subWord;
    }

    private int[] expandKey() {
        int temp, i = 0;
        while (i < Nk) {
            w[i] = 0x00000000;
            w[i] |= key[4 * i] << 24;
            w[i] |= key[4 * i + 1] << 16;
            w[i] |= key[4 * i + 2] << 8;
            w[i] |= key[4 * i + 3];
            i++;
        }
        i = Nk;
        while (i < Nb * (Nr + 1)) {
            temp = w[i - 1];
            if (i % Nk == 0) {
                temp = subWord(rotWord(temp)) ^ (rCon[i / Nk] << 24);
            } else if (Nk > 6 && (i % Nk == 4)) {
                temp = subWord(temp);
            }
            w[i] = w[i - Nk] ^ temp;
            i++;
        }
        return w;
    }

    private int[][] mixColumns(int[][] state) {
        int temp0, temp1, temp2, temp3;
        for (int c = 0; c < Nb; c++) {
            temp0 = mult(0x02, state[0][c]) ^ mult(0x03, state[1][c]) ^ state[2][c] ^ state[3][c];
            temp1 = state[0][c] ^ mult(0x02, state[1][c]) ^ mult(0x03, state[2][c]) ^ state[3][c];
            temp2 = state[0][c] ^ state[1][c] ^ mult(0x02, state[2][c]) ^ mult(0x03, state[3][c]);
            temp3 = mult(0x03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ mult(0x02, state[3][c]);

            state[0][c] = temp0;
            state[1][c] = temp1;
            state[2][c] = temp2;
            state[3][c] = temp3;
        }
        return state;
    }

    private static int mult(int a, int b) {
        int sum = 0;
        while (a != 0) {
            if ((a & 1) != 0) {
                sum = sum ^ b;
            }
            b = xtime(b);
            a = a >>> 1;
        }
        return sum;
    }

    private static int rotWord(int word) {
        return (word << 8) | ((word & 0xFF000000) >>> 24);
    }

    private int[][] shiftRows(int[][] state) {
        int temp1, temp2, temp3, i;

        // row 1
        temp1 = state[1][0];
        for (i = 0; i < Nb - 1; i++) {
            state[1][i] = state[1][(i + 1) % Nb];
        }
        state[1][Nb - 1] = temp1;

        // row 2
        temp1 = state[2][0];
        temp2 = state[2][1];
        for (i = 0; i < Nb - 2; i++) {
            state[2][i] = state[2][(i + 2) % Nb];
        }
        state[2][Nb - 2] = temp1;
        state[2][Nb - 1] = temp2;

        // row 3
        temp1 = state[3][0];
        temp2 = state[3][1];
        temp3 = state[3][2];
        for (i = 0; i < Nb - 3; i++) {
            state[3][i] = state[3][(i + 3) % Nb];
        }
        state[3][Nb - 3] = temp1;
        state[3][Nb - 2] = temp2;
        state[3][Nb - 1] = temp3;

        return state;
    }

    private int[][] subBytes(int[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] = subWord(state[i][j]) & 0xFF;
            }
        }
        return state;
    }

    private static int subWord(int word) {
        int subWord = 0;
        for (int i = 24; i >= 0; i -= 8) {
            int in = word << i >>> 24;
            subWord |= sBox[in] << (24 - i);
        }
        return subWord;
    }

    private static int xtime(int b) {
        if ((b & 0x80) == 0) {
            return b << 1;
        }
        return (b << 1) ^ 0x11b;
    }

   public String encryptFile(byte[] fileData) {
        long startTime = System.nanoTime();
        
        // Thêm padding PKCS#7
        int paddingLength = 16 - (fileData.length % 16);
        byte[] paddedData = new byte[fileData.length + paddingLength];
        System.arraycopy(fileData, 0, paddedData, 0, fileData.length);
        Arrays.fill(paddedData, fileData.length, paddedData.length, (byte)paddingLength);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < paddedData.length; i += 16) {
            byte[] block = Arrays.copyOfRange(paddedData, i, i + 16);
            byte[] encryptedBlock = encrypt(block);
            out.writeBytes(encryptedBlock);
        }
        
        encryptionTime = System.nanoTime() - startTime;
        return byteToHex(out.toByteArray());
    }

    public byte[] decryptFile(String encryptedHex) {
        long startTime = System.nanoTime();
        byte[] encryptedData = hexToByte(encryptedHex);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        
        for (int i = 0; i < encryptedData.length; i += 16) {
            byte[] block = Arrays.copyOfRange(encryptedData, i, i + 16);
            byte[] decryptedBlock = decrypt(block);
            out.writeBytes(decryptedBlock);
        }
        
        // Loại bỏ padding PKCS#7
        byte[] result = out.toByteArray();
        int padding = result[result.length - 1];
        
        decryptionTime = System.nanoTime() - startTime;
        return Arrays.copyOf(result, result.length - padding);
    }

    public long getEncryptionTime() {
        return encryptionTime;
    }

    public long getDecryptionTime() {
        return decryptionTime;
    }

    public static byte[] hexToByte(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                         + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String byteToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}