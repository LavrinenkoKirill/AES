#include "AES.h"
#include <string>
#include <fstream>


AES::AES(const AESKeyLength keyLength) {
    switch (keyLength) {
    case AESKeyLength::AES_128:
        this->Nk = 4;
        this->Nr = 10;
        break;
    case AESKeyLength::AES_192:
        this->Nk = 6;
        this->Nr = 12;
        break;
    case AESKeyLength::AES_256:
        this->Nk = 8;
        this->Nr = 14;
        break;
    }
}

unsigned char* AES::EncryptECB(const unsigned char in[], unsigned int inLen, const unsigned char key[]) {
    CheckLength(inLen);
    unsigned char* out = new unsigned char[inLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        EncryptBlock(in + i, out + i, roundKeys);
    }

    delete[] roundKeys;

    return out;
}




unsigned char* AES::DecryptECB(const unsigned char in[], unsigned int inLen,
    const unsigned char key[]) {
    CheckLength(inLen);
    unsigned char* out = new unsigned char[inLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        DecryptBlock(in + i, out + i, roundKeys);
    }

    delete[] roundKeys;

    return out;
}


int GetRandomNumber(int min, int max)
{
    srand(time(NULL));

    int num = min + rand() % (max - min + 1);

    return num;
}

std::vector<unsigned char> AES::GenerateKey() {
    std::vector<unsigned char> bytes = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    std::vector<unsigned char> key;
    int num = 0;
    for (int i = 0; i < bytes.size(); i++) {
        num = GetRandomNumber(0, bytes.size());
        key.push_back(bytes[i]);
    }

    return key;
}




unsigned char* AES::EncryptOFB(const unsigned char in[], unsigned int inLen, const unsigned char key[],const unsigned char* iv) {
    unsigned char* out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char encryptedBlock[blockBytesLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        EncryptBlock(block, encryptedBlock, roundKeys);
        XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
        memcpy(block, encryptedBlock, blockBytesLen);
    }

    delete[] roundKeys;
    return out;

}

unsigned char* AES::DecryptOFB(const unsigned char in[], unsigned int inLen,const unsigned char key[], const unsigned char* iv) {
    unsigned char* out = new unsigned char[inLen];
    unsigned char iv_block[blockBytesLen];
    unsigned char encryptedBlock[blockBytesLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(iv_block, iv, blockBytesLen);

    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        EncryptBlock(iv_block, encryptedBlock, roundKeys);
        XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
        memcpy(encryptedBlock, iv_block, blockBytesLen);
    }

    delete[] roundKeys;
    return out;


}


void AES::CheckLength(unsigned int len) {
    if (len % blockBytesLen != 0) {
        throw std::length_error("Plaintext length must be divisible by " +
            std::to_string(blockBytesLen));
    }
}

void AES::EncryptBlock(const unsigned char in[], unsigned char out[], unsigned char* roundKeys) {
    unsigned char state[4][Nb];
    unsigned int i, j, round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey(state, roundKeys);

    for (round = 1; round <= Nr - 1; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 4 * Nb);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }
}


void AES::DecryptBlock(const unsigned char in[], unsigned char out[], unsigned char* roundKeys) {
    unsigned char state[4][Nb];
    unsigned int i, j, round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (round = Nr - 1; round >= 1; round--) {
        InvSubBytes(state);
        InvShiftRows(state);
        AddRoundKey(state, roundKeys + round * 4 * Nb);
        InvMixColumns(state);
    }

    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, roundKeys);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }
}


void AES::SubBytes(unsigned char state[4][Nb]) {
    unsigned int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = sbox[t / 16][t % 16];
        }
    }
}


void AES::ShiftRow(unsigned char state[4][Nb], unsigned int i,
    unsigned int n)  // shift row i on n positions
{
    unsigned char tmp[Nb];
    for (unsigned int j = 0; j < Nb; j++) {
        tmp[j] = state[i][(j + n) % Nb];
    }
    memcpy(state[i], tmp, Nb * sizeof(unsigned char));
}

void AES::ShiftRows(unsigned char state[4][Nb]) {
    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);
}


unsigned char AES::xtime(unsigned char b)  // multiply on x
{
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

void AES::MixColumns(unsigned char state[4][Nb]) {
    unsigned char temp_state[4][Nb];
    for (size_t i = 0; i < 4; ++i) {
        memset(temp_state[i], 0, 4);
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                if (CMDS[i][k] == 1)
                    temp_state[i][j] ^= state[k][j];
                else
                    temp_state[i][j] ^= GF_MUL_TABLE[CMDS[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < 4; ++i) {
        memcpy(state[i], temp_state[i], 4);
    }
}


void AES::AddRoundKey(unsigned char state[4][Nb], unsigned char* key) {
    unsigned int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = state[i][j] ^ key[i + 4 * j];
        }
    }
}


void AES::SubWord(unsigned char* a) {
    int i;
    for (i = 0; i < 4; i++) {
        a[i] = sbox[a[i] / 16][a[i] % 16];
    }
}

void AES::RotWord(unsigned char* a) {
    unsigned char c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}


void AES::XorWords(unsigned char* a, unsigned char* b, unsigned char* c) {
    int i;
    for (i = 0; i < 4; i++) {
        c[i] = a[i] ^ b[i];
    }
}


void AES::Rcon(unsigned char* a, unsigned int n) {
    unsigned int i;
    unsigned char c = 1;
    for (i = 0; i < n - 1; i++) {
        c = xtime(c);
    }

    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}


void AES::KeyExpansion(const unsigned char key[], unsigned char w[]) {
    unsigned char temp[4];
    unsigned char rcon[4];

    unsigned int i = 0;
    while (i < 4 * Nk) {
        w[i] = key[i];
        i++;
    }

    i = 4 * Nk;
    while (i < 4 * Nb * (Nr + 1)) {
        temp[0] = w[i - 4 + 0];
        temp[1] = w[i - 4 + 1];
        temp[2] = w[i - 4 + 2];
        temp[3] = w[i - 4 + 3];

        if (i / 4 % Nk == 0) {
            RotWord(temp);
            SubWord(temp);
            Rcon(rcon, i / (Nk * 4));
            XorWords(temp, rcon, temp);
        }
        else if (Nk > 6 && i / 4 % Nk == 4) {
            SubWord(temp);
        }

        w[i + 0] = w[i - 4 * Nk] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
        i += 4;
    }
}

void AES::InvSubBytes(unsigned char state[4][Nb]) {
    unsigned int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = inv_sbox[t / 16][t % 16];
        }
    }
}


void AES::InvMixColumns(unsigned char state[4][Nb]) {
    unsigned char temp_state[4][Nb];

    for (size_t i = 0; i < 4; ++i) {
        memset(temp_state[i], 0, 4);
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                temp_state[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < 4; ++i) {
        memcpy(state[i], temp_state[i], 4);
    }
}

void AES::InvShiftRows(unsigned char state[4][Nb]) {
    ShiftRow(state, 1, Nb - 1);
    ShiftRow(state, 2, Nb - 2);
    ShiftRow(state, 3, Nb - 3);
}

void AES::XorBlocks(const unsigned char* a, const unsigned char* b,unsigned char* c, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        c[i] = a[i] ^ b[i];
    }
}


void AES::printHexArray(unsigned char a[], unsigned int n) {
    for (unsigned int i = 0; i < n; i++) {
        printf("%02x ", a[i]);
    }
}

void AES::printHexVector(std::vector<unsigned char> a) {
    for (unsigned int i = 0; i < a.size(); i++) {
        printf("%02x ", a[i]);
    }
}


std::vector<unsigned char> AES::ArrayToVector(unsigned char* a,
    unsigned int len) {
    std::vector<unsigned char> v(a, a + len * sizeof(unsigned char));
    return v;
}

unsigned char* AES::VectorToArray(std::vector<unsigned char>& a) {
    return a.data();
}

std::vector<unsigned char> AES::EncryptECB(std::vector<unsigned char> in, std::vector<unsigned char> key) {
    unsigned char* out = EncryptECB(VectorToArray(in), (unsigned int)in.size(),
    VectorToArray(key));
    std::vector<unsigned char> v = ArrayToVector(out, in.size());
    delete[] out;
    return v;
}



void AES::EncryptECB(const std::string& inputName, std::vector<unsigned char> key, const std::string& outputName) {
    std::ifstream inputFile;
    inputFile.open(inputName, std::ios::in | std::ios::binary);
    std::ofstream outputFile;
    outputFile.open(outputName, std::ios::out | std::ios::binary);
    if (!outputFile || !inputFile) {
        std::cout << "No such files" << std::endl;
        return;
    }

    std::vector<unsigned char> in;

    while (!inputFile.eof()) {
        in.push_back(inputFile.get());
    }
    in.pop_back();
    inputFile.close();


    if (in.size() == 16) {
        unsigned char* out = EncryptECB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key));
        std::vector<unsigned char> v = ArrayToVector(out, in.size());
        delete[] out;

        for (int i = 0; i < v.size(); i++) {
            outputFile << v[i];
        }
        outputFile.close();
    }
    else if (in.size() < 16) {
        while (in.size() != 16) {
            in.push_back(' ');
        }
        unsigned char* out = EncryptECB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key));
        std::vector<unsigned char> v = ArrayToVector(out, in.size());
        delete[] out;

        for (int i = 0; i < v.size(); i++) {
            outputFile << v[i];
        }

        outputFile.close();
    }

    else if (in.size() > 16) {
        std::vector<unsigned char> res;
        std::vector<unsigned char> part;
        for (int i = 0; i < in.size(); i++) {
            part.push_back(in[i]);
            if ((i + 1) % 16 == 0) {
                std::cout << '1';
                unsigned char* out = EncryptECB(VectorToArray(part), (unsigned int)part.size(), VectorToArray(key));
                std::vector<unsigned char> v = ArrayToVector(out, part.size());
                for (int j = 0; j < v.size(); j++) {
                    res.push_back(v[j]);
                }
                part.clear();
            }
            if (i == in.size() - 1 && (i + 1 % 16 != 0)) {
                while (part.size() != 16) {
                    part.push_back(' ');
                }
                unsigned char* out = EncryptECB(VectorToArray(part), (unsigned int)part.size(), VectorToArray(key));
                std::vector<unsigned char> v = ArrayToVector(out, part.size());
                for (int j = 0; j < v.size(); j++) {
                    res.push_back(v[j]);
                }
                delete[] out;


                for (int i = 0; i < res.size(); i++) {
                    outputFile << res[i];
                }

                outputFile.close();
            }

        }
      

       
    }

}


void AES::EncryptOFB(const std::string& inputName, std::vector<unsigned char> key, const std::string& outputName, std::vector<unsigned char> iv) {
    std::ifstream inputFile;
    inputFile.open(inputName, std::ios::in | std::ios::binary);
    std::ofstream outputFile;
    outputFile.open(outputName, std::ios::out | std::ios::binary);
    if (!outputFile || !inputFile) {
        std::cout << "No such files" << std::endl;
        return;
    }

    std::vector<unsigned char> in;

    while (!inputFile.eof()) {
        in.push_back(inputFile.get());
    }
    in.pop_back();
    inputFile.close();


    if (in.size() == 16) {
        unsigned char* out = EncryptOFB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), VectorToArray(iv));
        std::vector<unsigned char> v = ArrayToVector(out, in.size());
        delete[] out;

        for (int i = 0; i < v.size(); i++) {
            outputFile << v[i];
        }
        outputFile.close();
    }
    else if (in.size() < 16) {
        while (in.size() != 16) {
            in.push_back(' ');
        }
        unsigned char* out = EncryptOFB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), VectorToArray(iv));
        std::vector<unsigned char> v = ArrayToVector(out, in.size());
        delete[] out;

        for (int i = 0; i < v.size(); i++) {
            outputFile << v[i];
        }

        outputFile.close();
    }

    else if (in.size() > 16) {
        std::vector<unsigned char> res;
        std::vector<unsigned char> part;
        for (int i = 0; i < in.size(); i++) {
            part.push_back(in[i]);
            if ((i + 1) % 16 == 0) {
                std::cout << '1';
                unsigned char* out = EncryptOFB(VectorToArray(part), (unsigned int)part.size(), VectorToArray(key), VectorToArray(iv));
                std::vector<unsigned char> v = ArrayToVector(out, part.size());
                for (int j = 0; j < v.size(); j++) {
                    res.push_back(v[j]);
                }
                part.clear();
            }
            if (i == in.size() - 1 && (i + 1 % 16 != 0)) {
                while (part.size() != 16) {
                    part.push_back(' ');
                }
                unsigned char* out = EncryptOFB(VectorToArray(part), (unsigned int)part.size(), VectorToArray(key), VectorToArray(iv));
                std::vector<unsigned char> v = ArrayToVector(out, part.size());
                for (int j = 0; j < v.size(); j++) {
                    res.push_back(v[j]);
                }
                delete[] out;


                for (int i = 0; i < res.size(); i++) {
                    outputFile << res[i];
                }

                outputFile.close();
            }

        }



    }

}

void AES::DecryptOFB(const std::string& inputName, std::vector<unsigned char> key, const std::string& outputName, std::vector<unsigned char> iv) {
    std::ifstream f(inputName);
    f.seekg(0, std::ios::end);
    size_t size = f.tellg();
    std::string s(size, ' ');
    f.seekg(0);
    f.read(&s[0], size);
    std::vector<unsigned char> in;
    f.close();


    for (int i = 0; i < s.size(); i++) { in.push_back(s[i]); }

    std::ofstream output(outputName);
    unsigned char* out = DecryptOFB(VectorToArray(in), (unsigned int)in.size(),VectorToArray(key), VectorToArray(iv));
    std::vector<unsigned char> v = ArrayToVector(out, (unsigned int)in.size());
    delete[] out;
    for (int i = 0; i < v.size(); i++) {
        output << v[i];
    }
    output.close();
}

void AES::EncryptECB(bitmap_image* imageIN, std::vector<unsigned char> key, bitmap_image* imageOUT) {
    bitmap_image& imgIN = *imageIN;
    bitmap_image& imgOUT = *imageOUT;
    std::vector<rgb_t> in;
    std::vector<unsigned char> red;
    std::vector<unsigned char> green;
    std::vector<unsigned char> blue;

    for (int i = 0; i < imgIN.width(); i++) {
        for (int j = 0; j < imgIN.height(); j++) {
            in.push_back(imgIN.get_pixel(i, j));
        }
    }


    for (int i = 0; i < in.size(); i++) {
        red.push_back(in[i].red);
        green.push_back(in[i].green);
        blue.push_back(in[i].blue);
    }

    std::vector<unsigned char> n_red = EncryptVector(red, key);
    std::vector<unsigned char> n_green = EncryptVector(green, key);
    std::vector<unsigned char> n_blue = EncryptVector(blue, key);


    std::vector<rgb_t> encoded;
    rgb_t newColour;
    for (int i = 0; i < in.size(); i++) {
        newColour.red = n_red[i];
        newColour.green = n_green[i];
        newColour.blue = n_blue[i];
        encoded.push_back(newColour);
    }

    int r = 0;
    for (int i = 0; i < imgOUT.width(); i++) {
        for (int j = 0; j < imgOUT.height(); j++) {
            imgOUT.set_pixel(i, j, encoded[r]);
            r++;
        }
    }

    imgOUT.save_image("encoded.bmp");

}

void AES::EncryptOFB(bitmap_image* imageIN, std::vector<unsigned char> key, bitmap_image* imageOUT, std::vector<unsigned char> iv) {
    bitmap_image& imgIN = *imageIN;
    bitmap_image& imgOUT = *imageOUT;
    std::vector<rgb_t> in;
    std::vector<unsigned char> red;
    std::vector<unsigned char> green;
    std::vector<unsigned char> blue;

    for (int i = 0; i < imgIN.width(); i++) {
        for (int j = 0; j < imgIN.height(); j++) {
            in.push_back(imgIN.get_pixel(i, j));
        }
    }


    for (int i = 0; i < in.size(); i++) {
        red.push_back(in[i].red);
        green.push_back(in[i].green);
        blue.push_back(in[i].blue);
    }

    std::vector<unsigned char> n_red = EncryptVector(red, key);
    std::vector<unsigned char> n_green = EncryptVector(green, key);
    std::vector<unsigned char> n_blue = EncryptVector(blue, key);


    std::vector<rgb_t> encoded;
    rgb_t newColour;
    for (int i = 0; i < in.size(); i++) {
        newColour.red = n_red[i];
        newColour.green = n_green[i];
        newColour.blue = n_blue[i];
        encoded.push_back(newColour);
    }

    int r = 0;
    for (int i = 0; i < imgOUT.width(); i++) {
        for (int j = 0; j < imgOUT.height(); j++) {
            imgOUT.set_pixel(i, j, encoded[r]);
            r++;
        }
    }

    imgOUT.save_image("encoded.bmp");

}

void AES::DecryptECB(bitmap_image* imageIN, std::vector<unsigned char> key, bitmap_image* imageOUT) {
    bitmap_image& imgIN = *imageIN;
    bitmap_image& imgOUT = *imageOUT;
    std::vector<rgb_t> in;
    std::vector<unsigned char> red;
    std::vector<unsigned char> green;
    std::vector<unsigned char> blue;

    for (int i = 0; i < imgIN.width(); i++) {
        for (int j = 0; j < imgIN.height(); j++) {
            in.push_back(imgIN.get_pixel(i, j));
        }
    }


    for (int i = 0; i < in.size(); i++) {
        red.push_back(in[i].red);
        green.push_back(in[i].green);
        blue.push_back(in[i].blue);
    }

    std::vector<unsigned char> n_red = DecryptVector(red, key);
    std::vector<unsigned char> n_green = DecryptVector(green, key);
    std::vector<unsigned char> n_blue = DecryptVector(blue, key);



    std::vector<rgb_t> encoded;
    rgb_t newColour;
    for (int i = 0; i < in.size(); i++) {
        newColour.red = n_red[i];
        newColour.green = n_green[i];
        newColour.blue = n_blue[i];
        encoded.push_back(newColour);
    }

    int r = 0;
    for (int i = 0; i < imgOUT.width(); i++) {
        for (int j = 0; j < imgOUT.height(); j++) {
            imgOUT.set_pixel(i, j, encoded[r]);
            r++;
        }
    }

    imgOUT.save_image("result.bmp");

}

void AES::DecryptOFB(bitmap_image* imageIN, std::vector<unsigned char> key, bitmap_image* imageOUT, std::vector<unsigned char> iv) {
    bitmap_image& imgIN = *imageIN;
    bitmap_image& imgOUT = *imageOUT;
    std::vector<rgb_t> in;
    std::vector<unsigned char> red;
    std::vector<unsigned char> green;
    std::vector<unsigned char> blue;

    for (int i = 0; i < imgIN.width(); i++) {
        for (int j = 0; j < imgIN.height(); j++) {
            in.push_back(imgIN.get_pixel(i, j));
        }
    }


    for (int i = 0; i < in.size(); i++) {
        red.push_back(in[i].red);
        green.push_back(in[i].green);
        blue.push_back(in[i].blue);
    }

    std::vector<unsigned char> n_red = DecryptVector(red, key);
    std::vector<unsigned char> n_green = DecryptVector(green, key);
    std::vector<unsigned char> n_blue = DecryptVector(blue, key);



    std::vector<rgb_t> encoded;
    rgb_t newColour;
    for (int i = 0; i < in.size(); i++) {
        newColour.red = n_red[i];
        newColour.green = n_green[i];
        newColour.blue = n_blue[i];
        encoded.push_back(newColour);
    }

    int r = 0;
    for (int i = 0; i < imgOUT.width(); i++) {
        for (int j = 0; j < imgOUT.height(); j++) {
            imgOUT.set_pixel(i, j, encoded[r]);
            r++;
        }
    }

    imgOUT.save_image("resultbmp.bmp");

}

std::vector<unsigned char> AES::EncryptVector(std::vector<unsigned char> in, std::vector<unsigned char> key) {
    if (in.size() == 16) {
        unsigned char* out = EncryptECB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key));
        std::vector<unsigned char> v = ArrayToVector(out, in.size());
        delete[] out;

        return v;

    }
    else if (in.size() < 16) {
        while (in.size() != 16) {
            in.push_back(' ');
        }
        unsigned char* out = EncryptECB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key));
        std::vector<unsigned char> v = ArrayToVector(out, in.size());
        delete[] out;

        return v;


    }

    else if (in.size() > 16) {
        std::vector<unsigned char> res;
        std::vector<unsigned char> part;
        for (int i = 0; i < in.size(); i++) {
            part.push_back(in[i]);
            if ((i + 1) % 16 == 0) {
        
                unsigned char* out = EncryptECB(VectorToArray(part), (unsigned int)part.size(), VectorToArray(key));
                std::vector<unsigned char> v = ArrayToVector(out, part.size());
                for (int j = 0; j < v.size(); j++) {
                    res.push_back(v[j]);
                }
                part.clear();
            }
            if (i == in.size() - 1 && (i + 1 % 16 != 0)) {
                while (part.size() != 16) {
                    part.push_back(' ');
                }
                unsigned char* out = EncryptECB(VectorToArray(part), (unsigned int)part.size(), VectorToArray(key));
                std::vector<unsigned char> v = ArrayToVector(out, part.size());
                for (int j = 0; j < v.size(); j++) {
                    res.push_back(v[j]);
                }
                delete[] out;

                return res;


            }

        }



    }
}

std::vector<unsigned char> AES::EncryptVectorOFB(std::vector<unsigned char> in, std::vector<unsigned char> key, std::vector<unsigned char> iv) {
    if (in.size() == 16) {
        unsigned char* out = EncryptOFB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), VectorToArray(iv));
        std::vector<unsigned char> v = ArrayToVector(out, in.size());
        delete[] out;

        return v;

    }
    else if (in.size() < 16) {
        while (in.size() != 16) {
            in.push_back(' ');
        }
        unsigned char* out = EncryptOFB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), VectorToArray(iv));
        std::vector<unsigned char> v = ArrayToVector(out, in.size());
        delete[] out;

        return v;


    }

    else if (in.size() > 16) {
        std::vector<unsigned char> res;
        std::vector<unsigned char> part;
        for (int i = 0; i < in.size(); i++) {
            part.push_back(in[i]);
            if ((i + 1) % 16 == 0) {

                unsigned char* out = EncryptOFB(VectorToArray(part), (unsigned int)part.size(), VectorToArray(key), VectorToArray(iv));
                std::vector<unsigned char> v = ArrayToVector(out, part.size());
                for (int j = 0; j < v.size(); j++) {
                    res.push_back(v[j]);
                }
                part.clear();
            }
            if (i == in.size() - 1 && (i + 1 % 16 != 0)) {
                while (part.size() != 16) {
                    part.push_back(' ');
                }
                unsigned char* out = EncryptOFB(VectorToArray(part), (unsigned int)part.size(), VectorToArray(key), VectorToArray(iv));
                std::vector<unsigned char> v = ArrayToVector(out, part.size());
                for (int j = 0; j < v.size(); j++) {
                    res.push_back(v[j]);
                }
                delete[] out;

                return res;


            }

        }



    }
}




void AES::DecryptECB(const std::string& inputName, std::vector<unsigned char> key, const std::string& outputName) {
    std::ifstream f(inputName);
    f.seekg(0, std::ios::end);
    size_t size = f.tellg();
    std::string s(size, ' ');
    f.seekg(0);
    f.read(&s[0], size);
    std::vector<unsigned char> in;
    f.close();


    for (int i = 0; i < s.size(); i++) { in.push_back(s[i]); }

    std::ofstream output(outputName);
    unsigned char* out = DecryptECB(VectorToArray(in), (unsigned int)in.size(),
    VectorToArray(key));
    std::vector<unsigned char> v = ArrayToVector(out, (unsigned int)in.size());
    delete[] out;
    for (int i = 0; i < v.size(); i++) {
        output << v[i];
    }
    output.close();
}

std::vector<unsigned char> AES::DecryptVector(std::vector<unsigned char> in, std::vector<unsigned char> key) {

    if (in.size() == 16) {
        unsigned char* out = DecryptECB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key));
        std::vector<unsigned char> v = ArrayToVector(out, in.size());
        delete[] out;

        return v;

    }
    else if (in.size() < 16) {
        while (in.size() != 16) {
            in.push_back(' ');
        }
        unsigned char* out = DecryptECB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key));
        std::vector<unsigned char> v = ArrayToVector(out, in.size());
        delete[] out;

        return v;


    }

    else if (in.size() > 16) {
        std::vector<unsigned char> res;
        std::vector<unsigned char> part;
        for (int i = 0; i < in.size(); i++) {
            part.push_back(in[i]);
            if ((i + 1) % 16 == 0) {

                unsigned char* out = DecryptECB(VectorToArray(part), (unsigned int)part.size(), VectorToArray(key));
                std::vector<unsigned char> v = ArrayToVector(out, part.size());
                for (int j = 0; j < v.size(); j++) {
                    res.push_back(v[j]);
                }
                part.clear();
            }
            if (i == in.size() - 1 && (i + 1 % 16 != 0)) {
                while (part.size() != 16) {
                    part.push_back(' ');
                }
                unsigned char* out = DecryptECB(VectorToArray(part), (unsigned int)part.size(), VectorToArray(key));
                std::vector<unsigned char> v = ArrayToVector(out, part.size());
                for (int j = 0; j < v.size(); j++) {
                    res.push_back(v[j]);
                }
                delete[] out;

                return res;


            }

        }



    }
}

std::vector<unsigned char> AES::DecryptVectorOFB(std::vector<unsigned char> in, std::vector<unsigned char> key, std::vector<unsigned char> iv) {

    if (in.size() == 16) {
        unsigned char* out = DecryptOFB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), VectorToArray(iv));
        std::vector<unsigned char> v = ArrayToVector(out, in.size());
        delete[] out;

        return v;

    }
    else if (in.size() < 16) {
        while (in.size() != 16) {
            in.push_back(' ');
        }
        unsigned char* out = DecryptOFB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), VectorToArray(iv));
        std::vector<unsigned char> v = ArrayToVector(out, in.size());
        delete[] out;

        return v;


    }

    else if (in.size() > 16) {
        std::vector<unsigned char> res;
        std::vector<unsigned char> part;
        for (int i = 0; i < in.size(); i++) {
            part.push_back(in[i]);
            if ((i + 1) % 16 == 0) {

                unsigned char* out = DecryptOFB(VectorToArray(part), (unsigned int)part.size(), VectorToArray(key), VectorToArray(iv));
                std::vector<unsigned char> v = ArrayToVector(out, part.size());
                for (int j = 0; j < v.size(); j++) {
                    res.push_back(v[j]);
                }
                part.clear();
            }
            if (i == in.size() - 1 && (i + 1 % 16 != 0)) {
                while (part.size() != 16) {
                    part.push_back(' ');
                }
                unsigned char* out = DecryptOFB(VectorToArray(part), (unsigned int)part.size(), VectorToArray(key), VectorToArray(iv));
                std::vector<unsigned char> v = ArrayToVector(out, part.size());
                for (int j = 0; j < v.size(); j++) {
                    res.push_back(v[j]);
                }
                delete[] out;

                return res;


            }

        }



    }
}

std::vector<unsigned char> AES::EncryptOFB(std::vector<unsigned char> in, std::vector<unsigned char> key, std::vector<unsigned char> iv) {
    unsigned char* out = EncryptOFB(VectorToArray(in), (unsigned int)in.size(),
    VectorToArray(key), VectorToArray(iv));
    std::vector<unsigned char> v = ArrayToVector(out, in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::DecryptOFB(std::vector<unsigned char> in, std::vector<unsigned char> key, std::vector<unsigned char> iv) {
    unsigned char* out = DecryptOFB(VectorToArray(in), (unsigned int)in.size(),
    VectorToArray(key), VectorToArray(iv));
    std::vector<unsigned char> v = ArrayToVector(out, (unsigned int)in.size());
    delete[] out;
    return v;
}


