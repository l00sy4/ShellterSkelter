## Description

ShellterSkelter is a payload encryption/obfuscation tool.

It reads the payload from a file specified by the user, then pads it with NOP bytes according to the selected obfuscation method (MACfuscation/IPv4fuscation/UUIDfuscation requires the payload size to be a multiple of 6, 4 or 16). If no obfuscation method is selected, or if the payload is already a multiple of 6/4/16, padding is skipped.

It will then randomly generate a key (and IV if using AES) of the specified size (in bytes) and encrypt the payload using the specified method. A "magic byte" from the key is randomly chosen to be the XOR key used to encrypt the key. The Fowler-Noll-Vo hash of the magic byte is computed and printed, along with the FNV function itself and the encrypted key. A function to decrypt the key at runtime is also printed.

Finally, the (encrypted) payload is obfuscated using the specified method. The payload and the deobfuscation function are written to the selected output file.


## Usage

```
.\ShellterSkelter payload.bin output.cpp AES 16 MAC
```
> This will encrypt the payload using AES (Key and IV will be 16 bytes) and transform it into an array of MAC addresses. Then, the decryption/deobfuscation functions will be written in the `output.cpp` file.

```
.\ShellterSkelter payload.bin output.cpp NONE 0 UUID
```
> This won't encrypt the payload, it will just transform it into an array of UUIDs. Again, the deobfuscation function will be written in the `output.cpp` file.

```
.\ShellterSkelter payload.bin output.cpp XOR 32 NONE
```
> The payload won't be obfuscated, just encrypted using XOR with a 32-byte (256-bit) key. The payload will be written into the `output.cpp` file alongside the key and decryption function.

Supported encryption types:
- NONE: in this case the payload will only be obfuscated
- XOR
- AES: implemented using tiny-aes
- RC4: implemented using SystemFunction032

Supported obfuscation types:
- NONE: in this case the payload will only be encrypted
- MACfuscation: outputs the payload as an array of MAC addresses 
- IPv4fuscation: outputs the payload as an array of IPv4 addresses
- UUIDfuscation: outputs the payload as an array of UUIDs

Misc features:
- Key encryption
- Padding


## To-do
- Better argument handling
- Make the payload be printed on one line


## Example

![ShellterSkelter](Img/ExampleUsage2.gif)


### Credits

 - AES implementation from [tiny-aes-c](https://github.com/kokke/tiny-AES-c) (included in the libs/ directory)
 - The obfuscation algorithm is a modified version of the one used in [HellShell](https://github.com/NUL0x4C/HellShell)
