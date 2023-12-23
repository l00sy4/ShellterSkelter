
ShellterSkelter is a tool for encrypting/obfuscating payloads. 

It reads the payload from a user-specified file, then it will pad it with NOP bytes according to the selected obfuscation method (MACfuscation/IPv4fuscation/UUIDfuscation require the payload's size to be a multiple of 6, 4 respectively 16). If no obfuscation method was selected, or the payload is already a multiple of 6/4/16 it will skip padding. 

Afterwards, it will randomly generate a key (and IV, if using AES) and encrypt the payload using the specified method. The key (and IV) will be written into the selected output file, alongside the decryption function. If no obfuscation method was specified, the payload will also be written into the output file.

Finally, it will obfuscate the encrypted payload using the specified method. The payload and deobfuscation function will be written into the selected output file.

### Usage

```
.\ShellterSkelter payload.bin output.cpp AES MAC
```
> This will encrypt the payload using AES and transform it into an array of MAC addresses. The key, IV, and decryption/deobfuscation functions will be written in the `output.cpp` file.

```
.\ShellterSkelter payload.bin output.cpp NONE UUID
```
> This won't encrypt the payload, it will just transform it into an array of UUIDs. Again, the deobfuscation function wil be written in the `output.cpp` file.

```
.\ShellterSkelter payload.bin output.cpp XOR NONE
```
> The payload won't be obfuscated, just encrypted using XOR. The payload will be written into the `output.cpp` file alongside the key and decryption function.

Supported encryption types:
- NONE: in this case the payload will only be obfuscated
- XOR
- AES: implemented using tiny-aes

Supported obfuscation types:
- NONE: in this case the payload will only be encrypted
- MACfuscation: outputs the payload as an array of MAC addresses 
- IPv4fuscation: outputs the payload as an array of IPv4 addresses
- UUIDfuscation: outputs the payload as an array of UUIDs

Misc features:
- Padding

### To-do

- Add RC4
- Add the option to select key size (currently, keys are 16 bytes)
- Add key encryption

### Example

![ShellterSkelter](Images/ExampleUsage.gif)

### Credits

 - AES implementation from [tiny-aes-c](https://github.com/kokke/tiny-AES-c) (included in the libs/ directory)
 - The obfuscation algorithm is a modified version of the one used in [HellShell](https://github.com/NUL0x4C/HellShell)
