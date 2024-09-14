## Analysis

### The final part, the DLL
sha256: `1be0b96d502c268cb40da97a16952d89674a9329cb60bac81a96e01cf7356830` 

This is by far, the shortest section. The majority of this DLL is focused on setting up the GUI application and the file encryption, both parts which I am not interested in.

### Starting checks
After the processing is moved over to the DLL, the DLL will begin by checking whether it is the only copy of itself running or not:
```c
if ( passed_zero || EnsureOnlyInstance() )
   return 0;
```
Similarly to before, the `EnsureOnlyInstance` function will attempt to open up a mutex, if it is unable to do so, the program executable will exit. If this DLL is ran with a 1 instead of a zero, this check can be bypassed.

After checking that it is the only instance running, the DLL will fix the current directory context to be at the root of the executable file.
```c
GetModuleFileNameW(hModule, FileNameSelf, 259u);
  if (wcsrchr(FileNameSelf, '\\') )
    *wcsrchr(FileNameSelf, '\\') = 0;
  SetCurrentDirectoryW(FileNameSelf);
```

After this, the process will check if it has `SYSTEM` privileges by looking at the process token's privileges, this function is particularly interesting so I will refrain from adding it here.

The process will load the previously loaded `kernel32.dll` functions using `GetProcAddress` and use them later on in the process. In similar preparations, the process will initialize the Windows cryptography context for future use.
```c
  if ( CheckIfOnlyRunningProcess(0) || TestCrypto(0) )
  {
    thread_handle = CreateThread(0, 0, CreateDecryptorAddPersistence, 0, 0, 0);
    WaitForSingleObject(thread_handle, 0xFFFFFFFF);
    CloseHandle(thread_handle);
    return 0;
  }
```
Here, the part we are interested in is the `CreateDecryptorAddPersistence` function. 

### CreateDecryptorAddPersistence function
Looking at the code for this
```c
while ( 1 )
 {
   if ( time(0) >= unk_time && unk_value > 0 )
   {
     time_passed = 0;
     if ( !unk_time )
     {
       time_passed = 1;
       unk_time = time(0);
       read_or_write_file(&buffer, 0);
     }
     CreateAndRunDecryptor();
     if ( time_passed )
     {
       taskche_exe_path[0] = byte_1000DD98;
       memset(&taskche_exe_path[1], 0, 0x204u);
       v3 = 0;
       v4 = 0;
       GetFullPathNameA(first_step_path, 0x208u, taskche_exe_path, 0);
       AddPersistenceToSelf(taskche_exe_path);
     }
   }
   Sleep(30000u);
 }
```
The process will sleep for an unknown period of time, after which, it will read the contents of the previously seeded c.wnry file and use that to initialize the decryptor GUI program.
As this is run in a while loop, I am assuming that this will be checking if the GUI program is dead and if it is, it will reinitialize it.

### AddPersistenceToSelf
The `AddPersistenceToSelf` function will add the `taskche.exe` file to be auto run on login.
```c
strcpy(registery_key, "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
if ( IsMemberOfSystem() )
  qmemcpy(&registery_key[2], "LM", 2);
v3[0] = byte_1000DD98;
memset(&v3[1], 0, 0x60u);
v4 = 0;
v5 = 0;
sub_100014A0(v3);
sprintf(autorun_command, "cmd.exe /c reg add %s /v \"%s\" /t REG_SZ /d \"\\\"%s\\\"\" /f", registery_key, v3, a1);
return RunArgumentsAndWait(autorun_command, 0x2710u, 0);
```
I find it strange that this utilizes `cmd.exe` when before, the registery edits were done through the Windows API. Regardless, the run executable is the `taskche.exe`, which will enumerate open RDP sessions and attempt to spread there. 

After this, the process will launch multiple various threads, which are the actual encryption process. It will also launch instances of `taskdl.exe` which are used to delete residual files that the encryption process leaves behind.
As mentioned in the foreword, I will not be looking into the encryption process, as I do not find this interesting

## Closing thoughts
I found this to be the most boring part, by far. This DLL is the actual executor of the ransomware, leading it to being the most boring to me.

I did not dive that deep into the DLL, after finding out that this is where the actual ransomware takes place. I am sure I have information wrong in this part of this write up.

While looking through the strings, I found it interesting that the DLL lists every file format that it will encrypt, not vice versa. I suppose this is a smart move as to avoid wasting time on files that most likely do not contain anything interesting.

After the DLL is done, it will kill a bunch of Microsoft server processes, namesly `MSExchange`, `sqlserver`, `sqlwriter` and `mysqld`.