# Reversing WannaCry

This is a write up on what I found while reversing the original WannaCry sample. 

I found this to be a very enjoyable sample to work on, especially for a beginner such as myself.

## Foreword
I am not a professional, there is quite a bit of guesswork as to what is going on at times. This will be clearly indicated by the use of tentative language.

Some parts might and very well likely will be incorrect, but generally speaking, I believe that I gained an okay level understanding of everything I was interested in.

I have not read enough malware analysis reports to have a grasp of that standards of what malware analysis reports should hold, please keep this in mind while reading.

I originally got interested in doing WannaCry, as it seemed like an infamous sample with plenty of things going on.
My prior knowledge on WannaCry which was relevant to this analysis was the following:
- It is a ransomware.
- It used EternalBlue, an exploit abusing a vulnerability in the SMBv1 protocol.
- There is *some* sort of a domain killswitch.

As I did this project to mainly improve on static analysis, I avoided all sandboxes, unpackers, previous write ups or searching for information on WannaCry. This is somewhat against industry standards, but I believe I got the most out of this experience this way.

I did the vast majority of the reversing as static analysis, only using dynamic analysis towards the end to make unencrypting information easier.

## Scope
The scope of this write up, is to explain the crucial findings. This is not a short write up focusing on the important parts to detect nor is this just explaining everything externally visible WannaCry is doing. The purpose of this write up is to follow up on what I learned from reversing and analysing WannaCry. At times, the I will focus on individual `if` statements, during others, I might ignore entire trees of functions.

As such, this write up does not cover everything, the encryption part as an example, is not interesting to me. Similarly, I am not interested in how the GUI part of the application works. I found the worm aspect along with the multiple different layers of the sample very interesting, so I focused on those.

As this write up ended up being long, I have split this up to multiple parts:
- [The initial loader and spreader](https://github.com/Chalkybot/Reversing-Wannacry/blob/main/First-Dropper.md)
- [The second executable](https://github.com/Chalkybot/Reversing-Wannacry/blob/main/Second-Executable.md)
- [The final part, the DLL](https://github.com/Chalkybot/Reversing-Wannacry/blob/main/Final-DLL.md)

The DLL portion is very short compared to the other sections. This is due to the DLL mainly focusing on the encryption part of this ransomware and as previously mentioned, I was uninterested in this.

### Credits
- F & A helped a great deal! :)