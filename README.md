# emusun

I always wanted to fully Decompile an application from assembly, Write a C2 emulator, and learn how to reverse Golang, 
well I found the perfect sample for what I want, here I have fully decompiled sunshuttle from x64 Assembly to Go and wrote a C2 emulator that can interact with it, as well as the actual sample.

I have used IDA Pro Dissassembler (NO DECOMPILER), x64dbg and Go.

Sample: (MD5: 9466c865f7498a35e4e1a8f48ef1dffd)

#### C2 emulator interacting with real sunshuttle

https://github.com/user-attachments/assets/19448a03-cf9e-44f0-b2c9-5a7e584fbf66

#### C2 emulator interacting with my sunshuttle implementation

https://github.com/user-attachments/assets/206d856b-b96d-4263-991f-d8d9b8642c76

# Notes

I have noticed while debugging that sunshuttle authors modified google's shlex packages so it doesn't escape `\` which makes sense on windows, for that I made own [repo](https://github.com/ahm3dgg/shlex) 

Reference: 

- Got me started with Go reverse engineering highly recommended, he is also reversing sunshuttle but only made it to the key-exchange: [Reversing in action: Golang malware used in the SolarWinds attack](https://www.youtube.com/watch?v=_cL-OwU9pFQ)

- Got the sample from here: [New SUNSHUTTLE Second-Stage Backdoor Uncovered Targeting U.S.-Based Entity; Possible Connection to UNC2452](https://cloud.google.com/blog/topics/threat-intelligence/sunshuttle-second-stage-backdoor-targeting-us-based-entity)