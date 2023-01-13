# EnlyzeS7SoftwareControllerDecoder

This tool extracts the proprietarily encrypted and compressed binary of the Siemens S7-1500 Software Controller.
The S7-1500 Software Controller is an S7-1500 running on an x86 computer next to Windows in a VM.
It can be a software-only version that runs on any Siemens IPC or it can be a hardware/software combination like the CPU-1515SP, which looks and feels like a PLC but is nevertheless a fully integrated industrial PC.

This tool was inspired from the [sOfT7: Revealing the Secrets of Siemens S7 PLCs](https://www.youtube.com/watch?v=4PBdSvqyZwE) talk at Black Hat US 2022 and is more or less a drop-in reimplementation based on the limited information from the talk.
It has been successfully used to decode the CPU.ELF file of the S7-1505S Software Controller V21.9 (the one for the CPU-1515SP).

## Prerequisites (Siemens)
* Download the S7-1505S Software Controller from <https://support.industry.siemens.com/cs/document/109759122/updates-f%C3%BCr-simatic-et-200sp-open-controller-(cpu-1515sp-pc-pc2)-software-controller?dti=0&lc=de-DE>  
  I have taken the "SIMATIC_CPU_1505SP_V21_9.exe (1,0 GB)" binary and this tool is entirely written around its `VMM_2ND_STAGE.ELF` file.  
  Provided that Siemens hasn't changed the decoding algorithm between different models, you may be able to take the `VMM_2ND_STAGE.ELF` file from that download and extract any `CPU.ELF` with that.

* Run the downloaded `SIMATIC_CPU_1505SP_V21_9.exe`.
  Tell it to extract files without starting the installation.

* Navigate to the extraction folder -> InstData -> S7_Vmm -> Media -> Data1.cab.  
  Extract the `VMM_2ND_STAGE.ELF_4B3AB761_8023_596B_91E6_4235FAF5D2F3` from there.
  This file contains the decryption/decompression code.

* Navigate to the extraction folder -> InstData -> CPU1505SP -> Media -> Data1.cab.
  Extract the `CPU.ELF_C924BFD8_60A0_520A_A2EF_CBE66BEA1F2B` from there.
  This is a big encrypted and compressed ELF binary containing the entire S7-1500 in software.

## Prerequisites (Intel)
Just like the original presented in the talk, this tool is written around the [Intel Pin](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html) framework.
As VMM_2ND_STAGE.ELF is a binary that is meant to be run on the bare-metal, we use Pin to directly call into the decoding function and prepare an environment for the decoding function to work.

* Download and extract Intel Pin for Linux.
  I used `pin-3.25-98650-g8f6168173-gcc-linux`.

* Navigate to the extraction folder -> source -> tools.
  Clone this repo into an `EnlyzeS7SoftwareControllerDecoder` subfolder in `tools`.

## Building
Navigate to the `EnlyzeS7SoftwareControllerDecoder` folder inside `tools` and run

```
make obj-intel64/EnlyzeS7SoftwareControllerDecoder.so
```

## Usage
Within the same `EnlyzeS7SoftwareControllerDecoder` folder, run the following command

```
../../../pin -t obj-intel64/EnlyzeS7SoftwareControllerDecoder.so -c /path/to/CPU.ELF -- /path/to/VMM_2ND_STAGE.ELF
```

This will decode `CPU.ELF` and write it to `CPU.ELF.decoded` in the same folder.

## Future Work
This tool has not been tried with any other binaries.
Make sure that the binaries from SIMATIC_CPU_1505SP_V21_9.exe work, and then give other binaries a try.

## Contact
Colin Finck <c.finck@enlyze.com>
