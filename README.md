# Maltrace

Maltrace is a simple syscall tracer for Windows implemented through the use of [PIN](http://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool). In addition to this a series of Python scripts in the `pymal` directory can be used to collect, parse and analyze trace logs produced by the maltrace' tracer to analyze the behavior of unknown programs.

Take a look at the `docs/` folder for more information about how to use the tracer and the set of scripts.

# Build the tracer

In order to build the tracer you first have to generate some logging specific code, by using our code generator.

	$ python codegen/generator.py > generated.c

The code generator exploits definitions coming from header files contained in the `headers/` directory, in order to automatically generate logging code. If you want to follow only certain syscalls you can simply modify the file `syscalls.h` and remove the proper line. After having generated the `generated.c` file, you can build your `tracer.dll` library, by typing the following command:

	$ ..\nmake tracer.dll

# Custom Hooks

Custom hooks can be definied using the hooks directory. Hooks are used to customize logging output for certain functions. As an example take in consideration the `hooks/DeviceIoControlFile.hook` that is used to log IP address during a `IOCTL_AFD_CONNECT` operation.

# Trace an executable

To trace an executable:

	$ ..\..\..\pin -t obj-ia32\tracer.dll -- malware.exe arguments