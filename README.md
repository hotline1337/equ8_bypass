# EQU8 User-Mode Bypass and Injector

Simple EQU8 User-Mode Bypass that uses registry to find the driver path and close the IOCTL handle

## Proof of concept
By finding EQU8's driver **SessionId** using registry keys we get the IOCTL handle and close it - as it's the only handle to the driver and we close it the driver will simply unload itself

## Compiling
Build as **Release x64 | MSVC v143**

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
