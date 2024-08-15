# Black & White: Creature Isle scripts debugger

This is a project under development which aims to build a debugger for the CHL scripts for the game Black & White: Creature Isle.

## Overview

The debugger is made of a core system which creates an abstraction layer between the Lionhead Virtual Machine and the debug interface.
A debug interface is either a graphical or text interface built into debugger itself, or an implementation of a debug protocol that
connects the debugger to an external debug tool.

A set of debug interfaces is provided, but it can be extended by implementing new UI/protocols above the core API.

## Current status

The debugger supports the following interfaces:
- `gdb` text based built-in interface which mimics the popular gdb debugger;
- `xdebug` (partial support, experimental) general purpose TCP/IP based protocol, mainly used to debug PHP code.

## License

GPL 3

## Author

Daniels118
