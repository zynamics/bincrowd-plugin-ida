1. Prerequisites

The BinCrowd IDA plugin requires at least IDAPython 1.3.2.

2. Configuration

Create a configuration file called bincrowd.cfg with three lines.

First line: The BinCrowd server you want to use.
   The public server is http://bincrowd.zynamics.com/RPC2/
   
Second line: Your BinCrowd account name.

Third line: Your BinCrowd account password.

3. Use

Execute bincrowd.py to register the hotkeys

CTRL-1: Upload information about the function at the current address
CTRL-2: Download information about the function at the current address
CTRL-3: Upload information about all functions
CTRL-4: Download information about all functions