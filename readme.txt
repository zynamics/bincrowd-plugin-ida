zynamics BinCrowd IDA Pro Plugin

1. Prerequisites

The BinCrowd IDA plugin requires at least IDAPython 1.3.2.

Please note that there is a bug in IDAPython 1.3.2 which often
leads to access errors when running BinCrowd the first time on an IDB.
The bug is not critical as you can just run BinCrowd again and it works.
The bug was fixed in IDAPython already, so if you get the latest source
code from the IDAPython repository and compile the plugin yourself
the problem will go away.

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

4. License

The BinCrowd IDA plugin GPLv2-licensed. If you prefer to distribute code
from the plugin under another license please contact us to learn about
re-licensing options.

BinCrowd IDA Plugin
Copyright (C) 2010 zynamics GmbH

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program;
if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA