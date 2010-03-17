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

Please note that you have to create a free account on the zynamics BinCrowd
community server before you can use this server for sharing information.

Uploading information
  
  When uploading information, information about the upload operation is displayed
  in the IDA Pro console. Function information that is uploaded to the BinCrowd
  database includes function names and function descriptions as well as local
  variable names and descriptions and function argument names and descriptions.
  
Downloading information about one function
  
  When downloading information about a single file, you are shown a dialog
  where you can select from all possible candidates found in the BinCrowd
  database.
  
  Function matches of high quality are shown in green color in the function selection
  dialog.
  
Downloading information about all functions
  
  When downloading information about all functions you are shown a dialog that lists
  for what functions of an IDB file matching functions were found in the BinCrowd
  database. If you select one of the functions in the dialog, the dialog that was
  already described in the above paragraph about downloading information about
  single functions is shown.
  
  In addition to showing information about all matched functions, a score value for
  the most likely candidates is shown in the IDA Pro console. The higher the score
  the more functions are shared between your IDB file and the file in the database.
  
Batch Mode

  There is a batch mode available for the plugin. If you run IDA Pro with the command
  line
  
      idag -A -OIDAPython:PATH_TO_PLUGIN\bincrowd.py IDB_FILE
      
  all the function information from that IDB file is uploaded to the BinCrowd server.
  Note that in most cases it is smarter to use idaw instead of idag because idaw blocks
  the console which makes sure that uploads are batched. If you use idag in batch mode
  to upload a set of IDB files, as many instances of IDA as there are IDB files will
  open at the same time.

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