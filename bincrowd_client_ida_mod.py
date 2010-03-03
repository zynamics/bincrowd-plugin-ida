import sets
import hashlib
import time
import sys
import os
from bincrowd_client_common import *
from function_selection_dialog import *
from datetime import datetime
import xmlrpclib #import dumps, loads, ServerProxy
DEBUG = True
SHOWSKIPPED = True
"""
BINCROWD PARAMETERS
"""
RPCURI = "http://localhost:8000/RPC2/"
#RPCURI = "http://bincrowd.zynamics.com/bincrowd/RPC2/"
CLIENTVERSION = "0.1"
#CLIENTNAME = "Bincrowd IDA"
UPLOADHOTKEY = "Ctrl-1"
DOWNLOADHOTKEY = "Ctrl-2"
UPLOADALLHOTKEY = "Ctrl-3"
DOWNLOADALLHOTKEY = "Ctrl-4"
UPLOADDELAY = 0.1 #passed to time.sleep()

class proxyGraphNode:
    """
        A small stub class to proxy the BinNavi node class into IDA's
        graph class
    """
    def __init__( self, id, parentgraph ):
        self.parent = parentgraph
        self.id = id
    def get_children( self ):
        return self.parent.get_children( self.id )
    def get_parents( self ):
        return self.parent.get_parents( self.id )
    def set_children( self ):
        raise "not implemented"
    def set_parents( self ):
        raise "not implemented"
    def __hash__( self ):
        return self.parent.address+self.id
    def __cmp__( self, other ):
        if other.__class__ == self.__class__:
            if self.id < other.id:
                return -1
            if self.id > other.id:
                return 1
            return 0
        return 1
    def __eq__( self, other ):
        if other.__class__ == self.__class__:
            if other.id == self.id:
                return True
        else:
            return False
    children = property( get_children, set_children )
    parents = property( get_parents, set_parents )
            
class proxyGraphEdge:
    """
        A small stub class to proxy the BinNavi edge class into IDA's
        graph class
    """
    def __init__( self, source_id, target_id, parentgraph    ):
        self.parent = parentgraph
        self.source_id = source_id
        self.target_id = target_id
    def get_source( self ):
        return self.parent.get_node( self.source_id )
    def get_target( self ):
        return self.parent.get_node( self.target_id )
    def set_source( self ):
        raise "not implemented"
    def set_target( self ):
        raise "not implemented"
    source = property( get_source, set_source )
    target = property( get_target, set_target )
        

class proxyGraph:
    """
    A small stub class to proxy the BinNavi graph class into IDA's
    graph class. It would be much easier to build this if the qflow_chart_t
    contained meaningful values for "npred" and "pred" ... :-/
    
    But well. Life is not a ponyhof.
    """
    def __init__( self, address ):
        fn = idaapi.get_func( address )
        self.graph = idaapi.qflow_chart_t( "foo", fn, fn.startEA, fn.endEA, 0 )
        self.id_to_nodes = {}
        self.address = address
        for i in range( self.graph.size() ):
            self.id_to_nodes[ i ] = proxyGraphNode( i, self )
        self.id_to_children = [ [] for i in range(self.graph.size()) ]
        self.id_to_parents = [ [] for i in range(self.graph.size()) ]
        self.edges = []
        for i in range(self.graph.size()):
            for j in range(self.graph.nsucc(i)):
                self.edges.append( proxyGraphEdge( i, self.graph.succ(i,j), self) )
                self.id_to_children[ i ].append( self.graph.succ(i,j))
                self.id_to_parents[ self.graph.succ(i,j) ].append( i )
    def get_node( self, id ):
        return self.id_to_nodes[ id ]
    def get_children( self, id ):
        return [ self.get_node( i ) for i in self.id_to_children[id] ]
    def get_parents( self, id ):
        return [ self.get_node( i ) for i in self.id_to_parents[id] ]
    def get_nodes( self ):
        return self.id_to_nodes.values()
    def get_edges( self ):
        return self.edges
    def set_nodes( self ):
        raise "not implemented"
    def set_edges( self ):
        raise "not implemented"
    nodes = property( get_nodes, set_nodes )
    edges = property( get_edges, set_edges )


def get_list_of_mnemonics (address):
    fniter = idaapi.func_item_iterator_t(idaapi.get_func(address))
    mnemonics = []
    mnemonics.append( idc.GetMnem( fniter.current() ) )
    while fniter.next_code():
        mnemonics.append( idc.GetMnem( fniter.current() ) )
    return mnemonics
    
def calculate_prime_product_from_graph (address):
    mnemonics = get_list_of_mnemonics(address)
    return get_prime(mnemonics)





"""
BINCROWD RPC FUNCTIONS
"""

def edges_array_to_dict(e):
    edges = []
    for tup in e:
        edges.append(
               {'indegreeSource'          : tup[0],
                'outdegreeSource'         : tup[1],
                'indegreeTarget'          : tup[2],
                'outdegreeTarget'         : tup[3],
                'topologicalOrderSource'  : tup[4],
                'topologicalOrderTarget'  : tup[5]} )
                # Optional:
                #'sourcePrime'             : 0,
                #'sourceCallNum'           : 0,
                #'targetPrime'             : 0,
                #'targetCallNum'           : 0})
    return edges

def read_config_file():
    if DEBUG:
        print "Reading configuration file"
    
    directory = os.path.dirname(sys.argv[0])
    configuration_file = directory + "/bincrowd.cfg"
    
    if DEBUG:
        print "Determined script directory: %s" % directory
        print "Determined configuration file : %s" % configuration_file

    try:
        config_file = open(configuration_file, "r")
        lines = config_file.readlines()
        config_file.close()
        
        if len(lines) < 2:
            return (None, None)
        
        return (lines[0].rstrip("\r\n"), lines[1].rstrip("\r\n"))
    except:
        return (None, None)
    
class UploadReturn:
    UPLOAD_SUCCESS_ADDED = 0
    UPLOAD_SUCCESS_CHANGED = 1
    COULDNT_READ_CONFIG_FILE = 2
    SKIPPED_AUTO_GENERATED = 3
    SKIPPED_INTERNAL_ERROR = 4
    SKIPPED_TOO_SMALL = 5
    UNKNOWN_SERVER_REPLY = 6
    COULDNT_CONNECT_TO_SERVER = 7
        
def get_frame_information(ea):
    """
    This function returns a tuple of local variables of a stack frame and
    the arguments passed to the function.
    
    The function assumes that the stack frame has the following layout:
    
    local variables
    return address and/or base pointer
    arguments
    """
    local_variables = [ ]
    arguments = [ ]
    current = local_variables

    frame = idc.GetFrame(ea)
    
    if frame == None:
        return [[], []]
    
    start = idc.GetFirstMember(frame)
    end = idc.GetLastMember(frame)
    
    while start <= end:
        size = idc.GetMemberSize(frame, start)
        
        if size == None:
            start = start + 1
            continue

        name = idc.GetMemberName(frame, start)
        flag = idc.GetMemberFlag(frame, start)
        description = idc.GetMemberComment(frame, start, True) \
            or idc.GetMemberComment(frame, start, False) #repeatable/non-repeatable
        
        if DEBUG:
            print "%s: %d %08X" % (name, size, flag)
        
        start += size
        
        if name in [" r", " s"]:
            # Skip return address and base pointer
            current = arguments
            continue

        current.append({'name' : name, 'description' : description, 'size' : size, 'flag' : flag})

    return (local_variables, arguments)

def bincrowd_upload (ea=None):
    user, password = read_config_file()
    
    if user == None:
    	print "Error: Could not read config file. Please check readme.txt to learn how to configure BinCrowd."
    	return UploadReturn.COULDNT_READ_CONFIG_FILE

    if not ea:
        ea = here()

    fn = idaapi.get_func(ea)
    inf = idaapi.get_inf_structure()

    name = Demangle(idc.GetFunctionName(fn.startEA), idc.GetLongPrm(INF_SHORT_DN))
    if not name:
        name = idc.GetFunctionName(fn.startEA)
        
    # The Demangle function returns stuff like FooFunction(x,x,x,x) in IDA 5.6.
    # If you upload such a function name and download it again you get an error
    # because names with parentheses are invalid.
    first_parens = name.find("(")
    if first_parens != -1:
    	name = name[0:first_parens]

    print "0x%X: Submitting function %s" % (ea, name)
    
    if idaapi.has_dummy_name(idaapi.getFlags(fn.startEA)):
        if SHOWSKIPPED:
            print "0x%X: '%s' was not uploaded because it has an auto-generated name." % (fn.startEA, name)
        return UploadReturn.SKIPPED_AUTO_GENERATED

    try:
        p = proxyGraph( fn.startEA )
        number_of_nodes = len(p.get_nodes())
        e = extract_edge_tuples_from_graph( p )
    except:
        print "0x%X: '%s' was not uploaded because there was a local error in the edge list." % (fn.startEA, name)
        return UploadReturn.SKIPPED_AUTO_GENERATED
    if not e:
        print "0x%X: '%s' was not uploaded because it is too small." % (fn.startEA, name)
        return UploadReturn.SKIPPED_TOO_SMALL

    edges = edges_array_to_dict(e)
    prime = calculate_prime_product_from_graph(fn.startEA)
    
    description = idaapi.get_func_cmt(fn, True) \
                or idaapi.get_func_cmt(fn, False) #repeatable/non-repeatable
    
    md5 = idc.GetInputMD5().lower()
    sha1 = None
    sha256 = None
    filepath = idc.GetInputFilePath()
    if os.path.exists(filepath) and os.path.isfile(filepath):
        f = file(filepath, 'rb')
        data = f.read()
        f.close()
        sha1 = hashlib.sha1(data).hexdigest().lower()
        sha256 = hashlib.sha256(data).hexdigest().lower()    

    null_idx = inf.procName.find(chr(0))
    if null_idx > 0:
        processor = inf.procName[:null_idx]
    else:
        processor = inf.procName

    (local_variables, arguments) = get_frame_information(ea)
        
    stackFrame = ( local_variables, arguments )
    
    # Handle optional parameters.
    functionInformation = {
                'baseAddress'             : idaapi.get_imagebase(),
                'RVA'                     : fn.startEA - idaapi.get_imagebase(),     
                'processor'               : processor,
                'operatingSystem'         : '%d (index defined in libfuncs.hpp?)'%inf.ostype,
                'operatingSystemVersion'  : '',
                'language'                : idaapi.get_compiler_name(inf.cc.id),
                'numberOfNodes'           : "%d" % number_of_nodes,
                'frameSize'               : fn.frsize,
                'idaSignature'            : ''
                }


    fileInformation = {
                'hashMD5'                 : md5,
                'hashSHA1'                : sha1, 
                'hashSHA256'              : sha256, 
                'name'                    : idc.GetInputFile(),
                'description'             : '' #str NOTEPAD netblob?
                }
    #idaapi.get_file_type_name() #"Portable executable for 80386 (PE)"
    
    parameters = {
                 'username':user, 'password':password, 'version':CLIENTVERSION,
                 'name':name, 'description':description,                                
                 'primeProduct':'%d'%prime, 'edges':edges, 
                 'functionInformation':functionInformation,                                 
                 'fileInformation':fileInformation,
                 'stackFrame':stackFrame
                 }
#    time.sleep(UPLOADDELAY)        
    try:
        rpc_srv = xmlrpclib.ServerProxy(RPCURI,allow_none=True)
        response = rpc_srv.upload(parameters)
    except:
        print "Error: Could not connect to BinCrowd server"
        return (UploadReturn.COULDNT_CONNECT_TO_SERVER, None)
        
    print "0x%X: '%s' %s." % (fn.startEA, name, response)
    
    if response == "Added new function":
        return UploadReturn.UPLOAD_SUCCESS_ADDED
    elif response == "Changed existing function":
        return UploadReturn.UPLOAD_SUCCESS_CHANGED
    else:
        print "Error: Unknown server reply ", response
        return UploadReturn.UNKNOWN_SERVER_REPLY
    
    #import pprint
    #print pprint.PrettyPrinter().pformat(dir(rpc_srv))
    #print pprint.PrettyPrinter().pformat(dir(rpc_srv._ServerProxy__request))
    #print pprint.PrettyPrinter().pformat(dir(rpc_srv._ServerProxy__handler))

def bincrowd_upload_all():
    upload_stats = [0, 0, 0, 0, 0, 0, 0]
    
    functions = Functions(0, 0xFFFFFFFF)
    
    for function_ea in functions:
        name = idc.GetFunctionName(function_ea)
        if DEBUG:
        	print "Uploading %s at " % name, datetime.now()
        ret_val = bincrowd_upload(function_ea)
        
        if ret_val in (UploadReturn.COULDNT_READ_CONFIG_FILE, UploadReturn.COULDNT_CONNECT_TO_SERVER):
            return
        
        upload_stats[ret_val] += 1

    total_functions = sum(upload_stats)
    success_count = upload_stats[UploadReturn.UPLOAD_SUCCESS_ADDED] + upload_stats[UploadReturn.UPLOAD_SUCCESS_CHANGED]
    
    print "All function information was uploaded"
    print "  Successful: %d (%.02f%%)" % (success_count, 100.0 * success_count / total_functions)
    print "  Added new functions: %d (%.02f%%)" % (upload_stats[UploadReturn.UPLOAD_SUCCESS_ADDED], 100.0 * upload_stats[UploadReturn.UPLOAD_SUCCESS_ADDED] / total_functions)
    print "  Changed existing functions: %d (%.02f%%)" % (upload_stats[UploadReturn.UPLOAD_SUCCESS_CHANGED], 100.0 * upload_stats[UploadReturn.UPLOAD_SUCCESS_CHANGED] / total_functions)
    print "  Skipped (auto-generated names): %d (%.02f%%)" % (upload_stats[UploadReturn.SKIPPED_AUTO_GENERATED], 100.0 * upload_stats[UploadReturn.SKIPPED_AUTO_GENERATED] / total_functions)
    print "  Skipped (too small): %d (%.02f%%)" % (upload_stats[UploadReturn.SKIPPED_TOO_SMALL], 100.0 * upload_stats[UploadReturn.SKIPPED_TOO_SMALL] / total_functions)
    print "  Unknown server reply: %d (%.02f%%)" % (upload_stats[UploadReturn.UNKNOWN_SERVER_REPLY], 100.0 * upload_stats[UploadReturn.UNKNOWN_SERVER_REPLY] / total_functions)

MATCHDEGREE_STRINGS = [ "", "High", "Medium", "Low" ]

def formatresults(results, currentNodeCount, currentEdgeCount):
    """ build formatted strings of results and store in self.list """
    strlist = []
    for r in results:
        degree          = r['matchDegree']
        file            = r['file']           if len(r['file'])       <=26  else r['file'][:23]+'...'
        name            = r['name']           if len(r['name'])       <=26  else r['name'][:23]+'...'
        description     = r['description']    if len(r['description'])<=100 else r['description'][:97]+'...'
        numberOfNodes   = r['numberOfNodes']
        numberOfEdges   = r['numberOfEdges']
        owner           = r['owner']
        strlist.append([MATCHDEGREE_STRINGS[degree], file, name, description, "%d (%d)" % (numberOfNodes, numberOfNodes - currentNodeCount), "%d (%d)" % (numberOfEdges, numberOfEdges - currentEdgeCount), owner])
    return strlist
        
class DownloadReturn:
    SUCCESS = 0
    COULDNT_READ_CONFIG_FILE = 1
    COULDNT_RETRIEVE_DATA = 2
    COULDNT_CONNECT_TO_SERVER = 2
    
def download_without_application(ea, p):
    user, password = read_config_file()
    
    if user == None:
    	print "Error: Could not read config file. Please check readme.txt to learn how to configure BinCrowd."
    	return (DownloadReturn.COULDNT_READ_CONFIG_FILE, None)

    fn = idaapi.get_func(ea)
    inf = idaapi.get_inf_structure()

    print "Requesting information for function at 0x%X"%fn.startEA

    e = extract_edge_tuples_from_graph(p)
    edges = edges_array_to_dict(e)
    prime = calculate_prime_product_from_graph(fn.startEA)

    parameters = {
                 'username':user, 'password':password, 'version':CLIENTVERSION,
                 'primeProduct':'%d'%prime,'edges':edges, 
                 }
    try:
        rpc_srv = xmlrpclib.ServerProxy(RPCURI,allow_none=True)
        response = rpc_srv.download(parameters)
    except:
        print "Error: Could not connect to BinCrowd server"
        return (DownloadReturn.COULDNT_CONNECT_TO_SERVER, None)
        
    try:
        (params, methodname) = xmlrpclib.loads(response)
    except:
        print response
        return (DownloadReturn.COULDNT_RETRIEVE_DATA, None)
    
    return (DownloadReturn.SUCCESS, params)
 
def set_information(params, selected_row, fn):
    name        = params[selected_row]['name']
    description = params[selected_row]['description']
    idc.MakeName(fn.startEA, name)
    if description:
        idaapi.set_func_cmt(fn, description, True)
           
    (idb_lv, idb_args) = get_frame_information(fn.startEA)
    (local_variables, arguments) = params[selected_row]['stackFrame']
        
    # If the number of downloaded local variables and arguments are the same
    # as in the current IDB file then we rename the local variables and arguments
    # too.
        
    if (len(idb_lv) == len(local_variables) and len(idb_args) == len(arguments)):

        total = local_variables + arguments
        index = 0
        frame = idc.GetFrame(fn.startEA)
            
        if frame != None:
            start = idc.GetFirstMember(frame)
            end = idc.GetLastMember(frame)
            
            # The second check is important for stack frames ending in " r" or " s"
            while start <= end and index < len(total):
                size = idc.GetMemberSize(frame, start)
    
                if size == None:
                    start = start + 1
                    continue
                    
                name = total[index]['name']
                
                if name in [" r", " s"]:
                    # Skip return address and base pointer
                    start += size
                    continue
            
                idc.SetMemberName(frame, start, name)
                idc.SetMemberComment(frame, start, total[index]['description'], True)
                   
                index = index + 1
                start += size
    
def bincrowd_download(ea = None):
    if not ea:
        ea = here()

    fn = idaapi.get_func(ea)
    p = proxyGraph(fn.startEA)
    
    (error_code, params) = download_without_application(fn.startEA, p)

    if error_code != DownloadReturn.SUCCESS:
    	return
    
    if len(params) == 0:
        print "No information for function '%s' available" % idc.GetFunctionName(fn.startEA)
        return

    c = FunctionSelectionDialog("Retrieved Function Information", formatresults(params, len(p.get_nodes()), len(p.get_edges())))
    selected_row = c.Show(True)
    
    if selected_row >= 0:
        set_information(params, selected_row, fn)

def get_information_all_functions(file, result):
    """
    Takes the results of a file download request and returns only
    those pieces of information that come from the given source file.
    
    The result is a list that contains the ea of the target functions
    as well as the number of pieces of information available for the
    target functions.
    
    This is useful to list all functions of the currently active IDB
    file for which there is information available.
    """
    
    result_list = []
    
    for ea, (error_code, params) in result.items():
        if error_code == DownloadReturn.SUCCESS:
            info_pieces = [f for f in params if f['file'] == file]
            if len(info_pieces) > 0:
                result_list.append([ea, len(info_pieces)])
    
    return sorted(result_list, lambda x, y : y[1] - x[1])
    
def get_display_information_all_functions(information):
    """
    Converts information returned from get_information_all_functions and
    turns that information into something that can be displayed in a
    chooser2 dialog.
    """
    
    return [[idc.GetFunctionName(ea), "%d" % count] for [ea, count] in information]
    
def get_single_file_information(result, selected_ea, file):
    """
    Filters whole download results down to those for a given ea and
    a given source file.
    """
    return [r for r in result[selected_ea][1] if r['file'] == file]

def bincrowd_download_all():
    """
    Downloads information for all functions of the given file and lets
    the user choose what information he wants to accept.
    """
    
    result = { }     # ea => (error_code, information)
    file_count = { } # file => [ number of functions with information ]
    
    functions = Functions(0, 0xFFFFFFFF)
    
    for function_ea in functions:
        name = idc.GetFunctionName(function_ea)
        if DEBUG:
            print "Downloading %s at " % name, datetime.now()
        
        p = proxyGraph(function_ea)
        (error_code, params) = download_without_application(function_ea, p)
        result[function_ea] = (error_code, params)
        
        if error_code == DownloadReturn.SUCCESS:
            for i in xrange(len(params)):
                file = params[i]['file']
            
                if not file_count.has_key(file):
                    file_count[file] = 0
                
                file_count[file] = file_count[file] + 1
        else:
            pass # Do some error handling in the future
    
    # Create a list of [file name, number of pieces of information for that file]
    file_count_list = [[key, "%d" % file_count[key]] for key in sorted(file_count, key=file_count.get, reverse=True)]
    
    while True:
        # Let the user pick from what module he wants to copy information
        module_dialog = ModuleSelectionDialog("Retrieved Function Information", file_count_list)
        selected_module = module_dialog.Show(True)
        
        if selected_module == -1:
            break
        
        while True:
            # Let the user pick for what target function he wants to copy information
            file = file_count_list[selected_module][0]
            all_functions_information = get_information_all_functions(file, result)
            all_functions_dialog = AllFunctionsSelectionDialog("All Functions", get_display_information_all_functions(all_functions_information))
            selected_function = all_functions_dialog.Show(True)
        
            if selected_function == -1:
                break

            # Let the user pick for what downloaded information he wants to use for his target function
            selected_ea = all_functions_information[selected_function][0]
            
            idc.Jump(selected_ea)
            p = proxyGraph( selected_ea )
            fn = idaapi.get_func( selected_ea )
            
            function_information = get_single_file_information(result, selected_ea, file)
            function_selection_dialog = FunctionSelectionDialog("Retrieved Function Information", formatresults(function_information, len(p.get_nodes()), len(p.get_edges())))
            selected_row = function_selection_dialog.Show(True)
             
            if selected_row != -1:
                set_information(function_information, selected_row, fn)
    
            
"""
REGISTER IDA SHORTCUTS
"""
    
print "Registering hotkey %s for bincrowd_upload()"%UPLOADHOTKEY
idaapi.CompileLine('static _bincrowd_upload() { RunPythonStatement("bincrowd_upload()"); }')
idc.AddHotkey(UPLOADHOTKEY,"_bincrowd_upload")

print "Registering hotkey %s for bincrowd_download()"%DOWNLOADHOTKEY
idaapi.CompileLine('static _bincrowd_download() { RunPythonStatement("bincrowd_download()"); }')
idc.AddHotkey(DOWNLOADHOTKEY,"_bincrowd_download")

print "Registering hotkey %s for bincrowd_upload_all()"%UPLOADALLHOTKEY
idaapi.CompileLine('static _bincrowd_upload_all() { RunPythonStatement("bincrowd_upload_all()"); }')
idc.AddHotkey(UPLOADALLHOTKEY,"_bincrowd_upload_all")

print "Registering hotkey %s for _bincrowd_download_all()"%DOWNLOADALLHOTKEY
idaapi.CompileLine('static _bincrowd_download_all() { RunPythonStatement("bincrowd_download_all()"); }')
idc.AddHotkey(DOWNLOADALLHOTKEY,"_bincrowd_download_all")
