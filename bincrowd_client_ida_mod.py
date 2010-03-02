import sets
import hashlib
import time
import sys
import os
from bincrowd_client_common import *
from function_selection_dialog import *
from datetime import datetime
import xmlrpclib #import dumps, loads, ServerProxy
DEBUG = False
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
UPLOADSEGHOTKEY = "Ctrl-3"
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

    # Handle optional parameters.
    functionInformation = {
                'baseAddress'             : idaapi.get_imagebase(),
                'RVA'                     : fn.startEA - idaapi.get_imagebase(),     
                'processor'               : processor,
                'operatingSystem'         : '%d (index defined in libfuncs.hpp?)'%inf.ostype,
                'operatingSystemVersion'  : '',
                'language'                : idaapi.get_compiler_name(inf.cc.id),
                'numberOfArguments'       : None,#int  
                'frameSize'               : fn.frsize,
                'frameNumberOfVariables'  : None,#int  
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
                 'fileInformation':fileInformation                                             
                 }
                 
#    time.sleep(UPLOADDELAY)        
    rpc_srv = xmlrpclib.ServerProxy(RPCURI,allow_none=True)
    response = rpc_srv.upload(parameters)
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

def bincrowd_upload_seg():
    upload_stats = [0, 0, 0, 0, 0, 0, 0]
    
    ea = idc.ScreenEA()
    functions = Functions(idc.SegStart(ea), idc.SegEnd(ea))
    
    for function_ea in functions:
        name = idc.GetFunctionName(function_ea)
        if DEBUG:
        	print "Uploading %s at " % name, datetime.now()
        ret_val = bincrowd_upload(function_ea)
        
        if ret_val == UploadReturn.COULDNT_READ_CONFIG_FILE:
            return
        
        upload_stats[ret_val] += 1
        break

    total_functions = sum(upload_stats)
    success_count = upload_stats[UploadReturn.UPLOAD_SUCCESS_ADDED] + upload_stats[UploadReturn.UPLOAD_SUCCESS_CHANGED]
    
    print "All function information was uploaded"
    print "  Successful: %d (%.02f%%)" % (success_count, 100.0 * success_count / total_functions)
    print "  Added new functions: %d (%.02f%%)" % (upload_stats[UploadReturn.UPLOAD_SUCCESS_ADDED], 100.0 * upload_stats[UploadReturn.UPLOAD_SUCCESS_ADDED] / total_functions)
    print "  Changed existing functions: %d (%.02f%%)" % (upload_stats[UploadReturn.UPLOAD_SUCCESS_CHANGED], 100.0 * upload_stats[UploadReturn.UPLOAD_SUCCESS_CHANGED] / total_functions)
    print "  Skipped (auto-generated names): %d (%.02f%%)" % (upload_stats[UploadReturn.SKIPPED_AUTO_GENERATED], 100.0 * upload_stats[UploadReturn.SKIPPED_AUTO_GENERATED] / total_functions)
    print "  Skipped (too small): %d (%.02f%%)" % (upload_stats[UploadReturn.SKIPPED_TOO_SMALL], 100.0 * upload_stats[UploadReturn.SKIPPED_TOO_SMALL] / total_functions)
    print "  Unknown server reply: %d (%.02f%%)" % (upload_stats[UploadReturn.UNKNOWN_SERVER_REPLY], 100.0 * upload_stats[UploadReturn.UNKNOWN_SERVER_REPLY] / total_functions)


def formatresults(results):
    """ build formatted strings of results and store in self.list """
    strlist = []
    for r in results:
        name            = r['name']         if len(r['name'])       <=26  else r['name'][:23]+'...'
        description     = r['description']  if len(r['description'])<=100 else r['description'][:97]+'...'
        owner           = r['owner']
        degree        = r['matchDegree']
        strlist.append(["%2d" % degree, name, description, owner])
    return strlist
        

 
def bincrowd_download():
    fn = idaapi.get_func(here())
    inf = idaapi.get_inf_structure()

    print "Requesting information for function at 0x%X"%fn.startEA

    user, password = read_config_file()

    if user == None:
    	print "Error: Could not read config file. Please check readme.txt to learn how to configure BinCrowd."
    	return
    	
    p = proxyGraph(fn.startEA)
    e = extract_edge_tuples_from_graph(p)
    edges = edges_array_to_dict(e)
    prime = calculate_prime_product_from_graph(fn.startEA)

    parameters = {
                 'username':user, 'password':password, 'version':CLIENTVERSION,
                 'primeProduct':'%d'%prime,'edges':edges, 
                 }
    
    rpc_srv = xmlrpclib.ServerProxy(RPCURI,allow_none=True)
    response = rpc_srv.download(parameters)
    try:
        (params, methodname) = xmlrpclib.loads(response)
    except:
        print response
        return
    
    if len(params) == 0:
        print "No information for function '%s' available" % idc.GetFunctionName(fn.startEA)
        return

    # Display results and modify based on user selection
    # would be better to use choose2() from idapython src repo
    c = FunctionSelectionDialog("Retrieved Function Information", formatresults(params))
    selected_row = c.Show(True)
    
    if selected_row >= 0:
        name        = params[selected_row]['name']
        description = params[selected_row]['description']
        idc.MakeName(fn.startEA, name)
        if description:
            print "Changing comment to:\n%s" % description
            idaapi.set_func_cmt(fn, description, True)


"""
REGISTER IDA SHORTCUTS
"""
    
print "Registering hotkey %s for bincrowd_upload()"%UPLOADHOTKEY
idaapi.CompileLine('static _bincrowd_upload() { RunPythonStatement("bincrowd_upload()"); }')
idc.AddHotkey(UPLOADHOTKEY,"_bincrowd_upload")

print "Registering hotkey %s for bincrowd_download()"%DOWNLOADHOTKEY
idaapi.CompileLine('static _bincrowd_download() { RunPythonStatement("bincrowd_download()"); }')
idc.AddHotkey(DOWNLOADHOTKEY,"_bincrowd_download")

print "Registering hotkey %s for bincrowd_upload_seg()"%UPLOADSEGHOTKEY
idaapi.CompileLine('static _bincrowd_upload_seg() { RunPythonStatement("bincrowd_upload_seg()"); }')
idc.AddHotkey(UPLOADSEGHOTKEY,"_bincrowd_upload_seg")