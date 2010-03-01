import sets
import sys
import os
from bincloud_client_common import *
import xmlrpclib #import dumps, loads, ServerProxy
DEBUG = True

"""
BINCLOUD PARAMETERS
"""
RPCURI = "http://localhost:8000/RPC2/"
#RPCURI = "http://bincrowd.zynamics.com/bincrowd/RPC2/"
UPLOADHOTKEY = "Ctrl-1"
DOWNLOADHOTKEY = "Ctrl-2"
# Test string added to some of optional parameters 
#TESTSTR = "6"


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
    #print mnemonics
    return mnemonics
    
def calculate_prime_product_from_graph (address):
    mnemonics = get_list_of_mnemonics(address)
    return get_prime(mnemonics)





"""
BINCLOUD RPC FUNCTIONS
"""

def edges_array_to_dict(e):
    edges = []
    for tup in e:
        """ REFERENCE:
        for edge in flowgraph.edges:
            e.append(  ( len(edge.source.parents), \
                len(edge.source.children), \
                len(edge.target.parents), \
                len(edge.target.children), \
                node_to_layer_index[ edge.source ], \
                node_to_layer_index[ edge.target ] ) )
        """
        edges.append(
               {'indegreeSource'          : tup[0],
                'outdegreeSource'         : tup[1],
                'indegreeTarget'          : tup[2],
                'outdegreeTarget'         : tup[3],
                'topologicalOrderSource'  : tup[4],
                'topologicalOrderTarget'  : tup[5],
                # Optional:
                'sourcePrime'             : 0,
                'sourceCallNum'           : 0,
                'targetPrime'             : 0,
                'targetCallNum'           : 0  } )
    return edges
    
def read_config_file():
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
    
        return (lines[0], lines[1])
    except:
        return (None, None)
    
def bincloud_upload():
    print "Submitting function at 0x%X"%here()

    user, password = read_config_file()

    if user == None:
    	print "Error: Could not read config file. Please check readme.txt to learn how to configure BinCrowd."
    	return

    # Gather details from idb
    p = proxyGraph( here() )
    e = extract_edge_tuples_from_graph( p )
    edges = edges_array_to_dict(e)
    prime = calculate_prime_product_from_graph(here())
    fn = idaapi.get_func(here())
    name = Demangle(idc.GetFunctionName(fn.startEA), idc.GetLongPrm(INF_SHORT_DN))
    if not name:
        name = idc.GetFunctionName(fn.startEA)
    description = idaapi.get_func_cmt(fn, True) #repatable comment
    if not description: description = idaapi.get_func_cmt(fn, False) #non-repeatable
    if not description: description = ''
    inf = idaapi.get_inf_structure()

    # Handle optional parameters. FIX LATER
    functionInformation = {
                'baseAddress'             : idaapi.get_imagebase(),
                'RVA'                     : fn.startEA - idaapi.get_imagebase(),     
                'processor'               : '',# I dont know why but this crashes: inf.procName,
                'operatingSystem'         : 'ida index %d'%inf.ostype, # libfuncs.hpp has index
                'operatingSystemVersion'  : '',
                'language'                : idaapi.get_compiler_name(inf.cc.id),
                'numberOfArguments'       : None,#int  
                'frameSize'               : fn.frsize,
                'frameNumberOfVariables'  : None,#int  
                'idaSignature'            : '' #str
        }
    #idaapi.get_file_type_name()
    # "Portable executable for 80386 (PE)"


    fileInformation = {
                'hashMD5'                 : idc.GetInputMD5(),
                'hashSHA1'                : '',#str 
                'hashSHA256'              : '',#str 
                'name'                    : idc.GetInputFile(),
                'description'             : '' #str NOTEPAD netblob? 
        }

    parameters = {
                 'username':user, 'password':password, 'version':'0.1',
                 'name':name, 'description':description,                                
                 'primeProduct':'%d'%prime, 'edges':edges, 
                 'functionInformation':functionInformation,                                 
                 'fileInformation':fileInformation                                             
                 }
    if DEBUG:
        print "file", fileInformation
        print "func", functionInformation
        print "uploading function info to server"
        print "prime:", prime
        print "edges:", e
    rpc_srv = xmlrpclib.ServerProxy(RPCURI,allow_none=True)
    response = rpc_srv.upload(parameters)
    print "response:", response

def test(self, n):
    print n
    return 1

class MyChoose(Choose):
    def __init__(self, list=[], name="MyChooser", flags=1):          
        Choose.__init__(self, list, name, flags)
        self.width = 80
        self.columntitle = name
        # bincrowd specific:
        self.fn = None
        self.params = None
        """ From idaapi.py
        add_chooser_command(char chooser_caption, char cmd_caption, chooser_cb_t chooser_cb, 
        int menu_index=-1, int icon=-1, 
        int flags=0) -> bool
        """
        #print idaapi.add_chooser_command("test", "test", self)
                                
    def getl(self, n):
        """ wrap idaapi.Choose.getl() function to use a global column title """
        if n == 0:
           return self.columntitle
        if n <= self.sizer():
                return str(self.list[n-1])
        else:
                return "<Empty>"
            
    def enter(self,n):
        if n > 0:
            name        = self.params[n-1]['name']
            description = self.params[n-1]['description']
            print "changing 0x%X name to: %s"%(self.fn.startEA, name)
            idc.MakeName(self.fn.startEA, name)
            if description:
                print "changing comment to:\n%s"%description
                idaapi.set_func_cmt(self.fn, description, True)

    def formatresults(self,results):
        """ build formatted strings of results and store in self.list """
        strlist = []
        for r in results:
            name            = r['name']         if len(r['name'])       <=26  else r['name'][:23]+'...'
            description     = r['description']  if len(r['name'])       <=100 else r['name'][:97]+'...'
            owner           = r['owner']
            degree        = r['matchDegree']
            strlist.append("%-2d %-26s  %s  (%s)"% (degree, name,description, owner,))
        self.list = strlist
        
    # useless because kernwin.i of idapython sets to NULL
    #def destroy(self,n):
    #def get_icon(self,n):

 
def bincloud_download():
    print "requesting information for function at 0x%X"%here()
    user, password = read_config_file()
    
    if user == None:
    	print "Error: Could not read config file. Please check readme.txt to learn how to configure BinCrowd."
    	return

    # Gather details from idb
    p = proxyGraph( here())
    e = extract_edge_tuples_from_graph( p )
    edges = edges_array_to_dict(e)
    prime = calculate_prime_product_from_graph(here())
    fn = idaapi.get_func(here())
    inf = idaapi.get_inf_structure()

    if DEBUG:
        print "prime:", prime
        print "edges:", e
    parameters = {
                 'username':user, 'password':password, 'version':'0.1',
                 'primeProduct':'%d'%prime,'edges':edges, 
                 }
    rpc_srv = xmlrpclib.ServerProxy(RPCURI,allow_none=True)
    response = rpc_srv.download(parameters)
    try:
        (params, methodname) = xmlrpclib.loads(response)
        if DEBUG:
            print "response methodname:", methodname
            print "response data:"
            print params
    except:
        print "response:", response
        return


    # Display results and modify based on selection
    # would be better to use choose2() from idapython src repo
    # flag = 1 = popup. 0 = popup window
    chooser = MyChoose([], "Function matches", 1 | idaapi.CHOOSER_MULTI_SELECTION)
    chooser.columntitle = "name - description (owner, match deg.)"
    chooser.fn = fn
    chooser.params = params
    chooser.formatresults(params)    
    ch = chooser.choose()
    print ch
    chooser.enter(ch)




"""
REGISTER IDA SHORTCUTS
"""
    
print "registering hotkey %s for bincloud_upload()"%UPLOADHOTKEY
idaapi.CompileLine('static _bincloud_upload() { RunPythonStatement("bincloud_upload()"); }')
idc.AddHotkey(UPLOADHOTKEY,"_bincloud_upload")

print "registering hotkey %s for bincloud_download()"%DOWNLOADHOTKEY
idaapi.CompileLine('static _bincloud_download() { RunPythonStatement("bincloud_download()"); }')
idc.AddHotkey(DOWNLOADHOTKEY,"_bincloud_download")
