import sets
import hashlib
import time
import sys
import os
from datetime import datetime
import xmlrpclib
from idaapi import Choose2
import idautils
import locale

DEBUG = False

"""
BINCROWD PARAMETERS
"""
CLIENTVERSION = "1"
UPLOADHOTKEY = "Ctrl-1"
DOWNLOADHOTKEY = "Ctrl-2"
UPLOADALLHOTKEY = "Ctrl-3"
DOWNLOADALLHOTKEY = "Ctrl-4"

# We have to get the script directory globally, it is not set
# anymore when the script is evaluated through the hotkeys.
SCRIPT_DIRECTORY = sys.argv[0]

def debug_print(string):
    if DEBUG:
        print string

class FunctionSelectionDialog(Choose2):
    def __init__(self, title, items):
        Choose2.__init__(self, title, [ ["Match Quality", 10], [ "File", 20 ], ["Function", 20], ["Description", 30], ["Nodes", 8], ["Edges", 8], ["Author", 20] ], Choose2.CH_MODAL)
        self.n = 0
        self.items = items
        self.icon = -1
        self.selcount = 0
        self.popup_names = []

    def OnClose(self):
        pass

    def OnEditLine(self, n):
        self.items[n][1] = self.items[n][1] + "*"

    def OnInsertLine(self):
        self.items.append(self.make_item())

    def OnSelectLine(self, n):
        self.selcount += 1
        Warning("[%02d] selectline '%s'" % (self.selcount, n))

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnDeleteLine(self, n):
        del self.items[n]
        return n

    def OnRefresh(self, n):
        return n

    def OnCommand(self, n, cmd_id):
        pass
        
    def OnGetLineAttr(self, n):
        if self.items[n][0] == "High":
            return [0x00FF00, 0]

class AllFunctionsSelectionDialog(Choose2):
    def __init__(self, title, items):
        Choose2.__init__(self, title, [ [ "Function", 20 ], ["Count", 20] ], Choose2.CH_MODAL)
        self.n = 0
        self.items = items
        self.icon = -1
        self.selcount = 0
        self.popup_names = []

    def OnClose(self):
        pass

    def OnEditLine(self, n):
        self.items[n][1] = self.items[n][1] + "*"

    def OnInsertLine(self):
        self.items.append(self.make_item())

    def OnSelectLine(self, n):
        self.selcount += 1
        Warning("[%02d] selectline '%s'" % (self.selcount, n))

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnDeleteLine(self, n):
        del self.items[n]
        return n

    def OnRefresh(self, n):
        return n

    def OnCommand(self, n, cmd_id):
        pass

class FunctionDescription:
    def __init__( self, user, initialization_tuple ):
        self.user       = user				        # Name of the uploading user
        self.name       = initialization_tuple[0]	# Name of the function
        self.address    = initialization_tuple[1]	# Address of the function in the parent
        self.parentfile = initialization_tuple[2]	# MD5 of the parent executable
        self.primeproduct = initialization_tuple[3]	# prime product of this function
        self.prototype  = initialization_tuple[4]	# prototype string of this function
        self.edges      = initialization_tuple[5]	# list of edge signatures of this function
    def getTuple( self ):
        return (self.user, self.name, self.address, self.parentfile, self.primeproduct,
            self.prototype, self.primeproduct)



class BinCloudRPCClient:
    def __init__( self, servername, username, authtoken ):
        self.username=username
        self.authtoken=authtoken
        self.servername=servername
    
    def query( self, list_of_edges, prime_product ):
        """
            This will return a list of FunctionDescriptions
            
        """
        
        return [ FunctionDescription( ret[0], ret[1:] ) for ret in results ]
    
    def upload( self, list_of_function_tuples ):
        """
            A function tuple consists of:
                name of the function
                address of the function
                parent file MD5 of the function
                prime product of the function
                prototype string of the function
                edge tuples of the function
        """
        
        
        
  

g_Primes = (
    3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,
    127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,
    283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,
    467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,
    661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,
    877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997,1009,1013,1019,1021,1031,1033,1039,1049,1051,1061,1063,1069,
    1087,1091,1093,1097,1103,1109,1117,1123,1129,1151,1153,1163,1171,1181,1187,1193,1201,1213,1217,1223,1229,1231,1237,1249,1259,1277,1279,1283,1289,1291,
    1297,1301,1303,1307,1319,1321,1327,1361,1367,1373,1381,1399,1409,1423,1427,1429,1433,1439,1447,1451,1453,1459,1471,1481,1483,1487,1489,1493,1499,1511,
    1523,1531,1543,1549,1553,1559,1567,1571,1579,1583,1597,1601,1607,1609,1613,1619,1621,1627,1637,1657,1663,1667,1669,1693,1697,1699,1709,1721,1723,1733,
    1741,1747,1753,1759,1777,1783,1787,1789,1801,1811,1823,1831,1847,1861,1867,1871,1873,1877,1879,1889,1901,1907,1913,1931,1933,1949,1951,1973,1979,1987,
    1993,1997,1999,2003,2011,2017,2027,2029,2039,2053,2063,2069,2081,2083,2087,2089,2099,2111,2113,2129,2131,2137,2141,2143,2153,2161,2179,2203,2207,2213,
    2221,2237,2239,2243,2251,2267,2269,2273,2281,2287,2293,2297,2309,2311,2333,2339,2341,2347,2351,2357,2371,2377,2381,2383,2389,2393,2399,2411,2417,2423,
    2437,2441,2447,2459,2467,2473,2477,2503,2521,2531,2539,2543,2549,2551,2557,2579,2591,2593,2609,2617,2621,2633,2647,2657,2659,2663,2671,2677,2683,2687,
    2689,2693,2699,2707,2711,2713,2719,2729,2731,2741,2749,2753,2767,2777,2789,2791,2797,2801,2803,2819,2833,2837,2843,2851,2857,2861,2879,2887,2897,2903,
    2909,2917,2927,2939,2953,2957,2963,2969,2971,2999,3001,3011,3019,3023,3037,3041,3049,3061,3067,3079,3083,3089,3109,3119,3121,3137,3163,3167,3169,3181,
    3187,3191,3203,3209,3217,3221,3229,3251,3253,3257,3259,3271,3299,3301,3307,3313,3319,3323,3329,3331,3343,3347,3359,3361,3371,3373,3389,3391,3407,3413,
    3433,3449,3457,3461,3463,3467,3469,3491,3499,3511,3517,3527,3529,3533,3539,3541,3547,3557,3559,3571,3581,3583,3593,3607,3613,3617,3623,3631,3637,3643,
    3659,3671,3673,3677,3691,3697,3701,3709,3719,3727,3733,3739,3761,3767,3769,3779,3793,3797,3803,3821,3823,3833,3847,3851,3853,3863,3877,3881,3889,3907,
    3911,3917,3919,3923,3929,3931,3943,3947,3967,3989,4001,4003,4007,4013,4019,4021,4027,4049,4051,4057,4073,4079,4091,4093,4099,4111,4127,4129,4133,4139,
    4153,4157,4159,4177,4201,4211,4217,4219,4229,4231,4241,4243,4253,4259,4261,4271,4273,4283,4289,4297,4327,4337,4339,4349,4357,4363,4373,4391,4397,4409,
    4421,4423,4441,4447,4451,4457,4463,4481,4483,4493,4507,4513,4517,4519,4523,4547,4549,4561,4567,4583,4591,4597,4603,4621,4637,4639,4643,4649,4651,4657,
    4663,4673,4679,4691,4703,4721,4723,4729,4733,4751,4759,4783,4787,4789,4793,4799,4801,4813,4817,4831,4861,4871,4877,4889,4903,4909,4919,4931,4933,4937,
    4943,4951,4957,4967,4969,4973,4987,4993,4999,5003,5009,5011,5021,5023,5039,5051,5059,5077,5081,5087,5099,5101,5107,5113,5119,5147,5153,5167,5171,5179,
    5189,5197,5209,5227,5231,5233,5237,5261,5273,5279,5281,5297,5303,5309,5323,5333,5347,5351,5381,5387,5393,5399,5407,5413,5417,5419,5431,5437,5441,5443,
    5449,5471,5477,5479,5483,5501,5503,5507,5519,5521,5527,5531,5557,5563,5569,5573,5581,5591,5623,5639,5641,5647,5651,5653,5657,5659,5669,5683,5689,5693,
    5701,5711,5717,5737,5741,5743,5749,5779,5783,5791,5801,5807,5813,5821,5827,5839,5843,5849,5851,5857,5861,5867,5869,5879,5881,5897,5903,5923,5927,5939,
    5953,5981,5987,6007,6011,6029,6037,6043,6047,6053,6067,6073,6079,6089,6091,6101,6113,6121,6131,6133,6143,6151,6163,6173,6197,6199,6203,6211,6217,6221,
    6229,6247,6257,6263,6269,6271,6277,6287,6299,6301,6311,6317,6323,6329,6337,6343,6353,6359,6361,6367,6373,6379,6389,6397,6421,6427,6449,6451,6469,6473,
    6481,6491,6521,6529,6547,6551,6553,6563,6569,6571,6577,6581,6599,6607,6619,6637,6653,6659,6661,6673,6679,6689,6691,6701,6703,6709,6719,6733,6737,6761,
    6763,6779,6781,6791,6793,6803,6823,6827,6829,6833,6841,6857,6863,6869,6871,6883,6899,6907,6911,6917,6947,6949,6959,6961,6967,6971,6977,6983,6991,6997,
    7001,7013,7019,7027,7039,7043,7057,7069,7079,7103,7109,7121,7127,7129,7151,7159,7177,7187,7193,7207,7211,7213,7219,7229,7237,7243,7247,7253,7283,7297,
    7307,7309,7321,7331,7333,7349,7351,7369,7393,7411,7417,7433,7451,7457,7459,7477,7481,7487,7489,7499,7507,7517,7523,7529,7537,7541,7547,7549,7559,7561,
    7573,7577,7583,7589,7591,7603,7607,7621,7639,7643,7649,7669,7673,7681,7687,7691,7699,7703,7717,7723,7727,7741,7753,7757,7759,7789,7793,7817,7823,7829,
    7841,7853,7867,7873,7877,7879,7883,7901,7907,7919
)

def get_prime1(mnemonic):
    numbers = [ord(c.lower()) - 0x60 for c in mnemonic.strip()]
    numbers.reverse()
    index = reduce(lambda prev,current: prev*32+current, numbers, 0)
    return g_Primes[index % len(g_Primes)]

def get_prime( list_of_mnemonics ):
    initial = 1
    for mnemonic in list_of_mnemonics:
        initial = (initial * get_prime1( mnemonic )) % 2**64
    return initial

class GraphBFS:
    """
    A generic class to perform a BFS traversal of a given graph
    """
    def __init__( self, flowgraph ):
    	self.flowgraph = flowgraph
        self.root = self.find_root( flowgraph.nodes )
        self.layers = []
        self.layers.append( [ self.root ] )
        self.visited = sets.Set()
        work_layer = [ self.root ]
        while len( work_layer ) > 0:
            next_layer = sets.Set()
            for element in work_layer:
                temp_elements = [ x for x in element.children if x not in self.visited ]
                self.visited.update( temp_elements )
                next_layer.update( temp_elements )
                self.layers.append( list( next_layer ))
            work_layer = next_layer 
    def find_root(self, nodes):
        """Finds the root node of a view. Note that this function is a bit imprecise
            but it should do the trick for most views."""
        for node in nodes:
            if len(node.parents) == 0:
                return node
        return nodes[0]
    def get_layer_count( self ):
        return len( self.layers )
    def get_layer( self, index ):
        return self.layers[ index ]
    def get_node_to_layer_index( self ):
        result = {}
        
        # There is a problem with functions that have "weird"
        # shapes (multiple entry nodes, ...). The function for
        # extracting tuples expects all node layers to be
        # initialized but the breadth-first search does not hit
        # all nodes in weird graphs. That's why we do a default
        # value initialization which is later kept for all nodes
        # that are not hit by the breadth-first search.
        for node in self.flowgraph.nodes:
            result [ node ] = 0x31337
        
        for i in range( self.get_layer_count()):
            layer = self.get_layer( i )
            for node in layer:
                result[ node ] = i
        return result

class Foo:
    pass
        
def extract_edge_tuples_from_graph( flowgraph ):
    gBfs = GraphBFS( flowgraph )
    node_to_layer_index = gBfs.get_node_to_layer_index()
    result_tuples = []
    for edge in flowgraph.edges:
        sig = ( len(edge.source.parents), \
            len(edge.source.children), \
            len(edge.target.parents), \
            len(edge.target.children), \
            node_to_layer_index[ edge.source ], \
            node_to_layer_index[ edge.target ],
            edge.source.prime_product,
            edge.source.function_calls,
            edge.target.prime_product,
            edge.target.function_calls
        )
        result_tuples.append( sig )
    return result_tuples

def get_list_of_node_mnemonics(node):
    """ Returns a list of all mnemonics of a node.
    """
    start = node.startEA
    end = node.endEA
    
    mnemonics = []
    
    while start < end:
        mnemonic = idc.GetMnem( start )
        if mnemonic:
            mnemonics.append( mnemonic )
        start = start + 1
    
    return mnemonics
    
def calc_prime_product(node):
    """ Calculates the prime product for the given node.
    """
    return get_prime(get_list_of_node_mnemonics(node))
    
def count_function_calls(node):
    start = node.startEA
    end = node.endEA
    
    calls = 0
    
    while start < end:
        for xref in XrefsFrom(start, 0):
            if xref.type in [16, 17]:
                calls = calls + 1
        
        start = start + 1
        
    return calls

class proxyGraphNode:
    """
        A small stub class to proxy the BinNavi node class into IDA's
        graph class
    """
    def __init__( self, id, parentgraph ):
        self.parent = parentgraph
        self.id = id
        self.prime_product = calc_prime_product(parentgraph.graph[id])
        self.function_calls = count_function_calls(parentgraph.graph[id])
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

def get_list_of_function_mnemonics(address):
    """ Returns a list of all mnemonics found in a function.
    """
    fniter = idaapi.func_item_iterator_t(idaapi.get_func(address))
    
    mnemonics = []
    
    mnemonics.append( idc.GetMnem( fniter.current() ) )
    
    while fniter.next_code():
        mnemonics.append( idc.GetMnem( fniter.current() ) )
    
    return mnemonics
    
def calculate_prime_product_from_graph(address):
    """ Calculates the prime product for the function at the given address.
    """
    return get_prime(get_list_of_function_mnemonics(address))

"""
BINCROWD RPC FUNCTIONS
"""
def edges_array_to_dict(e):
    edges = []
    for tup in e:
        edges.append(
               {'indegree_source'            : tup[0],
                'outdegree_source'           : tup[1],
                'indegree_target'            : tup[2],
                'outdegree_target'           : tup[3],
                'topological_order_source'   : tup[4],
                'topological_order_target'   : tup[5],
                'source_prime'               : "%d" % tup[6],
                'source_call_num'            : tup[7],
                'target_prime'               : "%d" % tup[8],
                'target_call_num'            : tup[9]
            })
                
    return edges

def read_config_file():
    debug_print("Reading configuration file")
    
    directory = os.path.dirname(SCRIPT_DIRECTORY)
    
    configuration_file = directory + "/bincrowd.cfg"
    
    debug_print("Determined script directory: %s" % directory)
    debug_print("Determined configuration file : %s" % configuration_file)

    try:
        config_file = open(configuration_file, "r")
        lines = config_file.readlines()
        config_file.close()
        
        if len(lines) < 3:
            return (None, None, None)
        
        return (lines[0].rstrip("\r\n"), lines[1].rstrip("\r\n"), lines[2].rstrip("\r\n"))
    except:
        return (None, None, None)
    
class UploadReturn:
    UPLOAD_SUCCESS_ADDED = 0
    UPLOAD_SUCCESS_CHANGED = 1
    COULDNT_READ_CONFIG_FILE = 2
    SKIPPED_AUTO_GENERATED = 3
    SKIPPED_INTERNAL_ERROR = 4
    SKIPPED_TOO_SMALL = 5
    UNKNOWN_SERVER_REPLY = 6
    COULDNT_CONNECT_TO_SERVER = 7
    COULDNT_UPLOAD_DATA = 8
    NO_FUNCTION_AT_ADDRESS = 9
    INCOMPLETE_DATA = 10
    INVALID_VERSION_NUMBER = 11
    USER_NOT_AUTHENTICATED = 12
        
class UploadResults:
    """ Contains all possible return values of the upload function.
    """
    
    # Returned if the 'version' argument was not provided by the client.
    MISSING_ARGUMENT_VERSION = 1
    
    # Returned if the 'username' argument was not provided by the client.
    MISSING_ARGUMENT_USERNAME = 2
    
    # Returned if the 'password' argument was not provided by the client.
    MISSING_ARGUMENT_PASSWORD = 3
    
    # Returned if the 'name' argument was not provided by the client.
    MISSING_ARGUMENT_FUNCTION_NAME = 4
    
    # Returned if the 'prime_product' argument was not provided by the client.
    MISSING_ARGUMENT_PRIME_PRODUCT = 5
    
    # Returned if the 'edges' argument was not provided by the client.
    MISSING_ARGUMENT_EDGES = 6
    
    # Returned if any of the edge arguments lack the 'indegree_source' attribute.
    MISSING_ARGUMENT_EDGE_INDEGREE_SOURCE = 7
    
    # Returned if any of the edge arguments lack the 'outdegree_source' attribute.
    MISSING_ARGUMENT_EDGE_OUTDEGREE_SOURCE = 8
    
    # Returned if any of the edge arguments lack the 'indegree_target' attribute.
    MISSING_ARGUMENT_EDGE_INDEGREE_TARGET = 9
    
    # Returned if any of the edge arguments lack the 'outdegree_target' attribute.
    MISSING_ARGUMENT_EDGE_OUTDEGREE_TARGET = 10
    
    # Returned if any of the edge arguments lack the 'topological_order_source' attribute.
    MISSING_ARGUMENT_EDGE_TOPOLOGICAL_ORDER_SOURCE = 11
    
    # Returned if any of the edge arguments lack the 'topological_order_target' attribute.
    MISSING_ARGUMENT_EDGE_TOPOLOGICAL_ORDER_TARGET = 12
    
    # Returned if the file_information argument lacks the 'hash_md5' attribute.
    MISSING_ARGUMENT_MD5_HASH = 13
    
    # Returned if client and server versions are incompatible.
    INVALID_VERSION_NUMBER = 14
    
    # Returned if the provided login credentials could not be used to authenticate the user.
    USER_NOT_AUTHENTICATED = 15
    
    # Returned if a new function was added to the database.
    ADDED_NEW_FUNCTION = 16
    
    # Returned if an existing function was updated.
    UPDATED_EXISTING_FUNCTION = 17

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
            
        if description:
            description = idaapi.idb2scr(description).decode("iso-8859-1")
        
        debug_print("%s: %d %08X" % (name, size, flag))
        
        start += size
        
        if name in [" r", " s"]:
            # Skip return address and base pointer
            current = arguments
            continue
        
        current.append({'name' : name, 'description' : description, 'size' : size, 'flag' : flag})

    return (local_variables, arguments)

def get_demangled_name(ea):
    """ Gets the name of the function at address ea and demangles it.
    """
    name = Demangle(idc.GetFunctionName(ea), idc.GetLongPrm(INF_SHORT_DN))
    if not name:
        name = idc.GetFunctionName(ea)
        
    # The Demangle function returns stuff like FooFunction(x,x,x,x) in IDA 5.6.
    # If you upload such a function name and download it again you get an error
    # because names with parentheses are invalid.
    first_parens = name.find("(")
    if first_parens != -1:
    	name = name[0:first_parens]
    
    return name

def get_imported_function(imported_functions, ea):
    """ Returns the imported function at the given effective address.
        If there is no imported function at that address, None is returned.
    """
    for index in xrange(len(imported_functions)):
        functions = imported_functions[index]
        
        for f_ea, name in functions:
            if ea == f_ea:
                return (idaapi.get_import_module_name(index), name)

    return None
    
def get_processor_name(inf):
    null_idx = inf.procName.find(chr(0))
    if null_idx > 0:
        return inf.procName[:null_idx]
    else:
        return inf.procName
        
def bincrowd_upload(ea=None):
    """ Uploads information for the function at the given ea.
    """
    
    uri, user, password = read_config_file()
    
    if user == None:
    	print "Error: Could not read config file. Please check readme.txt to learn how to configure BinCrowd."
    	return UploadReturn.COULDNT_READ_CONFIG_FILE

    if not ea:
        ea = here()
        
    fn = idaapi.get_func(ea)
    
    if not fn:
        print "No function at address %X" % ea
        return UploadReturn.NO_FUNCTION_AT_ADDRESS

    name = get_demangled_name(fn.startEA)
    
    print "0x%X: Uploading function %s" % (ea, name)
    
    if idaapi.has_dummy_name(idaapi.getFlags(fn.startEA)):
        print "0x%X: '%s' was not uploaded because it has an auto-generated name." % (fn.startEA, name)
        return UploadReturn.SKIPPED_AUTO_GENERATED

    try:
        p = proxyGraph(fn.startEA)
        e = extract_edge_tuples_from_graph(p)
    except Exception, e:
        print "0x%X: '%s' was not uploaded because there was a local error in the edge list." % (fn.startEA, name)
        return UploadReturn.SKIPPED_INTERNAL_ERROR

    if not e:
        print "0x%X: '%s' was not uploaded because it is too small." % (fn.startEA, name)
        return UploadReturn.SKIPPED_TOO_SMALL

    edges = edges_array_to_dict(e)
    prime = calculate_prime_product_from_graph(fn.startEA)
    number_of_nodes = len(p.get_nodes())
    
    #repeatable/non-repeatable
    description = idaapi.get_func_cmt(fn, True) or idaapi.get_func_cmt(fn, False)
    
    if description:
        description = idaapi.idb2scr(description).decode("iso-8859-1")

    md5 = idc.GetInputMD5().lower()
    
    inf = idaapi.get_inf_structure()
    processor = get_processor_name(inf)
    
    (local_variables, arguments) = get_frame_information(ea)
        
    stackFrame = (local_variables, arguments)
    
    # Handle optional parameters.
    functionInformation = {
                'base_address'              : idaapi.get_imagebase(),
                'rva'                       : fn.startEA - idaapi.get_imagebase(),     
                'processor'                 : processor,
                'language'                  : idaapi.get_compiler_name(inf.cc.id),
                'number_of_nodes'           : "%d" % number_of_nodes
                }

    fileInformation = {
                'hash_md5'                 : md5,
                'name'                     : idc.GetInputFile(),
                'description'              : '',
                'operating_system'          : '%d (index defined in libfuncs.hpp?)' % inf.ostype,
                }
    
    parameters = {
                 'username'              : user,
                 'password'              : password,
                 'version'               : CLIENTVERSION,
                 'name'                  : name,
                 'description'           : description,
                 'prime_product'         : '%d' % prime,
                 'edges'                 : edges, 
                 'function_information'  : functionInformation,                                 
                 'file_information'      : fileInformation,
                 'stack_frame'           : stackFrame
                 }
    
    try:
        rpc_srv = xmlrpclib.ServerProxy(uri, allow_none=True)
    except:
        print "Error: Could not connect to BinCrowd server"
        return (UploadReturn.COULDNT_CONNECT_TO_SERVER, None)
        
    try:
        response = rpc_srv.upload(parameters)
    except Exception, e:
        print e
        print "Error: Could not upload data"
        return (UploadReturn.COULDNT_UPLOAD_DATA, None)
        
    if response in [
        UploadResults.MISSING_ARGUMENT_VERSION,
        UploadResults.MISSING_ARGUMENT_USERNAME,
        UploadResults.MISSING_ARGUMENT_PASSWORD,
        UploadResults.MISSING_ARGUMENT_FUNCTION_NAME,
        UploadResults.MISSING_ARGUMENT_PRIME_PRODUCT,
        UploadResults.MISSING_ARGUMENT_EDGES,
        UploadResults.MISSING_ARGUMENT_EDGE_INDEGREE_SOURCE,
        UploadResults.MISSING_ARGUMENT_EDGE_OUTDEGREE_SOURCE,
        UploadResults.MISSING_ARGUMENT_EDGE_INDEGREE_TARGET,
        UploadResults.MISSING_ARGUMENT_EDGE_OUTDEGREE_TARGET,
        UploadResults.MISSING_ARGUMENT_EDGE_TOPOLOGICAL_ORDER_SOURCE,
        UploadResults.MISSING_ARGUMENT_EDGE_TOPOLOGICAL_ORDER_TARGET,
        UploadResults.MISSING_ARGUMENT_MD5_HASH
        ]:
        print "Error: Uploaded incomplete data (Error code %d)" % response
        return UploadReturn.INCOMPLETE_DATA
    elif response == UploadResults.INVALID_VERSION_NUMBER:
        print "Error: Client uploaded an invalid version number"
        return UploadReturn.INVALID_VERSION_NUMBER
    elif response == UploadResults.USER_NOT_AUTHENTICATED:
        print "Error: User could not be authenticated by the server"
        return UploadReturn.USER_NOT_AUTHENTICATED
    elif response == UploadResults.ADDED_NEW_FUNCTION:
        print "Added new function"
        return UploadReturn.UPLOAD_SUCCESS_ADDED
    elif response == UploadResults.UPDATED_EXISTING_FUNCTION:
        print "Updated existing function"
        return UploadReturn.UPLOAD_SUCCESS_CHANGED
    else:
        print "Error: Unknown server reply ", response
        return UploadReturn.UNKNOWN_SERVER_REPLY

def is_showstopper_upload_return_value(ret_val):
    """ Determines whether an upload return value is important enough
        to completely stop and 'Upload All' operation.
    """
    return ret_val in [
        UploadReturn.COULDNT_READ_CONFIG_FILE,
        UploadReturn.COULDNT_CONNECT_TO_SERVER,
        UploadReturn.COULDNT_UPLOAD_DATA,
        UploadReturn.NO_FUNCTION_AT_ADDRESS,
        UploadReturn.INCOMPLETE_DATA,
        UploadReturn.INVALID_VERSION_NUMBER,
        UploadReturn.USER_NOT_AUTHENTICATED
    ]
        
def bincrowd_upload_all():
    """ Uploads information about all functions in the IDB.
    """
    upload_stats = [0, 0, 0, 0, 0, 0, 0]
    
    functions = Functions(0, 0xFFFFFFFF)
    
    for function_ea in functions:
        name = idc.GetFunctionName(function_ea)
        
        ret_val = bincrowd_upload(function_ea)
        
        if is_showstopper_upload_return_value(ret_val):
            print "Stopping upload of all functions"
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
        degree          = r['match_degree']
        file            = r['file']           if len(r['file'])       <=26  else r['file'][:23]+'...'
        name            = r['name']           if len(r['name'])       <=26  else r['name'][:23]+'...'
        description     = r['description']    if len(r['description'])<=100 else r['description'][:97]+'...'
        numberOfNodes   = r['number_of_nodes']
        numberOfEdges   = r['number_of_edges']
        owner           = r['owner']
        strlist.append([MATCHDEGREE_STRINGS[degree], file, name, description, "%d (%d)" % (numberOfNodes, numberOfNodes - currentNodeCount), "%d (%d)" % (numberOfEdges, numberOfEdges - currentEdgeCount), owner])
        
    return strlist
        
class DownloadReturn:
    SUCCESS = 0
    COULDNT_READ_CONFIG_FILE = 1
    COULDNT_RETRIEVE_DATA = 2
    COULDNT_CONNECT_TO_SERVER = 3
    FUNCTION_TOO_SMALL = 4
    INCOMPLETE_DATA = 5
    INVALID_VERSION_NUMBER = 6
    USER_NOT_AUTHENTICATED = 7
    NO_MATCHES_FOUND = 8
    NO_FUNCTION_AT_ADDRESS = 9
    
class DownloadImportedResults:
    """ Contains all possible return values of the download imported function.
    """
    
    # Returned if the 'version' argument was not provided by the client.
    MISSING_ARGUMENT_VERSION = 1
    
    # Returned if the 'username' argument was not provided by the client.
    MISSING_ARGUMENT_USERNAME = 2
    
    # Returned if the 'password' argument was not provided by the client.
    MISSING_ARGUMENT_PASSWORD = 3
    
    # Returned if the 'module' argument was not provided by the client.
    MISSING_ARGUMENT_MODULE = 4
    
    # Returned if the 'name' argument was not provided by the client.
    MISSING_ARGUMENT_FUNCTION_NAME = 5
    
    # Returned if client and server versions are incompatible.
    INVALID_VERSION_NUMBER = 6
    
    # Returned if the provided login credentials could not be used to authenticate the user.
    USER_NOT_AUTHENTICATED = 7
    
    # Returned if no matches for the uploaded functions were found.
    NO_MATCHES_FOUND = 8

def download_imported_function(module, name):
    """ Downloads information about an imported function
    """

    print "Downloading information for %s!%s" % (module, name)

    uri, user, password = read_config_file()
        
    try:
        rpc_srv = xmlrpclib.ServerProxy(uri, allow_none=True)
    except:
        print "Error: Could not connect to BinCrowd server"
        return (DownloadReturn.COULDNT_CONNECT_TO_SERVER, None)
        
    parameters = {
                 'username' : user,
                 'password' : password,
                 'version'  : CLIENTVERSION,
                 'module'   : module,
                 'name'     : name
                 }
                 
    try:
        response = rpc_srv.download_imported(parameters)
    except:
        print "Error: Could not download data"
        return (DownloadReturn.COULDNT_DOWNLOAD_DATA, None)

    if response in [
        DownloadImportedResults.MISSING_ARGUMENT_VERSION,
        DownloadImportedResults.MISSING_ARGUMENT_USERNAME,
        DownloadImportedResults.MISSING_ARGUMENT_PASSWORD,
        DownloadImportedResults.MISSING_ARGUMENT_MODULE,
        DownloadImportedResults.MISSING_ARGUMENT_FUNCTION_NAME
    ]:
        print "Error: Uploaded incomplete data (Error code %d)" % response
        return (DownloadReturn.INCOMPLETE_DATA, None)
    elif response == DownloadImportedResults.INVALID_VERSION_NUMBER:
        print "Error: Client uploaded an invalid version number"
        return (DownloadReturn.INVALID_VERSION_NUMBER, None)
    elif response == DownloadImportedResults.USER_NOT_AUTHENTICATED:
        print "Error: User could not be authenticated by the server"
        return (DownloadReturn.USER_NOT_AUTHENTICATED, None)
    elif response == DownloadImportedResults.NO_MATCHES_FOUND:
        return (DownloadReturn.NO_MATCHES_FOUND, None)
        
    try:
        (params, methodname) = xmlrpclib.loads(response)
        clean_params(params)
        return (DownloadReturn.SUCCESS, params)
    except:
        print response
        return (DownloadReturn.COULDNT_RETRIEVE_DATA, None)

class DownloadResults:
    """ Contains all possible return values of the download function.
    """
    
    # Returned if the 'version' argument was not provided by the client.
    MISSING_ARGUMENT_VERSION = 1
    
    # Returned if the 'username' argument was not provided by the client.
    MISSING_ARGUMENT_USERNAME = 2
    
    # Returned if the 'password' argument was not provided by the client.
    MISSING_ARGUMENT_PASSWORD = 3
    
    # Returned if the 'prime_product' argument was not provided by the client.
    MISSING_ARGUMENT_PRIME_PRODUCT = 4
    
    # Returned if the 'edges' argument was not provided by the client.
    MISSING_ARGUMENT_EDGES = 5
    
    # Returned if any of the edge arguments lack the 'indegree_source' attribute.
    MISSING_ARGUMENT_EDGE_INDEGREE_SOURCE = 6
    
    # Returned if any of the edge arguments lack the 'outdegree_source' attribute.
    MISSING_ARGUMENT_EDGE_OUTDEGREE_SOURCE = 7
    
    # Returned if any of the edge arguments lack the 'indegree_target' attribute.
    MISSING_ARGUMENT_EDGE_INDEGREE_TARGET = 8
    
    # Returned if any of the edge arguments lack the 'outdegree_target' attribute.
    MISSING_ARGUMENT_EDGE_OUTDEGREE_TARGET = 9
    
    # Returned if any of the edge arguments lack the 'topological_order_source' attribute.
    MISSING_ARGUMENT_EDGE_TOPOLOGICAL_ORDER_SOURCE = 10
    
    # Returned if any of the edge arguments lack the 'topological_order_target' attribute.
    MISSING_ARGUMENT_EDGE_TOPOLOGICAL_ORDER_TARGET = 11
    
    # Returned if client and server versions are incompatible.
    INVALID_VERSION_NUMBER = 12
    
    # Returned if the provided login credentials could not be used to authenticate the user.
    USER_NOT_AUTHENTICATED = 13
    
    # Returned if no matches for the uploaded functions were found.
    NO_MATCHES_FOUND = 14

def clean_params(params):
    for param in params:
        for k, v in param.items():
            if type(v) == type(u""):
                param[k] = idaapi.scr2idb(v.encode("iso-8859-1", "ignore"))
            if type(v) == type([]):
                clean_params(v[0])
                clean_params(v[1])
    
def download_regular_function(ea):
    """ Downloads information about the regular function at the given ea
    """
    uri, user, password = read_config_file()
    
    if user == None:
    	print "Error: Could not read config file. Please check readme.txt to learn how to configure BinCrowd."
    	return (DownloadReturn.COULDNT_READ_CONFIG_FILE, None)
    	
    fn = idaapi.get_func(ea)
    
    if not fn:
        return (DownloadReturn.NO_FUNCTION_AT_ADDRESS, None)
    
    p = proxyGraph(fn.startEA)
    inf = idaapi.get_inf_structure()

    print "Downloading information for %s" % get_function_name(ea)

    e = extract_edge_tuples_from_graph(p)
    edges = edges_array_to_dict(e)
    
    if not edges:
        return (DownloadReturn.FUNCTION_TOO_SMALL, None)
    
    prime = calculate_prime_product_from_graph(fn.startEA)

    parameters = {
                 'username'       : user,
                 'password'       : password,
                 'version'        : CLIENTVERSION,
                 'prime_product'  : '%d' % prime,
                 'edges'          : edges, 
                 }
    try:
        rpc_srv = xmlrpclib.ServerProxy(uri, allow_none=True)
        response = rpc_srv.download(parameters)
    except Exception, e:
        print "Error: Could not connect to BinCrowd server"
        print e
        return (DownloadReturn.COULDNT_CONNECT_TO_SERVER, None)
        
    if response in [
        DownloadResults.MISSING_ARGUMENT_VERSION,
        DownloadResults.MISSING_ARGUMENT_USERNAME,
        DownloadResults.MISSING_ARGUMENT_PASSWORD,
        DownloadResults.MISSING_ARGUMENT_PRIME_PRODUCT,
        DownloadResults.MISSING_ARGUMENT_EDGES,
        DownloadResults.MISSING_ARGUMENT_EDGE_INDEGREE_SOURCE,
        DownloadResults.MISSING_ARGUMENT_EDGE_OUTDEGREE_SOURCE,
        DownloadResults.MISSING_ARGUMENT_EDGE_INDEGREE_TARGET,
        DownloadResults.MISSING_ARGUMENT_EDGE_OUTDEGREE_TARGET,
        DownloadResults.MISSING_ARGUMENT_EDGE_TOPOLOGICAL_ORDER_SOURCE,
        DownloadResults.MISSING_ARGUMENT_EDGE_TOPOLOGICAL_ORDER_TARGET
    ]:
        print "Error: Uploaded incomplete data (Error code %d)" % response
        return (DownloadReturn.INCOMPLETE_DATA, None)
    elif response == DownloadResults.INVALID_VERSION_NUMBER:
        print "Error: Client uploaded an invalid version number"
        return (DownloadReturn.INVALID_VERSION_NUMBER, None)
    elif response == DownloadResults.USER_NOT_AUTHENTICATED:
        print "Error: User could not be authenticated by the server"
        return (DownloadReturn.USER_NOT_AUTHENTICATED, None)
    elif response == DownloadResults.NO_MATCHES_FOUND:
        return (DownloadReturn.NO_MATCHES_FOUND, None)
        
    try:
        (params, methodname) = xmlrpclib.loads(response.encode("utf-8"))
        clean_params(params)
        return (DownloadReturn.SUCCESS, params)
    except Exception, e:
        print e
        print response
        return (DownloadReturn.COULDNT_RETRIEVE_DATA, None)
        
imported_functions = []

def imported_functions_callback(ea, name, ord):
    """ Callback function for enumerating all imported functions of a module.
    """
    imported_functions[-1].append((ea, name))
    return 1

def fill_imported_functions():
    """ Fills the global imported_functions variable.
    """
    for import_index in xrange(idaapi.get_import_module_qty()):
        imported_functions.append([])
        idaapi.enum_import_names(import_index, imported_functions_callback)

def fill_imported_functions_if_necessary():
    """ Fills the global imported_functions variable if it has not yet been filled.
    """
    if len(imported_functions) == 0:
        fill_imported_functions()
            
def download_without_application(ea):
    """ Downloads information about the function at the given ea without applying
        that information to the IDB file.
    """
    fill_imported_functions_if_necessary()

    imported_function = get_imported_function(imported_functions, ea)
    
    if imported_function:
        (module, name) = imported_function
        return download_imported_function(module, name)
    else:
        return download_regular_function(ea)
 
def set_normal_information(information, fn):
    """ Assigns downloaded information to the given function.
    """
    name        = information['name']
    description = information['description']
    idc.MakeName(fn.startEA, name)
    if description:
        idaapi.set_func_cmt(fn, description, True)
           
    (idb_lv, idb_args) = get_frame_information(fn.startEA)
    (local_variables, arguments) = information['stack_frame']
        
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

def get_graph_data(ea):
    """ Finds the number of nodes and edges for the function at the given ea.
        If that function is an imported function, (0, 0) is returned.
    """
    imported_function = get_imported_function(imported_functions, ea)
    
    if imported_function:
        return (0, 0)
    else:
        fn = idaapi.get_func(ea)
        
        if not fn:
            raise "Internal Error: No function at the given ea"
        
        p = proxyGraph(fn.startEA)
        
        return (len(p.get_nodes()), len(p.get_edges()))

def set_import_information(information, ea):
    """ Sets the repeatable comment of the imported function at the given ea
        to whatever information was returnd from the server
    """
    (local_variables, arguments) = information['stack_frame']
            
    description = information['description']
            
    if len(arguments) > 0:
        description = description + "\n"
            
    for argument in arguments:
        description = description + "\n" + argument['name'] + ": " + argument['description']
            
    idaapi.set_cmt(ea, description, True)
    
def set_information(ea, information):
    """ Assigns downloaded information to the function at the given ea.
    """
    
    print "Assigning information to function %s" % get_function_name(ea)
    
    imported_function = get_imported_function(imported_functions, ea)
        
    if imported_function:
        set_import_information(information, ea)
    else:
        set_normal_information(information, idaapi.get_func(ea))
        
def bincrowd_download(ea = None):
    """ Downloads information for the function at the given ea.
    """
    if not ea:
        ea = here()

    (error_code, params) = download_without_application(ea)
    
    if error_code != DownloadReturn.SUCCESS:
    	return
    	
    if len(params) == 0:
        print "No information for function '%s' available" % get_function_name(ea)
        return
        
    nodes, edges = get_graph_data(ea)
    
    c = FunctionSelectionDialog("Retrieved Function Information", formatresults(params, nodes, edges))
    selected_row = c.Show(True)
    
    if selected_row >= 0:
        set_information(ea, params[selected_row])

def get_information_all_functions(result):
    result_list = []
    
    for ea, (error_code, params) in result.items():
        if error_code == DownloadReturn.SUCCESS and len(params) > 0:
            result_list.append([ea, len(params)])
    
    return sorted(result_list, lambda x, y : y[1] - x[1])
    
def get_function_name(ea):
    """ Returns the name of the function at the given address.
    """
    imported_function = get_imported_function(imported_functions, ea)
    
    if imported_function:
        return imported_function[1] + " (Imported)"
    else:
        return idc.GetFunctionName(ea)
     
def get_display_information_all_functions(information, perfect_match_count):
    """
    Converts information returned from get_information_all_functions and
    turns that information into something that can be displayed in a
    chooser2 dialog.
    """
    
    return [["Apply all top matches", "%d" % perfect_match_count]] + [[get_function_name(ea), "%d" % count] for [ea, count] in information]
    
def get_single_file_information(result, selected_ea):
    return [r for r in result[selected_ea][1]]

def count_perfect_matches(result):
    perfect_match_count = 0
    
    for ea, (error_code, params) in result.items():
        if error_code == DownloadReturn.SUCCESS and len(params) > 0:
            for param in params:
                if param['match_degree'] == 1:
                    perfect_match_count = perfect_match_count + 1
                    break
            
    return perfect_match_count
    
def apply_all_perfect_matches(result):
    # TODO: There can be many perfect matches returned for one function
    #       Find a way to determine a priority for them.
    for ea, (error_code, params) in result.items():
        if error_code == DownloadReturn.SUCCESS and len(params) > 0:
            for param in params:
                if param['match_degree'] == 1:
                    set_information(ea, param)
    
def bincrowd_download_all():
    """
    Downloads information for all functions of the given file and lets
    the user choose what information he wants to accept.
    """
    
    result = { }     # ea => (error_code, information)
    
    fill_imported_functions_if_necessary()

    # Download all imported functions
    for index in xrange(len(imported_functions)):
        for function_ea, name in imported_functions[index]:
            (error_code, params) = download_without_application(function_ea)
            result[function_ea] = (error_code, params)
        
            if error_code == DownloadReturn.SUCCESS:
                for i in xrange(len(params)):
                    file = params[i]['file']
            else:
                pass # Do some error handling in the future
        
    # Download all regular functions
    for function_ea in Functions(0, 0xFFFFFFFF):
        (error_code, params) = download_without_application(function_ea)
        result[function_ea] = (error_code, params)
        
        if error_code == DownloadReturn.SUCCESS:
            for i in xrange(len(params)):
                file = params[i]['file']
        else:
            pass # Do some error handling in the future
    
    while True:
        # Let the user pick for what target function he wants to copy information
        all_functions_information = get_information_all_functions(result)
        perfect_match_count = count_perfect_matches(result)
        all_functions_dialog = AllFunctionsSelectionDialog("All Functions", get_display_information_all_functions(all_functions_information, perfect_match_count))
        selected_function = all_functions_dialog.Show(True)
        
        if selected_function == -1:
            break
            
        if selected_function == 0:
            apply_all_perfect_matches(result)
        else:
            # Correct for the "Apply All" row
            selected_function = selected_function - 1
        
            # Let the user pick for what downloaded information he wants to use for his target function
            selected_ea = all_functions_information[selected_function][0]
            
            idc.Jump(selected_ea)

            nodes, edges = get_graph_data(selected_ea)
            
            function_information = get_single_file_information(result, selected_ea)
            function_selection_dialog = FunctionSelectionDialog("Retrieved Function Information", formatresults(function_information, nodes, edges))
            selected_row = function_selection_dialog.Show(True)
             
            if selected_row != -1:
                set_information(selected_ea, function_information[selected_row])
    
            
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
