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
import string
from operator import mul

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
        Choose2.__init__(self, title, [ [ "Function", 20 ], ["High", 6 | Choose2.CHCOL_DEC], ["Medium", 6 | Choose2.CHCOL_DEC], ["Low", 6 | Choose2.CHCOL_DEC], ["Edges", 20 | Choose2.CHCOL_DEC] ], Choose2.CH_MODAL)
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
        self.user       = user                        # Name of the uploading user
        self.name       = initialization_tuple[0]    # Name of the function
        self.address    = initialization_tuple[1]    # Address of the function in the parent
        self.parentfile = initialization_tuple[2]    # MD5 of the parent executable
        self.primeproduct = initialization_tuple[3]    # prime product of this function
        self.prototype  = initialization_tuple[4]    # prototype string of this function
        self.edges      = initialization_tuple[5]    # list of edge signatures of this function
    def getTuple( self ):
        return (self.user, self.name, self.address, self.parentfile, self.primeproduct,
            self.prototype, self.primeproduct)

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

def char_to_index(c):
    return ord(c.lower()) - 0x60

def position_aware_mult(prev, current):
    return prev * 32 + current

def get_prime1(mnemonic):
    numbers = reversed(map(char_to_index, mnemonic.strip()))
    index = reduce(position_aware_mult, numbers, 0)
    return g_Primes[index % len(g_Primes)]

def get_prime(list_of_mnemonics):
    return reduce(mul, map(get_prime1, list_of_mnemonics), 1) % 2**64

class proxyGraphNode:
    """
        A small stub class to proxy the BinNavi node class into IDA's
        graph class
    """
    def __init__( self, id, parentgraph ):
        self.parent = parentgraph
        self.id = id
        self.prime_product, self.function_calls = calculate_node_values(parentgraph.graph[id])
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

def is_call_reference(xref):
    """ Determines whether a given xref is a call reference.

        Parameters:
          - xref : The xref to check.

        Returns:
          True, if the xref is a call reference. False, otherwise.
    """
    return xref.type == 16 or xref.type == 17

def is_call(ea):
    """ Determines whether the instruction at the given ea is a call instruction.

        Parameters:
          - ea : The ea of the instruction to check.

        Returns:
          True, if the instruction at ea is a call instruction. False, otherwise.
    """
    xref = idaapi.xrefblk_t()

    if xref.first_from(ea, idaapi.XREF_FAR):
        if is_call_reference(xref):
            return True
        while xref.next_from():
            if is_call_reference(xref):
                return True

    return False

def calculate_node_values(node):
    """ Calculates the prime product and the number of outgoing calls for a control
        flow graph node.

        Parameters:
          - node : The node for which the values are calculated.

        Returns:
          A pair of the prime product of the node and the number of outgoing calls.
    """
    start = node.startEA
    end = node.endEA

    calls = 0
    mnemonics = []

    while start < end:
        if is_call(start):
            calls = calls + 1

        mnemonics.append(idaapi.ua_mnem(start))
        start = idaapi.next_head(start, end)

    return (get_prime(mnemonics), calls)

def calculate_prime_product(graph):
    """ Calculates the prime product of a graph.

        Parameters:
          - graph : The graph to calculate the prime product for.

        Returns:
          The prime product of the graph.
    """
    prime = 1

    for node in graph.get_nodes():
        prime = (prime * node.prime_product) % 2**64

    return prime

def edges_array_to_dict(edges):
    """ Takes a list of edges and converts them into a list of maps that
        can be sent to the BinCrowd server.

        Parameters:
          - A list of edges.

        Returns:
          A list of the same cardinality where every edge of the input map
          is described in a way that can be understood by the BinCrowd server.
    """
    output_list = []
    for (indegree_source, outdegree_source, indegree_target, outdegree_target, topological_order_source, topological_order_target, source_prime, source_call_num, target_prime, target_call_num) in edges:
        output_list.append(
               {'indegree_source'            : indegree_source,
                'outdegree_source'           : outdegree_source,
                'indegree_target'            : indegree_target,
                'outdegree_target'           : outdegree_target,
                'topological_order_source'   : topological_order_source,
                'topological_order_target'   : topological_order_target,
                'source_prime'               : "%d" % source_prime,
                'source_call_num'            : source_call_num,
                'target_prime'               : "%d" % target_prime,
                'target_call_num'            : target_call_num
            })

    return output_list

def read_config_file():
    """ Reads the BinCrowd IDA plugin configuration file.

        Returns:
          A triple of (url, username, password) which describes the location
          of the BinCrowd server and how to access it. If anything goes wrong,
          (None, None, None) is returned.
    """
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

def get_frame_information(ea):
    """ Analyzes the stack frame of the function at the given ea for information
        that is important to BinCrowd.

        Parameters:
          - ea : The ea of the function whose stack frame should be analyzed.

        Returns:
          A pair of local local variables and arguments found in the stack frame.
    """
    local_variables = [ ]
    arguments = [ ]
    current = local_variables

    frame = idc.GetFrame(ea)

    if frame == None:
        return [[], []]

    first = start = idc.GetFirstMember(frame)
    end = idc.GetLastMember(frame)

    # There are some really screwed up frames of millions and billions of bytes.
    # We need an upper limit, otherwise we'll loop forever.
    #
    # TODO: Find a better way to loop through the frame.
    while start <= end and start <= first + 10000:
        size = idc.GetMemberSize(frame, start)

        if size == None:
            start = start + 1
            continue

        name = idc.GetMemberName(frame, start)
        description = idc.GetMemberComment(frame, start, True) \
            or idc.GetMemberComment(frame, start, False) or '' #repeatable/non-repeatable

        description = idaapi.idb2scr(description).decode("iso-8859-1")

        debug_print("%s: %d" % (name, size))

        start += size

        if name in [" r", " s"]:
            # Skip return address and base pointer
            current = arguments
            continue

        current.append({'name' : name, 'description' : description, 'size' : size})

    return (local_variables, arguments)

def get_demangled_name(ea):
    """ Gets the name of the function at address ea and demangles it.

        Parameters:
          - ea : The ea of the function.

        Returns:
          The demangled name of the function.
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

def get_imported_function(ea):
    """ Searches through an array of imported functions for the imported function at ea.

        Parameters:
          - imported_functions : A list of list of imported_functions where each element
                                 of the list contains the imported functions of the imported
                                 library with the same index.
          - ea                 : The ea to search for.

        Returns:
          Returns a pair of module name and imported function name if an imported function
          was found at the given effective address. If there is no imported function at that
          address, None is returned.
    """
    fill_imported_functions_if_necessary()

    for index in xrange(len(imported_functions)):
        functions = imported_functions[index]

        for f_ea, name in functions:
            if ea == f_ea:
                return (idaapi.get_import_module_name(index), name)

    return None

def get_processor_name(inf):
    """ Determines the processor name for which the disassembled binary was generated.

        Parameters:
          - inf : The inf structure of the IDB file.

        Returns:
          The processor name for which the IDB was generated.
    """
    null_idx = inf.procName.find(chr(0))
    if null_idx > 0:
        return inf.procName[:null_idx]
    else:
        return inf.procName

class UploadReturn:
    SUCCESS = 0
    COULDNT_READ_CONFIG_FILE = 1
    COULDNT_CONNECT_TO_SERVER = 2
    COULDNT_UPLOAD_DATA = 3
    INCOMPLETE_DATA = 4
    INVALID_VERSION_NUMBER = 5
    USER_NOT_AUTHENTICATED = 6
    FUNCTION_TOO_SMALL = 7
    INTERNAL_ERROR = 8
    NO_FUNCTION_AT_ADDRESS = 9
    NO_FUNCTIONS_FOUND = 11

def get_regular_function_upload_params(fn):
    """ Calculates the parameters to be sent when the given function is uploaded

        Parameters:
          - fn : The function for which the upload parameters are generated.

        Returns:
          A pair of (error code, function description) where error code describes
          whether the parameter generation was successful and function description
          is a description of the function that can be sent to the BinCrowd server.
    """

    name = get_function_name(fn.startEA)

    p = proxyGraph(fn.startEA)
    e = extract_edge_tuples_from_graph(p)

    if not e:
        print "0x%X: '%s' was not uploaded because it is too small." % (fn.startEA, name)
        return (UploadReturn.FUNCTION_TOO_SMALL, None)

    edges = edges_array_to_dict(e)
    prime = calculate_prime_product(p)
    number_of_nodes = len(p.get_nodes())

    #repeatable/non-repeatable
    fn2 = idaapi.get_func(fn.startEA)
    description = idaapi.get_func_cmt(fn2, True) or idaapi.get_func_cmt(fn2, False) or ''

    if description:
        description = idaapi.idb2scr(description).decode("iso-8859-1")

    inf = idaapi.get_inf_structure()
    processor = get_processor_name(inf)

    (local_variables, arguments) = get_frame_information(fn.startEA)

    stackFrame = (local_variables, arguments)

    # Handle optional parameters.
    functionInformation = {
                'base_address'              : idaapi.get_imagebase(),
                'rva'                       : fn.startEA - idaapi.get_imagebase(),
                'processor'                 : processor,
                'language'                  : idaapi.get_compiler_name(inf.cc.id),
                'number_of_nodes'           : "%d" % number_of_nodes
                }

    return (0, {'name'                  : name,
             'description'           : description,
             'prime_product'         : '%d' % prime,
             'edges'                 : edges,
             'function_information'  : functionInformation,
             'stack_frame'           : stackFrame
    })

class UploadResults:
    """ Contains all possible return values of the upload function.
    """
    # Returned if the upload process completed successfully.
    SUCCESS = 0

    # Returned if client and server versions are incompatible.
    INVALID_VERSION_NUMBER = 1

    # Returned if the provided login credentials could not be used to authenticate the user.
    USER_NOT_AUTHENTICATED = 2

    # Returned if the data sent from the client to the server was malformed.
    MALFORMED_INPUT = 3

    # Returned if an unexpected error happened on the server
    INTERNAL_ERROR = 4

def upload(functions):
    """ Uploads information about a list of functions to the BinCrowd server.

        Parameters:
          - functions : The functions whose information should be uploaded.

        Returns:
          A pair of (error code, response list) where error code is an UploadReturn
          value that gives information about what happened and response list is a list
          of responses received for each uploaded function in case the upload was
          completed successfully.
    """

    uri, user, password = read_config_file()

    if user == None:
        print "Error: Could not read config file. Please check readme.txt to learn how to configure BinCrowd."
        return (UploadReturn.COULDNT_READ_CONFIG_FILE, None)

    parameters = []
    for fn in functions:
        (error_code, params) = get_regular_function_upload_params(fn)

        if params:
            parameters.append(params)

    if not parameters:
      return (UploadReturn.NO_FUNCTIONS_FOUND, None)

    print "Starting upload: %s" % datetime.now()

    try:
        rpc_srv = xmlrpclib.ServerProxy(uri, allow_none=True)
    except:
        print "Error: Could not connect to BinCrowd server"
        return (UploadReturn.COULDNT_CONNECT_TO_SERVER, None)

    md5 = idc.GetInputMD5().lower()
    inf = idaapi.get_inf_structure()

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
                 'file_information'      : fileInformation,
                 'functions'             : parameters
                 }

    # Ok, cut the upload into small chunks
    try:
        (error_code, response_list) = rpc_srv.upload(parameters)
    except Exception, e:
        print e
        print "Error: Could not upload data"
        return (UploadReturn.COULDNT_UPLOAD_DATA, None)

    if error_code == UploadResults.SUCCESS:
        print "Upload complete: %s" % datetime.now()
        return (UploadReturn.SUCCESS, response_list)
    elif error_code == UploadResults.MALFORMED_INPUT:
        print "Error: Incomplete data was sent to server"
        return (UploadReturn.INCOMPLETE_DATA, None)
    elif error_code == UploadResults.INVALID_VERSION_NUMBER:
        print "Error: Invalid version number was sent to server"
        return (UploadReturn.INVALID_VERSION_NUMBER, None)
    elif error_code == UploadResults.USER_NOT_AUTHENTICATED:
        print "Error: Server could not authenticate user"
        return (UploadReturn.USER_NOT_AUTHENTICATED, None)
    elif error_code == UploadResults.INTERNAL_ERROR:
        print "Error: Internal server error (%s)" % response_list
        return (UploadReturn.INTERNAL_ERROR, None)
    else:
        print "Unknown response code %d" % error_code
        return (None, None)

def bincrowd_upload_internal(ea=None):
    """ Uploads information for the function at the given ea.

        Parameters:
          - ea : The ea of the function whose information is uploaded.

        Returns:
          A pair of (error code, response list) where error code is an UploadReturn
          value that gives information about what happened and response list is a list
          of responses received for each uploaded function in case the upload was
          completed successfully.
    """

    if not ea:
        ea = here()

    fn = idaapi.get_func(ea)

    if not fn:
        return (UploadReturn.NO_FUNCTION_AT_ADDRESS, None)

    (error_code, result) = upload([fn])

    if error_code == UploadReturn.SUCCESS:
        if result[0] == 0:
            print "Upload was successful: Changed existing function"
        else:
            print "Upload was successful: Added new function"

def bincrowd_upload(ea=None):
    """ Uploads information for the function at the given ea.

        Parameters:
          - ea : The ea of the function whose information is uploaded.

        Returns:
          Nothing.
    """
    try:
        bincrowd_upload_internal(ea)
    except Exception, e:
        print e

class MyFunction:
    """ This is needed for a ridiculous workaround. In the upload_internal function we create the list of
        all functions of in an IDB file. Apparently there is a fixed size buffer in IDA of 128 func_t objects
        that can exist at the same time. So when we have more than 128 functions in an IDB file we get a
        collision and everything breaks down.
    """
    def __init__(self, ea):
        self.startEA = ea

def bincrowd_upload_all_internal():
    """ Uploads information about all functions in the IDB.
    """
    functions_to_upload = []

    for ea in Functions(0, 0xFFFFFFFF):
#        fn = idaapi.get_func(ea)
#        functions_to_upload.append(fn)
        functions_to_upload.append(MyFunction(ea))

    result_list = []

    temp_last = len(functions_to_upload)
    temp_range = range( 0, len(functions_to_upload), 1000 )
    for i in range( 1, len(temp_range)):
        lower = temp_range[i-1]
        upper = temp_range[i]
        print "Uploading functions %d to %d" % (lower, upper)
        (error_code, tempresults) = upload( functions_to_upload[ lower : upper ] )

        if error_code != UploadReturn.SUCCESS:
            return

        result_list = result_list + tempresults

    print "Uploading last chunk"
    if len(temp_range) > 0:
        (error_code, tempresults) = upload( functions_to_upload[ temp_range[-1]:] )
    else:
        (error_code, tempresults) = upload( functions_to_upload[0:] )

    if error_code != UploadReturn.SUCCESS:
        return

    result_list = result_list + tempresults

    total_functions = len(functions_to_upload)
    uploaded_functions = len(result_list)
    added_functions = sum(result_list)
    updated_functions = uploaded_functions - added_functions

    print "All function information was uploaded"
    print "  Successful: %d (%.02f%%)" % (uploaded_functions, 100.0 * uploaded_functions / total_functions)
    print "  Added new functions: %d (%.02f%%)" % (added_functions, 100.0 * added_functions / total_functions)
    print "  Changed existing functions: %d (%.02f%%)" % (updated_functions, 100.0 * updated_functions / total_functions)

def bincrowd_upload_all():
    """ Uploads information about all functions in the IDB.
    """
    try:
        bincrowd_upload_all_internal()
    except Exception, e:
        print e

class DownloadReturn:
    SUCCESS = 0
    COULDNT_READ_CONFIG_FILE = 1
    COULDNT_RETRIEVE_DATA = 2
    COULDNT_CONNECT_TO_SERVER = 3
    INCOMPLETE_DATA = 4
    INVALID_VERSION_NUMBER = 5
    USER_NOT_AUTHENTICATED = 6
    INTERNAL_ERROR = 7

def get_import_function_download_params(module, name):
    """ Returns an argument map for an imported function. This map can be sent to the BinCrowd
        server to describe the imported function.

        Parameters:
          - module : The module from which the function was imported.
          - name   : The name of the imported module.

        Returns:
          A map that describes the imported function.
    """
    return {'module' : module, 'name' : name }

def get_regular_function_download_params(fn, skip_small_functions):
    """ Returns an argument map for a regular function. This map can be sent to the BinCrowd
        server to describe the regular function.

        Parameters:
          - fn                   : The function to be described.
          - skip_small_functions : A flag that says whether small functions should be skipped.

        Returns:
          A map that describes the regular function.
    """
    p = proxyGraph(fn.startEA)
    e = extract_edge_tuples_from_graph(p)

    if skip_small_functions and len(e) < 10:
        print "Function %s is too small" % get_function_name(fn.startEA)
        return None

    return {'prime_product' : '%d' % calculate_prime_product(p), 'edges' : edges_array_to_dict(e) }

def get_download_params(ea, skip_small_functions):
    """ Returns an argument map for a function. This map can be sent to the BinCrowd
        server to describe the function.

        Parameters:
          - ea                   : The ea of the function to be described.
          - skip_small_functions : A flag that says whether small functions should be skipped.

        Returns:
          A map that describes the regular function. If there is no function at the given address,
          None is returned.
    """
    imported_function = get_imported_function(ea)

    if imported_function:
        return get_import_function_download_params(*imported_function)

    fn = idaapi.get_func(ea)

    if fn:
        return get_regular_function_download_params(fn, skip_small_functions)

    return None

class DownloadResults:
    """ Contains all possible return values of the download function.
    """

    # Returned if the download process completed successfully.
    SUCCESS = 0

    # Returned if client and server versions are incompatible.
    INVALID_VERSION_NUMBER = 1

    # Returned if the provided login credentials could not be used to authenticate the user.
    USER_NOT_AUTHENTICATED = 2

    # Returned if the data sent from the client to the server was malformed.
    MALFORMED_INPUT = 3

    # Returned if an unexpected error happened on the server
    INTERNAL_ERROR = 4

def clean_results(results):
    """ Cleans weird characters from downloaded strings.

        Parameters:
          - results : The results received from the BinCrowd server.

        Returns:
          Nothing.
    """
    for function_result in results:
        for single_result in function_result:
            for k, v in single_result.items():
                if type(v) == type(u""):
                    single_result[k] = idaapi.scr2idb(v.encode("iso-8859-1", "ignore"))
                if type(v) == type([]):
                    clean_results([v[0]])
                    clean_results([v[1]])

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
    if not imported_functions:
        fill_imported_functions()

def set_normal_information(information, fn):
    """ Assigns downloaded information to the given regular function.

        Parameters:
          - information : The downloaded function information for one function.
          - fn          : The function to which the information will be assigned.
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

        Parameters:
          - ea : The ea of the function whose graph data should be returned.

        Returns:
          A pair of (node count, edge count) that describes the graph of the function.
          If that function is an imported function, (0, 0) is returned.
    """
    if get_imported_function(ea):
        return (0, 0)
    else:
        fn = idaapi.get_func(ea)

        if not fn:
            raise "Internal Error: No function at the given ea"

        p = proxyGraph(fn.startEA)

        return (len(p.get_nodes()), len(p.get_edges()))

def set_import_information(information, ea):
    """ Assigns downloaded information to the given imported function.

        Parameters:
          - information : The downloaded function information for one function.
          - ea          : The ea of the imported function.
    """
    (local_variables, arguments) = information['stack_frame']

    description = information['description']

    if len(arguments) > 0:
        description = description + "\n"

    for argument in arguments:
        description = description + "\n" + argument['name'] + ": " + argument['description']

    idaapi.set_cmt(ea, description, True)

def set_information(information, ea):
    """ Assigns downloaded information to the given function.

        Parameters:
          - information : The downloaded function information for one function.
          - ea          : The ea of the imported function.
    """
    print "Assigning information to function %s" % get_function_name(ea)

    if get_imported_function(ea):
        set_import_information(information, ea)
    else:
        set_normal_information(information, idaapi.get_func(ea))

MATCHDEGREE_STRINGS = [ "", "High", "Medium", "Low" ]

def formatresults(results, currentNodeCount, currentEdgeCount):
    """ build formatted strings of results and store in self.list """
    strlist = []
    for r in results:
        degree          = r['match_degree']
        file            = r['file']
        name            = r['name']
        description     = r['description']
        numberOfNodes   = r['number_of_nodes']
        numberOfEdges   = r['number_of_edges']
        owner           = r['owner']
        strlist.append([MATCHDEGREE_STRINGS[degree], file, name, description, "%d (%d)" % (numberOfNodes, numberOfNodes - currentNodeCount), "%d (%d)" % (numberOfEdges, numberOfEdges - currentEdgeCount), owner])
    return strlist

def bincrowd_download_internal(ea):
    """ Downloads information for the function at the given ea.

        Parameters:
          - ea : The ea of the function to download.

        Returns:
          Nothing
    """
    functions = get_download_params(ea, False)

    if not functions:
        return

    (error_code, params) = download([functions])

    if error_code != DownloadReturn.SUCCESS:
        return

    params = params[0]

    if not params:
        print "No information for function '%s' available" % get_function_name(ea)
        return

    nodes, edges = get_graph_data(ea)
    c = FunctionSelectionDialog("Retrieved Function Information", formatresults(params, nodes, edges))
    selected_row = c.Show(True)

    if selected_row >= 0:
        set_information(params[selected_row], ea)

def bincrowd_download(ea = None):
    """ Downloads information for the function at the given ea.

        Parameters:
          - ea : The ea of the function to download.

        Returns:
          Nothing
    """
    if not ea:
        ea = here()

    try:
        bincrowd_download_internal(ea)
    except Exception, e:
        print e

def get_information_all_functions(zipped_overview):
    """ Takes a list of (ea, edge_count, downloaded function result) triples and converts
        that list into a list of equal cardinality that is suitable for displaying to the
        user.

        Parameters:
          - zipped_overview : The input list.

        Returns:
          The cleaned up version of the input list.
    """
    result_list = []

    for (ea, edge_count, result) in zipped_overview:
        result_list.append([ea, result['h'], result['m'], result['l'], edge_count])

    return sorted(result_list, lambda x, y : y[4] - x[4])


def get_function_name(ea):
    """ Returns the name of the function at the given address.

        Parameters:
          ea : The ea of the function.

        Returns:
          The name of the function at the given ea.
    """
    imported_function = get_imported_function(ea)

    if imported_function:
        return imported_function[1] + " (Imported)"
    else:
        return get_demangled_name(ea)

def get_display_information_all_functions(information):
    """
    Converts information returned from get_information_all_functions and
    turns that information into something that can be displayed in a
    chooser2 dialog.
    """
    return [[get_function_name(ea), "%d" % high, "%d" % medium, "%d" % low, "%d" % edge_count] for [ea, high, medium, low, edge_count] in information]

def download_overview(functions):
    """ Downloads an overview of the matches for the given functions.

        Parameters:
          - functions : The functions to download the overview for.

        Returns:
          A pair of (error code, overview) where error code is a DownloadReturn value that
          describes what happened and overview is the downloaded overview in case of success.
    """

    uri, user, password = read_config_file()

    if user == None:
        print "Error: Could not read config file. Please check readme.txt to learn how to configure BinCrowd."
        return (DownloadReturn.COULDNT_READ_CONFIG_FILE, None)

    CHUNK_SIZE = 1000
    chunks = [ functions[x:x+CHUNK_SIZE] for x in range( 0, len(functions), CHUNK_SIZE ) ]
    file_to_count = {}
    function_matches = []
    index = 0

    for chunk in chunks:
        parameters = {
                     'username'       : user,
                     'password'       : password,
                     'version'        : CLIENTVERSION,
                     'functions'      : chunk
                     }
        print "Downloading function information for chunk %d: %s" % (index, datetime.now())

        try:
            rpc_srv = xmlrpclib.ServerProxy(uri, allow_none=True)
            response = rpc_srv.download_overview(parameters)
        except Exception, e:
            print "Error: Could not connect to BinCrowd server"
            print e
            return (DownloadReturn.COULDNT_CONNECT_TO_SERVER, None)

        print "Parsing returned values: %s" % datetime.now()

        try:
            ((error_code, overview), methodname) = xmlrpclib.loads(response.encode("utf-8"))

            if error_code == DownloadResults.SUCCESS:
                # We now need to do some bookkeeping due to the chunking of requests
                match_quality = overview[0]

                # The score is additive, luckily
                for filename, score in match_quality:
                    if not file_to_count.has_key(filename):
                        file_to_count[filename] = string.atol(score)
                    else:
                        file_to_count[filename] = file_to_count[filename] + string.atol(score, 10)

                # Re-base the indices
                function_results = overview[1]
                for func_result in function_results:
                    func_result['i'] = func_result['i'] + (index * CHUNK_SIZE)
                function_matches.extend(function_results)
                index = index + 1
            elif error_code == DownloadResults.INVALID_VERSION_NUMBER:
                print "Error: Invalid version number was sent to server"
                return (DownloadReturn.INVALID_VERSION_NUMBER, None)
            elif error_code == DownloadResults.USER_NOT_AUTHENTICATED:
                print "Error: Server could not authenticate user"
                return (DownloadReturn.USER_NOT_AUTHENTICATED, None)
            elif error_code == DownloadResults.MALFORMED_INPUT:
                print "Error: Incomplete data was sent to server"
                return (DownloadReturn.INCOMPLETE_DATA, None)
            elif error_code == DownloadResults.INTERNAL_ERROR:
                print "Error: Internal server error (%s)" % overview
                return (DownloadReturn.INTERNAL_ERROR, None)
            else:
                print "Unknown return code %d" % error_code
        except Exception, e:
            print e
            return (DownloadReturn.COULDNT_RETRIEVE_DATA, None)

    # Ok, we have gotten all the data from the server. Now stitch everything
    # together again and return the final results
    match_quality = [ [x[0], "%d" % x[1]] for x in file_to_count.items() ]
    return (DownloadReturn.SUCCESS, (match_quality, function_matches))

def download(functions):
    """ Downloads matches for the given functions.

        Parameters:
          - functions : The functions to download the matches for.

        Returns:
          A pair of (error code, matches) where error code is a DownloadReturn value that
          describes what happened and matches are the downloaded matches in case of success.
    """

    uri, user, password = read_config_file()

    if user == None:
        print "Error: Could not read config file. Please check readme.txt to learn how to configure BinCrowd."
        return (DownloadReturn.COULDNT_READ_CONFIG_FILE, None)

    parameters = {
                 'username'       : user,
                 'password'       : password,
                 'version'        : CLIENTVERSION,
                 'functions'      : functions
                 }
    print "Downloading function information: %s" % datetime.now()

    try:
        rpc_srv = xmlrpclib.ServerProxy(uri, allow_none=True)
        response = rpc_srv.download(parameters)
    except Exception, e:
        print "Error: Could not connect to BinCrowd server"
        print e
        return (DownloadReturn.COULDNT_CONNECT_TO_SERVER, None)

    try:
        ((error_code, results), method_name) = xmlrpclib.loads(response.encode("utf-8"))

        if error_code == DownloadResults.SUCCESS:
            clean_results(results)
            return (DownloadReturn.SUCCESS, results)
        elif error_code == DownloadResults.INVALID_VERSION_NUMBER:
            print "Error: Invalid version number was sent to server"
            return (DownloadReturn.INVALID_VERSION_NUMBER, None)
        elif error_code == DownloadResults.USER_NOT_AUTHENTICATED:
            print "Error: Server could not authenticate user"
            return (DownloadReturn.USER_NOT_AUTHENTICATED, None)
        elif error_code == DownloadResults.MALFORMED_INPUT:
            print "Error: Incomplete data was sent to server"
            return (DownloadReturn.INCOMPLETE_DATA, None)
        elif error_code == DownloadResults.INTERNAL_ERROR:
            print "Error: Internal server error (%s)" % results
            return (DownloadReturn.INTERNAL_ERROR, None)
        else:
            print "Unknown return code %d" % error_code
    except Exception, e:
        print e
        print results
        return (DownloadReturn.COULDNT_RETRIEVE_DATA, None)

def download_all_internal():
    """
    Downloads information for all functions of the given file and lets
    the user choose what information he wants to accept.
    """

    collected_params = []
    eas = []
    edge_counts = []

    print "Collecting imported functions: %s" % datetime.now()

    # Download all imported functions
    for index in xrange(len(imported_functions)):
        for function_ea, name in imported_functions[index]:
            param = get_download_params(function_ea, True)

            if not param:
                continue

            collected_params.append(param)
            eas.append(function_ea)
            edge_counts.append(0)

    print "Collecting regular functions: %s" % datetime.now()

    # Download all regular functions
    for function_ea in idautils.Functions():
        fn = idaapi.get_func(function_ea)

        if not fn:
            continue

        if get_imported_function(function_ea):
            continue

        params = get_download_params(function_ea, True)

        if not params:
            continue

        if not params['edges']:
            continue

        collected_params.append(params)
        eas.append(function_ea)
        edge_counts.append(len(params['edges']))

    (error_code, result) = download_overview(collected_params)

    if error_code != DownloadReturn.SUCCESS:
        return

    print "Processing downloaded information: %s" % datetime.now()

    match_quality = result[0]
    function_results = result[1]

    print "Files with highest match scores:"

    for (file, match) in match_quality:
        print "%s: %s" % (file, match)

    zipped_overview = [(eas[result['i']], edge_counts[result['i']], result) for result in function_results]

    while True:
        # Let the user pick for what target function he wants to copy information
        all_functions_information = get_information_all_functions(zipped_overview)
        display_information = get_display_information_all_functions(all_functions_information)

        print "Displaying results: %s" % datetime.now()

        all_functions_dialog = AllFunctionsSelectionDialog("All Functions", display_information)
        selected_function = all_functions_dialog.Show(True)

        if selected_function == -1:
            break

        # Let the user pick for what downloaded information he wants to use for his target function
        selected_ea = all_functions_information[selected_function][0]

        idc.Jump(selected_ea)

        bincrowd_download(selected_ea)

def bincrowd_download_all():
    """
    Downloads information for all functions of the given file and lets
    the user choose what information he wants to accept.
    """
    try:
        download_all_internal()
    except Exception, e:
        print e

"""
REGISTER IDA SHORTCUTS
"""

if idaapi.cvar.batch:
    bincrowd_upload_all()
    idc.Exit(0)

print "Registering hotkey %s for bincrowd_upload()"%UPLOADHOTKEY
idaapi.CompileLine('static _bincrowd_upload() { RunPythonStatement("bincrowd_upload()"); }')
idc.AddHotkey(UPLOADHOTKEY,"_bincrowd_upload")

print "Registering hotkey %s for bincrowd_download()"%DOWNLOADHOTKEY
idaapi.CompileLine('static _bincrowd_download() { RunPythonStatement("bincrowd_download()"); }')
idc.AddHotkey(DOWNLOADHOTKEY,"_bincrowd_download")

print "Registering hotkey %s for bincrowd_upload_all()"%UPLOADALLHOTKEY
idaapi.CompileLine('static _bincrowd_upload_all() { RunPythonStatement("bincrowd_upload_all()"); }')
idc.AddHotkey(UPLOADALLHOTKEY,"_bincrowd_upload_all")

print "Registering hotkey %s for bincrowd_download_all()"%DOWNLOADALLHOTKEY
idaapi.CompileLine('static _bincrowd_download_all() { RunPythonStatement("bincrowd_download_all()"); }')
idc.AddHotkey(DOWNLOADALLHOTKEY,"_bincrowd_download_all")

