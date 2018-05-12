#!/usr/bin/python3

from .Exceptions import *
import logging
import json
import re


class JSAPObject:

    """
    A class to handle JSAP files

    Parameters
    ----------
    jsapFile : str
        The name (with relative or absolute path) of the JSAP file
    logLevel : int
        The desired level of debugging information (default = 40)
    
    Attributes
    ----------
    jsapDict : dict
        The full dictionary with the JSAP content
    host : str
        The hostname of the SEPA instance
    unsecureHost: str
        Optional value, it will be used in future
    protocol : str
        Protocol to be used for queries
    port : int
        The port number for queries    
    queryPath : str
        The path to the query resource of the SEPA instance
    updatePath : str
        The path to the update resource of the SEPA instance   
        
    SEhost: str
        Optional value, it will be used in future    
    SEProtocol : str
        In future SEPA will understand what protocol should be used
    wsPort : int
        The port number for unsecure Websocket connection
    unsecureSubscribePath : str
        The path to the subscribe resource of the SEPA instance
    wssPort : int
        The port number for secure Websocket connection
    secureSubscribePath : str
        The path to the secure subscribe resource of the SEPA instance
      
    secureHost: str
        The hostname for secure requests (such as oauth related requests), optional
    securePort : int
        The port number for secure oauth connection
    registerPath : str
        The path to register to the SEPA instance
    tokenRequestPath : str
        The path to request a token for secure connections to the SEPA instance
    securePath : str
        The path to compose URIs for secure connections to SEPA
    
    updateURI : str
        The URI to perform SPARQL updates
    queryURI : str
        The URI to perform SPARQL queries
    subscribeURI : str
        The URI to perform SPARQL subscriptions
        
    secureUpdateURI : str
        The URI to perform secure SPARQL updates
    secureQueryURI : str
        The URI to perform secure SPARQL queries
    secureSubscribeURI : str
        The URI to perform secure SPARQL subscriptions
        
    tokenReqURI : str
        The URI to perform secure SPARQL token requests
    registerURI : str
        The URI to perform secure SPARQL registrations    
    
    namespaces : dict
        Dictionary with prefixes (keys) and namespaces (values)
    queries : dict
        Dictionary with SPARQL query templates (values) indexed by a friendly name (key)   
    updates : dict
        Dictionary with SPARQL update templates (values) indexed by a friendly name (key)  
    
    """

    def __init__(self, jsapFile, logLevel = 10):

        """
        Constructor of the JSAPObject class

        Parameters
        ----------
        jsapFile : str
            The name (with relative or absolute path) of the JSAP file
        logLevel : int
            The desired level of debugging information (default = 40)
    
        """

        # logger
        self.logger = logging.getLogger("sepaLogger")
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logLevel)
        self.logger.setLevel(logLevel)
        self.logger.debug("=== JSAPObject::__init__ invoked ===")

        # store the file name
        self.jsapFile = jsapFile
        
        # try to open JSAP File
        try:
            with open(jsapFile) as jsapFileStream:
                self.jsapDict = json.load(jsapFileStream)
        except Exception as e:
            self.logger.error("Parsing of the JSAP file failed")
            raise JSAPParsingException("Parsing of the JSAP file failed")        

        # try to read the network configuration
        try:
            self.host = self.jsapDict["host"]
            self.unsecureHost = self.jsapDict["sparql11protocol"].get("host","")
            self.protocol = self.jsapDict["sparql11protocol"]["protocol"]
            self.port = self.jsapDict["sparql11protocol"]["port"]
            self.queryPath = self.jsapDict["sparql11protocol"]["query"]["path"]
            self.updatePath = self.jsapDict["sparql11protocol"]["update"]["path"]
            
            self.SEhost = self.jsapDict["sparql11seprotocol"].get("host","")
            self.SEProtocol = self.jsapDict["sparql11seprotocol"]["protocol"]
            self.wsPort = self.jsapDict["sparql11seprotocol"]["availableProtocols"]["ws"]["port"]
            self.unsecureSubscribePath = self.jsapDict["sparql11seprotocol"]["availableProtocols"]["ws"]["path"]
            self.wssPort = self.jsapDict["sparql11seprotocol"]["availableProtocols"]["wss"]["port"]
            self.secureSubscribePath = self.jsapDict["sparql11seprotocol"]["availableProtocols"]["wss"]["path"]
            
            security = self.jsapDict["sparql11seprotocol"].get("security")
            if security is not None:
                self.secureHost = security.get("host")
                self.securePort = security.get("port")
                self.registerPath = security.get("registration")
                self.tokenRequestPath = security.get("tokenRequest")
                self.securePath = security.get("securePath")
                self.client_id = security.get("client_id")
                self.client_secret = security.get("client_secret")
                self.jwt = security.get("jwt")
                self.expiry = security.get("expires")
            else:
                self.secureHost = None
                self.securePort = None
                self.registerPath = None
                self.tokenRequestPath = None
                self.securePath = None
                self.client_id = None
                self.client_secret = None
                self.jwt = None
                self.expiry = None
            
        except KeyError as e:
            self.logger.error("Network configuration incomplete in JSAP file")
            raise JSAPParsingException("Network configuration incomplete in JSAP file")
               
        # define attributes for unsecure connection
        self.subscribeURI = "ws://%s:%s%s" % (self.host, self.wsPort, self.unsecureSubscribePath)
        self.updateURI = "http://%s:%s%s" % (self.host, self.port, self.updatePath)
        self.queryURI = "http://%s:%s%s" % (self.host, self.port, self.queryPath)
        
        # define attributes for secure connection
        if self.securePath is not None and self.wssPort is not None and self.securePort is not None:
            self.secureSubscribeURI = "wss://%s:%s%s%s" % (self.host, self.wssPort, self.securePath, self.secureSubscribePath)
            self.secureUpdateURI = "https://%s:%s%s%s" % (self.host, self.securePort, self.securePath, self.updatePath)
            self.secureQueryURI = "https://%s:%s%s%s" % (self.host, self.securePort, self.securePath, self.queryPath)

        # define attributes for registration and token request
        if self.securePort is not None and self.tokenRequestPath is not None and self.registerPath is not None:
            self.tokenReqURI = "https://%s:%s%s" % (self.host, self.securePort, self.tokenRequestPath)
            self.registerURI = "https://%s:%s%s" % (self.host, self.securePort, self.registerPath)

        # read namespaces
        self.namespaces = {}
        try:
            self.namespaces = self.jsapDict["namespaces"]
        except Exception as e:            
            raise JSAPParsingException("Error while reading namespaces of the JSAP file")

        # define namespace sparql string
        self.nsSparql = ""
        for ns in self.namespaces.keys():
            self.nsSparql += "PREFIX %s: <%s> " % (ns, self.namespaces[ns])

        # read queries
        self.queries = {}
        try:
            self.queries = self.jsapDict["queries"]
        except Exception as e:            
            raise JSAPParsingException("Error while reading queries of the JSAP file")

        # read updates
        self.updates = {}
        try:
            self.updates = self.jsapDict["updates"]
        except Exception as e:            
            raise JSAPParsingException("Error while reading updates of the JSAP file")


    def getQuery(self, queryName, forcedBindings):

        """
        Returns a SPARQL query retrieved from the JSAP and
        modified with the forced bindings provided by the user.

        Parameters
        ----------
        queryName : str
            The friendly name of the SPARQL Query
        forcedBindings : Dict
            The dictionary containing the bindings to fill the template

        Returns
        -------
        str
            The complete SPARQL Query
       
        """

        # debug print
        self.logger.debug("=== JSAPObject::getQuery invoked ===")

        # call getSparql
        return self.getSparql(True, queryName, forcedBindings)


    def getUpdate(self, updateName, forcedBindings):

        """
        Returns a SPARQL update retrieved from the JSAP and
        modified with the forced bindings provided by the user.

        Parameters
        ----------
        updateName : str
            The friendly name of the SPARQL Update
        forcedBindings : Dict
            The dictionary containing the bindings to fill the template

        Returns
        -------
        str
            The complete SPARQL Update
       
        """

        # debug print
        self.logger.debug("=== JSAPObject::getUpdate invoked ===")

        # call getSparql
        return self.getSparql(False, updateName, forcedBindings)


    def getSparql(self, isQuery, sparqlName, forcedBindings):
        
        """
        Returns a SPARQL query/update retrieved from the JSAP and 
        modified with the forced bindings provided by the user.

        Parameters
        ----------
        isQuery : bool
            A variable to specify if looking for a query or an update
        sparqlName : str
            The friendly name of the SPARQL Update
        forcedBindings : Dict
            The dictionary containing the bindings to fill the template

        Returns
        -------
        str
            The complete SPARQL Query or Update
        
        """

        # debug print
        self.logger.debug("=== JSAPObject::getSparql invoked ===")

        # initialize
        jsapSparql = None
        jsapForcedBindings = None

        # determine if it is query or update
        if isQuery:

            # read the initial query
            try:
                jsapSparql = self.queries[sparqlName]["sparql"]
            except KeyError as e:
                self.logger.error("Query not found in JSAP file")
                raise JSAPParsingException("Query not found in JSAP file")
            
            try:
                jsapForcedBindings = self.queries[sparqlName]["forcedBindings"]
            except KeyError as e:
                self.logger.debug("No forcedBindings for the query {}".format(sparqlName))
        
        else:

            # read the initial update
            try:
                jsapSparql = self.updates[sparqlName]["sparql"]
                jsapForcedBindings = self.updates[sparqlName]["forcedBindings"]
            except KeyError as e:
                self.logger.error("Update not found in JSAP file")
                raise JSAPParsingException("Update not found in JSAP file")
        
        # for every forced binding perform a substitution
        for v in forcedBindings.keys():
            
            # check if v is in the jsap forced bindings
            if v in jsapForcedBindings.keys():
            
                # determine the variable replacement
                value = forcedBindings[v]
                valueType = jsapForcedBindings[v]["type"]

                if valueType=="literal":
                    value = "'{}'".format(value)
                else: 
                    # full uris between <>
                    namespace_node = False
                    for ns in self.namespaces:
                        r = re.compile("{}:.+".format(ns))
                        if r.match(value) is not None:
                            namespace_node = True
                            break
                    if not namespace_node:
                        value = "<{}>".format(value)
                        
                # debug print
                self.logger.debug("Replacing {} variable {} with {}".format(valueType,v,value)) 

                # replace the variable when it is followed by a space
                jsapSparql = re.sub(r'(\?|\$){1}' + v + r'\s+', value + " ", jsapSparql, flags=0)

                # replace the variable when it is followed by a braket
                jsapSparql = re.sub(r'(\?|\$){1}' + v + r'\}', value + " } ", jsapSparql, flags=0)

                # replace the variable when it is followed by a dot
                jsapSparql = re.sub(r'(\?|\$){1}' + v + r'\.', value + " . ", jsapSparql, flags=0)

        # return
        return self.nsSparql + jsapSparql
     
