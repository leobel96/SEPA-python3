#!/usr/bin/python3

import re
import yaml
import logging
from .Exceptions import *

class YSAPObject:

    """
    A class to handle YSAP files

    Parameters
    ----------
    ysapFile : str
        The name (with relative or absolute path) of the YSAP file
    logLevel : int
        The desired level of debugging information (default = 40)
    
    Attributes
    ----------
    ysapDict : dict
        The full dictionary with the YSAP content
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
    
    def __init__(self, ysapFile, logLevel = 40):

        """
        The constructor of the YSAPObject class. 

        Parameters
        ----------
        ysapFile : str
            The name (with relative or absolute path) of the YSAP file
        logLevel : int
            The desired level of debugging information (default = 40)

        """
        
        # logger
        self.logger = logging.getLogger("sepaLogger")
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logLevel)
        self.logger.setLevel(logLevel)
        self.logger.debug("=== YSAPObject::__init__ invoked ===")
        
        # store the file name
        self.ysapFile = ysapFile
        
        # try to open YSAP file
        try:
            with open(ysapFile) as ysapFileStream:
                self.ysapDict = yaml.load(ysapFileStream)
        except Exception as e:
            self.logger.error("Parsing of the YSAP file failed")
            raise YSAPParsingException("Parsing of the YSAP file failed")  

        # try to read the network configuration
        try:
            self.host = self.ysapDict["host"]
            self.unsecureHost = self.ysapDict["sparql11protocol"].get("host","")
            self.protocol = self.ysapDict["sparql11protocol"]["protocol"]
            self.port = self.ysapDict["sparql11protocol"]["port"]
            self.queryPath = self.ysapDict["sparql11protocol"]["query"]["path"]
            self.updatePath = self.ysapDict["sparql11protocol"]["update"]["path"]
            
            self.SEhost = self.ysapDict["sparql11seprotocol"].get("host","")
            self.SEProtocol = self.ysapDict["sparql11seprotocol"]["protocol"]
            self.wsPort = self.ysapDict["sparql11seprotocol"]["availableProtocols"]["ws"]["port"]
            self.unsecureSubscribePath = self.ysapDict["sparql11seprotocol"]["availableProtocols"]["ws"]["path"]
            self.wssPort = self.ysapDict["sparql11seprotocol"]["availableProtocols"]["wss"]["port"]
            self.secureSubscribePath = self.ysapDict["sparql11seprotocol"]["availableProtocols"]["wss"]["path"]
            
            security = self.ysapDict["sparql11seprotocol"].get("security")
            if security is not None:
                self.secureHost = security.get("host")
                self.securePort = security.get("port")
                self.registerPath = security.get("registration")
                self.tokenRequestPath = security.get("tokenRequest")
                self.securePath = security.get("securePath")
                self.client_id = security.get("client_id")
                self.client_name = security.get("client_secret")
                self.client_secret = security.get("client_id")
                self.jwt = security.get("jwt")
                self.expiry = security.get("expires")
            else:
                self.secureHost = None
                self.securePort = None
                self.registerPath = None
                self.tokenRequestPath = None
                self.securePath = None
                self.client_id = None
                self.client_name = None
                self.client_secret = None
                self.jwt = None
                self.expiry = None
            
        except KeyError as e:
            self.logger.error("Network configuration incomplete in YSAP file")
            raise YSAPParsingException("Network configuration incomplete in YSAP file")
            
        # initialize user data
        
            
        # define attributes for unsecure connection
        self.subscribeURI = "ws://%s:%s%s" % (self.host, self.wsPort, self.unsecureSubscribePath)
        self.updateURI = "http://%s:%s%s" % (self.host, self.port, self.updatePath)
        self.queryURI = "http://%s:%s%s" % (self.host, self.port, self.queryPath)
        
        # define attributes for secure connection
        self.secureSubscribeURI = "wss://%s:%s%s%s" % (self.host, self.wssPort, self.securePath, self.secureSubscribePath)
        self.secureUpdateURI = "https://%s:%s%s%s" % (self.host, self.securePort, self.securePath, self.updatePath)
        self.secureQueryURI = "https://%s:%s%s%s" % (self.host, self.securePort, self.securePath, self.queryPath)

        # define attributes for registration and token request
        self.tokenReqURI = "https://%s:%s%s" % (self.host, self.securePort, self.tokenRequestPath)
        self.registerURI = "https://%s:%s%s" % (self.host, self.securePort, self.registerPath)

        # read namespaces
        self.namespaces = {}
        try:
            self.namespaces = self.ysapDict["namespaces"]
        except Exception as e:            
            raise YSAPParsingException("Error while reading namespaces of the YSAP file")

        # define namespace sparql string
        self.nsSparql = ""
        for ns in self.namespaces.keys():
            self.nsSparql += "PREFIX %s: <%s> " % (ns, self.namespaces[ns])

        # read queries
        self.queries = {}
        try:
            self.queries = self.ysapDict["queries"]
        except Exception as e:            
            raise YSAPParsingException("Error while reading queries of the YSAP file")

        # read updates
        self.updates = {}
        try:
            self.updates = self.ysapDict["updates"]
        except Exception as e:            
            raise YSAPParsingException("Error while reading updates of the YSAP file")
            
    def getQuery(self, queryName, forcedBindings):

        """
        Returns a SPARQL query retrieved from the YSAP and
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
        self.logger.debug("=== YSAPObject::getQuery invoked ===")

        # call getSparql
        return self.getSparql(True, queryName, forcedBindings)


    def getUpdate(self, updateName, forcedBindings):

        """
        Returns a SPARQL update retrieved from the YSAP and
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
        self.logger.debug("=== YSAPObject::getUpdate invoked ===")

        # call getSparql
        return self.getSparql(False, updateName, forcedBindings)


    def getSparql(self, isQuery, sparqlName, forcedBindings):
        
        """
        Returns a SPARQL query/update retrieved from the YSAP and 
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
        self.logger.debug("=== YSAPObject::getSparql invoked ===")

        # initialize
        ysapSparql = None
        ysapForcedBindings = None

        # determine if it is query or update
        if isQuery:

            # read the initial query
            try:
                ysapSparql = self.queries[sparqlName]["sparql"]
            except KeyError as e:
                self.logger.error("Query not found in YSAP file")
                raise YSAPParsingException("Query not found in YSAP file")
            
            try:
                ysapForcedBindings = self.queries[sparqlName]["forcedBindings"]
            except KeyError as e:
                self.logger.debug("No forcedBindings for the query {}".format(sparqlName))
        
        else:

            # read the initial update
            try:
                ysapSparql = self.updates[sparqlName]["sparql"]
                ysapForcedBindings = self.updates[sparqlName]["forcedBindings"]
            except KeyError as e:
                self.logger.error("Update not found in YSAP file")
                raise YSAPParsingException("Update not found in YSAP file")
        
        # for every forced binding perform a substitution
        for v in forcedBindings.keys():
            
            # check if v is in the ysap forced bindings
            if v in ysapForcedBindings.keys():
            
                # determine the variable replacement
                value = forcedBindings[v]
                valueType = ysapForcedBindings[v]["type"]

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
                ysapSparql = re.sub(r'(\?|\$){1}' + v + r'\s+', value + " ", ysapSparql, flags=0)

                # replace the variable when it is followed by a braket
                ysapSparql = re.sub(r'(\?|\$){1}' + v + r'\}', value + " } ", ysapSparql, flags=0)

                # replace the variable when it is followed by a dot
                ysapSparql = re.sub(r'(\?|\$){1}' + v + r'\.', value + " . ", ysapSparql, flags=0)

        # return
        return self.nsSparql + ysapSparql

    # read client_id
    def readClientId(self):
        
        """Retrieves the client id form file, if present"""
        
        try:
            self.client_id = self.ysapDict["client_id"]
        except KeyError:
            pass


    # read client_id
    def readClientName(self):
        
        """Retrieves the client id form file, if present"""
        
        try:
            self.client_name = self.ysapDict["client_name"]
        except KeyError:
            pass


    # read client_secret
    def readClientSecret(self):
        
        """Retrieves the client secret form file, if present"""
        
        try:
            self.client_secret = self.ysapDict["client_secret"]
        except KeyError:
            pass


    # read token
    def readToken(self):
        
        """Retrieves the token form file, if present"""
        
        try:
            self.jwt = self.ysapDict["jwt"]
        except KeyError:
            pass


    # store config
    def storeConfig(self):

        """Method used to update the content of the ysap file"""

        # store data into file
        with open(self.ysapFile, "w") as ysapFileStream:
            json.dump(self.jparDict, ysapFileStream, indent=4)
            ysapFileStream.truncate()
    
    
    
    def getNamespace(self, ns):

        """
        Returns a namespace, given its prefix.

        Parameters
        ----------
        ns : str
            The prefix bound to the namespace

        Returns
        -------
        str
            The namespace bound to that prefix

        """

        self.logger.debug("Retrieving namespace for prefix %s" % ns)
        try:
            return self.namespaces[ns]
        except KeyError:
            raise YSAPParsingException("Namespace not found!")
