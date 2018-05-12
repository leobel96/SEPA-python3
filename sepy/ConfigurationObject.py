#!/usr/bin/python3

import re
import yaml
import json
import logging
from os.path import splitext
from uuid import getnode as get_mac

from .Exceptions import *

class ConfigurationObject:

    """
    A class to handle JSAP and YSAP files

    Parameters
    ----------
    configurationFile : str
        The name (with relative or absolute path) of the configuration file
    logLevel : int
        The desired level of debugging information (default = 40)
    
    Attributes
    ----------
    configurationDict : dict
        The full dictionary with the file content
    host : str
        The hostname of the SEPA instance
    queryHost: str
        Optional value, it will be used in future
    protocol : str
        Protocol to be used for queries
    port : int
        The port number for queries    
    queryPath : str
        The path to the query resource of the SEPA instance
    updatePath : str
        The path to the update resource of the SEPA instance   
        
    subscribeHost: str
        Optional value, it will be used in future    
    subscribeProtocol : str
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
    
    def __init__(self, configurationFile, logLevel = 40):

        """
        The constructor of the fileObject class. 

        Parameters
        ----------
        configurationFile : str
            The name (with relative or absolute path) of the file file
        logLevel : int
            The desired level of debugging information (default = 40)

        """
        
        # logger
        self.logger = logging.getLogger("sepaLogger")
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logLevel)
        self.logger.setLevel(logLevel)
        self.logger.debug("=== configurationObject::__init__ invoked ===")
        
        # store the file name
        self.configurationFile = configurationFile
        
        # try to open configuration file
        head,tail = splitext (configurationFile)
        if tail.upper() == ".YSAP":
            try:
                with open(configurationFile) as ysapFileStream:
                    self.configurationDict = yaml.load(ysapFileStream)
                    self.configurationExtension = ".YSAP"
            except Exception as e:
                self.logger.error("Parsing of the YSAP file failed")
                raise YSAPParsingException("Parsing of the YSAP file failed")  
        elif tail.upper() == ".JSAP":
            try:
                with open(configurationFile) as jsapFileStream:
                    self.configurationDict = json.load(jsapFileStream)
                    self.configurationExtension = ".JSAP"
            except Exception as e:
                self.logger.error("Parsing of the JSAP file failed")
                raise JSAPParsingException("Parsing of the JSAP file failed")   
        else:
            raise WrongFileException("Wrong file selected")
        

        # try to read the network configuration
        try:
            self.host = self.configurationDict["host"]
            self.queryHost = self.configurationDict["sparql11protocol"].get("host")
            self.protocol = self.configurationDict["sparql11protocol"]["protocol"]
            self.port = self.configurationDict["sparql11protocol"]["port"]
            self.queryPath = self.configurationDict["sparql11protocol"]["query"]["path"]
            self.updatePath = self.configurationDict["sparql11protocol"]["update"]["path"]
            
            self.subscribeHost = self.configurationDict["sparql11seprotocol"].get("host")
            self.subscribeProtocol = self.configurationDict["sparql11seprotocol"]["protocol"]
            self.wsPort = self.configurationDict["sparql11seprotocol"]["availableProtocols"]["ws"]["port"]
            self.unsecureSubscribePath = self.configurationDict["sparql11seprotocol"]["availableProtocols"]["ws"]["path"]
            self.wssPort = self.configurationDict["sparql11seprotocol"]["availableProtocols"]["wss"]["port"]
            self.secureSubscribePath = self.configurationDict["sparql11seprotocol"]["availableProtocols"]["wss"]["path"]
            
            security = self.configurationDict["sparql11seprotocol"]["security"]
            self.secureHost = security.get("host")
            self.securePort = security["port"]
            self.registerPath = security["registration"]
            self.tokenRequestPath = security["tokenRequest"]
            self.securePath = security["securePath"]
            self.expiry = security.get("expires")
            
        except KeyError as e:
            self.logger.error("Network configuration incomplete in file file")
            raise configurationParsingException("Network configuration incomplete in configuration file")
        
        if self.subscribeHost is None:
            subscribeHost = self.host
        else:
            subscribeHost = self.subscribeHost
        
        if self.queryHost is None:
            queryHost = self.host
        else:
            queryHost = self.queryHost
            
        if self.secureHost is None:
            secureHost = self.host
        else:
            secureHost = self.secureHost
            
        # define attributes for unsecure connection
        self.subscribeURI = "ws://%s:%s%s" % (subscribeHost, self.wsPort, self.unsecureSubscribePath)
        self.updateURI = "http://%s:%s%s" % (queryHost, self.port, self.updatePath)
        self.queryURI = "http://%s:%s%s" % (queryHost, self.port, self.queryPath)
        
        # define attributes for secure connection
        self.secureSubscribeURI = "wss://%s:%s%s%s" % (subscribeHost, self.wssPort, self.securePath, self.secureSubscribePath)
        self.secureUpdateURI = "https://%s:%s%s%s" % (queryHost, self.securePort, self.securePath, self.updatePath)
        self.secureQueryURI = "https://%s:%s%s%s" % (queryHost, self.securePort, self.securePath, self.queryPath)

        # define attributes for registration and token request
        self.tokenReqURI = "https://%s:%s%s" % (secureHost, self.securePort, self.tokenRequestPath)
        self.registerURI = "https://%s:%s%s" % (secureHost, self.securePort, self.registerPath)

        # read namespaces
        self.namespaces = {}
        try:
            self.namespaces = self.configurationDict["namespaces"]
        except Exception as e:            
            raise configurationParsingException("Error while reading namespaces of the configuration file")

        # define namespace sparql string
        self.nsSparql = ""
        for ns in self.namespaces.keys():
            self.nsSparql += "PREFIX %s: <%s> " % (ns, self.namespaces[ns])

        # read queries
        self.queries = {}
        try:
            self.queries = self.configurationDict["queries"]
        except Exception as e:            
            raise configurationParsingException("Error while reading queries of the configuration file")

        # read updates
        self.updates = {}
        try:
            self.updates = self.configurationDict["updates"]
        except Exception as e:            
            raise configurationParsingException("Error while reading updates of the configuration file")
            
    def getQuery(self, queryName, forcedBindings):

        """
        Returns a SPARQL query retrieved from the configuration and
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
        self.logger.debug("=== configurationObject::getQuery invoked ===")

        # call getSparql
        return self.getSparql(True, queryName, forcedBindings)


    def getUpdate(self, updateName, forcedBindings):

        """
        Returns a SPARQL update retrieved from the configuration and
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
        self.logger.debug("=== configurationObject::getUpdate invoked ===")

        # call getSparql
        return self.getSparql(False, updateName, forcedBindings)


    def getSparql(self, isQuery, sparqlName, forcedBindings):
        
        """
        Returns a SPARQL query/update retrieved from the configuration and 
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
        self.logger.debug("=== configurationObject::getSparql invoked ===")

        # initialize
        configurationSparql = None
        configurationForcedBindings = None

        # determine if it is query or update
        if isQuery:

            # read the initial query
            try:
                configurationSparql = self.queries[sparqlName]["sparql"]
            except KeyError as e:
                self.logger.error("Query not found in configuration file")
                raise configurationParsingException("Query not found in configuration file")
            
            try:
                configurationForcedBindings = self.queries[sparqlName]["forcedBindings"]
            except KeyError as e:
                self.logger.debug("No forcedBindings for the query {}".format(sparqlName))
        
        else:

            # read the initial update
            try:
                configurationSparql = self.updates[sparqlName]["sparql"]
                configurationForcedBindings = self.updates[sparqlName]["forcedBindings"]
            except KeyError as e:
                self.logger.error("Update not found in configuration file")
                raise configurationParsingException("Update not found in configuration file")
        
        # for every forced binding perform a substitution
        for v in forcedBindings.keys():
            
            # check if v is in the configuration forced bindings
            if v in configurationForcedBindings.keys():
            
                # determine the variable replacement
                value = forcedBindings[v]
                valueType = configurationForcedBindings[v]["type"]

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
                configurationSparql = re.sub(r'(\?|\$){1}' + v + r'\s+', value + " ", configurationSparql, flags=0)

                # replace the variable when it is followed by a braket
                configurationSparql = re.sub(r'(\?|\$){1}' + v + r'\}', value + " } ", configurationSparql, flags=0)

                # replace the variable when it is followed by a dot
                configurationSparql = re.sub(r'(\?|\$){1}' + v + r'\.', value + " . ", configurationSparql, flags=0)

        # return
        return self.nsSparql + configurationSparql
        
    def getClientID(self):
        
        """Method used to obtain unique client ID from MAC"""
        
        self.client_id = str(get_mac())

        
        
    # store config
    def storeConfig(self):

        """Method used to update the content of the configuration file"""

        # store data into file
        if self.configurationExtension == ".YSAP":
            with open(self.configurationFile, "w") as ysapFileStream:
                yaml.dump(self.ysapDict, ysapFileStream)
                ysapFileStream.truncate()
        else:
            with open(self.configurationFile, "w") as jsapFileStream:
                json.dump(self.configurationDict, jsapFileStream, indent=4)
                jsapFileStream.truncate()
