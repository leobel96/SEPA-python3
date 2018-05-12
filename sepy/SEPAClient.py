#!/usr/bin/python3

from os.path import splitext
import json
import logging
from .JSAPObject import *
from .YSAPObject import *
from .Exceptions import *
from .ConnectionHandler import *

# class KP
class SEPAClient:

    """
    This is the Low-level class used to develop a client for SEPA.

    Parameters
    ----------
    jparFile : str
        Name with relative/full path of the JPAR file used to exploit the security mechanism (default = None)
    logLevel : int
        The desired log level. Default = 40

    Attributes
    ----------
    subscriptions : dict
        Dictionary to keep track of the active subscriptions
    connectionManager : ConnectionManager
        The underlying responsible for network connections

    """

    # constructor
    def __init__(self, File, logLevel = 40):
        
        """
        Constructor for the Low-level KP class

        Parameters
        ----------
        File : str
            JSAP or YSAP file used for configuration
        logLevel : int
            The desired log level. Default = 40

        """

        # logger configuration
        self.logger = logging.getLogger("sepaLogger")
        self.logger.setLevel(logLevel)
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logLevel)
        self.logger.debug("=== KP::__init__ invoked ===")

        # initialize data structures
        self.subscriptions = {}

        # initialize handler
        head,tail = splitext (File)
        if tail.upper() == ".JSAP":
            self.configuration = JSAPObject(File)
            self.connectionManager = ConnectionHandler(File)
        elif tail.upper() == ".YSAP":
            self.configuration = YSAPObject(File)
            self.connectionManager = ConnectionHandler(File)
        else:
            raise WrongFileException("Wrong file selected")
        
        

    # update
    def update(self, updateName, forcedBindings = {}, secure = False, tokenURI = None, registerURI = None):

        """
        This method is used to perform a SPARQL update

        Parameters
        ----------
        updateName : str
            The SPARQL update to perform
        forcedBindings : dict
            The dictionary containing the bindings to fill the template
        secure : bool
            A boolean that states if the connection must be secure or not (default = False)
        tokenURI : str
            The URI to request token if using a secure connection (default = None)
        registerURI : str
            The URI to register if using a secure connection (default = None)

        Returns
        -------
        status : bool
            True or False, depending on the success/failure of the request
        results : json
            The results of the SPARQL update

        """
        
        # debug print
        self.logger.debug("=== KP::update invoked ===")

        # perform the update request
        updateURI = self.configuration.updateURI
        sparqlUpdate = self.configuration.getQuery(updateName, focedBindings)
        
        if secure:
            tokenURI = self.configuration.tokenReqURI
            registerURI = self.configuration.registerURI
            status, results = self.connectionManager.secureRequest(updateURI, sparqlUpdate, False, tokenURI, registerURI)
        else:
            status, results = self.connectionManager.unsecureRequest(updateURI, sparqlUpdate, False)

        # return
        if int(status) == 200:
            return True, results
        else:
            return False, results


    # query
    def query(self, queryName, forcedBindings = {}, secure = False, tokenURI = None, registerURI = None):
    
        """
        This method is used to perform a SPARQL query

        Parameters
        ----------
        queryName : str
            The friendly name of the SPARQL Query
        forcedBindings : dict
            The dictionary containing the bindings to fill the template
        secure : bool
            A boolean that states if the connection must be secure or not (default = False)
        tokenURI : str
            The URI to request token if using a secure connection (default = None)
        registerURI : str
            The URI to register if using a secure connection (default = None)

        Returns
        -------
        status : bool
            True or False, depending on the success/failure of the request
        results : json
            The results of the SPARQL query

        """

        # debug print
        self.logger.debug("=== KP::query invoked ===")
        
        # perform the query request
        queryURI = self.configuration.queryURI
        sparqlQuery = self.configuration.getQuery(queryName, forcedBindings)

        if secure:
            status, results = self.connectionManager.secureRequest(queryURI, sparqlQuery, True, tokenURI, registerURI)
        else:
            status, results = self.connectionManager.unsecureRequest(queryURI, sparqlQuery, True)
            
        # return 
        if int(status) == 200:
            jresults = json.loads(results)
            if "error" in jresults:
                return False, jresults["error"]["message"]
            else:
                return True, jresults
        else:
            return False, results
        

    # susbscribe
    def subscribe(self, subscriptionName, alias, handler, secure = False, registerURI = None, tokenURI = None):

        """
        This method is used to start a SPARQL subscription

        Parameters
        ----------
        subscriptionName : str
            The SPARQL subscription to request
        alias : str
            A friendly name for the subscription
        handler : Handler
            A class to handle notifications
        secure : bool
            A boolean that states if the connection must be secure or not (default = False)
        tokenURI : str
            The URI to request token if using a secure connection (default = None)
        registerURI : str
            The URI to register if using a secure connection (default = None)

        Returns
        -------
        subid : str
            The id of the subscription, useful to call the unsubscribe method

        """
        
        # debug print
        self.logger.debug("=== KP::subscribe invoked ===")
      
        # start the subscription and return the ID
        subscribeURI = self.configuration.subscribeURI
        sparqlQuery = self.configuration.getQuery(subscriptionName, focedBindings)
        
        subid = None
        if secure:
            subid = self.connectionManager.openSecureWebsocket(subscribeURI, sparqlQuery, alias, handler, registerURI, tokenURI)
        else:
            subid = self.connectionManager.openUnsecureWebsocket(subscribeURI, sparqlQuery, alias, handler)
        return subid
        
    
    # unsubscribe
    def unsubscribe(self, subid, secure = False):

        """
        This method is used to start a SPARQL subscription

        Parameters
        ----------
        subid : str
            The id of the subscription
        secure : bool
            A boolean that states if the connection must be secure or not (default = False)

        """
        
        # debug print
        self.logger.debug("=== KP::unsubscribe invoked ===")

        # close the subscription, given the id
        self.connectionManager.closeWebsocket(subid, secure)

