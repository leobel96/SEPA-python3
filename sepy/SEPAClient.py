#!/usr/bin/python3

from os.path import splitext
import json
import logging
from .ConfigurationObject import *
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
        self.configuration = ConfigurationObject(File)
        self.connectionManager = ConnectionHandler()        
        

    # update
    def update(self, updateName, forcedBindings = {}, secure = False):

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
        sparqlUpdate = self.configuration.getUpdate(updateName, forcedBindings)
        
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
    def query(self, queryName, forcedBindings = {}, secure = False):
    
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
            # take register URI from configuration file
            registerURI = self.configuration.registerURI
            # take token request URI from configuration file
            tokenURI = self.configuration.tokenReqURI
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
    def subscribe(self, subscriptionName, alias = None, handler = None, yskFile = None):

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
        yskFile : str
            The file that contains secure websocket credentials (default = None)
        
        Returns
        -------
        subid : str
            The id of the subscription, useful to call the unsubscribe method

        """
        
        # debug print
        self.logger.debug("=== KP::subscribe invoked ===")
      
        # start the subscription and return the ID
        sparqlQuery = self.configuration.getQuery(subscriptionName, forcedBindings = {})
  
        subid = None
        if yskFile:
            subscribeURI = self.configuration.secureSubscribeURI
            registerURI = self.configuration.registerURI
            tokenURI = self.configuration.tokenReqURI
            subid = self.connectionManager.openWebsocket(subscribeURI, sparqlQuery, registerURI, tokenURI, alias = alias, handler = handler, yskFile = yskFile)
        else:
            subscribeURI = self.configuration.subscribeURI
            subid = self.connectionManager.openWebsocket(subscribeURI, sparqlQuery, alias = alias, handler = handler)
        return subid
        
    
    # unsubscribe
    def unsubscribe(self, subid = None, secure = False):

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
        self.connectionManager.closeWebsocket(spuid = subid, secure = secure)

