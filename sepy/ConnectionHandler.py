#!/usr/bin/python3

# global requirements
from threading import Thread
import websocket
import requests
import asyncio
import logging
import base64
import time
import json
import sys
import ssl
import yaml

# local requirements
from .Exceptions import *
from .ConfigurationObject import *

# class ConnectionHandler
class ConnectionHandler:

    """This is the ConnectionHandler class"""

    # constructor
    def __init__(self, logLevel = 10):
        
        """Constructor of the ConnectionHandler class"""

        # logger configuration
        self.logger = logging.getLogger("sepaLogger")
        self.logger.setLevel(logLevel)
        self.logger.debug("=== ConnectionHandler::__init__ invoked ===")
        logging.getLogger("urllib3").setLevel(logLevel)
        logging.getLogger("requests").setLevel(logLevel)
            
        # open subscriptions
        self.websockets = {}
        self.lastSpuid = None
        
        # initialize client credentials
        self.yskDict = None
        self.filename = None
        self.client_id = None
        self.client_secret = None
        self.jwt = None
        self.expires = None
        self.type = None
        

    # do HTTP request
    def unsecureRequest(self, reqURI, sparql, isQuery):

        """Method to issue a SPARQL request over HTTP"""

        # debug
        self.logger.debug("=== ConnectionHandler::unsecureRequest invoked ===")

        # perform the request
        headers = {"Accept":"application/json"}
        if isQuery:
            headers["Content-Type"] = "application/sparql-query"
        else:
            headers["Content-Type"] = "application/sparql-update"

        r = requests.post(reqURI, headers = headers, data = sparql.encode("utf-8"))
        r.connection.close()
        return r.status_code, r.text


    # do HTTPS request
    def secureRequest(self, reqURI, sparql, isQuery, tokenURI, registerURI, File):

        # debug
        self.logger.debug("=== ConnectionHandler::secureRequest invoked ===")
        
        yskHandler(File)
        
        if self.client_secret is None:
            self.register(registerURI)
        if self.jwt is None:
            self.requestToken(tokenURI)
                        
        # perform the request
        self.logger.debug("Performing a secure SPARQL request")
        if isQuery:
            headers = {"Content-Type":"application/sparql-query", 
                       "Accept":"application/json",
                       "Authorization": "Bearer " + self.jwt}
            r = requests.post(reqURI, headers = headers, data = sparql, verify = False)        
            r.connection.close()
        else:
            headers = {"Content-Type":"application/sparql-update", 
                       "Accept":"application/json",
                       "Authorization": "Bearer " + self.jwt}
            r = requests.post(reqURI, headers = headers, data = sparql, verify = False)        
            r.connection.close()
            
        # check for errors on token validity
        if r.status_code == 401:
            self.jwt = None
            self.yskDict["jwt"] = self.jwt
            self.storeConfig()
            raise TokenExpiredException

        # return
        return r.status_code, r.text

    
    ###################################################
    #
    # registration function
    #
    ###################################################

    def register(self, registerURI):

        # debug print
        self.logger.debug("=== ConnectionHandler::register invoked ===")
        
        # obtain client_id
        self.getClientID()
        
        # define headers and payload
        headers = {"Content-Type":"application/json", "Accept":"application/json"}
        payload = '{"client_identity":' + self.client_id + ', "grant_types":["client_credentials"]}'
        
        # perform the request
        r = requests.post(registerURI, headers = headers, data = payload, verify = False)        
        r.connection.close()
        if r.status_code == 201:

            # parse the response
            jresponse = json.loads(r.text)

            # encode with base64 client_id and client_secret
            cred = base64.b64encode(bytes(jresponse["client_id"] + ":" + jresponse["client_secret"], "utf-8"))
            self.client_secret = "Basic " + cred.decode("utf-8")
            self.yskDict["client_secret"] = self.client_secret
            
            # store data into the configuration file
            self.storeConfig()

        else:
            raise RegistrationFailedException()
        
    ###################################################
    #
    # token request
    #
    ###################################################

    # do request token
    def requestToken(self, tokenURI):

        # debug print
        self.logger.debug("=== ConnectionHandler::requestToken invoked ===")
        
        # define headers and payload        
        headers = {"Content-Type":"application/json", 
                   "Accept":"application/json",
                   "Authorization": self.client_secret}    
        
        # perform the request
        r = requests.post(tokenURI, headers = headers, verify = False)        
        r.connection.close()

        if r.status_code == 201:
            jresponse = json.loads(r.text)
            self.jwt = jresponse["token"]["access_token"]
            self.yskDict["jwt"] = self.jwt
            
            # store data into the configuration file
            self.storeConfig()
        else:
            raise TokenRequestFailedException()


    ###################################################
    #
    # websocket section
    #
    ###################################################

    # do open websocket
    def openWebsocket(self, subscribeURI, sparql, registerURI = None, tokenURI = None, alias = None, handler = None, yskFile = None):                         

    #yskFile is used for credentials storage
    
        # debug
        self.logger.debug("=== ConnectionHandler::openWebsocket invoked ===")

        if registerURI is not None and tokenURI is not None and yskFile is not None:    # Secure request 
            secure = True
        else:
            secure = False
                
        if secure:
            self.yskHandler(yskFile)
            if self.client_secret is None:
                self.register(registerURI)
            if self.jwt is None:
                self.requestToken(tokenURI)
        
        
        # initialization
        handler = handler
        spuid = None

        # on_message callback
        def on_message(ws, message):

            # debug
            self.logger.debug("=== ConnectionHandler::on_message invoked ===")
            self.logger.debug(message)

            # process message
            jmessage = json.loads(message)
                
            
            if "notification" in jmessage:
                
                nonlocal spuid
                sequence = jmessage["notification"]["sequence"]
                spuid = jmessage["notification"]["spuid"]
                
                if sequence == "0":     # just subscribed
                    self.logger.log("Subscribed to spuid: " + spuid)
                    temp = {}
                    temp["ws"] = ws
                    temp["authorization"] = self.jwt
                    self.websockets[spuid] = temp    # save the subscription id, the thread and the jwt
         
                else:
                    added = jmessage["notification"]["addedResults"]
                    removed = jmessage["notification"]["removedResults"]
                    self.logger.debug("Added bindings: {}".format(added))
                    self.logger.debug("Removed bindings: {}".format(removed))
                    
                    if handler is not None:
                        handler.handle(added, removed)
                    
                    
            elif "error" in jmessage:                
                
                self.logger.error(jmessage)
                
                if handler is not None:
                    handler.handleError(jmessage)
                
            elif "unsubscribed" in jmessage:
                
                uspuid = jmessage["unsubscribed"]["spuid"]
                self.logger.log("Successfully unsubscribed from spuid: " + uspuid)
                try:
                    ws.close()
                    del self.websockets[uspuid]
                except:
                    pass
                
            else:

                self.logger.error("Unknown message received: " + jmessage)


        # on_error callback
        def on_error(ws, error):

            self.logger.debug("=== ConnectionHandler::on_error invoked ===")
            self.logger.error("Error:" + error)
            if handler is not None:
                handler.handleError(error)


        # on_close callback
        def on_close(ws):

            # debug
            self.logger.debug("=== ConnectionHandler::on_close invoked ===")

            # destroy the websocket dictionary
            try:
                del self.websockets[spuid]
            except:
                pass


        # on_open callback
        def on_open(ws):           

            # debug
            self.logger.debug("=== ConnectionHandler::on_open invoked ===")

            # composing message
            msg = {}
            msg1 = {}
            msg1["sparql"] = sparql
            if alias is not None:
                msg["alias"] = alias
            if secure:
                msg1["authorization"] = self.jwt
            
            msg["subscribe"] = msg1
            # send subscription request
            self.logger.debug(msg)
            ws.send(json.dumps(msg))
        

        # configuring the websocket
        ws = websocket.WebSocketApp(subscribeURI,
                                    on_message = on_message,
                                    on_error = on_error,
                                    on_close = on_close,
                                    on_open = on_open)                                        
        
        # I don't know why but thread immediately dies. If I don't use threads, the rest
        # of the code stops working
        
        if secure:
            wst=Thread(target=ws.run_forever,kargs=dict(sslopt={"cert_reqs": ssl.CERT_NONE}))
        else:
            wst=Thread(target=ws.run_forever)
        
        wst.daemon = True
        wst.start()
        # return
        while not spuid:
            self.logger.debug("Waiting for subscription ID")
            time.sleep(0.1)            
        #self.lastSpuid = spuid
        return spuid
        
        def close():
        
            # debug
            self.logger.debug("=== ConnectionHandler::closeWebsocket invoked ===")

            nonlocal spuid
            nonlocal ws
            
            # Compose unsubscription message
            message = {}
            temp = {}
            temp["spuid"] = spuid     
            if secure:
                temp["authorization"] = self.websockets[spuid]["authorization"]
            message["unsubscribe"] = temp
            
            print("ws: {}".format(ws))
            ws.send(json.dumps(message))
        
        
    def getClientID(self):
    
        """Method used to obtain unique client ID from MAC"""
        
        self.client_id = str(get_mac())
        self.yskDict["client_id"] = self.client_id
        
        
    def yskHandler(self, File):
        
        """Method used to handle ysk file used to store credentials"""
        
        try:
            with open(File) as yskFileStream:
                self.yskDict = yaml.load(yskFileStream)
            print (self.yskDict)
            self.filename = File
            self.client_id = self.yskDict["security"].get("client_id")
            self.client_secret = self.yskDict["security"].get("client_secret")
            self.jwt = self.yskDict["security"].get("jwt")
            self.expires = self.yskDict["security"].get("expires")
            self.type = self.yskDict["security"].get("type")
        except Exception as e:
            self.logger.error("Parsing of the YSK file failed")
            raise YSKParsingException("Parsing of the YSK file failed") 
      
    # store config
    def storeConfig(self):

        """Method used to update the content of the configuration file"""

        # store data into file
        with open(self.filename, "w") as yskFileStream:
            yaml.dump(self.yskDict, yskFileStream)
            yskFileStream.truncate()
        
