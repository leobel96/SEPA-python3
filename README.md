# SEPA-python3
Client-side libraries for the SEPA platform (Python3)

## Installation and usage

Go to the folder named `dist`, uncompress the archive using `tar`, then type the usual:

```python setup.py build```

and

```python setup.py install```

(this one as root).

To use the classes you have to import them in this way:

```
from sepy.<the class you want to import> import *
```

For example, if you want to import the ConfigurationObject (used to handle JSAP and YSAP files) you have to write:

```python
from sepy.ConfigurationObject import *
```

This library consists of 5 classes that can be used for different purposes:
- Configurationbject: An handler class for YSAP and JSAP files
- SEPAClient: A low-level class used to develop a client for SEPA
- ConnectionHandler: A class for connection handling
- BasicHandler: A simple example of an Handler class
- Exceptions: Used to handle exceptions

Let's talk about some classes deeply:

## SEPAClient

These APIs allows to develop a client for the SEPA platform using a simple interface. First of all the class SEPAClient must be initialized. Then the standard methods to interact with the broker are available.

### Initialization parameters:
- File :
  A string indicating the name with relative/full path of the YSAP or JSAP file used for configuration
- logLevel :
  A number indicating the desired log level. Default = 40
The parameters are optional. They activate query, update, subscribe, unsubscribe methods.

### Example with the mqtt.yaml file

```python
sc = SEPAClient("mqtt.yaml") # A JSAP or YSAP file
```

### Query and Update

These two methods (`query` and `update`) return a boolean indicating the request's success and a JSON with the results of the requests.

#### Query and Update parameters:
- queryName/updateName :
  A string indicating the friendly name for the query in JSAP or YSAP file; the complete query/update string will be obtained by the parser
- forcedBindings :
  A dictionary for in-request name replacements; by default it is empty
- secure :
  A boolean specifying whether security mechanisms should be used or not; by default it is set as unsecure
  
Refering to the previous example:

```python
queryName = "MQTT_TOPICS"
simple_query = sc.query(queryName, {})
updateName = "MQTT_MESSAGE"
forcedBindings = {"topic":"top2", "broker":"brok2", "value":"val2"}
simple_update = sc.update(updateName, forcedBindings)
```

### Subscribe and Unsubscribe

The `subscribe` primitive requires a SPARQL query, an alias for the subscription, an handler class (containing the handle method) and the boolean referred to security. The `unsubscribe` primitive only needs to know the ID of the subscription.

## YSAPObject and JSAPObject

This package supports both Semantic Application Profiles encoded with YAML or JSON. Simply create an instance of the desired class and exploits the methods to get a query/update with the provided forced bindings.

## Something else?

Yes, (almost) all the code is documented through pydoc, so if you want, you can get the full documentation of attributes and methods. For example from prompt write:

```
python -m pydoc sepy.YSAPObject
```

## Foreseen changes

- [ ] Update tests
- [ ] Correct subscribe problems
- [ ] Correct secure requests
- [x] Modify YSAPObject and JSAPObject classes in order to automatically add prefixes to queries/updates
- [ ] Add possibility to install the library using pip

Stay Tuned!
