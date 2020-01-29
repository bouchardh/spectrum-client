"""specrum_client"""

import os
import xml.etree.ElementTree as ET

import requests
from requests.auth import HTTPBasicAuth

SPECTRUM_URL = os.environ.get('SPECTRUM_URL')
SPECTRUM_USERNAME = os.environ.get('SPECTRUM_USERNAME')
SPECTRUM_PASSWORD = os.environ.get('SPECTRUM_PASSWORD')
DEFAULT_ATTRIBUTES = [
    "0x129fa",  # Model Handle
    "0x1006e",  # Model Name
    "0x1000a",  # Condition
    "0x11ee8",  # Model Class
    "0x129e7",  # Site ID
    "0x12d7f",  # IP Address
    "0x1290c",  # Criticality
    "0x10000",  # Model Type Name
    "0x10001",  # Model Type Handle
    "0x23000e",  # Device Type
    "0x11d42",  # Landscape Name
    "0x1295d",  # isManaged
    "0x11564",  # Notes
    "0x12db9"]  # ServiceDesk Asset ID
convert_to_hex = ['0x10001', '0x12a56']


class SpectrumClientException(Exception):
    """Raised on OneClick errors"""


class SpectrumClientAuthException(SpectrumClientException):
    """Raised on authentication errrors"""


class SpectrumClientParameterError(SpectrumClientException):
    """Raised when invalid parameters are passed"""


class Spectrum(object):
    """A wrapper form OneClick REST API."""
    headers = {'Content-Type': 'application/xml; charset=UTF-8'}

    attributes = DEFAULT_ATTRIBUTES
    xml_namespace = {'ca': 'http://www.ca.com/spectrum/restful/schema/response'}
    models_search_template = '''<?xml version="1.0" encoding="UTF-8"?>
    <rs:model-request throttlesize="9999"
    xmlns:rs="http://www.ca.com/spectrum/restful/schema/request"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://www.ca.com/spectrum/restful/schema/request ../../../xsd/Request.xsd ">
        <rs:target-models>
            <rs:models-search>
                <rs:search-criteria xmlns="http://www.ca.com/spectrum/restful/schema/filter">
                    <filtered-models>
                    {models_filter}
                    </filtered-models>
                </rs:search-criteria>
            </rs:models-search>
        </rs:target-models>
        {models_attributes}
        </rs:model-request>
    '''
    event_by_ip_template = '''<?xml version="1.0" encoding="UTF-8"?>
    <rs:event-request throttlesize="10" xmlns:rs="http://www.ca.com/spectrum/restful/schema/request" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.ca.com/spectrum/restful/schema/request ../../../xsd/Request.xsd">
        <rs:event>
            <rs:target-models>
                <rs:models-search>
                    <rs:search-criteria xmlns="http://www.ca.com/spectrum/restful/schema/filter">
                    <action-models>
                        <filtered-models>
                        <equals>
                            <model-type>SearchManager</model-type>
                        </equals>
                        </filtered-models>
                        <action>FIND_DEV_MODELS_BY_IP</action>
                        <attribute id="AttributeID.NETWORK_ADDRESS">
                            <value>{address}</value>
                        </attribute>
                    </action-models>
                    </rs:search-criteria>
                </rs:models-search>
            </rs:target-models>
            <!-- event ID -->
            <rs:event-type id="{event}"/>
            <!-- attributes/varbinds -->
            {var_binds}
        </rs:event>
    </rs:event-request>
'''

    def __init__(self, url=SPECTRUM_URL, username=SPECTRUM_USERNAME, password=SPECTRUM_PASSWORD):
        if url is None:
            raise ValueError('Spectrum (OneClick) url must be provided either in the constructor or as an environment variable')
        self.url = url if not url.endswith('/') else url[:-1]
        self.auth = HTTPBasicAuth(username, password)
        # SSL verification on a per connection basis
        self.ssl_verify = True
        # Keep generated xml for easy troubleshooting
        self.__xml = None

    @property
    def xml(self):
        return self.__xml

    def xml_attributes(self):
        if self.attributes is None:
            self.attributes = DEFAULT_ATTRIBUTES
        xml = ''
        for attr in self.attributes:
            if type(attr) is 'int':
                attr = hex(attr)
            xml += '<rs:requested-attribute id="{}" />\n'.format(attr)
        return xml
    
    def _parse_create(self, res):
        self._check_http_response(res)

        root = ET.fromstring(res.content)
        result = root.get('error')
        if result == 'Success':
            return
        # Did not get Success
        raise SpectrumClientParameterError(result)

    def _parse_get(self, res):
        self._check_http_response(res)

        root = ET.fromstring(res.content)
        model_error = root.find('.//ca:model', self.xml_namespace).get('error')
        if model_error:
            raise SpectrumClientParameterError('Model Error: ' + model_error)
        attr_error = root.find('.//ca:attribute', self.xml_namespace).get('error')
        if attr_error:
            raise SpectrumClientParameterError(attr_error)

    def _parse_update(self, res):
        self._check_http_response(res)

        root = ET.fromstring(res.content)
        if root.find('.//ca:model', self.xml_namespace).get('error') == 'Success':
            return

        if root.find('.//ca:model', self.xml_namespace).get('error') == 'PartialFailure':
            msg = root.find('.//ca:attribute', self.xml_namespace).get('error-message')
        else:
            msg = root.find('.//ca:model', self.xml_namespace).get('error-message')
        raise SpectrumClientParameterError(msg)

    def _build_filter(self, filters, landscape=None):
        if isinstance(filters[0], (str, int)):
            filters = [filters]
        filters = [
            dict(
                operation=f[1],
                attr_id=hex(f[0]) if isinstance(f[0], int) else f[0],
                value=f[2]
            ) for f in filters
        ]
        filters = ['''
            <{operation}>
                <attribute id="{attr_id}">
                    <value>{value}</value>
                </attribute>
            </{operation}>'''.format(**f) for f in filters]
        filters = '\n'.join(filters)
        if landscape:
            landscape_filter = self.xml_landscape_filter(landscape)
        else:
            landscape_filter = ''

        models_filter = '''
        <and>
            {landscape_filter}
            {filters}
         </and>'''.format(landscape_filter=landscape_filter, filters=filters)
        return(self.models_search_template.format(models_filter=models_filter, models_attributes=self.xml_attributes()))

    def if_int(self, input, attr=None):
        """Convert to int if possible, otherwis, return string
           Convert to HEX if in convert_to_hex list
        """
        if input is None:
            return None
        if not input.isdigit():
            return input
        num = int(input)
        if attr in convert_to_hex:
            num = hex(num)
        return num

    @staticmethod
    def _check_http_response(res):
        """Validate the HTTP response"""
        if res.status_code == 401:
            raise SpectrumClientAuthException('Authorization Failure. Invalid user name or password.')
        res.raise_for_status()

    @staticmethod
    def xml_landscape_filter(landscape):
        """Return a xml fragment filtering by landscape"""
        xml = '''
        <greater-than>
            <attribute id="0x129fa">
                <value>{}</value>
            </attribute>
        </greater-than>
        <less-than>
            <attribute id="0x129fa">
                <value>{}</value>
            </attribute>
        </less-than>'''
        landscape_start = hex(landscape)
        landscape_end = hex(landscape + 0xfffff)
        return xml.format(landscape_start, landscape_end).strip()

    def add_model(self,modelname, model):
        '''Create model from dict passed as model'''
        self.__xml = ''
        # Add model name attribute to dict
        model['0x1006e'] = modelname

        # Set model type to '0x1002d' if not found and no ipaddress
        if model.get('0x10001') is not None:
            model['mtypeid'] = model.pop('0x10001')
        elif model.get('ipaddress') is None:
            model['mtypeid'] = model.get('mtypeid', '0x1002d')

        # look for parent, if not found, add Universe as parent
        if not ('parent' in model.keys()):
            model['parentmh'] = model.get('parentmh', '0x100004')
        else:
            modelfilter = [('0x1006e', 'equals', model['parent']), ('0x10001', 'equals','0x1002d' )]
            result = self.models_by_filters(modelfilter)
            if len(result) == 0:
                # LAN type not found, try Network type
                modelfilter = [('0x1006e', 'equals', model['parent']), ('0x10001', 'equals','0x1002e' )]
                result = self.models_by_filters(modelfilter)
                if len(result) == 0:
                    # parent model handle not found, return None
                    return None
            model['parentmh'] = list(result)[0] # Take first result, TODO: need to track duplicates
            del model['parent']
        
        # set landscapeid to 0x100000 if not found
        model['landscapeid'] = model.get('landscapeid', '0x100000')

        # if model type is globalcollection, remove parentmh
        if model.get('mtypeid') == '0x10474':
            del model['parentmh']

        # if it has asytem description, remove it and the device name
        if model.get('0x10052') is not None:
            model.pop('0x10052')
            model.pop('0x1006e')

        # Generate URL
        # Refactor with request parameters
        url = '{}/spectrum/restful/model'.format(self.url)
        params = []
        for attrib in model:
            if model[attrib] is None:
                continue
            if attrib[:2] == '0x':
                params.append(('attr', attrib))
                params.append(('val', model[attrib]))
            else:
                params.append((attrib, model[attrib]))

        # Do API call
        result = requests.post(url, params=params, headers=self.headers, auth=self.auth, verify=self.ssl_verify)

        # Make sure it worked and return mh
        self._parse_create(result)
        xmlData = ET.fromstring(result.content)
        return xmlData.find('ca:model', self.xml_namespace).get('mh')

    def get_attribute(self, model_handle, attr_id):
        """Get an attribute from Spectrum model.

        Arguments:
            model_handle {int} -- Model Handle of the model being queried.
            attr_id {int} -- Attribute ID of the attribute being queried.
        """
        url = '{}/spectrum/restful/model/{}'.format(self.url, hex(model_handle))
        self.__xml = None
        params = {'attr': hex(attr_id)}
        res = requests.get(url, params=params, auth=self.auth, verify=self.ssl_verify)
        self._parse_get(res)
        root = ET.fromstring(res.content)
        return root.find('.//ca:attribute', self.xml_namespace).text

    def devices_by_filters(self, filters, landscape=None):
        """Returns a list of devices matching the filters"""
        device_only = (0x10001, 'is-derived-from', 0x1004b)
        filters = [device_only] + filters
        xml = self._build_filter(filters, landscape)
        return self.search_models(xml)

    def devices_by_attr(self, attr, value, landscape=None):
        """Returns a list of devices matching an attribute value"""
        return self.devices_by_filters([(attr, 'equals', value)], landscape)

    def devices_by_name(self, regex, landscape=None):
        """Returns a list of devices for which the name matches a regex"""
        return self.devices_by_filters([('0x1006e', 'has-pcre', regex)], landscape)

    def models_by_filters(self, filters, landscape=None):
        """Returns a list of models matching the filters"""
        xml = self._build_filter(filters, landscape)
        return self.search_models(xml)

    def models_by_attr(self, attr, value, landscape=None):
        """Returns a list of models matching an attribute value"""
        return self.models_by_filters([(attr, 'equals', value)], landscape)

    def models_by_name(self, regex, landscape=None):
        """Returns a list of models for which the name matches a regex"""
        return self.models_by_filters([('0x1006e', 'has-pcre', regex)], landscape)

    def search_models(self, xml):
        """Returns the models matching the xml search"""
        url = '{}/spectrum/restful/models'.format(self.url)
        self.__xml = xml.encode('utf-8')
        res = requests.post(url, self.xml, headers=self.headers, auth=self.auth, verify=self.ssl_verify)
        self._check_http_response(res)
        root = ET.fromstring(res.content)
        etmodels = root.findall('.//ca:model', self.xml_namespace)
        models = {
            model.get('mh'): {
                attr.get('id'): attr.text for attr in model.getchildren()
            } for model in etmodels
        }
        # convert number strings to actual numbers, this is possibly a breaking change
        for model in list(models):
            for attrib in models[model]:
                models[model][attrib] = self.if_int(models[model][attrib], attrib)
        return models

    def set_maintenance(self, model_handle, on=True):
        """Puts a device in maintenance mode"""
        return self.update_attribute(model_handle, 0x1295d, str(not on))

    def update_attribute(self, model_handle, attr_id, value):
        """Update a single  attribute of a model"""
        self.update_attributes(model_handle, (attr_id, value))

    def update_attributes(self, model_handle, updates):
        """Update a list of attributes of a model"""
        if isinstance(model_handle, int):
            model_handle = hex(model_handle)
        if isinstance(updates[0], (str, int)):
            updates = [updates]
        updates = [
            f(x) for x in updates for f in (
                lambda x: ('attr', hex(x[0]) if isinstance(x[0], int) else x[0]),
                lambda x: ('val', x[1])
            )
        ]
        url = self.url + '/spectrum/restful/model/{}'.format(model_handle)
        self.__xml = None
        res = requests.put(url, params=updates, auth=self.auth, verify=self.ssl_verify)
        self._parse_update(res)

    # TODO: Parse the response
    def generate_event_by_ip(self, event, address, variables):
        var_binds = ""
        for key, value in variables.items():
            var_binds += '<rs:varbind id="{}">{}</rs:varbind>'.format(key, value)
        self.__xml = self.event_by_ip_template.format(event=event, address=address, var_binds=var_binds)
        url = self.url + '/spectrum/restful/events'
        res = requests.post(url, self.xml, headers=self.headers, auth=self.auth, verify=self.ssl_verify)
        return res
