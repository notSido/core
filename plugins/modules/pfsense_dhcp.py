#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Mikhail Sidorenko <sido@crackshack.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_dhcp

short_description: Manage pfSense dhcps

version_added: "0.7.0"

description:
  - Manage pfSense dhcps.

options:
  enable:
    description: Enable DHCP server on LAN interface.
    type: bool
  ignorebootp:
    description: Ignore BOOTP queries.
    type: bool
  denyunknown:
    description: Deny Unknown Clients of the dhcp. When set to.
    default: disabled
    choices: ['disabled', 'enabled', 'class']
    type: str
  nonak:
    description: Ignore denied clients rather than reject.
    type: bool
  ignoreclientuids:
    description: Do not record a unique identifier (UID) in client lease data if present in the client DHCP request.
    type: bool
  range_from:
    description: Address Pool Range of the dhcp. From.
    default: 10.42.5.100
    type: str
  range_to:
    description: Address Pool Range of the dhcp. To.
    default: 10.42.5.200
    type: str
  wins1:
    description: WINS Servers of the dhcp.
    default: None
    type: str
  wins2:
    description: unknown_9
    default: None
    type: str
  dns1:
    description: DNS Servers of the dhcp.
    default: 9.9.9.9
    type: str
  dns2:
    description: unknown_11
    default: 8.8.8.8
    type: str
  dns3:
    description: unknown_12
    default: None
    type: str
  dns4:
    description: unknown_13
    default: None
    type: str
  omapi_port:
    description: OMAPI Port of the dhcp. Set the port that OMAPI will listen on. The default port is 7911, leave blank to disable.Only the first OMAPI configuration is used.
    default: None
    type: str
  omapi_key:
    description: OMAPI Key of the dhcp. Enter a key matching the selected algorithm.
    default: None
    type: str
  omapi_gen_key:
    description: Generate New Key.
    type: bool
  omapi_key_algorithm:
    description: Key Algorithm of the dhcp. Set the algorithm that OMAPI key will use.
    default: hmac-sha256
    choices: ['hmac-md5', 'hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512']
    type: str
  gateway:
    description: Gateway of the dhcp. The default is to use the IP address of this firewall interface as the gateway. Specify an alternate gateway here if this is not the correct gateway for the network. Enter "none" for no gateway assignment.
    default: 
    type: str
  domain:
    description: Domain Name of the dhcp. The default is to use the domain name of this firewall as the default domain name provided by DHCP. An alternate domain name may be specified here.
    default: 
    type: str
  domainsearchlist:
    description: Domain Search List of the dhcp. The DHCP server can optionally provide a domain search list. Use the semicolon character as separator.
    default: 
    type: str
  deftime:
    description: Default Lease Time of the dhcp. This is used for clients that do not ask for a specific expiration time. The default is 7200 seconds.
    default: 
    type: int
  maxtime:
    description: Maximum Lease Time of the dhcp. This is the maximum lease time for clients that ask for a specific expiration time. The default is 86400 seconds.
    default: 
    type: int
  failover_peerip:
    description: Failover peer IP of the dhcp. Leave blank to disable. Enter the interface IP address of the other firewall (failover peer) in this subnet. Firewalls must be using CARP. Advertising skew of the CARP VIP on this interface determines whether the DHCP daemon is Primary or Secondary. Ensure the advertising skew for the VIP on one firewall is < 20 and the other is > 20.
    default: 
    type: str
  staticarp:
    description: Enable Static ARP entries.
    type: bool
  dhcpleaseinlocaltime:
    description: Change DHCP display lease time from UTC to local time.
    type: bool
  statsgraph:
    description: Enable monitoring graphs for DHCP lease statistics.
    type: bool
  disablepingcheck:
    description: Disable ping check.
    type: bool
  ddnsupdate:
    description: Enable DDNS registration of DHCP clients.
    type: bool
  ddnsdomain:
    description: DDNS Domain of the dhcp. Enter the dynamic DNS domain which will be used to register client names in the DNS server.
    default: 
    type: str
  ddnsforcehostname:
    description: Force dynamic DNS hostname to be the same as configured hostname for Static Mappings.
    type: bool
  ddnsdomainprimary:
    description: Primary DDNS Server of the dhcp. Primary domain name server IPv4 address.
    default: 
    type: str
  ddnsdomainprimaryport:
    description: Primary DDNS Server of the dhcp. The port on which the server listens for DDNS requests.
    default: 
    type: str
  ddnsdomainsecondary:
    description: Secondary DDNS Server of the dhcp. Secondary domain name server IPv4 address.
    default: 
    type: str
  ddnsdomainsecondaryport:
    description: Secondary DDNS Server of the dhcp. The port on which the server listens for DDNS requests.
    default: 
    type: str
  ddnsdomainkeyname:
    description: DNS Domain Key of the dhcp. Dynamic DNS domain key name which will be used to register client names in the DNS server.
    default: 
    type: str
  ddnsdomainkeyalgorithm:
    description: Key Algorithm of the dhcp.
    default: hmac-md5
    choices: ['hmac-md5', 'hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512']
    type: str
  ddnsdomainkey:
    description: DNS Domain Key Secret of the dhcp. Dynamic DNS domain key secret which will be used to register client names in the DNS server.
    default: 
    type: str
  ddnsclientupdates:
    description: DDNS Client Updates of the dhcp. How Forward entries are handled when client indicates they wish to update DNS.  Allow prevents DHCP from updating Forward entries, Deny indicates that DHCP will do the updates and the client should not, Ignore specifies that DHCP will do the update and the client can also attempt the update usually using a different domain name.
    default: allow
    choices: ['allow', 'deny', 'ignore']
    type: str
  mac_allow:
    description: MAC Allow of the dhcp. List of full or partial MAC addresses to allow access in this scope/pool. Implicitly denies any MACs not listed. Does not define known/unknown clients. Enter addresses as comma separated without spaces.
    default: 
    type: str
  mac_deny:
    description: MAC Deny of the dhcp. List of full or partial MAC addresses to deny access in this scope/pool. Implicitly allows any MACs not listed. Does not define known/unknown clients. Enter addresses as comma separated without spaces.
    default: 
    type: str
  ntp1:
    description: NTP Server 1 of the dhcp.
    default: None
    type: str
  ntp2:
    description: NTP Server 2 of the dhcp.
    default: None
    type: str
  ntp3:
    description: NTP Server 3 of the dhcp.
    default: None
    type: str
  ntp4:
    description: NTP Server 4 of the dhcp.
    default: None
    type: str
  tftp:
    description: TFTP Server of the dhcp. Leave blank to disable. Enter a valid IP address, hostname or URL for the TFTP server.
    default: 
    type: str
  ldap:
    description: 'LDAP Server URI of the dhcp. Leave blank to disable. Enter a full URI for the LDAP server in the form ldap://ldap.example.com/dc=example,dc=com.'
    default: 
    type: str
  netboot:
    description: Enable Network Booting.
    type: bool
  nextserver:
    description: Next Server of the dhcp. Enter the IPv4 address of the next server.
    default: 
    type: str
  filename:
    description: Default BIOS File Name of the dhcp.
    default: 
    type: str
  filename32:
    description: UEFI 32 bit File Name of the dhcp.
    default: 
    type: str
  filename64:
    description: UEFI 64 bit File Name of the dhcp.
    default: 
    type: str
  filename32arm:
    description: ARM 32 bit File Name of the dhcp.
    default: 
    type: str
  filename64arm:
    description: ARM 64 bit File Name of the dhcp. Both a filename and a boot server must be configured for this to work! All five filenames and a configured boot server are necessary for UEFI & ARM to work!.
    default: 
    type: str
  uefihttpboot:
    description: 'UEFI HTTPBoot URL of the dhcp. string-format: http://(servername)/(firmwarepath).'
    default: 
    type: str
  rootpath:
    description: 'Root Path of the dhcp. string-format: iscsi:(servername):(protocol):(port):(LUN):targetname.'
    default: 
    type: str
  number0:
    description: 
    default: 
    type: int
  itemtype0:
    description: 
    default: text
    choices: ['text', 'string', 'boolean', 'unsigned integer 8', 'unsigned integer 16', 'unsigned integer 32', 'signed integer 8', 'signed integer 16', 'signed integer 32', 'ip-address']
    type: str
  value0:
    description: 
    default: 
    type: str
  if:
    description: 
    type: 

author: Mikhail Sidorenko (@)
'''

EXAMPLES = r'''
- name: Configure dhcp
  pfsensible.core.pfsense_dhcp:
    enable: true
    ignorebootp: true
    denyunknown: disabled
    nonak: true
    ignoreclientuids: true
    range_from: 
    range_to: 
    wins1: 
    wins2: 
    dns1: 
    dns2: 
    dns3: 
    dns4: 
    omapi_port: 
    omapi_key: 
    omapi_gen_key: true
    omapi_key_algorithm: hmac-md5
    gateway: 
    domain: 
    domainsearchlist: 
    deftime: 
    maxtime: 
    failover_peerip: 
    staticarp: true
    dhcpleaseinlocaltime: true
    statsgraph: true
    disablepingcheck: true
    ddnsupdate: true
    ddnsdomain: 
    ddnsforcehostname: true
    ddnsdomainprimary: 
    ddnsdomainprimaryport: 
    ddnsdomainsecondary: 
    ddnsdomainsecondaryport: 
    ddnsdomainkeyname: 
    ddnsdomainkeyalgorithm: hmac-md5
    ddnsdomainkey: 
    ddnsclientupdates: allow
    mac_allow: 
    mac_deny: 
    ntp1: 
    ntp2: 
    ntp3: 
    ntp4: 
    tftp: 
    ldap: 
    netboot: true
    nextserver: 
    filename: 
    filename32: 
    filename64: 
    filename32arm: 
    filename64arm: 
    uefihttpboot: 
    rootpath: 
    number0: 
    itemtype0: text
    value0: 
    if: 
'''
RETURN = r'''
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI).
    returned: always
    type: list
    sample: ["update dhcp set ..."]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_config_base import PFSenseModuleConfigBase

# TODO - Keep either this or the next compact version of DHCP_ARGUMENT_SPEC
DHCP_ARGUMENT_SPEC = {
    'enable': {
        'type': 'bool',
    },
    'ignorebootp': {
        'type': 'bool',
    },
    'denyunknown': {
        'choices': ['disabled', 'enabled', 'class'],
        'type': 'str',
    },
    'nonak': {
        'type': 'bool',
    },
    'ignoreclientuids': {
        'type': 'bool',
    },
    'range_from': {
        'type': 'str',
    },
    'range_to': {
        'type': 'str',
    },
    'wins1': {
        'type': 'str',
    },
    'wins2': {
        'type': 'str',
    },
    'dns1': {
        'type': 'str',
    },
    'dns2': {
        'type': 'str',
    },
    'dns3': {
        'type': 'str',
    },
    'dns4': {
        'type': 'str',
    },
    'omapi_port': {
        'type': 'str',
    },
    'omapi_key': {
        'type': 'str',
    },
    'omapi_gen_key': {
        'type': 'bool',
    },
    'omapi_key_algorithm': {
        'choices': ['hmac-md5', 'hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512'],
        'type': 'str',
    },
    'gateway': {
        'type': 'str',
    },
    'domain': {
        'type': 'str',
    },
    'domainsearchlist': {
        'type': 'str',
    },
    'deftime': {
        'type': 'int',
    },
    'maxtime': {
        'type': 'int',
    },
    'failover_peerip': {
        'type': 'str',
    },
    'staticarp': {
        'type': 'bool',
    },
    'dhcpleaseinlocaltime': {
        'type': 'bool',
    },
    'statsgraph': {
        'type': 'bool',
    },
    'disablepingcheck': {
        'type': 'bool',
    },
    'ddnsupdate': {
        'type': 'bool',
    },
    'ddnsdomain': {
        'type': 'str',
    },
    'ddnsforcehostname': {
        'type': 'bool',
    },
    'ddnsdomainprimary': {
        'type': 'str',
    },
    'ddnsdomainprimaryport': {
        'type': 'str',
    },
    'ddnsdomainsecondary': {
        'type': 'str',
    },
    'ddnsdomainsecondaryport': {
        'type': 'str',
    },
    'ddnsdomainkeyname': {
        'type': 'str',
    },
    'ddnsdomainkeyalgorithm': {
        'choices': ['hmac-md5', 'hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512'],
        'type': 'str',
    },
    'ddnsdomainkey': {
        'type': 'str',
    },
    'ddnsclientupdates': {
        'choices': ['allow', 'deny', 'ignore'],
        'type': 'str',
    },
    'mac_allow': {
        'type': 'str',
    },
    'mac_deny': {
        'type': 'str',
    },
    'ntp1': {
        'type': 'str',
    },
    'ntp2': {
        'type': 'str',
    },
    'ntp3': {
        'type': 'str',
    },
    'ntp4': {
        'type': 'str',
    },
    'tftp': {
        'type': 'str',
    },
    'ldap': {
        'type': 'str',
    },
    'netboot': {
        'type': 'bool',
    },
    'nextserver': {
        'type': 'str',
    },
    'filename': {
        'type': 'str',
    },
    'filename32': {
        'type': 'str',
    },
    'filename64': {
        'type': 'str',
    },
    'filename32arm': {
        'type': 'str',
    },
    'filename64arm': {
        'type': 'str',
    },
    'uefihttpboot': {
        'type': 'str',
    },
    'rootpath': {
        'type': 'str',
    },
    'number0': {
        'type': 'int',
    },
    'itemtype0': {
        'choices': ['text', 'string', 'boolean', 'unsigned integer 8', 'unsigned integer 16', 'unsigned integer 32', 'signed integer 8', 'signed integer 16', 'signed integer 32', 'ip-address'],
        'type': 'str',
    },
    'value0': {
        'type': 'str',
    },
    'if': {
        'type': '',
    },
}

# Compact style
DHCP_ARGUMENT_SPEC = dict(
    enable=dict(type='bool'),
    ignorebootp=dict(type='bool'),
    denyunknown=dict(type='str', choices=['disabled', 'enabled', 'class'],),
    nonak=dict(type='bool'),
    ignoreclientuids=dict(type='bool'),
    range_from=dict(type='str'),
    range_to=dict(type='str'),
    wins1=dict(type='str'),
    wins2=dict(type='str'),
    dns1=dict(type='str'),
    dns2=dict(type='str'),
    dns3=dict(type='str'),
    dns4=dict(type='str'),
    omapi_port=dict(type='str'),
    omapi_key=dict(type='str'),
    omapi_gen_key=dict(type='bool'),
    omapi_key_algorithm=dict(type='str', choices=['hmac-md5', 'hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512'],),
    gateway=dict(type='str'),
    domain=dict(type='str'),
    domainsearchlist=dict(type='str'),
    deftime=dict(type='int'),
    maxtime=dict(type='int'),
    failover_peerip=dict(type='str'),
    staticarp=dict(type='bool'),
    dhcpleaseinlocaltime=dict(type='bool'),
    statsgraph=dict(type='bool'),
    disablepingcheck=dict(type='bool'),
    ddnsupdate=dict(type='bool'),
    ddnsdomain=dict(type='str'),
    ddnsforcehostname=dict(type='bool'),
    ddnsdomainprimary=dict(type='str'),
    ddnsdomainprimaryport=dict(type='str'),
    ddnsdomainsecondary=dict(type='str'),
    ddnsdomainsecondaryport=dict(type='str'),
    ddnsdomainkeyname=dict(type='str'),
    ddnsdomainkeyalgorithm=dict(type='str', choices=['hmac-md5', 'hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512'],),
    ddnsdomainkey=dict(type='str'),
    ddnsclientupdates=dict(type='str', choices=['allow', 'deny', 'ignore'],),
    mac_allow=dict(type='str'),
    mac_deny=dict(type='str'),
    ntp1=dict(type='str'),
    ntp2=dict(type='str'),
    ntp3=dict(type='str'),
    ntp4=dict(type='str'),
    tftp=dict(type='str'),
    ldap=dict(type='str'),
    netboot=dict(type='bool'),
    nextserver=dict(type='str'),
    filename=dict(type='str'),
    filename32=dict(type='str'),
    filename64=dict(type='str'),
    filename32arm=dict(type='str'),
    filename64arm=dict(type='str'),
    uefihttpboot=dict(type='str'),
    rootpath=dict(type='str'),
    number0=dict(type='int'),
    itemtype0=dict(type='str', choices=['text', 'string', 'boolean', 'unsigned integer 8', 'unsigned integer 16', 'unsigned integer 32', 'signed integer 8', 'signed integer 16', 'signed integer 32', 'ip-address'],),
    value0=dict(type='str'),
)

# TODO - Check for validity - what parameters are actually required when creating a new dhcp?
DHCP_REQUIRED_IF = [
]

# TODO - Review this for clues for input validation.  Search for functions in the below require_once files in /etc and /usr/local/pfSense/include
PHP_VALIDATION = r'''
require_once('guiconfig.inc');
require_once('filter.inc');
require_once('rrd.inc');
require_once('shaper.inc');
require_once('util.inc');
require_once('services_dhcp.inc');



'''
"""
# TODO - Add validation and parsing methods for parameters that require it
DHCP_ARG_ROUTE = dict(
# TODO - These are just examples
    authorizedkeys=dict(parse=p2o_ssh_pub_key),
    password=dict(validate=validate_password),
)
"""
DHCP_ARG_ROUTE = {}

DHCP_PHP_COMMAND_SET = r'''
require_once("filter.inc");
if (filter_configure() == 0) { clear_subsystem_dirty(''); }
'''


class PFSenseDhcpModule(PFSenseModuleConfigBase):
    """ module managing pfsense dhcps """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return DHCP_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseDhcpModule, self).__init__(module, pfsense, root='system', node='None', key='None', update_php=DHCP_PHP_COMMAND_SET,
                                                arg_route=DHCP_ARG_ROUTE)


def main():
    module = AnsibleModule(
        argument_spec=DHCP_ARGUMENT_SPEC,
        required_if=DHCP_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseDhcpModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
