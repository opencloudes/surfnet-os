# Copyright 2020 OpenCloud.ES & Fairbanks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import json
import os
from itertools import chain
import shutil
import subprocess
import yaml

from collections import OrderedDict
from copy import deepcopy
from functools import partial
import uuid
import glob
from base64 import b64encode
from charmhelpers.contrib.openstack import context, templating
from charmhelpers.contrib.openstack.neutron import (
    neutron_plugin_attribute,
)

from charmhelpers.contrib.openstack import context, templating
from charmhelpers.contrib.openstack.utils import (
    os_release,
    get_os_codename_install_source,
    configure_installation_source,
    incomplete_relation_data,
    is_unit_paused_set,
    make_assess_status_func,
    pause_unit,
    resume_unit,
    os_application_version_set,
    token_cache_pkgs,
    enable_memcache,
    CompareOpenStackReleases,
    reset_os_release,
    remote_restart,
    os_release,
)
from charmhelpers.core.unitdata import kv
from collections import OrderedDict
import vpp_context
from charmhelpers.contrib.network.ovs import (
    add_bridge,
    add_bridge_port,
    is_linuxbridge_interface,
    add_ovsbridge_linuxbridge,
    full_restart,
    enable_ipfix,
    disable_ipfix,
)
from charmhelpers.core.hookenv import (
    charm_dir,
    config,
    log,
    DEBUG,
    relation_ids,
    related_units,
    relation_get,
    relation_set,
    local_unit,
    is_leader,
)

from charmhelpers.fetch import (
    apt_update,
    apt_install,
    apt_upgrade,
    add_source,
    filter_missing_packages,
    apt_purge,
    apt_autoremove,
)

from charmhelpers.core.host import (
    lsb_release,
    CompareHostReleases,
    service_stop,
    service_start,
    service_restart,
)

from charmhelpers.contrib.openstack.neutron import (
    parse_bridge_mappings,
    determine_dkms_package,
    headers_package,
)
from charmhelpers.contrib.openstack.context import (
    ExternalPortContext,
    DataPortContext,
    WorkerConfigContext,
    parse_data_port_mappings,
    DHCPAgentContext,
    validate_ovs_use_veth,
)
from charmhelpers.core.host import (
    lsb_release,
    service_restart,
    service_running,
    CompareHostReleases,
    init_is_systemd,
    group_exists,
    user_exists,
    is_container,
    restart_on_change
)
from charmhelpers.core.kernel import (
    modprobe,
)

from charmhelpers.fetch import (
    apt_install,
    apt_purge,
    apt_update,
    filter_installed_packages,
    filter_missing_packages,
    apt_autoremove,
    get_upstream_version,
    add_source,
)

from pci import PCINetDevices

VERSION_PACKAGE = 'neutron-common'
NOVA_CONF_DIR = "/etc/nova"
VPP_CONF_DIR = "/etc/vpp"
VPP_CONF = '%s/startup.conf' % VPP_CONF_DIR
NEUTRON_CONF_DIR = "/etc/neutron"
NEUTRON_DEFAULT = '/etc/default/neutron-server'
ML2_CONF = '%s/plugins/ml2/ml2_conf.ini' % NEUTRON_CONF_DIR
OVS_CONF = '%s/plugins/ml2/openvswitch_agent.ini' % NEUTRON_CONF_DIR
EXT_PORT_CONF = '/etc/init/ext-port.conf'
NEUTRON_METADATA_AGENT_CONF = "/etc/neutron/metadata_agent.ini"

PY3_PACKAGES = [
    'python3-neutron',
    'python3-zmq',  # fwaas_v2_log
]

PURGE_PACKAGES = [
    'python-neutron',
    'python-neutron-fwaas',
]

FILES = 'files/'
TEMPLATES = 'templates/'
OVS_DEFAULT = '/etc/default/openvswitch-switch'
DPDK_INTERFACES = '/etc/dpdk/interfaces'
VPP_CONF = os.path.join(VPP_CONF_DIR,
                                    'startup.conf')
VPP_SYSTEMD_UNIT = os.path.join('/lib/systemd/system',
                                          'vpp.service')
USE_FQDN_KEY = 'vpp-charm-use-fqdn'


def use_fqdn_hint():
    """Hint for whether FQDN should be used for agent registration

    :returns: True or False
    :rtype: bool
    """
    db = kv()
    return db.get(USE_FQDN_KEY, False)


BASE_RESOURCE_MAP = OrderedDict([
    (VPP_CONF, {
        'services': ['vpp'],
        'contexts': [vpp_context.VPPPluginContext(),
                     vpp_context.RemoteRestartContext(
                         ['neutron-plugin', 'neutron-control']),
                     context.NotificationDriverContext(),
                     context.HostInfoContext(use_fqdn_hint_cb=use_fqdn_hint),
                     vpp_context.ZoneContext(),
                     ],
    }),
    (ML2_CONF, {
        'services': ['vpp'],
        'contexts': [vpp_context.VPPPluginContext()],
    }),
])

# The interface is said to be satisfied if anyone of the interfaces in the
# list has a complete context.
REQUIRED_INTERFACES = {
}

TEMPLATES = 'templates/'
INT_BRIDGE = "br-int"
EXT_BRIDGE = "br-ex"
DATA_BRIDGE = 'br-data'
INTERFACES = ' '


def install_packages():
    # NOTE(lramirez): install vpp packages DEPRECATED - Because we need to do a downgrade and the lib is not supporting the feature
    #install_tmpfilesd()
    with open(os.path.join(charm_dir(),
                        'files/vpp.key')) as vpp_gpg_key:
        priv_gpg_key = vpp_gpg_key.read()
    add_source(
        'https://packagecloud.io/fdio/release/ubuntu '
        'main',
        key=priv_gpg_key)
    apt_update()
    #apt_install(filter_installed_packages(['vpp=20.05.1-release']),
    #            fatal=True)
    #apt_install(filter_installed_packages(['vpp-plugin-core=20.05.1-release']),
    #            fatal=True)
    #apt_install(filter_installed_packages(['python3-vpp-api=20.05.1-release']),
    #            fatal=True)
    #apt_install(filter_installed_packages(['libvppinfra=20.05.1-release']),
    #            fatal=True)            
    #apt_install(filter_installed_packages(['vpp-api-python python3-vpp-api vpp-dbg vpp-dev']),
    #            fatal=True)


def install_tmpfilesd():
    '''Install systemd-tmpfiles configuration for vpp'''
    shutil.copy('files/80-vpp.conf',
                    '/etc/sysctl.d/80-vpp.conf')
    subprocess.check_call(['systemd-tmpfiles', '--create'])
    shutil.copy('files/startup.txt',
                    '/etc/vpp/startup.txt')
    subprocess.check_call(['systemd-tmpfiles', '--create'])   
    shutil.copy('files/startup.conf',
                    '/etc/vpp/startup.conf')
    subprocess.check_call(['systemd-tmpfiles', '--create'])    
    if not os.path.exists('/etc/neutron'):
        os.mkdir('/etc/neutron')
        os.mkdir('/etc/neutron/plugins')
        os.mkdir('/etc/neutron/plugins/ml2')
    shutil.copy('files/dhcp_agent.ini',
                    '/etc/neutron/dhcp_agent.ini')
    subprocess.check_call(['systemd-tmpfiles', '--create']) 
    shutil.copy('files/ml2_conf.ini',
                    '/etc/neutron/plugins/ml2/ml2_conf.ini')
    subprocess.check_call(['systemd-tmpfiles', '--create']) 
    shutil.copy('files/l3_agent.ini',
                    '/etc/neutron/l3_agent.ini')
    subprocess.check_call(['systemd-tmpfiles', '--create']) 
    shutil.copy('files/vpp-agent.service',
                    '/etc/systemd/system/vpp-agent.service')
    subprocess.check_call(['systemd-tmpfiles', '--create']) 

def register_configs(release=None):
    release = release or os_release('neutron-common')
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)
    for cfg, rscs in resource_map().items():
        configs.register(cfg, rscs['contexts'])
    return configs

def resource_map():
    '''
    Dynamically generate a map of resources that will be managed for a single
    hook execution.
    '''
    drop_config = []
    resource_map = deepcopy(BASE_RESOURCE_MAP)

    return resource_map

def restart_map():
    '''
    Constructs a restart map based on charm config settings and relation
    state.
    '''
    return {k: v['services'] for k, v in resource_map().items()}

def services():
    ''' Returns a list of services associate with this charm '''
    _services = []
    for v in restart_map().values():
        _services = _services + v
    return list(set(_services))

def assess_status(configs):
    """Assess status of current unit
    Decides what the state of the unit should be based on the current
    configuration.
    SIDE EFFECT: calls set_os_workload_status(...) which sets the workload
    status of the unit.
    Also calls status_set(...) directly if paused state isn't complete.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    assess_status_func(configs)()
    #os_application_version_set(VERSION_PACKAGE)


def assess_status_func(configs):
    """Helper function to create the function that will assess_status() for
    the unit.
    Uses charmhelpers.contrib.openstack.utils.make_assess_status_func() to
    create the appropriate status function and then returns it.
    Used directly by assess_status() and also for pausing and resuming
    the unit.

    NOTE: REQUIRED_INTERFACES is augmented with the optional interfaces
    depending on the current config before being passed to the
    make_assess_status_func() function.

    @param configs: a templating.OSConfigRenderer() object
    @return f() -> None : a function that assesses the unit's workload status
    """
    required_interfaces = REQUIRED_INTERFACES.copy()
    #if enable_nova_metadata():
    #    required_interfaces['neutron-plugin-api'] = ['neutron-plugin-api']
    return make_assess_status_func(
        configs, required_interfaces,
        charm_func=check_optional_relations,
        services=services(), ports=None)

def check_optional_relations(configs):
    """Check that if we have a relation_id for high availability that we can
    get the hacluster config.  If we can't then we are blocked.  This function
    is called from assess_status/set_os_workload_status as the charm_func and
    needs to return either "unknown", "" if there is no problem or the status,
    message if there is a problem.

    :param configs: an OSConfigRender() instance.
    :return 2-tuple: (string, string) = (status, message)
    """
    # return 'unknown' as the lowest priority to not clobber an existing
    # status.
    return 'unknown', ''

def pause_unit_helper(configs):
    """Helper function to pause a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.pause_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(pause_unit, configs)


def resume_unit_helper(configs):
    """Helper function to resume a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.resume_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(resume_unit, configs)


def _pause_resume_helper(f, configs):
    """Helper function that uses the make_assess_status_func(...) from
    charmhelpers.contrib.openstack.utils to create an assess_status(...)
    function that can be used with the pause/resume of the unit
    @param f: the function to be used with the assess_status(...) function
    @returns None - this function is executed for its side-effect
    """
    # TODO(ajkavanagh) - ports= has been left off because of the race hazard
    # that exists due to service_start()
    f(assess_status_func(configs),
      services=services(),
      ports=None)

# TODO(lramirez): purge packages & validations