#!/usr/bin/env python3

import subprocess
import sys

from charmhelpers.core.hookenv import (
    config,
    log,
    status_set
)
from charmhelpers.core.templating import render

status_set('maintenance', 'Getting config elements')

# Get global config and get cidr and gateway
cfg = config()
huge = cfg.get('hugepages')
maxmap = cfg.get('max_map_count')
shmmax = cfg.get('shmmax')

kernconf_file = '/etc/sysctld/{}.conf' #.format(service) 
service_template = '80-vpp.j2'
context = {
    'hugepages': huge,
    'max_map_count': maxmap,
    'shmmax': shmmax,
}
# Render the service template
render(service_template, kernconf_file, context, perms=0o644)

# Restart the one-shot service
cmd = 'systemctl restart {}'.format(service)
subprocess.check_call(cmd, shell=True)

status_set('active', 'Unit ready')
