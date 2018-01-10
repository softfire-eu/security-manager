import pexpect
import sys
from eu.softfire.sec.utils.utils import *

logger = get_logger(config_path, __name__)

floating_ip = sys.argv[1]
pfsense_lan_ip = sys.argv[2]

try:
     cmd_str = ['ssh-keygen -R %s' % floating_ip,
                'ssh -o StrictHostKeyChecking=no -y -t cirros@%s ssh -y -t root@%s easyrule pass wan tcp any any 22' % (floating_ip, pfsense_lan_ip),
                'ssh -o StrictHostKeyChecking=no -y -t cirros@%s ssh -y -t root@%s easyrule pass wan tcp any any 80' % (floating_ip, pfsense_lan_ip),
                'ssh -o StrictHostKeyChecking=no -y -t cirros@%s ssh -y -t root@%s easyrule pass wan tcp any any 443' % (floating_ip, pfsense_lan_ip)]

     logger.debug(cmd_str)
     logger.info("starting configuring pfsense")
     child = pexpect.spawn(cmd_str[0])
     child = pexpect.spawn(cmd_str[1])
     child.expect ('password:.')
     child.sendline ('gocubsgo')
     child.expect ('password:')
     child.sendline ('pfsense')
     child.interact()
     child = pexpect.spawn(cmd_str[2])
     child.expect ('password:.')
     child.sendline ('gocubsgo')
     child.expect ('password:')
     child.sendline ('pfsense')
     child.interact()
     child = pexpect.spawn(cmd_str[3])
     child.expect ('password:.')
     child.sendline ('gocubsgo')
     child.expect ('password:')
     child.sendline ('pfsense')
     child.interact()
except Exception as e:
     logger.error(e)
     sys.exit(1)

