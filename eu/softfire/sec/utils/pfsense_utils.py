import pexpect
import sys

floating_ip = sys.argv[1]
pfsense_lan_ip = sys.argv[2]

try:
     cmd_str = ['ssh-keygen -R %s' % floating_ip,
                'ssh -o StrictHostKeyChecking=no -y -t cirros@%s ssh -y -t root@%s easyrule pass wan tcp any any 22' % (floating_ip, pfsense_lan_ip),
                'ssh -o StrictHostKeyChecking=no -y -t cirros@%s ssh -y -t root@%s easyrule pass wan tcp any any 80' % (floating_ip, pfsense_lan_ip),
                'ssh -o StrictHostKeyChecking=no -y -t cirros@%s ssh -y -t root@%s easyrule pass wan tcp any any 443' % (floating_ip, pfsense_lan_ip)]

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
     print(e)
     sys.exit(1)

