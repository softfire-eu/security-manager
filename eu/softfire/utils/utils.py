import logging
import logging.config

def get_logger():
    logging.config.fileConfig("/home/daniele/softfire-dev-code/security-manager/etc/security-manager.ini")
    return logging.getLogger("security-manager")