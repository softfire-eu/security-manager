import logging
import logging.config

config_path = '/etc/softfire/security-manager/security-manager.ini'

def get_logger(config_path):
    logging.config.fileConfig(config_path)
    return logging.getLogger("security-manager")