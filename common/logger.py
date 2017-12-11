import os
import logging
from logging.handlers import RotatingFileHandler
import errno


# from iam_proxy_common import SingletonMetaClass
# from iam_proxy import SingletonMetaClass
from iam_proxy_common import SingletonMetaClass
# import global_config
import global_config


class LoggerInvalidState:
    # Exception Logger is in an Invalid state, e.g. Log directory is not set
    # yet

    def __init__(self):
        Exception.__init__(self, "Logger not in a valid state.")


# Key-Value cache
class Logger:
    __metaclass__ = SingletonMetaClass

    def __init__(self):
        # Allow empty initialization
        pass

    def set_logger_path(self, logger_path):
        if(self.is_logger_set()):
            print "Logger is already set. Ignoring request."
            return
        else:
            # Create Logger path now
            self.l_path = logger_path

            # Create logger path if it does not exist
            try:
                log_dir = os.path.dirname(self.l_path)
                os.makedirs(log_dir)
            except OSError as exc:
                if(not (exc.errno == errno.EEXIST) or (not os.path.isdir(log_dir))):
                    raise

            # Set logger object
            self.l_handle = logging.getLogger(global_config.LOGGER_NAME)
            log_file = self.l_path

            #f_handle = logging.FileHandler(log_file)
            f_handle = RotatingFileHandler(
                log_file, maxBytes=100, backupCount=5)
            f_handle = logging.FileHandler(log_file)
            l_formatter = logging.Formatter(global_config.LOG_FORMAT)
            f_handle.setFormatter(l_formatter)
            self.l_handle.addHandler(f_handle)
            self.l_handle.setLevel(global_config.LOG_LEVEL)

    def is_logger_set(self):
        if(hasattr(self, 'l_path')):
            return True
        else:
            return False


def LOG_INFO(message):
    global logger
    if not logger.is_logger_set():
        raise LoggerInvalidState
    logger.l_handle.info(message)


def LOG_WARN(message):
    global logger
    if not logger.is_logger_set():
        raise LoggerInvalidState
    logger.l_handle.warn(message)


def LOG_ERR(message):
    global logger
    if not logger.is_logger_set():
        raise LoggerInvalidState
    logger.l_handle.error(message)


def LOG_CRIT(message):
    global logger
    if not logger.is_logger_set():
        raise LoggerInvalidState
    logger.l_handle.critical(message)


def LOG_DEBUG(message):
    global logger
    if not logger.is_logger_set():
        raise LoggerInvalidState
    logger.l_handle.debug(message)


# Initialize Global Logger
logger = Logger()

# Set log path
log_file = os.path.dirname(os.path.realpath(__file__)) + \
    '/' + global_config.LOG_REL_PATH + '/' + global_config.LOG_NAME

logger.set_logger_path(log_file)


LOG_INFO('Logger Initialized')
