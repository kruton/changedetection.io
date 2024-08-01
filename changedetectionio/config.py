class Config(object):
    HOST = ''
    PORT = 5000
    DATASTORE_PATH = None
    CREATE_DATASTORE_PATH = False
    DO_CLEANUP = False
    IPV6_ENABLED = False
    SSL_MODE = False
    LOGGER_LEVEL = "DEBUG"

    @property
    def default_datastore_dir(self):
        import os
        if os.name == 'nt':
            datastore_path = os.path.expandvars(r'%APPDATA%\changedetection.io')
        else:
            datastore_path = os.path.join(os.getcwd(), "../datastore")
        return datastore_path