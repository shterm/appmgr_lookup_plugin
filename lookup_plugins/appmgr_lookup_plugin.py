#!/usr/bin/python
# -*- coding: utf-8 -*-
from ansible.plugins.lookup import LookupBase
class LookupModule(LookupBase):
    def retrieve_secrets(self, terms):
        secrets = []
        if terms is None or len(terms) < 1:
            raise Exception('params is not match required')
        context = terms[0]
        appid = context.get('appid', None)
        query = context.get('query', None)
        rtninfo = context.get('extra', None)
        #rtn_fields = self.analyize_query_params(rtninfo)
        # ueryPassword(objectName, resourceName, appId, requestReason, credentialFile, port):
        query_params = self.analyize_query_params(query)
        account_name = query_params.get("username", None)
        resouce_name = query_params.get("resourceName", None)
        request_reason = query_params.get("reason", None)
        request_requiredAttribute = query_params.get("requiredAttribute", None)
        connect_port = query_params.get("connectPort", 0)
        connect_host = query_params.get("host", HOST)
        ca_file = query_params.get("cafile", None)
        cert_file = query_params.get("certfile", None)
        key_file = query_params.get("keyfile", None)
        credentialFile = None
        if rtninfo:
            credentialFile = rtninfo.get('creFile', None)
        account_info = PasswordExecutor.queryPassword(account_name, resouce_name, appid, request_reason, query, request_requiredAttribute, credentialFile, connect_port, connect_host, ca_file, cert_file, key_file)
        really_account = account_info['objectName']
        really_password = account_info['objectContent']
        really_extras = account_info['extras']
        secret = {'password':really_password, 'account':really_account, 'extras':really_extras}
        secrets.append(secret)
        return secrets

    def analyize_query_params(self, query_param):
        """
        str splits with;
        each item was splited by =
        :param query_param:     the params
        :return:
        """
        if not query_param:
            raise Exception('query is empty')

        keyValues = query_param.split(';')
        convert_params = dict()
        for item in keyValues:
            keyValue=item.split("=")
            if len(keyValue) != 2:
                continue
            convert_params[keyValue[0]] = keyValue[1]

        return convert_params

    def analyize_rtn_info(self, rtnInfo):
        """
        analysis the info from the query
        :param rtnInfo: Expect the field to be returned
        :return: list type
        """
        return rtnInfo.split(';')

    def run(self, terms, variables=None, **kwargs):
        return self.retrieve_secrets(terms)


# pwdlib executor
__all__ = ['PasswordExecutor', 'PwdlibException']
import json, os, getpass, sys
import platform, time, socket, struct, ssl, hashlib
from threading import Lock

# host ip
HOST = "127.0.0.1"
# sdk current version
SDK_CURRENT_VERSION = "v2"
# port
DEFAULT_CONNECT_PORT = 29463
# default tls port
DEFAULT_CONNECT_TLS_PORT = 29443
# password request
USER_PASSWD_REQUEST = 0x19
# password request response
USER_PASSWD_RESPONSE = 0x20
# register request
MESSAGE_CODE_REGISTER = 0x21
# password sync response
USER_PASSWD_SYNC_RESPONSE = 0x23
# response after sync password
PASSWD_CHANGE_NOTIFY_RESPOND = 0x24
# UUID
UID = "uid"
# appId key
APP_ID = "appId"
# username key
USERNAME = "username"
# connectHost key
CONNECT_HOST = "connectHost"
# connectPort key
CONNECT_PORT = "connectPort"
# default ca file
DEFAULT_CA_FILE_PATH = "server.crt"
# default client certifcation file
DEFAULT_CLIENT_CERT_FILE_PATH = "client.crt"
# default client key file
DEFAULT_CLIENT_KEY_FILE_PATH = "client.key"
# buffer when reading a file 
READ_FILE_BUFFER = 8096

systemType = platform.system()


class PwdlibException(Exception):
    PWDSDK_NO_ERROR = 0
    PWDSDK_ERROR_AUTHENTICATE = 1
    PWDSDK_ERROR_PERMISSION = 2
    PWDSDK_ERROR_PARSE = 3
    PWDSDK_ERROR_INTERNAL = 4

    PWDSDK_ERRORCODEOFFSET = 1000
    PWDSDK_ERROR_OBJECT = PWDSDK_ERRORCODEOFFSET + 1
    PWDSDK_ERROR_PARAMETER = PWDSDK_ERRORCODEOFFSET + 2
    PWDSDK_ERROR_NO_MEMORY = PWDSDK_ERRORCODEOFFSET + 3
    PWDSDK_ERROR_INVALID_JSON = PWDSDK_ERRORCODEOFFSET + 4
    PWDSDK_ERROR_WSA = PWDSDK_ERRORCODEOFFSET + 5
    PWDSDK_ERROR_CREATE_SOCKET = PWDSDK_ERRORCODEOFFSET + 6
    PWDSDK_ERROR_CONNECT = PWDSDK_ERRORCODEOFFSET + 7
    PWDSDK_ERROR_RECONNECT = PWDSDK_ERRORCODEOFFSET + 8
    PWDSDK_ERROR_SETTIMEOUT = PWDSDK_ERRORCODEOFFSET + 9
    PWDSDK_ERROR_CHANGINGPASSWORD = PWDSDK_ERRORCODEOFFSET + 10
    PWDSDK_ERROR_INVALID_RETURNS = PWDSDK_ERRORCODEOFFSET + 11
    PWDSDK_ERROR_EXTENSION = PWDSDK_ERRORCODEOFFSET + 12
    PWDSDK_ERROR_CREDENTIALFILE = PWDSDK_ERRORCODEOFFSET + 13
    PWDSDK_ERROR_TLS_CONNECT = PWDSDK_ERRORCODEOFFSET + 23
    PWDSDK_ERROR_TLS_PYTHON_SUPPORT = PWDSDK_ERRORCODEOFFSET + 24

    def __init__(self, code, args):
        """
        Initializes the exception class
        :param code: error code
        :param args: error message
        """
        self.code = code
        self.args = args

def fillIdAppE(errMsg, errCode):
    """
    Get error message
    :param errMsg:
    :param errCode:
    :return: error message
    """
    return "{}{:0>4d} {}".format("EACCAPP", errCode, errMsg)

# message manager class
class ServerMessageManager:
    def __init__(self):
        self.__lock = Lock()
        self.__socket = None
        self.__port = DEFAULT_CONNECT_PORT
        self.__corelationId = 1
        self.__certFileHash = None
        self.__keyFileHash = None
        self.__sslContext = None
        self.__sslSocket = None
        self.__sock = None
        

    def __del__(self):
        if self.__socket:
            self.__socket.close()
        if self.__sslSocket:
            self.__sslSocket.close()

    # reconnect ssl socket
    def __initSslSocket(self, caFile, certFile, keyFile, host, port):
        """
        Initialize ssl for socket
        """
        if self.__sslSocket:
            self.__sslSocket.close()
            self.__sslContext = None
        
        if caFile is None:
            caFile = DEFAULT_CA_FILE_PATH
        if certFile is None:
            certFile = DEFAULT_CLIENT_CERT_FILE_PATH
        if keyFile is None:
            keyFile = DEFAULT_CLIENT_KEY_FILE_PATH
        
        try:
            self.__sslContext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            self.__sslContext.load_cert_chain(certfile=certFile, keyfile=keyFile)
            self.__sslContext.load_verify_locations(caFile)
            self.__sslContext.verify_mode = ssl.CERT_REQUIRED
            self.__certFileHash = self.calcFileMd5(certFile)
            self.__keyFileHash = self.calcFileMd5(keyFile)
        except Exception as e:
            return False

        if not self.__sock:
            try:
                self.__sock = socket.socket()
            except socket.error:
                return False
            
        try:
            self.__sslSocket = self.__sslContext.wrap_socket(self.__sock, server_side=False)
            if host is None:
                host = HOST
            self.__sslSocket.connect((host, port))
        except Exception:
            return False
          
        return True  
    
    # Unified interface for initial socket   
    def __initSock(self, port, host=HOST, caFile=None, certFile=None, keyFile=None):
        if host == HOST:
            if port == 0:
                port = DEFAULT_CONNECT_PORT
            return self.__initSocket(port)
        else:
            if port == 0:
                port = DEFAULT_CONNECT_TLS_PORT
            return self.__initSslSocket(caFile, certFile, keyFile, host, port)
                
    
    # reconnect socket
    def __initSocket(self, port):
        """
        Initialize the socket
        :return: result
        """
        if self.__socket:
            self.__socket.close()
            self.__socket = None

        try:
            self.__socket = socket.socket()
        except socket.error:
            return False

        try:
            self.__socket.connect((HOST, port))
        except (socket.error, socket.gaierror):
            if self.__socket:
                self.__socket.close()
                self.__socket = None
            return False

        # set recv timeout 30 seconds
        if 'Windows' == systemType:
            self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 30000, 0))
        else:
            self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 30, 0))

        return True
    
    def calcFileMd5(self, filename):
        if not os.path.isfile(filename):
            return
        fileHash = hashlib.md5()
        file = open(filename, "rb")
        while True:
            block = file.read(READ_FILE_BUFFER)
            if not block:
                break
            fileHash.update(block)
        file.close()
        return fileHash.hexdigest()
    
    # judge file is change or not by calculate file's MD5 hash code
    def isFileChange(self, filename, tag):
        result = False
        hashCode = self.calcFileMd5(filename)
        if tag == "cert":
            return self.__certFileHash == hashCode
        if tag == "key":
            return self.__keyFileHash == hashCode

        return result
        
    # receive all data
    # python2 not support socket.MSG_WAITALL
    def recvLen(self, bufSize, useTls=False):
        """
        Receive complete data
        :param bufSize: The size of data
        :return: Bytes data
        """
        recvSize = 0
        recvBytes = b""
        while recvSize < bufSize:
            if useTls:
                ret = self.__sslSocket.recv(bufSize - recvSize)
            else:
                ret = self.__socket.recv(bufSize - recvSize)
            # Linux
            if ret == '':
                raise socket.error("disconnect")
            recvBytes += ret
            recvSize += len(ret)
        return recvBytes
    
    # send data and receive
    def sendDataSync(self, port, code, message, haveResponse=False, host=HOST, caFile=None, certFile=None, keyFile=None):
        """
        Synchronous messaging
        :param port: Port number
        :param code: The message code
        :param message: The message to send
        :param haveResponse: Whether to return a message
        :return: None or the returned message
        """
        useTls = False
        if host != HOST:
            useTls = True
        ret = ""
        self.__lock.acquire()
        if useTls:
            if self.__sslContext is None or self.__sslSocket is None or not self.isFileChange(certFile, "cert") or not self.isFileChange(keyFile, "key"):
                if not self.__initSock(port, host, caFile, certFile, keyFile):
                    self.__lock.release()
                    raise PwdlibException(PwdlibException.PWDSDK_ERROR_TLS_CONNECT, 
                                          (fillIdAppE("Connect ssl fail", PwdlibException.PWDSDK_ERROR_TLS_CONNECT), ))
                else:
                    self.__port = port
        else:
            if self.__socket is None or self.__port != port:
                if not self.__initSock(port):
                    self.__lock.release()
                    raise PwdlibException(PwdlibException.PWDSDK_ERROR_CONNECT,
                                        (fillIdAppE("Connect fail", PwdlibException.PWDSDK_ERROR_CONNECT), ))
                else:
                    self.__port = port

        msg = struct.pack(">HHI", code, self.__corelationId, len(message))
        self.__corelationId = (self.__corelationId + 1) % 0xffff
        if self.__corelationId == 0:
            self.__corelationId = 1

        if useTls:
            try:
                self.__sslSocket.send(msg + str.encode(message))
            except socket.error:
                # reconnect
                if not self.__initSock(port, host, caFile, certFile, keyFile):
                    self.__lock.release()
                    raise PwdlibException(PwdlibException.PWDSDK_ERROR_TLS_CONNECT,
                                        (fillIdAppE("Connection failed", PwdlibException.PWDSDK_ERROR_TLS_CONNECT),))
                else:
                    self.__lock.release()
                    raise PwdlibException(PwdlibException.PWDSDK_ERROR_RECONNECT,
                                        (fillIdAppE("Error or timeout, reconnect",
                                                    PwdlibException.PWDSDK_ERROR_RECONNECT),))        
        else:
            try:
                self.__socket.sendall(msg + str.encode(message))
            except socket.error:
                # reconnect
                if not self.__initSock(port):
                    self.__lock.release()
                    raise PwdlibException(PwdlibException.PWDSDK_ERROR_CONNECT,
                                        (fillIdAppE("Connect fail", PwdlibException.PWDSDK_ERROR_CONNECT),))
                else:
                    self.__lock.release()
                    raise PwdlibException(PwdlibException.PWDSDK_ERROR_RECONNECT,
                                        (fillIdAppE("Reconnect", PwdlibException.PWDSDK_ERROR_RECONNECT),))

        if haveResponse:
            try:
                msg = self.recvLen(8, useTls)
                _, _, length = struct.unpack(">HHI", msg)
                ret = self.recvLen(length, useTls)
            except socket.error:
                if useTls:
                    # reconnect
                    if not self.__initSock(port, host, caFile, certFile, keyFile):
                        self.__lock.release()
                        raise PwdlibException(PwdlibException.PWDSDK_ERROR_TLS_CONNECT,
                                                (fillIdAppE("Connection failed", PwdlibException.PWDSDK_ERROR_TLS_CONNECT),))
                    else:
                        self.__lock.release()
                        raise PwdlibException(PwdlibException.PWDSDK_ERROR_RECONNECT,
                                                (fillIdAppE("Error or timeout, reconnect",
                                                            PwdlibException.PWDSDK_ERROR_RECONNECT),))
                else:
                    # reconnect
                    if not self.__initSock(port):
                        self.__lock.release()
                        raise PwdlibException(PwdlibException.PWDSDK_ERROR_CONNECT,
                                            (fillIdAppE("Connect fail", PwdlibException.PWDSDK_ERROR_CONNECT),))
                    else:
                        self.__lock.release()
                        raise PwdlibException(PwdlibException.PWDSDK_ERROR_RECONNECT,
                                            (fillIdAppE("Reconnect", PwdlibException.PWDSDK_ERROR_RECONNECT),))

        self.__lock.release()
        return ret


class PasswordExecutor:
    __SererMessageManager = ServerMessageManager()
    __enableCache = False
    __passwordCache = {}
    __lock = Lock()

    def __init__(self):
        pass

    @staticmethod
    def queryPassword(objectName, resourceName, appId, requestReason, query, requiredAttribute, credentialFile, port, host=HOST, caFile=None, certFile=None, keyFile=None):
        """
        Query password
        :param objectName: Object name
        :param resourceName: The utf-8 encoded resource name
        :param appId: The application identity for the request password
        :param requestReason: Reason for the request
        :param query: Query Conditions
        :param requiredAttribute: Required attribute
        :param credentialFile: Credential file path, assign None when credential is not used
        :param port: port number, assign zero to use default port
        :return: Password object
        """
        if not (objectName and appId and requestReason and
                isinstance(port, int) and 0 <= port <= 65535):
            raise PwdlibException(PwdlibException.PWDSDK_ERROR_PARAMETER,
                                  (fillIdAppE("Invalid Parameter", PwdlibException.PWDSDK_ERROR_PARAMETER),))
        useTls = False
        if host != HOST:
            useTls = True
            if caFile is None:
                caFile = DEFAULT_CA_FILE_PATH
            if certFile is None:
                certFile = DEFAULT_CLIENT_CERT_FILE_PATH
            if keyFile is None:
                keyFile = DEFAULT_CLIENT_KEY_FILE_PATH
        if useTls and sys.version_info < (2, 7, 9):
            raise PwdlibException(PwdlibException.PWDSDK_ERROR_TLS_PYTHON_SUPPORT, 
                                  (fillIdAppE("Tls support requires Python2.7.9+", PwdlibException.PWDSDK_ERROR_TLS_PYTHON_SUPPORT), ))
        if port == 0:
            if useTls:
                port = DEFAULT_CONNECT_TLS_PORT
            else:
                port = DEFAULT_CONNECT_PORT

        # Query local cache(default close)
        if PasswordExecutor.__enableCache:
            PasswordExecutor.__lock.acquire()
            if appId in PasswordExecutor.__passwordCache:
                if PasswordExecutor.__passwordCache[appId][1] + 5 > time.time():
                    #print("find")
                    pwdObj = {}
                    pwdObj["objectName"] = objectName
                    pwdObj["objectContent"] = PasswordExecutor.__passwordCache[appId][0]
                    PasswordExecutor.__lock.release()
                    return pwdObj
                else:
                    # Delete expired passwords
                    for key in list(PasswordExecutor.__passwordCache):
                        if PasswordExecutor.__passwordCache[key][1] + 5 >= time.time():
                            PasswordExecutor.__passwordCache.pop(key)
            PasswordExecutor.__lock.release()
        # Password request structure
        passwordRequest = {}
        passwordRequest["objectName"] = objectName
        passwordRequest["resourceName"] = resourceName
        passwordRequest["appId"] = appId
        passwordRequest["requestReason"] = requestReason
        passwordRequest["query"] = query
        passwordRequest["requiredAttribute"] = requiredAttribute
        # Get additional information
        additionalInfo = {}
        additionalInfo["osUser"] = getpass.getuser()
        additionalInfo["path"] = os.path.abspath(sys.argv[0])
        if isinstance(credentialFile, str) and len(credentialFile):
            cf = None
            try:
                cf = open(credentialFile, 'r')
                additionalInfo["credential"] = cf.read()
                json.dumps(additionalInfo["credential"])
            except:
                raise PwdlibException(PwdlibException.PWDSDK_ERROR_CREDENTIALFILE, (
                    fillIdAppE("Credential file error", PwdlibException.PWDSDK_ERROR_CREDENTIALFILE),))
            finally:
                if cf:
                    cf.close()
        # Get sdk info
        sdkInfo = {}
        sdkInfo["version"] = SDK_CURRENT_VERSION
        # Generate a request
        requestInfo = {}
        requestInfo["additionalInfo"] = additionalInfo
        requestInfo["passwordRequest"] = passwordRequest
        requestInfo["sdk"] = sdkInfo
        response = PasswordExecutor.__SererMessageManager.sendDataSync(port, USER_PASSWD_REQUEST,
                                                                       json.dumps(requestInfo), True, host, caFile, certFile, keyFile)
        if response:
            account = json.loads(response.decode())
            # Judging additional information
            if "extras" in account:
                if "changingPassword" in account["extras"] and account["extras"]["changingPassword"]:
                    raise PwdlibException(PwdlibException.PWDSDK_ERROR_CHANGINGPASSWORD, (
                        fillIdAppE("Changing password", PwdlibException.PWDSDK_ERROR_CHANGINGPASSWORD),))
                if "errorCode" in account["extras"] and account["extras"]["errorCode"] != 0:
                    errorMsg = "Unknown error from server"
                    if "errorMsg" in account["extras"]:
                        errorMsg = account["extras"]["errorMsg"]
                    raise PwdlibException(account["extras"]["errorCode"],
                                          (fillIdAppE(errorMsg, account["extras"]["errorCode"]),))
            else:
                # TODO
                pass

            # String is empty
            if ("objectName" not in account or "objectContent" not in account or
                account["objectName"].strip() == "" or account["objectContent"].strip() == ""):
                raise PwdlibException(PwdlibException.PWDSDK_ERROR_INVALID_RETURNS, (
                    fillIdAppE("Invalid data returned", PwdlibException.PWDSDK_ERROR_INVALID_RETURNS),))
            pwdObj = {}
            pwdObj["objectName"] = account["objectName"]
            pwdObj["objectContent"] = account["objectContent"]
            pwdObj["extras"] = account["extras"];
            if PasswordExecutor.__enableCache:
                PasswordExecutor.__lock.acquire()
                PasswordExecutor.__passwordCache[appId] = (account["objectContent"], time.time())
                PasswordExecutor.__lock.release()
            return pwdObj
        return