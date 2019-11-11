# -*- coding: utf-8 -*-
__all__ = ['PasswordExecutor', 'PwdlibException']
import json, os, getpass, sys
import platform, time, socket, struct
from threading import Lock

# host ip
HOST = "127.0.0.1"
# sdk current version
SDK_CURRENT_VERSION = "v1"
# port
DEFAULT_CONNECT_PORT = 29463
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

# system type
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

    def __init__(self, code, args):
        """
        Initializes the exception class
        :param code: error code
        :param args: error message
        """
        self.code = code
        self.args = args


# message manager class
class ServerMessageManager:
    def __init__(self):
        self.__lock = Lock()
        self.__socket = None
        self.__port = DEFAULT_CONNECT_PORT
        self.__corelationId = 1
        if 'APPMGR_IP' in os.environ:
            self.__envIp = os.environ['APPMGR_IP']
        else:
            self.__envIp = ""

    def __del__(self):
        if self.__socket:
            self.__socket.close()

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

        ip = HOST
        if isinstance(self.__envIp, str) and len(self.__envIp) > 0:
            ip = self.__envIp
        try:
            self.__socket.connect((ip, port))
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

    # receive all data
    # python2 not support socket.MSG_WAITALL
    def recvLen(self, bufSize):
        """
        Receive complete data
        :param bufSize: The size of data
        :return: Bytes data
        """
        recvSize = 0
        recvBytes = b""
        while recvSize < bufSize:
            ret = self.__socket.recv(bufSize - recvSize)
            # Linux
            if ret == '':
                raise socket.error("disconnect")
            recvBytes += ret
            recvSize += len(ret)
        return recvBytes

    # send data and receive
    def sendDataSync(self, port, code, message, haveResponse=False):
        """
        Synchronous messaging
        :param port: Port number
        :param code: The message code
        :param message: The message to send
        :param haveResponse: Whether to return a message
        :return: None or the returned message
        """
        ret = ""
        self.__lock.acquire()
        if self.__socket is None or self.__port != port:
            if not self.__initSocket(port):
                self.__lock.release()
                raise PwdlibException(PwdlibException.PWDSDK_ERROR_CONNECT, ("Connect fail",))
            else:
                self.__port = port

        msg = struct.pack(">HHI", code, self.__corelationId, len(message))
        self.__corelationId = (self.__corelationId + 1) % 0xffff
        if self.__corelationId == 0:
            self.__corelationId = 1

        try:
            self.__socket.sendall(msg + str.encode(message))
        except socket.error:
            # reconnect
            if not self.__initSocket(port):
                self.__lock.release()
                raise PwdlibException(PwdlibException.PWDSDK_ERROR_CONNECT, ("Connect fail",))
            else:
                self.__lock.release()
                raise PwdlibException(PwdlibException.PWDSDK_ERROR_RECONNECT, ("Reconnect",))

        if haveResponse:
            try:
                msg = self.recvLen(8)
                _, _, length = struct.unpack(">HHI", msg)
                ret = self.recvLen(length)
            except socket.error:
                # reconnect
                if not self.__initSocket(port):
                    self.__lock.release()
                    raise PwdlibException(PwdlibException.PWDSDK_ERROR_CONNECT, ("Connect fail",))
                else:
                    self.__lock.release()
                    raise PwdlibException(PwdlibException.PWDSDK_ERROR_RECONNECT, ("Reconnect",))

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
    def queryPassword(objectName, resourceName, appId, requestReason, credentialFile, port):
        """
        Query password
        :param objectName: Object name
        :param resourceName: The utf-8 encoded resource name
        :param appId: The application identity for the request password
        :param requestReason: Reason for the request
        :param credentialFile: Credential file path, assign None when credential is not used
        :param port: port number, assign zero to use default port
        :return: Password object
        """
        if not (objectName and resourceName and appId and requestReason and
                isinstance(port, int) and 0 <= port <= 65535):
            raise PwdlibException(PwdlibException.PWDSDK_ERROR_PARAMETER, ('Invalid Parameter',))
        if port == 0:
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
                raise PwdlibException(PwdlibException.PWDSDK_ERROR_CREDENTIALFILE, ("Credential file error",))
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
                                                                       json.dumps(requestInfo), True)
        if response:
            account = json.loads(response.decode())
            # Judging additional information
            if "extras" in account:
                if "changingPassword" in account["extras"] and account["extras"]["changingPassword"]:
                    raise PwdlibException(PwdlibException.PWDSDK_ERROR_CHANGINGPASSWORD, ("Changing password", ))
                if "errorCode" in account["extras"] and account["extras"]["errorCode"] != 0:
                    raise PwdlibException(account["extras"]["errorCode"],
                                          ("The server returns error code %d" % account["extras"]["errorCode"], ))
            else:
                # TODO
                pass

            # String is empty
            if ("objectName" not in account or "objectContent" not in account or
                account["objectName"].strip() == "" or account["objectContent"].strip() == ""):
                raise PwdlibException(PwdlibException.PWDSDK_ERROR_INVALID_RETURNS, ("Invalid data returned", ))
            pwdObj = {}
            pwdObj["objectName"] = account["objectName"]
            pwdObj["objectContent"] = account["objectContent"]
            if PasswordExecutor.__enableCache:
                PasswordExecutor.__lock.acquire()
                PasswordExecutor.__passwordCache[appId] = (account["objectContent"], time.time())
                PasswordExecutor.__lock.release()
            return pwdObj
        return
