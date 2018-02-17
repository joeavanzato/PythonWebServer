
#Example string format:
#'export REMOTE_HOST='127.0.0.1'; export GATEWAY_INTERFACE='CGI/1.1'; export REQUEST_METHOD='POST'; export CONTENT_TYPE='application/x-www-form-urlencoded'; export CONTENT_LENGTH='21'; export QUERY_STRING='username=x&password=s'; echo QUERY_STRING | php-cgi -f C:\Users\Joe\source\repos\Server-1\Server-1\web\login.php'

import subprocess

class phpstrings():

    def __init__(self, method, ip, clength, ctype, temp_URI, query):
        global HTTP_HOST
        global METHOD
        global CONTENT_LENGTH
        global CONTENT_TYPE
        global GATEWAY_INTERFACE
        global FILE
        global QUERY_STRING
        HTTP_HOST = ip
        METHOD = method
        CONTENT_LENGTH = clength
        CONTENT_TYPE = ctype
        GATEWAY_INTERFACE = 'CGI/1.1'  
        FILE = temp_URI
        QUERY_STRING = query

        if METHOD == 'GET':
            self.makeget()
        elif METHOD == 'POST':
            self.makepost()

    def makepost(self):
        REMOTE_HOST = HTTP_HOST
        REQUEST_METHOD = METHOD
        bashcmd = "export REMOTE_HOST='"+REMOTE_HOST+"'; export GATEWAY_INTERFACE='"+GATEWAY_INTERFACE+"'; export REQUEST_METHOD='"+REQUEST_METHOD+"'; export CONTENT_TYPE='"+CONTENT_TYPE+"'; export CONTENT_LENGTH='"+CONTENT_LENGTH+"'; export QUERY_STRING='"+QUERY_STRING+"'; echo QUERY_STRING | php-cgi -f "+FILE
        print(bashcmd)
        try:
            subprocess.check_output(bashcmd, shell=True)
        except:
            print("Command Failed")
    def makeget(self):
        bashcmd = "export HTTP_HOST='"+HTTP_HOST+"'; export GATEWAY_INTERFACE='"+GATEWAY_INTERFACE+"'; export METHOD='"+METHOD+"'; export QUERY_STRING='"+QUERY_STRING+"'; php-cgi -f "+FILE
        print(bashcmd)
        try:
            subprocess.check_output(bashcmd, shell=True)
        except:
            print("Command Failed")