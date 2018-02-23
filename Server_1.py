#Verbose Web-Server class for HTTP/PHP Content handling (GET, POST, PUT, DELETE and CONNECT)

import sys
import time
import threading
import socket
import os
import io
import subprocess
import traceback
#import phpstrings

global connection_count
global body
global auth
global HTTP_Parameters_ID
global HTTP_Parameters_Value
global HTTP_Data
global cl
global ct
global clength
global ah
global ctype
global cauth
global HTTP_HOST
global METHOD
global CONTENT_LENGTH
global CONTENT_TYPE
global GATEWAY_INTERFACE
global FILE
global QUERY_STRING

connection_count = 0

class Server(object):
    global HTTP_HOST
    global METHOD
    global CONTENT_LENGTH
    global CONTENT_TYPE
    global GATEWAY_INTERFACE
    global FILE
    global QUERY_STRING
    global body
    global connection_count
    global body
    global auth
    global HTTP_Parameters_ID
    global HTTP_Parameters_Value
    global HTTP_Data
    global cl
    global ct
    global clength
    global ah
    global ctype
    global cauth

    def __init__(self, port, ip):
        self.port = port
        self.ips = ip
        self.hostname = socket.gethostbyname(socket.gethostname())
        self.location = rootdir
        print("Detected Local Host Name "+self.hostname) 
        print("Port Selected : "+str(port)) 

    
    def phpstrings(self, method2, ip2, clength2, ctype2, temp_URI2, query2):
        global HTTP_HOST
        global METHOD
        global CONTENT_LENGTH
        global CONTENT_TYPE
        global GATEWAY_INTERFACE
        global FILE
        global QUERY_STRING
        global body
        HTTP_HOST = ip2
        METHOD = method2
        CONTENT_LENGTH = clength2
        CONTENT_TYPE = ctype2
        GATEWAY_INTERFACE = 'CGI/1.1'  
        FILE = temp_URI2
        QUERY_STRING = query2

        if METHOD == 'GET':
            self.makeget()
        elif METHOD == 'POST':
            self.makepost()

    def makepost(self):
        global body
        REMOTE_HOST = HTTP_HOST
        REQUEST_METHOD = METHOD
        bashcmd = "export REDIRECT_STATUS='CGI'; export SCRIPT_FILENAME='"+FILE+"'; export REMOTE_HOST='"+REMOTE_HOST+"'; export GATEWAY_INTERFACE='"+GATEWAY_INTERFACE+"'; export REQUEST_METHOD='"+REQUEST_METHOD+"'; export CONTENT_TYPE='"+CONTENT_TYPE+"'; export CONTENT_LENGTH='"+CONTENT_LENGTH+"'; export REQUEST_BODY='"+QUERY_STRING+"'; echo $REQUEST_BODY | php-cgi -f "+FILE
        print(bashcmd)
        try:
            body = subprocess.check_output(bashcmd, shell=True)
            print("Command Executed")
            return body
        except:
            print("Command Failed")
            traceback.print_exc()
            body = 500
            print("Internal Server Error "+str(body))
            return body

    def makeget(self):
        global body
        if QUERY_STRING == 'X':
            bashcmd = "export SCRIPT_FILENAME='"+FILE+"'; export REDIRECT_STATUS='CGI'; export HTTP_HOST='"+HTTP_HOST+"'; export GATEWAY_INTERFACE='"+GATEWAY_INTERFACE+"'; export REQUEST_METHOD='"+METHOD+"'; php-cgi -f "+FILE
        else:
            bashcmd = "export SCRIPT_FILENAME='"+FILE+"'; export REDIRECT_STATUS='CGI'; export HTTP_HOST='"+HTTP_HOST+"'; export GATEWAY_INTERFACE='"+GATEWAY_INTERFACE+"'; export REQUEST_METHOD='"+METHOD+"'; export QUERY_STRING='"+QUERY_STRING+"'; php-cgi -f "+FILE
        print(bashcmd)
        try:
            body = subprocess.check_output(bashcmd, shell=True, stderr=subprocess.STDOUT)
            print("Command Executed")
            return body
        except:
            print("Command Failed")
            traceback.print_exc()
            body = 500
            print("Internal Server Error "+str(body))
            return body

    def createSocket(self): #IPv4/TCP Mode hard-configured
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print("Binding server to Socket "+self.hostname+":"+str(self.port))
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.ips, self.port))
            self.portListen()
        except socket.error:
            print("Error Creating or Binding Socket!")
            traceback.print_exc()
            #self.destroySocket()

    def destroySocket(self): #Closes Socket when called
        print("Destroying Socket Connection...")
        try:
            self.sock.close()
            #self.sock.shutdown(socket.SHUT_RDWR)
        except socket.error:
            print("Error Closing Socket!")
            traceback.print_exc()

    def portListen(self):
        self.sock.listen(5) #Max Connections
        print("Listening on Port "+str(self.port))
        while True:
            print("Listen Loop Initiated..")
            (remotename, remoteIP) = self.sock.accept() #Listens for connections from Remote Clients indefinitely via loop
            print("Connection from "+str(remoteIP))
            newthread = threading.Thread(target=self.processConnection(remotename, remoteIP)) #Separate thread for each client
            newthread.start()

    def processConnection(self, clientname, clientsock): 
        global connection_count
        global init_data
        global filename
        global query
        global ip
        global clength
        global ctype
        global body
        size = 2048 #Number of Bytes Processed as group, might need raising
        print("Socket Information "+str(clientname))

        while True:
            connection_count = connection_count + 1
            print("Connection Number : "+str(connection_count))
            print("Active Thread for "+str(clientsock))
            ip = str(clientsock).split('\'')[1]
            print(ip)
            #try:
            #init_data = clientname.recv(size).decode() #Entire HTTP message from RC
            init = clientname.recv(size)
            init_data = init.decode()

            try:
                method = init_data.split(' ')[0] #Gets HTTP Request Method from RC
                URI = init_data.split(' ')[1]
                httpver = init_data.split(' ')[2]
                print("Method = "+method)
                print("URI = "+URI)
                print("Version = "+httpver)
            except:
                print("Malformed HTTP Request")
                writeLog(init_data, 0)
                responsehead = self.makeHeader(500)
                response = "<html><body>Error 500: Malformed Request!</body></html>"
                fullresponse = (responsehead + response).encode() 
                print("Responding with "+str(fullresponse))
                clientname.send(fullresponse)
                fullresponse = ""
                clientname.close()
                break

            if "HTTP/1.1" not in httpver:
                print("DETECTED VERSION NOT ALLOWED, ONLY HTTP/1.1")
                writeLog(init_data, 0)
                responsehead = self.makeHeader(505)
                fullresponse = responsehead.encode() 
                print("Responding with "+str(fullresponse))
                clientname.send(fullresponse)
                fullresponse = ""
                clientname.close()
                break


            elif method not in allowed_methods:
                print("DETECTED METHOD NOT ALLOWED")
                writeLog(init_data, 0)
                responsehead = self.makeHeader(405)
                fullresponse = responsehead.encode() 
                response = b"<html><body>Error 403: Forbidden!</body></html>"
                fullresponse =+ response
                print("Responding with "+str(fullresponse))
                clientname.send(fullresponse)
                fullresponse = ""
                clientname.close()
                break
                
            else:

                self.getParams(method, clientname)

                #print("Entire Message = "+init_data)
                URI_requested = init_data.split(' ')[1] #Gets second of three elements on Request Line (ex. GET / HTTP/1.1) would get '/'

                if (method == 'GET'): #Done?  Not Quite - Implement GET with Data Below for GET-Based PHP requests
                    if (URI_requested == "/") or (URI_requested == "\\"): #If Index Request
                        tmpURI = str(rootdir)+"/index.html"
                        tmpURI.replace(' ', '')
                        tmpURI.replace('\r','')
                        tmpURI.replace('\n','')
                    else: #Any other referenced URI
                        tmpURI = str(rootdir)+URI_requested
                        print(tmpURI)

                    if "?" in URI_requested: #Parses data for GET-PHP requests, naively
                        a, b = tmpURI.split('?', 1)
                        tmpURI = a
                        query = b
                        if ".php" in tmpURI and "php" in allowed_scripts:

                            if URI_requested in protected_files and ah == 0:
                                writeLog(init_data, 0)
                                responsehead = self.makeHeader(401)
                                response = b"<html><body>Error 401: Unauthorized!</body></html>"
                                fullresponse = responsehead.encode()
                                fullresponse += response
                                print("Responding with "+str(fullresponse))
                                clientname.send(fullresponse)
                                fullresponse = ""
                                clientname.close()
                                self.cleanUp()
                                break
                            else:
                                print("PHP URI REQUESTED VIA GET")
                                self.phpstrings(method, ip, 0, 0, tmpURI, query)
                                if type(body) == int:
                                    writeLog(init_data, 0)
                                    responsehead = self.makeHeader(500)
                                    fullresponse = responsehead.encode()
                                    print("Responding with "+str(fullresponse))
                                    clientname.send(fullresponse)
                                    fullresponse = ""
                                    clientname.close()
                                    self.cleanUp()
                                    print("Error Executing PHP, 500 Error Sent")
                                    break
                                else:
                                    writeLog(init_data, 1)
                                    header = ''
                                    header += 'HTTP/1.1 200 OK\r\n' #Successful GET requests
                                    curtime = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime())
                                    header += ('Date: '+curtime+'\r\n')
                                    header += 'Server: Python HTTP Test Server\r\n'
                                    clen = len(body)
                                    header += 'Content-Length: '+str(clen)+"\r\n"
                                    header += 'Keep-Alive: timeout=5, max=100\r\n'
                                    header += 'Connection: Keep-Alive\r\n'
                                    print("TESTING2")
                                    if "Status: 302" in str(body):
                                    	print("Replacing Status and De-Coupling Responses")
                                    	header += 'Connection: Keep-Alive\r\n\r\n'                               
                                    	body = body.replace(b"Status:", b"HTTP/1.1")
                                    	clientname.send(body)
                                    	clientname.close()
                                    else:
                                    	header += 'Connection: Keep-Alive\r\n'
                                    	#body = body.encode()
                                    	#response = ((header).encode())+body
                                    	body = body.decode('utf-8')
                                    	response = str(header)+str(body)
                                    	clientname.send(bytes(response.encode('utf-8')))
                                    	#clientname.send(body)
                                    	print("Responding With.."+str(response))
                                    	clientname.close()
                                    	#fullresponse += body
                                    	#clientname.send(fullresponse)
                                    break
                        #if '.php' == os.path.splitext(tmpURI)[-1].lower():
                            #php.makeGET(tmpURI, query, htt)
                        elif ".php" in tmpURI and "php" not in allowed_scripts:
                            print("Script Extension Not Supported 1")
                            writeLog(init_data, 0)
                            responsehead = self.makeHeader(403)
                            response = b"<html><body>Error 403: Forbidden!</body></html>"
                            fullresponse = responsehead.encode()
                            fullresponse += response
                            print("Responding with "+str(fullresponse))
                            clientname.send(fullresponse)
                            fullresponse = ""
                            clientname.close()
                            self.cleanUp()
                        else:
                            pass
                        break

                    else:
                        print(allowed_scripts)
                        print(tmpURI)
                        if ".php" in tmpURI and "php" in allowed_scripts:
                            try:
                                clength = 0
                                ctype = 0
                                query = ''
                                self.phpstrings(method, ip, clength, ctype, tmpURI, query)
                                if type(body) == int:
                                    writeLog(init_data, 0)
                                    responsehead = self.makeHeader(500)
                                    response = b"<html><body>Error 500: Internal Server Error!</body></html>"
                                    fullresponse = responsehead.encode()
                                    fullresponse += response
                                    print("Responding with "+str(fullresponse))
                                    clientname.send(fullresponse)
                                    clientname.close()
                                else:
                                    writeLog(init_data, 1)
                                    header = ''
                                    header += 'HTTP/1.1 200 OK\r\n' #Successful GET requests
                                    curtime = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime())
                                    header += ('Date: '+curtime+'\r\n')
                                    header += 'Server: Python HTTP Test Server\r\n'
                                    clen = len(body)
                                    header += 'Content-Length: '+str(clen)+"\r\n"
                                    header += 'Keep-Alive: timeout=5, max=100\r\n'
                                    header += 'Connection: Keep-Alive\r\n'
                                    print("TESTING1")
                                    if "Status: 302" in str(body):

                                    	print("Replacing Status and De-Coupling Responses")
                                    	header += 'Connection: Keep-Alive\r\n\r\n'                               

                                    	body = body.replace(b"Status:", b"HTTP/1.1")
                                    	print(body)
                                    	clientname.send(body)
                                    	clientname.close()
                                    else:
                                    	header += 'Connection: Keep-Alive\r\n'
                                    	#body = body.encode()
                                    	#response = ((header).encode())+body
                                    	body = body.decode('utf-8')
                                    	response = str(header)+str(body)
                                    	clientname.send(bytes(response.encode('utf-8')))
                                    	#clientname.send(body)
                                    	print("Responding With.."+str(response))
                                    	clientname.close()
                                    	#fullresponse += body

                                    	#clientname.send(fullresponse)
                            except:
                                traceback.print_exc()
                                writeLog(init_data, 0)
                                responsehead = self.makeHeader(500)
                                response = b"<html><body>Error 500: Internal Server Error!</body></html>"
                                fullresponse = responsehead.encode()
                                #fullresponse += response
                                print("Responding with "+str(fullresponse))
                                clientname.send(fullresponse)
                                print("500 Response Previously Sent, Error Executing PHP")
 
                            break
                        elif ".php" in tmpURI and "php" not in allowed_scripts:
                            print("Script Extension Not Supported 2")
                            writeLog(init_data, 0)
                            responsehead = self.makeHeader(403)
                            response = b"<html><body>Error 403: Forbidden!</body></html>"
                            fullresponse = responsehead.encode()
                            fullresponse += response
                            print("Responding with "+str(fullresponse))
                            clientname.send(fullresponse)
                            fullresponse = ""
                            clientname.close()
                            self.cleanUp()
                            break
                        else:
                            try:
                                filedir, filename = os.path.split(tmpURI)
                                print("Requesting URI : "+tmpURI)
                                print("Serving file...")
                                f = open(tmpURI, 'rb')
                                response = f.read()
                                f.close()
                                responsehead = self.makeHeader(200)
                                fullresponse = responsehead.encode() 
                                fullresponse += response #Adding HTTP code to response
                                print("Responding with "+str(fullresponse))
                                clientname.send(fullresponse)
                                writeLog(init_data, 1)
                                fullresponse = ""
                                print("Closing Connection with "+str(clientsock))
                                clientname.close()
                                self.cleanUp()
                            except:
                                print("Error Reading "+tmpURI)
                                traceback.print_exc()
                                writeLog(init_data, 0)
                                responsehead = self.makeHeader(404)
                                response = b"<html><body>Error 404: File Not Found!</body></html>"
                                fullresponse = responsehead.encode()
                                fullresponse += response
                                print("Responding with "+str(fullresponse))
                                clientname.send(fullresponse)
                                fullresponse = ""
                                clientname.close()
                                self.cleanUp()
                    break
                elif (method == 'DELETE'): #Done?
                    New_URI = init_data.split(' ')[1]
                    temp_URI = rootdir+New_URI
                    temp_URI = os.path.normpath(temp_URI)
                    print("Attempting to delete resource located at "+temp_URI)
                    filedir, filename = os.path.split(temp_URI)
                    curdir = os.getcwd()
                    try:
                        os.chdir(filedir)
                        if (os.path.isfile(filename) == 1):
                            print("File Exists! Deleting...")
                            os.remove(filename)
                            print("File Deleted!")
                            writeLog(init_data, 1)
                            responsehead = self.makeHeader(200)
                            response = b"<html><body>200: OK!</body></html>"
                            fullresponse = responsehead.encode()
                            fullresponse += response
                            print("Responding with "+str(fullresponse))
                            clientname.send(fullresponse)
                            fullresponse = ""
                            clientname.close()
                            self.cleanUp()

                        else:
                            print("Specified File Doesn't Exist!")
                            writeLog(init_data, 0)
                            responsehead = self.makeHeader(404)
                            response = b"<html><body>Error 404: File Not Found!</body></html>"
                            fullresponse = responsehead.encode()
                            fullresponse += response
                            print("Responding with "+str(fullresponse))
                            clientname.send(fullresponse)
                            fullresponse = ""
                            clientname.close()
                            self.cleanUp()

                        os.chdir(curdir)
                        break
                    except OSError:
                        traceback.print_exc()
                        print("Path or File Deletion Error!")
                        writeLog(init_data, 0)
                        responsehead = self.makeHeader(500)
                        response = b"<html><body>Error 500: Internal Server Error!</body></html>"
                        fullresponse = responsehead.encode()
                        fullresponse += response
                        print("Responding with "+str(fullresponse))
                        clientname.send(fullresponse)
                        fullresponse = ""
                        clientname.close()
                        self.cleanUp()
                    break

                elif (method == 'POST'): #Content-Length, Content-Type must exist
                    print("Post Mechanism")
                    New_URI = init_data.split(' ')[1]
                    temp_URI = rootdir+New_URI
                    temp_URI = os.path.normpath(temp_URI)
                    print(allowed_scripts)
                    print(temp_URI)
                    print(New_URI)
                    protect = 0
                    print(protected_files)
                    lenp = len(protected_files)
                    x = 0
                    while (x != lenp):
                        print(protected_files[x])
                        if protected_files[x] in New_URI:
                            #print(New_URI+" Match Detected with Protected File")
                            protect = 0 #Change for Final
                            break
                        else:
                            x = x + 1
                            pass
                    if (".php" in temp_URI) and ("php" in allowed_scripts):
                        query = HTTP_Data[1]
                        print(method+" "+ip+" "+clength+" "+ctype+" "+temp_URI+" "+query)
                        print("PHP URI REQUESTED 3")
                        if protect == 1 and ah == 0:
                            writeLog(init_data, 0)
                            responsehead = self.makeHeader(401)
                            response = b"<html><body>Error 401: Unauthorized!</body></html>"
                            fullresponse = responsehead.encode()
                            fullresponse += response
                            print("Responding with "+str(fullresponse))
                            clientname.send(fullresponse)
                            fullresponse = ""
                            clientname.close()
                            self.cleanUp()
                            break
                        else:
                            try:
                                self.phpstrings(method, ip, clength, ctype, temp_URI, query)
                                if type(body) == int:
                                    traceback.print_exc()
                                    print("Path or File Deletion Error!")
                                    writeLog(init_data, 0)
                                    responsehead = self.makeHeader(500)
                                    response = b"<html><body>Error 500: Internal Server Error!</body></html>"
                                    fullresponse = responsehead.encode()
                                    fullresponse += response
                                    print("Responding with "+str(fullresponse))
                                    clientname.send(fullresponse)
                                    fullresponse = ""
                                    clientname.close()
                                    self.cleanUp()
                                    break
                                else:
                                    writeLog(init_data, 1)
                                    header = ''
                                    header += 'HTTP/1.1 200 OK\r\n' #Successful PUT requests
                                    curtime = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime())
                                    header += ('Date: '+curtime+'\r\n')
                                    header += 'Server: Python HTTP Test Server\r\n'
                                    clen = len(body)
                                    header += 'Content-Length: '+str(clen)+"\r\n"
                                    header += 'Keep-Alive: timeout=5, max=100\r\n'
                                    if "Status: 302" in str(body):
                                    	print("Replacing Status and De-Coupling Responses")
                                    	header += 'Connection: Keep-Alive\r\n'                               
                                    	body = body.replace(b"Status:", b"HTTP/1.1")
                                    	clientname.send(body)
                                    	clientname.close()
                                    else:
                                    	header += 'Connection: Keep-Alive\r\n'
                                    	#body = body.encode()
                                    	#response = ((header).encode())+body
                                    	body = body.decode('utf-8')
                                    	response = str(header)+str(body)
                                    	clientname.send(bytes(response.encode('utf-8')))
                                    	#clientname.send(body)
                                    	print("Responding With.."+str(response))
                                    	clientname.close()
                                    	#fullresponse += body
                                    	#clientname.send(fullresponse)
                            except:
                                traceback.print_exc()
                                print("PHP Allowed, .php in URI, Error Executing PHP or Passing Data")
                                #writeLog(init_data, 0)
                                #responsehead = self.makeHeader(500)
                                #response = b"<html><body>Error 500: Internal Server Error!</body></html>"
                                #fullresponse = responsehead.encode()
                                #fullresponse += response
                                #print("Responding with "+str(fullresponse))
                                #clientname.send(fullresponse)
                            fullresponse = ""
                            clientname.close()
                            self.cleanUp()
                            #if '.php' == os.path.splitext(tmpURI)[-1].lower():
                                #php.makeGET(tmpURI, query, htt)
                    elif (".php" in temp_URI) and ("php" not in allowed_scripts):
                        print("Script Extension Not Supported")
                        writeLog(init_data, 0)
                        responsehead = self.makeHeader(403)
                        response = b"<html><body>Error 403: Forbidden!</body></html>"
                        fullresponse = responsehead.encode()
                        fullresponse += response
                        print("Responding with "+str(fullresponse))
                        clientname.send(fullresponse)
                        fullresponse = ""
                        clientname.close()
                        self.cleanUp()
                        
                    break

                elif (method == 'PUT'):
                    if (cl == 0): #Stops functionality if 'Content-Length' not seen in original request
                        break
                    print("\n")
                    New_URI = init_data.split(' ')[1]
                    temp_URI = rootdir+New_URI
                    temp_URI = os.path.normpath(temp_URI)
                    print("Attempting to create/modify resource located at "+temp_URI)
                    filedir, filename = os.path.split(temp_URI)
                    curdir = os.getcwd()
                    try:
                        os.chdir(filedir)
                        if (os.path.isfile(filename) == 1):
                            print("File Already Exists! Replacing...")
                        f = open(filename, 'w')
                        x = 0
                        lendata = len(HTTP_Data)
                        print("Lines Detected : "+str(lendata))
                        for x in range(1, lendata):
                            f.write(HTTP_Data[x])
                            print(HTTP_Data[x], end='')
                        f.close()
                        print("")
                        os.chdir(curdir)
                        print("URI Created..")
                        writeLog(init_data, 1)
                        responsehead = self.makeHeader(201)
                        response = b"<html><body>201: Resource Created!</body></html>"
                        fullresponse = responsehead.encode()
                        fullresponse += response
                        print("Responding with "+str(fullresponse))
                        clientname.send(fullresponse)
                        fullresponse = ""
                    except OSError:
                        print("Failed Writing File!")
                        writeLog(init_data, 0)
                        responsehead = self.makeHeader(500)
                        response = b"<html><body>Error 500: Internal Server Error!</body></html>"
                        fullresponse = responsehead.encode()
                        fullresponse += response
                        print("Responding with "+str(fullresponse))
                        clientname.send(fullresponse)
                        fullresponse = ""
                    clientname.close()
                    self.cleanUp()
                    break
                elif (method == 'CONNECT'):
                    if auth == 1: #Changed for usage, when adding real authentication, change back to 0
                        print("Unauthorized Proxy Connection Detected")
                        writeLog(init_data, 0)
                        responsehead = self.makeHeader(401)
                        response = b"<html><body>401: Unauthorized</body></html>"
                        fullresponse = responsehead.encode()
                        fullresponse += response
                        print("Responding with "+str(fullresponse))
                        clientname.send(fullresponse)
                        fullresponse = ""
                        clientname.close()
                        self.cleanUp()
                        
                    else:
                        print("Authorized Proxy Connection Detected")
                        writeLog(init_data, 1)
                        proxyURI = init_data.split(' ')[1]
                        Requested_URL, Requested_Port = proxyURI.split(':')
                        #print(Requested_URL+str(Requested_Port))
                        newsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        proxyinfo = socket.gethostbyname(Requested_URL)
                        print("Attempting Connection To "+proxyinfo+":"+Requested_Port)
                        newuri = (proxyinfo, int(Requested_Port))
                        try:
                            newsock.connect(newuri)
                            newsock.sendall(b"GET / HTTP/1.1\r\n\r\n")
                            newdata = newsock.recv(8192)
                            newsock.close()
                            clientname.send(newdata)
                            clientname.close()
                        except socket.error:
                            print("Error Connecting to Specified Remote Host!")
                            newsock.close()
                            clientname.close()

                    break
                else:
                    print("This is a problem..")
                    responsehead = self.makeHeader(500)
                    response = b"<html><body>Broken Server!</body></html>"
                    break

                #except Exception:
                    #print("Error receiving/decoding data!")
                    #self.destroySocket()
                    #sys.exit(1)
                    #newServer()

    def makeHeader(self, code): #Creates standard HTTP header with status line and general headers using a parameter variable to determine response type
        header = ''
        if (code == 200):
            header += 'HTTP/1.1 200 OK\n' #Valid requests
        elif (code == 201):
            header += 'HTTP/1.1 201 Created\n' #Successful PUT requests
        elif (code == 202):
            header += 'HTTP/1.1 202 Accepted\n' #Request passed to appropriate handler (IE CGI scripts)
        elif (code == 204):
            header += 'HTTP/1.1 204 No Content\n' #No data to send
        elif (code == 400):
            header += 'HTTP/1.1 400 Bad Request\n' #Malformed
        elif (code == 401):
            header += 'HTTP/1.1 401 Unauthorized\n' #Accessing un-restricted but not logged in
        elif (code == 403):
            header += 'HTTP/1.1 403 Forbidden\n' #Attempting to access restricted files
        elif (code == 404):
            header += 'HTTP/1.1 404 Not Found\n' #If URI not found to exist in GET, POST, DELETE, CONNECT
        elif (code == 405):
            header += 'HTTP/1.1 405 Method Not Allowed\n' #Custom/Disallowed methods (IE those not specified in config file)
        elif (code == 411):
            header += 'HTTP/1.1 411 Length Required\n' #Receiving POST/PUT request with no content length
        elif (code == 500):
            header += 'HTTP/1.1 500 Internal Server Error\n' #PUT file write fail, other generic OS failures, etc
        elif (code == 505):
            header += 'HTTP/1.1 505 HTTP Version Not Supported\n'
        curtime = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime())
        header += ('Date: '+curtime+'\n')
        header += 'Server: Python HTTP Test Server\n'
        header += 'Connection: Close\n'
        header += '\n'
        return header

    def getParams(self, method, clientname): #Retrieves HTTP Options from received HTTP requests, data from POST/PUT
        global auth
        global HTTP_Parameters_ID
        global HTTP_Parameters_Value
        global HTTP_Data
        global cl
        global ct
        global clength
        global ah
        global ctype
        global cauth
        auth = 0 
        HTTP_Parameters_ID = []
        HTTP_Parameters_Value = []
        HTTP_Data = []
        string_stream = io.StringIO(init_data)
        linecount = 0
        #print(string_stream)
        #print(init_data)
        cl = 0
        ct = 0
        ah = 0

        for line in string_stream:
            if (linecount == 0):
                method, URI, Version = line.split(' ')
                linecount += 1
            else:
                if (method == 'GET'):
                    try:
                        a, b = line.split(":", 1) #For lines headers before body, disregard semi-colons after first split
                        if "Authorization" in a:
                            print("Authorization Detected")
                            ah = 1
                            cauth=b.strip()
                        HTTP_Parameters_ID.append(a)
                        HTTP_Parameters_Value.append(b)
                        linecount += 1

                    except:
                        print("End of Headers Detected!") #GET should not have body as per HTTP/1.1 specifications, section 4.3s
                        
                elif (method == 'DELETE'):
                    try:
                        a, b = line.split(":", 1) 
                        HTTP_Parameters_ID.append(a)
                        HTTP_Parameters_Value.append(b)
                        linecount += 1
                    except:
                        print("End of Headers Detected!")
                        
                elif (method == 'CONNECT'):
                    print("CONNECT Parameters")
                elif (method == 'POST'):
                    try:
                        a, b = line.split(":", 1) #For lines headers before body, disregard semi-colons after first split
                        if "Content-Length" in a:
                            print("Length Detected")
                            cl = 1
                            clength=b.strip()
                        if "Content-Type" in a:
                            print("Type Detected")
                            ct = 1
                            ctype=b.strip()
                        if "Authorization" in a:
                            print("Authorization Detected")
                            ah = 1
                            cauth=b.strip()
                        HTTP_Parameters_ID.append(a)
                        HTTP_Parameters_Value.append(b)
                        linecount += 1
                    except:
                        print(cl)
                        if cl == 1 and ct == 1:
                            c = line
                            HTTP_Data.append(c)
                        elif cl == 0:
                            print("Content-Length not specified in POST request!")
                            writeLog(init_data, 0)
                            responsehead = self.makeHeader(411)
                            response = b"<html><body>Error 411: Length Required!</body></html>"
                            fullresponse = responsehead.encode()
                            fullresponse += response
                            print("Responding with "+str(fullresponse))
                            clientname.send(fullresponse)
                            fullresponse = "s"
                            clientname.close()
                            self.cleanUp()
                            break
                        elif ct == 0:
                            print("Content-Type not specified in POST request!")
                            writeLog(init_data, 0)
                            responsehead = self.makeHeader(411)
                            response = b"<html><body>Error 411: Type Required!</body></html>"
                            fullresponse = responsehead.encode()
                            fullresponse += response
                            print("Responding with "+str(fullresponse))
                            clientname.send(fullresponse)
                            fullresponse = "s"
                            clientname.close()
                            self.cleanUp()
                            break
                        
                elif (method == 'PUT'):
                    try:
                        a, b = line.split(":", 1) #For lines headers before body, disregard semi-colons after first split
                        if "Content-Length" in a:
                            print("Length Detected")
                            cl = 1
                        HTTP_Parameters_ID.append(a)
                        HTTP_Parameters_Value.append(b)
                        linecount += 1
                    except:
                        print(cl)
                        if cl == 1:
                            c = line
                            HTTP_Data.append(c)
                        else:
                            print("Content-Length not specified in PUT request!")
                            writeLog(init_data, 0)
                            responsehead = self.makeHeader(411)
                            response = b"<html><body>Error 411: Length Required!</body></html>"
                            fullresponse = responsehead.encode()
                            fullresponse += response
                            print("Responding with "+str(fullresponse))
                            clientname.send(fullresponse)
                            fullresponse = "s"
                            clientname.close()
                            self.cleanUp()
                            break


                        
        param_length = len(HTTP_Parameters_ID)
        body_length = len(HTTP_Data)
        x = 0
        print("Parameters Detected :"+str(param_length))
        for x in range(param_length):
            a = HTTP_Parameters_ID[x]
            b = HTTP_Parameters_Value[x]
            x = x + 1
            print(a+": "+b, end='')
        y = 0
        for y in range(body_length):
            a = HTTP_Data[y]
            print(a, end='')

    def cleanUp(self):
        if (connection_count > 99999): #Change to limit total connection limit
            try:
                self.destroySocket()
            except:
                print("Binding Doesn't Exist!")
        else:
            return


def writeLog(message, grade): #Grade 0 means request failed/rejected, Grade 1 indicates success
    if grade == 0:
        failLog(message)
    elif grade == 1:
        passLog(message)
    else:
        pass

def failLog(message):  #Log-Writing functions
    try:
        temp = os.getcwd()
        os.chdir(faillogdir)
    except OSError:
        #print("Error Changing Working Directory to "+str(faillogdir))
        pass
    try:
        curtime = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime())
        f = open('Rejected Requests Log.txt', 'a')
        f.write("\n" + curtime + "\n" + message + "\n")
        f.close()
    except OSError:
        print("Error Writing to Log File at "+str(faillogdir))
    os.chdir(temp)

def passLog(message): #Writes requests which are granted to the specified log
    try:
        temp = os.getcwd()
        print(passlogdir)
        os.chdir(passlogdir)
    except OSError:
        pass
        #print("Error Changing Working Directory to "+str(passlogdir))
    try:
        curtime = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime())
        f = open('Approved Requests Log.txt', 'a')
        f.write(curtime + "\n" + message + "\n")
        f.close()
    except OSError:
        print("Error Writing to Log File at "+str(passlogdir))
        os.chdir(temp)


def getConfig(): #Reads 'config.txt' from script's working directory to assign IP, Port, Root Content Dir. and Logging Directories ('Bad Logs.txt', 'Good Logs.txt')
    current_dir = os.getcwd()
    global listenIP
    global listenPort
    global rootdir
    global passlogdir
    global faillogdir
    global allowed_methods
    global allowed_scripts
    global protected_files
    protected_files = []
    config_options = []
    config_values = []

    try:
        f = open('config.txt')
        linecount = 0
        for line in f:
            if linecount is 0:
                a, b = line.split(":")
                allowed_methods = b
            if linecount is not 0:
                a,b = line.split(":", 1)
                config_options.append(a)
                config_values.append(b)
            linecount = (linecount + 1)
        print("DETECTED CONFIGURATION SETTINGS")
        print("")
        print("Allowed Methods : "+allowed_methods, end='')
        print(config_options[0]+": "+config_values[0], end='')
        print(config_options[1]+": "+config_values[1], end='')
        print(config_options[2]+": "+config_values[2], end='')
        print(config_options[3]+": "+config_values[3], end='')
        print(config_options[4]+": "+config_values[4], end='')
        print(config_options[5]+": "+config_values[5], end='')
        print(config_options[6]+": "+config_values[6])
        print("")

        listenIP = config_values[0]
        listenPort = int(config_values[1])
        rootdir = (str(config_values[2]).strip())
        passlogdir = config_values[3]
        faillogdir = config_values[4]
        allowed_scripts = config_values[5]
        protected_files = config_values[6]
        newServer()

    except OSError:
        print("Error reading 'config.txt' in base directory!")
        print("Please Check Configuration File exists within same directory as Python script!")
        t=input("Press Any Key to Quit...")
        quit

def newServer():
    vserver = Server(listenPort, listenIP)
    vserver.createSocket()

getConfig()
