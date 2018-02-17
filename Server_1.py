#Verbose Web-Server class for HTTP/PHP Content handling (GET, POST, PUT, DELETE and CONNECT)

import sys
import time
import threading
import socket
import os
import io
import phpstrings

global connection_count #Server set to shutdown after N connections in cleanUp()
connection_count = 0

class Server(object):

    def __init__(self, port):
        self.port = port
        self.hostname = socket.gethostname()#.split('.')[0] #Can change depending upon requirements
        self.location = rootdir
        print("Detected Local Host Name "+self.hostname) 
        print("Port Selected : "+str(port)) 

    def createSocket(self): #IPv4/TCP Mode hard-configured
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print("Binding server to Socket "+self.hostname+":"+str(self.port))
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((listenIP, self.port))
            self.portListen()
        except socket.error:
            print("Error Creating or Binding Socket!")
            #self.destroySocket()

    def destroySocket(self): #Closes Socket when called
        print("Destroying Socket Connection...")
        try:
            self.sock.close()
            #self.sock.shutdown(socket.SHUT_RDWR)
        except socket.error:
            print("Error Closing Socket!")

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
                clientname.close()
                break

            if method not in allowed_methods:
                print("DETECTED METHOD NOT ALLOWED")
                writeLog(init_data, 0)
                responsehead = self.makeHeader(405)
                fullresponse = responsehead.encode() 
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
                        tmpURI = str(rootdir)+"\index.html"
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
                        if ".php" in tmpURI:
                            print("PHP URI REQUESTED")
                            phpstrings.phpstrings(method, ip, 0, 0, tmpURI, query)
                            print(method+" "+ip+" "+tmpURI+" "+query)
                        #if '.php' == os.path.splitext(tmpURI)[-1].lower():
                            #php.makeGET(tmpURI, query, htt)
                        else:
                            print("Extension Not Supported")

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
                    New_URI = init_data.split(' ')[1]
                    temp_URI = rootdir+New_URI
                    temp_URI = os.path.normpath(temp_URI)
                    print("\n")
                    print("POST MECHANISM")
                    query = HTTP_Data[1]
                    phpstrings.phpstrings(method, ip, clength, ctype, temp_URI, query)
                    print(method+" "+ip+" "+clength+" "+ctype+" "+temp_URI+" "+query)
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
        global ctype
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
        for line in string_stream:
            if (linecount == 0):
                method, URI, Version = line.split(' ')
                linecount += 1
            else:
                if (method == 'GET'):
                    try:
                        a, b = line.split(":", 1) #For lines headers before body, disregard semi-colons after first split
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
        print("Error Changing Working Directory to "+str(faillogdir))
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
        print("Error Changing Working Directory to "+str(passlogdir))
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
        print(config_options[4]+": "+config_values[4])

        listenIP = config_values[0]
        listenPort = int(config_values[1])
        rootdir = (str(config_values[2]).strip())
        passlogdir = config_values[3]
        faillogdir = config_values[4]

        newServer()

    except OSError:
        print("Error reading 'config.txt' in base directory!")
        print("Please Check Configuration File exists within same directory as Python script!")
        t=input("Press Any Key to Quit...")
        quit

def newServer():
    vserver = Server(listenPort)
    vserver.createSocket()

getConfig()