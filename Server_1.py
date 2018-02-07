#Verbose Web-Server class for HTTP/PHP Content handling (GET, POST, PUT, DELETE and CONNECT)

import sys
import time
import threading
import socket
import signal
import os
import ntpath
import io

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
        size = 2048 #Number of Bytes Processed as group, might need raising
        print("Socket Information "+str(clientname))

        while True:
            connection_count = connection_count + 1
            print("Connection Number : "+str(connection_count))
            print("Active Thread for "+str(clientsock))
            #try:
            init_data = clientname.recv(size).decode() #Entire HTTP message from RC
            method = init_data.split(' ')[0] #Gets HTTP Request Method from RC
            URI = init_data.split(' ')[1]
            httpver = init_data.split(' ')[2]
            print("Method = "+method)
            print("URI = "+URI)
            print("Version = "+httpver)

            if method not in allowed_methods:
                print("DETECTED METHOD NOT ALLOWED")
                writeLog(init_data, 0)
                responsehead = self.makeHeader(405)
                fullresponse = responsehead.encode() 
                print("Responding with "+str(fullresponse))
                clientname.send(fullresponse)
                fullresponse = ""

                
            else:

                self.getParams(method)
                #print("Entire Message = "+init_data)
                if (method == 'GET') or (method == 'DELETE') or (method == 'POST'):  
                    URI_requested = init_data.split(' ')[1] #Gets second of three elements on Request Line (ex. GET / HTTP/1.1) would get '/'

                    if (method == 'GET'):
                        if (URI_requested == "/") or (URI_requested == "\\"): #If Index Request
                            tmpURI = str(rootdir)+"\index.html"
                            tmpURI.replace(' ', '')
                            tmpURI.replace('\r','')
                            tmpURI.replace('\n','')
                        else: #Any other referenced URI
                            tmpURI = str(rootdir)+URI_requested
                            print(tmpURI)

                            if "?" in URI_requested: #Parses data for GET-PHP requests
                                a, b = tmpURI.split('?', 1)
                                tmpURI = a

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
                    elif (method == 'DELETE'):
                        print("DELETE")
                        self.cleanUp()
                        break
                    elif (method == 'POST'):
                        print("POST")
                        self.cleanUp()
                        break
                elif (method == 'PUT'):
                    print("\n")
                    print("Entering PUT Functionality...")
                    New_URI = init_data.split(' ')[1]
                    temp_URI = rootdir+New_URI
                    temp_URI = os.path.normpath(temp_URI)
                    print("Attempting to create/modify resource located at "+temp_URI)
                    filedir, filename = os.path.split(temp_URI)
                    print(filedir)
                    print(filename)
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
                    except OSError:
                        print("Failed Writing File!")
                        writeLog(init_data, 0)
                        responsehead = self.makeHeader(500)
                        response = b"<html><body>Error 500: File Not Found!</body></html>"
                        fullresponse = responsehead.encode()
                        fullresponse += response
                        print("Responding with "+str(fullresponse))
                        clientname.send(fullresponse)
                        fullresponse = ""
                        clientname.close()
                        self.cleanUp()
                    break

                else:
                    print("HTTP Method "+method+" not recognized!")
                    responsehead = self.makeHeader(400)
                    response = b"<html><body>Broken HTTP Request!</body></html>"
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

    def getParams(self, method): #Retrieves HTTP Options from received HTTP requests, data from POST/PUT
        global HTTP_Parameters_ID
        global HTTP_Parameters_Value
        global HTTP_Data
        HTTP_Parameters_ID = []
        HTTP_Parameters_Value = []
        HTTP_Data = []
        string_stream = io.StringIO(init_data)
        linecount = 0
        #print(string_stream)
        #print(init_data)
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
                        print("End of Headers Detected!")
                        
                elif (method == 'DELETE'):
                    print("Delete Parameters")
                elif (method == 'POST'):
                    print("Post Parameters")
                elif (method == 'PUT'):
                    try:
                        a, b = line.split(":", 1) #For lines headers before body, disregard semi-colons after first split
                        HTTP_Parameters_ID.append(a)
                        HTTP_Parameters_Value.append(b)
                        linecount += 1
                    except:
                        c = line
                        HTTP_Data.append(c)

                        
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
        f.write(curtime + "\n" + message + "\n")
        f.close()
    except OSError:
        print("Error Writing to Log File at "+str(faillogdir))
    os.chdir(temp)

def passLog(message): #Writes requests which are granted to the specified log
    try:
        temp = os.getcwd()
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
