#Verbose Web-Server class for HTTP/PHP Content handling (GET, POST, PUT and DELETE)

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
        self.port = port #Hardcoded to 80 currently
        self.hostname = socket.gethostname()#.split('.')[0] #Can change depending upon requirements
        self.location = os.getcwd() #Script must be stored in root directory/modified to find HTTP files
        print("Detected Local Host Name "+self.hostname) #Testing
        print("Port Selected : "+str(port)) #Testing

    def createSocket(self): #Creates/Binds on IPv4/Server Mode
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print("Binding server to Socket "+self.hostname+":"+str(self.port))
            self.sock.bind(('', self.port))
            self.portListen()
        except socket.error:
            print("Error Creating/Binding Socket!")
            #self.destroySocket()

    def destroySocket(self): #Closes after N connections
        print("Destroying Socket Connection...")
        try:
            self.sock.close()
            #self.sock.shutdown(socket.SHUT_RDWR)
        except socket.error:
            print("Error Shutting Socket!")

    def portListen(self):
        self.sock.listen(5) #Number of connections to listen for
        print("Listening on Port "+str(self.port))
        while True:
            print("Listen Loop Initiated..")
            (remotename, remoteIP) = self.sock.accept() #Listens for connections from Remote Clients (RC)
            print("Connection from "+str(remoteIP))
            newthread = threading.Thread(target=self.processConnection(remotename, remoteIP)) #Put handling for each RC in separate thread
            newthread.start()

    def processConnection(self, clientname, clientsock):
        global connection_count
        global init_data
        size = 2048 #Number of Bytes to Process at once
        print("Socket Information "+str(clientname))

        while True:
            connection_count = connection_count + 1
            print("Connection Number : "+str(connection_count))
            print("Active Thread for "+str(clientsock))
            #try:
            init_data = clientname.recv(size).decode() #Entire HTTP message from RC
            method = init_data.split(' ')[0] #Gets HTTP Request Method from RC
            print("Method = "+method)
            self.getParams(method)
            #print("Entire Message = "+init_data)
            if (method == 'GET') or (method == 'DELETE') or (method == 'POST'):  
                URI_requested = init_data.split(' ')[1]
                try:
                    filefull = os.path.normpath(URI_requested)
                    filedir, filename = ntpath.split(URI_requested)
                    if (URI_requested == "/") or (URI_requested == "\\"):
                        filename = "index.html"
                    #print(filedir)
                    #print(filename)
                    print("Requesting URI : "+URI_requested)
                except OSError:
                    print("Error Reading Specified URI : "+str(URI_requested))
                fulldir = self.location+'\\'+filename
                if (method == 'GET'):
                    try:
                        print("Serving file located at "+fulldir)
                        f = open(fulldir, 'rb')
                        response = f.read()
                        f.close()
                        responsehead = self.makeHeader(200)
                        fullresponse = responsehead.encode() 
                        fullresponse += response #Adding HTTP code to response
                        print("Responding with "+str(fullresponse))
                        clientname.send(fullresponse)
                        fullresponse = ""
                        print("Closing Connection with "+str(clientsock))
                        clientname.close()
                        self.cleanUp()
                    except:
                        print("Error Reading "+fulldir)
                        responsehead = self.makeHeader(404)
                        response = b"<html><body>Error 404: File Not Found!</body></html>"
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
                print("Entering PUT Functionality...")
                New_URI = init_data.split(' ')[1]
                filedir, filename = ntpath.split(New_URI)
                print("Attempting to create/modify resource located at "+filedir+filename)
                curdir = os.getcwd()
                #os.chdir(filedir)
                if (os.path.isfile(filename) == 1):
                    print("File Already Exists! Replacing...")

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

    def makeHeader(self, code):
        header = ''
        if (code == 200):
            header += 'HTTP/1.1 200 OK\n'
        elif (code == 201):
            header += 'HTTP/1.1 201 Created\n'
        elif (code == 202):
            header += 'HTTP/1.1 202 Accepted\n'
        elif (code == 204):
            header += 'HTTP/1.1 204 No Content\n'
        elif (code == 400):
            header += 'HTTP/1.1 400 Bad Request\n'
        elif (code == 404):
            header += 'HTTP/1.1 404 Not Found\n'
        curtime = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime())
        header += ('Date: '+curtime)
        header += 'Server: Python HTTP Test Server'
        header += 'Connection: Close'
        return header

    def getParams(self, method):
        global HTTP_Parameters
        HTTP_Parameters = []
        string_stream = io.StringIO(init_data)
        linecount = 0
        print(string_stream)
        #print(init_data)
        for line in string_stream:
            if (linecount == 0):
                print(line)
                method, URI, Version = line.split(' ')
                print(method)
                print(URI)
                print(Version)
                linecount += 1
            else:
                if (method == 'GET'):
                    print("Get Parameters")
                    try:
                        a, b = line.split(":", 1) #For lines headers before body, disregard semi-colons after first split
                        print(a+":"+b)
                        HTTP_Parameters.append(a)
                        HTTP_Parameters.append(b)
                        linecount += 1
                    except OSError:
                        print("End of Headers Detected!")
                        break
                elif (method == 'DELETE'):
                    print("Delete Parameters")
                elif (method == 'POST'):
                    print("Post Parameters")
                elif (method == 'PUT'):
                    print("Put Parmaeters")
        param_length = len(HTTP_Parameters)
        x = 0
        print(param_length)
        for x in range(param_length-1):
            print(x)
            a = HTTP_Parameters[x]
            #print(a)
            x = x + 1
            b = HTTP_Parameters[x]
            #print(b)
            x = x + 1
            print(a+" : "+b)


    def cleanUp(self):
        if (connection_count > 5): #Change to limit total connection / shutdown limit
            try:
                self.destroySocket()
            except:
                print("Binding Doesn't Exist!")
        else:
            return

def newServer():
    vserver = Server(80)
    vserver.createSocket()

newServer()
