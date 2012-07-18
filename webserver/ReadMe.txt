Name:
Web Server

Author:
Umut Can Genlik


Description:
Simple web server written in Java. Supports basic authentication and SSL.

Compilation:
Compile all classes against JDK 6. Entry point to the program is located in ServerFrame class.

Running:
Execute the JAR file locate in "bin" folder.

Usage:
In order to protect files from unauthorized access, you need to place a ".users" file in the folder you want to protect. This file should contain user name-password pairs separated by ':' character per line. See the "sample/www" folder for an example. There is also SSLStore file in sample folder to test SSL functionality. The keystore and certificate passwords are "steflik".

Design:
There are 3 classes in the program:
ServerFrame is a JFrame that handles GUI operations allowing user to choose document root, port number, enabling of SSL and choosing key store file.
WebServer is the main class that accepts connections and passes them to RequestHandler class.
RequestHandler is the class that parses the request, reads the file and send back to the browser. RequestHandler is also responsible for checking access control information for basic authentication.
