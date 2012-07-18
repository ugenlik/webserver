package webserver;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import sun.misc.BASE64Decoder;

/**
 * HTTP and HTTPS web server with Basic Authentication.
 * @author Umut Can Genlik
 */
public class WebServer implements Runnable{
    
	int port;
	File rootDir; // document root
	ServerSocket serverSocket = null;
	boolean stopping = false; // indicates that stop() is called. used by thread communication
    
	/**
	 * Create a WebServer.
	 * @param rootDir Directory to be served
	 * @param port Port number
	 * @param secure Is going to run on SSL?
	 * @param keyStorePath Path to the key store file
	 * @param password Key store password
	 * @throws IOException When there is an error while creating web server.
	 */
	public WebServer(String rootDir, int port, boolean secure, String keyStorePath, String password) throws IOException {
		this.port = port;
		this.rootDir = new File(rootDir);
		if(!this.rootDir.isDirectory()){
			throw new IllegalArgumentException("rootDir must be directory path.");
		}
		SSLContext sslContext;
        
		if(secure){
			FileInputStream fis;
			KeyStore ks;
			try {
				fis = new FileInputStream(keyStorePath);
				ks = KeyStore.getInstance("JKS");
				ks.load(fis, password.toCharArray());
				KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
				kmf.init(ks, password.toCharArray());
				TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
				tmf.init(ks);
				sslContext = SSLContext.getInstance("SSL");
				sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
				fis.close();
				serverSocket = sslContext.getServerSocketFactory().createServerSocket(port);
			} catch (KeyManagementException ex) {
				Logger.getLogger(WebServer.class.getName()).log(Level.SEVERE, null, ex);
			} catch (UnrecoverableKeyException ex) {
				Logger.getLogger(WebServer.class.getName()).log(Level.SEVERE, null, ex);
			} catch (NoSuchAlgorithmException ex) {
				Logger.getLogger(WebServer.class.getName()).log(Level.SEVERE, null, ex);
			} catch (CertificateException ex) {
				Logger.getLogger(WebServer.class.getName()).log(Level.SEVERE, null, ex);
			} catch (KeyStoreException ex) {
				Logger.getLogger(WebServer.class.getName()).log(Level.SEVERE, null, ex);
			}
		}
		else
			serverSocket = new ServerSocket(port);
	}
    
	/**
	 * Simple constructor.
	 * @param rootDirectory Directory to be served
	 * @throws IOException When something went wrong?!@#$
	 */
	public WebServer(String rootDirectory) throws IOException{
		this(rootDirectory, 80, false, null, null);
	}
    
	/**
	 * Simple web server. Serves HTTP on given root. For testing purposes only.
	 * @param args The document root.
	 */
	public static void main(String[] args) {
		if(args.length != 1){
			System.out.println("Wrong usage: Enter document root as argument.");
			System.exit(-1);
		}
		try {
			WebServer webServer = new WebServer(args[0]);
			webServer.start();
			System.out.println("Web server is running.");
			System.out.print("Press enter to exit...");
			System.in.read();
			webServer.stop();
		} catch (IOException ex) {
			System.out.println("Cannot start web server.");
		}
    }
    
	/**
	 * Start the web server. Does not block.
	 */
	public void start() {
		Thread accepter = new Thread(this);
		accepter.setName("Accepter");
		accepter.start();
	}
    
	/**
	 * Stop the web server. Does not block.
	 */
	public void stop(){
		if(serverSocket != null){
			try {
				stopping = true;
				serverSocket.close();
			} catch (IOException ex) {}
			serverSocket = null;
		}
	}
    
	/**
	 * Returns the root of the web server.
	 * @return Root directory of the WebServer
	 */
	public File getRoot(){
		return rootDir;
	}
    
	/**
	 * Accepter thread.
	 * Loops forever ServerSocket.accept() until server is stopped.
	 */
	public void run(){
		while(serverSocket != null){
			try {
				Socket socket = serverSocket.accept();
				new Thread(new RequestHandler(socket, this)).start();
			} catch (IOException ex) {
				if(!stopping)
					Logger.getLogger(WebServer.class.getName()).log(Level.SEVERE, null, ex);
			} finally {
				stopping = false;
			}
		}
	}
    
}

/**
 * Handles one HTTP request
 * @author Umut Can Genlik
 */
class RequestHandler implements Runnable {
    
	Socket socket; // socket to the client
	PrintWriter writer; // output stream
	BufferedReader reader; // input stream
	File root; // document root of the web server
    
	// Parsed from first line of request
	String method; // http method
	String url; // resource string
	File requestedFile; // file requested
    
	// For basic authenticaion
	String username; // username that client sent
	String password; // password that client sent
	HashMap<String, String> users; // list of users that has access to the requested file
	String realm; // realm of the requested file, in other words its parent directory
	boolean realmSet; // used by the recursive isFolderProtected method
	boolean folderProtected; // is the requested file protected by password
    
	/**
	 *
	 * @param socket Socket to the client
	 * @param webServer Context the request is going to be handled
	 */
	public RequestHandler(Socket socket, WebServer webServer){
		this.socket = socket;
		root = webServer.getRoot();
		users = new HashMap<String, String>();
	}
    
	/**
	 * Main serving method. It is better to run this as seperate thread.
	 */
	public void run(){
		try {
			reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			writer = new PrintWriter(socket.getOutputStream());
            
			// Parse first line of request
			String request = reader.readLine(); System.out.println("Request: " + request);
			String[] requestArray = request.split(" ");
			method = requestArray[0];
			url = requestArray[1];
            
			// If a folder requested serve index.html in it
			requestedFile = new File(root, url);
			if(requestedFile.isDirectory())
				requestedFile = new File(requestedFile, "index.html");
            
			// Serve logic
			if(isFolderProtected(requestedFile.getParentFile())){
				if(isAuthorizationSent()){
					if(isUserValid()){
						sendResponse();
					}else{
						sendForbidden();
					}
				}else{
					sendAuthorizationRequired();
				}
			}else{
				sendResponse();
			}
            
		} catch (IOException ex) {
			Logger.getLogger(RequestHandler.class.getName()).log(Level.SEVERE, null, ex);
		} finally {
			try {
				if(writer != null){
					writer.close();
				}
				socket.close();
			} catch (IOException ex) {}
		}
	}
    
	/**
	 * Send 501 if method is not implemented else send the requested file if it does not start with '.'.
	 */
	private void sendResponse(){
		if(method.equals("GET")){
			if(requestedFile.getName().charAt(0) != '.') sendOK(); // do not server files starting with '.'
			else sendForbidden();
		} else {
			sendNotImplemented();
		}
	}
    
	/**
	 * Send HTTP code 200 and requested resouce.
	 */
	private void sendOK(){
		FileInputStream fis = null;
		try {
			String contentType;
			String fileName = requestedFile.getName();
            
			if ((fileName.toLowerCase().endsWith(".jpg")) || (fileName.toLowerCase().endsWith(".jpeg")) || (fileName.toLowerCase().endsWith(".jpe"))) {
				contentType = "image/jpg";
			} else if ((fileName.toLowerCase().endsWith(".gif"))) {
				contentType = "image/gif";
			} else if ((fileName.toLowerCase().endsWith(".htm")) || (fileName.toLowerCase().endsWith(".html"))) {
				contentType = "text/html";
			} else if ((fileName.toLowerCase().endsWith(".qt")) || (fileName.toLowerCase().endsWith(".mov"))) {
				contentType = "video/quicktime";
			} else if ((fileName.toLowerCase().endsWith(".class"))) {
				contentType = "application/octet-stream";
			} else if ((fileName.toLowerCase().endsWith(".mpg")) || (fileName.toLowerCase().endsWith(".mpeg")) || (fileName.toLowerCase().endsWith(".mpe"))) {
				contentType = "video/mpeg";
			} else if ((fileName.toLowerCase().endsWith(".au")) || (fileName.toLowerCase().endsWith(".snd"))) {
				contentType = "audio/basic";
			} else if ((fileName.toLowerCase().endsWith(".wav"))) {
				contentType = "audio/x-wave";
			} else {
				contentType = "text/plain";
			} //default
            
			fis = new FileInputStream(requestedFile);
			writer.println("HTTP/1.1 200 OK");
			writer.println("Content-Type: " + contentType);
			writer.println();
            
			int i;
			while((i = fis.read()) != -1){
				writer.write(i);
			}
		} catch (FileNotFoundException ex) {
			sendNotFound();
		} catch (IOException ex) {
			Logger.getLogger(RequestHandler.class.getName()).log(Level.SEVERE, null, ex);
		} finally {
			if(fis != null) {
				try {
					fis.close();
				} catch (IOException ex) {}
			}
		}
	}
    
	/**
	 * Send HTTP code 404.
	 */
	private void sendNotFound(){
		writer.println("HTTP/1.1 404 Not Found");
		writer.println();
		writer.println("HTTP/1.1 404 Not Found");
	}
    
	/**
	 * Send HTTP code 501.
	 */
	private void sendNotImplemented(){
		writer.println("HTTP/1.1 501 Not Implemented");
		writer.println();
		writer.println("HTTP/1.1 501 Not Implemented");
	}
    
	/**
	 * Check the directory to see if it is protected and set realm users hash map.
	 * @param directory Directory to be checked.
	 * @return true if the directory contains .users file, else otherwise.
	 */
	private boolean isFolderProtected(File directory) {
		File usersFile = new File(directory, ".users");
		if(usersFile.isFile()){
			try {
				FileInputStream fis = new FileInputStream(usersFile);
				BufferedReader userReader = new BufferedReader(new InputStreamReader(fis));
				String line;
				try {
					while((line = userReader.readLine()) != null){
						String[] items = line.split(":");
						users.put(items[0], items[1]);
					}
				} catch (IOException ex) { }
				folderProtected = true;
				if(!realmSet){
					realm = directory.getPath().substring((int)root.getPath().length());
					if(realm.equals("")) realm = "/";
					realm = realm.replace('\\', '/'); // convert windows directory path seperator
					realmSet = true;
				}
			} catch (FileNotFoundException ex) {
				Logger.getLogger(RequestHandler.class.getName()).log(Level.SEVERE, null, ex);
			}
		}
        
		directory = directory.getParentFile();
		if(directory == null || directory.equals(root.getParentFile())) return folderProtected;
		else return isFolderProtected(directory);
	}
    
	/**
	 * Checks user name and password.
	 * @return true if user name and password is valid, else otherwise
	 */
	private boolean isUserValid() {
		try{
			if(users.get(username).equals(password)) return true;
		} catch (NullPointerException e){}
		return false;
	}
    
	/**
	 * Send HTTP code 401.
	 */
	private void sendAuthorizationRequired() {
		writer.println("HTTP/1.1 401 Authorization Required");
		writer.println("WWW-Authenticate: Basic realm=\""+ realm +"\"");
		writer.println();
		writer.println("HTTP/1.1 401 Authorization Required");
	}
    
	/**
	 * Checks to see if the browser sent the "Authorization" header in request
	 * @return true if "Authorization" header is sent, false otherwise
	 */
	private boolean isAuthorizationSent() {
		try {
			String line;
			while(!(line = reader.readLine()).equals("")){
				int idx = line.indexOf(':');
				if(idx != -1){
					String header = line.substring(0, idx).trim();
					if(header.equals("Authorization")){
						String value = line.substring(idx+1).trim();
						String[] items = value.split(" ");
						BASE64Decoder decoder = new BASE64Decoder();
						String decodedValue = new String(decoder.decodeBuffer(items[1]));
						String[] userPassPair = decodedValue.split(":");
						if(userPassPair.length == 2){
							username = userPassPair[0];
							password = userPassPair[1];
							return true;
						}
					}
				}
			} 
		}catch (IOException ex) { }
		return false;
	}
    
	/**
	 * Send HTTP code 403.
	 */
	private void sendForbidden() {
		writer.println("HTTP/1.1 403 Forbidden");
		writer.println();
		writer.println("HTTP/1.1 403 Forbidden");
	}
    
}
