/*
 * ServerFrame.java
 * Umut Can Genlik
 * 
 */

package webserver;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

/**
 *
 * @author Umut Can Genlik
 */
public class ServerFrame extends javax.swing.JFrame {
    
	WebServer webServer;
    
    /** Creates new form ServerFrame */
    public ServerFrame() {
        initComponents();
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {
        
        jLabel1 = new javax.swing.JLabel();
        dirField = new javax.swing.JTextField();
        rootBrowseButton = new javax.swing.JButton();
        portField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        runButton = new javax.swing.JToggleButton();
        sslBox = new javax.swing.JCheckBox();
        keyStoreField = new javax.swing.JTextField();
        keyStoreBrowseButton = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        passswordField = new javax.swing.JPasswordField();
        
        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("WebServer");
        setLocationByPlatform(true);
        
        jLabel1.setText("Document Root:");
        
        dirField.setText(System.getProperty("user.dir"));
        
        rootBrowseButton.setText("Browse");
        rootBrowseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rootBrowseButtonActionPerformed(evt);
            }
        });
        
        portField.setText("80");
        portField.setPreferredSize(new java.awt.Dimension(59, 20));
        
        jLabel2.setText("Port:");
        
        runButton.setText("Run");
        runButton.setPreferredSize(new java.awt.Dimension(75, 23));
        runButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                runButtonActionPerformed(evt);
            }
        });
        
        sslBox.setText("SSL");
        sslBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sslBoxActionPerformed(evt);
            }
        });
        
        keyStoreField.setText(System.getProperty("user.dir"));
        keyStoreField.setEnabled(false);
        
        keyStoreBrowseButton.setText("Browse");
        keyStoreBrowseButton.setEnabled(false);
        keyStoreBrowseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                keyStoreBrowseButtonActionPerformed(evt);
            }
        });
        
        jLabel3.setText("Keystore:");
        
        jLabel4.setText("Keystore Password:");
        
        passswordField.setEnabled(false);
        
        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                                  layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                  .addGroup(layout.createSequentialGroup()
                                            .addContainerGap()
                                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                      .addComponent(jLabel1)
                                                      .addComponent(jLabel2)
                                                      .addComponent(jLabel3)
                                                      .addComponent(jLabel4))
                                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                      .addGroup(layout.createSequentialGroup()
                                                                .addComponent(portField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                .addComponent(sslBox))
                                                      .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                                          .addComponent(keyStoreField, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 205, Short.MAX_VALUE)
                                                                          .addComponent(dirField, javax.swing.GroupLayout.DEFAULT_SIZE, 205, Short.MAX_VALUE))
                                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                                                          .addComponent(keyStoreBrowseButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                                          .addComponent(rootBrowseButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                                                .addGap(6, 6, 6))
                                                      .addComponent(runButton, javax.swing.GroupLayout.PREFERRED_SIZE, 98, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                      .addComponent(passswordField, javax.swing.GroupLayout.PREFERRED_SIZE, 88, javax.swing.GroupLayout.PREFERRED_SIZE))
                                            .addContainerGap())
                                  );
        layout.setVerticalGroup(
                                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addGroup(layout.createSequentialGroup()
                                          .addContainerGap()
                                          .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                    .addComponent(rootBrowseButton)
                                                    .addComponent(dirField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                    .addComponent(jLabel1))
                                          .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                          .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                    .addComponent(jLabel2)
                                                    .addComponent(portField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                    .addComponent(sslBox))
                                          .addGap(6, 6, 6)
                                          .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                    .addComponent(keyStoreField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                    .addComponent(jLabel3)
                                                    .addComponent(keyStoreBrowseButton))
                                          .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                          .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                    .addComponent(jLabel4)
                                                    .addComponent(passswordField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                          .addGap(18, 18, 18)
                                          .addComponent(runButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                          .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                );
        
        pack();
    }// </editor-fold>//GEN-END:initComponents
    
	private void rootBrowseButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rootBrowseButtonActionPerformed
		JFileChooser chooser = new JFileChooser(dirField.getText());
		chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		int option = chooser.showOpenDialog(this);
		if(option == JFileChooser.APPROVE_OPTION){
			dirField.setText(chooser.getSelectedFile().getAbsolutePath());
		}
	}//GEN-LAST:event_rootBrowseButtonActionPerformed
    
	private void runButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_runButtonActionPerformed
		if(runButton.isSelected()){
			try {
				String root = dirField.getText();
				int port = Integer.parseInt(portField.getText());
                
				webServer = new WebServer(root, port, sslBox.isSelected(), keyStoreField.getText(), passswordField.getText());
                
				webServer.start();
				
				// Disable buttons and text fields
				dirField.setEnabled(false);
				portField.setEnabled(false);
				rootBrowseButton.setEnabled(false);
				sslBox.setEnabled(false);
				keyStoreField.setEnabled(false);
				keyStoreBrowseButton.setEnabled(false);
				passswordField.setEnabled(false);
                
				runButton.setText("Running...");
			} catch (IOException ex) {
				ex.printStackTrace();
				JOptionPane.showMessageDialog(this, "Cannot start web server: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
				runButton.setSelected(false);
			}
		}else{
			webServer.stop();
			webServer = null;
            
			// Enable buttons
			dirField.setEnabled(true);
			portField.setEnabled(true);
			rootBrowseButton.setEnabled(true);
			sslBox.setEnabled(true);
			if(sslBox.isSelected()){
				keyStoreField.setEnabled(true);
				keyStoreBrowseButton.setEnabled(true);
				passswordField.setEnabled(true);
			}
            
			runButton.setText("Run");
		}
	}//GEN-LAST:event_runButtonActionPerformed
    
	private void sslBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_sslBoxActionPerformed
		if(!sslBox.isSelected()){
			keyStoreField.setEnabled(false);
			keyStoreBrowseButton.setEnabled(false);
			passswordField.setEnabled(false);
			portField.setText("80");
		}else{
			keyStoreField.setEnabled(true);
			keyStoreBrowseButton.setEnabled(true);
			passswordField.setEnabled(true);
			portField.setText("443");
		}
	}//GEN-LAST:event_sslBoxActionPerformed
    
	private void keyStoreBrowseButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_keyStoreBrowseButtonActionPerformed
		JFileChooser chooser = new JFileChooser(dirField.getText());
		chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
		int option = chooser.showOpenDialog(this);
		if(option == JFileChooser.APPROVE_OPTION){
			keyStoreField.setText(chooser.getSelectedFile().getAbsolutePath());
		}
	}//GEN-LAST:event_keyStoreBrowseButtonActionPerformed
    
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		} catch (ClassNotFoundException ex) {
			Logger.getLogger(ServerFrame.class.getName()).log(Level.SEVERE, null, ex);
		} catch (InstantiationException ex) {
			Logger.getLogger(ServerFrame.class.getName()).log(Level.SEVERE, null, ex);
		} catch (IllegalAccessException ex) {
			Logger.getLogger(ServerFrame.class.getName()).log(Level.SEVERE, null, ex);
		} catch (UnsupportedLookAndFeelException ex) {
			Logger.getLogger(ServerFrame.class.getName()).log(Level.SEVERE, null, ex);
		}
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new ServerFrame().setVisible(true);
            }
        });
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField dirField;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JButton keyStoreBrowseButton;
    private javax.swing.JTextField keyStoreField;
    private javax.swing.JPasswordField passswordField;
    private javax.swing.JTextField portField;
    private javax.swing.JButton rootBrowseButton;
    private javax.swing.JToggleButton runButton;
    private javax.swing.JCheckBox sslBox;
    // End of variables declaration//GEN-END:variables
    
}
