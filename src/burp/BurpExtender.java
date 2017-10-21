package burp;
import java.awt.Component;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.util.*;
import java.net.URL;
import java.io.*;
import javax.swing.*;
import javax.swing.event.*;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.Color;
import java.awt.Desktop;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.filechooser.FileNameExtensionFilter;

/**
 *
 * @author Amit Agarwal
 * Twitter Handle  @amitbcp
 *
 */

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController, IScopeChangeListener
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IResponseInfo respInfo;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;
    public LogEntry logEntry;
    private  PrintWriter stdout;
    private  PrintWriter stderr;
    private File file;
    private File file1;
    private File file2;
    private FileWriter filewriter;
    private Pattern pattern;
    private Matcher matcher;
    private StringBuffer resptag;
    private String stringresp;
    private String respContentType;
    private String responseContentType_burp;
    private String hashHeader;
    private String hashResponse;
    private String hashTag;
    


    //ITab fields
	private JButton testConnButton;
	private JPanel component;
        private JTextField hostField;
        private String caption;
        private JTabbedPane topTabs;

     //Exporting Logs Fields

    private boolean canSaveCSV;
    private JFileChooser chooser;
    private File csvFile;
    private boolean cancelOp = false;

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        stdout = new PrintWriter(callbacks.getStdout(), true);

        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Response Encoder");

        //set ITab implementation

        caption = "Check";
	component = new JPanel(new GridLayout(7,2));

        // create our UI

        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                // main split pane
                 JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // table of log entries
                Table logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable);
                splitPane.setLeftComponent(scrollPane);

                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);

                // tabs with log/options viewers
                LoggerOptionsPanel optionsJPanel = new LoggerOptionsPanel();

                // About tab
		AboutPanel aboutJPanel = new AboutPanel(); //Options
                topTabs = new JTabbedPane();
                topTabs.addTab("View Logs", splitPane);
		topTabs.addTab("Options",optionsJPanel);
                topTabs.addTab("About", aboutJPanel);


                // customize our UI components
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(tabs);
                callbacks.customizeUiComponent(topTabs);
                //callbacks.customizeUiComponent(component);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);

                // register ourselves as an HTTP listener
                callbacks.registerHttpListener(BurpExtender.this);
                callbacks.registerScopeChangeListener(BurpExtender.this);
            }
        });

    }

    //
    // implement ITab
    //

    @Override
    public String getTabCaption()
    {
        return "RCoder";
    }

    @Override
    public Component getUiComponent()
    {
        return topTabs;
    }

    @Override
    public void scopeChanged()
    {
        System.out.println("Scope Modified");
    }
    //
    //Encrypt Using SHA-1 ALgorithm
    //

    public static String sha1(String input) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input.getBytes());
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < result.length; i++) {
            sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
        }
         return sb.toString();
            }
    
       //
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        // only process responses
        if (!messageIsRequest)
        {

            //only process InScopeResponse
            if(callbacks.isInScope(helpers.analyzeRequest(messageInfo).getUrl()))
            {
                //Get Content Type/MIME Type
                IResponseInfo tempAnalyzedResp = helpers.analyzeResponse(messageInfo.getResponse());
                responseContentType_burp =tempAnalyzedResp.getInferredMimeType();
                List<String> lstFullResponseHeader = tempAnalyzedResp.getHeaders();
                for(String item:lstFullResponseHeader){
					item = item.toLowerCase();
					if(item.startsWith("content-type: ")){
						String[] temp = item.split("content-type:\\s",2);
						if(temp.length>0){
                                                    this.respContentType = temp[1];
                                                }
                                                else{
                                                    this.respContentType=null;
                                                }

					}
                                        //Removing the variable Date From the Headers
                                        else if(item.startsWith("date: ")){
                                            lstFullResponseHeader.remove(item);						

					}
		}
             StringBuilder headers_string = new StringBuilder();  
             for (String s : lstFullResponseHeader)
                headers_string.append(s+" ");
             
             
            //Getting Response in resp Byte Stream
            byte[] resp = messageInfo.getResponse();
            //Analysing Response
            respInfo=helpers.analyzeResponse(resp);
            //Marking the start of Body
            int respDataStart = respInfo.getBodyOffset();
            // Setting ByteStream for Response Data
            byte[] respData=new byte[resp.length-respDataStart];
            //Copying Response Body Message
            int i=respDataStart;
            int j=0;
            while(i<resp.length)
            {
                respData[j] = resp[i];
                i++;
                j++;
            }

            // create a new log entry with the message details
            synchronized(log)
            {
                try
                {
                    //Parsing JSON responses
                    if(respContentType.startsWith("application/json") || responseContentType_burp.equalsIgnoreCase("json"))
                    {
                        stringresp = new String(respData);
                        pattern = Pattern.compile("\".*\"\\s?:");
                        matcher= pattern.matcher(stringresp);
                        resptag=new StringBuffer();
                        while(matcher.find())
                        {
                            resptag= resptag.append(stringresp.substring(matcher.start(), matcher.end()));
                        }

                        //Used to check resptag by writing the last response in file
                        file = new File("C:/filename.txt");
                        filewriter =new FileWriter(file);
                        filewriter.write(resptag.toString());
                        filewriter.close();

                    }
                    //Parsing HTML/XML responses
                    else
                    {
                        stringresp = new String(respData);
                        pattern = Pattern.compile("<.*?>");
                        matcher= pattern.matcher(stringresp);
                        resptag=new StringBuffer();
                        while(matcher.find())
                        {
                            resptag= resptag.append(stringresp.substring(matcher.start(), matcher.end()));
                        }
                         
                    }
                    //
                    //Image/Audio and other files will be in Full hash only

                    file2 = new File("C:/Users/Amit/Desktop/filename2.txt");
                    filewriter =new FileWriter(file2);
                    filewriter.write(resptag.toString());
                    filewriter.close();
//                    
                    file1 = new File("C:/Users/Amit/Desktop/filename1.txt");
                    filewriter =new FileWriter(file1);
                    filewriter.write(stringresp);
                    filewriter.close();

                    //inserting rows
                    int row = log.size();
                    //Check for Hash Modification
////                    if(sha1(stringresp.toString()).equalsIgnoreCase(sha1(resptag.toString())))
////                       hashStatus="Constant";
////                    else
////                        hashStatus="Modified";
                    hashHeader=sha1(headers_string.toString());
                    hashResponse=sha1(stringresp);
                    hashTag=sha1(resptag.toString());
                    log.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),respContentType, helpers.analyzeRequest(messageInfo).getUrl(),hashResponse,hashTag,responseContentType_burp,hashHeader) );

                    fireTableRowsInserted(row, row);
                }
                catch(Exception E)
                {
                    System.out.println("OKAY");
                }
            }
        }
        }
    }

    //
    // extend AbstractTableModel
    //

    @Override
    public int getRowCount()
    {
        return log.size();
    }

    @Override
    public int getColumnCount()
    {
        return 7;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "Tool";
            case 1:
                return "URL";
            case 2:
                return "Content Type";
            case 3:
                return "MIME Type";
            case 4:
                return "Hash Header";
            case 5:
                return "Full Hash";
            case 6:
                return "Tag Hash";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return callbacks.getToolName(logEntry.tool);
            case 1:
                return logEntry.url.toString();
            case 2:
                return logEntry.respContentType;
            case 3:
                return logEntry.responseContentType_burp;
            case 4:
                return logEntry.hashHeader;
            case 5:
                return logEntry.fHash;
            case 6:
                return logEntry.rHash;
            default:
                return "";
        }
    }

    //
    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages being displayed
    //

    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    //
    // extend JTable to handle cell selection
    //


    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    //
    // class to hold details of each log entry
    //

    public  class LogEntry
    {
        final int tool;
        final IHttpRequestResponsePersisted requestResponse;
        //final IResponseInfo respInfo;
        final String respContentType;
        final URL url;
        final String fHash;
        final String rHash;
        final String responseContentType_burp;
        final String hashHeader;

        LogEntry(int tool, IHttpRequestResponsePersisted requestResponse,String respContentType, URL url, String fHash, String rHash,String responseContentType_burp,String hashHeader)
        {
            if(fHash.equalsIgnoreCase("da39a3ee5e6b4b0d3255bfef95601890afd80709"))
                this.fHash="Null";
            else
                this.fHash =fHash;
            if(rHash.equalsIgnoreCase("da39a3ee5e6b4b0d3255bfef95601890afd80709"))
                this.rHash="Null";
            else
                this.rHash =rHash;

            this.tool = tool;
            this.requestResponse = requestResponse;
            //this.respInfo= respInfo;
            this.respContentType=respContentType;
            this.url = url;
            this.responseContentType_burp= responseContentType_burp;
            this.hashHeader=hashHeader;

        }
      }

//
//Top Tabs UI and functionality Class
//
public class LoggerOptionsPanel extends JPanel{

    private JToggleButton tglbtnIsEnabled = new JToggleButton("Rcoder is running");
    private JButton btnSaveLogsButton = new JButton("Save log table as CSV");
    private JButton btnSaveFullLogs = new JButton("Save fill logs as CSV (slow)");
    private final JLabel lblNewLabel = new JLabel("Note 1: Status Flag shows whether Full Hash & Response Hash are same or not");
    private final JLabel lblNoteIn = new JLabel("Note 2: Null represents empty Response Body");
    private final JLabel lblNoteUpdating = new JLabel("Note 3: Only InScope items shown");
    private final JLabel lblColumnSettings = new JLabel("Usage Notes:");
    private final JLabel lblNewLabel_1 = new JLabel("Directions to use");

    /**
	 * Create the panel.
     */

    public LoggerOptionsPanel() {
        super();

        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[]{53, 94, 320, 250, 0, 0};
        gridBagLayout.rowHeights = new int[]{0, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0};
        gridBagLayout.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
        gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
        setLayout(gridBagLayout);

                    //LABEL : STATUS
                    JLabel lblLoggerStatus = new JLabel("Status:");
				lblLoggerStatus.setFont(new Font("Tahoma", Font.BOLD, 14));
				GridBagConstraints gbc_lblLoggerStatus = new GridBagConstraints();
				gbc_lblLoggerStatus.anchor = GridBagConstraints.SOUTHWEST;
				gbc_lblLoggerStatus.insets = new Insets(0, 0, 5, 5);
				gbc_lblLoggerStatus.gridx = 1;
				gbc_lblLoggerStatus.gridy = 1;
				add(lblLoggerStatus, gbc_lblLoggerStatus);

                    //TOGGLE BUTTON
                    tglbtnIsEnabled.setFont(new Font("Tahoma", Font.PLAIN, 13));
				GridBagConstraints gbc_tglbtnIsEnabled = new GridBagConstraints();
				gbc_tglbtnIsEnabled.anchor = GridBagConstraints.SOUTH;
				gbc_tglbtnIsEnabled.fill = GridBagConstraints.HORIZONTAL;
				gbc_tglbtnIsEnabled.insets = new Insets(0, 0, 5, 5);
				gbc_tglbtnIsEnabled.gridx = 2;
				gbc_tglbtnIsEnabled.gridy = 1;
				add(tglbtnIsEnabled, gbc_tglbtnIsEnabled);

                    //SAVE LOGS
                    btnSaveLogsButton.setToolTipText("This does not save requests and responses");
                    btnSaveLogsButton.setFont(new Font("Tahoma", Font.PLAIN, 13));
                    btnSaveLogsButton.addActionListener(new ActionListener() {
                            public void actionPerformed(ActionEvent arg0) {


                                            try {
                                            chooser = null;
                                            obtainFileName("Test");

                                            if(csvFile!=null){
                                                   ExcelExporter exp = new ExcelExporter();
                                                   exp.exportTable(log, csvFile);

                                            }

                                            }
                                            catch (Exception ex) {
                                            stderr.println(ex.getMessage());
                                            ex.printStackTrace();
                                            }




                            }
                    });

                    GridBagConstraints gbc_btnSaveLogsButton = new GridBagConstraints();
                    gbc_btnSaveLogsButton.anchor = GridBagConstraints.SOUTH;
                    gbc_btnSaveLogsButton.fill = GridBagConstraints.HORIZONTAL;
                    gbc_btnSaveLogsButton.insets = new Insets(0, 0, 5, 5);
                    gbc_btnSaveLogsButton.gridx = 3;
                    gbc_btnSaveLogsButton.gridy = 1;
                    add(btnSaveLogsButton, gbc_btnSaveLogsButton);

                    //CLEAR LOGS
                    JButton btnClearTheLog = new JButton("Clear the logs");
				btnClearTheLog.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {

						log.clear();
					}
				});
                                btnClearTheLog.setFont(new Font("Tahoma", Font.PLAIN, 13));
				GridBagConstraints gbc_btnClearTheLog = new GridBagConstraints();
				gbc_btnClearTheLog.anchor = GridBagConstraints.NORTH;
				gbc_btnClearTheLog.fill = GridBagConstraints.HORIZONTAL;
				gbc_btnClearTheLog.insets = new Insets(0, 0, 5, 5);
				gbc_btnClearTheLog.gridx = 3;
				gbc_btnClearTheLog.gridy = 13;
				add(btnClearTheLog, gbc_btnClearTheLog);

                //
                //Columns and Text Details
                //

                GridBagConstraints gbc_lblColumnSettings = new GridBagConstraints();
		gbc_lblColumnSettings.anchor = GridBagConstraints.WEST;
		gbc_lblColumnSettings.insets = new Insets(0, 0, 5, 5);
		gbc_lblColumnSettings.gridx = 1;
		gbc_lblColumnSettings.gridy = 14;
		lblColumnSettings.setFont(new Font("Tahoma", Font.BOLD, 14));
		add(lblColumnSettings, gbc_lblColumnSettings);

		GridBagConstraints gbc_lblNewLabel_1 = new GridBagConstraints();
		gbc_lblNewLabel_1.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblNewLabel_1.gridx = 2;
		gbc_lblNewLabel_1.gridy = 14;
		add(lblNewLabel_1, gbc_lblNewLabel_1);

		GridBagConstraints gbc_lblNewLabel = new GridBagConstraints();
		gbc_lblNewLabel.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel.gridwidth = 3;
		gbc_lblNewLabel.insets = new Insets(0, 0, 5, 5);
		gbc_lblNewLabel.gridx = 1;
		gbc_lblNewLabel.gridy = 15;
		add(lblNewLabel, gbc_lblNewLabel);

		GridBagConstraints gbc_lblNoteIn = new GridBagConstraints();
		gbc_lblNoteIn.anchor = GridBagConstraints.WEST;
		gbc_lblNoteIn.gridwidth = 3;
		gbc_lblNoteIn.insets = new Insets(0, 0, 5, 5);
		gbc_lblNoteIn.gridx = 1;
		gbc_lblNoteIn.gridy = 16;
		add(lblNoteIn, gbc_lblNoteIn);

		GridBagConstraints gbc_lblNoteUpdating = new GridBagConstraints();
		gbc_lblNoteUpdating.anchor = GridBagConstraints.WEST;
		gbc_lblNoteUpdating.gridwidth = 2;
		gbc_lblNoteUpdating.insets = new Insets(0, 0, 0, 5);
		gbc_lblNoteUpdating.gridx = 1;
		gbc_lblNoteUpdating.gridy = 17;
		add(lblNoteUpdating, gbc_lblNoteUpdating);

    }

}

// source: http://book.javanb.com/swing-hacks/swinghacks-chp-3-sect-6.html
//Exporting in CSV Format

	public class ExcelExporter {
            private static final String COMMA_DELIMITER = ",";
	    private static final String NEW_LINE_SEPARATOR = "\n";
            //CSV file header
	    private static final String FILE_HEADER = "Tool,URL,Content Type,Mime,Hash Status,Full Hash,Tag Hash";
            public ExcelExporter() { }
            public void exportTable(List<LogEntry> log, File file) throws IOException {
                FileWriter out=new FileWriter(file);
                //Write the CSV file header
                out.write(FILE_HEADER);

	        //Add a new line separator after the header
                out.append(NEW_LINE_SEPARATOR);

	        //Write  list to the CSV file
                for (LogEntry item : log) {

	                out.append(callbacks.getToolName(item.tool));
	                out.append(COMMA_DELIMITER);
	                out.append(String.valueOf(item.url));
	                out.append(COMMA_DELIMITER);
                        out.append(item.respContentType);
                        out.append(COMMA_DELIMITER);
                        out.append(item.responseContentType_burp);
                        out.append(COMMA_DELIMITER);
                        out.append(item.hashHeader);
                        out.append(COMMA_DELIMITER);
	                out.append(item.fHash);
	                out.append(COMMA_DELIMITER);
	                out.append(item.rHash);
	                out.append(NEW_LINE_SEPARATOR);
                }
                out.close();
            }

	}


// source: https://community.oracle.com/thread/1357495?start=0&tstart=0
//Obtaining Filename via System Browsing

        private void obtainFileName(String filename) {
                cancelOp = false;
		csvFile = null;
		FileNameExtensionFilter filter = new FileNameExtensionFilter("Excel Format (CSV)", "csv");
		if(chooser == null) {
			chooser = new JFileChooser();
			chooser.setDialogTitle("Saving Database");
			chooser.setFileFilter(filter);
			chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
			chooser.setSelectedFile( new File(filename+".csv") );
			chooser.setAcceptAllFileFilterUsed(false);
		}

		int val = chooser.showSaveDialog((Component)null);

		if(val == JFileChooser.APPROVE_OPTION) {
			csvFile = chooser.getSelectedFile();
			boolean fixed = fixExtension(csvFile, "csv");

			if(!fixed && !cancelOp) {
				JOptionPane.showMessageDialog(null,"File Name Specified Not Supported",
						"File Name Error", JOptionPane.ERROR_MESSAGE);
				obtainFileName(filename);
				return;
			}

		}
		if (cancelOp){
			csvFile = null;
		}
	}

        private boolean fixExtension(File file, String prefExt) {
		String fileName = file.getName();
		String dir = file.getParentFile().getAbsolutePath();

		String ext = null;

		try {
			ext = fileName.substring( fileName.lastIndexOf("."), fileName.length() );
			stdout.println("Original File Extension: " + ext);
		} catch(StringIndexOutOfBoundsException e) {
			ext = null;
		}

		if(ext != null && !ext.equalsIgnoreCase("."+prefExt)) {
			return false;
		}

		String csvName = null;

		if(ext == null || ext.length() == 0) {
			csvName = fileName + "." + prefExt;
		} else {
			csvName = fileName.substring(0, fileName.lastIndexOf(".") + 1) + prefExt;
		}

		stdout.println("Corrected File Name: " + csvName);

		File csvCert = new File(dir, csvName);

		if(csvCert.exists()) {
			int val = JOptionPane.showConfirmDialog(null, "Replace Existing File?", "File Exists",
					JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);

			if(val == JOptionPane.NO_OPTION) {
				obtainFileName(file.getName());
				cancelOp = true;
				return false;
			} else if(val == JOptionPane.CANCEL_OPTION) {
				cancelOp = true;
				return false;
			}
		}

		if(!file.renameTo(csvCert)) {
			file = new File(dir, csvName);
			try {
				file.createNewFile();
			} catch(IOException ioe) {}
		}

		stdout.println("Exporting as: " + file.getAbsolutePath() );

		return true;
	}

        // To Browse Desktop to Save File

        public static void openWebpage(URI uri) {
		Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
		if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
			try {
				desktop.browse(uri);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}


        //To Browse Lucideus.com

        private static void openWebpage(String url) {
		try {
			openWebpage((new URL(url)).toURI());
		} catch (URISyntaxException e) {
			e.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
	}

// Top Tabs- AboutUs  UI & functionality Class

        public class AboutPanel extends JPanel {

            public AboutPanel(){
                GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{0, 86, 80, 248, 0};
		gridBagLayout.rowHeights = new int[]{0, 38, 0, 0, 0, 43, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);


                //ClassLoader cldr = this.getClass().getClassLoader();
                //java.net.URL imageURLMain   = BurpExtender.class.getResource("resources/Lucideus.png");

		ImageIcon imageIconMain = new ImageIcon("resources/index.jpg");
		JLabel lblMain = new JLabel("Main");
                lblMain.setIcon(imageIconMain);
		// lblMain = new JLabel(imageIconMain);

		GridBagConstraints gbc_lblMain = new GridBagConstraints();
		gbc_lblMain.gridheight = 8;
		gbc_lblMain.insets = new Insets(0, 0, 0, 5);
		gbc_lblMain.gridx = 1;
		gbc_lblMain.gridy = 1;
		add(lblMain, gbc_lblMain);
                lblMain.setVisible(true);


                JLabel lblName = new JLabel("Name");
		GridBagConstraints gbc_lblName = new GridBagConstraints();
		gbc_lblName.anchor = GridBagConstraints.SOUTHWEST;
		gbc_lblName.insets = new Insets(0, 0, 5, 5);
		gbc_lblName.gridx = 2;
		gbc_lblName.gridy = 1;
		add(lblName, gbc_lblName);

                JLabel lblDynamicname = new JLabel("Burp Suite Response Encoder");
		GridBagConstraints gbc_lblDynamicname = new GridBagConstraints();
		gbc_lblDynamicname.anchor = GridBagConstraints.SOUTHWEST;
		gbc_lblDynamicname.insets = new Insets(0, 0, 5, 0);
		gbc_lblDynamicname.gridx = 3;
		gbc_lblDynamicname.gridy = 1;
		add(lblDynamicname, gbc_lblDynamicname);

                JLabel lblComapny = new JLabel("Institute");
		GridBagConstraints gbc_lblComapny = new GridBagConstraints();
		gbc_lblComapny.insets = new Insets(0, 0, 5, 5);
		gbc_lblComapny.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblComapny.gridx = 2;
		gbc_lblComapny.gridy = 2;
		add(lblComapny, gbc_lblComapny);

                JLabel lblDynamiccompany = new JLabel("Intitute of Enginnering & Management");
		GridBagConstraints gbc_lblDynamiccompany = new GridBagConstraints();
		gbc_lblDynamiccompany.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblDynamiccompany.insets = new Insets(0, 0, 5, 0);
		gbc_lblDynamiccompany.gridx = 3;
		gbc_lblDynamiccompany.gridy = 2;
		add(lblDynamiccompany, gbc_lblDynamiccompany);

                JLabel lblVersion = new JLabel("Version");
		GridBagConstraints gbc_lblVersion = new GridBagConstraints();
		gbc_lblVersion.insets = new Insets(0, 0, 5, 5);
		gbc_lblVersion.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblVersion.gridx = 2;
		gbc_lblVersion.gridy = 3;
		add(lblVersion, gbc_lblVersion);

		JLabel lblDynamicversion = new JLabel("1.0");
		GridBagConstraints gbc_lblDynamicversion = new GridBagConstraints();
		gbc_lblDynamicversion.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblDynamicversion.insets = new Insets(0, 0, 5, 0);
		gbc_lblDynamicversion.gridx = 3;
		gbc_lblDynamicversion.gridy = 3;
		add(lblDynamicversion, gbc_lblDynamicversion);

                JLabel lblAuthor = new JLabel("Author");
		GridBagConstraints gbc_lblAuthor = new GridBagConstraints();
		gbc_lblAuthor.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblAuthor.insets = new Insets(0, 0, 5, 5);
		gbc_lblAuthor.gridx = 2;
		gbc_lblAuthor.gridy = 4;
		add(lblAuthor, gbc_lblAuthor);

                JLabel lblDynamicauthor = new JLabel("Amit Agarwal");
		GridBagConstraints gbc_lblDynamicauthor = new GridBagConstraints();
		gbc_lblDynamicauthor.insets = new Insets(0, 0, 5, 0);
		gbc_lblDynamicauthor.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblDynamicauthor.gridx = 3;
		gbc_lblDynamicauthor.gridy = 4;
		add(lblDynamicauthor, gbc_lblDynamicauthor);



                JLabel lblAboutus = new JLabel("About Us");
		GridBagConstraints gbc_lblAboutus = new GridBagConstraints();
		gbc_lblAboutus.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblAboutus.insets = new Insets(0, 0, 5, 5);
		gbc_lblAboutus.gridx = 2;
		gbc_lblAboutus.gridy = 5;
		add(lblAboutus, gbc_lblAboutus);

                //JLabel lblDynamicaboutus = new JLabel("We are complete cyber-space security providers."+"We are a select group of cyber security analysts who delivers easy-to-use web security products and services, both generic and customized to keep your web-resources protected. ");
                  JLabel lblDynamicaboutus = new JLabel("");
		GridBagConstraints gbc_lblDynamicaboutus = new GridBagConstraints();
		gbc_lblDynamicaboutus.insets = new Insets(0, 0, 5, 0);
		gbc_lblDynamicaboutus.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblDynamicaboutus.gridx = 3;
		gbc_lblDynamicaboutus.gridy = 5;
		add(lblDynamicaboutus, gbc_lblDynamicaboutus);

                 JLabel label = new JLabel("          ");
		GridBagConstraints gbc_label = new GridBagConstraints();
		gbc_label.insets = new Insets(0, 0, 5, 5);
		gbc_label.gridx = 2;
		gbc_label.gridy = 6;
		add(label, gbc_label);

                JButton btnOpenLucideus = new JButton("Visit  homepage");
		btnOpenLucideus.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				openWebpage("http://iem.edu.in/");
			}
		});
		GridBagConstraints gbc_btnOpenLucideus = new GridBagConstraints();
		gbc_btnOpenLucideus.insets = new Insets(0, 0, 5, 0);
		gbc_btnOpenLucideus.gridwidth = 2;
		gbc_btnOpenLucideus.anchor = GridBagConstraints.NORTHWEST;
		gbc_btnOpenLucideus.gridx = 2;
		gbc_btnOpenLucideus.gridy = 6;
		add(btnOpenLucideus, gbc_btnOpenLucideus);
            }
        }















}
