from burp import IBurpExtender, IProxyListener, IHttpListener, IResponseInfo, ITab
from java.io import PrintWriter
from datetime import datetime
from javax import swing
from java.awt import BorderLayout

class BurpExtender(IBurpExtender, IProxyListener, IHttpListener, IResponseInfo, ITab):
    filePathBase = "/tmp"
    imageMimeTypes = ["JPEG", "PNG", "GIF"]

    # Used to store the config in Burp
    FILELOCATION = "location"
    MIMETYPES = "mimetypes"

    def saveData(self, e):
        # self._stdout.println (e.getSource().getText() + " was clicked")
        # self._stdout.println (self.saveLocationInput.getText())

        location = self.saveLocationInput.getText()

        # force a / on the end if not provided

        if (location[len(location)-1] != "/"):
            location = location + "/"
        self._stdout.println("Saving files to: " + location)

        self.filePathBase = location

        # Save the location
        self._callbacks.saveExtensionSetting (self.FILELOCATION, location)

    def initUI(self):
        self.tab = swing.JPanel()

        # Create the text area at the top of the tab
        textPanel = swing.JPanel()
        boxVertical = swing.Box.createVerticalBox()

        # Create the label for save location
        boxHorizontal = swing.Box.createHorizontalBox()
        textLabel = swing.JLabel("Save location: ")
        boxHorizontal.add(textLabel)

        # Create save location input
        self.saveLocationInput = swing.JTextField(100)
        boxHorizontal.add(self.saveLocationInput)
        boxVertical.add(boxHorizontal)

        # Create the label for the mime type
        boxHorizontal = swing.Box.createHorizontalBox()
        textLabel = swing.JLabel("MIME Types - comma separated: ")
        boxHorizontal.add(textLabel)

        # Create MIME type input
        self.mimeTypeInput = swing.JTextField(100)
        boxHorizontal.add(self.mimeTypeInput)
        boxVertical.add(boxHorizontal)

        # Save button
        boxHorizontal = swing.Box.createHorizontalBox()
        saveButton = swing.JButton("Save")
        saveButton.addActionListener(self.saveData)
        boxHorizontal.add(saveButton)

        boxVertical.add(boxHorizontal)

        # Add the text label and area to the text panel
        textPanel.add(boxVertical)

        # Add the text panel to the top of the main tab
        self.tab.add(textPanel, BorderLayout.NORTH) 

    def getTabCaption(self):
        return "Save Browsing Files"

    def getUiComponent(self):
        return self.tab

    def registerExtenderCallbacks( self, callbacks):
        extName = "Save Files"
        # keep a reference to our callbacks object and add helpers
        self._callbacks = callbacks
        self._helpers = self._callbacks.getHelpers()

        # set our extension name
        self._callbacks.setExtensionName(extName)

        # obtain our output streams
        self._stdout = PrintWriter(self._callbacks.getStdout(), True)
        self._stderr = PrintWriter(self._callbacks.getStderr(), True)

        # register ourselves as a Proxy listener
        self._callbacks.registerHttpListener(self)

        # print extension name
        self._stdout.println(extName)

        # Build list to compare against
        # Need to load this from storage as well
        self.imageMimeTypes = ["JPEG", "PNG", "GIF"]

        # Load the location from Burp storage
        self.filePathBase = self._callbacks.loadExtensionSetting(self.FILELOCATION)

        # Default to /tmp
        # May be better to check the OS to make this decision, but sticking
        # with this for now.
        if self.filePathBase is None:
            self.filePathBase = "/tmp/"

        self._stdout.println("Saving files to: " + self.filePathBase)

        self.initUI()
        self._callbacks.addSuiteTab(self)
        self.saveLocationInput.setText(self.filePathBase)

        return

    def processHttpMessage(self, toolflag, messageIsRequest, messageInfo):
        if (messageIsRequest == False):
            response = messageInfo.getResponse()
            responseInfo = self._helpers.analyzeResponse(response)

            request = messageInfo.getRequest()
            self._stdout.println(type(request))

            #for header in request:
          #      self._stdout.println(header)

            #for header in request.getHeaders():
            #    self._stdout.println(header)
#
 #           self._stdout.println(request)

            # Get MIME types
            inferredMime = responseInfo.getInferredMimeType()
            statedMime = responseInfo.getStatedMimeType()

            # Get response body
            bodyOffset = responseInfo.getBodyOffset()
            # self._stdout.println(bodyOffset)
            # Build image request body
            imgData = response[bodyOffset:]
            self._stdout.println(imgData)

            self._stdout.println("Stated MIME Type: " + statedMime)
            self._stdout.println("Inferred MIME Type: " + inferredMime)

            # If multiple files are loaded in the same second they will all get
            # the same name and be overwritten so need to add something extra to 
            # the name to ensure it is unique.

            if (statedMime in self.imageMimeTypes) or (inferredMime in self.imageMimeTypes):
                # Build file path
                fileName = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
                fileExtension = "." + inferredMime.lower()
                fullFilename = self.filePathBase + fileName + fileExtension
                self._stdout.println("Writing to file: " + fullFilename)
                # Write to file
                f = open(fullFilename, "wb")
                f.write(imgData)
                f.close()
        return
