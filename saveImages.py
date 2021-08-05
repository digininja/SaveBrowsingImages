from burp import IBurpExtender, IProxyListener, IHttpListener, IResponseInfo, ITab
from java.io import PrintWriter
from datetime import datetime
from javax import swing
from java.awt import BorderLayout

class BurpExtender(IBurpExtender, IProxyListener, IHttpListener, IResponseInfo, ITab):
    filePathBase = "/home/robin/wolfrun"

    def saveData(self, e):
        print e.getSource().getText() + " was clicked"
        self._stdout.println(self.saveLocationInput.getText())

        location = self.saveLocationInput.getText()


        if (location[len(location)-1] != "/"):
            location = location + "/"
        self._stdout.println("Saving files to: " + location)

        self.filePathBase = location

    def initUI(self):
        self.tab = swing.JPanel()

        # Create the text area at the top of the tab
        textPanel = swing.JPanel()

        # Create the label for the text area
        boxVertical = swing.Box.createVerticalBox()
        boxHorizontal = swing.Box.createHorizontalBox()
        textLabel = swing.JLabel("Save location")
        boxHorizontal.add(textLabel)
        boxVertical.add(boxHorizontal)

        # Create the text area itself
        boxHorizontal = swing.Box.createHorizontalBox()
        self.saveLocationInput = swing.JTextField(100)
        boxHorizontal.add(self.saveLocationInput)

        # Save button
        saveButton = swing.JButton("Save")
        saveButton.addActionListener(self.saveData)
        boxHorizontal.add(saveButton)

        boxVertical.add(boxHorizontal)

        # Add the text label and area to the text panel
        textPanel.add(boxVertical)

        # Add the text panel to the top of the main tab
        self.tab.add(textPanel, BorderLayout.NORTH) 

    def getTabCaption(self):
        return "Save Browsing Images"

    def getUiComponent(self):
        return self.tab

    def registerExtenderCallbacks( self, callbacks):
        extName = "Save Images"
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

        self.initUI()
        self._callbacks.addSuiteTab(self)

        # print extension name
        self._stdout.println(extName)

        if (self.filePathBase[len(self.filePathBase)-1] != "/"):
            self.filePathBase = self.filePathBase + "/"
        self._stdout.println("Saving files to: " + self.filePathBase)

        return

    def processHttpMessage(self, toolflag, messageIsRequest, messageInfo):
        if (messageIsRequest == False):
            response = messageInfo.getResponse()
            responseInfo = self._helpers.analyzeResponse(response)

            # Find out if image
            inferredMime = responseInfo.getInferredMimeType()
            statedMime = responseInfo.getStatedMimeType()
            # Build list to compare against
            imageMimeTypes = ["JPEG", "PNG", "GIF"]

            # Get response body
            bodyOffset = responseInfo.getBodyOffset()
            # self._stdout.println(bodyOffset)
            # Build image request body
            imgData = response[bodyOffset:]
            self._stdout.println(imgData)

            self._stdout.println("Stated MIME Type: " + statedMime)
            self._stdout.println("Inferred MIME Type: " + inferredMime)

            if (statedMime in imageMimeTypes) or (inferredMime in imageMimeTypes):
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
