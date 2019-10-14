package burp;

import java.net.URL;

// class implementing IScanIssue to hold our custom scan issue details
class POISlingerScanIssue implements IScanIssue {
    // Globals
    private static final int EXTENSION_GENERATED_ISSUE_TYPE = 0x08000000;
    private static final String ISSUE_NAME = "PHP Object Injection Vulnerability";
    private static final String SEVERITY = "High";
    private static final String CONFIDENCE = "Certain";
    private static final String ISSUE_BACKGROUND = "<p>PHP Object Injection is a vulnerability where a vulnerable application unserializes " +
                "user-controllable data. Doing so can be used to instantiate arbitrary objects that depending " +
                "on their implementations can be used for various attacks. These attacks include arbitrary code " +
                "execution, SQL injection, arbitrary file access, and others.</p>" +
                "<p>See also: <a href=\"https://www.owasp.org/index.php/PHP_Object_Injection\">https://www.owasp.org/index.php/PHP_Object_Injection</a></p>";
    private static final String REMEDIATION_BACKGROUND = "<p>Avoid unserializing untrusted (user) data. " +
                "Use <strong><code>json_decode()</code>/<code>json_decode</code></strong> or set the " +
                "<strong><code>unserialize()</code></strong> options to <strong>allowed_classes=false</strong> (PHP >= 7.0).</p>";
    private final URL url;
    private final String detail;
    private final IHttpService httpService;
    private final IHttpRequestResponse[] httpMessages;

    POISlingerScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String gen_with, String payload, IBurpCollaboratorInteraction collaboratorInteraction) {
        this.url = url;
        this.httpService = httpService;
        this.httpMessages = httpMessages;
        this.detail = buildIssueDetail(name, gen_with, payload, collaboratorInteraction);
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return ISSUE_NAME;
    }

    @Override
    public int getIssueType() {
        return EXTENSION_GENERATED_ISSUE_TYPE;
    }

    @Override
    public String getSeverity() {
        return SEVERITY;
    }

    @Override
    public String getConfidence() {
        return CONFIDENCE;
    }

    @Override
    public String getIssueBackground() {
        return ISSUE_BACKGROUND;
    }

    @Override
    public String getRemediationBackground() {
        return REMEDIATION_BACKGROUND;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    private String buildIssueDetail(String name, String gen_with, String payload, IBurpCollaboratorInteraction event) {
        return "<p>The Web Application is vulnerable to PHP Object Injection.</p><br />" +
               "<p>It appears that the Web Application is running: "+ name +" </p>" +
               "<p>The following serialized PHP Object was sent to the application: <br /><strong>" + payload + "</strong><br /> </p><br />" +
               "<p>To further check the exploitability of this issue download the tool <a href=\"https://github.com/ambionics/phpggc\">PHPGCC</a> " +
               "and generate your payload with the following command: <strong>"+ gen_with +"</strong></p>" +
               "<p>The Web Application Web Server made " + eventDescription(event) +
               "<strong>" + event.getProperty("interaction_id") + ".burpcollaborator.net</strong></p><br />" +
               "<p>The <strong>" + interactionType(event.getProperty("type")) +
               "</strong> was received from the IP address <strong>" + event.getProperty("client_ip") +
               "</strong> at " + event.getProperty("time_stamp") + ".</p>";
    }

    private String interactionType(String type) {
        if (type.equalsIgnoreCase("http")) {
            return "HTTP connection";
        } else if (type.equalsIgnoreCase("dns")) {
            return "DNS lookup";
        } else {
            return "Interaction";
        }
    }

    private String eventDescription(IBurpCollaboratorInteraction event) {
        if (event.getProperty("type").equalsIgnoreCase("http")) {
            return "an <strong>HTTP</strong> request to the the Collaborator Callback Host: ";
        } else if (event.getProperty("type").equalsIgnoreCase("dns")) {
            return "a <strong>DNS</strong> lookup of type <strong>" + event.getProperty("query_type") + "</strong> to the Collaborator Callback Host: ";
        } else {
            return "an unknown interaction with the Collaborator Callback Host: ";
        }
    }
}
