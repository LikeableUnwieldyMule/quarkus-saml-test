package com.example.saml;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/saml")
public class SamlResource {

    private static final Logger LOG = Logger.getLogger(SamlResource.class);

    // Inject values from application.properties
    @ConfigProperty(name = "saml.entraIdpUrl")
    String entraIdpUrl;

    @ConfigProperty(name = "saml.spEntityId")
    String spEntityId;

    private final SamlService samlService;

    public SamlResource(SamlService samlService) {
        this.samlService = samlService;
    }

    @POST
    @Path("/acs")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)  // Serve HTML response
    public Response handleSamlResponse(@FormParam("SAMLResponse") String samlResponse) {
        if (samlResponse == null || samlResponse.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("<html><body><h3>SAMLResponse parameter is missing or empty</h3></body></html>")
                    .build();
        }

        try {
            // Decode Base64
            byte[] decodedBytes = Base64.getDecoder().decode(samlResponse);
            String decodedSaml = new String(decodedBytes, StandardCharsets.UTF_8);

            // Process the SAML response and extract key fields
            SamlResponseData responseData = samlService.extractSamlData(decodedSaml);

            // Check for the Department attribute
            List<SamlAttribute> departmentAttributes = responseData.getAttributes().stream()
                .filter(attr -> "Department".equals(attr.getName()) && "Mule Mongery".equals(attr.getValue()))
                .collect(Collectors.toList());
            boolean isMuleMongery = departmentAttributes.size() > 0;

            // Build HTML output
            String htmlResponse = "<html><body>";
            htmlResponse += "<h2>SAML Response Fields</h2>";
            htmlResponse += "<ul>";
            htmlResponse += "<li>Issuer: " + responseData.getIssuer() + "</li>";
            htmlResponse += "<li>Subject: " + responseData.getSubject() + "</li>";
            htmlResponse += "<li>Session Index: " + responseData.getSessionIndex() + "</li>";
            htmlResponse += "<li>Authn Statement Time: " + responseData.getAuthnTime() + "</li>";
            htmlResponse += "</ul>";

            if (isMuleMongery) {
                htmlResponse += "<div><h1>Mule Monger Portal</h1><img src=\"https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSwgTWCMu9EU1bh5UdNyW2doP7I-_QzlS_GPQ&s\" alt=\"Image\" width=\"100\" height=\"100\"></div>";
            }

            htmlResponse += "<h2>Full Decoded SAML Response</h2>";
            htmlResponse += "<pre>" + escapeHtml(decodedSaml) + "</pre>";
            htmlResponse += "</body></html>";

            return Response.ok(htmlResponse).build();
        } catch (Exception e) {
            LOG.error("Error processing SAML response", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("<html><body><h3>Internal error occurred while processing the SAML response</h3></body></html>")
                    .build();
        }
    }

    // Utility method to escape HTML
    private String escapeHtml(String input) {
        return input.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    .replace("\"", "&quot;").replace("'", "&#39;");
    }

    @POST
    @Path("/initiateSso")
    @Consumes("application/x-www-form-urlencoded")
    public Response initiateSso() {
        try {
            // Generate the SAML request (this function should create the SAML AuthnRequest XML)
            String samlRequest = samlService.createSamlRequest(spEntityId);

            // Base64 encode the SAML request
            String encodedSamlRequest = samlService.base64Encode(samlRequest);

            // Generate the POST form with the SAML request
            // Now, the encoded SAML request is properly inserted into the form
            String htmlForm = samlService.createHtmlForm(entraIdpUrl, encodedSamlRequest);

            // Return the form as an HTML response
            return Response.ok(htmlForm).build();
        } catch (Exception e) {
            LOG.error("Error initiating SSO", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Error initiating SSO").build();
        }
    }
}