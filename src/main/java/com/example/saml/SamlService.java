package com.example.saml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.BadRequestException;

@ApplicationScoped
public class SamlService {

    private static final Logger LOG = Logger.getLogger(SamlService.class);

    // Inject configuration properties
    @ConfigProperty(name = "saml.sp.entityId")
    String entityId;
    
    @ConfigProperty(name = "saml.acs.url")
    String acsUrl;

    @ConfigProperty(name = "saml.idp.publicKey")
    String publicKeyPem;

    /**
     * Process the SAML response received from the IdP.
     * 
     * @param samlResponse The base64-encoded SAML response.
     * @return A string containing the processed SAML assertion.
     */
    public String processSamlResponse(String samlResponse) {
        try {
            // Step 1: Decode and inflate the SAML response
            byte[] decodedResponse = decodeAndInflate(samlResponse);
            
            // Step 2: Parse the decoded response XML
            String assertion = parseSamlAssertion(decodedResponse);

            // Step 3: Validate the SAML signature using the Entra public key
            if (!validateSignature(decodedResponse, assertion)) {
                throw new BadRequestException("Invalid SAML signature.");
            }

            return assertion;

        } catch (Exception e) {
            LOG.error("Error processing SAML response", e);
            throw new BadRequestException("Invalid SAML response.");
        }
    }

    /**
     * Decode the base64-encoded and compressed SAML response.
     * 
     * @param samlResponse The base64-encoded SAML response.
     * @return The inflated byte array.
     */
    private byte[] decodeAndInflate(String samlResponse) throws IOException, DataFormatException {
        // Decode base64
        byte[] decodedBytes = Base64.getDecoder().decode(samlResponse);

        // Inflate (decompress) the response
        Inflater inflater = new Inflater();
        inflater.setInput(decodedBytes);
        byte[] inflatedBytes = new byte[1024]; // Assuming the inflated response won't exceed this size
        int inflatedLength = inflater.inflate(inflatedBytes);
        inflater.end();

        byte[] result = new byte[inflatedLength];
        System.arraycopy(inflatedBytes, 0, result, 0, inflatedLength);
        return result;
    }

    /**
     * Parse the SAML assertion from the inflated byte array.
     * 
     * @param response The inflated SAML response.
     * @return The SAML assertion (usually XML format).
     * @throws Exception If parsing fails.
     */
    private String parseSamlAssertion(byte[] response) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(response);
        org.w3c.dom.Document doc = builder.parse(byteArrayInputStream);

        // Extract the SAML assertion from the document
        // (This will depend on your specific XML structure, so adjust the XPath as needed)
        String assertion = doc.getElementsByTagName("Assertion").item(0).getTextContent();
        return assertion;
    }

    /**
     * Validate the SAML signature using Entra's public key.
     * 
     * @param response The decoded and inflated SAML response.
     * @param assertion The SAML assertion string.
     * @return True if the signature is valid.
     * @throws Exception If signature validation fails.
     */
    private boolean validateSignature(byte[] response, String assertion) throws Exception {
        // Load the public key from the PEM string (provided via config)
        PublicKey publicKey = loadPublicKey(publicKeyPem);

        // Use the public key to verify the SAML signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);

        // Normally, you would extract the signature from the SAML response, 
        // but for simplicity, we'll assume it's the entire response (this may need modification).
        signature.update(response);
        
        // Validate signature
        return signature.verify(Base64.getDecoder().decode(assertion));  // Assuming the assertion itself contains the signature.
    }

    /**
     * Load a public key from a PEM-encoded string.
     * 
     * @param publicKeyPem The PEM-encoded public key.
     * @return The public key object.
     * @throws Exception If key loading fails.
     */
    private PublicKey loadPublicKey(String publicKeyPem) throws Exception {
        String publicKeyPEM = publicKeyPem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return certificateFactory.generateCertificate(new ByteArrayInputStream(encoded)).getPublicKey();
    }

    /**
     * Creates the SAML authentication request XML.
     * 
     * @param spEntityId The Service Provider's Entity ID.
     * @return The generated SAML authentication request XML.
     */
    public String createSamlRequest(String spEntityId) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.newDocument();

            // Build the SAML Authentication Request XML
            Element authnRequest = document.createElement("samlp:AuthnRequest");
            authnRequest.setAttribute("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            // xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            authnRequest.setAttribute("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            authnRequest.setAttribute("ID", "_" + System.currentTimeMillis());
            authnRequest.setAttribute("Version", "2.0");
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'");
            String issueInstant = formatter.format(Instant.now().atOffset(ZoneOffset.UTC));
            authnRequest.setAttribute("IssueInstant", issueInstant);
            authnRequest.setAttribute("Destination", "https://login.microsoftonline.com/5945593b-3e9f-4298-8fc8-f3dcab7839e5/saml2");
            authnRequest.setAttribute("AssertionConsumerServiceURL", "https://quarkus-saml-test-d9apgdavfvewhyhf.centralus-01.azurewebsites.net/saml/acs");

            Element issuer = document.createElement("saml:Issuer");
            issuer.appendChild(document.createTextNode(spEntityId));
            authnRequest.appendChild(issuer);

            // Add the request to the document
            document.appendChild(authnRequest);

            // Convert document to string (XML format)
            return documentToString(document);

        } catch (Exception e) {
            LOG.error("Error creating SAML request", e);
            throw new RuntimeException("Error creating SAML request", e);
        }
    }

    /**
     * Base64-encodes the given SAML request XML.
     * 
     * @param samlRequest The SAML request XML.
     * @return The base64-encoded SAML request.
     */
    public String base64Encode(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generates an HTML form that will POST the base64-encoded SAML request to the IdP.
     * 
     * @param idpUrl The IdP SSO URL.
     * @param encodedSamlRequest The base64-encoded SAML request.
     * @return The HTML form as a string.
     */
    public String createHtmlForm(String idpUrl, String encodedSamlRequest) {
        // Use String.format to inject the base64-encoded request into the form
        return String.format(
            "<html><body>" +
            "<form id='samlForm' method='POST' action='%s'>" +
            "<input type='hidden' name='SAMLRequest' value='%s' />" +
            "<input type='submit' value='Login with SSO' />" +
            "</form>" +
            "<script>document.getElementById('samlForm').submit();</script>" +
            "</body></html>",
            idpUrl, encodedSamlRequest
        );
    }

    /**
     * Converts the XML document to a string.
     * 
     * @param document The XML document to convert.
     * @return The XML as a string.
     */
    private String documentToString(Document document) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            javax.xml.transform.Transformer transformer = javax.xml.transform.TransformerFactory.newInstance().newTransformer();
            transformer.transform(new javax.xml.transform.dom.DOMSource(document), new javax.xml.transform.stream.StreamResult(baos));
        } catch (Exception e) {
            throw new IOException("Error converting document to string", e);
        }
        return baos.toString();
    }

    public SamlResponseData extractSamlData(String decodedSaml) throws Exception {
        SamlResponseData data = new SamlResponseData();

        // Parse the XML
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(decodedSaml.getBytes(StandardCharsets.UTF_8)));

        // Extract Issuer
        Node issuerNode = doc.getElementsByTagNameNS("*", "Issuer").item(0);
        if (issuerNode != null) {
            data.setIssuer(issuerNode.getTextContent());
        }

        // Extract Subject
        Node subjectNode = doc.getElementsByTagNameNS("*", "NameID").item(0);
        if (subjectNode != null) {
            data.setSubject(subjectNode.getTextContent());
        }

        // Extract Session Index
        Node sessionIndexNode = doc.getElementsByTagNameNS("*", "AuthnStatement").item(0);
        if (sessionIndexNode != null) {
            Element authnStatement = (Element) sessionIndexNode;
            data.setSessionIndex(authnStatement.getAttribute("SessionIndex"));
        }

        // Extract Authn Time
        if (sessionIndexNode != null) {
            Element authnStatement = (Element) sessionIndexNode;
            data.setAuthnTime(authnStatement.getAttribute("AuthnInstant"));
        }

        // Extract Attributes
        NodeList attributeNodes = doc.getElementsByTagNameNS("*", "Attribute");
        for (int i = 0; i < attributeNodes.getLength(); i++) {
            Element attributeNode = (Element) attributeNodes.item(i);
            String attributeName = attributeNode.getAttribute("Name");
            String attributeValue = attributeNode.getElementsByTagNameNS("*", "AttributeValue").item(0).getTextContent();
            SamlAttribute attribute = new SamlAttribute(attributeName, attributeValue);
            data.addAttribute(attribute);
        }

        return data;
    }
}