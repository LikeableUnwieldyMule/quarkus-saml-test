package com.example;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.eclipse.microprofile.config.inject.ConfigProperty;


@Path("/saml/metadata")
public class SamlMetadataEndpoint {
    @ConfigProperty(name = "saml.spEntityId")
    String entityId;
    @ConfigProperty(name = "saml.acs.url")
    String acsUrl;
    @ConfigProperty(name = "saml.slo.url")
    String sloUrl; // Optional
    @ConfigProperty(name = "saml.cert")
    String cert;


    @GET
    @Produces(MediaType.APPLICATION_XML)
    public Response getMetadata() {
        String metadataXml = generateMetadata();
        return Response.ok(metadataXml).build();
    }

    private String generateMetadata() {
        return String.format("""
            <EntityDescriptor entityID="%s" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
                <SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="1"/>
                    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
                    <KeyDescriptor use="signing">
                        <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                            <X509Data>
                                <X509Certificate>%s</X509Certificate>
                            </X509Data>
                        </KeyInfo>
                    </KeyDescriptor>
                </SPSSODescriptor>
            </EntityDescriptor>
            """, entityId, acsUrl, sloUrl, cert);
    }
}
