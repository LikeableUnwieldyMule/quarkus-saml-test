package com.example;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/saml/metadata")
public class SamlMetadataEndpoint {
    @GET
    @Produces(MediaType.APPLICATION_XML)
    public Response getMetadata() {
        String metadataXml = generateMetadata();
        return Response.ok(metadataXml).build();
    }

    private String generateMetadata() {
        @ConfigProperty(name = "saml.spEntityId")
        String entityId;
        @ConfigProperty(name = "saml.acs.url")
        String acsUrl;
        @ConfigProperty(name = "saml.slo.url")
        String sloUrl; // Optional
        String cert = "MIIDYzCCAkugAwIBAgIUd1m1kdOZGZMgwg9qQQ5FPGSg894wDQYJKoZIhvcNAQELBQAwQTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkhJMREwDwYDVQQHDAhIb25vbHVsdTESMBAGA1UECgwJTXVsZSBDb3JwMB4XDTI1MDIxMzIzMzY0NFoXDTM1MDIxMTIzMzY0NFowQTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkhJMREwDwYDVQQHDAhIb25vbHVsdTESMBAGA1UECgwJTXVsZSBDb3JwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0s8juMn+nW8wLnpGJ1sKgYXDQAygwMCPieMVISPgVX29NAr6t+CUFaaVgnduV9CpGPTWvqiayuXQvfxDgP858AU9cH92UBgDVcOv2cuGA2fYCIaTv9aN83CuW0Bj3l3fBpJ0PYXwmetHs4qSPB615mGcL6Jg27bthRiqOPWEBsuNBHQP19+9B8OL0jAX07yg3df+MxIwRrTfiBsAsdF7nj8d328POvCGjUQc+PML6kjrCBSjCpgHIic8kLJs0PgbgMlk6zx3PWnInTZB2qdQNpCgTVjiedu3lhiAWxJ2exvIvL5l8TAx/+spv0/kHKxQ64le1jbwFt0Qn7RvjX2QSwIDAQABo1MwUTAdBgNVHQ4EFgQUVtr8La2y3iOAwdtFu/mGVno0GDIwHwYDVR0jBBgwFoAUVtr8La2y3iOAwdtFu/mGVno0GDIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAsrXf0HAZYnQl+bbUjK/37fJfyQerz8o8AKxPxzg0TWSDXsm3XrZ67EvCPAQ6o6Id078cUqxGLBxx8gxJtcfTRWsrScAd+HGYBDDZqomUIT8wuAY/vtUTKOMl3yjU+/WtBA5o4DJcFIVzTB26yf8lvd8DuwnVjvd0ok04jEKJSmNmn4fX136cQ9Fmta5ojg8q5e/pPZtLQhZFVZaPo/BbFYIrtR5RNg2H4LOXXaFdzHwOi+zWPgXom5s1HCoSS1oYMq0zh6vp7jer7hKK1iWmiHI4Rt6XMtM9MD4JYy81W7QQKVOQBUdg21LVe+pF7Y34YY58kUumu7WyPVWnfHEMXg==";
    
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
