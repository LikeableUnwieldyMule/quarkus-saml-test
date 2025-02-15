package com.example.saml;

import java.util.List;

public class SamlResponseData {
    private String issuer;
    private String subject;
    private String sessionIndex;
    private String authnTime;
    private List<SamlAttribute> attributes;

    public List<SamlAttribute> getAttributes() {
        return attributes;
    }

    public void setAttributes(List<SamlAttribute> attributes) {
        this.attributes = attributes;
    }

    public void addAttribute(SamlAttribute attribute) {
        if (this.attributes == null) {
            this.attributes = new java.util.ArrayList<>();
        }
        this.attributes.add(attribute);
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getSessionIndex() {
        return sessionIndex;
    }

    public void setSessionIndex(String sessionIndex) {
        this.sessionIndex = sessionIndex;
    }

    public String getAuthnTime() {
        return authnTime;
    }

    public void setAuthnTime(String authnTime) {
        this.authnTime = authnTime;
    }


}