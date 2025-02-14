package com.example.saml;

public class SamlResponseData {
    private String issuer;
    private String subject;
    private String sessionIndex;
    private String authnTime;

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