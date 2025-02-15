package com.example.saml;

public class SamlAttribute {
    private String name;
    private String value;

    public SamlAttribute(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return "SamlAttribute{name='" + name + "', value='" + value + "'}";
    }
}