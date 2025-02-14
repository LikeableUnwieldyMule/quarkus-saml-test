package com.example;

import java.io.IOException;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("/hello")
public class GreetingResource {

    @GET
    @Produces(MediaType.TEXT_HTML)
    public String index() throws IOException {
        return new String(getClass().getResourceAsStream("/META-INF/resources/index.html").readAllBytes());
    }
}
