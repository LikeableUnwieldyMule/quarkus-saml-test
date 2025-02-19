import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@Path("/")
public class IndexResource {

    @Inject
    Template index;

    @ConfigProperty(name = "saml.idpUrl")
    String idpUrl;

    @GET
    @Produces(MediaType.TEXT_HTML)
    public String get() {
        return index.data("samlIdpUrl", idpUrl).render();
    }
}