package eu.merloteducation.didservice.models.did;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@JsonPropertyOrder({"kty", "n", "e", "alg", "x5u"})
public class PublicJwk {
    private String kty;
    private String n;
    private String e;
    private String alg;
    private String x5u;
}
