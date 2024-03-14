package eu.merloteducation.didservice.models.did;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@JsonPropertyOrder({"@context", "id", "type", "controller", "publicKeyJwk"})
public class VerificationMethod {
    @JsonProperty("@context")
    private List<String> context;
    private String id;
    private String type;
    private String controller;
    private PublicJwk publicKeyJwk;
}
