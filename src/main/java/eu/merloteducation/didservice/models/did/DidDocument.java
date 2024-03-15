package eu.merloteducation.didservice.models.did;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@JsonPropertyOrder({"@context", "id", "verificationMethod"})
public class DidDocument {
    @JsonProperty("@context")
    private List<String> context;
    private String id;
    private List<VerificationMethod> verificationMethod;
}
