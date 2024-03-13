package eu.merloteducation.didservice.models.dtos;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ParticipantDidPrivateKeyCreateRequest {
    @NotNull
    private String issuer;

    @NotNull
    private String subject;
}
