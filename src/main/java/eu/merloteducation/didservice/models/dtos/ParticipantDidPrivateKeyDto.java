package eu.merloteducation.didservice.models.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ParticipantDidPrivateKeyDto {
    private String did;

    private String privateKey;
}
