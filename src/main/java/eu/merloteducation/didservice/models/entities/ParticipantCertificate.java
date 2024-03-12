package eu.merloteducation.didservice.models.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class ParticipantCertificate {
    @Id
    private String did;

    private String certificate;
}
