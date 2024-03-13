package eu.merloteducation.didservice.models.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class ParticipantCertificate {
    @Id
    @GeneratedValue
    private UUID id;

    @Column(unique = true)
    private String did;

    @Column(length = 2048)
    private String certificate;
}
