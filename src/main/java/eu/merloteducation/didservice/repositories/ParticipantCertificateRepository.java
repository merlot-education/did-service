package eu.merloteducation.didservice.repositories;

import eu.merloteducation.didservice.models.entities.ParticipantCertificate;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ParticipantCertificateRepository extends JpaRepository<ParticipantCertificate, String> {
    ParticipantCertificate findByDid(String did);
}
