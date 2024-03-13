package eu.merloteducation.didservice.repositories;

import eu.merloteducation.didservice.models.entities.ParticipantCertificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ParticipantCertificateRepository extends JpaRepository<ParticipantCertificate, String> {

    @Query("SELECT cert.certificate FROM ParticipantCertificate cert WHERE cert.did = :certId")
    String findByDid(@Param("certId") String certId);
}
