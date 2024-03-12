package eu.merloteducation.didservice.service;

import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyDto;
import org.springframework.stereotype.Service;

@Service
public class DidService {
    public String getCertificate(String participantDid) {
        return "certificate for " + participantDid;
    }

    public String getDidDocument() {
        return "DID document";
    }

    public ParticipantDidPrivateKeyDto generateDidAndPrivateKey(String seed) {
        return new ParticipantDidPrivateKeyDto();
    }
}
