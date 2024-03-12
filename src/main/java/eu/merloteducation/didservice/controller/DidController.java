package eu.merloteducation.didservice.controller;

import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyDto;
import eu.merloteducation.didservice.service.DidService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/")
public class DidController {
    @Autowired
    private DidService didService;

    /**
     * POST endpoint for creating a did:web and a private key for a new MERLOT participant.
     *
     * @return dto containing the generated did:web and private key
     */
    @PostMapping("/generateDidAndPrivateKey")
    public ParticipantDidPrivateKeyDto generateDidAndPrivateKey(@RequestBody(required = false) String seed) {
        return didService.generateDidAndPrivateKey(seed);
    }

    /**
     * GET endpoint for retrieving the DID document containing all MERLOT-generated did:webs and associated certificates.
     *
     * @return DID document
     */
    @GetMapping("/didDocument")
    public String getDidDocument() {
        return didService.getDidDocument();
    }

    /**
     * GET endpoint for retrieving the certificate for a given participant DID.
     *
     * @return certificate of the participant
     */
    @GetMapping("/certificate/{participantDid}")
    public String getCertificate(@PathVariable(value = "participantDid") String participantDid) {
        return didService.getCertificate(participantDid);
    }
}
