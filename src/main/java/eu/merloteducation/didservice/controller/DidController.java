package eu.merloteducation.didservice.controller;

import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyCreateRequest;
import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyDto;
import eu.merloteducation.didservice.service.DidService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@RestController
@RequestMapping("/")
public class DidController {
    @Autowired
    private DidService didService;

    /**
     * POST endpoint for generating a did:web, a key pair and a certificate. Returns the did:web, the verification
     * method and the associated private key.
     *
     * @param request with information needed for certificate generation
     * @return dto containing the generated did:web, the verification method and the associated private key
     */
    @PostMapping("/generateDidAndPrivateKey")
    public ParticipantDidPrivateKeyDto generateDidAndPrivateKey(
        @RequestBody ParticipantDidPrivateKeyCreateRequest request) {

        try {
            return didService.generateDidAndPrivateKey(request);
        } catch (Exception e) {
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR,
                "Failed to generate did:web / key pair / certificate");
        }
    }

    /**
     * GET endpoint for retrieving the DID document for given participant.
     *
     * @param id id for retrieving the DID document
     * @return DID document
     */
    @GetMapping(value = "/participant/{id}/did.json", produces = "application/json")
    public ResponseEntity<String> getDidDocument(@PathVariable(value = "id") String id) {

        String didDocument = null;
        try {
            didDocument = didService.getDidDocument(id);
        } catch (Exception e) {
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR, "Failed to provide did document");
        }
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);

        return new ResponseEntity<>(didDocument, httpHeaders, HttpStatus.OK);
    }

    /**
     * GET endpoint for retrieving the certificate for given participant.
     *
     * @param id id for retrieving the certificate
     * @return certificate
     */
    @GetMapping(value = "/participant/{id}/cert.pem", produces = "application/x-x509-ca-cert")
    public ResponseEntity<String> getCertificate(@PathVariable(value = "id") String id) {

        String certificate = null;

        try {
            certificate = didService.getCertificate(id);
        } catch (Exception e) {
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR, e.getMessage());
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("application/x-x509-ca-cert"));

        return new ResponseEntity<>(certificate, headers, HttpStatus.OK);
    }
}
