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

@RestController
@RequestMapping("/")
public class DidController {
    @Autowired
    private DidService didService;

    /**
     * POST endpoint for generating a did:web, a key pair and certificate. Returns the did:web and private key.
     *
     * @param request with information needed for certificate generation
     * @return dto containing the generated did:web and private key
     */
    @PostMapping("/generateDidAndPrivateKey")
    public ParticipantDidPrivateKeyDto generateDidAndPrivateKey(
        @RequestBody ParticipantDidPrivateKeyCreateRequest request) {

        return didService.generateDidAndPrivateKey(request);
    }

    /**
     * GET endpoint for retrieving the DID document containing all MERLOT-generated did:webs and associated
     * certificates.
     *
     * @return DID document
     */
    @GetMapping(value = "/did.json", produces = "application/json")
    public ResponseEntity<String> getDidDocument() {

        String didDocument = didService.getDidDocument();
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);

        return new ResponseEntity<>(didDocument, httpHeaders, HttpStatus.OK);
    }

    /**
     * GET endpoint for retrieving a certificate by id.
     *
     * @param certId id for retrieving the certificate
     * @return certificate
     */
    @GetMapping(value = "/certificate/{certId}.pem", produces = "application/x-x509-ca-cert")
    public ResponseEntity<String> getCertificate(@PathVariable(value = "certId") String certId) {

        String certificate = didService.getCertificate(certId);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("application/x-x509-ca-cert"));

        return new ResponseEntity<>(certificate, headers, HttpStatus.OK);
    }
}
