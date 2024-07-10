/*
 *  Copyright 2023-2024 Dataport AöR
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package eu.merloteducation.didservice.controller;

import eu.merloteducation.didservice.models.exceptions.*;
import eu.merloteducation.didservice.service.DidService;
import eu.merloteducation.modelslib.api.did.ParticipantDidPrivateKeyCreateRequest;
import eu.merloteducation.modelslib.api.did.ParticipantDidPrivateKeyDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.cert.CertificateException;

import static org.springframework.http.HttpStatus.*;

@RestController
@RequestMapping("/")
public class DidController {
    @Autowired
    private DidService didService;

    /**
     * GET endpoint for retrieving the DID document for given participant.
     *
     * @param id id for retrieving the DID document
     * @return participant DID document
     */
    @GetMapping(value = "/participant/{id}/did.json", produces = "application/json")
    public ResponseEntity<String> getDidDocument(@PathVariable(value = "id") String id) {

        String didDocument;
        try {
            didDocument = didService.getDidDocument(id);
        } catch (ParticipantNotFoundException e1) {
            throw new ResponseStatusException(NOT_FOUND, e1.getMessage());
        } catch (DidDocumentGenerationException e2) {
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR,
                "Did document provision failed: " + e2.getMessage());
        }
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);

        return new ResponseEntity<>(didDocument, httpHeaders, HttpStatus.OK);
    }

    /**
     * GET endpoint for retrieving the certificate for given participant.
     *
     * @param id id for retrieving the certificate
     * @return participant certificate
     */
    @GetMapping(value = "/participant/{id}/cert.ss.pem", produces = "application/x-x509-ca-cert")
    public ResponseEntity<String> getCertificate(@PathVariable(value = "id") String id) {

        String certificate;

        try {
            certificate = didService.getCertificate(id);
        } catch (ParticipantNotFoundException e) {
            throw new ResponseStatusException(NOT_FOUND, e.getMessage());
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("application/x-x509-ca-cert"));

        return new ResponseEntity<>(certificate, headers, HttpStatus.OK);
    }

    /**
     * GET endpoint for retrieving the DID document for the MERLOT federation.
     *
     * @return MERLOT DID document
     */
    @GetMapping(value = "/.well-known/did.json", produces = "application/json")
    public String getMerlotDidDocument() {
        try {
            return didService.getMerlotDidDocument();
        } catch (DidDocumentGenerationException e) {
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR,
                    "Did document provision failed: " + e.getMessage());
        }
    }

    /**
     * GET endpoint for retrieving the certificate for the MERLOT federation.
     *
     * @return MERLOT certificate
     */
    @GetMapping(value = "/.well-known/cert.ss.pem", produces = "application/x-x509-ca-cert")
    public String getCertificate() {
        try {
            return didService.getMerlotCertificate();
        } catch (CertificateException e) {
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR, "Failed to load federation certificate.");
        }

    }
}
