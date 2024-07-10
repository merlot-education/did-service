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

package eu.merloteducation.didservice;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import eu.merloteducation.didservice.controller.DidController;
import eu.merloteducation.didservice.models.exceptions.*;
import eu.merloteducation.didservice.service.DidService;
import eu.merloteducation.modelslib.api.did.ParticipantDidPrivateKeyCreateRequest;
import eu.merloteducation.modelslib.api.did.ParticipantDidPrivateKeyDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.security.cert.CertificateException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest({ DidController.class })
@AutoConfigureMockMvc
class DidControllerTests {
    @MockBean
    private DidService didService;

    @Autowired
    private MockMvc mvc;

    @BeforeEach
    public void beforeEach() throws Exception {

        ParticipantDidPrivateKeyDto dto = new ParticipantDidPrivateKeyDto("did:web", "did:web#mvm", "did:web#vm", "private key");
        ParticipantDidPrivateKeyCreateRequest emptyRequest = getEmptyCreateRequest();
        ParticipantDidPrivateKeyCreateRequest request1 = getCreateRequestCryptoAssetGenException();
        ParticipantDidPrivateKeyCreateRequest request2 = getCreateRequestPemConversionException();

        lenient().when(didService.generateDidAndPrivateKey(any())).thenReturn(dto);
        lenient().when(didService.generateDidAndPrivateKey(emptyRequest)).thenThrow(RequestArgumentException.class);
        lenient().when(didService.generateDidAndPrivateKey(request1))
            .thenThrow(CryptographicAssetGenerationException.class);
        lenient().when(didService.generateDidAndPrivateKey(request2)).thenThrow(PemConversionException.class);

        lenient().when(didService.getDidDocument(any())).thenReturn("did document");
        lenient().when(didService.getDidDocument("unknown-participant")).thenThrow(ParticipantNotFoundException.class);
        lenient().when(didService.getDidDocument("broken-certificate")).thenThrow(DidDocumentGenerationException.class);

        lenient().when(didService.getCertificate(any())).thenReturn("certificate");
        lenient().when(didService.getCertificate("unknown-participant")).thenThrow(ParticipantNotFoundException.class);

    }

    @Test
    void getDidDocumentOk() throws Exception {

        mvc.perform(MockMvcRequestBuilders.get("/participant/any/did.json").accept(MediaType.APPLICATION_JSON))
            .andDo(print()).andExpect(status().isOk());
    }

    @Test
    void getMerlotDidDocumentOk() throws Exception {

        mvc.perform(MockMvcRequestBuilders.get("/.well-known/did.json").accept(MediaType.APPLICATION_JSON))
                .andDo(print()).andExpect(status().isOk());
    }

    @Test
    void getMerlotDidDocumentFailed() throws Exception {
        when(didService.getMerlotDidDocument()).thenThrow(new DidDocumentGenerationException("Failed to generate did document"));
        mvc.perform(MockMvcRequestBuilders.get("/.well-known/did.json").accept(MediaType.APPLICATION_JSON))
                .andDo(print()).andExpect(status().isInternalServerError());
    }

    @Test
    void getDidDocumentNotFound() throws Exception {

        mvc.perform(
                MockMvcRequestBuilders.get("/participant/unknown-participant/did.json").accept(MediaType.APPLICATION_JSON))
            .andDo(print()).andExpect(status().isNotFound());
    }

    @Test
    void getDidDocumentInternalServerError() throws Exception {

        mvc.perform(
                MockMvcRequestBuilders.get("/participant/broken-certificate/did.json").accept(MediaType.APPLICATION_JSON))
            .andDo(print()).andExpect(status().isInternalServerError());
    }

    @Test
    void getCertificateOk() throws Exception {

        mvc.perform(MockMvcRequestBuilders.get("/participant/any/cert.ss.pem")
            .accept(MediaType.parseMediaType("application/x-x509-ca-cert"))).andDo(print()).andExpect(status().isOk());
    }

    @Test
    void getMerlotCertificateOk() throws Exception {

        mvc.perform(MockMvcRequestBuilders.get("/.well-known/cert.ss.pem")
                .accept(MediaType.parseMediaType("application/x-x509-ca-cert"))).andDo(print()).andExpect(status().isOk());
    }

    @Test
    void getMerlotCertificateReadFail() throws Exception {
        when(didService.getMerlotCertificate()).thenThrow(new CertificateException("failed to read cert"));
        mvc.perform(MockMvcRequestBuilders.get("/.well-known/cert.ss.pem")
                .accept(MediaType.parseMediaType("application/x-x509-ca-cert"))).andDo(print()).andExpect(status().isInternalServerError());
    }

    @Test
    void getCertificateNotFound() throws Exception {

        mvc.perform(MockMvcRequestBuilders.get("/participant/unknown-participant/cert.ss.pem")
                .contentType(MediaType.APPLICATION_JSON).accept(MediaType.parseMediaType("application/x-x509-ca-cert")))
            .andDo(print()).andExpect(status().isNotFound());
    }

    @Test
    @Disabled
    void generateDidAndPrivateKeyOk() throws Exception {

        mvc.perform(MockMvcRequestBuilders.post("/generateDidAndPrivateKey").contentType(MediaType.APPLICATION_JSON)
                .content(objectAsJsonString(getValidCreateRequest())).accept(MediaType.APPLICATION_JSON)).andDo(print())
            .andExpect(status().isOk());
    }

    @Test
    @Disabled
    void generateDidAndPrivateKeyInternalServerError1() throws Exception {

        mvc.perform(MockMvcRequestBuilders.post("/generateDidAndPrivateKey").contentType(MediaType.APPLICATION_JSON)
                .content(objectAsJsonString(getCreateRequestCryptoAssetGenException())).accept(MediaType.APPLICATION_JSON))
            .andDo(print()).andExpect(status().isInternalServerError());
    }

    @Test
    @Disabled
    void generateDidAndPrivateKeyInternalServerError2() throws Exception {

        mvc.perform(MockMvcRequestBuilders.post("/generateDidAndPrivateKey").contentType(MediaType.APPLICATION_JSON)
                .content(objectAsJsonString(getCreateRequestPemConversionException())).accept(MediaType.APPLICATION_JSON))
            .andDo(print()).andExpect(status().isInternalServerError());
    }

    @Test
    @Disabled
    void generateDidAndPrivateKeyBadRequest() throws Exception {

        mvc.perform(MockMvcRequestBuilders.post("/generateDidAndPrivateKey").contentType(MediaType.APPLICATION_JSON)
                .content(objectAsJsonString(getEmptyCreateRequest())).accept(MediaType.APPLICATION_JSON)).andDo(print())
            .andExpect(status().isBadRequest());
    }

    private ParticipantDidPrivateKeyCreateRequest getCreateRequestPemConversionException() {

        return new ParticipantDidPrivateKeyCreateRequest("pem conversion exception");
    }

    private ParticipantDidPrivateKeyCreateRequest getCreateRequestCryptoAssetGenException() {

        return new ParticipantDidPrivateKeyCreateRequest("cryptographic asset generation exception");
    }

    private ParticipantDidPrivateKeyCreateRequest getEmptyCreateRequest() {

        return new ParticipantDidPrivateKeyCreateRequest();
    }

    private ParticipantDidPrivateKeyCreateRequest getValidCreateRequest() {

        return new ParticipantDidPrivateKeyCreateRequest("valid");
    }

    private String objectAsJsonString(final Object obj) {

        try {
            return JsonMapper.builder().addModule(new JavaTimeModule()).build().writeValueAsString(obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
