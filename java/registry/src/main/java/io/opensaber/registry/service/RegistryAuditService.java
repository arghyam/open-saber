package io.opensaber.registry.service;

import io.opensaber.registry.exception.*;

import java.io.IOException;
import java.util.NoSuchElementException;

public interface RegistryAuditService {

    public String frameAuditEntity(org.eclipse.rdf4j.model.Model entityModel) throws IOException;

    public org.eclipse.rdf4j.model.Model getAuditNode(String id) throws IOException, NoSuchElementException,
            RecordNotFoundException, EncryptionException, AuditFailedException;

    public String getAuditNodeFramed(String id) throws IOException, NoSuchElementException, RecordNotFoundException,
            EncryptionException, AuditFailedException, IOException, MultipleEntityException, EntityCreationException;
}