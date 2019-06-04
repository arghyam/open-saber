package io.opensaber.validators;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.opensaber.pojos.APIMessage;
import io.opensaber.registry.middleware.Middleware;
import io.opensaber.registry.middleware.MiddlewareHaltException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class ValidationFilter implements Middleware {
	private static final String VALIDATION_FAILURE_MSG = "Validation failed";
	private IValidate validationService;

    ObjectMapper objectMapper = new ObjectMapper();

	@Autowired
	private APIMessage apiMessage;

	public ValidationFilter(IValidate validationServiceImpl) {
		this.validationService = validationServiceImpl;
	}

	@Override
	public boolean execute(APIMessage apiMessage) throws MiddlewareHaltException, JsonProcessingException {
		String entityType = apiMessage.getRequest().getEntityType();
		String payload = apiMessage.getRequest().getRequestMapAsString();
        if (!validationService.validate(entityType, payload)) {
			throw new MiddlewareHaltException(VALIDATION_FAILURE_MSG);
		}
		return true;
	}
}
