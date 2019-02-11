/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.cvarjao.keycloak.authentication.requiredactions;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.requiredactions.util.UpdateProfileContext;
import org.keycloak.authentication.requiredactions.util.UserUpdateProfileContext;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.AttributeFormDataProcessor;
import org.keycloak.services.validation.Validation;


import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class UpdateProfile implements RequiredActionProvider, RequiredActionFactory {
	public static final String PROVIDER_ID = "cvarjao_update_profile";
	public static final String FORM = "cvarjao_update_profile.ftl";
	
    @Override
    public void evaluateTriggers(RequiredActionContext context) {
    }

    public Response createResponse(LoginFormsProvider provider) {
    	return provider.createForm(FORM);
    }
    
    public LoginFormsProvider createForm(RequiredActionContext context) {
    	UserModel user = context.getUser();
    	RealmModel realm = context.getRealm();
    	UpdateProfileContext userBasedContext = new UserUpdateProfileContext(realm, user);
    	
    	LoginFormsProvider form = context.form()
                .setAttribute("user", userBasedContext);
  
    	return form;
    }
    
    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        Response challenge = createResponse(createForm(context));   
        context.challenge(challenge);
    }

   
    @Override
    public void processAction(RequiredActionContext context) {
        EventBuilder event = context.getEvent();
        event.event(EventType.UPDATE_PROFILE);
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        UserModel user = context.getUser();
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();


        List<FormMessage> errors = Validation.validateUpdateProfileForm(realm, formData);
        if (errors != null && !errors.isEmpty()) {
            Response challenge = createResponse(createForm(context)
                    .setErrors(errors)
                    .setFormData(formData));
            
            context.challenge(challenge);
            return;
        }

        if (realm.isEditUsernameAllowed()) {
            String username = formData.getFirst("username");
            String oldUsername = user.getUsername();

            boolean usernameChanged = oldUsername != null ? !oldUsername.equals(username) : username != null;

            if (usernameChanged) {

                if (session.users().getUserByUsername(username, realm) != null) {
                    Response challenge = createResponse(createForm(context)
                            .setError(Messages.USERNAME_EXISTS)
                            .setFormData(formData));
                    context.challenge(challenge);
                    return;
                }

                user.setUsername(username);
            }

        }

        user.setFirstName(formData.getFirst("firstName"));
        user.setLastName(formData.getFirst("lastName"));

        String email = formData.getFirst("email");

        String oldEmail = user.getEmail();
        boolean emailChanged = oldEmail != null ? !oldEmail.equals(email) : email != null;

        if (emailChanged) {
            if (!realm.isDuplicateEmailsAllowed()) {
                UserModel userByEmail = session.users().getUserByEmail(email, realm);

                // check for duplicated email
                if (userByEmail != null && !userByEmail.getId().equals(user.getId())) {
                    Response challenge = createResponse(createForm(context)
                            .setError(Messages.EMAIL_EXISTS)
                            .setFormData(formData));
                    context.challenge(challenge);
                    return;
                }
            }

            user.setEmail(email);
            user.setEmailVerified(false);
        }

        AttributeFormDataProcessor.process(formData, realm, user);

        if (emailChanged) {
            event.clone().event(EventType.UPDATE_EMAIL).detail(Details.PREVIOUS_EMAIL, oldEmail).detail(Details.UPDATED_EMAIL, email).success();
        }
        context.success();

    }


    @Override
    public void close() {

    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getDisplayText() {
        return "Update Profile (CVARJAO)";
    }


    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
