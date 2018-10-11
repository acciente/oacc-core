/*
 * Copyright 2009-2018, Acciente LLC
 *
 * Acciente LLC licenses this file to you under the
 * Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the
 * License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in
 * writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.acciente.oacc;

import com.acciente.oacc.helper.TestConfigLoader;
import org.junit.Test;

import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_setCredentials extends TestAccessControlBase {
   @Test
   public void setCredentials_onSystemResource() throws Exception {
      authenticateSystemResource();

      // update credentials and verify
      final char[] newPwd = (TestConfigLoader.getOaccRootPassword() + "_modified").toCharArray();
      accessControlContext.setCredentials(getSystemResource(), PasswordCredentials.newInstance(newPwd));
      accessControlContext.unauthenticate();
      try {
         accessControlContext.authenticate(getSystemResource(),
                                           PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));
         fail("authenticating with old credentials should have failed");
      }
      catch (IncorrectCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      accessControlContext.authenticate(getSystemResource(), PasswordCredentials.newInstance(newPwd));

      // update credentials and verify
      final char[] intermediatePwd = (TestConfigLoader.getOaccRootPassword() + "_intermediate").toCharArray();
      accessControlContext.setCredentials(getSystemResource(), PasswordCredentials.newInstance(intermediatePwd));
      try {
         accessControlContext.authenticate(getSystemResource(), PasswordCredentials.newInstance(newPwd));
         fail("authenticating with old credentials should have failed");
      }
      catch (IncorrectCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      try {
         accessControlContext.authenticate(getSystemResource(),
                                           PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));
         fail("authenticating with old credentials should have failed");
      }
      catch (IncorrectCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      accessControlContext.authenticate(getSystemResource(), PasswordCredentials.newInstance(intermediatePwd));

      // optional: reset to original password
      accessControlContext.setCredentials(getSystemResource(),
                                          PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));
   }

   @Test
   public void setCredentials_invalidPassword_shouldFail() throws Exception {
      authenticateSystemResource();

      // attempt to set credentials
      try {
         accessControlContext.setCredentials(getSystemResource(),
                                             PasswordCredentials.newInstance(null));
         fail("setting password credentials with null password should have failed");
      }
      catch (InvalidCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password required, none specified"));
      }

      try {
         accessControlContext.setCredentials(getSystemResource(),
                                             PasswordCredentials.newInstance("".toCharArray()));
         fail("setting password credentials with empty password should have failed");
      }
      catch (InvalidCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password cannot be zero length"));
      }

      try {
         accessControlContext.setCredentials(getSystemResource(),
                                             PasswordCredentials.newInstance("\t ".toCharArray()));
         fail("setting password credentials with blank password should have failed");
      }
      catch (InvalidCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password cannot be blank"));
      }
   }

   @Test
   public void setCredentials_onNonAuthenticatedResource() throws Exception {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      // set credentials and verify
      final char[] newPassword = (password + "_modified").toCharArray();
      accessControlContext.setCredentials(authenticatableResource,
                                          PasswordCredentials.newInstance(newPassword));
      accessControlContext.unauthenticate();
      try {
         accessControlContext.authenticate(authenticatableResource,
                                           PasswordCredentials.newInstance(password));
         fail("authenticating with old credentials should have failed");
      }
      catch (IncorrectCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      accessControlContext.authenticate(authenticatableResource,
                                        PasswordCredentials.newInstance(newPassword));
   }

   @Test
   public void setCredentials_withExtId() throws Exception {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final String externalId = generateUniqueExternalId();
      final Resource authenticatableResource = generateAuthenticatableResourceWithExtId(password, externalId);

      // set credentials and verify
      final char[] newPassword = (password + "_modified").toCharArray();
      accessControlContext.setCredentials(Resources.getInstance(externalId),
                                          PasswordCredentials.newInstance(newPassword));
      accessControlContext.unauthenticate();
      try {
         accessControlContext.authenticate(authenticatableResource,
                                           PasswordCredentials.newInstance(password));
         fail("authenticating with old credentials should have failed");
      }
      catch (IncorrectCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      accessControlContext.authenticate(authenticatableResource,
                                        PasswordCredentials.newInstance(newPassword));
   }

   @Test
   public void setCredentials_onUnauthenticatableResource_shouldFail() throws Exception {
      authenticateSystemResource();

      final Resource unauthenticatableResource = generateUnauthenticatableResource();

      // attempt to set credentials
      final char[] newPassword = generateUniquePassword();
      try {
         accessControlContext.setCredentials(unauthenticatableResource,
                                             PasswordCredentials.newInstance(newPassword));
         fail("setting credentials on an unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("unauthenticatable resource is not valid"));
      }
   }

   @Test
   public void setCredentials_withoutResetAuthorization_shouldFail() throws Exception {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final char[] accessorPassword = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(accessorPassword);

      // authenticate and attempt to set credentials
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(accessorPassword));

      final char[] newPassword = (password + "_modified").toCharArray();
      try {
         accessControlContext.setCredentials(authenticatableResource,
                                             PasswordCredentials.newInstance(newPassword));
         fail("setting credentials without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("reset credentials"));
      }
   }

   @Test
   public void setCredentials_withoutResetAuthorization_shouldSucceed() throws Exception {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      // authenticate and attempt to set credentials on oneself
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      final char[] newPassword = (password + "_modified").toCharArray();
      accessControlContext.setCredentials(authenticatableResource, PasswordCredentials.newInstance(newPassword));

      // verify
      accessControlContext.unauthenticate();
      try {
         accessControlContext.authenticate(authenticatableResource,
                                           PasswordCredentials.newInstance(password));
         fail("authenticating with old credentials should have failed");
      }
      catch (IncorrectCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      accessControlContext.authenticate(authenticatableResource,
                                        PasswordCredentials.newInstance(newPassword));
   }

   @Test
   public void setCredentials_directResetAuthorization_shouldSucceed() throws Exception {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final char[] accessorPassword = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(accessorPassword);
      final Set<ResourcePermission> resetCredentialsPermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));

      // set up resource permissions: accessor --RESET-CREDENTIALS-> authenticatable
      accessControlContext.setResourcePermissions(accessorResource, authenticatableResource, resetCredentialsPermissions);

      // authenticate and set credentials
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(accessorPassword));

      final char[] newPassword = (password + "_modified").toCharArray();
      accessControlContext.setCredentials(authenticatableResource, PasswordCredentials.newInstance(newPassword));

      // verify
      accessControlContext.unauthenticate();
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(newPassword));
   }

   @Test
   public void setCredentials_globalResetAuthorization_shouldSucceed() throws Exception {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final String authenticatableResourceClassName = accessControlContext.getResourceClassInfoByResource(authenticatableResource).getResourceClassName();
      final String authenticatableDomainName = accessControlContext.getDomainNameByResource(authenticatableResource);
      final char[] accessorPassword = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(accessorPassword);
      final Set<ResourcePermission> resetCredentialsPermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));

      // set up global permissions: accessor --RESET-CREDENTIALS-> {authenticatable class, authenticatable domain}
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        authenticatableDomainName,
                                                        resetCredentialsPermissions);

      // authenticate and set credentials
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(accessorPassword));

      final char[] newPassword = (password + "_modified").toCharArray();
      accessControlContext.setCredentials(authenticatableResource, PasswordCredentials.newInstance(newPassword));

      // verify
      accessControlContext.unauthenticate();
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(newPassword));
   }

   @Test
   public void setCredentials_domainInheritedResetAuthorization_shouldSucceed() throws Exception {
      authenticateSystemResource();

      final String parentDomainName = generateDomain();
      final String childDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(childDomainName, parentDomainName);

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password, childDomainName);
      final String authenticatableResourceClassName = accessControlContext.getResourceClassInfoByResource(authenticatableResource).getResourceClassName();
      final char[] accessorPassword = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(accessorPassword);
      final Set<ResourcePermission> resetCredentialsPermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));

      // set up global permissions: accessor --RESET-CREDENTIALS-> {authenticatable class, parent domain}
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        parentDomainName,
                                                        resetCredentialsPermissions);

      // authenticate and set credentials
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(accessorPassword));

      final char[] newPassword = (password + "_modified").toCharArray();
      accessControlContext.setCredentials(authenticatableResource, PasswordCredentials.newInstance(newPassword));

      // verify
      accessControlContext.unauthenticate();
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(newPassword));
   }

   @Test
   public void setCredentials_inheritResetAuthorization_shouldSucceed() throws Exception {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final String authenticatableResourceClassName = accessControlContext.getResourceClassInfoByResource(authenticatableResource).getResourceClassName();
      final String authenticatableDomainName = accessControlContext.getDomainNameByResource(authenticatableResource);
      final char[] accessorPassword = generateUniquePassword();
      final Resource donorResource = generateUnauthenticatableResource();
      final Resource accessorResource = generateAuthenticatableResource(accessorPassword);
      final Set<ResourcePermission> resetCredentialsPermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));

      // set up global permissions: accessor --RESET-CREDENTIALS-> {authenticatable class, authenticatable domain}
      accessControlContext.setGlobalResourcePermissions(donorResource,
                                                        authenticatableResourceClassName,
                                                        authenticatableDomainName,
                                                        resetCredentialsPermissions);

      // set up inheritance : accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate and set credentials
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(accessorPassword));

      final char[] newPassword = (password + "_modified").toCharArray();
      accessControlContext.setCredentials(authenticatableResource, PasswordCredentials.newInstance(newPassword));

      // verify
      accessControlContext.unauthenticate();
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(newPassword));
   }

   @Test
   public void setCredentials_superUserAuthorization_shouldSucceed() throws Exception {
      authenticateSystemResource();

      final String parentDomainName = generateDomain();
      final String childDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(childDomainName, parentDomainName);

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password, childDomainName);
      final char[] accessorPassword = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(accessorPassword);

      // set up domain permissions: accessor --SUPER-USER-> parent domain
      accessControlContext.setDomainPermissions(accessorResource,
                                                parentDomainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // authenticate and set credentials
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(accessorPassword));

      final char[] newPassword = (password + "_modified").toCharArray();
      accessControlContext.setCredentials(authenticatableResource, PasswordCredentials.newInstance(newPassword));

      // verify
      accessControlContext.unauthenticate();
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(newPassword));
   }

   @Test
   public void setCredentials_impersonateResetAuthorization_shouldFail() throws Exception {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final char[] accessorPassword = generateUniquePassword();
      final Resource donorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessorResource = generateAuthenticatableResource(accessorPassword);
      final Set<ResourcePermission> resetCredentialsPermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));

      // set up resource permissions: donor --RESET-CREDENTIALS-> authenticatable
      accessControlContext.setResourcePermissions(donorResource, authenticatableResource, resetCredentialsPermissions);

      // set up impersonate authorization : accessor --IMPERSONATE-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // authenticate and impersonate
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(accessorPassword));
      accessControlContext.impersonate(donorResource);

      // attempt to set credentials
      final char[] newPassword = (password + "_modified").toCharArray();
      try {
         accessControlContext.setCredentials(authenticatableResource,
                                             PasswordCredentials.newInstance(newPassword));
         fail("setting credentials while impersonating another resource should have failed");
      }
      catch (IllegalStateException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("while impersonating another resource"));
      }
   }

   @Test
   public void setCredentials_nulls() throws Exception {
      authenticateSystemResource();

      // attempt to update credentials
      final char[] newPwd = "new_password".toCharArray();
      try {
         accessControlContext.setCredentials(null, PasswordCredentials.newInstance(newPwd));
         fail("setting credentials with null resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.setCredentials(Resources.getInstance(null), PasswordCredentials.newInstance(newPwd));
         fail("setting credentials with null external resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.setCredentials(getSystemResource(), null);
         fail("setting credentials with null credentials should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("credentials required"));
      }
   }

   @Test
   public void setCredentials_nonExistentReferences_shouldFail() throws Exception {
      authenticateSystemResource();

      // attempt to update credentials
      final char[] newPwd = "new_password".toCharArray();
      try {
         accessControlContext.setCredentials(Resources.getInstance(-999L), PasswordCredentials.newInstance(newPwd));
         fail("setting credentials with non-existent resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.setCredentials(Resources.getInstance("invalid"), PasswordCredentials.newInstance(newPwd));
         fail("setting credentials with non-existent external resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.setCredentials(Resources.getInstance(-999L, "invalid"), PasswordCredentials.newInstance(newPwd));
         fail("setting credentials with mismatched internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
   }
}
