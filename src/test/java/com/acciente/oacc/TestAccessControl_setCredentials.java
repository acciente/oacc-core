/*
 * Copyright 2009-2014, Acciente LLC
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

import com.acciente.oacc.helper.Constants;
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
      final char[] newPwd = (Constants.OACC_ROOT_PWD + "_modified").toCharArray();
      accessControlContext.setCredentials(getSystemResource(), PasswordCredentials.newInstance(newPwd));
      accessControlContext.unauthenticate();
      try {
         accessControlContext.authenticate(getSystemResource(),
                                           PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));
         fail("authenticating with old credentials should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      accessControlContext.authenticate(getSystemResource(), PasswordCredentials.newInstance(newPwd));

      // update credentials and verify
      final char[] intermediatePwd = (Constants.OACC_ROOT_PWD + "_intermediate").toCharArray();
      accessControlContext.setCredentials(getSystemResource(), PasswordCredentials.newInstance(intermediatePwd));
      try {
         accessControlContext.authenticate(getSystemResource(), PasswordCredentials.newInstance(newPwd));
         fail("authenticating with old credentials should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      try {
         accessControlContext.authenticate(getSystemResource(),
                                           PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));
         fail("authenticating with old credentials should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      accessControlContext.authenticate(getSystemResource(), PasswordCredentials.newInstance(intermediatePwd));

      // optional: reset to original password
      accessControlContext.setCredentials(getSystemResource(),
                                          PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));
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
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password required, none specified"));
      }

      try {
         accessControlContext.setCredentials(getSystemResource(),
                                             PasswordCredentials.newInstance("".toCharArray()));
         fail("setting password credentials with empty password should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password cannot be zero length"));
      }

      try {
         accessControlContext.setCredentials(getSystemResource(),
                                             PasswordCredentials.newInstance("\t ".toCharArray()));
         fail("setting password credentials with blank password should have failed");
      }
      catch (AccessControlException e) {
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
      catch (AccessControlException e) {
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
      catch (AccessControlException e) {
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
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authorized"));
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
      catch (AccessControlException e) {
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
                                                        resetCredentialsPermissions,
                                                        authenticatableDomainName);

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
                                                        resetCredentialsPermissions,
                                                        parentDomainName);

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
                                                        resetCredentialsPermissions,
                                                        authenticatableDomainName);

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
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("while impersonating another resource"));
      }
   }
   // todo: set with impersonate
}
