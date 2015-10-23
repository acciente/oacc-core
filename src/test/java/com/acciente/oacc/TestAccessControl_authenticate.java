/*
 * Copyright 2009-2015, Acciente LLC
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

import java.sql.SQLException;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_authenticate extends TestAccessControlBase {
   @Test
   public void authenticateSystemUser_validPwd_shouldSucceed() {
      accessControlContext.authenticate(SYS_RESOURCE,
                                        PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));
      assertThat(accessControlContext.getAuthenticatedResource(), is(SYS_RESOURCE));
      assertThat(accessControlContext.getSessionResource(), is(SYS_RESOURCE));

      assertThat(accessControlContext.getResourceClassInfoByResource(SYS_RESOURCE), is(not(nullValue())));
   }

   @Test
   public void authenticateSystemUser_reAuthenticate_shouldSucceed() {
      accessControlContext.authenticate(SYS_RESOURCE,
                                        PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));
      // authenticate again
      accessControlContext.authenticate(SYS_RESOURCE,
                                        PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));
      assertThat(accessControlContext.getAuthenticatedResource(), is(SYS_RESOURCE));
      assertThat(accessControlContext.getSessionResource(), is(SYS_RESOURCE));
   }

   @Test
   public void authenticateSystemUser_reAuthenticateAfterImpersonate_shouldSucceed() {
      accessControlContext.authenticate(SYS_RESOURCE,
                                        PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));

      // impersonate
      accessControlContext.impersonate(generateAuthenticatableResource(generateUniquePassword()));

      // authenticate again
      accessControlContext.authenticate(SYS_RESOURCE,
                                        PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));
      assertThat(accessControlContext.getAuthenticatedResource(), is(SYS_RESOURCE));
      assertThat(accessControlContext.getSessionResource(), is(SYS_RESOURCE));
   }

   @Test
   public void authenticateSystemUser_invalidPwd_shouldFail() throws SQLException, InterruptedException {
      try {
         accessControlContext.authenticate(SYS_RESOURCE,
                                           PasswordCredentials.newInstance("invalid".toCharArray()));
         fail("authentication of system resource with invalid password should not have succeeded");
      }
      catch (IncorrectCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }

      try {
         accessControlContext.authenticate(SYS_RESOURCE, PasswordCredentials.newInstance("".toCharArray()));
         fail("authentication of system resource with invalid empty password should not have succeeded");
      }
      catch (IncorrectCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }

      try {
         accessControlContext.authenticate(SYS_RESOURCE, PasswordCredentials.newInstance(" \t".toCharArray()));
         fail("authentication of system resource with invalid blank password should not have succeeded");
      }
      catch (IncorrectCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
   }

   @Test
   public void authenticate_withExtId_shouldSucceed() {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, true);
      final String externalId1 = generateUniqueExternalId();
      final String externalId2 = generateUniqueExternalId();
      final String externalId3 = generateUniqueExternalId();
      final Credentials credentials = PasswordCredentials.newInstance(generateUniquePassword());

      // create resources with external id
      final Resource resource1
            = accessControlContext.createResource(resourceClassName, domainName, externalId1, credentials);
      assertThat(resource1, is(not(nullValue())));
      final Resource resource2
            = accessControlContext.createResource(resourceClassName, domainName, externalId2, credentials);
      assertThat(resource2, is(not(nullValue())));
      final Resource resource3
            = accessControlContext.createResource(resourceClassName, domainName, externalId3, credentials);
      assertThat(resource3, is(not(nullValue())));

      // authenticate with external id and verify
      accessControlContext.authenticate(Resources.getInstance(resource1.getExternalId()), credentials);
      assertThat(accessControlContext.getAuthenticatedResource(), is(resource1));
      assertThat(accessControlContext.getSessionResource(), is(resource1));

      // authenticate with resource id and external id and verify
      accessControlContext.authenticate(Resources.getInstance(resource2.getId(), resource2.getExternalId()), credentials);
      assertThat(accessControlContext.getAuthenticatedResource(), is(resource2));
      assertThat(accessControlContext.getSessionResource(), is(resource2));

      // authenticate with resource id and verify
      accessControlContext.authenticate(Resources.getInstance(resource3.getId()), credentials);
      assertThat(accessControlContext.getAuthenticatedResource(), is(resource3));
      assertThat(accessControlContext.getSessionResource(), is(resource3));
   }

   @Test
   public void authenticate_whitespaceAndCaseSensitivePasswords() {
      final String oaccRootPwd = new String(TestConfigLoader.getOaccRootPassword());
      final String oaccRootPwd_whitespaced = " " + oaccRootPwd + "\t";
      final String oaccRootPwd_mixedCase
            = oaccRootPwd.toLowerCase().substring(0, oaccRootPwd.length()/2)
            + oaccRootPwd.toUpperCase().substring(oaccRootPwd.length()/2);

      // ensure the passwords variations are sound
      assertThat(oaccRootPwd.toLowerCase(), is(oaccRootPwd_mixedCase.toLowerCase()));
      accessControlContext.authenticate(SYS_RESOURCE,
                                        PasswordCredentials.newInstance(oaccRootPwd.toCharArray()));

      // verify
      try {
         accessControlContext.authenticate(SYS_RESOURCE,
                                           PasswordCredentials.newInstance(oaccRootPwd_whitespaced.toCharArray()));
         fail("authentication of sys resource with whitespaced password should not have succeeded");
      }
      catch (IncorrectCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      try {
         accessControlContext.authenticate(SYS_RESOURCE,
                                           PasswordCredentials.newInstance(oaccRootPwd_mixedCase.toCharArray()));
         fail("authentication of sys resource with different cased password should not have succeeded");
      }
      catch (IncorrectCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
   }

   @Test
   public void authenticateSystemUser_nulls() {
      try {
         accessControlContext.authenticate(null, PasswordCredentials.newInstance(null));
         fail("authentication of null-resource should not have succeeded");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required, none specified"));
      }
      try {
         accessControlContext.authenticate(Resources.getInstance(null), PasswordCredentials.newInstance(null));
         fail("authentication of null resource ids should not have succeeded");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id"));
      }
      try {
         accessControlContext.authenticate(getSystemResource(), null);
         fail("authentication of system resource with null password credentials should not have succeeded");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("credentials required, none specified"));
      }
      try {
         accessControlContext.authenticate(getSystemResource(), PasswordCredentials.newInstance(null));
         fail("authentication of system resource with null password should not have succeeded");
      }
      catch (InvalidCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password required, none specified"));
      }
   }

   @Test
   public void authenticate_nonExistentResource_shouldFail() {
      try {
         accessControlContext.authenticate(Resources.getInstance(-999L),
                                           PasswordCredentials.newInstance("any_password".toCharArray()));
         fail("authentication of non-existent resource reference should not have succeeded");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.authenticate(Resources.getInstance("invalid"),
                                           PasswordCredentials.newInstance("any_password".toCharArray()));
         fail("authentication of non-existent external id reference should not have succeeded");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.authenticate(Resources.getInstance(-999L, "invalid"),
                                           PasswordCredentials.newInstance("any_password".toCharArray()));
         fail("authentication of mismatched resource and external id reference should not have succeeded");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
   }

   @Test
   public void authenticate_unauthenticatableResource_shouldFail() {
      Resource unauthenticatableResource = generateUnauthenticatableResource();
      try {
         accessControlContext.authenticate(unauthenticatableResource,
                                           PasswordCredentials.newInstance("any_password".toCharArray()));
         fail("authentication of unauthenticatable resource should not have succeeded");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not of an authenticatable resource class"));
      }
   }
}
