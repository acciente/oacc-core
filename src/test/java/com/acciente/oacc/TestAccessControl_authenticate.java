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

import com.acciente.oacc.helper.Constants;
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
   public void authenticateSystemUser_validPwd_shouldSucceed() throws AccessControlException {
      accessControlContext.authenticate(SYS_RESOURCE,
                                        PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));
      assertThat(accessControlContext.getAuthenticatedResource(), is(SYS_RESOURCE));
      assertThat(accessControlContext.getSessionResource(), is(SYS_RESOURCE));

      assertThat(accessControlContext.getResourceClassInfoByResource(SYS_RESOURCE), is(not(nullValue())));
   }

   @Test
   public void authenticateSystemUser_reAuthenticate_shouldSucceed() throws AccessControlException {
      accessControlContext.authenticate(SYS_RESOURCE,
                                        PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));
      // authenticate again
      accessControlContext.authenticate(SYS_RESOURCE,
                                        PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));
      assertThat(accessControlContext.getAuthenticatedResource(), is(SYS_RESOURCE));
      assertThat(accessControlContext.getSessionResource(), is(SYS_RESOURCE));
   }

   @Test
   public void authenticateSystemUser_reAuthenticateAfterImpersonate_shouldSucceed() throws AccessControlException {
      accessControlContext.authenticate(SYS_RESOURCE,
                                        PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));

      // impersonate
      accessControlContext.impersonate(generateAuthenticatableResource(generateUniquePassword()));

      // authenticate again
      accessControlContext.authenticate(SYS_RESOURCE,
                                        PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));
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
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }

      try {
         accessControlContext.authenticate(SYS_RESOURCE, PasswordCredentials.newInstance("".toCharArray()));
         fail("authentication of system resource with invalid empty password should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }

      try {
         accessControlContext.authenticate(SYS_RESOURCE, PasswordCredentials.newInstance(" \t".toCharArray()));
         fail("authentication of system resource with invalid blank password should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
   }

   @Test
   public void authenticate_whitespaceAndCaseSensitivePasswords() throws SQLException, InterruptedException, AccessControlException {
      final String oaccRootPwd = new String(Constants.OACC_ROOT_PWD);
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
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      try {
         accessControlContext.authenticate(SYS_RESOURCE,
                                           PasswordCredentials.newInstance(oaccRootPwd_mixedCase.toCharArray()));
         fail("authentication of sys resource with different cased password should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
   }

   @Test
   public void authenticateSystemUser_nulls() throws SQLException, InterruptedException, AccessControlException {
      try {
         accessControlContext.authenticate(null, PasswordCredentials.newInstance(null));
         fail("authentication of null-resource should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required, none specified"));
      }
      try {
         accessControlContext.authenticate(getSystemResource(), null);
         fail("authentication of system resource with null password credentials should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("credentials required, none specified"));
      }
      try {
         accessControlContext.authenticate(getSystemResource(), PasswordCredentials.newInstance(null));
         fail("authentication of system resource with null password should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password required, none specified"));
      }
   }

   @Test
   public void authenticate_unauthenticatableResource_shouldFail() throws InterruptedException, AccessControlException, SQLException {
      Resource unauthenticatableResource = generateUnauthenticatableResource();
      try {
         accessControlContext.authenticate(unauthenticatableResource,
                                           PasswordCredentials.newInstance("any_password".toCharArray()));
         fail("authentication of unauthenticatable resource should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not of an authenticatable type"));
      }
   }

}
