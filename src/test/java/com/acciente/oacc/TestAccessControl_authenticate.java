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
import org.junit.Assert;
import org.junit.Test;

import java.sql.SQLException;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

public class TestAccessControl_authenticate extends TestAccessControlBase {
   @Test
   public void authenticateSystemUser_validPwd_shouldSucceed() throws AccessControlException {
      Resource systemAuthResource = getSystemResource();
      accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(systemAuthResource,
                                                                                          Constants.OACC_ROOT_PWD));
      assertThat(accessControlContext.getAuthenticatedResource(), is(systemAuthResource));
      assertThat(accessControlContext.getSessionResource(), is(systemAuthResource));

      assertThat(accessControlContext.getResourceClassInfoByResource(systemAuthResource), is(not(nullValue())));
   }

   @Test
   public void authenticateSystemUser_reAuthenticate_shouldSucceed() throws AccessControlException {
      Resource systemAuthResource = getSystemResource();
      accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(systemAuthResource,
                                                                                          Constants.OACC_ROOT_PWD));
      // authenticate again
      accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(systemAuthResource,
                                                                                          Constants.OACC_ROOT_PWD));
      assertThat(accessControlContext.getAuthenticatedResource(), is(systemAuthResource));
      assertThat(accessControlContext.getSessionResource(), is(systemAuthResource));

      // todo: impersonate, then re-authenticate and ensure sessionResource got reset
   }

   @Test
   public void authenticateSystemUser_invalidPwd_shouldFail() throws SQLException, InterruptedException {
      Resource oSysAuthResource = getSystemResource();
      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(oSysAuthResource,
                                                                                             "invalid"));
         Assert.fail("authentication of system resource with invalid password should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }

      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(oSysAuthResource,
                                                                                             ""));
         Assert.fail("authentication of system resource with invalid empty password should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
   }

   // todo: test passwords are whitespace- and case-sensitive

   @Test
   public void authenticateSystemUser_nulls() throws SQLException, InterruptedException, AccessControlException {
      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(null, null));
         Assert.fail("authentication of null-resource should not have succeeded");
      }
      catch (NullPointerException e) {
      }
      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(getSystemResource(), null));
         Assert.fail("authentication of system resource with null password should not have succeeded");
      }
      catch (NullPointerException e) {
      }
   }

   // todo: temporarily ignored until setupScenario() can handle createPermissions for nested domains
   @Test
   public void authenticate_unauthenticatableResource_shouldFail() throws InterruptedException, AccessControlException, SQLException {
      Resource unauthenticatableResource = generateUnauthenticatableResource();
      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(unauthenticatableResource, "any_password"));
         Assert.fail("authentication of system resource with invalid password should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not of an authenticatable type"));  // todo: exception message seems unclear for a client
      }
   }

}
