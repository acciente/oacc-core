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
      accessControlContext.authenticate(systemAuthResource,
                                        PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));
      assertThat(accessControlContext.getAuthenticatedResource(), is(systemAuthResource));
      assertThat(accessControlContext.getSessionResource(), is(systemAuthResource));

      assertThat(accessControlContext.getResourceClassInfoByResource(systemAuthResource), is(not(nullValue())));
   }

   @Test
   public void authenticateSystemUser_reAuthenticate_shouldSucceed() throws AccessControlException {
      Resource systemAuthResource = getSystemResource();
      accessControlContext.authenticate(systemAuthResource,
                                        PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));
      // authenticate again
      accessControlContext.authenticate(systemAuthResource,
                                        PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));
      assertThat(accessControlContext.getAuthenticatedResource(), is(systemAuthResource));
      assertThat(accessControlContext.getSessionResource(), is(systemAuthResource));

      // todo: impersonate, then re-authenticate and ensure sessionResource got reset
   }

   @Test
   public void authenticateSystemUser_invalidPwd_shouldFail() throws SQLException, InterruptedException {
      Resource oSysAuthResource = getSystemResource();
      try {
         accessControlContext.authenticate(oSysAuthResource,
                                           PasswordCredentials.newInstance("invalid".toCharArray()));
         Assert.fail("authentication of system resource with invalid password should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }

      try {
         accessControlContext.authenticate(oSysAuthResource, PasswordCredentials.newInstance("".toCharArray()));
         Assert.fail("authentication of system resource with invalid empty password should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }

      try {
         accessControlContext.authenticate(oSysAuthResource, PasswordCredentials.newInstance(" \t".toCharArray()));
         Assert.fail("authentication of system resource with invalid blank password should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
   }

   // todo: test passwords are whitespace- and case-sensitive

   @Test
   public void authenticateSystemUser_nulls() throws SQLException, InterruptedException, AccessControlException {
      try {
         accessControlContext.authenticate(null, PasswordCredentials.newInstance(null));
         Assert.fail("authentication of null-resource should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required, none specified"));
      }
      try {
         accessControlContext.authenticate(getSystemResource(), null);
         Assert.fail("authentication of system resource with null password credentials should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("credentials required, none specified"));
      }
      try {
         accessControlContext.authenticate(getSystemResource(), PasswordCredentials.newInstance(null));
         Assert.fail("authentication of system resource with null password should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password required, none specified"));
      }
   }

   // todo: temporarily ignored until setupScenario() can handle createPermissions for nested domains
   @Test
   public void authenticate_unauthenticatableResource_shouldFail() throws InterruptedException, AccessControlException, SQLException {
      Resource unauthenticatableResource = generateUnauthenticatableResource();
      try {
         accessControlContext.authenticate(unauthenticatableResource,
                                           PasswordCredentials.newInstance("any_password".toCharArray()));
         Assert.fail("authentication of unauthenticatable resource should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not of an authenticatable type"));
      }
   }

}
