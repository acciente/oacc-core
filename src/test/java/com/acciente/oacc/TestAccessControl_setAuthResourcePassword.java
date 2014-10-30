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

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertThat;

public class TestAccessControl_setAuthResourcePassword extends TestAccessControlBase {
   @Test
   public void setAuthResourcePassword_authenticatedUser() throws Exception {
      authenticateSystemResource();

      // optional: explicit check of password stored in DB
//      final DB_Resource helperResource_preChange = new DB_Resource.Builder( systemResource.getID() )
//            .resourceClassID( 0 )
//            .domainID( 0 )
//            .password_plaintext( Constants.OACC_ROOT_PWD )
//            .build();
//      final Resource authenticatedResource_preChange = accessControlContext.getAuthenticatedResource();
//      final DB_Resource helperResourceFromDB_preChange = DB_Resource.Finder.findByID( con, Constants.DB_SCHEMA, authenticatedResource_preChange.getID() );
//
//      // use DB_Resource.equals() to verify password matches prior to change
//      assertThat( helperResourceFromDB_preChange, is( helperResource_preChange ) );

      // update password and verify
      final String newPwd = Constants.OACC_ROOT_PWD + "_modified";
      accessControlContext.setAuthenticatedResourcePassword(newPwd);
      accessControlContext.unauthenticate();
      try {
         accessControlContext.authenticate(getSystemResource(), Constants.OACC_ROOT_PWD);
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      accessControlContext.authenticate(getSystemResource(), newPwd);

      // optional: explicit check of password stored in DB
//      final DB_Resource helperResource_postChange = new DB_Resource.Builder( systemResource.getID() )
//            .resourceClassID( 0 )
//            .domainID( 0 )
//            .password_plaintext( newPwd )
//            .build();
//      final Resource authenticatedResource_postChange = accessControlContext.getAuthenticatedResource();
//      final DB_Resource helperResourceFromDB_postChange = DB_Resource.Finder.findByID( con, Constants.DB_SCHEMA, authenticatedResource_postChange.getID() );
//      assertThat( authenticatedResource_postChange, is( authenticatedResource_preChange ) );
//      assertThat( helperResourceFromDB_postChange, is( helperResource_postChange ) );

      // update password and verify
      final String emptyPwd = "";
      accessControlContext.setAuthenticatedResourcePassword(emptyPwd);
      try {
         accessControlContext.authenticate(getSystemResource(), newPwd);
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      try {
         accessControlContext.authenticate(getSystemResource(), Constants.OACC_ROOT_PWD);
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      accessControlContext.authenticate(getSystemResource(), emptyPwd);

      // optional: reset to original password
      accessControlContext.setAuthenticatedResourcePassword(Constants.OACC_ROOT_PWD);
   }

   @Test
   public void setAuthResourcePassword_authenticatedUser_invalidPassword() throws Exception {
      authenticateSystemResource();

      // update password and verify
      try {
         accessControlContext.setAuthenticatedResourcePassword(null);
      }
      catch (NullPointerException e) {
      }
   }

   @Test
   public void setAuthResourcePassword_onNonAuthenticatedResource() throws Exception {
      authenticateSystemResource();

      final String password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      // set password and verify
      final String newPassword = password + "_modified";
      accessControlContext.setResourcePassword(authenticatableResource, newPassword);
      accessControlContext.unauthenticate();
      try {
         accessControlContext.authenticate(authenticatableResource, password);
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      accessControlContext.authenticate(authenticatableResource, newPassword);
   }

   // todo: try setting pwd on resource we don't have permissions on

}
