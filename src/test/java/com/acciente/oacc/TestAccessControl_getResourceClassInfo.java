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

import org.junit.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_getResourceClassInfo extends TestAccessControlBase {
   @Test
   public void getResourceClassInfo_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      generateResourceClass(false, false);
      final String resourceClassName = generateResourceClass(true, false);

      // verify
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfo(resourceClassName);
      assertThat(resourceClassInfo, is(not(nullValue())));
      assertThat(resourceClassInfo.getResourceClassName(), is(resourceClassName));
      assertThat(resourceClassInfo.isAuthenticatable(), is(true));
      assertThat(resourceClassInfo.isUnauthenticatedCreateAllowed(), is(false));
   }

   @Test
   public void getResourceClassInfo_validAsAuthenticated() throws AccessControlException {
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      generateResourceClass(false, false);
      final String resourceClassName = generateResourceClass(false, true);

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfo(resourceClassName);
      assertThat(resourceClassInfo, is(not(nullValue())));
      assertThat(resourceClassInfo.getResourceClassName(), is(resourceClassName));
      assertThat(resourceClassInfo.isAuthenticatable(), is(false));
      assertThat(resourceClassInfo.isUnauthenticatedCreateAllowed(), is(true));
   }

   @Test
   public void getResourceClassInfo_whitespaceConsistent() throws AccessControlException {
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      generateResourceClass(false, false);
      final String resourceClassName = generateResourceClass(true, true);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfo(resourceClassName_whitespaced);
      assertThat(resourceClassInfo, is(not(nullValue())));
      assertThat(resourceClassInfo.getResourceClassName(), is(resourceClassName));
      assertThat(resourceClassInfo.isAuthenticatable(), is(true));
      assertThat(resourceClassInfo.isUnauthenticatedCreateAllowed(), is(true));
   }

   @Test
   public void getResourceClassInfo_nonExistentReferences_shouldFail() throws AccessControlException {
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      generateResourceClass(false, false);

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getResourceClassInfo("does_not_exist");
         fail("getting resource class info for non-existent resource class reference should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourceClassInfo("");
         fail("getting resource class info for blank resource class reference should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
   }

   @Test
   public void getResourceClassInfo_nulls() throws AccessControlException {
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      generateResourceClass(false, false);

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getResourceClassInfo(null);
         fail("getting resource class info for null resource class reference should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
   }
}
