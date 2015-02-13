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

public class TestAccessControl_getResourceClassInfoByResource extends TestAccessControlBase {
   @Test
   public void getResourceClassInfoByResource_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource queriedResource = accessControlContext.createResource(resourceClassName,
                                                                           PasswordCredentials.newInstance(generateUniquePassword()));

      // verify
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(queriedResource);
      assertThat(resourceClassInfo, is(not(nullValue())));
      assertThat(resourceClassInfo.getResourceClassName(), is(resourceClassName));
      assertThat(resourceClassInfo.isAuthenticatable(), is(true));
      assertThat(resourceClassInfo.isUnauthenticatedCreateAllowed(), is(false));
   }

   @Test
   public void getResourceClassInfoByResource_validAsAuthenticated() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, true);
      final Resource queriedResource = accessControlContext.createResource(resourceClassName);

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(queriedResource);
      assertThat(resourceClassInfo, is(not(nullValue())));
      assertThat(resourceClassInfo.getResourceClassName(), is(resourceClassName));
      assertThat(resourceClassInfo.isAuthenticatable(), is(false));
      assertThat(resourceClassInfo.isUnauthenticatedCreateAllowed(), is(true));
   }

   @Test
   public void getResourceClassInfoByResource_nonExistentReferences_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      generateResourceClass(false, false);

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getResourceClassInfoByResource(Resources.getInstance(-999L));
         fail("getting resource class info by resource for non-existent resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not determine resource class for resource"));
      }
   }

   @Test
   public void getResourceClassInfoByResource_nulls() throws AccessControlException {
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      generateResourceClass(false, false);

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getResourceClassInfoByResource(null);
         fail("getting resource class info by resource for null resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
   }
}
