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

public class TestAccessControl_getDomainNameByResource extends TestAccessControlBase {
   @Test
   public void getDomainNameByResource_validAsSystemResource() {
      authenticateSystemResource();

      generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, true);
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      final Resource queriedResource = accessControlContext.createResource(resourceClassName, sysDomainName);

      // verify
      final String domainName = accessControlContext.getDomainNameByResource(queriedResource);
      assertThat(domainName, is(not(nullValue())));
      assertThat(domainName, is(sysDomainName));
   }

   @Test
   public void getDomainNameByResource_withExtId() {
      authenticateSystemResource();

      generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, true);
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      final String externalId = generateUniqueExternalId();
      accessControlContext.createResource(resourceClassName, sysDomainName, externalId);

      // verify
      final String domainName = accessControlContext.getDomainNameByResource(Resources.getInstance(externalId));
      assertThat(domainName, is(not(nullValue())));
      assertThat(domainName, is(sysDomainName));
   }

   @Test
   public void getDomainNameByResource_validAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, true);
      final String queriedResourceDomain = generateDomain();
      final Resource queriedResource = accessControlContext.createResource(resourceClassName, queriedResourceDomain);

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final String domainName = accessControlContext.getDomainNameByResource(queriedResource);
      assertThat(domainName, is(queriedResourceDomain));
   }

   @Test
   public void getDomainNameByResource_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      generateUnauthenticatableResource();

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getDomainNameByResource(Resources.getInstance(-999L));
         fail("getting domain name by resource for non-existent resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.getDomainNameByResource(Resources.getInstance("invalid"));
         fail("getting domain name by resource for non-existent external resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.getDomainNameByResource(Resources.getInstance(-999L, "invalid"));
         fail("getting domain name by resource for mismatched internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
   }

   @Test
   public void getDomainNameByResource_nulls() {
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      generateUnauthenticatableResource();

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getDomainNameByResource(null);
         fail("getting resource class info by resource for null resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getDomainNameByResource(Resources.getInstance(null));
         fail("getting resource class info by resource for null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
   }
}
