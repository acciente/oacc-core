/*
 * Copyright 2009-2017, Acciente LLC
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
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_getDomainDescendants extends TestAccessControlBase {
   @Test
   public void getDomainDescendents_validAsSystemResource() {
      authenticateSystemResource();

      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);

      assertThat(accessControlContext.getDomainDescendants(sysDomainName), is(setOf(sysDomainName)));
   }

   @Test
   public void getDomainDescendents_validAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final String domainName = generateDomain();
      final Resource accessorResource = generateAuthenticatableResource(password, domainName);

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      assertThat(accessControlContext.getDomainDescendants(sysDomainName), is(setOf(sysDomainName)));

      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getDomainDescendants(accessorDomainName), is(setOf(domainName)));
   }

   @Test
   public void getDomainDescendents_hierarchy_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String parentDomain = generateDomain();
      final String childDomain_1 = generateUniqueDomainName();
      accessControlContext.createDomain(childDomain_1, parentDomain);

      final String childDomain_2 = generateUniqueDomainName();
      accessControlContext.createDomain(childDomain_2, parentDomain);

      final String grandChildDomain_1 = generateUniqueDomainName();
      accessControlContext.createDomain(grandChildDomain_1, childDomain_2);

      final String grandChildDomain_2 = generateUniqueDomainName();
      accessControlContext.createDomain(grandChildDomain_2, childDomain_2);

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      assertThat(accessControlContext.getDomainDescendants(parentDomain),
                 is(setOf(parentDomain, childDomain_1, childDomain_2, grandChildDomain_1, grandChildDomain_2)));

      assertThat(accessControlContext.getDomainDescendants(childDomain_1),
                 is(setOf(childDomain_1)));

      assertThat(accessControlContext.getDomainDescendants(childDomain_2),
                 is(setOf(childDomain_2, grandChildDomain_1, grandChildDomain_2)));

      assertThat(accessControlContext.getDomainDescendants(grandChildDomain_1),
                 is(setOf(grandChildDomain_1)));

      assertThat(accessControlContext.getDomainDescendants(grandChildDomain_2),
                 is(setOf(grandChildDomain_2)));
   }

   @Test
   public void getDomainDescendents_whitespaceConsistent() {
      authenticateSystemResource();

      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      final String sysDomainName_whitespaced = " " + sysDomainName + "\t";

      assertThat(accessControlContext.getDomainDescendants(sysDomainName_whitespaced), is(setOf(sysDomainName)));
   }

   @Test
   public void getDomainDescendents_nonExistingDomain() {
      authenticateSystemResource();

      // because we don't have a getter for *all* domains, I'm using unique domain name for each test run
      assertThat(accessControlContext.getDomainDescendants(generateUniqueDomainName()).isEmpty(), is(true));
   }

   @Test
   public void getDomainDescendents_nulls() {
      authenticateSystemResource();

      try {
         accessControlContext.getDomainDescendants(null);
         fail("getting domain descendents' names with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }
}
