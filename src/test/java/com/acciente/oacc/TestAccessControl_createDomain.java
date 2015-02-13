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
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_createDomain extends TestAccessControlBase {
   @Test
   public void createDomain_rootLevel() throws Exception {
      authenticateSystemResource();

      // because we don't have a getter for *all* domains, I'm creating unique test domains for each test run
      final String domainName_one = generateUniqueDomainName();
      final String domainName_two = generateUniqueDomainName();
      assertThat(accessControlContext.getDomainDescendants(domainName_one).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_two).isEmpty(), is(true));

      accessControlContext.createDomain(domainName_one);
      accessControlContext.createDomain(domainName_two);

      assertThat(accessControlContext.getDomainDescendants(domainName_one).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_one), hasItem(domainName_one));

      assertThat(accessControlContext.getDomainDescendants(domainName_two).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_two), hasItem(domainName_two));
   }

   @Test
   public void createDomain_childLevel() throws Exception {
      authenticateSystemResource();

      // because we don't have a getter for *all* domains, I'm creating unique test domains for each test run
      final String domainName_parent = generateUniqueDomainName();
      final String domainName_child1 = "rd_child1Of-" + domainName_parent;
      final String domainName_child2 = "rd_child2Of-" + domainName_parent;
      assertThat(accessControlContext.getDomainDescendants(domainName_parent).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_child2).isEmpty(), is(true));

      accessControlContext.createDomain(domainName_parent);
      accessControlContext.createDomain(domainName_child1, domainName_parent);
      accessControlContext.createDomain(domainName_child2, domainName_parent);

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(3));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent, domainName_child1, domainName_child2));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItems(domainName_child1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child2).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child2), hasItems(domainName_child2));
   }

   @Test
   public void createDomain_grandchildLevel() throws Exception {
      authenticateSystemResource();

      // because we don't have a getter for *all* domains, I'm creating unique test domains for each test run
      final String domainName_parent = generateUniqueDomainName();
      final String domainName_child1 = "rd_child1Of-" + domainName_parent;
      final String domainName_grandchild1 = "rd_grandchild1Of-" + domainName_child1;
      assertThat(accessControlContext.getDomainDescendants(domainName_parent).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_grandchild1).isEmpty(), is(true));

      accessControlContext.createDomain(domainName_parent);
      accessControlContext.createDomain(domainName_child1, domainName_parent);
      accessControlContext.createDomain(domainName_grandchild1, domainName_child1);

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(3));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent, domainName_child1, domainName_grandchild1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(2));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItems(domainName_child1, domainName_grandchild1));
      assertThat(accessControlContext.getDomainDescendants(domainName_grandchild1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_grandchild1), hasItem(domainName_grandchild1));
   }

   @Test
   public void createDomain_onlyRootLevelAsAuthorized() throws Exception {
      // set up an authenticatable resource with domain create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      grantDomainCreatePermission(authenticatedResource);

      final String domainName_parent = generateUniqueDomainName();
      final String domainName_child1 = "rd_child1Of-" + domainName_parent;
      assertThat(accessControlContext.getDomainDescendants(domainName_parent).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).isEmpty(), is(true));

      // create domain and verify
      accessControlContext.createDomain(domainName_parent);

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItem(domainName_parent));

      // attempt to create a child domain without authorization
      try {
         accessControlContext.createDomain(domainName_child1, domainName_parent);
         fail("create child domain without CREATE_CHILD_DOMAIN authorization should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authorized"));
      }
      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItem(domainName_parent));
   }

   @Test
   public void createDomain_childLevelAsAuthorized() throws Exception {
      // set up an authenticatable resource with domain create and child domain create permissions
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      grantDomainAndChildCreatePermission(authenticatedResource);

      final String domainName_parent = generateUniqueDomainName();
      final String domainName_child1 = "rd_child1Of-" + domainName_parent;
      assertThat(accessControlContext.getDomainDescendants(domainName_parent).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).isEmpty(), is(true));

      // create domain and verify
      accessControlContext.createDomain(domainName_parent);
      accessControlContext.createDomain(domainName_child1, domainName_parent);

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(2));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent, domainName_child1));

      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItem(domainName_child1));
   }

   @Test
   public void createDomain_whitespaceConsistent() throws Exception {
      authenticateSystemResource();

      final String domainName = generateUniqueDomainName().trim();
      final String domainNameWhitespaced = " " + domainName + "\t";
      assertThat(accessControlContext.getDomainDescendants(domainName).isEmpty(), is(true));

      accessControlContext.createDomain(domainNameWhitespaced);

      assertThat(accessControlContext.getDomainDescendants(domainName).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName), hasItem(domainName));

      assertThat(accessControlContext.getDomainDescendants(domainNameWhitespaced).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainNameWhitespaced), hasItem(domainName));

      final String parentDomain = generateDomain();
      final String parentDomainWhitespaced = " " + parentDomain + "\t";
      final String childDomainName = generateUniqueDomainName().trim();
      final String childDomainNameWhitespaced = " " + childDomainName + "\t";

      accessControlContext.createDomain(childDomainNameWhitespaced, parentDomainWhitespaced);

      assertThat(accessControlContext.getDomainDescendants(parentDomain).size(), is(2));
      assertThat(accessControlContext.getDomainDescendants(parentDomain), hasItem(parentDomain));
      assertThat(accessControlContext.getDomainDescendants(parentDomain), hasItem(childDomainName));

      assertThat(accessControlContext.getDomainDescendants(childDomainName).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(childDomainName), hasItem(childDomainName));

      assertThat(accessControlContext.getDomainDescendants(childDomainNameWhitespaced).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(childDomainNameWhitespaced), hasItem(childDomainName));
   }

   @Test
   public void createDomain_caseSensitiveConsistent() throws Exception {
      authenticateSystemResource();

      final String domainNameBase = generateUniqueDomainName();
      final String domainName_lower = domainNameBase + "_ddd";
      final String domainName_UPPER = domainNameBase + "_DDD";
      assertThat(accessControlContext.getDomainDescendants(domainName_lower).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_UPPER).isEmpty(), is(true));

      accessControlContext.createDomain(domainName_lower);
      if (isDatabaseCaseSensitive()) {
         accessControlContext.createDomain(domainName_UPPER);

         assertThat(accessControlContext.getDomainDescendants(domainName_lower).size(), is(1));
         assertThat(accessControlContext.getDomainDescendants(domainName_lower), hasItem(domainName_lower));

         assertThat(accessControlContext.getDomainDescendants(domainName_UPPER).size(), is(1));
         assertThat(accessControlContext.getDomainDescendants(domainName_UPPER), hasItem(domainName_UPPER));
      }
      else {
         try {
            accessControlContext.createDomain(domainName_UPPER);
            fail("creating a domain with the name of an existing domain that differs in case only should have failed for case-insensitive databases");
         }
         catch (AccessControlException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("duplicate domain"));
         }
      }
   }

   @Test
   public void createDomain_duplicateDomainName_shouldFail() throws Exception {
      authenticateSystemResource();

      final String domainName = generateUniqueDomainName();
      final String otherDomainName = generateDomain();
      assertThat(accessControlContext.getDomainDescendants(domainName).isEmpty(), is(true));
      accessControlContext.createDomain(domainName);

      // attempt to create duplicate domain
      try {
         accessControlContext.createDomain(domainName);
         fail("creating a duplicate domain should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate"));
      }

      try {
         accessControlContext.createDomain(domainName, domainName);
         fail("creating a duplicate child domain should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate"));
      }

      try {
         accessControlContext.createDomain(otherDomainName, domainName);
         fail("creating a duplicate nested (but unrelated) domain should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate"));
      }

      assertThat(accessControlContext.getDomainDescendants(domainName).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName), hasItem(domainName));
      assertThat(accessControlContext.getDomainDescendants(otherDomainName).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(otherDomainName), hasItem(otherDomainName));
   }

   @Test
   public void createDomain_null_shouldFail() throws Exception {
      authenticateSystemResource();

      // attempt to create domain with null name
      try {
         accessControlContext.createDomain(null);
         fail("creating a null domain should fail");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("none specified"));
      }
   }

   @Test
   public void createDomain_blankDomainName_shouldFail() throws Exception {
      authenticateSystemResource();

      // attempt to create domain with empty or blank name
      try {
         accessControlContext.createDomain("");
         fail("creating a domain with empty name should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("none specified"));
      }

      try {
         accessControlContext.createDomain(" \t");
         fail("creating a domain with empty name should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("none specified"));
      }
   }

   @Test
   public void createDomain_nonExistentReferences_shouldFail() throws Exception {
      authenticateSystemResource();

      final String domainName = generateUniqueDomainName();
      assertThat(accessControlContext.getDomainDescendants(domainName).isEmpty(), is(true));

      try {
         accessControlContext.createDomain(domainName, "invalid_domain_name");
         fail("creating a child domain with non-existent parent domain reference should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("parent domain"));
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }

      assertThat(accessControlContext.getDomainDescendants(domainName).isEmpty(), is(true));
   }

   @Test
   public void createDomain_notAuthorized_shouldFail() throws Exception {
      final String domainName = generateUniqueDomainName();

      // attempt to create domain without authorization
      generateResourceAndAuthenticate();
      try {
         accessControlContext.createDomain(domainName);
         fail("creating a domain without authorization should fail");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authorized"));
      }
      assertThat(accessControlContext.getDomainDescendants(domainName).isEmpty(), is(true));
   }
}
