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
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_deleteDomain extends TestAccessControlBase {
   @Test
   public void deleteDomain_validAsSystemResource() {
      authenticateSystemResource();

      final String obsoleteDomain = generateDomain();
      final String otherDomain = generateDomain();

      assertThat(accessControlContext.getDomainDescendants(obsoleteDomain).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(obsoleteDomain), hasItem(obsoleteDomain));
      assertThat(accessControlContext.getDomainDescendants(otherDomain).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(otherDomain), hasItem(otherDomain));

      // delete domain and verify
      assertThat(accessControlContext.deleteDomain(obsoleteDomain), is(true));

      assertThat(accessControlContext.getDomainDescendants(obsoleteDomain).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(otherDomain).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(otherDomain), hasItem(otherDomain));
   }

   @Test
   public void deleteDomain_validAsAuthenticatedResource() {
      authenticateSystemResource();
      final String obsoleteDomain = generateUniqueDomainName();
      final String otherDomain = generateUniqueDomainName();

      // set up an authenticatable resource with resource class create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      grantDomainCreatePermission(authenticatedResource, DomainPermissions.getInstance(DomainPermissions.DELETE));

      accessControlContext.createDomain(obsoleteDomain);
      accessControlContext.createDomain(otherDomain);

      assertThat(accessControlContext.getDomainDescendants(obsoleteDomain).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(obsoleteDomain), hasItem(obsoleteDomain));
      assertThat(accessControlContext.getDomainDescendants(otherDomain).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(otherDomain), hasItem(otherDomain));

      // delete domain and verify
      assertThat(accessControlContext.deleteDomain(obsoleteDomain), is(true));

      assertThat(accessControlContext.getDomainDescendants(obsoleteDomain).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(otherDomain).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(otherDomain), hasItem(otherDomain));
   }

   @Test
   public void deleteDomain_repeatedly_shouldSucceed() {
      authenticateSystemResource();

      final String obsoleteDomain = generateDomain();

      assertThat(accessControlContext.getDomainDescendants(obsoleteDomain).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(obsoleteDomain), hasItem(obsoleteDomain));

      // delete domain and verify
      assertThat(accessControlContext.deleteDomain(obsoleteDomain), is(true));

      // delete again and verify
      assertThat(accessControlContext.deleteDomain(obsoleteDomain), is(false));
   }

   @Test
   public void deleteDomain_rootLevel() throws Exception {
      authenticateSystemResource();

      final String domainName_parent = generateUniqueDomainName();
      final String domainName_child1 = "rd_child1Of-" + domainName_parent;
      final String domainName_child2 = "rd_child2Of-" + domainName_parent;

      accessControlContext.createDomain(domainName_parent);
      accessControlContext.createDomain(domainName_child1, domainName_parent);
      accessControlContext.createDomain(domainName_child2, domainName_parent);

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(3));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent,
                                                                                        domainName_child1,
                                                                                        domainName_child2));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItems(domainName_child1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child2).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child2), hasItems(domainName_child2));

      // delete domain and verify
      assertThat(accessControlContext.deleteDomain(domainName_parent), is(true));

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_child2).isEmpty(), is(true));
   }

   @Test
   public void deleteDomain_childLevel() throws Exception {
      authenticateSystemResource();

      final String domainName_parent = generateUniqueDomainName();
      final String domainName_child1 = "rd_child1Of-" + domainName_parent;
      final String domainName_child2 = "rd_child2Of-" + domainName_parent;

      accessControlContext.createDomain(domainName_parent);
      accessControlContext.createDomain(domainName_child1, domainName_parent);
      accessControlContext.createDomain(domainName_child2, domainName_parent);

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(3));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent,
                                                                                        domainName_child1,
                                                                                        domainName_child2));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItems(domainName_child1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child2).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child2), hasItems(domainName_child2));

      // delete domain and verify
      assertThat(accessControlContext.deleteDomain(domainName_child1), is(true));

      assertThat(accessControlContext.getDomainDescendants(domainName_child1).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_child2).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child2), hasItem(domainName_child2));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(2));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent,
                                                                                        domainName_child2));
   }

   @Test
   public void deleteDomain_grandchildLevel() throws Exception {
      authenticateSystemResource();

      final String domainName_parent = generateUniqueDomainName();
      final String domainName_child1 = "rd_child1Of-" + domainName_parent;
      final String domainName_grandchild1 = "rd_grandchild1Of-" + domainName_child1;

      accessControlContext.createDomain(domainName_parent);
      accessControlContext.createDomain(domainName_child1, domainName_parent);
      accessControlContext.createDomain(domainName_grandchild1, domainName_child1);

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(3));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent, domainName_child1, domainName_grandchild1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(2));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItems(domainName_child1,
                                                                                        domainName_grandchild1));
      assertThat(accessControlContext.getDomainDescendants(domainName_grandchild1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_grandchild1), hasItem(domainName_grandchild1));

      // delete domain and verify
      assertThat(accessControlContext.deleteDomain(domainName_grandchild1), is(true));

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(2));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent,
                                                                                        domainName_child1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItem(domainName_child1));
      assertThat(accessControlContext.getDomainDescendants(domainName_grandchild1).isEmpty(), is(true));
   }

   @Test
   public void deleteDomain_withAncestors_shouldSucceed() throws Exception {
      authenticateSystemResource();

      final String domainName_parent = generateUniqueDomainName();
      final String domainName_child1 = "rd_child1Of-" + domainName_parent;
      final String domainName_grandchild1 = "rd_grandchild1Of-" + domainName_child1;

      accessControlContext.createDomain(domainName_parent);
      accessControlContext.createDomain(domainName_child1, domainName_parent);
      accessControlContext.createDomain(domainName_grandchild1, domainName_child1);

      accessControlContext.createResource(generateResourceClass(false, false), domainName_parent);

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(3));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent,
                                                                                        domainName_child1,
                                                                                        domainName_grandchild1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(2));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItems(domainName_child1,
                                                                                        domainName_grandchild1));
      assertThat(accessControlContext.getDomainDescendants(domainName_grandchild1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_grandchild1), hasItem(domainName_grandchild1));

      // delete domain and verify
      assertThat(accessControlContext.deleteDomain(domainName_child1), is(true));

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_grandchild1).isEmpty(), is(true));
   }

   @Test
   public void deleteDomain_onlyAuthorizedOnRootLevel_shouldSucceed() throws Exception {
      // set up an authenticatable resource with domain create permissions, incl. create-child-domain
      final Resource authenticatedResource = generateResourceAndAuthenticate();

      final String domainName_parent = generateUniqueDomainName();
      final String domainName_child1 = "rd_child1Of-" + domainName_parent;
      final String domainName_grandChild1 = "rd_grandchild1Of-" + domainName_child1;

      // set up domains with delete permission
      grantDomainCreatePermission(authenticatedResource,
                                  DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                  DomainPermissions.getInstance(DomainPermissions.DELETE));
      accessControlContext.createDomain(domainName_parent);

      // set up domains without delete permission
      grantDomainCreatePermission(authenticatedResource,
                                  DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
      accessControlContext.createDomain(domainName_child1, domainName_parent);
      accessControlContext.createDomain(domainName_grandChild1, domainName_child1);

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(3));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent,
                                                                                        domainName_child1,
                                                                                        domainName_grandChild1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(2));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItems(domainName_child1,
                                                                                        domainName_grandChild1));
      assertThat(accessControlContext.getDomainDescendants(domainName_grandChild1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_grandChild1), hasItem(domainName_grandChild1));

      // delete child domain and verify
      assertThat(accessControlContext.deleteDomain(domainName_grandChild1), is(true));

      assertThat(accessControlContext.getDomainDescendants(domainName_grandChild1).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(2));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent,
                                                                                        domainName_child1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItems(domainName_child1));

      // delete parent domain and verify
      assertThat(accessControlContext.deleteDomain(domainName_parent), is(true));

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).isEmpty(), is(true));
   }

   @Test
   public void deleteDomain_onlyAuthorizedOnChildLevel_shouldFail() throws Exception {
      // set up an authenticatable resource with domain create permissions, incl. create-child-domain
      final Resource authenticatedResource = generateResourceAndAuthenticate();

      final String domainName_parent = generateUniqueDomainName();
      final String domainName_child1 = "rd_child1Of-" + domainName_parent;
      final String domainName_grandChild1 = "rd_grandchild1Of-" + domainName_child1;

      // set up domains without delete permission
      grantDomainCreatePermission(authenticatedResource,
                                  DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
      accessControlContext.createDomain(domainName_parent);

      // set up domains with delete permission
      grantDomainCreatePermission(authenticatedResource,
                                  DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                  DomainPermissions.getInstance(DomainPermissions.DELETE));
      accessControlContext.createDomain(domainName_child1, domainName_parent);
      accessControlContext.createDomain(domainName_grandChild1, domainName_child1);

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(3));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent,
                                                                                        domainName_child1,
                                                                                        domainName_grandChild1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(2));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItems(domainName_child1,
                                                                                        domainName_grandChild1));
      assertThat(accessControlContext.getDomainDescendants(domainName_grandChild1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_grandChild1), hasItem(domainName_grandChild1));

      // delete child domain and verify
      assertThat(accessControlContext.deleteDomain(domainName_grandChild1), is(true));

      assertThat(accessControlContext.getDomainDescendants(domainName_grandChild1).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(2));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent,
                                                                                        domainName_child1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItems(domainName_child1));

      // delete parent domain and verify
      try {
         accessControlContext.deleteDomain(domainName_parent);
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission(s)" ));
         assertThat(e.getMessage().toLowerCase(), containsString("on domain " + domainName_parent.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString("on domain " + domainName_child1.toLowerCase())));
      }
   }

   @Test
   public void deleteDomain_nonEmpty_shouldFail() throws Exception {
      authenticateSystemResource();

      final String domainName_parent = generateUniqueDomainName();
      final String domainName_child1 = "rd_child1Of-" + domainName_parent;
      final String domainName_child2 = "rd_child2Of-" + domainName_parent;

      accessControlContext.createDomain(domainName_parent);
      accessControlContext.createDomain(domainName_child1, domainName_parent);
      accessControlContext.createDomain(domainName_child2, domainName_parent);

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(3));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent,
                                                                                        domainName_child1,
                                                                                        domainName_child2));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItems(domainName_child1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child2).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child2), hasItems(domainName_child2));

      // set up resource(s) within the domain(s)
      accessControlContext.createResource(generateResourceClass(false, false), domainName_child2);

      // attempt to delete domain and verify
      try {
         accessControlContext.deleteDomain(domainName_child2);
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains resources directly or in a descendant domain"));
         assertThat(e.getMessage().toLowerCase(), containsString("domain (" + domainName_child2.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString("domain (" + domainName_parent.toLowerCase())));
         assertThat(e.getMessage().toLowerCase(), not(containsString("domain (" + domainName_child1.toLowerCase())));
      }
      try {
         accessControlContext.deleteDomain(domainName_parent);
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains resources directly or in a descendant domain"));
         assertThat(e.getMessage().toLowerCase(), containsString("domain (" + domainName_parent.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString("domain (" + domainName_child1.toLowerCase())));
         assertThat(e.getMessage().toLowerCase(), not(containsString("domain (" + domainName_child1.toLowerCase())));
      }

      // delete domain and verify
      assertThat(accessControlContext.deleteDomain(domainName_child1), is(true));

      assertThat(accessControlContext.getDomainDescendants(domainName_child1).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent).isEmpty(), is(false));
      assertThat(accessControlContext.getDomainDescendants(domainName_child2).isEmpty(), is(false));
   }

   @Test
   public void deleteDomain_withAllDependencies() throws Exception {
      authenticateSystemResource();

      final String unaffected_domainName = generateDomain();
      final String domainName_grandParent = generateDomain();
      final String domainName_parent = generateUniqueDomainName();
      final String domainName_child1 = "rd_child1Of-" + domainName_parent;

      accessControlContext.createDomain(domainName_parent, domainName_grandParent);
      accessControlContext.createDomain(domainName_child1, domainName_parent);

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(2));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent,
                                                                                        domainName_child1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItems(domainName_child1));

      // set up resource(s) with dependencies on the domain(s)
      final Resource parentAccessor = generateUnauthenticatableResource();
      final Resource childAccessor = generateUnauthenticatableResource();
      final Resource unaffectedAccessor = generateUnauthenticatableResource();

      // 1. domain permissions
      grantDomainPermission(parentAccessor, domainName_parent, DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      grantDomainPermission(childAccessor, domainName_child1, DomainPermissions.getInstance(DomainPermissions.DELETE));

      grantDomainPermission(unaffectedAccessor, unaffected_domainName, DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
      grantDomainPermission(unaffectedAccessor, domainName_grandParent, DomainPermissions.getInstance(DomainPermissions.DELETE));

      // 2. resource create permissions
      final String resourceClassName_create = generateResourceClass(true, false);
      final String permissionName_create = generateResourceClassPermission(resourceClassName_create);
      grantResourceCreatePermission(parentAccessor,
                                    resourceClassName_create,
                                    domainName_parent,
                                    permissionName_create,
                                    ResourcePermissions.INHERIT);
      grantResourceCreatePermission(childAccessor,
                                    resourceClassName_create,
                                    domainName_child1,
                                    ResourcePermissions.DELETE,
                                    permissionName_create);

      grantResourceCreatePermission(unaffectedAccessor,
                                    resourceClassName_create,
                                    domainName_grandParent,
                                    ResourcePermissions.INHERIT,
                                    permissionName_create);
      grantResourceCreatePermission(unaffectedAccessor,
                                    resourceClassName_create,
                                    unaffected_domainName,
                                    ResourcePermissions.DELETE,
                                    permissionName_create);

      // 3. global permissions
      final String resourceClassName_global = generateResourceClass(true, false);
      final String permissionName_global = generateResourceClassPermission(resourceClassName_global);
      accessControlContext.grantGlobalResourcePermissions(parentAccessor,
                                                          resourceClassName_global,
                                                          domainName_parent,
                                                          ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS),
                                                          ResourcePermissions.getInstance(permissionName_global));
      accessControlContext.grantGlobalResourcePermissions(childAccessor,
                                                          resourceClassName_global,
                                                          domainName_child1,
                                                          ResourcePermissions.getInstance(ResourcePermissions.DELETE),
                                                          ResourcePermissions.getInstance(permissionName_global));

      accessControlContext.grantGlobalResourcePermissions(unaffectedAccessor,
                                                          resourceClassName_global,
                                                          unaffected_domainName,
                                                          ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                          ResourcePermissions.getInstance(permissionName_global));
      accessControlContext.grantGlobalResourcePermissions(unaffectedAccessor,
                                                          resourceClassName_global,
                                                          domainName_grandParent,
                                                          ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS),
                                                          ResourcePermissions.getInstance(permissionName_global));

      // delete domain and verify
      assertThat(accessControlContext.deleteDomain(domainName_parent), is(true));

      assertThat(accessControlContext.getDomainDescendants(domainName_child1).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent).isEmpty(), is(true));

      assertThat(accessControlContext.getDomainPermissionsMap(parentAccessor).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainPermissionsMap(childAccessor).isEmpty(), is(true));
      assertThat(accessControlContext.getResourceCreatePermissionsMap(parentAccessor).isEmpty(), is(true));
      assertThat(accessControlContext.getResourceCreatePermissionsMap(childAccessor).isEmpty(), is(true));
      assertThat(accessControlContext.getGlobalResourcePermissionsMap(parentAccessor).isEmpty(), is(true));
      assertThat(accessControlContext.getGlobalResourcePermissionsMap(childAccessor).isEmpty(), is(true));

      assertThat(accessControlContext.getDomainDescendants(unaffected_domainName).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_grandParent).size(), is(1));

      assertThat(accessControlContext.getDomainPermissionsMap(unaffectedAccessor).size(), is(2));
      assertThat(accessControlContext.getResourceCreatePermissionsMap(unaffectedAccessor).size(), is(2));
      assertThat(accessControlContext.getGlobalResourcePermissionsMap(unaffectedAccessor).size(), is(2));
   }

   @Test
   public void deleteDomain_whitespaceConsistent() throws Exception {
      authenticateSystemResource();

      final String domainName = generateUniqueDomainName().trim();
      final String domainNameWhitespaced = " " + domainName + "\t";

      accessControlContext.createDomain(domainName);

      assertThat(accessControlContext.getDomainDescendants(domainName).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName), hasItem(domainName));

      assertThat(accessControlContext.getDomainDescendants(domainNameWhitespaced).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainNameWhitespaced), hasItem(domainName));

      // delete and verify
      accessControlContext.deleteDomain(domainNameWhitespaced);

      assertThat(accessControlContext.getDomainDescendants(domainName).isEmpty(), is(true));
      assertThat(accessControlContext.getDomainDescendants(domainNameWhitespaced).isEmpty(), is(true));
   }

   @Test
   public void deleteDomain_caseSensitiveConsistent() throws Exception {
      authenticateSystemResource();

      final String domainNameBase = generateUniqueDomainName();
      final String domainName_lower = domainNameBase + "_ddd";
      final String domainName_UPPER = domainNameBase + "_DDD";

      accessControlContext.createDomain(domainName_lower);

      assertThat(accessControlContext.getDomainDescendants(domainName_lower).isEmpty(), is(false));

      if (isDatabaseCaseSensitive()) {
         assertThat(accessControlContext.deleteDomain(domainName_UPPER), is(false));
         assertThat(accessControlContext.getDomainDescendants(domainName_lower).isEmpty(), is(false));
      }
      else {
         accessControlContext.deleteDomain(domainName_UPPER);

         assertThat(accessControlContext.getDomainDescendants(domainName_lower).isEmpty(), is(true));
         assertThat(accessControlContext.getDomainDescendants(domainName_UPPER).isEmpty(), is(true));
      }
   }

   @Test
   public void deleteDomain_null_shouldFail() throws Exception {
      authenticateSystemResource();

      // attempt to delete domain with null name
      try {
         accessControlContext.deleteDomain(null);
         fail("deleting a domain with a null domain reference should fail");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("none specified"));
      }
   }

   @Test
   public void deleteDomain_blankDomainName_shouldFail() throws Exception {
      authenticateSystemResource();

      // attempt to delete domain with empty or blank name
      try {
         accessControlContext.deleteDomain("");
         fail("deleting a domain with empty name should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("none specified"));
      }

      try {
         accessControlContext.deleteDomain(" \t");
         fail("deleting a domain with empty name should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("none specified"));
      }
   }

   @Test
   public void deleteDomain_nonExistentReferences_shouldSucceed() throws Exception {
      authenticateSystemResource();

      final String invalid_domain_name = "invalid_domain_name";
      assertThat(accessControlContext.getDomainDescendants(invalid_domain_name).isEmpty(), is(true));

      // attempt to delete and verify
      assertThat(accessControlContext.deleteDomain(invalid_domain_name), is(false));
   }

   @Test
   public void deleteDomain_notAuthorized_shouldFail() throws Exception {
      // set up an authenticatable resource with domain create permissions, incl. create-child-domain
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      grantDomainAndChildCreatePermission(authenticatedResource);

      final String domainName_parent = generateUniqueDomainName();
      final String domainName_child1 = "rd_child1Of-" + domainName_parent;

      // set up domains
      accessControlContext.createDomain(domainName_parent);
      accessControlContext.createDomain(domainName_child1, domainName_parent);

      assertThat(accessControlContext.getDomainDescendants(domainName_parent).size(), is(2));
      assertThat(accessControlContext.getDomainDescendants(domainName_parent), hasItems(domainName_parent,
                                                                                        domainName_child1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1).size(), is(1));
      assertThat(accessControlContext.getDomainDescendants(domainName_child1), hasItem(domainName_child1));

      // attempt to delete domain and verify
      try {
         accessControlContext.deleteDomain(domainName_child1);
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission(s)" ));
         assertThat(e.getMessage().toLowerCase(), containsString("on domain " + domainName_child1.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString("on domain " + domainName_parent.toLowerCase())));
      }
      try {
         accessControlContext.deleteDomain(domainName_parent);
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission(s)" ));
         assertThat(e.getMessage().toLowerCase(), containsString("on domain " + domainName_parent.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString("on domain " + domainName_child1.toLowerCase())));
      }
   }
}
