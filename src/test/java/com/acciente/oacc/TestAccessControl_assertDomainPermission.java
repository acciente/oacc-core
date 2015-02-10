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

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_assertDomainPermission extends TestAccessControlBase {
   @Test
   public void assertDomainPermission_succeedsAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final Resource accessorResource = generateUnauthenticatableResource();

      final Set<DomainPermission> allDomainPermissions
            = accessControlContext.getEffectiveDomainPermissions(SYS_RESOURCE, domainName);

      assertThat(allDomainPermissions.size(), is(2));

      // verify
      accessControlContext.assertDomainPermission(SYS_RESOURCE,
                                                  DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                  domainName);
      accessControlContext.assertDomainPermission(SYS_RESOURCE,
                                                  DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true),
                                                  domainName);
      accessControlContext.assertDomainPermission(SYS_RESOURCE,
                                                  DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  domainName);
      accessControlContext.assertDomainPermission(SYS_RESOURCE,
                                                  DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true),
                                                  domainName);

      try {
         accessControlContext.assertDomainPermission(accessorResource,
                                                     DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                     domainName);
         fail("asserting domain permission for accessor resource when none exist should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(true));
         assertThat(e.getMessage().toLowerCase(), containsString("does not have requested permission"));
      }
      try {
         accessControlContext.assertDomainPermission(accessorResource,
                                                     DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                     domainName);
         fail("asserting domain permission for accessor resource when none exist should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(true));
         assertThat(e.getMessage().toLowerCase(), containsString("does not have requested permission"));
      }
   }

   @Test
   public void assertDomainPermission_emptyAsAuthenticated() throws AccessControlException {
      final Resource accessorResource = generateUnauthenticatableResource();

      final String domainName = generateDomain();
      generateResourceAndAuthenticate();

      final Map<String,Set<DomainPermission>> allDomainPermissions 
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.isEmpty(), is(true));

      // verify
      try {
         accessControlContext.assertDomainPermission(accessorResource,
                                                     DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                     domainName);
         fail("asserting domain permission for authenticated accessor resource when none exist should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(true));
         assertThat(e.getMessage().toLowerCase(), containsString("does not have requested permission"));
      }
      try {
         accessControlContext.assertDomainPermission(accessorResource,
                                                     DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                     domainName);
         fail("asserting domain permission for authenticated accessor resource when none exist should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(true));
         assertThat(e.getMessage().toLowerCase(), containsString("does not have requested permission"));
      }
   }

   @Test
   public void assertDomainPermission_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName1 = generateDomain();
      final String domainName2 = generateDomain();

      // set domain permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> domainPermissions_pre1 = new HashSet<>();
      domainPermissions_pre1.add(domPerm_superuser);
      domainPermissions_pre1.add(domPerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      accessControlContext.assertDomainPermission(accessorResource, domPerm_superuser, domainName1);
      accessControlContext.assertDomainPermission(accessorResource, domPerm_child, domainName1);

      // let's try another domain
      Set<DomainPermission> domainPermissions_pre2 = new HashSet<>();
      domainPermissions_pre2.add(domPerm_child_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, domainName2, domainPermissions_pre2);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions2
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions2.size(), is(2));
      assertThat(allDomainPermissions2.get(domainName1), is(domainPermissions_pre1));
      assertThat(allDomainPermissions2.get(domainName2), is(domainPermissions_pre2));

      accessControlContext.assertDomainPermission(accessorResource, domPerm_child_withGrant, domainName2);
   }

   @Test
   public void assertDomainPermission_validWithInheritFromParentDomain() throws AccessControlException {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_createchilddomain
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String childDomain = generateUniqueDomainName();
      final String parentDomain = generateDomain();
      accessControlContext.createDomain(childDomain, parentDomain);

      // set parent domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> parentDomainPermissions_pre = setOf(domPerm_superuser_withGrant, domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, parentDomain, parentDomainPermissions_pre);

      // set child domain permissions
      Set<DomainPermission> childDomainPermissions_pre = setOf(domPerm_superuser, domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, childDomain, childDomainPermissions_pre);

      // verify
      accessControlContext.assertDomainPermission(accessorResource, domPerm_superuser_withGrant, childDomain);
      accessControlContext.assertDomainPermission(accessorResource, domPerm_createchilddomain_withGrant, childDomain);
   }

   @Test
   public void assertDomainPermission_validWithInheritFromAncestorDomainWithEmptyIntermediaryAncestors() throws AccessControlException {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_createchilddomain
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String parentDomain = generateDomain();
      final String childDomain = generateUniqueDomainName();
      final String grandChildDomain = generateUniqueDomainName();
      final String greatGrandChildDomain = generateUniqueDomainName();
      final String greatGreatGrandChildDomain = generateUniqueDomainName();
      accessControlContext.createDomain(childDomain, parentDomain);
      accessControlContext.createDomain(grandChildDomain, childDomain);
      accessControlContext.createDomain(greatGrandChildDomain, grandChildDomain);
      accessControlContext.createDomain(greatGreatGrandChildDomain, greatGrandChildDomain);

      // set parent domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> parentDomainPermissions_pre = setOf(domPerm_superuser_withGrant, domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, parentDomain, parentDomainPermissions_pre);

      // set child domain permissions
      Set<DomainPermission> childDomainPermissions_pre = setOf(domPerm_superuser);
      accessControlContext.setDomainPermissions(accessorResource, childDomain, childDomainPermissions_pre);

      // set great-great-grand-child domain permissions
      Set<DomainPermission> greatGreatGrandChildDomainPermissions_pre = setOf(domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(accessorResource,
                                                greatGreatGrandChildDomain,
                                                greatGreatGrandChildDomainPermissions_pre);

      // verify
      accessControlContext.assertDomainPermission(accessorResource, domPerm_superuser_withGrant, greatGreatGrandChildDomain);
      accessControlContext.assertDomainPermission(accessorResource, domPerm_createchilddomain_withGrant, greatGreatGrandChildDomain);
   }

   @Test
   public void assertDomainPermission_validWithInheritFromResource() throws AccessControlException {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_createchilddomain
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName = generateDomain();
      Resource accessorResource = generateUnauthenticatableResource();

      // set child domain permissions
      Set<DomainPermission> directDomainPermissions_pre = new HashSet<>();
      directDomainPermissions_pre.add(domPerm_superuser_withGrant);
      directDomainPermissions_pre.add(domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, domainName, directDomainPermissions_pre);

      // set donor permissions
      Resource donorResource = generateUnauthenticatableResource();
      Set<DomainPermission> donorDomainPermissions_pre = new HashSet<>();
      donorDomainPermissions_pre.add(domPerm_superuser);
      donorDomainPermissions_pre.add(domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(donorResource, domainName, donorDomainPermissions_pre);

      // set accessor --INHERIT-> donor
      Set<ResourcePermission> inheritanceResourcePermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritanceResourcePermissions);

      // verify
      accessControlContext.assertDomainPermission(accessorResource, domPerm_superuser_withGrant, domainName);
      accessControlContext.assertDomainPermission(accessorResource, domPerm_createchilddomain_withGrant, domainName);
   }

   @Test
   public void assertDomainPermission_validWithInheritFromAncestorDomainAndResource() throws AccessControlException {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_createchilddomain
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String childDomain = generateUniqueDomainName();
      final String parentDomain = generateDomain();
      accessControlContext.createDomain(childDomain, parentDomain);

      // set parent domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> parentDomainPermissions_pre = setOf(domPerm_superuser_withGrant, domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, parentDomain, parentDomainPermissions_pre);

      // set child domain permissions
      Set<DomainPermission> childDomainPermissions_pre = setOf(domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, childDomain, childDomainPermissions_pre);

      // set donor permissions
      Resource donorResource = generateUnauthenticatableResource();
      Set<DomainPermission> parentDomainDonorPermissions_pre = setOf(domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(donorResource, childDomain, parentDomainDonorPermissions_pre);

      // set accessor --INHERIT-> donor
      Set<ResourcePermission> inheritanceResourcePermisions = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritanceResourcePermisions);

      // verify
      accessControlContext.assertDomainPermission(accessorResource, domPerm_superuser_withGrant, childDomain);
      accessControlContext.assertDomainPermission(accessorResource, domPerm_createchilddomain_withGrant, childDomain);
   }

   @Test
   public void assertDomainPermission_whitespaceConsistent() throws AccessControlException {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);

      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";

      // set domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> domainPermissions_pre = new HashSet<>();
      domainPermissions_pre.add(domCreatePerm_superuser);
      accessControlContext.setDomainPermissions(accessorResource, domainName, domainPermissions_pre);

      // get domain create permissions and verify
      accessControlContext.assertDomainPermission(accessorResource, domCreatePerm_superuser, domainName_whitespaced);
   }

   @Test
   public void assertDomainPermission_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainPermission domPerm_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final String domainName = generateDomain();

      try {
         accessControlContext.assertDomainPermission(null, domPerm_superUser, domainName);
         fail("asserting domain permissions with null accessor resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.assertDomainPermission(accessorResource, null, domainName);
         fail("asserting domain permissions with null domain permission reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.assertDomainPermission(accessorResource, domPerm_superUser, null);
         fail("asserting domain permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void assertDomainPermission_nonExistentReferences_shouldSucceed() throws AccessControlException {
      authenticateSystemResource();

      final DomainPermission domPerm_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final String domainName = generateDomain();
      final Resource invalidResource = Resources.getInstance(-999L);

      try {
         // the assert will "succeed" in the sense that it will fail to assert the permission on the
         // invalid resource, since that resource does not have the specified permission
         accessControlContext.assertDomainPermission(invalidResource, domPerm_superUser, domainName);
         fail("asserting domain permissions for invalid accessor resource should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have requested permission"));
      }
   }

   @Test
   public void assertDomainPermission_nonExistentReferences_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainPermission domPerm_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final String domainName = generateDomain();


      try {
         accessControlContext.assertDomainPermission(accessorResource, domPerm_superUser, "invalid_domain");
         fail("asserting domain permissions with invalid domain name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }
}
