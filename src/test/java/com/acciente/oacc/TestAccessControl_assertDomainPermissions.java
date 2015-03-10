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

public class TestAccessControl_assertDomainPermissions extends TestAccessControlBase {
   @Test
   public void assertDomainPermissions_succeedsAsSystemResource() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final Resource accessorResource = generateUnauthenticatableResource();

      final Set<DomainPermission> allDomainPermissions
            = accessControlContext.getEffectiveDomainPermissions(SYS_RESOURCE, domainName);

      assertThat(allDomainPermissions.size(), is(2));

      // verify
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                 true));

      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                   DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                 true));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                   DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                 true),
                                                   DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                   DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                 true));

      accessControlContext.assertDomainPermissions(domainName,
                                                   DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                   DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                 true),
                                                   DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                   DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                 true));

      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
         fail("asserting domain permission for accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
         fail("asserting domain permission for accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                      DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
         fail("asserting multiple domain permission for accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
   }

   @Test
   public void assertDomainPermissions_emptyAsAuthenticated() {
      final Resource accessorResource = generateUnauthenticatableResource();

      final String domainName = generateDomain();
      generateResourceAndAuthenticate();

      final Map<String,Set<DomainPermission>> allDomainPermissions 
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.isEmpty(), is(true));

      // verify
      try {
         accessControlContext.assertDomainPermissions(domainName,
                                                      DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
         fail("asserting domain permission for implicit authenticated accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
         fail("asserting domain permission for authenticated accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
         fail("asserting domain permission for authenticated accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                      DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
         fail("asserting multiple domain permission for authenticated accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
   }

   @Test
   public void assertDomainPermissions_validAsSystemResource() {
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

      accessControlContext.assertDomainPermissions(accessorResource, domainName1, domPerm_superuser, domPerm_child);
      accessControlContext.assertDomainPermissions(accessorResource, domainName1, domPerm_child, domPerm_superuser);

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

      accessControlContext.assertDomainPermissions(accessorResource, domainName2, domPerm_child_withGrant);
      accessControlContext.assertDomainPermissions(domainName2, domPerm_child_withGrant);
   }

   @Test
   public void assertDomainPermissions_partiallyValidAsSystemResource() {
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
      final char[] password = generateUniquePassword();
      Resource accessorResource = generateAuthenticatableResource(password);
      Set<DomainPermission> domainPermissions_pre1 = setOf(domPerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName1,
                                                      domPerm_child,
                                                      domPerm_child_withGrant);
         fail("asserting partially valid domain permission for system resource should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName1,
                                                      domPerm_child_withGrant,
                                                      domPerm_child);
         fail("asserting partially valid domain permission for system resource should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }

      // let's try another domain
      Set<DomainPermission> domainPermissions_pre2 = setOf(domPerm_child_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, domainName2, domainPermissions_pre2);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions2
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions2.size(), is(2));
      assertThat(allDomainPermissions2.get(domainName1), is(domainPermissions_pre1));
      assertThat(allDomainPermissions2.get(domainName2), is(domainPermissions_pre2));

      try {accessControlContext.assertDomainPermissions(accessorResource,
                                                        domainName2,
                                                        domPerm_child_withGrant,
                                                        domPerm_superuser);
         fail("asserting partially valid domain permissions should have failed for system resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }

      accessControlContext.assertDomainPermissions(accessorResource,
                                                   domainName2,
                                                   domPerm_child_withGrant,
                                                   domPerm_child);
      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.assertDomainPermissions(domainName1,
                                                      domPerm_child,
                                                      domPerm_child_withGrant);
         fail("asserting partially valid domain permission for implicit authenticated resource should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
   }

   @Test
   public void assertDomainPermissions_superUser_suceedsAsAuthenticatedResource() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName1 = generateDomain();

      // set super-user domain permission
      final char[] password = generateUniquePassword();
      Resource accessorResource = generateAuthenticatableResource(password);
      Set<DomainPermission> domainPermissions_pre1 = setOf(domPerm_superuser);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // get domain create permissions
      final Map<String,Set<DomainPermission>> allDomainPermissions
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertDomainPermissions(accessorResource, domainName1, domPerm_superuser_withGrant);
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   domainName1,
                                                   domPerm_child_withGrant,
                                                   domPerm_child,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_superuser);
      accessControlContext.assertDomainPermissions(domainName1,
                                                   domPerm_child_withGrant,
                                                   domPerm_child,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_superuser);
   }

   @Test
   public void assertDomainPermissions_validWithDifferingGrantingRights_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName1 = generateDomain();

      // set super-user domain permission
      final char[] password = generateUniquePassword();
      Resource accessorResource = generateAuthenticatableResource(password);
      Set<DomainPermission> domainPermissions_pre1 = setOf(domPerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // get domain create permissions
      final Map<String,Set<DomainPermission>> allDomainPermissions
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName1, domPerm_child_withGrant);
         fail("asserting domain permission with exceeding granting rights should have failed for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(domainName1, domPerm_child_withGrant);
         fail("asserting domain permission with exceeding granting rights should have failed for implicit authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }

      // let's try another domain
      authenticateSystemResource();
      final String domainName2 = generateDomain();
      Set<DomainPermission> domainPermissions_pre2 = setOf(domPerm_child_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, domainName2, domainPermissions_pre2);

      // get domain create permissions
      final Map<String,Set<DomainPermission>> allDomainPermissions2
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions2.size(), is(2));
      assertThat(allDomainPermissions2.get(domainName1), is(domainPermissions_pre1));
      assertThat(allDomainPermissions2.get(domainName2), is(domainPermissions_pre2));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertDomainPermissions(accessorResource, domainName2, domPerm_child);
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   domainName2,
                                                   domPerm_child_withGrant,
                                                   domPerm_child);
      accessControlContext.assertDomainPermissions(domainName2,
                                                   domPerm_child_withGrant,
                                                   domPerm_child);
   }

   @Test
   public void assertDomainPermissions_validWithInheritFromParentDomain() {
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
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   childDomain,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_createchilddomain_withGrant);
      accessControlContext.assertDomainPermissions(childDomain,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_createchilddomain_withGrant);
   }

   @Test
   public void assertDomainPermissions_validWithInheritFromAncestorDomainWithEmptyIntermediaryAncestors() {
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
      accessControlContext.createDomain(childDomain, parentDomain);
      final String grandChildDomain = generateUniqueDomainName();
      accessControlContext.createDomain(grandChildDomain, childDomain);
      final String greatGrandChildDomain = generateUniqueDomainName();
      accessControlContext.createDomain(greatGrandChildDomain, grandChildDomain);
      final String greatGreatGrandChildDomain = generateUniqueDomainName();
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
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   greatGreatGrandChildDomain,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_createchilddomain_withGrant);
   }

   @Test
   public void assertDomainPermissions_validWithInheritFromResource() {
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
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   domainName,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_createchilddomain_withGrant);
   }

   @Test
   public void assertDomainPermissions_validWithInheritFromAncestorDomainAndResource() {
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
      Set<ResourcePermission> inheritanceResourcePermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritanceResourcePermissions);

      // verify
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   childDomain,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_createchilddomain_withGrant);
      accessControlContext.assertDomainPermissions(childDomain,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_createchilddomain_withGrant);
   }

   @Test
   public void assertDomainPermissions_whitespaceConsistent() {
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
      accessControlContext.assertDomainPermissions(accessorResource, domainName_whitespaced, domCreatePerm_superuser);
      accessControlContext.assertDomainPermissions(domainName_whitespaced, domCreatePerm_superuser);
   }

   @Test
   public void assertDomainPermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainPermission domPerm_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final String domainName = generateDomain();

      try {
         accessControlContext.assertDomainPermissions(null, domainName, domPerm_superUser);
         fail("asserting domain permissions with null accessor resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource, null, domPerm_superUser);
         fail("asserting domain permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
      try {
         accessControlContext.assertDomainPermissions(null, domPerm_superUser);
         fail("asserting domain permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName, null);
         fail("asserting domain permissions with null domain permission reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }
      try {
         accessControlContext.assertDomainPermissions(domainName, null);
         fail("asserting domain permissions with null domain permission reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName, new DomainPermission[] {null});
         fail("asserting domain permissions with null domain permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertDomainPermissions(domainName, new DomainPermission[] {null});
         fail("asserting domain permissions with null domain permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName, domPerm_superUser, null);
         fail("asserting domain permissions with null domain permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertDomainPermissions(domainName, domPerm_superUser, null);
         fail("asserting domain permissions with null domain permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
   }

   @Test
   public void assertDomainPermissions_emptyPermissions_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName);
         fail("asserting domain permissions with null domain permission element should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("non-empty"));
      }
      try {
         accessControlContext.assertDomainPermissions(domainName);
         fail("asserting domain permissions with null domain permission element should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("non-empty"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName, new DomainPermission[] {});
         fail("asserting domain permissions with null domain permission element should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("non-empty"));
      }
      try {
         accessControlContext.assertDomainPermissions(domainName, new DomainPermission[] {});
         fail("asserting domain permissions with null domain permission element should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("non-empty"));
      }
   }

   @Test
   public void assertDomainPermissions_duplicatePermissions_shouldSucceed() {
      authenticateSystemResource();
      final DomainPermission domPerm_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final String domainName = generateDomain();

      accessControlContext.assertDomainPermissions(SYS_RESOURCE, domainName, domPerm_superUser, domPerm_superUser);
      accessControlContext.assertDomainPermissions(domainName, domPerm_superUser, domPerm_superUser);
   }

   @Test
   public void assertDomainPermissions_nonExistentReferences_shouldSucceed() {
      authenticateSystemResource();

      final DomainPermission domPerm_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final String domainName = generateDomain();
      final Resource invalidResource = Resources.getInstance(-999L);

      try {
         // the assert will "succeed" in the sense that it will fail to assert the permission on the
         // invalid resource, since that resource does not have the specified permission
         accessControlContext.assertDomainPermissions(invalidResource, domainName, domPerm_superUser);
         fail("asserting domain permissions for invalid accessor resource should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
   }

   @Test
   public void assertDomainPermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainPermission domPerm_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);

      try {
         accessControlContext.assertDomainPermissions(accessorResource, "invalid_domain", domPerm_superUser);
         fail("asserting domain permissions with invalid domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
      try {
         accessControlContext.assertDomainPermissions("invalid_domain", domPerm_superUser);
         fail("asserting domain permissions with invalid domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }
}
