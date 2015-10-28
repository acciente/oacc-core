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

public class TestAccessControl_getEffectiveDomainPermissions extends TestAccessControlBase {
   @Test
   public void getEffectiveDomainPermissions_emptyAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<DomainPermission> domainPermissions = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveDomainPermissions_emptyAsAuthenticated() {
      final Resource accessorResource = generateUnauthenticatableResource();

      generateResourceAndAuthenticate();
      grantQueryPermission(accessControlContext.getSessionResource(), accessorResource);

      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<DomainPermission> domainPermissions = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveDomainPermissions_validAsSystemResource() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domCreatePerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName1 = generateDomain();
      final String domainName2 = generateDomain();
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);

      // set domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> domainPermissions_pre1 = new HashSet<>();
      domainPermissions_pre1.add(domCreatePerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      final Set<DomainPermission> domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName1);
      assertThat(domainPermissions_post, is(domainPermissions_pre1));

      // let's try another domain
      Set<DomainPermission> domainPermissions_pre2 = new HashSet<>();
      domainPermissions_pre2.add(domCreatePerm_child_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, domainName2, domainPermissions_pre2);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions2 = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions2.size(), is(2));
      assertThat(allDomainPermissions2.get(domainName1), is(domainPermissions_pre1));
      assertThat(allDomainPermissions2.get(domainName2), is(domainPermissions_pre2));

      final Set<DomainPermission> domainPermissions_post2 = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName2);
      assertThat(domainPermissions_post2, is(domainPermissions_pre2));

      // let's try system domain
      Set<DomainPermission> domainPermissions_pre3 = new HashSet<>();
      domainPermissions_pre3.add(domCreatePerm_child_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, sysDomainName, domainPermissions_pre3);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions3 = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions3.size(), is(3));
      assertThat(allDomainPermissions3.get(domainName1), is(domainPermissions_pre1));
      assertThat(allDomainPermissions3.get(domainName2), is(domainPermissions_pre2));
      assertThat(allDomainPermissions3.get(sysDomainName), is(domainPermissions_pre3));

      final Set<DomainPermission> domainPermissions_post3 = accessControlContext.getEffectiveDomainPermissions(accessorResource, sysDomainName);
      assertThat(domainPermissions_post3, is(domainPermissions_pre3));
   }

   @Test
   public void getEffectiveDomainPermissions_withExtId() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domCreatePerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName1 = generateDomain();
      final String domainName2 = generateDomain();
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);

      // set domain create permissions
      final String externalId = generateUniqueExternalId();
      Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);
      Set<DomainPermission> domainPermissions_pre1 = new HashSet<>();
      domainPermissions_pre1.add(domCreatePerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions
            = accessControlContext.getEffectiveDomainPermissionsMap(Resources.getInstance(externalId));
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      final Set<DomainPermission> domainPermissions_post
            = accessControlContext.getEffectiveDomainPermissions(Resources.getInstance(externalId), domainName1);
      assertThat(domainPermissions_post, is(domainPermissions_pre1));
   }

   @Test
   public void getEffectiveDomainPermissions_validWithInheritFromParentDomain() {
      authenticateSystemResource();
      final DomainPermission domPerm_createchilddomain
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String childDomain = generateUniqueDomainName();
      final String parentDomain = generateDomain();
      accessControlContext.createDomain(childDomain, parentDomain);

      // set parent domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> parentDomainPermissions_pre = new HashSet<>();
      parentDomainPermissions_pre.add(domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, parentDomain, parentDomainPermissions_pre);

      // set child domain permissions
      Set<DomainPermission> childDomainPermissions_pre = new HashSet<>();
      childDomainPermissions_pre.add(domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, childDomain, childDomainPermissions_pre);

      // verify
      Set<DomainPermission> childDomainPermissions_expected = new HashSet<>();
      childDomainPermissions_expected.add(domPerm_createchilddomain_withGrant);

      final Set<DomainPermission> childDomainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, childDomain);
      assertThat(childDomainPermissions_post, is(childDomainPermissions_expected));

      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(2));
      assertThat(allDomainPermissions.get(parentDomain), is(parentDomainPermissions_pre));
      assertThat(allDomainPermissions.get(childDomain), is(childDomainPermissions_expected));
   }

   @Test
   public void getEffectiveDomainPermissions_validWithInheritFromAncestorDomainWithEmptyIntermediaryAncestors() {
      authenticateSystemResource();
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
      Set<DomainPermission> parentDomainPermissions_pre = new HashSet<>();
      parentDomainPermissions_pre.add(domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, parentDomain, parentDomainPermissions_pre);

      // set child domain permissions
      Set<DomainPermission> childDomainPermissions_pre = new HashSet<>();
      accessControlContext.setDomainPermissions(accessorResource, childDomain, childDomainPermissions_pre);

      // set great-great-grand-child domain permissions
      Set<DomainPermission> greatGreatGrandChildDomainPermissions_pre = new HashSet<>();
      greatGreatGrandChildDomainPermissions_pre.add(domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(accessorResource,
                                                greatGreatGrandChildDomain,
                                                greatGreatGrandChildDomainPermissions_pre);

      // verify
      Set<DomainPermission> childDomainPermissions_expected = new HashSet<>();
      childDomainPermissions_expected.add(domPerm_createchilddomain);

      Set<DomainPermission> grandChildDomainPermissions_expected = new HashSet<>();
      grandChildDomainPermissions_expected.add(domPerm_createchilddomain);

      Set<DomainPermission> greatGrandChildDomainPermissions_expected = new HashSet<>();
      greatGrandChildDomainPermissions_expected.add(domPerm_createchilddomain);

      Set<DomainPermission> greatGreatGrandChildDomainPermissions_expected = new HashSet<>();
      greatGreatGrandChildDomainPermissions_expected.add(domPerm_createchilddomain_withGrant);

      final Set<DomainPermission> greatGreatGrandChildDomainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, greatGreatGrandChildDomain);
      assertThat(greatGreatGrandChildDomainPermissions_post, is(greatGreatGrandChildDomainPermissions_expected));

      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(5));
      assertThat(allDomainPermissions.get(parentDomain), is(parentDomainPermissions_pre));
      assertThat(allDomainPermissions.get(childDomain), is(childDomainPermissions_expected));
      assertThat(allDomainPermissions.get(grandChildDomain), is(grandChildDomainPermissions_expected));
      assertThat(allDomainPermissions.get(greatGrandChildDomain), is(greatGrandChildDomainPermissions_expected));
      assertThat(allDomainPermissions.get(greatGreatGrandChildDomain), is(greatGreatGrandChildDomainPermissions_expected));
   }

   @Test
   public void getEffectiveDomainPermissions_validWithInheritFromResource() {
      authenticateSystemResource();
      final DomainPermission domPerm_createchilddomain
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName = generateDomain();
      Resource accessorResource = generateUnauthenticatableResource();

      // set child domain permissions
      Set<DomainPermission> directDomainPermissions_pre = new HashSet<>();
      directDomainPermissions_pre.add(domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, domainName, directDomainPermissions_pre);

      // set donor permissions
      Resource donorResource = generateUnauthenticatableResource();
      Set<DomainPermission> donorDomainPermissions_pre = new HashSet<>();
      donorDomainPermissions_pre.add(domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(donorResource, domainName, donorDomainPermissions_pre);

      // set accessor --INHERIT-> donor
      Set<ResourcePermission> inheritanceResourcePermisions = new HashSet<>();
      inheritanceResourcePermisions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritanceResourcePermisions);

      // verify
      Set<DomainPermission> domainPermissions_expected = new HashSet<>();
      domainPermissions_expected.add(domPerm_createchilddomain_withGrant);

      final Set<DomainPermission> domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_expected));

      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName), is(domainPermissions_expected));
   }

   @Test
   public void getEffectiveDomainPermissions_validWithInheritFromAncestorDomainAndResource() {
      authenticateSystemResource();
//      final DomainPermission domPerm_superuser_withGrant
//            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_createchilddomain
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String childDomain = generateUniqueDomainName();
      final String parentDomain = generateDomain();
      accessControlContext.createDomain(childDomain, parentDomain);

      // set parent domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> parentDomainPermissions_pre = new HashSet<>();
      parentDomainPermissions_pre.add(domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, parentDomain, parentDomainPermissions_pre);

      // set child domain permissions
      Set<DomainPermission> childDomainPermissions_pre = new HashSet<>();
      childDomainPermissions_pre.add(domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, childDomain, childDomainPermissions_pre);

      // set donor permissions
      Resource donorResource = generateUnauthenticatableResource();
      Set<DomainPermission> parentDomainDonorPermissions_pre = new HashSet<>();
      parentDomainDonorPermissions_pre.add(domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(donorResource, childDomain, parentDomainDonorPermissions_pre);

      // set accessor --INHERIT-> donor
      Set<ResourcePermission> inheritanceResourcePermisions = new HashSet<>();
      inheritanceResourcePermisions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritanceResourcePermisions);

      // verify
      Set<DomainPermission> childDomainPermissions_expected = new HashSet<>();
      childDomainPermissions_expected.add(domPerm_createchilddomain_withGrant);

      Set<DomainPermission> parentDomainPermissions_expected = new HashSet<>();
      parentDomainPermissions_expected.add(domPerm_createchilddomain);

      final Set<DomainPermission> childDomainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, childDomain);
      assertThat(childDomainPermissions_post, is(childDomainPermissions_expected));

      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(2));
      assertThat(allDomainPermissions.get(parentDomain), is(parentDomainPermissions_expected));
      assertThat(allDomainPermissions.get(childDomain), is(childDomainPermissions_expected));
   }

   @Test
   public void getEffectiveDomainPermissions_superUser_succeedsAsSystemResource() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domCreatePerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domCreatePerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);
      final DomainPermission domCreatePerm_delete
            = DomainPermissions.getInstance(DomainPermissions.DELETE);
      final DomainPermission domCreatePerm_delete_withGrant
            = DomainPermissions.getInstance(DomainPermissions.DELETE, true);

      final String domainName1 = generateDomain();
      final String domainName2 = generateDomain();

      // set domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> domainPermissions_pre1 = new HashSet<>();
      domainPermissions_pre1.add(domCreatePerm_superuser);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      Set<DomainPermission> domainPermissions_expectedSuperUser = setOf(domCreatePerm_superuser_withGrant,
                                                                        domCreatePerm_child_withGrant,
                                                                        domCreatePerm_delete_withGrant);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_expectedSuperUser));

      final Set<DomainPermission> domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName1);
      assertThat(domainPermissions_post, is(domainPermissions_expectedSuperUser));

      // let's try another domain
      Set<DomainPermission> domainPermissions_pre2 = new HashSet<>();
      domainPermissions_pre2.add(domCreatePerm_child_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, domainName2, domainPermissions_pre2);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions2 = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions2.size(), is(2));
      assertThat(allDomainPermissions2.get(domainName1), is(domainPermissions_expectedSuperUser));
      assertThat(allDomainPermissions2.get(domainName2), is(domainPermissions_pre2));

      final Set<DomainPermission> domainPermissions_post2 = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName2);
      assertThat(domainPermissions_post2, is(domainPermissions_pre2));

   }

   @Test
   public void getEffectiveDomainPermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName1 = generateDomain();

      // set domain create permissions
      Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      Set<DomainPermission> domainPermissions_pre1 = new HashSet<>();
      domainPermissions_pre1.add(domCreatePerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // authenticate without query authorization
      generateResourceAndAuthenticate();

      // get domain create permissions and verify
      try {
         accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
         fail("getting effective domain permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
      try {
         accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName1);
         fail("getting effective domain permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void getEffectiveDomainPermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName1 = generateDomain();

      // set domain create permissions
      Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      Set<DomainPermission> domainPermissions_pre1 = new HashSet<>();
      domainPermissions_pre1.add(domCreatePerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // authenticate with implicit query authorization
      final char[] password = generateUniquePassword();
      Resource authenticatableResource = generateAuthenticatableResource(password);
      accessControlContext.grantResourcePermissions(authenticatableResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      final Set<DomainPermission> domainPermissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName1);
      assertThat(domainPermissions_post, is(domainPermissions_pre1));
   }

   @Test
   public void getEffectiveDomainPermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName1 = generateDomain();

      // set domain create permissions
      Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      Set<DomainPermission> domainPermissions_pre1 = new HashSet<>();
      domainPermissions_pre1.add(domCreatePerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // authenticate with implicit query authorization
      final char[] password = generateUniquePassword();
      Resource authenticatableResource = generateAuthenticatableResource(password);
      grantQueryPermission(authenticatableResource, accessorResource);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      final Set<DomainPermission> domainPermissions_post
            = accessControlContext.getEffectiveDomainPermissions( accessorResource, domainName1);
      assertThat(domainPermissions_post, is(domainPermissions_pre1));
   }

   @Test
   public void getEffectiveDomainPermissions_whitespaceConsistent() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";

      // set domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> domainPermissions_pre = new HashSet<>();
      domainPermissions_pre.add(domCreatePerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName, domainPermissions_pre);

      // get domain create permissions and verify
      final Set<DomainPermission> domainPermissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName_whitespaced);
      assertThat(domainPermissions_post, is(domainPermissions_pre));
   }

   @Test
   public void getEffectiveDomainPermissions_nulls_shouldFail() {
      authenticateSystemResource();

      try {
         accessControlContext.getEffectiveDomainPermissionsMap(null);
         fail("getting effective domain permissions map with null accessor resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getEffectiveDomainPermissionsMap(Resources.getInstance(null));
         fail("getting effective domain permissions map with null internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.getEffectiveDomainPermissions(null, domainName);
         fail("getting effective domain permissions with null accessor resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getEffectiveDomainPermissions(Resources.getInstance(null), domainName);
         fail("getting effective domain permissions map with null internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.getEffectiveDomainPermissions(generateUnauthenticatableResource(), null);
         fail("getting effective domain permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void getEffectiveDomainPermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();

      final String domainName = generateDomain();
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      try {
         accessControlContext.getEffectiveDomainPermissions(invalidResource, domainName);
         fail("getting effective domain permissions with invalid resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveDomainPermissions(invalidExternalResource, domainName);
         fail("getting effective domain permissions with invalid external resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveDomainPermissions(mismatchedResource, domainName);
         fail("getting effective domain permissions with mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.getEffectiveDomainPermissions(accessorResource, "invalid_domain");
         fail("getting effective domain permissions with invalid domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }


      try {
         accessControlContext.getEffectiveDomainPermissionsMap(invalidResource);
         fail("getting effective domain permission map with invalid resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveDomainPermissionsMap(invalidExternalResource);
         fail("getting effective domain permissions with invalid external resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveDomainPermissionsMap(mismatchedResource);
         fail("getting effective domain permissions with mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

   }
}
