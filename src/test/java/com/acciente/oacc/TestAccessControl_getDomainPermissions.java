/*
 * Copyright 2009-2018, Acciente LLC
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

public class TestAccessControl_getDomainPermissions extends TestAccessControlBase {
   @Test
   public void getDomainPermissions_emptyAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<DomainPermission> domainPermissions = accessControlContext.getDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions.isEmpty(), is(true));
   }

   @Test
   public void getDomainPermissions_emptyAsAuthenticated() {
      final Resource accessorResource = generateUnauthenticatableResource();

      generateResourceAndAuthenticate();
      grantQueryPermission(accessControlContext.getSessionResource(), accessorResource);

      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<DomainPermission> domainPermissions = accessControlContext.getDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions.isEmpty(), is(true));
   }

   @Test
   public void getDomainPermissions_validAsSystemResource() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domCreatePerm_child_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName1 = generateDomain();
      final String domainName2 = generateDomain();
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);

      // set domain permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> domainPermissions_pre1 = setOf(domCreatePerm_superuser, domCreatePerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // get domain permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      final Set<DomainPermission> domainPermissions_post = accessControlContext.getDomainPermissions(accessorResource, domainName1);
      assertThat(domainPermissions_post, is(domainPermissions_pre1));

      // let's try another domain
      Set<DomainPermission> domainPermissions_pre2 = setOf(domCreatePerm_child_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, domainName2, domainPermissions_pre2);

      // get domain permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions2 = accessControlContext.getDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions2.size(), is(2));
      assertThat(allDomainPermissions2.get(domainName1), is(domainPermissions_pre1));
      assertThat(allDomainPermissions2.get(domainName2), is(domainPermissions_pre2));

      final Set<DomainPermission> domainPermissions_post2 = accessControlContext.getDomainPermissions(accessorResource, domainName2);
      assertThat(domainPermissions_post2, is(domainPermissions_pre2));

      // let's try the system domain
      Set<DomainPermission> domainPermissions_pre3 = setOf(domCreatePerm_child_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, sysDomainName, domainPermissions_pre3);

      // get domain permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions3 = accessControlContext.getDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions3.size(), is(3));
      assertThat(allDomainPermissions3.get(domainName1), is(domainPermissions_pre1));
      assertThat(allDomainPermissions3.get(domainName2), is(domainPermissions_pre2));
      assertThat(allDomainPermissions3.get(sysDomainName), is(domainPermissions_pre3));

      final Set<DomainPermission> domainPermissions_post3 = accessControlContext.getDomainPermissions(accessorResource, sysDomainName);
      assertThat(domainPermissions_post3, is(domainPermissions_pre3));
   }

   @Test
   public void getDomainPermissions_withExtId() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName1 = generateDomain();

      // set domain permissions
      final String externalId = generateUniqueExternalId();
      Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);
      Set<DomainPermission> domainPermissions_pre1 = setOf(domCreatePerm_superuser, domCreatePerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // get domain permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions 
            = accessControlContext.getDomainPermissionsMap(Resources.getInstance(externalId));
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      final Set<DomainPermission> domainPermissions_post 
            = accessControlContext.getDomainPermissions(Resources.getInstance(externalId), domainName1);
      assertThat(domainPermissions_post, is(domainPermissions_pre1));
   }

   @Test
   public void getDomainPermissions_validWithInheritFromParentDomain() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_createchilddomain
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String childDomain = generateUniqueDomainName();
      final String parentDomain = generateDomain();
      accessControlContext.createDomain(childDomain, parentDomain);

      // set parent domain permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> parentDomainPermissions_pre = setOf(domPerm_superuser_withGrant, domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, parentDomain, parentDomainPermissions_pre);

      // set child domain permissions
      Set<DomainPermission> childDomainPermissions_pre = setOf(domPerm_superuser, domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, childDomain, childDomainPermissions_pre);

      // verify
      final Set<DomainPermission> childDomainPermissions_post = accessControlContext.getDomainPermissions(accessorResource, childDomain);
      assertThat(childDomainPermissions_post, is(childDomainPermissions_pre));

      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(2));
      assertThat(allDomainPermissions.get(parentDomain), is(parentDomainPermissions_pre));
      assertThat(allDomainPermissions.get(childDomain), is(childDomainPermissions_pre));
   }

   @Test
   public void getDomainPermissions_validWithInheritFromResource() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_createchilddomain
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName = generateDomain();
      Resource accessorResource = generateUnauthenticatableResource();

      // set domain permissions
      Set<DomainPermission> directDomainPermissions_pre = setOf(domPerm_superuser_withGrant, domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, domainName, directDomainPermissions_pre);

      // set donor permissions
      Resource donorResource = generateUnauthenticatableResource();
      Set<DomainPermission> donorDomainPermissions_pre = setOf(domPerm_superuser, domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(donorResource, domainName, donorDomainPermissions_pre);

      // set accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // verify
      final Set<DomainPermission> domainPermissions_post = accessControlContext.getDomainPermissions(accessorResource,
                                                                                                     domainName);
      assertThat(domainPermissions_post, is(directDomainPermissions_pre));

      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName), is(directDomainPermissions_pre));
   }

   @Test
   public void getDomainPermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName1 = generateDomain();

      // set domain permissions
      Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      Set<DomainPermission> domainPermissions_pre1 = setOf(domCreatePerm_superuser, domCreatePerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // authenticate without query authorization
      generateResourceAndAuthenticate();

      // get domain permissions and verify
      try {
         accessControlContext.getDomainPermissionsMap(accessorResource);
         fail("getting domain permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }

      try {
         accessControlContext.getDomainPermissions(accessorResource, domainName1);
         fail("getting domain permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void getDomainPermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName1 = generateDomain();

      // set domain permissions
      Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      Set<DomainPermission> domainPermissions_pre1 = setOf(domCreatePerm_superuser, domCreatePerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // authenticate with implicit query authorization
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      accessControlContext.grantResourcePermissions(authenticatableResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // get domain permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      final Set<DomainPermission> domainPermissions_post = accessControlContext.getDomainPermissions(accessorResource, domainName1);
      assertThat(domainPermissions_post, is(domainPermissions_pre1));

   }

   @Test
   public void getDomainPermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName1 = generateDomain();

      // set domain permissions
      Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      Set<DomainPermission> domainPermissions_pre1 = setOf(domCreatePerm_superuser, domCreatePerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // authenticate with implicit query authorization
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      grantQueryPermission(authenticatableResource, accessorResource);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // get domain permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      final Set<DomainPermission> domainPermissions_post = accessControlContext.getDomainPermissions(accessorResource, domainName1);
      assertThat(domainPermissions_post, is(domainPermissions_pre1));

   }

   @Test
   public void getDomainPermissions_whitespaceConsistent() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";

      // set domain permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> domainPermissions_pre = new HashSet<>();
      domainPermissions_pre.add(domCreatePerm_superuser);
      domainPermissions_pre.add(domCreatePerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName, domainPermissions_pre);

      // get domain permissions and verify
      final Set<DomainPermission> domainPermissions_post
            = accessControlContext.getDomainPermissions(accessorResource, domainName_whitespaced);
      assertThat(domainPermissions_post, is(domainPermissions_pre));
   }

   @Test
   public void getDomainPermissions_nulls_shouldFail() {
      authenticateSystemResource();

      try {
         accessControlContext.getDomainPermissionsMap(null);
         fail("getting domain permissions map with null accessor resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getDomainPermissionsMap(Resources.getInstance(null));
         fail("getting domain permissions map with null external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.getDomainPermissions(null, generateDomain());
         fail("getting domain permissions with null accessor resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getDomainPermissions(Resources.getInstance(null), generateDomain());
         fail("getting domain permissions with null external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.getDomainPermissions(generateUnauthenticatableResource(), null);
         fail("getting domain permissions with null domain reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void getDomainPermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      try {
         accessControlContext.getDomainPermissions(invalidResource, domainName);
         fail("getting domain permissions with invalid resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getDomainPermissions(invalidExternalResource, domainName);
         fail("getting domain permissions with invalid external resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getDomainPermissions(mismatchedResource, domainName);
         fail("getting domain permissions with mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.getDomainPermissions(accessorResource, "invalid_domain");
         fail("getting domain permissions with invalid domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }

      try {
         accessControlContext.getDomainPermissionsMap(invalidResource);
         fail("getting domain permissions with invalid resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getDomainPermissionsMap(invalidExternalResource);
         fail("getting domain permissions with invalid external resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getDomainPermissionsMap(mismatchedResource);
         fail("getting domain permissions with mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
   }
}
