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

import java.util.Map;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_getGlobalResourcePermissions extends TestAccessControlBase {
   @Test
   public void getGlobalResourcePermissions_emptyAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String, Map<String, Set<ResourcePermission>>> allGlobalPermissions
            = accessControlContext.getGlobalResourcePermissionsMap(accessorResource);
      assertThat(allGlobalPermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();
      final Set<ResourcePermission> globalResourcePermissions
            = accessControlContext.getGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(globalResourcePermissions.isEmpty(), is(true));
   }

   @Test
   public void getGlobalResourcePermissions_emptyAsAuthenticated() {
      generateResourceAndAuthenticate();

      final Resource accessorResource = generateUnauthenticatableResource();
      grantQueryPermission(accessControlContext.getSessionResource(), accessorResource);

      final Map<String, Map<String, Set<ResourcePermission>>> allGlobalPermissions
            = accessControlContext.getGlobalResourcePermissionsMap(accessorResource);
      assertThat(allGlobalPermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();
      final Set<ResourcePermission> globalResourcePermissions
            = accessControlContext.getGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(globalResourcePermissions.isEmpty(), is(true));
   }

   @Test
   public void getGlobalResourcePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      assertThat(accessControlContext.getGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // setup global permissions
      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(generateResourceClassPermission(authenticatableResourceClassName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        sysDomainName,
                                                        permissions_pre);

      // verify
      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getGlobalResourcePermissions(accessorResource,
                                                                authenticatableResourceClassName,
                                                                sysDomainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).get(authenticatableResourceClassName), is(permissions_pre));
   }

   @Test
   public void getGlobalResourcePermissions_withExtId() {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final String externalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      assertThat(accessControlContext.getGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // setup global permissions
      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(generateResourceClassPermission(authenticatableResourceClassName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        sysDomainName,
                                                        permissions_pre);

      // verify
      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getGlobalResourcePermissions(Resources.getInstance(externalId),
                                                                authenticatableResourceClassName,
                                                                sysDomainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getGlobalResourcePermissionsMap(Resources.getInstance(externalId));
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).get(authenticatableResourceClassName), is(permissions_pre));
   }

   @Test
   public void getGlobalResourcePermissions_validAsAuthenticatedResource() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String grantorDomainName = accessControlContext.getDomainNameByResource(grantorResource);
      assertThat(accessControlContext.getGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true),
                    ResourcePermissions.getInstance(customPermissionName, true));

      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(customPermissionName));

      // setup grantor permissions
      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getGlobalResourcePermissions(grantorResource, resourceClassName, grantorDomainName),
                 is(grantorResourcePermissions));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        permissions_pre);

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // verify
      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).get(resourceClassName), is(permissions_pre));
   }

   @Test
   public void getGlobalResourcePermissions_validInheritFromParentDomain() {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      final String childDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(childDomainName, sysDomainName);
      assertThat(accessControlContext.getGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // setup global permissions on system domain
      final ResourcePermission resourcePermission_parentDomain
            = ResourcePermissions.getInstance(generateResourceClassPermission(authenticatableResourceClassName));
      Set<ResourcePermission> permissions_parentDomain_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true),
                    ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS),
                    resourcePermission_parentDomain);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        sysDomainName,
                                                        permissions_parentDomain_pre);

      // setup global permissions on child domain
      final ResourcePermission resourcePermission_childDomain = ResourcePermissions.getInstance(
            generateResourceClassPermission(authenticatableResourceClassName));
      Set<ResourcePermission> permissions_childDomain_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true),
                    resourcePermission_childDomain);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        childDomainName,
                                                        permissions_childDomain_pre);

      // verify
      final Set<ResourcePermission> permissions_post_sysDomain
            = accessControlContext.getGlobalResourcePermissions(accessorResource,
                                                                authenticatableResourceClassName,
                                                                sysDomainName);
      assertThat(permissions_post_sysDomain, is(permissions_parentDomain_pre));

      final Set<ResourcePermission> permissions_post_childDomain
            = accessControlContext.getGlobalResourcePermissions(accessorResource,
                                                                authenticatableResourceClassName,
                                                                childDomainName);
      assertThat(permissions_post_childDomain, is(permissions_childDomain_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(2));
      assertThat(permissions_post_all.get(sysDomainName).size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).get(authenticatableResourceClassName), is(permissions_parentDomain_pre));
      assertThat(permissions_post_all.get(childDomainName).get(authenticatableResourceClassName), is(permissions_childDomain_pre));
   }

   @Test
   public void getGlobalResourcePermissions_validWithInheritFromResource() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final ResourcePermission resPerm_impersonate
            = ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE);
      final ResourcePermission resPerm_impersonate_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true);
      final ResourcePermission resPerm_resetCredentials
            = ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS);
      final ResourcePermission resPerm_resetCredentials_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true);

      final String domainName = generateDomain();
      final char[] password = generateUniquePassword();
      Resource accessorResource = generateAuthenticatableResource(password, domainName);

      // set accessor's global permissions
      Set<ResourcePermission> directResourcePermissions_pre = setOf(resPerm_impersonate_withGrant,
                                                                    resPerm_resetCredentials);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        directResourcePermissions_pre);

      // set donor permissions
      Resource donorResource = generateUnauthenticatableResource();
      Set<ResourcePermission> donorResourcePermissions_pre = setOf(resPerm_impersonate,
                                                                   resPerm_resetCredentials_withGrant);
      accessControlContext.setGlobalResourcePermissions(donorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        donorResourcePermissions_pre);

      // set accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final Set<ResourcePermission> resourcePermissions_post
            = accessControlContext.getGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourcePermissions_post, is(directResourcePermissions_pre));

      final Map<String, Map<String,Set<ResourcePermission>>> allGlobalResourcePermissions
            = accessControlContext.getGlobalResourcePermissionsMap(accessorResource);
      assertThat(allGlobalResourcePermissions.size(), is(1));
      assertThat(allGlobalResourcePermissions.get(domainName).get(resourceClassName), is(directResourcePermissions_pre));
      assertThat(allGlobalResourcePermissions.get(domainName).size(), is(1));
   }

   @Test
   public void getGlobalResourcePermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String grantorDomainName = accessControlContext.getDomainNameByResource(grantorResource);
      assertThat(accessControlContext.getGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true),
                    ResourcePermissions.getInstance(customPermissionName, true));

      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(customPermissionName));

      // setup grantor permissions
      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getGlobalResourcePermissions(grantorResource,
                                                                   resourceClassName,
                                                                   grantorDomainName),
                 is(grantorResourcePermissions));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        permissions_pre);

      // authenticate without query authorization
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.getGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName);
         fail("getting global permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }

      try {
         accessControlContext.getGlobalResourcePermissionsMap(accessorResource);
         fail("getting global permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void getGlobalResourcePermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String grantorDomainName = accessControlContext.getDomainNameByResource(grantorResource);
      assertThat(accessControlContext.getGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true),
                    ResourcePermissions.getInstance(customPermissionName, true));

      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(customPermissionName));

      // setup grantor permissions
      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getGlobalResourcePermissions(grantorResource,
                                                                   resourceClassName,
                                                                   grantorDomainName),
                 is(grantorResourcePermissions));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        permissions_pre);

      // authenticate with implicit query authorization
      accessControlContext.grantResourcePermissions(grantorResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // verify
      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).get(resourceClassName), is(permissions_pre));
   }

   @Test
   public void getGlobalResourcePermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String grantorDomainName = accessControlContext.getDomainNameByResource(grantorResource);
      assertThat(accessControlContext.getGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true),
                    ResourcePermissions.getInstance(customPermissionName, true));

      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(customPermissionName));

      // setup grantor permissions
      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getGlobalResourcePermissions(grantorResource,
                                                                   resourceClassName,
                                                                   grantorDomainName),
                 is(grantorResourcePermissions));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        permissions_pre);

      // authenticate with query authorization
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // verify
      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).get(resourceClassName), is(permissions_pre));
   }

   @Test
   public void getGlobalResourcePermissions_whitespaceConsistent() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      final String domainName_whitespaced = " " + domainName + "\t";
      assertThat(accessControlContext.getGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // setup global permissions
      Set<ResourcePermission> permissions_pre 
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource, 
                                                        resourceClassName,
                                                        domainName,
                                                        permissions_pre);

      // verify
      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getGlobalResourcePermissions(accessorResource,
                                                                resourceClassName_whitespaced,
                                                                domainName_whitespaced);
      assertThat(permissions_post_specific, is(permissions_pre));
   }

   @Test
   public void getGlobalResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      try {
         accessControlContext.getGlobalResourcePermissionsMap(null);
         fail("getting direct global resource permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getGlobalResourcePermissionsMap(Resources.getInstance(null));
         fail("getting direct global resource permissions with null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      final Resource accessorResource = generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();
      try {
         accessControlContext.getGlobalResourcePermissions(null, resourceClassName, domainName);
         fail("getting direct global resource permissions with null resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getGlobalResourcePermissions(Resources.getInstance(null), resourceClassName, domainName);
         fail("getting direct global resource permissions with null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.getGlobalResourcePermissions(accessorResource, null, domainName);
         fail("getting direct global resource permissions with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getGlobalResourcePermissions(accessorResource, resourceClassName, null);
         fail("getting direct global resource permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void getGlobalResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource validResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      try {
         accessControlContext.getGlobalResourcePermissions(invalidResource, resourceClassName, domainName);
         fail("getting direct global resource permissions with invalid accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getGlobalResourcePermissions(invalidExternalResource, resourceClassName, domainName);
         fail("getting direct global resource permissions with invalid external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getGlobalResourcePermissions(mismatchedResource, resourceClassName, domainName);
         fail("getting direct global resource permissions with mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.getGlobalResourcePermissions(validResource, "invalid_resourceClassName", domainName);
         fail("getting direct global resource permissions with invalid accessed resource class reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.getGlobalResourcePermissions(validResource, resourceClassName, "invalid_domainName");
         fail("getting direct global resource permissions with invalid domain reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }
}
