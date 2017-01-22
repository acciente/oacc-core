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

import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_getResourcePermissions extends TestAccessControlBase {
   @Test
   public void getResourcePermissions_emptyAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final Set<ResourcePermission> resourcePermissions
            = accessControlContext.getResourcePermissions(accessorResource, accessedResource);
      assertThat(resourcePermissions.isEmpty(), is(true));
   }

   @Test
   public void getResourcePermissions_emptyAsAuthenticated() {
      generateResourceAndAuthenticate();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      grantQueryPermission(accessControlContext.getSessionResource(), accessorResource);

      final Set<ResourcePermission> resourcePermissions
            = accessControlContext.getResourcePermissions(accessorResource, accessedResource);
      assertThat(resourcePermissions.isEmpty(), is(true));
   }

   @Test
   public void getResourcePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup permissions
      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                    ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName)));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      // verify
      final Set<ResourcePermission> permissions_post
            = accessControlContext.getResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void getResourcePermissions_withExtId() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String accessorExternalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(accessorExternalId);
      final String accessedExternalId = generateUniqueExternalId();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName,
                                                                            generateDomain(),
                                                                            accessedExternalId);
      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup permissions
      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                    ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName)));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      // verify
      Set<ResourcePermission> permissions_post
            = accessControlContext.getResourcePermissions(Resources.getInstance(accessorExternalId), accessedResource);
      assertThat(permissions_post, is(permissions_pre));

      permissions_post
            = accessControlContext.getResourcePermissions(accessorResource, Resources.getInstance(accessedExternalId));
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void getResourcePermissions_validAsAuthenticatedResource() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                    ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      // authenticate new resource
      generateResourceAndAuthenticate();
      grantQueryPermission(accessControlContext.getSessionResource(), accessorResource);

      // verify as authenticated resource
      final Set<ResourcePermission> permissions_post
            = accessControlContext.getResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void getResourcePermissions_validWithDirect() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String directPermissionName = generateResourceClassPermission(resourceClassName);

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());

      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup direct permissions
      Set<ResourcePermission> directPermissions = setOf(ResourcePermissions.getInstance(directPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, directPermissions);
      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource), is(directPermissions));

      // verify
      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource), is(directPermissions));
   }

   @Test
   public void getResourcePermissions_validWithInherited() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String inheritedPermissionName = generateResourceClassPermission(resourceClassName);

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());

      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup donor permissions
      Set<ResourcePermission> donorResourcePermissions
            = setOf(ResourcePermissions.getInstanceWithGrantOption(inheritedPermissionName));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getResourcePermissions(donorResource, accessedResource), is(
            donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getResourcePermissions(accessorResource, donorResource), is(
            inheritResourcePermissions));

      // verify
      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));
   }

   @Test
   public void getResourcePermissions_validWithGlobal() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String directGlobalPermissionName = generateResourceClassPermission(resourceClassName);

      final Resource accessorResource = generateUnauthenticatableResource();
      final String accessedDomain = generateDomain();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, accessedDomain);

      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup global permissions
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(ResourcePermissions.getInstance(directGlobalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessedDomain,
                                                        globalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            accessedDomain), is(globalResourcePermissions));

      // verify
      final Set<ResourcePermission> permissions_post = accessControlContext.getResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post.isEmpty(), is(true));
   }

   @Test
   public void getResourcePermissions_validWithDomainInherited() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String domainInheritedGlobalPermissionName = generateResourceClassPermission(resourceClassName);

      final String parentDomain = generateDomain();
      final String childDomain = generateUniqueDomainName();
      accessControlContext.createDomain(childDomain, parentDomain);

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, childDomain);

      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup domain-inherited global permissions
      Set<ResourcePermission> domainInheritedGlobalResourcePermissions = new HashSet<>();
      domainInheritedGlobalResourcePermissions.add(ResourcePermissions.getInstance(domainInheritedGlobalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        parentDomain,
                                                        domainInheritedGlobalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            parentDomain), is(domainInheritedGlobalResourcePermissions));

      // verify
      final Set<ResourcePermission> permissions_post = accessControlContext.getResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post.isEmpty(), is(true));
   }

   @Test
   public void getResourcePermissions_validWithDirectAndInheritedAndGlobalAndDomainInherited() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String directPermissionName = generateResourceClassPermission(resourceClassName);
      final String inheritedPermissionName = generateResourceClassPermission(resourceClassName);
      final String directGlobalPermissionName = generateResourceClassPermission(resourceClassName);
      final String domainInheritedGlobalPermissionName = generateResourceClassPermission(resourceClassName);

      final String parentDomain = generateDomain();
      final String childDomain = generateUniqueDomainName();
      accessControlContext.createDomain(childDomain, parentDomain);

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, childDomain);

      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup direct permissions
      Set<ResourcePermission> directPermissions = new HashSet<>();
      directPermissions.add(ResourcePermissions.getInstance(directPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, directPermissions);
      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource), is(directPermissions));

      // setup donor permissions
      Set<ResourcePermission> donorResourcePermissions = new HashSet<>();
      donorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(inheritedPermissionName));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getResourcePermissions(donorResource, accessedResource), is(donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getResourcePermissions(accessorResource, donorResource), is(inheritResourcePermissions));

      // setup global permissions
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(ResourcePermissions.getInstance(directGlobalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, childDomain, globalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, childDomain), is(globalResourcePermissions));

      // setup domain-inherited global permissions
      Set<ResourcePermission> domainInheritedGlobalResourcePermissions = new HashSet<>();
      domainInheritedGlobalResourcePermissions.add(ResourcePermissions.getInstance(domainInheritedGlobalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, parentDomain, domainInheritedGlobalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, parentDomain), is(domainInheritedGlobalResourcePermissions));

      // verify
      final Set<ResourcePermission> permissions_post = accessControlContext.getResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(directPermissions));
   }

   @Test
   public void getResourcePermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                    ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      // authenticate without query authorization
      generateResourceAndAuthenticate();

      // verify as authenticated resource
      try {
         accessControlContext.getResourcePermissions(accessorResource, accessedResource);
         fail("getting resource permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void getResourcePermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                    ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      // authenticate with implicit query authorization
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      accessControlContext.grantResourcePermissions(authenticatableResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify as authenticated resource
      final Set<ResourcePermission> permissions_post
            = accessControlContext.getResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void getResourcePermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                    ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      // authenticate with query authorization
      generateResourceAndAuthenticate();
      grantQueryPermission(accessControlContext.getSessionResource(), accessorResource);

      // verify as authenticated resource
      final Set<ResourcePermission> permissions_post
            = accessControlContext.getResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void getResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      Resource accessedResource = generateUnauthenticatableResource();
      try {
         accessControlContext.getResourcePermissions(null, accessedResource);
         fail("getting permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getResourcePermissions(Resources.getInstance(null), accessedResource);
         fail("getting permissions with null internal/external accessor resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      final Resource accessorResource = generateUnauthenticatableResource();
      try {
         accessControlContext.getResourcePermissions(accessorResource, null);
         fail("getting permissions with null accessed resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getResourcePermissions(accessorResource, Resources.getInstance(null));
         fail("getting permissions with null internal/external accessed resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
   }

   @Test
   public void getResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource validResource = generateUnauthenticatableResource();
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      try {
         accessControlContext.getResourcePermissions(invalidResource, validResource);
         fail("getting resource permissions with invalid accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getResourcePermissions(invalidExternalResource, validResource);
         fail("getting resource permissions with invalid external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getResourcePermissions(mismatchedResource, validResource);
         fail("getting resource permissions with mismatched internal/external accessor resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.getResourcePermissions(validResource, invalidResource);
         fail("getting resource permissions with invalid accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getResourcePermissions(validResource, invalidExternalResource);
         fail("getting resource permissions with invalid external accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getResourcePermissions(validResource, mismatchedResource);
         fail("getting resource permissions with mismatched internal/external accessed resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
   }
}
