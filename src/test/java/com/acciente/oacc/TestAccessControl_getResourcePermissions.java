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
            = setOf(ResourcePermissions.getInstance(inheritedPermissionName, true));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getResourcePermissions(donorResource, accessedResource), is(donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getResourcePermissions(accessorResource, donorResource), is(inheritResourcePermissions));

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

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, accessedDomain, globalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, accessedDomain), is(globalResourcePermissions));

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

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, parentDomain, domainInheritedGlobalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, parentDomain), is(domainInheritedGlobalResourcePermissions));

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
      donorResourcePermissions.add(ResourcePermissions.getInstance(inheritedPermissionName, true));

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

      final Resource accessorResource = generateUnauthenticatableResource();
      try {
         accessControlContext.getResourcePermissions(accessorResource, null);
         fail("getting permissions with null accessed resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
   }

   @Test
   public void getResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource validResource = generateUnauthenticatableResource();
      final Resource invalidResource = Resources.getInstance(-999L);

      try {
         accessControlContext.getResourcePermissions(invalidResource, validResource);
         fail("getting resource permissions with invalid accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getResourcePermissions(validResource, invalidResource);
         fail("getting resource permissions with invalid accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
   }
}
