/*
 * Copyright 2009-2014, Acciente LLC
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

public class TestAccessControl_getResourcesByResourcePermission extends TestAccessControlBase {
   @Test
   public void getResourcesByResourcePermission_emptyAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final String domainName = generateDomain();

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermission(resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName));
      assertThat(resourcesByPermission.isEmpty(), is(true));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName),
                                                                    domainName);
      assertThat(resourcesByPermissionAndDomain.isEmpty(), is(true));

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName));
      assertThat(resourcesByAccessorAndPermission.isEmpty(), is(true));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName),
                                                                    domainName);
      assertThat(resourcesByAccessorAndPermissionAndDomain.isEmpty(), is(true));
   }

   @Test
   public void getResourcesByResourcePermission_direct_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final String domainName = generateDomain();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, domainName);

      // set permission between sysresource and accessed
      Set<ResourcePermission> resourcePermissions = new HashSet<>();
      resourcePermissions.add(ResourcePermissions.getInstance(permissionName));
      accessControlContext.setResourcePermissions(SYS_RESOURCE, accessedResource, resourcePermissions);

      // set permission between accessor and accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);

      // verify
      Set<Resource> expectedResources = new HashSet<>();
      expectedResources.add(accessedResource);

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermission(resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName));
      assertThat(resourcesByPermission, is(expectedResources));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName),
                                                                    domainName);
      assertThat(resourcesByPermissionAndDomain, is(expectedResources));

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName),
                                                                    domainName);
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources));
   }

   @Test
   public void getResourcesByResourcePermission_direct_validAsAuthenticated() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String queriedDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource_queriedClassUnqueriedDomain
            = accessControlContext.createResource(queriedResourceClass, generateDomain());
      final Resource resource_unqueriedPermission
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);

      // set permission between accessor and accessed resources
      Set<ResourcePermission> queriedResourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermission));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedClassQueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedClassUnqueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedPermission,
                                                  setOf(ResourcePermissions.getInstance(unqueriedPermission)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));

      // verify as system resource
      final Set<Resource> expectedResources_anyDomain = setOf(resource_queriedClassQueriedDomain,
                                                              resource_queriedClassUnqueriedDomain);
      final Set<Resource> expectedResources_queriedDomain = setOf(resource_queriedClassQueriedDomain);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByPermissionAndDomain, is(expectedResources_queriedDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

   }

   @Test
   public void getResourcesByResourcePermission_unauthorized_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource= generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();

      final String queriedDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource_queriedClassUnqueriedDomain
            = accessControlContext.createResource(queriedResourceClass, generateDomain());
      final Resource resource_unqueriedPermission
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);

      // set permission between accessor and accessed resources
      Set<ResourcePermission> queriedResourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermission));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedClassQueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedClassUnqueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedPermission,
                                                  setOf(ResourcePermissions.getInstance(unqueriedPermission)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));

      // authenticate as accessor and verify
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                               queriedResourceClass,
                                                               ResourcePermissions.getInstance(queriedPermission));
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource must have impersonate, reset_credentials or inherit permission"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                               queriedResourceClass,
                                                               ResourcePermissions.getInstance(queriedPermission),
                                                               queriedDomain);
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource must have impersonate, reset_credentials or inherit permission"));
      }
   }

   @Test
   public void getResourcesByResourcePermission_authorized_shouldSucceed() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource= generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());

      final String queriedDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource_queriedClassUnqueriedDomain
            = accessControlContext.createResource(queriedResourceClass, generateDomain());
      final Resource resource_unqueriedPermission
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);

      // set permission between accessor and accessed resources
      Set<ResourcePermission> queriedResourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermission));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedClassQueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedClassUnqueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedPermission,
                                                  setOf(ResourcePermissions.getInstance(unqueriedPermission)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));

      final Set<Resource> expectedResources_anyDomain = setOf(resource_queriedClassQueriedDomain,
                                                              resource_queriedClassUnqueriedDomain);
      final Set<Resource> expectedResources_queriedDomain = setOf(resource_queriedClassQueriedDomain);

      // set permission: authenticatable --IMPERSONATE--> accessor
      accessControlContext.setResourcePermissions(authenticatableResource,
                                                  accessorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // authenticate as accessor and verify
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      // set permission: authenticatable --INHERIT--> accessor
      authenticateSystemResource();
      accessControlContext.setResourcePermissions(authenticatableResource,
                                                  accessorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate as accessor and verify
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      // set permission: authenticatable --RESET_CREDENTIALS--> accessor
      authenticateSystemResource();
      accessControlContext.setResourcePermissions(authenticatableResource,
                                                  accessorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS)));

      // authenticate as accessor and verify
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));
   }

   @Test
   public void getResourcesByResourcePermission_directWithAndWithoutGrant_validAsAuthenticated() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String queriedDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(false, false);
      final String permissionName = generateResourceClassPermission(queriedResourceClass);
      final ResourcePermission permission_withoutGrant
            = ResourcePermissions.getInstance(permissionName);
      final ResourcePermission permission_withGrant
            = ResourcePermissions.getInstance(permissionName, true);
      final Resource resource_queriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource_unqueriedDomain
            = accessControlContext.createResource(queriedResourceClass, generateDomain());
      final Resource resource_queriedDomainWithGrant
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      // set permission between accessor and accessed resources
      Set<ResourcePermission> permissions_withoutGrant = setOf(permission_withoutGrant);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedDomain,
                                                  permissions_withoutGrant);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedDomain,
                                                  permissions_withoutGrant);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedDomainWithGrant,
                                                  setOf(permission_withGrant));

      // verify as system resource
      final Set<Resource> expectedResources_withoutGrant_anyDomain = setOf(resource_queriedDomain,
                                                                           resource_unqueriedDomain,
                                                                           resource_queriedDomainWithGrant);
      final Set<Resource> expectedResources_withoutGrant_queriedDomain = setOf(resource_queriedDomain,
                                                                               resource_queriedDomainWithGrant);
      final Set<Resource> expectedResources_withGrant_queriedDomain = setOf(resource_queriedDomainWithGrant);

      Set<Resource> resourcesByAccessorAndPermissionWithoutGrant
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    permission_withoutGrant);
      assertThat(resourcesByAccessorAndPermissionWithoutGrant, is(expectedResources_withoutGrant_anyDomain));

      Set<Resource> resourcesByAccessorAndPermissionWithGrant
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    permission_withGrant);
      assertThat(resourcesByAccessorAndPermissionWithGrant, is(expectedResources_withGrant_queriedDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndDomainWithoutGrant
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    permission_withoutGrant,
                                                                    queriedDomain);
      assertThat(resourcesByAccessorAndPermissionAndDomainWithoutGrant, is(expectedResources_withoutGrant_queriedDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndDomainWithGrant
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    permission_withGrant,
                                                                    queriedDomain);
      assertThat(resourcesByAccessorAndPermissionAndDomainWithGrant, is(expectedResources_withGrant_queriedDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermissionWithoutGrant
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    permission_withoutGrant);
      assertThat(resourcesByPermissionWithoutGrant, is(expectedResources_withoutGrant_anyDomain));

      Set<Resource> resourcesByPermissionWithGrant
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    permission_withGrant);
      assertThat(resourcesByPermissionWithGrant, is(expectedResources_withGrant_queriedDomain));

      Set<Resource> resourcesByPermissionAndDomainWithoutGrant
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    permission_withoutGrant,
                                                                    queriedDomain);
      assertThat(resourcesByPermissionAndDomainWithoutGrant, is(expectedResources_withoutGrant_queriedDomain));

      Set<Resource> resourcesByPermissionAndDomainWithGrant
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    permission_withGrant,
                                                                    queriedDomain);
      assertThat(resourcesByPermissionAndDomainWithGrant, is(expectedResources_withGrant_queriedDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndDomainWithGrant
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    permission_withGrant,
                                                                    queriedDomain);
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomainWithGrant, is(expectedResources_withGrant_queriedDomain));
   }

   @Test
   public void getResourcesByResourcePermission_inherited_validAsAuthenticated() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donorResource = generateUnauthenticatableResource();

      final String queriedDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource_queriedClassUnqueriedDomain
            = accessControlContext.createResource(queriedResourceClass, generateDomain());
      final Resource resource_unqueriedPermission
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);

      // set permission between donor and accessed resources
      Set<ResourcePermission> queriedResourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermission));
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_queriedClassQueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_queriedClassUnqueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_unqueriedPermission,
                                                  setOf(ResourcePermissions.getInstance(unqueriedPermission)));
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_unqueriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));

      // set accessor --INHERIT--> donor
      Set<ResourcePermission> inheritPermission = new HashSet<>();
      inheritPermission.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritPermission);

      // verify as system resource
      final Set<Resource> expectedResources_anyDomain = setOf(resource_queriedClassQueriedDomain,
                                                              resource_queriedClassUnqueriedDomain);
      final Set<Resource> expectedResources_queriedDomain = setOf(resource_queriedClassQueriedDomain);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByPermissionAndDomain, is(expectedResources_queriedDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));
   }

   @Test
   public void getResourcesByResourcePermission_global_validAsAuthenticated() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String queriedDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final String unqueriedDomain = generateDomain();
      final Resource resource_queriedClassUnqueriedDomain
            = accessControlContext.createResource(queriedResourceClass, unqueriedDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);

      // set global permission for accessor
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        setOf(ResourcePermissions.getInstance(queriedPermission)),
                                                        queriedDomain);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        setOf(ResourcePermissions.getInstance(queriedPermission)),
                                                        unqueriedDomain);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        unqueriedResourceClass,
                                                        setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)),
                                                        queriedDomain);

      // verify as system resource
      final Set<Resource> expectedResources_anyDomain = setOf(resource_queriedClassQueriedDomain,
                                                              resource_queriedClassUnqueriedDomain);
      final Set<Resource> expectedResources_queriedDomain = setOf(resource_queriedClassQueriedDomain);


      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByPermissionAndDomain, is(expectedResources_queriedDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

   }

   @Test
   public void getResourcesByResourcePermission_domainInherited_validAsAuthenticated() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String parentDomain = generateDomain();
      final String childDomain1 = generateChildDomain(parentDomain);
      final String childDomain2 = generateChildDomain(parentDomain);
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermissionName = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_parentDomain = accessControlContext.createResource(queriedResourceClass, parentDomain);
      final Resource resource_childDomain1 = accessControlContext.createResource(queriedResourceClass, childDomain1);
      final Resource resource_childDomain2 = accessControlContext.createResource(queriedResourceClass, childDomain2);

      final String unqueriedDomain = generateDomain();
      final String unqueriedResourceClass = generateResourceClass(false, false);
      accessControlContext.createResourcePermission(unqueriedResourceClass, unqueriedPermissionName);
      final Resource resource_unqueriedClassChildDomain1
            = accessControlContext.createResource(unqueriedResourceClass, childDomain1);
      final Resource resource_unqueriedClassUnqueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, unqueriedDomain);

      // set global permission for accessor
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        setOf(ResourcePermissions.getInstance(queriedPermission)),
                                                        parentDomain);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        setOf(ResourcePermissions.getInstance(unqueriedPermissionName)),
                                                        childDomain2);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        unqueriedResourceClass,
                                                        setOf(ResourcePermissions.getInstance(unqueriedPermissionName)),
                                                        childDomain1);

      // verify as system resource
      final Set<Resource> expectedResources_anyDomain = setOf(resource_parentDomain,
                                                              resource_childDomain1,
                                                              resource_childDomain2);
      final Set<Resource> expectedResources_childDomain1 = setOf(resource_childDomain1);


      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    parentDomain);
      assertThat(resourcesByAccessorAndPermissionAndParentDomain, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndChildDomain1
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    childDomain1);
      assertThat(resourcesByAccessorAndPermissionAndChildDomain1, is(expectedResources_childDomain1));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    parentDomain);
      assertThat(resourcesByPermissionAndParentDomain, is(expectedResources_anyDomain));

      Set<Resource> resourcesByPermissionAndChildDomain1
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    childDomain1);
      assertThat(resourcesByPermissionAndChildDomain1, is(expectedResources_childDomain1));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndChildDomain1
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    childDomain1);
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndChildDomain1, is(expectedResources_childDomain1));
   }

   @Test
   public void getResourcesByResourcePermission_superUser_validAsAuthenticated() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String parentDomain = generateDomain();
      final String childDomain = generateChildDomain(parentDomain);
      final String otherDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermissionName = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_parentDomain = accessControlContext.createResource(queriedResourceClass, parentDomain);
      final Resource resource_childDomain = accessControlContext.createResource(queriedResourceClass, childDomain);
      final Resource resource_otherDomain = accessControlContext.createResource(queriedResourceClass, otherDomain);

      final String unqueriedDomain = generateDomain();
      final String unqueriedResourceClass = generateResourceClass(false, false);
      accessControlContext.createResourcePermission(unqueriedResourceClass, unqueriedPermissionName);
      final Resource resource_unqueriedClassChildDomain
            = accessControlContext.createResource(unqueriedResourceClass, childDomain);
      final Resource resource_unqueriedClassUnqueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, unqueriedDomain);
      final Resource resource_queriedClassUnqueriedDomain
            = accessControlContext.createResource(queriedResourceClass, unqueriedDomain);

      // set super-user permission for accessor
      accessControlContext.setDomainPermissions(accessorResource,
                                                parentDomain,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));
      accessControlContext.setDomainPermissions(accessorResource,
                                                otherDomain,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // verify as system resource
      final Set<Resource> expectedResources_anyDomain = setOf(resource_parentDomain,
                                                              resource_childDomain,
                                                              resource_otherDomain);
      final Set<Resource> expectedResources_parentDomain = setOf(resource_parentDomain,
                                                              resource_childDomain);
      final Set<Resource> expectedResources_childDomain = setOf(resource_childDomain);
      final Set<Resource> expectedResources_otherDomain = setOf(resource_otherDomain);


      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    parentDomain);
      assertThat(resourcesByAccessorAndPermissionAndParentDomain, is(expectedResources_parentDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndChildDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    childDomain);
      assertThat(resourcesByAccessorAndPermissionAndChildDomain, is(expectedResources_childDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndOtherDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    otherDomain);
      assertThat(resourcesByAccessorAndPermissionAndOtherDomain, is(expectedResources_otherDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    parentDomain);
      assertThat(resourcesByPermissionAndParentDomain, is(expectedResources_parentDomain));

      Set<Resource> resourcesByPermissionAndChildDomain
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    childDomain);
      assertThat(resourcesByPermissionAndChildDomain, is(expectedResources_childDomain));

      Set<Resource> resourcesByPermissionAndOtherDomain
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    otherDomain);
      assertThat(resourcesByPermissionAndOtherDomain, is(expectedResources_otherDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndOtherDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    otherDomain);
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndOtherDomain, is(expectedResources_otherDomain));
   }

   @Test
   public void getResourcesByResourcePermission_whitespaceConsistent() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String domain = generateDomain();
      final String resourceClass = generateResourceClass(false, false);
      final String permission = generateResourceClassPermission(resourceClass);
      final Resource resource = accessControlContext.createResource(resourceClass, domain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource,
                                                  setOf(ResourcePermissions.getInstance(permission)));

      final String resourceClass_whitespaced = " " + resourceClass + "\t";
      final String permission_whitespaced = " " + permission + "\t";
      final String domain_whitespaced = " " + domain + "\t";

      // verify as system resource
      final Set<Resource> expectedResources = setOf(resource);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    resourceClass_whitespaced,
                                                                    ResourcePermissions.getInstance(permission_whitespaced));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    resourceClass_whitespaced,
                                                                    ResourcePermissions.getInstance(permission_whitespaced),
                                                                    domain_whitespaced);
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermission(resourceClass_whitespaced,
                                                                    ResourcePermissions.getInstance(permission_whitespaced));
      assertThat(resourcesByPermission, is(expectedResources));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(resourceClass_whitespaced,
                                                                    ResourcePermissions.getInstance(permission_whitespaced),
                                                                    domain_whitespaced);
      assertThat(resourcesByPermissionAndDomain, is(expectedResources));
   }

   @Test
   public void getResourcesByResourcePermission_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String domain = generateDomain();
      final String resourceClass = generateResourceClass(false, false);
      final ResourcePermission resourcePermission
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClass));

      try {
         accessControlContext.getResourcesByResourcePermission(null, resourceClass, resourcePermission);
         fail("getting resources by resource permission with null accessor resource should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(null, resourceClass, resourcePermission, domain);
         fail("getting resources by resource permission with null accessor resource should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(accessorResource, null, resourcePermission);
         fail("getting resources by resource permission with null resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(accessorResource, null, resourcePermission, domain);
         fail("getting resources by resource permission with null resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(accessorResource, resourceClass, null);
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(accessorResource, resourceClass, null, domain);
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(accessorResource, resourceClass, resourcePermission, null);
         fail("getting resources by resource permission with null domain should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      // authenticate as accessor
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getResourcesByResourcePermission(null, resourcePermission);
         fail("getting resources by resource permission with null resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(null, resourcePermission, domain);
         fail("getting resources by resource permission with null resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(resourceClass, null);
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(resourceClass, null, domain);
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(resourceClass, resourcePermission, null);
         fail("getting resources by resource permission with null domain should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void getResourcesByResourcePermission_nonExistentReferences_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource nonExistentResource = Resources.getInstance(-999L);
      final String domain = generateDomain();
      final String resourceClass = generateResourceClass(false, false);
      final ResourcePermission resourcePermission
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClass));
      final ResourcePermission nonExistentPermission = ResourcePermissions.getInstance("does_not_exist");

      try {
         accessControlContext.getResourcesByResourcePermission(nonExistentResource, resourceClass, resourcePermission, domain);
         fail("getting resources by resource permission with non-existent accessor resource should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not determine resource domain for resource"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(accessorResource, "does_not_exit", resourcePermission);
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(accessorResource, "does_not_exit", resourcePermission, domain);
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(accessorResource, resourceClass, nonExistentPermission);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(accessorResource, resourceClass, nonExistentPermission, domain);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(accessorResource, resourceClass, resourcePermission, "does_not_exist");
         fail("getting resources by resource permission with non-existent domain should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }

      // authenticate as accessor
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getResourcesByResourcePermission("does_not_exit", resourcePermission);
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission("does_not_exit", resourcePermission, domain);
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(resourceClass, nonExistentPermission);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(resourceClass, nonExistentPermission, domain);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermission(resourceClass, resourcePermission, "does_not_exist");
         fail("getting resources by resource permission with non-existent domain should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }

   @Test
   public void getResourcesByResourcePermission_nonExistentReferences_shouldSucceed() throws AccessControlException {
      authenticateSystemResource();

      final Resource nonExistentResource = Resources.getInstance(-999L);
      final String resourceClass = generateResourceClass(false, false);
      final ResourcePermission resourcePermission
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClass));

      final Set<Resource> nonExistentAccessorResources
            = accessControlContext.getResourcesByResourcePermission(nonExistentResource, resourceClass, resourcePermission);
      assertThat(nonExistentAccessorResources.isEmpty(), is(true));
   }
}
