/*
 * Copyright 2009-2016, Acciente LLC
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

import java.util.Set;

import static junit.framework.TestCase.fail;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

public class TestAccessControl_deleteResource extends TestAccessControlBase {
   @Test
   public void deleteResource_validAsSystemResource() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // create resource
      final Resource resource = accessControlContext.createResource(resourceClassName, domainName);
      assertThat(resource, is(not(nullValue())));
      accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                     resource,
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(SYS_RESOURCE,
                                                                     resourceClassName,
                                                                     ResourcePermissions
                                                                           .getInstance(ResourcePermissions.INHERIT));
      assertThat(resourcesByPermission, is(setOf(resource)));

      // delete resource and verify
      assertThat(accessControlContext.deleteResource(resource), is(true));

      Set<Resource> resourcesByPermission_postDelete
            = accessControlContext.getResourcesByResourcePermissions(SYS_RESOURCE,
                                                                     resourceClassName,
                                                                     ResourcePermissions
                                                                           .getInstance(ResourcePermissions.INHERIT));
      assertThat(resourcesByPermission_postDelete.isEmpty(), is(true));

      try {
         accessControlContext.getDomainNameByResource(resource);
         fail("getting domain name for resource after deletion should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.getResourceClassInfoByResource(resource);
         fail("getting resource class info for resource after deletion should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                        resource,
                                                        ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("asserting permission on resource after deletion should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
   }

   @Test
   public void deleteResource_validAsSystemResource_withExtId() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final String externalId1 = generateUniqueExternalId();
      final String externalId2 = generateUniqueExternalId();
      final String externalId3 = generateUniqueExternalId();

      // create resources with external id
      final Resource resource1 = accessControlContext.createResource(resourceClassName, domainName, externalId1);
      assertThat(resource1, is(not(nullValue())));
      final Resource resource2 = accessControlContext.createResource(resourceClassName, domainName, externalId2);
      assertThat(resource2, is(not(nullValue())));
      final Resource resource3 = accessControlContext.createResource(resourceClassName, domainName, externalId3);
      assertThat(resource3, is(not(nullValue())));

      accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                     resource1,
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                     resource2,
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                     resource3,
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(SYS_RESOURCE,
                                                                     resourceClassName,
                                                                     ResourcePermissions
                                                                           .getInstance(ResourcePermissions.INHERIT));
      assertThat(resourcesByPermission, is(setOf(resource1, resource2, resource3)));

      // delete resource by external id
      assertThat(accessControlContext.deleteResource(Resources.getInstance(resource1.getExternalId())), is(true));

      // delete resource by external id and resource id
      assertThat(accessControlContext.deleteResource(Resources.getInstance(resource2.getId(),
                                                                           resource2.getExternalId())),
                 is(true));

      // delete resource by resource id
      assertThat(accessControlContext.deleteResource(Resources.getInstance(resource3.getId())), is(true));

      // verify
      Set<Resource> resourcesByPermission_postDelete
            = accessControlContext.getResourcesByResourcePermissions(SYS_RESOURCE,
                                                                     resourceClassName,
                                                                     ResourcePermissions
                                                                           .getInstance(ResourcePermissions.INHERIT));
      assertThat(resourcesByPermission_postDelete.isEmpty(), is(true));
   }

   @Test
   public void deleteResource_validAsAuthorized() {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // set up an authenticatable resource with resource class create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantedResourcePermission = ResourcePermissions.getInstance(permissionName);
      grantResourceCreatePermission(authenticatedResource, resourceClassName, domainName, permissionName, ResourcePermissions.DELETE);

      // create resources
      final Resource resource = accessControlContext.createResource(resourceClassName, domainName);
      final Resource resource2 = accessControlContext.createResource(resourceClassName, domainName);

      Set<Resource> resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(authenticatedResource,
                                                                                                   resourceClassName,
                                                                                                   grantedResourcePermission);
      assertThat(resourcesByPermission, is(setOf(resource, resource2)));

      // delete resource and verify
      accessControlContext.deleteResource(resource);

      Set<Resource> resourcesByPermission_postDelete
            = accessControlContext.getResourcesByResourcePermissions(authenticatedResource,
                                                                     resourceClassName,
                                                                     grantedResourcePermission);
      assertThat(resourcesByPermission_postDelete, is(setOf(resource2)));

      try {
         accessControlContext.getDomainNameByResource(resource);
         fail("getting domain name for resource after deletion should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.getResourceClassInfoByResource(resource);
         fail("getting resource class info for resource after deletion should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      // ensure even system resource doesn't have any authorization on the deleted resource
      grantQueryPermission(authenticatedResource, SYS_RESOURCE);
      try {
         accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                        resource,
                                                        ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("asserting permission on resource after deletion should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
   }

   @Test
   public void deleteResource_repeatedly_shouldSucceed() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // create resource
      final Resource resource = accessControlContext.createResource(resourceClassName, domainName);
      assertThat(resource, is(not(nullValue())));
      accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                     resource,
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(SYS_RESOURCE,
                                                                     resourceClassName,
                                                                     ResourcePermissions
                                                                           .getInstance(ResourcePermissions.INHERIT));
      assertThat(resourcesByPermission, is(setOf(resource)));

      // delete resource and verify
      assertThat(accessControlContext.deleteResource(resource), is(true));

      // delete resource again and verify
      assertThat(accessControlContext.deleteResource(resource), is(false));
   }

   @Test
   public void deleteResource_sessionResource_shouldSucceed() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource impersonatedResource
            = accessControlContext.createResource(resourceClassName,
                                                  domainName,
                                                  PasswordCredentials.newInstance(generateUniquePassword()));
      accessControlContext.setResourcePermissions(impersonatedResource,
                                                  impersonatedResource,
                                                  setOf(ResourcePermissions
                                                              .getInstance(ResourcePermissions.DELETE)));

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource authenticatedResource = generateAuthenticatableResource(password);
      accessControlContext.setResourcePermissions(authenticatedResource,
                                                  impersonatedResource,
                                                  setOf(ResourcePermissions
                                                              .getInstance(ResourcePermissions.IMPERSONATE)));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(authenticatedResource,
                                                                     resourceClassName,
                                                                     ResourcePermissions
                                                                           .getInstance(ResourcePermissions.IMPERSONATE));
      assertThat(resourcesByPermission, is(setOf(impersonatedResource)));

      // authenticate and then impersonate another resource
      accessControlContext.authenticate(authenticatedResource, PasswordCredentials.newInstance(password));
      accessControlContext.impersonate(impersonatedResource);
      assertThat(accessControlContext.getAuthenticatedResource(), is(authenticatedResource));
      assertThat(accessControlContext.getSessionResource(), is(impersonatedResource));

      // delete resource and verify
      accessControlContext.deleteResource(impersonatedResource);

      assertThat(accessControlContext.getAuthenticatedResource(), is(authenticatedResource));
      assertThat(accessControlContext.getSessionResource(), is(authenticatedResource));

      Set<Resource> resourcesByPermission_postDelete
            = accessControlContext.getResourcesByResourcePermissions(authenticatedResource,
                                                                     resourceClassName,
                                                                     ResourcePermissions
                                                                           .getInstance(ResourcePermissions.IMPERSONATE));
      assertThat(resourcesByPermission_postDelete.isEmpty(), is(true));

      try {
         accessControlContext.getDomainNameByResource(impersonatedResource);
         fail("getting domain name for resource after deletion should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.getResourceClassInfoByResource(impersonatedResource);
         fail("getting resource class info for resource after deletion should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      // ensure even system resource doesn't have any authorization on the deleted resource
      grantQueryPermission(authenticatedResource, SYS_RESOURCE);
      try {
         accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                        impersonatedResource,
                                                        ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("asserting permission on resource after deletion should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
   }

   @Test
   public void deleteResource_authenticatedResource_shouldSucceed() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource authenticatedResource
            = accessControlContext.createResource(resourceClassName,
                                                  domainName,
                                                  PasswordCredentials.newInstance(password));
      accessControlContext.setResourcePermissions(authenticatedResource,
                                                  authenticatedResource,
                                                  setOf(ResourcePermissions
                                                              .getInstance(ResourcePermissions.DELETE)));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(authenticatedResource,
                                                                     resourceClassName,
                                                                     ResourcePermissions
                                                                           .getInstance(ResourcePermissions.DELETE));
      assertThat(resourcesByPermission, is(setOf(authenticatedResource)));

      // authenticate
      accessControlContext.authenticate(authenticatedResource, PasswordCredentials.newInstance(password));
      assertThat(accessControlContext.getAuthenticatedResource(), is(authenticatedResource));
      assertThat(accessControlContext.getSessionResource(), is(authenticatedResource));

      // delete resource and verify
      accessControlContext.deleteResource(authenticatedResource);

      try {
         accessControlContext.getAuthenticatedResource();
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("session not authenticated"));
      }
      try {
         accessControlContext.getSessionResource();
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("session not authenticated"));
      }

      // verify as system resource
      authenticateSystemResource();

      try {
         accessControlContext.getDomainNameByResource(authenticatedResource);
         fail("getting domain name for resource after deletion should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.getResourceClassInfoByResource(authenticatedResource);
         fail("getting resource class info for resource after deletion should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                        authenticatedResource,
                                                        ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("asserting permission on resource after deletion should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
   }

   @Test
   public void deleteResource_withAllDependencies() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantedResourcePermission = ResourcePermissions.getInstance(permissionName);

      // create resource
      final Resource obsoleteResource
            = accessControlContext.createResource(resourceClassName,
                                                  domainName,
                                                  PasswordCredentials.newInstance(generateUniquePassword()));
      assertThat(obsoleteResource, is(not(nullValue())));
      accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                     obsoleteResource,
                                                     grantedResourcePermission);

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(SYS_RESOURCE,
                                                                     resourceClassName,
                                                                     grantedResourcePermission);
      assertThat(resourcesByPermission, is(setOf(obsoleteResource)));

      // set up dependencies
      // I. dependencies as accessor
      // I.1. domainCreatePermissions
      accessControlContext
            .setDomainCreatePermissions(obsoleteResource,
                                        setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                              DomainCreatePermissions
                                                    .getInstance(DomainPermissions
                                                                       .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))));
      // I.2. domainPermissions
      final String dependentDomain = generateDomain();
      accessControlContext.setDomainPermissions(obsoleteResource,
                                                dependentDomain,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));
      // I.3. resourceCreatePermissions
      final String dependentResourceClass = generateResourceClass(true, false);
      final String dependentPermissionName = generateResourceClassPermission(dependentResourceClass);
      accessControlContext
            .setResourceCreatePermissions(obsoleteResource,
                                          dependentResourceClass,
                                          dependentDomain,
                                          setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                                                ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions
                                                                         .getInstance(ResourcePermissions.DELETE)),
                                                ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions
                                                                         .getInstance(dependentPermissionName))));
      // I.4. global resourcePermissions
      accessControlContext.setGlobalResourcePermissions(obsoleteResource,
                                                        dependentResourceClass,
                                                        dependentDomain,
                                                        setOf(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.DELETE),
                                                              ResourcePermissions.getInstance(dependentPermissionName)));
      // I.5. resourcePermissions
      final Resource dependentAccessedResource
            = accessControlContext.createResource(dependentResourceClass,
                                                  dependentDomain,
                                                  PasswordCredentials.newInstance(generateUniquePassword()));
      accessControlContext.setResourcePermissions(obsoleteResource,
                                                  dependentAccessedResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.DELETE),
                                                        ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT),
                                                        ResourcePermissions.getInstanceWithGrantOption(dependentPermissionName)));

      // II. dependencies as accessed
      // II.1. direct resourcePermissions
      final Resource dependentAccessorResource = generateUnauthenticatableResource();
      final String obsoletePermissionName = generateResourceClassPermission(resourceClassName);
      accessControlContext.setResourcePermissions(dependentAccessorResource,
                                                  obsoleteResource,
                                                  setOf(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.DELETE),
                                                        ResourcePermissions.getInstanceWithGrantOption(obsoletePermissionName)));

      // delete resource and verify
      accessControlContext.deleteResource(obsoleteResource);

      Set<Resource> resourcesByPermission_postDelete
            = accessControlContext.getResourcesByResourcePermissions(SYS_RESOURCE,
                                                                     resourceClassName,
                                                                     grantedResourcePermission);
      assertThat(resourcesByPermission_postDelete.isEmpty(), is(true));

      try {
         accessControlContext.assertResourcePermissions(dependentAccessorResource,
                                                        obsoleteResource,
                                                        ResourcePermissions.getInstance(obsoletePermissionName));
         fail("asserting permission for resource after deletion should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.assertResourcePermissions(obsoleteResource,
                                                        dependentAccessedResource,
                                                        ResourcePermissions.getInstance(dependentPermissionName));
         fail("asserting permission on resource after deletion should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
   }

   @Test
   public void deleteResource_nulls_shouldFail() {
      authenticateSystemResource();

      // attempt to delete resources with null parameters
      try {
         accessControlContext.deleteResource(null);
         fail("deleting resource with null resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
   }

   @Test
   public void deleteResource_nonExistentReferences_shouldSucceed() {
      authenticateSystemResource();

      // attempt to delete resources with non-existent references
      assertThat(accessControlContext.deleteResource(Resources.getInstance(-999L)), is(false));
      assertThat(accessControlContext.deleteResource(Resources.getInstance("invalid")), is(false));
   }

   @Test
   public void deleteResource_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      // attempt to delete resource with mis-matched external id reference
      try {
         accessControlContext.deleteResource(Resources.getInstance(-999L, "invalid"));
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
   }

   @Test
   public void deleteResource_notAuthorized_shouldFail() {
      final Resource obsoleteResource = generateUnauthenticatableResource();

      final Resource resource = generateResourceAndAuthenticate();

      // attempt to delete obsolete resource without authorization
      try {
         accessControlContext.deleteResource(obsoleteResource);
         fail("deleting resource without authorization should fail");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(resource).toLowerCase()
                                                                       + " is not authorized to delete resource"));
      }
   }
}
