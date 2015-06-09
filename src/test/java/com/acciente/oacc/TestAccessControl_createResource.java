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

import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_createResource extends TestAccessControlBase {
   @Test
   public void createResource_validAsSystemResource() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // create resource and verify
      final Resource resource = accessControlContext.createResource(resourceClassName, domainName);

      assertThat(resource, is(not(nullValue())));
      assertThat(accessControlContext.getDomainNameByResource(resource), is(domainName));
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(resource);
      assertThat(resourceClassInfo.getResourceClassName(), is(resourceClassName));
   }

   @Test
   public void createResource_validAsAuthorized() {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // set up an authenticatable resource with resource class create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantedResourcePermission = ResourcePermissions.getInstance(permissionName);
      grantResourceCreatePermission(authenticatedResource, resourceClassName, domainName, permissionName);

      Set<Resource> resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClassName,
                                                                                                   grantedResourcePermission);
      assertThat(resourcesByPermission.isEmpty(), is(true));

      // create resource and verify
      final Resource resource = accessControlContext.createResource(resourceClassName, domainName);

      assertThat(resource, is(not(nullValue())));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClassName,
                                                                                     grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(1));
      assertThat(accessControlContext.getDomainNameByResource(resource), is(domainName));
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(resource);
      assertThat(resourceClassInfo.getResourceClassName(), is(resourceClassName));

      // create another resource
      final Resource resource2 = accessControlContext.createResource(resourceClassName, domainName);

      assertThat(resource2, is(not(nullValue())));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClassName,
                                                                                     grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(2));
      assertThat(resource2.getId(), is(not(resource.getId())));
      assertThat(accessControlContext.getDomainNameByResource(resource2), is(domainName));
      final ResourceClassInfo resourceClassInfo2 = accessControlContext.getResourceClassInfoByResource(resource);
      assertThat(resourceClassInfo2.getResourceClassName(), is(resourceClassName));
   }

   @Test
   public void createResource_validAsUnauthenticated() {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, true);
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final String permissionName2 = generateResourceClassPermission(resourceClassName);

      // set up an authenticatable resource with resource class create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      grantResourceCreatePermission(authenticatedResource, resourceClassName, domainName);

      final ResourcePermission implicitResourcePermission = ResourcePermissions.getInstance(permissionName);
      final ResourcePermission implicitResourcePermission2 = ResourcePermissions.getInstance(permissionName2);
      Set<Resource> resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClassName,
                                                                                                   implicitResourcePermission);
      assertThat(resourcesByPermission.isEmpty(), is(true));
      Set<Resource> resourcesByPermission2 = accessControlContext.getResourcesByResourcePermissions(resourceClassName,
                                                                                                    implicitResourcePermission2);
      assertThat(resourcesByPermission2.isEmpty(), is(true));

      // create resource while unauthenticated and verify
      accessControlContext.unauthenticate();
      final Resource resource = accessControlContext.createResource(resourceClassName, domainName);

      assertThat(resource, is(not(nullValue())));
      // re-authenticate as System Resource (because we don't have the previous credentials) and verify created resource
      authenticateSystemResource();
      assertThat(accessControlContext.getDomainNameByResource(resource), is(domainName));
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(resource);
      assertThat(resourceClassInfo.getResourceClassName(), is(resourceClassName));

      // verify resource created while unauthenticated gets *ALL* available resource class permissions
      resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClassName,
                                                                                     implicitResourcePermission);
      assertThat(resourcesByPermission.size(), is(1));
      resourcesByPermission2 = accessControlContext.getResourcesByResourcePermissions(resourceClassName,
                                                                                      implicitResourcePermission2);
      assertThat(resourcesByPermission2.size(), is(1));
   }

   @Test
   public void createResource_whitespaceConsistent_AsAuthorized() {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // set up an authenticatable resource with resource class create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantedResourcePermission = ResourcePermissions.getInstance(permissionName);
      grantResourceCreatePermission(authenticatedResource, resourceClassName, domainName, permissionName);

      Set<Resource> resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClassName,
                                                                                                   grantedResourcePermission);
      assertThat(resourcesByPermission.isEmpty(), is(true));

      // create resource with white-spaced names and verify
      final String domainName_whitespaced = " " + domainName + "\t";
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final Resource resource = accessControlContext.createResource(resourceClassName_whitespaced, domainName_whitespaced);

      assertThat(resource, is(not(nullValue())));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClassName,
                                                                                     grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(1));

      // create another resource WITHOUT white-spaced names
      final Resource resource2 = accessControlContext.createResource(resourceClassName, domainName);

      assertThat(resource2, is(not(nullValue())));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClassName,
                                                                                     grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(2));
      assertThat(resource2.getId(), is(not(resource.getId())));
   }

   @Test
   public void createResource_caseSensitiveConsistent_AsAuthorized() {
      authenticateSystemResource();
      final String domainBase = generateUniqueDomainName();
      final String resourceClassBase = generateUniqueResourceClassName();
      final String domain_lower = domainBase + "_ddd";
      final String domain_UPPER = domainBase + "_DDD";
      final String resourceClass_lower = resourceClassBase + "_ccc";
      final String resourceClass_UPPER = resourceClassBase + "_CCC";
      final String permissionName = generateUniquePermissionName();

      if (isDatabaseCaseSensitive()) {
         accessControlContext.createDomain(domain_lower);
         accessControlContext.createDomain(domain_UPPER);
         accessControlContext.createResourceClass(resourceClass_lower,false,false);
         accessControlContext.createResourceClass(resourceClass_UPPER,false,false);
         accessControlContext.createResourcePermission(resourceClass_lower, permissionName);
         accessControlContext.createResourcePermission(resourceClass_UPPER, permissionName);

         // set up an authenticatable resource with resource class create permission
         // and an extra permission in each domain/class combo, so that we can look up
         // the resources later via that permission
         final Resource authenticatedResource = generateResourceAndAuthenticate();
         grantResourceCreatePermission(authenticatedResource, resourceClass_lower, domain_lower, permissionName);
         grantResourceCreatePermission(authenticatedResource, resourceClass_lower, domain_UPPER, permissionName);
         grantResourceCreatePermission(authenticatedResource, resourceClass_UPPER, domain_lower, permissionName);
         grantResourceCreatePermission(authenticatedResource, resourceClass_UPPER, domain_UPPER, permissionName);
         final ResourcePermission grantedResourcePermission_lower = ResourcePermissions.getInstance(permissionName);
         final ResourcePermission grantedResourcePermission_UPPER = ResourcePermissions.getInstance(permissionName);

         Set<Resource> resourcesByPermission;
         resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClass_lower,
                                                                                        grantedResourcePermission_lower);
         assertThat(resourcesByPermission.isEmpty(), is(true));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClass_UPPER,
                                                                                        grantedResourcePermission_UPPER);
         assertThat(resourcesByPermission.isEmpty(), is(true));

         // create resources with case-sensitive domain/class names and verify resources get created in different domain/classes
         final Resource resource_lowlow = accessControlContext.createResource(resourceClass_lower, domain_lower);
         assertThat(resource_lowlow, is(not(nullValue())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClass_lower,
                                                                                        grantedResourcePermission_lower);
         assertThat(resourcesByPermission.size(), is(1));

         final Resource resource_lowUP = accessControlContext.createResource(resourceClass_lower, domain_UPPER);
         assertThat(resource_lowUP, is(not(nullValue())));
         assertThat(resource_lowUP.getId(), is(not(resource_lowlow.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClass_lower,
                                                                                        grantedResourcePermission_lower);
         assertThat(resourcesByPermission.size(), is(2));

         final Resource resource_UPlow = accessControlContext.createResource(resourceClass_UPPER, domain_lower);
         assertThat(resource_UPlow, is(not(nullValue())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClass_UPPER,
                                                                                        grantedResourcePermission_UPPER);
         assertThat(resourcesByPermission.size(), is(1));

         final Resource resource_UPUP = accessControlContext.createResource(resourceClass_UPPER, domain_UPPER);
         assertThat(resource_UPUP, is(not(nullValue())));
         assertThat(resource_UPUP.getId(), is(not(resource_UPlow.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClass_UPPER,
                                                                                        grantedResourcePermission_UPPER);
         assertThat(resourcesByPermission.size(), is(2));
      }
      else {
         accessControlContext.createDomain(domain_lower);
         accessControlContext.createResourceClass(resourceClass_lower, false, false);
         accessControlContext.createResourcePermission(resourceClass_lower, permissionName);

         // set up an authenticatable resource with resource class create permission
         // so that we can look up the resources later via that permission
         final Resource authenticatedResource = generateResourceAndAuthenticate();
         grantResourceCreatePermission(authenticatedResource, resourceClass_lower, domain_lower, permissionName);
         final ResourcePermission grantedResourcePermission = ResourcePermissions.getInstance(permissionName);

         Set<Resource> resourcesByPermission;
         resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClass_lower,
                                                                                        grantedResourcePermission);
         assertThat(resourcesByPermission.isEmpty(), is(true));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClass_UPPER,
                                                                                        grantedResourcePermission);
         assertThat(resourcesByPermission.isEmpty(), is(true));

         // create resources with case-sensitive domain/class names and verify resources get created in same domain/classes
         final Resource resource_lowlow = accessControlContext.createResource(resourceClass_lower, domain_lower);
         assertThat(resource_lowlow, is(not(nullValue())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClass_lower,
                                                                                        grantedResourcePermission);
         assertThat(resourcesByPermission.size(), is(1));

         final Resource resource_lowUP = accessControlContext.createResource(resourceClass_lower, domain_UPPER);
         assertThat(resource_lowUP, is(not(nullValue())));
         assertThat(resource_lowUP.getId(), is(not(resource_lowlow.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClass_lower,
                                                                                        grantedResourcePermission);
         assertThat(resourcesByPermission.size(), is(2));

         final Resource resource_UPlow = accessControlContext.createResource(resourceClass_UPPER, domain_lower);
         assertThat(resource_UPlow, is(not(nullValue())));
         assertThat(resource_UPlow.getId(), is(not(resource_lowlow.getId())));
         assertThat(resource_UPlow.getId(), is(not(resource_lowUP.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClass_UPPER,
                                                                                        grantedResourcePermission);
         assertThat(resourcesByPermission.size(), is(3));

         final Resource resource_UPUP = accessControlContext.createResource(resourceClass_UPPER, domain_UPPER);
         assertThat(resource_UPUP, is(not(nullValue())));
         assertThat(resource_UPUP.getId(), is(not(resource_lowlow.getId())));
         assertThat(resource_UPUP.getId(), is(not(resource_lowUP.getId())));
         assertThat(resource_UPUP.getId(), is(not(resource_UPlow.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(resourceClass_UPPER,
                                                                                        grantedResourcePermission);
         assertThat(resourcesByPermission.size(), is(4));
      }
   }

   @Test
   public void createResource_authenticatableResourceClass_withoutCredentials_shouldFail() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);

      // attempt to create resource for authenticatable resource class
      try {
         accessControlContext.createResource(resourceClassName, domainName);
         fail("creating resource without credentials for authenticatable resource class should have failed");
      }
      catch (InvalidCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("credentials required"));
      }
   }

   @Test
   public void createResource_nulls_shouldFail() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // attempt to create resources with null parameters
      try {
         accessControlContext.createResource(null, domainName);
         fail("creating resource with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.createResource(resourceClassName, (String) null);
         fail("creating resource with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void createResource_emptyNames_shouldFail() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // attempt to create resources with empty or whitespace parameters
      try {
         accessControlContext.createResource("", domainName);
         fail("creating resource with empty resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.createResource(" \t", domainName);
         fail("creating resource with empty resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.createResource(resourceClassName, "");
         fail("creating resource with empty domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.createResource(resourceClassName, " \t");
         fail("creating resource with empty domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void createResource_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // attempt to create resources with non-existent references to class or domain names
      try {
         accessControlContext.createResource("does_not_exist", domainName);
         fail("creating resource with non-existent resource class name should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.createResource(resourceClassName, "does_not_exist");
         fail("creating resource with non-existent domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }

   @Test
   public void createResource_notAuthorized_shouldFail() {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      final Resource resource = generateResourceAndAuthenticate();

      // attempt to create resource without create-permission authorization
      try {
         accessControlContext.createResource(resourceClassName, domainName);
         fail("creating resource without authorization should fail");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(resource).toLowerCase()
                                                                       + " is not authorized to create resource"));
      }
   }
}
