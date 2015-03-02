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
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_hasResourcePermission extends TestAccessControlBase {
   @Test
   public void hasResourcePermission_succeedsAsSystemResource() {
      authenticateSystemResource();

      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      final Resource accessedResource = accessControlContext.createResource(resourceClassName);

      // verify setup
      final Set<ResourcePermission> allResourcePermissions
            = accessControlContext.getEffectiveResourcePermissions(SYS_RESOURCE, accessedResource);
      assertThat(allResourcePermissions.isEmpty(), is(true));

      // verify
      if (!accessControlContext.hasResourcePermission(SYS_RESOURCE,
                                                      accessedResource,
                                                      ResourcePermissions.getInstance(customPermissionName))) {
         fail("checking valid resource permission for system resource should have succeeded");
      }
   }

   @Test
   public void hasResourcePermission_noPermissions_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final Resource accessedResource
            = accessControlContext.createResource(resourceClassName, PasswordCredentials.newInstance(generateUniquePassword()));

      // verify setup
      final Set<ResourcePermission> allResourcePermissions
            = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(allResourcePermissions.isEmpty(), is(true));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (accessControlContext.hasResourcePermission(accessorResource,
                                                     accessedResource,
                                                     ResourcePermissions.getInstance(customPermissionName))) {
         fail("checking resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourcePermission_direct_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasResourcePermission(accessorResource, accessedResource, customPermission)) {
         fail("checking direct resource permission for authenticated resource should have succeeded");
      }
   }

   @Test
   public void hasResourcePermission_directWithDifferentGrantingRights_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName1 = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission1_withoutGrant
            = ResourcePermissions.getInstance(customPermissionName1);
      final ResourcePermission customPermission1_withGrant
            = ResourcePermissions.getInstance(customPermissionName1, true);

      final String customPermissionName2 = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission2_withoutGrant
            = ResourcePermissions.getInstance(customPermissionName2);
      final ResourcePermission customPermission2_withGrant
            = ResourcePermissions.getInstance(customPermissionName2, true);

      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission1_withGrant, customPermission2_withoutGrant));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasResourcePermission(accessorResource, accessedResource, customPermission1_withoutGrant)) {
         fail("checking resource permission with different grant than the one granted should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasResourcePermission(accessorResource, accessedResource, customPermission1_withGrant)) {
         fail("checking resource permission with different grant than the one granted should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasResourcePermission(accessorResource, accessedResource, customPermission2_withoutGrant)) {
         fail("checking resource permission with different grant than the one granted should have succeeded for authenticated resource");
      }

      if (accessControlContext.hasResourcePermission(accessorResource, accessedResource, customPermission2_withGrant)) {
         fail("checking resource permission with grant when the one granted does not have grant should not have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourcePermission_resourceInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(donorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // setup accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasResourcePermission(accessorResource, accessedResource, customPermission)) {
         fail("checking inherited resource permission should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourcePermission_domainInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      final String accessedDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      accessControlContext.createDomain(accessedDomainName, intermediaryDomainName);

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateAuthenticatableResource(generateUniquePassword(), accessedDomainName);
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup global permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        accessedResourceClassName,
                                                        parentDomainName,
                                                        setOf(customPermission));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasResourcePermission(accessorResource, accessedResource, customPermission)) {
         fail("checking domain-inherited resource permission should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourcePermission_domainInheritedInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      final String accessedDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      accessControlContext.createDomain(accessedDomainName, intermediaryDomainName);

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateAuthenticatableResource(generateUniquePassword(), accessedDomainName);
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup global permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setGlobalResourcePermissions(donorResource,
                                                        accessedResourceClassName,
                                                        parentDomainName,
                                                        setOf(customPermission));

      // setup accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasResourcePermission(accessorResource, accessedResource, customPermission)) {
         fail("checking inherited domain-inherited  resource permission should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourcePermission_superUser_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      final String accessedDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      accessControlContext.createDomain(accessedDomainName, intermediaryDomainName);

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateAuthenticatableResource(generateUniquePassword(), accessedDomainName);
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup super-user domain permission on parent domain
      accessControlContext.setDomainPermissions(accessorResource,
                                                parentDomainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);

      if (!accessControlContext.hasResourcePermission(accessorResource, accessedResource, customPermission)) {
         fail("checking resource permission when having super-user privileges should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourcePermission_superUserInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      final String accessedDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      accessControlContext.createDomain(accessedDomainName, intermediaryDomainName);

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateAuthenticatableResource(generateUniquePassword(), accessedDomainName);
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup super-user domain permission on parent domain
      final Resource donorResource = generateUnauthenticatableResource();
      accessControlContext.setDomainPermissions(donorResource,
                                                parentDomainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // setup accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);

      if (!accessControlContext.hasResourcePermission(accessorResource, accessedResource, customPermission)) {
         fail("checking resource permission when inheriting super-user privileges should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourcePermission_superUserInvalidPermission_shouldFailAsSystemResource() {
      authenticateSystemResource();
      // setup unauthenticatable resource without any permissions
      final Resource unauthenticatableResource = generateUnauthenticatableResource();

      // verify
      try {
         accessControlContext.hasResourcePermission(SYS_RESOURCE,
                                                    unauthenticatableResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));
         fail("checking implicit resource permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext.hasResourcePermission(SYS_RESOURCE,
                                                    unauthenticatableResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("checking implicit global resource permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
   }

   @Test
   public void hasResourcePermission_nulls_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.hasResourcePermission(null, accessedResource, customPermission);
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.hasResourcePermission(accessorResource, null, customPermission);
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.hasResourcePermission(accessorResource, accessedResource, null);
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }
   }

   @Test
   public void hasResourcePermission_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      final Resource invalidResource = Resources.getInstance(-999L);
      final ResourcePermission invalidPermission = ResourcePermissions.getInstance("invalid_permission");

      try {
         accessControlContext.hasResourcePermission(invalidResource, accessedResource, customPermission);
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.hasResourcePermission(accessorResource, invalidResource, customPermission);
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not determine resource class for resource"));
      }
      try {
         accessControlContext.hasResourcePermission(accessorResource, accessedResource, invalidPermission);
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }
}
