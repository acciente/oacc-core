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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_hasResourceCreatePermissions extends TestAccessControlBase {
   @Test
   public void hasResourceCreatePermissions_succeedsAsSystemResource() {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final String domainName = generateDomain();

      // verify setup
      final Set<ResourceCreatePermission> directResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getResourceCreatePermissions(SYS_RESOURCE, resourceClassName, domainName);
      assertThat(directResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          ResourceCreatePermissions
                                                .getInstance(ResourceCreatePermissions.CREATE))) {
         fail("checking implicit system resource create permission for domain when none has been granted should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          ResourceCreatePermissions
                                                .getInstanceWithGrantOption(ResourceCreatePermissions.CREATE))) {
         fail("checking implicit system resource create permission with grant for domain when none has been granted should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          ResourceCreatePermissions
                                                .getInstance(ResourcePermissions.getInstance(customPermissionName)))) {
         fail("checking implicit custom resource create permission for domain when none has been granted should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          ResourceCreatePermissions
                                                .getInstanceWithGrantOption(ResourcePermissions.getInstance(customPermissionName)))) {
         fail("checking implicit custom resource create permission with grant for domain when none has been granted should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          ResourceCreatePermissions
                                                .getInstance(ResourcePermissions.getInstanceWithGrantOption(customPermissionName)))) {
         fail("checking implicit custom resource create permission for domain when none has been granted should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          ResourceCreatePermissions
                                                .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(customPermissionName)))) {
         fail("checking implicit custom resource create permission with grant for domain when none has been granted should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          ResourceCreatePermissions
                                                .getInstance(ResourcePermissions.getInstanceWithGrantOption(customPermissionName)),
                                          ResourceCreatePermissions
                                                .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(customPermissionName)),
                                          ResourceCreatePermissions
                                                .getInstance(ResourceCreatePermissions.CREATE))) {
         fail("checking multiple implicit custom resource create permission for domain when none has been granted should have succeeded for system resource");
      }

      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(ResourceCreatePermissions.CREATE)))) {
         fail("checking implicit system resource create permission for domain when none has been granted should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstanceWithGrantOption(ResourceCreatePermissions.CREATE)))) {
         fail("checking implicit system resource create permission with grant for domain when none has been granted should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions
                                                                         .getInstance(customPermissionName))))) {
         fail("checking implicit custom resource create permission for domain when none has been granted should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstanceWithGrantOption(ResourcePermissions
                                                                         .getInstance(customPermissionName))))) {
         fail("checking implicit custom resource create permission with grant for domain when none has been granted should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions.getInstanceWithGrantOption(customPermissionName))))) {
         fail("checking implicit custom resource create permission for domain when none has been granted should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(customPermissionName))))) {
         fail("checking implicit custom resource create permission with grant for domain when none has been granted should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions.getInstanceWithGrantOption(customPermissionName)),
                                                ResourceCreatePermissions
                                                      .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(customPermissionName)),
                                                ResourceCreatePermissions
                                                      .getInstance(ResourceCreatePermissions.CREATE)))) {
         fail("checking multiple implicit custom resource create permission for domain when none has been granted should have succeeded for system resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_noPermissions_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String domainName = generateDomain();

      // verify setup
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          domainName,
                                          ResourceCreatePermissions
                                                .getInstance(ResourcePermissions.getInstance(customPermissionName)))) {
         fail("checking resource create permission for domain when none has been granted should have failed for authenticated resource");
      }
      if (accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          domainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions
                                                                         .getInstance(customPermissionName))))) {
         fail("checking resource create permission for domain when none has been granted should have failed for authenticated resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String resourceClassName = generateResourceClass(false, false);

      // setup create permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);
      final ResourceCreatePermission customCreatePermission_accessorDomain_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(customPermission_forAccessorDomain);
      final ResourceCreatePermission createPermission_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessorDomainName,
                                    createPermission_withGrant,
                                    customCreatePermission_accessorDomain_withGrant);

      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant, customCreatePermission_accessorDomain_withGrant)));

      // authenticate resource without query authorization
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext
               .hasResourceCreatePermissions(accessorResource,
                                                resourceClassName,
                                                accessorDomainName,
                                                customCreatePermission_accessorDomain_withGrant);
         fail("checking resource create permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(accessorResource,
                                                resourceClassName,
                                                accessorDomainName,
                                                setOf(customCreatePermission_accessorDomain_withGrant));
         fail("checking resource create permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void hasResourceCreatePermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String resourceClassName = generateResourceClass(false, false);

      // setup create permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);
      final ResourceCreatePermission customCreatePermission_accessorDomain_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(customPermission_forAccessorDomain);
      final ResourceCreatePermission createPermission_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessorDomainName,
                                    createPermission_withGrant,
                                    customCreatePermission_accessorDomain_withGrant);

      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant, customCreatePermission_accessorDomain_withGrant)));

      // authenticate resource with implicit query authorization
      accessControlContext.grantResourcePermissions(authenticatableResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          customCreatePermission_accessorDomain_withGrant)) {
         fail("checking resource create permissions with implicit query authorization should have succeeded");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(customCreatePermission_accessorDomain_withGrant))) {
         fail("checking resource create permissions with implicit query authorization should have succeeded");
      }
   }

   @Test
   public void hasResourceCreatePermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String resourceClassName = generateResourceClass(false, false);

      // setup create permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);
      final ResourceCreatePermission customCreatePermission_accessorDomain_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(customPermission_forAccessorDomain);
      final ResourceCreatePermission createPermission_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessorDomainName,
                                    createPermission_withGrant,
                                    customCreatePermission_accessorDomain_withGrant);

      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant, customCreatePermission_accessorDomain_withGrant)));

      // authenticate resource with query authorization
      grantQueryPermission(authenticatableResource, accessorResource);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          customCreatePermission_accessorDomain_withGrant)) {
         fail("checking resource create permissions with query authorization should have succeeded");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(customCreatePermission_accessorDomain_withGrant))) {
         fail("checking resource create permissions with query authorization should have succeeded");
      }
   }

   @Test
   public void hasResourceCreatePermissions_direct_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // setup create permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);
      final ResourceCreatePermission customCreatePermission_accessorDomain_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(customPermission_forAccessorDomain);

      final String customPermissionName_accessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessedDomain
            = ResourcePermissions.getInstance(customPermissionName_accessedDomain);
      final ResourceCreatePermission customCreatePermission_accessedDomain_withoutGrant
            = ResourceCreatePermissions.getInstance(customPermission_forAccessedDomain);

      final ResourceCreatePermission createPermission_withoutGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPermission_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessorDomainName,
                                    createPermission_withGrant,
                                    customCreatePermission_accessorDomain_withGrant);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessedDomainName,
                                    createPermission_withoutGrant,
                                    customCreatePermission_accessedDomain_withoutGrant);

      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant, customCreatePermission_accessorDomain_withGrant)));

      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessedDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessedDomainName);
      assertThat(allResourceCreatePermissionsForAccessedDomain,
                 is(setOf(createPermission_withoutGrant, customCreatePermission_accessedDomain_withoutGrant)));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          customCreatePermission_accessorDomain_withGrant)) {
         fail("checking direct custom resource create permission for domain should have succeeded for authenticated resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          customCreatePermission_accessedDomain_withoutGrant)) {
         fail("checking direct custom resource create permission for domain should have succeeded for authenticated resource");
      }

      // test set-based version
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(customCreatePermission_accessorDomain_withGrant))) {
         fail("checking direct custom resource create permission for domain should have succeeded for authenticated resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          setOf(customCreatePermission_accessedDomain_withoutGrant))) {
         fail("checking direct custom resource create permission for domain should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_direct_withExtId() {
      authenticateSystemResource();

      final String externalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String resourceClassName = generateResourceClass(false, false);

      // setup create permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);
      final ResourceCreatePermission customCreatePermission_accessorDomain_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(customPermission_forAccessorDomain);
      final ResourceCreatePermission createPermission_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessorDomainName,
                                    createPermission_withGrant,
                                    customCreatePermission_accessorDomain_withGrant);

      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant, customCreatePermission_accessorDomain_withGrant)));

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(Resources.getInstance(externalId),
                                          resourceClassName,
                                          accessorDomainName,
                                          customCreatePermission_accessorDomain_withGrant)) {
         fail("checking direct custom resource create permission for domain should have succeeded for resource with external id");
      }

      if (!accessControlContext
            .hasResourceCreatePermissions(Resources.getInstance(externalId),
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(customCreatePermission_accessorDomain_withGrant))) {
         fail("checking direct custom resource create permission for domain should have succeeded for resource with external id");
      }
   }

   @Test
   public void hasResourceCreatePermissions_partialDirect_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // setup create permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);
      final ResourceCreatePermission customCreatePermission_accessorDomain_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(customPermission_forAccessorDomain);

      final String customPermissionName_accessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessedDomain
            = ResourcePermissions.getInstance(customPermissionName_accessedDomain);
      final ResourceCreatePermission customCreatePermission_accessedDomain_withoutGrant
            = ResourceCreatePermissions.getInstance(customPermission_forAccessedDomain);

      final ResourceCreatePermission createPermission_withoutGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPermission_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessorDomainName,
                                    createPermission_withGrant,
                                    customCreatePermission_accessorDomain_withGrant);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessedDomainName,
                                    createPermission_withoutGrant,
                                    customCreatePermission_accessedDomain_withoutGrant);

      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant, customCreatePermission_accessorDomain_withGrant)));

      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessedDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessedDomainName);
      assertThat(allResourceCreatePermissionsForAccessedDomain,
                 is(setOf(createPermission_withoutGrant, customCreatePermission_accessedDomain_withoutGrant)));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          customCreatePermission_accessorDomain_withGrant,
                                          ResourceCreatePermissions
                                                .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)))) {
         fail("checking direct custom resource create permission for domain with partial authorization should have failed for authenticated resource");
      }
      if (accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          customCreatePermission_accessedDomain_withoutGrant,
                                          ResourceCreatePermissions
                                                .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)))) {
         fail("checking direct custom resource create permission for domain with partial authorization should have failed for authenticated resource");
      }

      // test set-based versions
      if (accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(customCreatePermission_accessorDomain_withGrant,
                                                ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions
                                                                         .getInstance(ResourcePermissions.INHERIT))))) {
         fail("checking direct custom resource create permission for domain with partial authorization should have failed for authenticated resource");
      }
      if (accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          setOf(customCreatePermission_accessedDomain_withoutGrant,
                                                ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions
                                                                         .getInstance(ResourcePermissions.INHERIT))))) {
         fail("checking direct custom resource create permission for domain with partial authorization should have failed for authenticated resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_multipleDirect_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // setup create permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);
      final ResourceCreatePermission customCreatePermission_accessorDomain_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(customPermission_forAccessorDomain);

      final String customPermissionName_accessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessedDomain
            = ResourcePermissions.getInstance(customPermissionName_accessedDomain);
      final ResourceCreatePermission customCreatePermission_accessedDomain_withoutGrant
            = ResourceCreatePermissions.getInstance(customPermission_forAccessedDomain);

      final ResourceCreatePermission createPermission_withoutGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPermission_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission inheritPermission_withoutGrant
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessorDomainName,
                                    createPermission_withGrant,
                                    customCreatePermission_accessorDomain_withGrant,
                                    inheritPermission_withoutGrant);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessedDomainName,
                                    createPermission_withoutGrant,
                                    customCreatePermission_accessedDomain_withoutGrant,
                                    inheritPermission_withoutGrant);

      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant, customCreatePermission_accessorDomain_withGrant, inheritPermission_withoutGrant)));

      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessedDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessedDomainName);
      assertThat(allResourceCreatePermissionsForAccessedDomain,
                 is(setOf(createPermission_withoutGrant, customCreatePermission_accessedDomain_withoutGrant, inheritPermission_withoutGrant)));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          inheritPermission_withoutGrant,
                                          customCreatePermission_accessorDomain_withGrant)) {
         fail("checking multiple direct custom resource create permission for domain should have succeeded for authenticated resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          customCreatePermission_accessorDomain_withGrant,
                                          inheritPermission_withoutGrant)) {
         fail("checking multiple direct custom resource create permission for domain should have succeeded for authenticated resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          customCreatePermission_accessedDomain_withoutGrant,
                                          inheritPermission_withoutGrant)) {
         fail("checking multiple direct custom resource create permission for domain authorization should have succeeded for authenticated resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          inheritPermission_withoutGrant,
                                          customCreatePermission_accessedDomain_withoutGrant)) {
         fail("checking multiple direct custom resource create permission for domain authorization should have succeeded for authenticated resource");
      }

      // test set-based versions
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(inheritPermission_withoutGrant,
                                                customCreatePermission_accessorDomain_withGrant))) {
         fail("checking multiple direct custom resource create permission for domain should have succeeded for authenticated resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(customCreatePermission_accessorDomain_withGrant,
                                                inheritPermission_withoutGrant))) {
         fail("checking multiple direct custom resource create permission for domain should have succeeded for authenticated resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          setOf(customCreatePermission_accessedDomain_withoutGrant,
                                                inheritPermission_withoutGrant))) {
         fail("checking multiple direct custom resource create permission for domain authorization should have succeeded for authenticated resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          setOf(inheritPermission_withoutGrant,
                                                customCreatePermission_accessedDomain_withoutGrant))) {
         fail("checking multiple direct custom resource create permission for domain authorization should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_directWithDifferentGrantingRights_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // setup create permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantableCustomPermission_forAccessorDomain
            = ResourcePermissions.getInstanceWithGrantOption(customPermissionName_accessorDomain);
      final ResourcePermission ungrantableCustomPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);
      final ResourceCreatePermission grantableCustomCreatePermission_accessorDomain_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(grantableCustomPermission_forAccessorDomain);

      final String customPermissionName_accessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantableCustomPermission_forAccessedDomain
            = ResourcePermissions.getInstanceWithGrantOption(customPermissionName_accessedDomain);
      final ResourcePermission ungrantableCustomPermission_forAccessedDomain
            = ResourcePermissions.getInstance(customPermissionName_accessedDomain);
      final ResourceCreatePermission ungrantableCustomCreatePermission_accessedDomain_withoutGrant
            = ResourceCreatePermissions.getInstance(ungrantableCustomPermission_forAccessedDomain);

      final ResourceCreatePermission createPermission_withoutGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPermission_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessorDomainName,
                                    createPermission_withGrant,
                                    grantableCustomCreatePermission_accessorDomain_withGrant);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessedDomainName,
                                    createPermission_withoutGrant,
                                    ungrantableCustomCreatePermission_accessedDomain_withoutGrant);


      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant, grantableCustomCreatePermission_accessorDomain_withGrant)));

      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessedDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessedDomainName);
      assertThat(allResourceCreatePermissionsForAccessedDomain,
                 is(setOf(createPermission_withoutGrant,
                          ungrantableCustomCreatePermission_accessedDomain_withoutGrant)));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          ResourceCreatePermissions.getInstance(grantableCustomPermission_forAccessorDomain),
                                          ResourceCreatePermissions.getInstanceWithGrantOption(grantableCustomPermission_forAccessorDomain))) {
         fail("checking direct custom resource create permission with same and lesser granting rights should have succeeded for authenticated resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          ResourceCreatePermissions.getInstance(ungrantableCustomPermission_forAccessorDomain),
                                          ResourceCreatePermissions.getInstanceWithGrantOption(ungrantableCustomPermission_forAccessorDomain))) {
         fail("checking direct custom resource create permission with lesser post-create and create granting rights should have succeeded for authenticated resource");
      }

      if(!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          ResourceCreatePermissions.getInstance(ungrantableCustomPermission_forAccessedDomain))) {
         fail("checking direct custom resource create permission with same granting rights should have succeeded for authenticated resource");
      }

      if (accessControlContext
               .hasResourceCreatePermissions(accessorResource,
                                             resourceClassName,
                                             accessedDomainName,
                                             ResourceCreatePermissions.getInstance(grantableCustomPermission_forAccessedDomain))) {
         fail("checking direct custom resource create permission with exceeded post-create granting rights should have failed for authenticated resource");
      }
      if (accessControlContext
               .hasResourceCreatePermissions(accessorResource,
                                             resourceClassName,
                                             accessedDomainName,
                                             ResourceCreatePermissions.getInstanceWithGrantOption(ungrantableCustomPermission_forAccessedDomain))) {
         fail("checking direct custom resource create permission with exceeded create granting rights should have failed for authenticated resource");
      }

      // test set-based versions
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(ResourceCreatePermissions.getInstance(
                                                      grantableCustomPermission_forAccessorDomain),
                                                ResourceCreatePermissions.getInstanceWithGrantOption(
                                                      grantableCustomPermission_forAccessorDomain)))) {
         fail("checking direct custom resource create permission with same and lesser granting rights should have succeeded for authenticated resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(ResourceCreatePermissions.getInstance(
                                                      ungrantableCustomPermission_forAccessorDomain),
                                                ResourceCreatePermissions.getInstanceWithGrantOption(
                                                      ungrantableCustomPermission_forAccessorDomain)))) {
         fail("checking direct custom resource create permission with lesser post-create and create granting rights should have succeeded for authenticated resource");
      }

      if(!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          setOf(ResourceCreatePermissions.getInstance(
                                                ungrantableCustomPermission_forAccessedDomain)))) {
         fail("checking direct custom resource create permission with same granting rights should have succeeded for authenticated resource");
      }

      if (accessControlContext
               .hasResourceCreatePermissions(accessorResource,
                                             resourceClassName,
                                             accessedDomainName,
                                             setOf(ResourceCreatePermissions.getInstance(
                                                   grantableCustomPermission_forAccessedDomain)))) {
         fail("checking direct custom resource create permission with exceeded post-create granting rights should have failed for authenticated resource");
      }
      if (accessControlContext
               .hasResourceCreatePermissions(accessorResource,
                                             resourceClassName,
                                             accessedDomainName,
                                             setOf(ResourceCreatePermissions.getInstanceWithGrantOption(
                                                   ungrantableCustomPermission_forAccessedDomain)))) {
         fail("checking direct custom resource create permission with exceeded create granting rights should have failed for authenticated resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_resourceInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName_forAccessorDomain = generateResourceClassPermission(resourceClassName);
      final String customPermissionName_forAccessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_forAccessorDomain);
      final ResourcePermission customPermission_forAccessedDomain
            = ResourcePermissions.getInstance(customPermissionName_forAccessedDomain);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource intermediaryResource = generateUnauthenticatableResource();
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();

      // setup create permissions
      grantResourceCreatePermission(intermediaryResource, resourceClassName, accessorDomainName, customPermissionName_forAccessorDomain);
      grantResourceCreatePermission(intermediaryResource, resourceClassName, accessedDomainName, customPermissionName_forAccessedDomain);
      // setup inheritance permission
      Set<ResourcePermission> resourcePermissions = new HashSet<>();
      resourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, intermediaryResource, resourcePermissions);

      // verify permissions
      Set<ResourceCreatePermission> resourceCreatePermissions_forAccessorDomain = new HashSet<>();
      resourceCreatePermissions_forAccessorDomain.add(ResourceCreatePermissions
                                                            .getInstance(ResourceCreatePermissions.CREATE));
      resourceCreatePermissions_forAccessorDomain.add(ResourceCreatePermissions
                                                            .getInstance(customPermission_forAccessorDomain));
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(intermediaryResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndAccessorDomain, is(
            resourceCreatePermissions_forAccessorDomain));

      Set<ResourceCreatePermission> resourceCreatePermissions_forAccessedDomain = new HashSet<>();
      resourceCreatePermissions_forAccessedDomain.add(ResourceCreatePermissions
                                                            .getInstance(ResourceCreatePermissions.CREATE));
      resourceCreatePermissions_forAccessedDomain.add(ResourceCreatePermissions
                                                            .getInstance(customPermission_forAccessedDomain));
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndAccessedDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(intermediaryResource, resourceClassName, accessedDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndAccessedDomain, is(resourceCreatePermissions_forAccessedDomain));

      final Set<ResourcePermission> allResourcePermissionsForAccessorResource
            = accessControlContext.getEffectiveResourcePermissions(accessorResource, intermediaryResource);
      assertThat(allResourcePermissionsForAccessorResource, is(resourcePermissions));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          ResourceCreatePermissions
                                                .getInstance(customPermission_forAccessorDomain))) {
         fail("checking inherited resource create permission should have succeeded for authenticated resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          ResourceCreatePermissions
                                                .getInstance(customPermission_forAccessedDomain))) {
         fail("checking inherited resource create permission for domain should have succeeded for authenticated resource");
      }

      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(customPermission_forAccessorDomain)))) {
         fail("checking inherited resource create permission should have succeeded for authenticated resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(customPermission_forAccessedDomain)))) {
         fail("checking inherited resource create permission for domain should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_domainInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName_forAccessorDomain = generateResourceClassPermission(resourceClassName);
      final String customPermissionName_forIntermediaryDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_forAccessorDomain);
      final ResourcePermission customPermission_forIntermediaryDomain
            = ResourcePermissions.getInstance(customPermissionName_forIntermediaryDomain);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String intermediaryDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, accessorDomainName);
      final String accessedDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(accessedDomainName, intermediaryDomainName);

      // setup create permissions
      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessorDomainName,
                                    customPermissionName_forAccessorDomain);
      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    intermediaryDomainName,
                                    customPermissionName_forIntermediaryDomain);

      // verify permissions
      Set<ResourceCreatePermission> resourceCreatePermissions_forAccessorDomain = new HashSet<>();
      resourceCreatePermissions_forAccessorDomain.add(ResourceCreatePermissions
                                                            .getInstance(ResourceCreatePermissions.CREATE));
      resourceCreatePermissions_forAccessorDomain.add(ResourceCreatePermissions
                                                            .getInstance(customPermission_forAccessorDomain));
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndAccessorDomain, is(resourceCreatePermissions_forAccessorDomain));

      Set<ResourceCreatePermission> resourceCreatePermissions_forIntermediaryDomain = new HashSet<>();
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermissions
                                                                .getInstance(ResourceCreatePermissions.CREATE));
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermissions
                                                                .getInstance(customPermission_forIntermediaryDomain));
      resourceCreatePermissions_forIntermediaryDomain.addAll(resourceCreatePermissions_forAccessorDomain);
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndIntermediaryDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, intermediaryDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndIntermediaryDomain, is(resourceCreatePermissions_forIntermediaryDomain));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          ResourceCreatePermissions
                                                .getInstance(customPermission_forAccessorDomain))) {
         fail("checking parent resource create permission should have succeeded for authenticated resource");
      }

      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          ResourceCreatePermissions
                                                .getInstance(customPermission_forAccessorDomain),
                                          ResourceCreatePermissions
                                                .getInstance(customPermission_forIntermediaryDomain))) {
         fail("checking domain-inherited resource create permission from domain should have succeeded for authenticated resource");
      }

      // test set-based versions
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(customPermission_forAccessorDomain)))) {
         fail("checking parent resource create permission should have succeeded for authenticated resource");
      }

      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(customPermission_forAccessorDomain),
                                                ResourceCreatePermissions
                                                      .getInstance(customPermission_forIntermediaryDomain)))) {
         fail("checking domain-inherited resource create permission from domain should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_domainInheritedInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName_forAccessorDomain = generateResourceClassPermission(resourceClassName);
      final String customPermissionName_forIntermediaryDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_forAccessorDomain);
      final ResourcePermission customPermission_forIntermediaryDomain
            = ResourcePermissions.getInstance(customPermissionName_forIntermediaryDomain);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final Resource donorResource = accessControlContext.createResource(generateResourceClass(false, false),
                                                                         accessorDomainName);
      final String intermediaryDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, accessorDomainName);
      final String accessedDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(accessedDomainName, intermediaryDomainName);

      // setup create permissions
      grantResourceCreatePermission(donorResource,
                                    resourceClassName,
                                    accessorDomainName,
                                    customPermissionName_forAccessorDomain);
      grantResourceCreatePermission(donorResource,
                                    resourceClassName,
                                    intermediaryDomainName,
                                    customPermissionName_forIntermediaryDomain);
      // setup inheritance permission
      Set<ResourcePermission> inheritanceResourcePermissions = new HashSet<>();
      inheritanceResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritanceResourcePermissions);

      // verify permissions
      Set<ResourceCreatePermission> resourceCreatePermissions_forDonorDomain = new HashSet<>();
      resourceCreatePermissions_forDonorDomain.add(ResourceCreatePermissions
                                                         .getInstance(ResourceCreatePermissions.CREATE));
      resourceCreatePermissions_forDonorDomain.add(ResourceCreatePermissions
                                                         .getInstance(customPermission_forAccessorDomain));
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDonorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDonorDomain, is(resourceCreatePermissions_forDonorDomain));

      Set<ResourceCreatePermission> resourceCreatePermissions_forIntermediaryDomain = new HashSet<>();
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermissions
                                                                .getInstance(ResourceCreatePermissions.CREATE));
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermissions
                                                                .getInstance(customPermission_forIntermediaryDomain));
      resourceCreatePermissions_forIntermediaryDomain.addAll(resourceCreatePermissions_forDonorDomain);
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndIntermediaryDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClassName, intermediaryDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndIntermediaryDomain, is(resourceCreatePermissions_forIntermediaryDomain));

      final Set<ResourcePermission> allResourcePermissionsForAccessorResource
            = accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource);
      assertThat(allResourcePermissionsForAccessorResource, is(inheritanceResourcePermissions));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          ResourceCreatePermissions
                                                .getInstance(customPermission_forAccessorDomain))) {
         fail("checking inherited parent resource create permission should have succeeded for authenticated resource");
      }

      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          ResourceCreatePermissions
                                                .getInstance(customPermission_forAccessorDomain),
                                          ResourceCreatePermissions
                                                .getInstance(customPermission_forIntermediaryDomain))) {
         fail("checking inherited domain-inherited resource create permission domain should have succeeded for authenticated resource");
      }

      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(customPermission_forAccessorDomain)))) {
         fail("checking inherited parent resource create permission should have succeeded for authenticated resource");
      }

      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessedDomainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(customPermission_forAccessorDomain),
                                                ResourceCreatePermissions
                                                      .getInstance(customPermission_forIntermediaryDomain)))) {
         fail("checking inherited domain-inherited resource create permission domain should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_globalOnly_shouldFailAsAuthenticatedResource() {
      // special case where the requested permission hasn't been granted as a create permission
      // but will be available from the granted global permissions on the {resource class, domain}-tuple
      // Note that in this test case there is no *CREATE and no post-create permission, and the test should thus fail
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission globalResourcePermission = ResourcePermissions.getInstance(customPermissionName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);

      // setup global permission
      Set<ResourcePermission> globalResourcePermissions
            = setOf(globalResourcePermission, ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        globalResourcePermissions);

      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(true));

      final Set<ResourcePermission> allGlobalResourcePermissionsForResourceClass
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allGlobalResourcePermissionsForResourceClass.isEmpty(), is(false));
      assertThat(allGlobalResourcePermissionsForResourceClass,
                 hasItems(globalResourcePermission, ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          ResourceCreatePermissions
                                                .getInstance(globalResourcePermission))) {
         fail("checking resource create permission for domain without *CREATE or post-create should have failed for authenticated resource");
      }
      if (accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          ResourceCreatePermissions
                                                .getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)),
                                          ResourceCreatePermissions
                                                .getInstance(globalResourcePermission))) {
         fail("checking multiple resource create permission for domain without *CREATE or post-create should have failed for authenticated resource");
      }

      // test set-based versions
      if (accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(globalResourcePermission)))) {
         fail("checking resource create permission for domain without *CREATE or post-create should have failed for authenticated resource");
      }
      if (accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions
                                                                         .getInstance(ResourcePermissions.IMPERSONATE)),
                                                ResourceCreatePermissions
                                                      .getInstance(globalResourcePermission)))) {
         fail("checking multiple resource create permission for domain without *CREATE or post-create should have failed for authenticated resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_superUser_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);

      // setup super-user domain permission
      accessControlContext.setDomainPermissions(accessorResource,
                                                accessorDomainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          ResourceCreatePermissions
                                                .getInstance(ResourcePermissions.getInstance(customPermissionName)),
                                          ResourceCreatePermissions
                                                .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)))) {
         fail("checking implicit custom and system resource create permissions for domain when having super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions
                                                                         .getInstance(customPermissionName)),
                                                ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions
                                                                         .getInstance(ResourcePermissions.INHERIT))))) {
         fail("checking implicit custom and system resource create permissions for domain when having super-user privileges should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_superUserInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);

      // setup super-user domain permission
      final Resource donorResource = generateUnauthenticatableResource();
      accessControlContext.setDomainPermissions(donorResource,
                                                accessorDomainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // setup accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          ResourceCreatePermissions
                                                .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)),
                                          ResourceCreatePermissions
                                                .getInstance(ResourcePermissions.getInstance(customPermissionName)))) {
         fail("checking implicit custom resource create permission for domain when inheriting super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName,
                                          accessorDomainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions
                                                                         .getInstance(ResourcePermissions.INHERIT)),
                                                ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions
                                                                         .getInstance(customPermissionName))))) {
         fail("checking implicit custom resource create permission for domain when inheriting super-user privileges should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_superUserInvalidPermission_shouldFailAsSystemResource() {
      authenticateSystemResource();
      // setup resourceClass without any permissions
      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();

      // verify setup
      final Set<ResourceCreatePermission> directResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getResourceCreatePermissions(SYS_RESOURCE, resourceClassName, domainName);
      assertThat(directResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));

      // verify
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             domainName,
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS)));
         fail("checking implicit resource create permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             domainName,
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));
         fail("checking implicit resource create permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             domainName,
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));
         fail("checking multiple implicit resource create permission valid and invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }

      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             domainName,
                                             setOf(ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions
                                                                            .getInstance(ResourcePermissions.RESET_CREDENTIALS))));
         fail("checking implicit resource create permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             domainName,
                                             setOf(ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions
                                                                            .getInstance(ResourcePermissions.IMPERSONATE))));
         fail("checking implicit resource create permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             domainName,
                                             setOf(ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions
                                                                            .getInstance(ResourcePermissions.INHERIT)),
                                                   ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions
                                                                            .getInstance(ResourcePermissions.IMPERSONATE))));
         fail("checking multiple implicit resource create permission valid and invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
   }

   @Test
   public void hasResourceCreatePermissions_whitespaceConsistent() {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";

      // verify setup
      final Set<ResourceCreatePermission> directResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getResourceCreatePermissions(SYS_RESOURCE, resourceClassName, domainName);
      assertThat(directResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName_whitespaced,
                                          domainName_whitespaced,
                                          ResourceCreatePermissions
                                                .getInstance(ResourcePermissions.getInstance(customPermissionName)))) {
         fail("checking implicit resource create permission for domain for whitespaced resource class and domain name should have succeeded for system resource");
      }

      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName_whitespaced,
                                          domainName_whitespaced,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions
                                                                         .getInstance(customPermissionName))))) {
         fail("checking implicit resource create permission for domain for whitespaced resource class and domain name should have succeeded for system resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_whitespaceConsistent_asAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final String customPermissionName_forAccessorDomain = generateResourceClassPermission(resourceClassName);
      final String customPermissionName_forAccessedDomain = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();
      final String accessedDomainName_whitespaced = " " + accessedDomainName + "\t";

      // setup create permissions
      grantResourceCreatePermission(accessorResource, resourceClassName, accessorDomainName, customPermissionName_forAccessorDomain);
      grantResourceCreatePermission(accessorResource, resourceClassName, accessedDomainName, customPermissionName_forAccessedDomain);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName_whitespaced,
                                          accessedDomainName_whitespaced,
                                          ResourceCreatePermissions
                                                .getInstance(ResourcePermissions.getInstance(
                                                      customPermissionName_forAccessedDomain)))) {
         fail("checking resource create permission for domain for whitespaced resource class and domain name should have succeeded for authenticated resource");
      }

      if (!accessControlContext
            .hasResourceCreatePermissions(accessorResource,
                                          resourceClassName_whitespaced,
                                          accessedDomainName_whitespaced,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(ResourcePermissions
                                                                         .getInstance(
                                                                               customPermissionName_forAccessedDomain))))) {
         fail("checking resource create permission for domain for whitespaced resource class and domain name should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final String customPermissionName2 = generateResourceClassPermission(resourceClassName);
      final String domainName = generateDomain();

      try {
         accessControlContext
               .hasResourceCreatePermissions(null,
                                             resourceClassName,
                                             domainName,
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(customPermissionName)));
         fail("checking resource create permission (by domain) for null accessor resource reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(Resources.getInstance(null),
                                             resourceClassName,
                                             domainName,
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(customPermissionName)));
         fail("checking resource create permission (by domain) for null internal/external resource references should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             null,
                                             domainName,
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(customPermissionName)));
         fail("checking resource create permission (by domain) for null resource class reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             (String) null,
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(customPermissionName)));
         fail("checking resource create permission (by domain) for null domain reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
      try {
         accessControlContext.hasResourceCreatePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           (ResourceCreatePermission) null);
         fail("checking resource create permission (by domain) for null resource permission reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource create permission required"));
      }
      try {
         accessControlContext.hasResourceCreatePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourceCreatePermissions
                                                                 .getInstance(ResourcePermissions.getInstance(customPermissionName)),
                                                           null);
         fail("checking resource create permission (by domain) for null resource permission sequence should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }
      try {
         accessControlContext.hasResourceCreatePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourceCreatePermissions
                                                                 .getInstance(ResourcePermissions.getInstance(customPermissionName)),
                                                           new ResourceCreatePermission[]{null});
         fail("checking resource create permission for null resource permissions should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.hasResourceCreatePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourceCreatePermissions
                                                                 .getInstance(ResourcePermissions.getInstance(customPermissionName)),
                                                           ResourceCreatePermissions
                                                                 .getInstance(ResourcePermissions.getInstance(customPermissionName2)),
                                                           null);
         fail("checking resource create permission for null resource permissions should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      // test set-based versions
      try {
         accessControlContext
               .hasResourceCreatePermissions(null,
                                             resourceClassName,
                                             domainName,
                                             setOf(ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions
                                                                            .getInstance(customPermissionName))));
         fail("checking resource create permission (by domain) for null accessor resource reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(Resources.getInstance(null),
                                             resourceClassName,
                                             domainName,
                                             setOf(ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions
                                                                            .getInstance(customPermissionName))));
         fail("checking resource create permission (by domain) for null internal/external resource references should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             null,
                                             domainName,
                                             setOf(ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions
                                                                            .getInstance(customPermissionName))));
         fail("checking resource create permission (by domain) for null resource class reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             (String) null,
                                             setOf(ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions
                                                                            .getInstance(customPermissionName))));
         fail("checking resource create permission (by domain) for null domain reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
      try {
         accessControlContext.hasResourceCreatePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           (Set<ResourceCreatePermission>) null);
         fail("checking resource create permission (by domain) for null resource permission reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
      try {
         accessControlContext.hasResourceCreatePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           setOf(ResourceCreatePermissions
                                                                     .getInstance(ResourcePermissions
                                                                                        .getInstance(customPermissionName)),
                                                                 null));
         fail("checking resource create permission for null resource permissions should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
   }

   @Test
   public void hasResourceCreatePermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();

      try {
         accessControlContext.hasResourceCreatePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           Collections.<ResourceCreatePermission>emptySet());
         fail("checking resource create permission (by domain) for null resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void hasResourceCreatePermissions_emptyPermissions_shouldSucceed() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();

      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          ResourceCreatePermissions
                                                .getInstance(ResourceCreatePermissions.CREATE))) {
         fail("checking resource create permission (by domain) for empty resource permission sequence should have failed for system resource");
      }
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          ResourceCreatePermissions
                                                .getInstance(ResourceCreatePermissions.CREATE),
                                          new ResourceCreatePermission[] {})) {
         fail("checking resource create permission (by domain) for empty resource permission sequence should have failed for system resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_duplicatePermissions_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();
      // setup
      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();

      // verify
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             domainName,
                                             ResourceCreatePermissions
                                                   .getInstance(ResourceCreatePermissions.CREATE),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourceCreatePermissions.CREATE));
         fail("checking resource create permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void hasResourceCreatePermissions_duplicatePermissions_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();
      // setup
      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();

      // verify
      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          ResourceCreatePermissions
                                                .getInstance(ResourceCreatePermissions.CREATE),
                                          ResourceCreatePermissions
                                                .getInstanceWithGrantOption(ResourceCreatePermissions.CREATE))) {
         fail("checking resource create permission with duplicate elements (with different grant options) should have succeeded for system resource");
      }

      if (!accessControlContext
            .hasResourceCreatePermissions(SYS_RESOURCE,
                                          resourceClassName,
                                          domainName,
                                          setOf(ResourceCreatePermissions
                                                      .getInstance(ResourceCreatePermissions.CREATE),
                                                ResourceCreatePermissions
                                                      .getInstanceWithGrantOption(ResourceCreatePermissions.CREATE)))) {
         fail("checking resource create permission with duplicate elements (with different grant options) should have succeeded for system resource");
      }
   }

   @Test
   public void hasResourceCreatePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");
      final String domainName = generateDomain();

      try {
         accessControlContext
               .hasResourceCreatePermissions(invalidResource,
                                             resourceClassName,
                                             domainName,
                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(customPermissionName)));
         fail("checking resource create permission (by domain) for invalid accessor resource reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(invalidExternalResource,
                                             resourceClassName,
                                             domainName,
                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(customPermissionName)));
         fail("checking resource create permission (by domain) for invalid external accessor resource reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(mismatchedResource,
                                             resourceClassName,
                                             domainName,
                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(customPermissionName)));
         fail("checking resource create permission (by domain) for mismatched internal/external resource references should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             "invalid_resource_class",
                                             domainName,
                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(customPermissionName)));
         fail("checking resource create permission (by domain) for invalid resource class reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             "invalid_domain",
                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(customPermissionName)));
         fail("checking resource create permission (by domain) for invalid domain reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             domainName,
                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance("invalid_permission")));
         fail("checking resource create permission (by domain) for invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             domainName,

                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(customPermissionName)),
                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance("invalid_permission")));
         fail("checking resource create permission (by domain) for valid and invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }

      // test set-based versions
      try {
         accessControlContext
               .hasResourceCreatePermissions(invalidResource,
                                             resourceClassName,
                                             domainName,
                                             setOf(ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions.getInstance(
                                                               customPermissionName))));
         fail("checking resource create permission (by domain) for invalid accessor resource reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(invalidExternalResource,
                                             resourceClassName,
                                             domainName,
                                             setOf(ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions
                                                                            .getInstance(customPermissionName))));
         fail("checking resource create permission (by domain) for invalid external accessor resource reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(mismatchedResource,
                                             resourceClassName,
                                             domainName,
                                             setOf(ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions
                                                                            .getInstance(customPermissionName))));
         fail("checking resource create permission (by domain) for mismatched internal/external resource references should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             "invalid_resource_class",
                                             domainName,
                                             setOf(ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions.getInstance(
                                                               customPermissionName))));
         fail("checking resource create permission (by domain) for invalid resource class reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             "invalid_domain",
                                             setOf(ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions.getInstance(
                                                               customPermissionName))));
         fail("checking resource create permission (by domain) for invalid domain reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             domainName,
                                             setOf(ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions.getInstance(
                                                               "invalid_permission"))));
         fail("checking resource create permission (by domain) for invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext
               .hasResourceCreatePermissions(SYS_RESOURCE,
                                             resourceClassName,
                                             domainName,
                                             setOf(ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions.getInstance(
                                                               customPermissionName)),
                                                   ResourceCreatePermissions
                                                         .getInstance(ResourcePermissions.getInstance(
                                                               "invalid_permission"))));
         fail("checking resource create permission (by domain) for valid and invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
   }
}