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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_hasPostCreateResourcePermissions extends TestAccessControlBase {
   @Test
   public void hasPostCreateResourcePermissions_succeedsAsSystemResource() {
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
      if (!accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                                 resourceClassName,
                                                                 domainName,
                                                                 ResourcePermissions.getInstance(customPermissionName))) {
         fail("checking implicit post-create resource permission (for a domain) should have succeeded for system resource");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                                 resourceClassName,
                                                                 domainName,
                                                                 ResourcePermissions.getInstance(customPermissionName),
                                                                 ResourcePermissions.getInstance(ResourcePermissions.INHERIT))) {
         fail("checking multiple implicit post-create resource permission (for a domain) should have succeeded for system resource");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                                 resourceClassName,
                                                                 domainName,
                                                                 setOf(ResourcePermissions
                                                                             .getInstance(customPermissionName)))) {
         fail("checking implicit post-create resource permission (for a domain) should have succeeded for system resource");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                                 resourceClassName,
                                                                 domainName,
                                                                 setOf(ResourcePermissions
                                                                             .getInstance(customPermissionName),
                                                                       ResourcePermissions
                                                                             .getInstance(ResourcePermissions.INHERIT)))) {
         fail("checking multiple implicit post-create resource permission (for a domain) should have succeeded for system resource");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_noPermissions_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // verify setup
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      final String domainName = generateDomain();

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));

      // verify
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                domainName,
                                                                ResourcePermissions.getInstance(customPermissionName))) {
         fail("checking post-create resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                domainName,
                                                                ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                                ResourcePermissions.getInstance(customPermissionName))) {
         fail("checking multiple post-create resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }

      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                domainName,
                                                                setOf(ResourcePermissions
                                                                            .getInstance(customPermissionName)))) {
         fail("checking post-create resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                domainName,
                                                                setOf(ResourcePermissions
                                                                            .getInstance(ResourcePermissions.INHERIT),
                                                                      ResourcePermissions
                                                                            .getInstance(customPermissionName)))) {
         fail("checking multiple post-create resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
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
         accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessorDomainName,
                                                               customPermission_forAccessorDomain);
         fail("checking post-create resource permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }

      try {
         accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessorDomainName,
                                                               setOf(customPermission_forAccessorDomain));
         fail("checking post-create resource permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
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
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant, customCreatePermission_accessorDomain_withGrant)));

      // authenticate resource with implicit query authorization
      accessControlContext.grantResourcePermissions(authenticatableResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 customPermission_forAccessorDomain)) {
         fail("checking post-create resource permissions with implicit query authorization should have succeeded");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(customPermission_forAccessorDomain))) {
         fail("checking post-create resource permissions with implicit query authorization should have succeeded");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
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
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 customPermission_forAccessorDomain)) {
         fail("checking post-create resource permissions with query authorization should have succeeded");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(customPermission_forAccessorDomain))) {
         fail("checking post-create resource permissions with query authorization should have succeeded");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_direct_succeedsAsAuthenticatedResource() {
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
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 customPermission_forAccessorDomain)) {
         fail("checking direct post-create resource permission for domain should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 customPermission_forAccessedDomain)) {
         fail("checking direct post-create resource permission for domain should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(customPermission_forAccessorDomain))) {
         fail("checking direct post-create resource permission for domain should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 setOf(customPermission_forAccessedDomain))) {
         fail("checking direct post-create resource permission for domain should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_direct_withExtId() {
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
      if (!accessControlContext.hasPostCreateResourcePermissions(Resources.getInstance(externalId),
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 customPermission_forAccessorDomain)) {
         fail("checking direct post-create resource permission for domain should have succeeded for resource with external id");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(Resources.getInstance(externalId),
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(customPermission_forAccessorDomain))) {
         fail("checking direct post-create resource permission for domain should have succeeded for resource with external id");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_partialDirect_shouldFailAsAuthenticatedResource() {
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
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessorDomainName,
                                                                ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                                customPermission_forAccessorDomain)) {
         fail("checking direct and unauthorized post-create resource permission for domain should have failed for authenticated resource");
      }

      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessedDomainName,
                                                                ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                                customPermission_forAccessedDomain)) {
         fail("checking direct and unauthorized post-create resource permission for domain should have failed for authenticated resource");
      }

      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessorDomainName,
                                                                setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                                      customPermission_forAccessorDomain))) {
         fail("checking direct and unauthorized post-create resource permission for domain should have failed for authenticated resource");
      }

      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessedDomainName,
                                                                setOf(ResourcePermissions.getInstance(
                                                                      ResourcePermissions.INHERIT),
                                                                      customPermission_forAccessedDomain))) {
         fail("checking direct and unauthorized post-create resource permission for domain should have failed for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_multipleDirect_shouldSucceedAsAuthenticatedResource() {
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
                                    ResourceCreatePermissions
                                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)),
                                    customCreatePermission_accessorDomain_withGrant);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessedDomainName,
                                    createPermission_withoutGrant,
                                    ResourceCreatePermissions
                                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)),
                                    customCreatePermission_accessedDomain_withoutGrant);


      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant,
                          customCreatePermission_accessorDomain_withGrant,
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)))));

      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessedDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessedDomainName);
      assertThat(allResourceCreatePermissionsForAccessedDomain,
                 is(setOf(createPermission_withoutGrant,
                          customCreatePermission_accessedDomain_withoutGrant,
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)))));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                                 customPermission_forAccessorDomain)) {
         fail("checking multiple direct post-create resource permission for domain should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 customPermission_forAccessorDomain,
                                                                 ResourcePermissions.getInstance(ResourcePermissions.INHERIT))) {
         fail("checking multiple direct post-create resource permission for domain should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                                 customPermission_forAccessedDomain)) {
         fail("checking multiple direct post-create resource permission for domain should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 customPermission_forAccessedDomain,
                                                                 ResourcePermissions.getInstance(ResourcePermissions.INHERIT))) {
         fail("checking multiple direct post-create resource permission for domain should have succeeded for authenticated resource");
      }

      // test set-based versions
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(ResourcePermissions
                                                                             .getInstance(ResourcePermissions.INHERIT),
                                                                       customPermission_forAccessorDomain))) {
         fail("checking multiple direct post-create resource permission for domain should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(customPermission_forAccessorDomain,
                                                                       ResourcePermissions
                                                                             .getInstance(ResourcePermissions.INHERIT)))) {
         fail("checking multiple direct post-create resource permission for domain should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 setOf(ResourcePermissions
                                                                             .getInstance(ResourcePermissions.INHERIT),
                                                                       customPermission_forAccessedDomain))) {
         fail("checking multiple direct post-create resource permission for domain should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 setOf(customPermission_forAccessedDomain,
                                                                       ResourcePermissions
                                                                             .getInstance(ResourcePermissions.INHERIT)))) {
         fail("checking multiple direct post-create resource permission for domain should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_directWithDifferentGrantingRights_succeedsAsAuthenticatedResource() {
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
                                    ResourceCreatePermissions
                                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)),
                                    grantableCustomCreatePermission_accessorDomain_withGrant);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessedDomainName,
                                    createPermission_withoutGrant,
                                    ResourceCreatePermissions
                                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)),
                                    ungrantableCustomCreatePermission_accessedDomain_withoutGrant);


      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant,
                          grantableCustomCreatePermission_accessorDomain_withGrant,
                          ResourceCreatePermissions.getInstance(ResourcePermissions
                                                                      .getInstance(ResourcePermissions.INHERIT)))));

      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessedDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessedDomainName);
      assertThat(allResourceCreatePermissionsForAccessedDomain,
                 is(setOf(createPermission_withoutGrant,
                          ungrantableCustomCreatePermission_accessedDomain_withoutGrant,
                          ResourceCreatePermissions.getInstance(ResourcePermissions
                                                                      .getInstance(ResourcePermissions.INHERIT)))));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 grantableCustomPermission_forAccessorDomain)) {
         fail("checking direct post-create resource permission with same granting rights (for a domain) should have succeeded");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 ungrantableCustomPermission_forAccessorDomain)) {
         fail("checking direct post-create resource permission with lesser granting rights (for a domain) should have succeeded");
      }
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessorDomainName,
                                                                ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT),
                                                                ungrantableCustomPermission_forAccessorDomain)) {
         fail("checking multiple direct post-create resource permission with lesser and exceeded granting rights (for a domain) should have failed");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 ungrantableCustomPermission_forAccessedDomain)) {
         fail("checking direct post-create resource permission with same granting rights (for a domain) should have succeeded");
      }
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessedDomainName,
                                                                grantableCustomPermission_forAccessedDomain)) {
         fail("checking direct post-create resource permission with exceeded granting rights (for a domain) should have failed");
      }
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessedDomainName,
                                                                ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                                grantableCustomPermission_forAccessedDomain)) {
         fail("checking multiple direct post-create resource permission with same and exceeded granting rights (for a domain) should have failed");
      }

      // test set-based versions
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(grantableCustomPermission_forAccessorDomain))) {
         fail("checking direct post-create resource permission with same granting rights (for a domain) should have succeeded");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(ungrantableCustomPermission_forAccessorDomain))) {
         fail("checking direct post-create resource permission with lesser granting rights (for a domain) should have succeeded");
      }
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessorDomainName,
                                                                setOf(ResourcePermissions
                                                                            .getInstanceWithGrantOption(ResourcePermissions.INHERIT),
                                                                      ungrantableCustomPermission_forAccessorDomain))) {
         fail("checking multiple direct post-create resource permission with lesser and exceeded granting rights (for a domain) should have failed");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 setOf(ungrantableCustomPermission_forAccessedDomain))) {
         fail("checking direct post-create resource permission with same granting rights (for a domain) should have succeeded");
      }
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessedDomainName,
                                                                setOf(grantableCustomPermission_forAccessedDomain))) {
         fail("checking direct post-create resource permission with exceeded granting rights (for a domain) should have failed");
      }
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessedDomainName,
                                                                setOf(ResourcePermissions
                                                                            .getInstance(ResourcePermissions.INHERIT),
                                                                      grantableCustomPermission_forAccessedDomain))) {
         fail("checking multiple direct post-create resource permission with same and exceeded granting rights (for a domain) should have failed");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_resourceInherited_succeedsAsAuthenticatedResource() {
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
      assertThat(allResourceCreatePermissionsForResourceClassAndAccessorDomain, is(resourceCreatePermissions_forAccessorDomain));

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
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 customPermission_forAccessorDomain)) {
         fail("checking inherited post-create resource permission should have succeeded");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 customPermission_forAccessedDomain)) {
         fail("checking inherited post-create resource permission for a domain should have succeeded");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(customPermission_forAccessorDomain))) {
         fail("checking inherited post-create resource permission should have succeeded");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 setOf(customPermission_forAccessedDomain))) {
         fail("checking inherited post-create resource permission for a domain should have succeeded");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_domainInherited_succeedsAsAuthenticatedResource() {
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
      assertThat(allResourceCreatePermissionsForResourceClassAndAccessorDomain, is(
            resourceCreatePermissions_forAccessorDomain));

      Set<ResourceCreatePermission> resourceCreatePermissions_forIntermediaryDomain = new HashSet<>();
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermissions
                                                                .getInstance(ResourceCreatePermissions.CREATE));
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermissions
                                                                .getInstance(customPermission_forIntermediaryDomain));
      resourceCreatePermissions_forIntermediaryDomain.addAll(resourceCreatePermissions_forAccessorDomain);
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndIntermediaryDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, intermediaryDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndIntermediaryDomain, is(
            resourceCreatePermissions_forIntermediaryDomain));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 customPermission_forAccessorDomain)) {
         fail("checking domain-inherited post-create resource permission should have succeeded");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 customPermission_forAccessorDomain,
                                                                 customPermission_forIntermediaryDomain)) {
         fail("checking multiple domain-inherited post-create resource permission (for intermediary domain) should have succeeded");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(customPermission_forAccessorDomain))) {
         fail("checking domain-inherited post-create resource permission should have succeeded");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 setOf(customPermission_forAccessorDomain,
                                                                       customPermission_forIntermediaryDomain))) {
         fail("checking multiple domain-inherited post-create resource permission (for intermediary domain) should have succeeded");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_domainInheritedInherited_succeedsAsAuthenticatedResource() {
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
      assertThat(allResourceCreatePermissionsForResourceClassAndDonorDomain,
                 is(resourceCreatePermissions_forDonorDomain));

      Set<ResourceCreatePermission> resourceCreatePermissions_forIntermediaryDomain = new HashSet<>();
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermissions
                                                                .getInstance(ResourceCreatePermissions.CREATE));
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermissions
                                                                .getInstance(customPermission_forIntermediaryDomain));
      resourceCreatePermissions_forIntermediaryDomain.addAll(resourceCreatePermissions_forDonorDomain);
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndIntermediaryDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClassName, intermediaryDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndIntermediaryDomain, is(
            resourceCreatePermissions_forIntermediaryDomain));

      final Set<ResourcePermission> allResourcePermissionsForAccessorResource
            = accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource);
      assertThat(allResourcePermissionsForAccessorResource, is(inheritanceResourcePermissions));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 customPermission_forAccessorDomain)) {
         fail("checking inherited domain-inherited post-create resource permission should have succeeded");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 customPermission_forAccessorDomain,
                                                                 customPermission_forIntermediaryDomain)) {
         fail("checking multiple inherited domain-inherited post-create resource permission (for intermediary domain) should have succeeded");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(customPermission_forAccessorDomain))) {
         fail("checking inherited domain-inherited post-create resource permission should have succeeded");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 setOf(customPermission_forAccessorDomain,
                                                                       customPermission_forIntermediaryDomain))) {
         fail("checking multiple inherited domain-inherited post-create resource permission (for intermediary domain) should have succeeded");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_globalOnly_shouldFailAsAuthenticatedResource() {
      // special case where the requested permission hasn't been granted as a create permission
      // but will be available from the granted global permissions on the {resource class, domain}-tuple
      // Note that in this test case there is no *CREATE permission, and the test should thus fail
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
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         accessorDomainName);
      assertThat(allGlobalResourcePermissionsForResourceClass.isEmpty(), is(false));
      assertThat(allGlobalResourcePermissionsForResourceClass, hasItem(globalResourcePermission));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessorDomainName,
                                                                globalResourcePermission)) {
         fail("checking post-create resource permission without *CREATE should not have succeeded for authenticated resource");
      }
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessorDomainName,
                                                                ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                                globalResourcePermission)) {
         fail("checking multiple post-create resource permission without *CREATE should not have succeeded for authenticated resource");
      }
      // test set-based version
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessorDomainName,
                                                                setOf(globalResourcePermission))) {
         fail("checking post-create resource permission without *CREATE should not have succeeded for authenticated resource");
      }
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessorDomainName,
                                                                setOf(ResourcePermissions.getInstance(
                                                                      ResourcePermissions.IMPERSONATE),
                                                                      globalResourcePermission))) {
         fail("checking multiple post-create resource permission without *CREATE should not have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_globalAndDirect_succeedsAsAuthenticatedResource() {
      // special case where some of the requested permission haven't been granted as a create permission
      // but will be available from the granted global permissions on the {resource class, domain}-tuple
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(true, false);
      final String globalPermissionName = generateResourceClassPermission(resourceClassName);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission globalResourcePermission = ResourcePermissions.getInstance(globalPermissionName);
      final ResourcePermission customResourcePermission = ResourcePermissions.getInstance(customPermissionName);
      final ResourcePermission systemResourcePermission = ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);

      // setup direct resource create permissions
      final ResourceCreatePermission createPermission_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPermission_custom
            = ResourceCreatePermissions.getInstance(customResourcePermission);
      final ResourceCreatePermission createPermission_system
            = ResourceCreatePermissions.getInstance(systemResourcePermission);
      Set<ResourceCreatePermission> resourceCreatePermissions
            = setOf(createPermission_create, createPermission_custom, createPermission_system);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        resourceCreatePermissions);
      // setup global permission
      Set<ResourcePermission> globalResourcePermissions
            = setOf(globalResourcePermission, ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        globalResourcePermissions);

      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(false));
      assertThat(allResourceCreatePermissionsForResourceClass.size(), is(3));
      assertThat(allResourceCreatePermissionsForResourceClass,
                 hasItems(createPermission_create, createPermission_custom, createPermission_system));

      final Set<ResourcePermission> allGlobalResourcePermissionsForResourceClass
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allGlobalResourcePermissionsForResourceClass.isEmpty(), is(false));
      assertThat(allGlobalResourcePermissionsForResourceClass, hasItem(globalResourcePermission));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 globalResourcePermission,
                                                                 customResourcePermission,
                                                                 ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                                 systemResourcePermission)) {
         fail("checking multiple global permission and system post-create resource permission for a domain should have succeeded");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(globalResourcePermission,
                                                                       customResourcePermission,
                                                                       ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                                       systemResourcePermission))) {
         fail("checking multiple global permission and system post-create resource permission for a domain should have succeeded");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_globalWithDifferentGrantingRights_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // setup create permissions
      final ResourceCreatePermission createPermission_withoutGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPermission_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(createPermission_withGrant));
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessedDomainName,
                                                        setOf(createPermission_withoutGrant));

      // setup global permission
      final String globalPermissionName1 = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantableGlobalPermission1 = ResourcePermissions.getInstanceWithGrantOption(globalPermissionName1);
      final ResourcePermission ungrantableGlobalPermission1 = ResourcePermissions.getInstance(globalPermissionName1);
      final String globalPermissionName2 = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantableGlobalPermission2 = ResourcePermissions.getInstanceWithGrantOption(globalPermissionName2);
      final ResourcePermission ungrantableGlobalPermission2 = ResourcePermissions.getInstance(globalPermissionName2);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(grantableGlobalPermission1));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessedDomainName,
                                                        setOf(ungrantableGlobalPermission2));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 grantableGlobalPermission1,
                                                                 ungrantableGlobalPermission1)) {
         fail("checking multiple post-create resource permission for a global permission with same and lesser granting rights (for a domain) should have succeeded");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 ungrantableGlobalPermission2)) {
         fail("checking post-create resource permission for a global permission with same granting rights (for a domain) should have succeeded");
      }

      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessedDomainName,
                                                                grantableGlobalPermission2)) {
         fail("checking post-create resource permission for a global (create) permission (for a domain) with exceeded granting rights should have failed");
      }
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessedDomainName,
                                                                ungrantableGlobalPermission2,
                                                                grantableGlobalPermission2)) {
         fail("checking multiple post-create resource permission for a global (create) permission (for a domain) with same and exceeded granting rights should have failed");
      }

      // test set-based versions
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(grantableGlobalPermission1,
                                                                       ungrantableGlobalPermission1))) {
         fail("checking multiple post-create resource permission for a global permission with same and lesser granting rights (for a domain) should have succeeded");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessedDomainName,
                                                                 setOf(ungrantableGlobalPermission2))) {
         fail("checking post-create resource permission for a global permission with same granting rights (for a domain) should have succeeded");
      }

      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessedDomainName,
                                                                setOf(grantableGlobalPermission2))) {
         fail("checking post-create resource permission for a global (create) permission (for a domain) with exceeded granting rights should have failed");
      }
      if (accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                resourceClassName,
                                                                accessedDomainName,
                                                                setOf(ungrantableGlobalPermission2,
                                                                      grantableGlobalPermission2))) {
         fail("checking multiple post-create resource permission for a global (create) permission (for a domain) with same and exceeded granting rights should have failed");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_superUser_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission globalResourcePermission = ResourcePermissions.getInstance(customPermissionName);
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
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                                 globalResourcePermission)) {
         fail("checking implicit post-create resource permission (for a domain) when having super-user privileges should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(ResourcePermissions
                                                                             .getInstance(ResourcePermissions.INHERIT),
                                                                       globalResourcePermission))) {
         fail("checking implicit post-create resource permission (for a domain) when having super-user privileges should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_superUserInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission globalResourcePermission = ResourcePermissions.getInstance(customPermissionName);
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
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                                 globalResourcePermission)) {
         fail("checking implicit post-create resource permission (for a domain) when inheriting super-user privileges should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName,
                                                                 accessorDomainName,
                                                                 setOf(ResourcePermissions
                                                                             .getInstance(ResourcePermissions.INHERIT),
                                                                       globalResourcePermission))) {
         fail("checking implicit post-create resource permission (for a domain) when inheriting super-user privileges should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_superUserInvalidPermission_shouldFailAsSystemResource() {
      authenticateSystemResource();
      // setup resourceClass without any permissions
      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();

      // verify setup
      final Set<ResourceCreatePermission> directResourceCreatePermissionsForResourceClass
            = accessControlContext.getResourceCreatePermissions(SYS_RESOURCE, resourceClassName, domainName);
      assertThat(directResourceCreatePermissionsForResourceClass.isEmpty(), is(true));

      // verify
      try {
         accessControlContext
               .hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                 resourceClassName,
                                                 domainName,
                                                 ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));
         fail("checking implicit resource create permission (for a domain) invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                 resourceClassName,
                                                 domainName,
                                                 ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("checking implicit resource create permission (for a domain) invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                 resourceClassName,
                                                 domainName,
                                                 ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                 ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("checking implicit resource create permission (for a domain) valid and invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }

      // test set-based versions
      try {
         accessControlContext
               .hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                 resourceClassName,
                                                 domainName,
                                                 setOf(ResourcePermissions
                                                             .getInstance(ResourcePermissions.RESET_CREDENTIALS)));
         fail("checking implicit resource create permission (for a domain) invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                 resourceClassName,
                                                 domainName,
                                                 setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));
         fail("checking implicit resource create permission (for a domain) invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                 resourceClassName,
                                                 domainName,
                                                 setOf(ResourcePermissions
                                                             .getInstance(ResourcePermissions.INHERIT),
                                                       ResourcePermissions
                                                             .getInstance(ResourcePermissions.IMPERSONATE)));
         fail("checking implicit resource create permission (for a domain) valid and invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_whitespaceConsistent() {
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
      // checking post-create resource permission (even when none has been granted) should succeed for system resource
      if (!accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                                 resourceClassName_whitespaced,
                                                                 domainName_whitespaced,
                                                                 ResourcePermissions.getInstance(customPermissionName))) {
         fail("checking post-create resource permission on whitespaced resource class and domain name should have succeeded for system resource");
      }

      if (!accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                                 resourceClassName_whitespaced,
                                                                 domainName_whitespaced,
                                                                 setOf(ResourcePermissions.getInstance(
                                                                       customPermissionName)))) {
         fail("checking post-create resource permission on whitespaced resource class and domain name should have succeeded for system resource");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_whitespaceConsistent_asAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final String customPermissionName_forAccessorDomain = generateResourceClassPermission(resourceClassName);
      final String customPermissionName_forAccessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessedDomain = ResourcePermissions.getInstance(
            customPermissionName_forAccessedDomain);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();
      final String accessedDomainName_whitespaced = " " + accessedDomainName + "\t";

      // setup create permissions
      grantResourceCreatePermission(accessorResource, resourceClassName, accessorDomainName, customPermissionName_forAccessorDomain);
      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessedDomainName,
                                    customPermissionName_forAccessedDomain);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName_whitespaced,
                                                                 accessedDomainName_whitespaced,
                                                                 customPermission_forAccessedDomain)) {
         fail("checking post-create resource permission on whitespaced resource class and domain name should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(accessorResource,
                                                                 resourceClassName_whitespaced,
                                                                 accessedDomainName_whitespaced,
                                                                 setOf(customPermission_forAccessedDomain))) {
         fail("checking post-create resource permission on whitespaced resource class and domain name should have succeeded for authenticated resource");
      }
   }


   @Test
   public void hasPostCreateResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final String domainName = generateDomain();

      try {
         accessControlContext.hasPostCreateResourcePermissions(null,
                                                               resourceClassName,
                                                               domainName,
                                                               ResourcePermissions.getInstance(customPermissionName));
         fail("checking post-create resource permission (by domain) for null accessor resource reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(Resources.getInstance(null),
                                                               resourceClassName,
                                                               domainName,
                                                               ResourcePermissions.getInstance(customPermissionName));
         fail("checking post-create resource permission (by domain) for null internal/external resource references should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               null,
                                                               domainName,
                                                               ResourcePermissions.getInstance(customPermissionName));
         fail("checking post-create resource permission (by domain) for null resource class reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               (String) null,
                                                               ResourcePermissions.getInstance(customPermissionName));
         fail("checking post-create resource permission (by domain) for null domain reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               (ResourcePermission) null);
         fail("checking post-create resource permission (by domain) for null resource permission reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                               null);
         fail("checking post-create resource permission (by domain) for null resource permission sequence should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                               new ResourcePermission[] {null});
         fail("checking post-create resource permission (by domain) for null resource permission reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                               ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                               null);
         fail("checking post-create resource permission (by domain) for null resource permission reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      // test set-based versions
      try {
         accessControlContext.hasPostCreateResourcePermissions(null,
                                                               resourceClassName,
                                                               domainName,
                                                               setOf(ResourcePermissions
                                                                           .getInstance(customPermissionName)));
         fail("checking post-create resource permission (by domain) for null accessor resource reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(Resources.getInstance(null),
                                                               resourceClassName,
                                                               domainName,
                                                               setOf(ResourcePermissions
                                                                           .getInstance(customPermissionName)));
         fail("checking post-create resource permission (by domain) for null internal/external resource references should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               null,
                                                               domainName,
                                                               setOf(ResourcePermissions
                                                                           .getInstance(customPermissionName)));
         fail("checking post-create resource permission (by domain) for null resource class reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               (String) null,
                                                               setOf(ResourcePermissions
                                                                           .getInstance(customPermissionName)));
         fail("checking post-create resource permission (by domain) for null domain reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               (Set<ResourcePermission>) null);
         fail("checking post-create resource permission (by domain) for null resource permission reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               setOf(ResourcePermissions
                                                                           .getInstance(customPermissionName),
                                                                     null));
         fail("checking post-create resource permission (by domain) for null resource permission reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(true, false);
      final String domainName = generateDomain();

      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               Collections.<ResourcePermission>emptySet());
         fail("checking post-create resource permission (by domain) for null resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_emptyPermissions_shouldSucceed() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final String domainName = generateDomain();

      if (!accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                                 resourceClassName,
                                                                 domainName,
                                                                 ResourcePermissions.getInstance(customPermissionName))) {
         fail("checking post-create resource permission (by domain) for empty sequence of resource permissions should have failed for implicit system resource");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                                 resourceClassName,
                                                                 domainName,
                                                                 ResourcePermissions.getInstance(customPermissionName),
                                                                 new ResourcePermission[] {})) {
         fail("checking post-create resource permission (by domain) for empty sequence of resource permissions should have failed for implicit system resource");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_duplicatePermissions_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final String domainName = generateDomain();

      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               ResourcePermissions.getInstance(customPermissionName),
                                                               ResourcePermissions
                                                                     .getInstance(customPermissionName));
         fail("checking post-create resource permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_duplicatePermissions_shouldSucceed() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final String domainName = generateDomain();

      if (!accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                                 resourceClassName,
                                                                 domainName,
                                                                 ResourcePermissions.getInstance(customPermissionName),
                                                                 ResourcePermissions
                                                                       .getInstanceWithGrantOption(customPermissionName))) {
         fail("checking post create resource permission with duplicate permissions (with different grant options) should have succeeded");
      }
      if (!accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                                 resourceClassName,
                                                                 domainName,
                                                                 setOf(ResourcePermissions
                                                                             .getInstance(customPermissionName),
                                                                       ResourcePermissions
                                                                             .getInstanceWithGrantOption(customPermissionName)))) {
         fail("checking post create resource permission with duplicate permissions (with different grant options) should have succeeded");
      }
   }

   @Test
   public void hasPostCreateResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");
      final String domainName = generateDomain();

      try {
         accessControlContext.hasPostCreateResourcePermissions(invalidResource,
                                                               resourceClassName,
                                                               domainName,
                                                               ResourcePermissions.getInstance(customPermissionName));
         fail("checking post-create resource permission (by domain) for invalid accessor resource reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(invalidExternalResource,
                                                               resourceClassName,
                                                               domainName,
                                                               ResourcePermissions.getInstance(customPermissionName));
         fail("checking post-create resource permission (by domain) for invalid external accessor resource reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(mismatchedResource,
                                                               resourceClassName,
                                                               domainName,
                                                               ResourcePermissions.getInstance(customPermissionName));
         fail("checking post-create resource permission (by domain) for mismatched internal/external resource references should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               "invalid_resource_class",
                                                               domainName,
                                                               ResourcePermissions.getInstance(customPermissionName));
         fail("checking post-create resource permission (by domain) for invalid resource class reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               "invalid_domain",
                                                               ResourcePermissions.getInstance(customPermissionName));
         fail("checking post-create resource permission (by domain) for invalid domain reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               ResourcePermissions.getInstance("invalid_permission"));
         fail("checking post-create resource permission (by domain) for invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               ResourcePermissions.getInstance(customPermissionName),
                                                               ResourcePermissions.getInstance("invalid_permission"));
         fail("checking post-create resource permission (by domain) for valid and invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }

      // test set-based versions
      try {
         accessControlContext.hasPostCreateResourcePermissions(invalidResource,
                                                               resourceClassName,
                                                               domainName,
                                                               setOf(ResourcePermissions
                                                                           .getInstance(customPermissionName)));
         fail("checking post-create resource permission (by domain) for invalid accessor resource reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(invalidExternalResource,
                                                               resourceClassName,
                                                               domainName,
                                                               setOf(ResourcePermissions
                                                                           .getInstance(customPermissionName)));
         fail("checking post-create resource permission (by domain) for invalid external accessor resource reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(mismatchedResource,
                                                               resourceClassName,
                                                               domainName,
                                                               setOf(ResourcePermissions
                                                                           .getInstance(customPermissionName)));
         fail("checking post-create resource permission (by domain) for mismatched internal/external resource references should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               "invalid_resource_class",
                                                               domainName,
                                                               setOf(ResourcePermissions
                                                                           .getInstance(customPermissionName)));
         fail("checking post-create resource permission (by domain) for invalid resource class reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               "invalid_domain",
                                                               setOf(ResourcePermissions
                                                                           .getInstance(customPermissionName)));
         fail("checking post-create resource permission (by domain) for invalid domain reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               setOf(ResourcePermissions
                                                                           .getInstance("invalid_permission")));
         fail("checking post-create resource permission (by domain) for invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.hasPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               setOf(ResourcePermissions
                                                                           .getInstance(customPermissionName),
                                                                     ResourcePermissions
                                                                           .getInstance("invalid_permission")));
         fail("checking post-create resource permission (by domain) for valid and invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
   }
}