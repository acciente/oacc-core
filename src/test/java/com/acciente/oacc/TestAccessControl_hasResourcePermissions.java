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
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_hasResourcePermissions extends TestAccessControlBase {
   @Test
   public void hasResourcePermissions_succeedsAsSystemResource() {
      authenticateSystemResource();

      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      final Resource accessedResource = accessControlContext.createResource(resourceClassName,
                                                                            accessControlContext
                                                                                  .getDomainNameByResource(SYS_RESOURCE));

      // verify setup
      final Set<ResourcePermission> directResourcePermissions
            = accessControlContext.getResourcePermissions(SYS_RESOURCE, accessedResource);
      assertThat(directResourcePermissions.isEmpty(), is(true));

      // verify
      if (!accessControlContext.hasResourcePermissions(SYS_RESOURCE,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(customPermissionName))) {
         fail("checking implicit resource permission for system resource should have succeeded");
      }
      if (!accessControlContext.hasResourcePermissions(SYS_RESOURCE,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(customPermissionName),
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT))) {
         fail("checking multiple implicit resource permission for system resource should have succeeded");
      }

      if (!accessControlContext.hasResourcePermissions(SYS_RESOURCE,
                                                       accessedResource,
                                                       setOf(ResourcePermissions.getInstance(customPermissionName)))) {
         fail("checking implicit resource permission for system resource should have succeeded");
      }
      if (!accessControlContext.hasResourcePermissions(SYS_RESOURCE,
                                                       accessedResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(customPermissionName),
                                                             ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT)))) {
         fail("checking multiple implicit resource permission for system resource should have succeeded");
      }
   }

   @Test
   public void hasResourcePermissions_noPermissions_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final Resource accessedResource
            = accessControlContext.createResource(resourceClassName,
                                                  accessControlContext.getDomainNameByResource(SYS_RESOURCE),
                                                  PasswordCredentials.newInstance(generateUniquePassword()));

      // verify setup
      final Set<ResourcePermission> allResourcePermissions
            = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(allResourcePermissions.isEmpty(), is(true));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (accessControlContext.hasResourcePermissions(accessorResource,
                                                      accessedResource,
                                                      ResourcePermissions.getInstance(customPermissionName))) {
         fail("checking resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      if (accessControlContext.hasResourcePermissions(accessorResource,
                                                      accessedResource,
                                                      ResourcePermissions.getInstance(customPermissionName),
                                                      ResourcePermissions.getInstance(ResourcePermissions.INHERIT))) {
         fail("checking multiple resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }

      if (accessControlContext.hasResourcePermissions(accessorResource,
                                                      accessedResource,
                                                      setOf(ResourcePermissions.getInstance(customPermissionName)))) {
         fail("checking resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      if (accessControlContext.hasResourcePermissions(accessorResource,
                                                      accessedResource,
                                                      setOf(ResourcePermissions
                                                                  .getInstance(customPermissionName),
                                                            ResourcePermissions
                                                                  .getInstance(ResourcePermissions.INHERIT)))) {
         fail("checking multiple resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourcePermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate resource without query authorization
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission);
         fail("checking resource permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, accessedResource, setOf(customPermission));
         fail("checking resource permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void hasResourcePermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate resource with implicit query authorization
      accessControlContext.grantResourcePermissions(authenticatableResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission)) {
         fail("checking resource permissions with implicit query authorization should have succeeded");
      }
      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, setOf(customPermission))) {
         fail("checking resource permissions with implicit query authorization should have succeeded");
      }
   }

   @Test
   public void hasResourcePermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate resource with query authorization
      grantQueryPermission(authenticatableResource, accessorResource);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission)) {
         fail("checking resource permissions with query authorization should have succeeded");
      }
      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, setOf(customPermission))) {
         fail("checking resource permissions with query authorization should have succeeded");
      }
   }

   @Test
   public void hasResourcePermissions_direct_succeedsAsAuthenticatedResource() {
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
      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission)) {
         fail("checking direct resource permission for authenticated resource should have succeeded");
      }

      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, setOf(customPermission))) {
         fail("checking direct resource permission for authenticated resource should have succeeded");
      }
   }

   @Test
   public void hasResourcePermissions_direct_withExtId() {
      authenticateSystemResource();

      final String accessorExternalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(accessorExternalId);
      final String accessedExternalId = generateUniqueExternalId();
      final Resource accessedResource = generateUnauthenticatableResourceWithExtId(accessedExternalId);
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // verify
      if (!accessControlContext.hasResourcePermissions(Resources.getInstance(accessorExternalId), accessedResource, customPermission)) {
         fail("checking direct resource permission for external accessor id should have succeeded");
      }
      if (!accessControlContext.hasResourcePermissions(Resources.getInstance(accessorExternalId), accessedResource, setOf(customPermission))) {
         fail("checking direct resource permission for external accessor id should have succeeded");
      }

      if (!accessControlContext.hasResourcePermissions(accessorResource,
                                                       Resources.getInstance(accessedExternalId),
                                                       customPermission)) {
         fail("checking direct resource permission for external accessed id should have succeeded");
      }
      if (!accessControlContext.hasResourcePermissions(accessorResource, Resources.getInstance(accessedExternalId), setOf(customPermission))) {
         fail("checking direct resource permission for external accessed id should have succeeded");
      }
   }

   @Test
   public void hasResourcePermissions_partialDirect_shouldFailAsAuthenticatedResource() {
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
      if (accessControlContext.hasResourcePermissions(accessorResource,
                                                      accessedResource,
                                                      customPermission,
                                                      ResourcePermissions.getInstance(ResourcePermissions.INHERIT))) {
         fail("checking direct and unauthorized resource permission for authenticated resource should have failed");
      }

      if (accessControlContext.hasResourcePermissions(accessorResource,
                                                      accessedResource,
                                                      setOf(customPermission,
                                                            ResourcePermissions
                                                                  .getInstance(ResourcePermissions.INHERIT)))) {
         fail("checking direct and unauthorized resource permission for authenticated resource should have failed");
      }
   }

   @Test
   public void hasResourcePermissions_multipleDirect_succeedsAsAuthenticatedResource() {
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
                                                  setOf(customPermission,
                                                        ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       customPermission,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT))) {
         fail("checking multiple valid direct resource permission for authenticated resource should have succeeded");
      }

      if (!accessControlContext.hasResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       setOf(customPermission,
                                                             ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT)))) {
         fail("checking multiple valid direct resource permission for authenticated resource should have succeeded");
      }
   }

   @Test
   public void hasResourcePermissions_directWithDifferentGrantingRights_succeedsAsAuthenticatedResource() {
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
            = ResourcePermissions.getInstanceWithGrantOption(customPermissionName1);

      final String customPermissionName2 = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission2_withoutGrant
            = ResourcePermissions.getInstance(customPermissionName2);
      final ResourcePermission customPermission2_withGrant
            = ResourcePermissions.getInstanceWithGrantOption(customPermissionName2);

      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission1_withGrant, customPermission2_withoutGrant));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       customPermission1_withoutGrant,
                                                       customPermission1_withGrant)) {
         fail("checking resource permission with different grant than the one granted should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission2_withoutGrant)) {
         fail("checking resource permission with different grant than the one granted should have succeeded for authenticated resource");
      }

      if (accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission2_withGrant)) {
         fail("checking resource permission with grant when the one granted does not have grant should not have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       setOf(customPermission1_withoutGrant,
                                                             customPermission1_withGrant))) {
         fail("checking resource permission with different grant than the one granted should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, setOf(customPermission2_withoutGrant))) {
         fail("checking resource permission with different grant than the one granted should have succeeded for authenticated resource");
      }

      if (accessControlContext.hasResourcePermissions(accessorResource, accessedResource, setOf(customPermission2_withGrant))) {
         fail("checking resource permission with grant when the one granted does not have grant should not have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourcePermissions_resourceInherited_succeedsAsAuthenticatedResource() {
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
      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission)) {
         fail("checking inherited resource permission should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, setOf(customPermission))) {
         fail("checking inherited resource permission should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourcePermissions_domainInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      final String accessedDomainName = generateUniqueDomainName();
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
      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission)) {
         fail("checking domain-inherited resource permission should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, setOf(customPermission))) {
         fail("checking domain-inherited resource permission should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourcePermissions_domainInheritedInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      final String accessedDomainName = generateUniqueDomainName();
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
      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission)) {
         fail("checking inherited domain-inherited  resource permission should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, setOf(customPermission))) {
         fail("checking inherited domain-inherited  resource permission should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourcePermissions_superUser_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      final String accessedDomainName = generateUniqueDomainName();
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

      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission)) {
         fail("checking resource permission when having super-user privileges should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       customPermission,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT))) {
         fail("checking multiple resource permission when having super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, setOf(customPermission))) {
         fail("checking resource permission when having super-user privileges should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       setOf(customPermission,
                                                             ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT)))) {
         fail("checking multiple resource permission when having super-user privileges should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourcePermissions_superUserInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      final String accessedDomainName = generateUniqueDomainName();
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

      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission)) {
         fail("checking resource permission when inheriting super-user privileges should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       customPermission,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT))) {
         fail("checking multiple resource permission when inheriting super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, setOf(customPermission))) {
         fail("checking resource permission when inheriting super-user privileges should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       setOf(customPermission,
                                                             ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT)))) {
         fail("checking multiple resource permission when inheriting super-user privileges should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasResourcePermissions_superUserInvalidPermission_shouldFailAsSystemResource() {
      authenticateSystemResource();
      // setup unauthenticatable resource without any permissions
      final Resource unauthenticatableResource = generateUnauthenticatableResource();

      // verify
      try {
         accessControlContext.hasResourcePermissions(SYS_RESOURCE,
                                                     unauthenticatableResource,
                                                     ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));
         fail("checking implicit resource permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext.hasResourcePermissions(SYS_RESOURCE,
                                                     unauthenticatableResource,
                                                     ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("checking implicit global resource permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext.hasResourcePermissions(SYS_RESOURCE,
                                                     unauthenticatableResource,
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                     ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("checking multiple implicit global resource permission valid and invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }

      // test set-based versions
      try {
         accessControlContext.hasResourcePermissions(SYS_RESOURCE,
                                                     unauthenticatableResource,
                                                     setOf(ResourcePermissions
                                                                 .getInstance(ResourcePermissions.RESET_CREDENTIALS)));
         fail("checking implicit resource permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext.hasResourcePermissions(SYS_RESOURCE,
                                                     unauthenticatableResource,
                                                     setOf(ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE)));
         fail("checking implicit global resource permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext.hasResourcePermissions(SYS_RESOURCE,
                                                     unauthenticatableResource,
                                                     setOf(ResourcePermissions
                                                                 .getInstance(ResourcePermissions.INHERIT),
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE)));
         fail("checking multiple implicit global resource permission valid and invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
   }

   @Test
   public void hasResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      final String customPermissionName2 = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission2 = ResourcePermissions.getInstance(customPermissionName2);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.hasResourcePermissions(null, accessedResource, customPermission);
         fail("checking resource permission for null accessor resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.hasResourcePermissions(Resources.getInstance(null), accessedResource, customPermission);
         fail("checking resource permission for null internal/external accessor resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, (Resource) null, customPermission);
         fail("checking resource permission for null accessed resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, Resources.getInstance(null), customPermission);
         fail("checking resource permission for null internal/external accessed resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, accessedResource, (ResourcePermission) null);
         fail("checking resource permission with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission, null);
         fail("checking resource permission for null permission sequence should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     customPermission,
                                                     customPermission2,
                                                     null);
         fail("checking resource permission for null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission, new ResourcePermission[]{null});
         fail("checking resource permission for null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      // test set-based versions
      try {
         accessControlContext.hasResourcePermissions(null, accessedResource, setOf(customPermission));
         fail("checking resource permission for null accessor resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.hasResourcePermissions(Resources.getInstance(null), accessedResource, setOf(customPermission));
         fail("checking resource permission for null internal/external accessor resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, (Resource) null, setOf(customPermission));
         fail("checking resource permission for null accessed resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessedResource, Resources.getInstance(null), customPermission);
         fail("checking resource permission for null internal/external accessed resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, accessedResource, (Set<ResourcePermission>) null);
         fail("checking resource permission with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, accessedResource, setOf(customPermission, null));
         fail("checking resource permission for null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
   }

   @Test
   public void hasResourcePermissions_emptyPermissionSet_shouldFail() {
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
         accessControlContext.hasResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     Collections.<ResourcePermission>emptySet());
         fail("checking resource permission with null permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void hasResourcePermissions_emptyPermissions_shouldSucceed() {
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
      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission)) {
         fail("checking resource permission for empty permission sequence should have succeeded");
      }

      if (!accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission, new ResourcePermission[] {})) {
         fail("checking resource permission for empty permission sequence should have succeeded");
      }
   }

   @Test
   public void hasResourcePermissions_duplicatePermissions_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();

      // setup direct permissions
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.hasResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("checking resource permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void hasResourcePermissions_duplicatePermissions_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();

      // setup direct permissions
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                       ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT))) {
         fail("checking duplicate resource permission for authenticated resource should have succeeded");
      }

      if (!accessControlContext.hasResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT),
                                                             ResourcePermissions
                                                                   .getInstanceWithGrantOption(ResourcePermissions.INHERIT)))) {
         fail("checking duplicate resource permission for authenticated resource should have succeeded");
      }
   }

   @Test
   public void hasResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");
      final ResourcePermission invalidPermission = ResourcePermissions.getInstance("invalid_permission");

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
         accessControlContext.hasResourcePermissions(invalidResource, accessedResource, customPermission);
         fail("checking resource permission for invalid accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasResourcePermissions(invalidExternalResource, accessedResource, customPermission);
         fail("checking resource permission for invalid external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasResourcePermissions(mismatchedResource, accessedResource, customPermission);
         fail("checking resource permission for mismatched internal/external accessor resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, invalidResource, customPermission);
         fail("checking resource permission for invalid accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, invalidExternalResource, customPermission);
         fail("checking resource permission for invalid external accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, mismatchedResource, customPermission);
         fail("checking resource permission for mismatched internal/external accessed resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, accessedResource, invalidPermission);
         fail("checking resource permission with undefined permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, accessedResource, customPermission, invalidPermission);
         fail("checking resource permission with undefined permission element should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      // test set-based versions
      try {
         accessControlContext.hasResourcePermissions(invalidResource, accessedResource, setOf(customPermission));
         fail("checking resource permission for invalid accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasResourcePermissions(invalidExternalResource, accessedResource, setOf(customPermission));
         fail("checking resource permission for invalid external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasResourcePermissions(mismatchedResource, accessedResource, setOf(customPermission));
         fail("checking resource permission for mismatched internal/external accessor resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, invalidResource, setOf(customPermission));
         fail("checking resource permission for invalid accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, invalidExternalResource, setOf(customPermission));
         fail("checking resource permission for invalid external accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, mismatchedResource, setOf(customPermission));
         fail("checking resource permission for mismatched internal/external accessed resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, accessedResource, setOf(invalidPermission));
         fail("checking resource permission with undefined permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
      try {
         accessControlContext.hasResourcePermissions(accessorResource, accessedResource, setOf(customPermission, invalidPermission));
         fail("checking resource permission with undefined permission element should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }
}
