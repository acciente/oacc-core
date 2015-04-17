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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_grantResourceCreatePermissions extends TestAccessControlBase {
   @Test
   public void grantResourceCreatePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE), false);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true), true);
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre
            = setOf(createPerm_create_withGrant, createPerm_impersonate, createPerm_inherit_withGrant, createPerm_resetPwd);

      // grant create permissions and verify
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          createPerm_create_withGrant,
                                                          createPerm_impersonate,
                                                          createPerm_inherit_withGrant,
                                                          createPerm_resetPwd);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre));
   }

   @Test
   public void grantResourceCreatePermissions_validAsAuthorized() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant, true);

      // set up the grantorResource
      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      Set<ResourceCreatePermission> grantorPermissions = setOf(createPerm_create_withGrant,
                                                               createPerm_inherit_withGrant);

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // now authenticate as the granterResource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // prep for the createPermissions to be assigned to the accessorResource
      final Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // grant create permissions and verify
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          ResourceCreatePermissions
                                                                .getInstance(ResourceCreatePermissions.CREATE, false),
                                                          createPerm_inherit_withGrant);

      Set<ResourceCreatePermission> resourceCreatePermissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false),
                    createPerm_inherit_withGrant);
      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_validWithDefaultSessionDomain() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant, true);

      // set up the grantorResource
      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);

      Set<ResourceCreatePermission> grantorPermissions = setOf(createPerm_create_withGrant, createPerm_inherit_withGrant);

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // now authenticate as the granterResource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // prep for the createPermissions to be assigned to the accessorResource
      final Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));


      // grant create permissions using the implicit session domain and verify
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          ResourceCreatePermissions
                                                                .getInstance(ResourceCreatePermissions.CREATE, false),
                                                          createPerm_inherit_withGrant);

      Set<ResourceCreatePermission> resourceCreatePermissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false),
                    createPerm_inherit_withGrant);
      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_addPermission_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantablePermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantablePermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      final String grantorDomain = accessControlContext.getDomainNameByResource(grantorResource);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        grantorDomain,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, grantorDomain),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantablePermissionName), true));
      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, grantorDomain, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, grantorDomain),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          ResourceCreatePermissions
                                                                .getInstance(ResourcePermissions.getInstance(grantablePermissionName)));

      Set<ResourceCreatePermission> permissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantablePermissionName)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));

      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          ResourceCreatePermissions
                                                                .getInstance(ResourcePermissions.getInstance(grantablePermissionName)));
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, grantorDomain),
                 is(permissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_addPermission_withAndWithoutGrant_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantablePermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantablePermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantablePermissionName), true));
      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      final String grantorDomain = accessControlContext.getDomainNameByResource(grantorResource);
      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, grantorDomain, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, grantorDomain),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantablePermissionName)),
                                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));
         fail("granting resource create permission without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantablePermissionName)),
                                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));
         fail("granting resource create permission without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
   }

   @Test
   public void grantResourceCreatePermissions_addPermission_withUnauthorizedPermissionsGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantablePermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantablePermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantablePermissionName), true));
      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      final String grantorDomain = accessControlContext.getDomainNameByResource(grantorResource);
      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, grantorDomain, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, grantorDomain),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantablePermissionName)),
                                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));
         fail("granting existing resource create permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantablePermissionName)),
                                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));
         fail("granting existing resource create permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
   }

   @Test
   public void grantResourceCreatePermissions_regrantPermissions() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant, true);

      // set up the grantorResource
      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);

      Set<ResourceCreatePermission> grantorPermissions = setOf(createPerm_create_withGrant, createPerm_inherit_withGrant);

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // now authenticate as the granterResource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // prep for the createPermissions to be assigned to the accessorResource
      final Resource accessorResource = generateUnauthenticatableResource();

      // grant create permissions and verify
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          ResourceCreatePermissions
                                                                .getInstance(ResourceCreatePermissions.CREATE, false),
                                                          createPerm_inherit_withGrant);

      Set<ResourceCreatePermission> resourceCreatePermissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false),
                    createPerm_inherit_withGrant);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(resourceCreatePermissions_expected));

      // regrant create permissions and verify nothing changed
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          createPerm_inherit_withGrant);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(resourceCreatePermissions_expected));

      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          createPerm_inherit_withGrant);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(resourceCreatePermissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_downgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions
                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true), true),
                    ResourceCreatePermissions
                          .getInstance(ResourcePermissions.getInstance(customPermissionName), true));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true),
                    ResourceCreatePermissions
                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true), true),
                    ResourceCreatePermissions
                          .getInstance(ResourcePermissions.getInstance(customPermissionName, true), true));


      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT,
                                                                                               true)),
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstance(customPermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(accessorPermissions_pre));
   }

   @Test
   public void grantResourceCreatePermissions_downgradePostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions
                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true), true),
                    ResourceCreatePermissions
                          .getInstance(ResourcePermissions.getInstance(customPermissionName, true), false));

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true),
                    ResourceCreatePermissions
                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true), true),
                    ResourceCreatePermissions
                          .getInstance(ResourcePermissions.getInstance(customPermissionName, true), true));


      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                               true),
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstance(customPermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(accessorPermissions_pre));
   }

   @Test
   public void grantResourceCreatePermissions_downgradeGrantingAndPostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions
                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true), true));

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true),
                    ResourceCreatePermissions
                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true), true));


      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(accessorPermissions_pre));
   }

   @Test
   public void grantResourceCreatePermissions_downgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantablePermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantablePermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantablePermissionName),
                                                          true));

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true));
      grantorPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantablePermissionName),
                                                                   true));

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      Set<ResourceCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            grantablePermissionName)));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            ungrantablePermissionName)));

      try {
         accessControlContext
               .grantResourceCreatePermissions(accessorResource,
                                               resourceClassName,
                                               domainName,
                                               ResourceCreatePermissions
                                                     .getInstance(ResourceCreatePermissions.CREATE),
                                               ResourceCreatePermissions
                                                     .getInstance(ResourcePermissions.getInstance(grantablePermissionName)),
                                               ResourceCreatePermissions
                                                     .getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));
         fail("Downgrading (=removal of granting rights) of create-permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
   }

   @Test
   public void grantResourceCreatePermissions_upgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true),
                                                          true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName, true),
                                                          true));

      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions
                                                                     .getInstance(ResourcePermissions.INHERIT, true),
                                                               true),
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstance(grantedPermissionName),
                                                               true));

      Set<ResourceCreatePermission> permissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName), true));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_upgradePostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true),
                                                          true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName, true),
                                                          true));

      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions
                                                                     .getInstance(ResourcePermissions.INHERIT, true),
                                                               true),
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstance(grantedPermissionName, true)));

      Set<ResourceCreatePermission> permissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName, true)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_upgradeGrantingRightsAndPostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName, true),
                                                          true));

      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstance(grantedPermissionName, true),
                                                               true));

      Set<ResourceCreatePermission> permissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName, true), true));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_upgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantedPermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            ungrantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      grantorPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName),
                                                                   true));

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourceCreatePermissions.getInstance(
                                                                   ResourceCreatePermissions.CREATE),
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName)),
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourcePermissions.getInstance(ungrantedPermissionName, true)));
         fail("Upgrading (=addition of granting rights) of create-permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void grantResourceCreatePermissions_withoutCreate_shouldFail() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to grant create permissions without *CREATE system permission
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_inherit);
         fail("granting create-permissions without *CREATE system permission when accessor doesn't already have it, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("*create must be specified"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_withoutGrantableCreate_shouldSucceed() {
      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // set up the grantorResource
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true),
                                                          true));

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // now authenticate as the granterResource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant create permissions and verify
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      Set<ResourceCreatePermission> resourceCreatePermissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions
                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(resourceCreatePermissions_expected));

      // grant duplicate create permissions for implicit domain
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(resourceCreatePermissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_resetCredentialsPermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName).isEmpty(),
                 is(true));

      // attempt to grant *RESET_CREDENTIALS system permission
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourceCreatePermissions.CREATE),
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourcePermissions
                                                                                      .getInstance(ResourcePermissions.RESET_CREDENTIALS)));
         fail("granting *RESET_CREDENTIALS system permission as a create permission on an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourceCreatePermissions.CREATE),
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourcePermissions
                                                                                      .getInstance(ResourcePermissions.RESET_CREDENTIALS)));
         fail("granting *RESET_CREDENTIALS system permission as a create permission on an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_impersonatePermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName).isEmpty(),
                 is(true));

      // attempt to grant *IMPERSONATE system permission
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourceCreatePermissions.CREATE),
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourcePermissions
                                                                                      .getInstance(ResourcePermissions.IMPERSONATE)));
         fail("granting *IMPERSONATE system permission as a create permission on an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourceCreatePermissions.CREATE),
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourcePermissions
                                                                                      .getInstance(ResourcePermissions.IMPERSONATE)));
         fail("granting *IMPERSONATE system permission as a create permission on an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_mismatchedResourceClassAndPermission_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName1 = generateResourceClass(true, false);
      final String resourceClassName2 = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      final String permissionName1 = generateResourceClassPermission(resourceClassName1);

      // attempt to grant global permissions for mismatched resource class and permission
      try {
         accessControlContext
               .grantResourceCreatePermissions(accessorResource,
                                               resourceClassName2,
                                               domainName,
                                               ResourceCreatePermissions
                                                     .getInstance(ResourcePermissions.getInstance(permissionName1)));
         fail("granting create permissions with mismatched resource class and permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not exist for the specified resource class"));
      }
      try {
         accessControlContext
               .grantResourceCreatePermissions(accessorResource,
                                               resourceClassName2,
                                               ResourceCreatePermissions
                                                     .getInstance(ResourcePermissions.getInstance(permissionName1)));
;
         fail("granting create permissions with mismatched resource class and permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not exist for the specified resource class"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_whitespaceConsistent() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";
      final String resourceClassName = generateResourceClass(false, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false);
      final ResourceCreatePermission createPerm_customPerm
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName), false);
      final ResourceCreatePermission createPerm_customPerm_ws
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName + " \t"), false);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // grant create permissions and verify
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName_whitespaced,
                                                          domainName_whitespaced,
                                                          createPerm_create,
                                                          createPerm_customPerm_ws);

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(createPerm_create);
      permissions_expected.add(createPerm_customPerm_ws);
      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(permissions_expected));
      assertThat(resourceCreatePermissions_post, hasItem(createPerm_create));
      assertThat(resourceCreatePermissions_post, hasItem(createPerm_customPerm));     // whitespace is trimmed upon permission creation
      assertThat(resourceCreatePermissions_post, hasItem(createPerm_customPerm_ws));

      // grant create permissions with implicit domain and verify
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName_whitespaced,
                                                          createPerm_create,
                                                          createPerm_customPerm_ws);

      final Set<ResourceCreatePermission> resourceCreatePermissions_implicitDomain_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(resourceCreatePermissions_implicitDomain_post, is(permissions_expected));
      assertThat(resourceCreatePermissions_implicitDomain_post, hasItem(createPerm_create));
      assertThat(resourceCreatePermissions_implicitDomain_post, hasItem(createPerm_customPerm));     // whitespace is trimmed upon permission creation
      assertThat(resourceCreatePermissions_implicitDomain_post, hasItem(createPerm_customPerm_ws));
   }

   @Test
   public void grantResourceCreatePermissions_caseSensitiveConsistent() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName = generateUniquePermissionName();
      final String permissionName_lower = permissionName + "_ppp";
      final String permissionName_UPPER = permissionName + "_PPP";
      accessControlContext.createResourcePermission(resourceClassName, permissionName_lower);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false);
      final ResourceCreatePermission createPerm_lower
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName_lower), false);
      final ResourceCreatePermission createPerm_UPPER
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName_UPPER), false);

      if (isDatabaseCaseSensitive()) {
         accessControlContext.createResourcePermission(resourceClassName, permissionName_UPPER);

         assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

         // grant create permissions and verify
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create,
                                                             createPerm_UPPER);

         Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
         permissions_expected.add(createPerm_create);
         permissions_expected.add(createPerm_UPPER);
         final Set<ResourceCreatePermission> resourceCreatePermissions_post
               = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
         assertThat(resourceCreatePermissions_post, is(permissions_expected));
         assertThat(resourceCreatePermissions_post, hasItem(createPerm_create));
         assertThat(resourceCreatePermissions_post, hasItem(createPerm_UPPER));
         assertThat(resourceCreatePermissions_post, not(hasItem(createPerm_lower)));     // whitespace is trimmed upon permission creation
      }
      else {
         assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

         // grant create permissions and verify
         try {
            accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                                resourceClassName,
                                                                domainName,
                                                                createPerm_create,
                                                                createPerm_UPPER);
            fail("granting resource create permission with the name of an existing permission that differs in case only should have failed for case-insensitive databases");
         }
         catch (IllegalArgumentException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("does not exist"));
         }
      }
   }

   @Test
   public void grantResourceCreatePermissions_duplicatePermissions_shouldSucceed() {
      final ResourcePermission resourcePermission_inherit
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT);
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit, true);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant, true);

      // set up the grantorResource
      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);

      Set<ResourceCreatePermission> grantorPermissions = setOf(createPerm_create_withGrant, createPerm_inherit_withGrant);

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // now authenticate as the granterResource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // prep for the createPermissions to be assigned to the accessorResource
      final Resource accessorResource = generateUnauthenticatableResource();

      // grant create permissions and verify
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          ResourceCreatePermissions
                                                                .getInstance(ResourceCreatePermissions.CREATE, false),
                                                          createPerm_inherit,
                                                          createPerm_inherit);

      Set<ResourceCreatePermission> resourceCreatePermissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false),
                    createPerm_inherit);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(resourceCreatePermissions_expected));

      // grant duplicate create permissions for implicit domain
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          createPerm_inherit_withGrant,
                                                          createPerm_inherit_withGrant);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false),
                          createPerm_inherit_withGrant)));
   }

   @Test
   public void grantResourceCreatePermissions_duplicatePermissionNames_shouldFail() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant = ResourceCreatePermissions.getInstance(
            ResourceCreatePermissions.CREATE,
            true);
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true));
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true),
                                                    true);

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // define a set of create permissions that contains the same permission twice, but with different grant-options
      Set<ResourceCreatePermission> resourceCreatePermissions_pre = new HashSet<>();
      resourceCreatePermissions_pre.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre.add(createPerm_inherit_withGrant);
      resourceCreatePermissions_pre.add(createPerm_inherit);

      // attempt to grant create permissions with "near" duplicates
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create_withGrant,
                                                             createPerm_inherit_withGrant,
                                                             createPerm_inherit);
         fail("granting create-permissions that include the same permission, but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             createPerm_create_withGrant,
                                                             createPerm_inherit_withGrant,
                                                             createPerm_inherit);
         fail("granting create-permissions that include the same permission, but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to grant create permissions with null parameters
      try {
         accessControlContext.grantResourceCreatePermissions(null,
                                                             resourceClassName,
                                                             createPerm_create_withGrant,
                                                             createPerm_inherit);
         fail("granting create-permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(null,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create_withGrant,
                                                             createPerm_inherit);
         fail("granting create-permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             null,
                                                             createPerm_create_withGrant,
                                                             createPerm_inherit);
         fail("granting create-permissions with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             null,
                                                             domainName,
                                                             createPerm_create_withGrant,
                                                             createPerm_inherit);
         fail("granting create-permissions with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             null);
         fail("granting create-permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             null);
         fail("granting create-permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             createPerm_create_withGrant,
                                                             null);
         fail("granting create-permissions with null element in permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("an array or a sequence"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create_withGrant,
                                                             null);
         fail("granting create-permissions with null element in permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("an array or a sequence"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             (String) null,
                                                             createPerm_create_withGrant,
                                                             createPerm_inherit);
         fail("granting create-permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_invalid
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance("invalid_permission", false));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // define a valid set of create permissions
      Set<ResourceCreatePermission> resourceCreatePermissions_valid = new HashSet<>();
      resourceCreatePermissions_valid.add(createPerm_create_withGrant);

      // define a set of create permissions that includes an invalid permission reference
      Set<ResourceCreatePermission> resourceCreatePermissions_invalid = new HashSet<>();
      resourceCreatePermissions_invalid.add(createPerm_create_withGrant);
      resourceCreatePermissions_invalid.add(createPerm_invalid);

      // attempt to grant create permissions with invalid references
      try {
         accessControlContext.grantResourceCreatePermissions(Resources.getInstance(-999L),
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create_withGrant);
         fail("granting create-permissions with reference to non-existent accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             "invalid_resource_class",
                                                             domainName,
                                                             createPerm_create_withGrant);
         fail("granting create-permissions with reference to non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             "invalid_resource_domain",
                                                             createPerm_create_withGrant);
         fail("granting create-permissions with reference to non-existent domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create_withGrant,
                                                             createPerm_invalid);
         fail("granting create-permissions with reference to non-existent permission name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not exist for the specified resource class"));
      }
   }
}
