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
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_setResourceCreatePermissions extends TestAccessControlBase {
   @Test
   public void setResourceCreatePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre = new HashSet<>();
      resourceCreatePermissions_pre.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre.add(createPerm_impersonate);
      resourceCreatePermissions_pre.add(createPerm_inherit_withGrant);
      resourceCreatePermissions_pre.add(createPerm_resetPwd);

      // set create permissions and verify
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        resourceCreatePermissions_pre);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre));
   }

   @Test
   public void setResourceCreatePermissions_withExtId() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS));

      final String externalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre = new HashSet<>();
      resourceCreatePermissions_pre.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre.add(createPerm_impersonate);
      resourceCreatePermissions_pre.add(createPerm_inherit_withGrant);
      resourceCreatePermissions_pre.add(createPerm_resetPwd);

      // set create permissions and verify
      accessControlContext.setResourceCreatePermissions(Resources.getInstance(externalId),
                                                        resourceClassName,
                                                        domainName,
                                                        resourceCreatePermissions_pre);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre));
   }

   @Test
   public void setResourceCreatePermission_resetCredentialsPermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(),
                 is(true));

      Set<ResourceCreatePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      permissions_pre.add(ResourceCreatePermissions
                                .getInstance(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS)));

      // attempt to set *RESET_CREDENTIALS system permission
      try {
         accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, permissions_pre);
         fail("granting *RESET_CREDENTIALS system permission as a create permission on an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void setResourceCreatePermission_impersonatePermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(),
                 is(true));

      Set<ResourceCreatePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      permissions_pre.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // attempt to set *IMPERSONATE system permission
      try {
         accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, permissions_pre);
         fail("granting *IMPERSONATE system permission as a create permission on an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void setResourceCreatePermissions_validAsAuthorized() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(resourcePermission_inherit_withGrant);

      // set up the grantorResource
      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(createPerm_create_withGrant);
      grantorPermissions.add(createPerm_inherit_withGrant);

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
      grantQueryPermission(grantorResource, accessorResource);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre = new HashSet<>();
      resourceCreatePermissions_pre.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      resourceCreatePermissions_pre.add(createPerm_inherit_withGrant);

      // set create permissions and verify
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        resourceCreatePermissions_pre);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre));
   }

   @Test
   public void setResourceCreatePermissions_resetPermissions() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre1 = new HashSet<>();
      resourceCreatePermissions_pre1.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre1.add(createPerm_impersonate);
      resourceCreatePermissions_pre1.add(createPerm_inherit_withGrant);

      // set create permissions and verify
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        resourceCreatePermissions_pre1);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post1
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post1, is(resourceCreatePermissions_pre1));

      // reset create permissions and verify that only the latest apply
      Set<ResourceCreatePermission> resourceCreatePermissions_pre2 = new HashSet<>();
      resourceCreatePermissions_pre2.add(createPerm_create);
      resourceCreatePermissions_pre2.add(createPerm_resetPwd);
      resourceCreatePermissions_pre2.add(createPerm_inherit);

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        resourceCreatePermissions_pre2);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post2
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post2, is(resourceCreatePermissions_pre2));

      // reset create permissions to empty set (i.e. remove all) and verify
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        Collections.<ResourceCreatePermission>emptySet());

      final Set<ResourceCreatePermission> resourceCreatePermissions_post3
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post3.isEmpty(), is(true));
   }

   @Test
   public void setResourceCreatePermissions_whitespaceConsistent() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";
      final String resourceClassName = generateResourceClass(false, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_customPerm
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName));
      final ResourceCreatePermission createPerm_customPerm_ws
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName + " \t"));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre = new HashSet<>();
      resourceCreatePermissions_pre.add(createPerm_create);
      resourceCreatePermissions_pre.add(createPerm_customPerm_ws);

      // set create permissions and verify
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName_whitespaced,
                                                        domainName_whitespaced,
                                                        resourceCreatePermissions_pre);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre));
      assertThat(resourceCreatePermissions_post, hasItem(createPerm_create));
      assertThat(resourceCreatePermissions_post, hasItem(createPerm_customPerm));     // whitespace is trimmed upon permission creation
      assertThat(resourceCreatePermissions_post, hasItem(createPerm_customPerm_ws));
   }

   @Test
   public void setResourceCreatePermissions_caseSensitiveConsistent() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName = generateUniquePermissionName();
      final String permissionName_lower = permissionName + "_ppp";
      final String permissionName_UPPER = permissionName + "_PPP";
      accessControlContext.createResourcePermission(resourceClassName, permissionName_lower);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_lower
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName_lower));
      final ResourceCreatePermission createPerm_UPPER
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName_UPPER));

      if (isDatabaseCaseSensitive()) {
         accessControlContext.createResourcePermission(resourceClassName, permissionName_UPPER);

         assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

         Set<ResourceCreatePermission> resourceCreatePermissions_pre = new HashSet<>();
         resourceCreatePermissions_pre.add(createPerm_create);
         resourceCreatePermissions_pre.add(createPerm_UPPER);

         // set create permissions and verify
         accessControlContext.setResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           resourceCreatePermissions_pre);

         final Set<ResourceCreatePermission> resourceCreatePermissions_post
               = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
         assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre));
         assertThat(resourceCreatePermissions_post, hasItem(createPerm_create));
         assertThat(resourceCreatePermissions_post, hasItem(createPerm_UPPER));
         assertThat(resourceCreatePermissions_post, not(hasItem(createPerm_lower)));     // whitespace is trimmed upon permission creation
      }
      else {
         assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

         Set<ResourceCreatePermission> resourceCreatePermissions_pre = new HashSet<>();
         resourceCreatePermissions_pre.add(createPerm_create);
         resourceCreatePermissions_pre.add(createPerm_UPPER);

         // set create permissions and verify
         try {
            accessControlContext.setResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              resourceCreatePermissions_pre);
            fail("setting resource create permission with the name of an existing permission that differs in case only should have failed for case-insensitive databases");
         }
         catch (IllegalArgumentException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
         }
      }
   }

   @Test
   public void setResourceCreatePermission_addPermission_withUnauthorizedPermissionsGrantedElsewhere_shouldSucceedAsAuthorized() {
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
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE));
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourceCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            grantedPermissionName)));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            ungrantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName)));
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantedPermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourceCreatePermission_removePermission_withUnauthorizedPermissionsGrantedElsewhere_shouldSucceedAsAuthorized() {
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
            grantedPermissionName)));
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            ungrantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
//      grantorPermissions.add(ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, true));
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourceCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            ungrantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantedPermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourceCreatePermission_downgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(
            grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE));
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourceCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            grantedPermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourceCreatePermission_downgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
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
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(
            ungrantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE));
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourceCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            grantedPermissionName)));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            ungrantedPermissionName)));

      try {
         accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);
         fail("Downgrading (=removal of granting rights) of create-permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void setResourceCreatePermission_upgradeGrantingRightsAndPostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE));
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions
                                                                         .getInstanceWithGrantOption(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourceCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(
            grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(
            grantedPermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourceCreatePermission_upgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
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
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourceCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      requestedPermissions.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstance(grantedPermissionName)));
      requestedPermissions.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstanceWithGrantOption(ungrantedPermissionName)));

      try {
         accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);
         fail("Upgrading (=addition of granting rights) of create-permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void setResourceCreatePermission_upgradePostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE));
      grantorPermissions.add(ResourceCreatePermissions
                                   .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourceCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(
            grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(
            grantedPermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourceCreatePermission_downgradePostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(
            grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE));
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourceCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            grantedPermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourceCreatePermission_upgradePostCreateGrantingRights_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE));
      grantorPermissions.add(ResourceCreatePermissions
                                   .getInstanceWithGrantOption(ResourcePermissions.getInstance(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourceCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(
            grantedPermissionName)));

      try {
         accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);
         fail("Upgrading (=addition of granting rights) a post-create permission, to which I have no post-create granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(grantedPermissionName));
      }
   }

   @Test
   public void setResourceCreatePermission_downgradePostCreateGrantingRights_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(
            grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE));
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourceCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            grantedPermissionName)));

      try {
         accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);
         fail("Downgrading (=removal of granting rights) a post-create permission, to which I have no post-create granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(grantedPermissionName));
      }
   }


   @Test
   public void setResourceCreatePermissions_duplicatePermissionNames_shouldFail() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // define a set of create permissions that contains the same permission twice, but with different grant-options
      Set<ResourceCreatePermission> resourceCreatePermissions_pre = new HashSet<>();
      resourceCreatePermissions_pre.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre.add(createPerm_inherit_withGrant);
      resourceCreatePermissions_pre.add(createPerm_inherit);

      // attempt to set create permissions with "near" duplicates
      try {
         accessControlContext.setResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           resourceCreatePermissions_pre);
         fail("setting create-permissions that include the same permission, but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
      try {
         accessControlContext.setResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           setOf(createPerm_create,
                                                                 createPerm_create_withGrant));
         fail("setting create-permissions that include the same permission, but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void setResourceCreatePermissions_withoutCreate_shouldFail() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // define a set of create permissions without the *CREATE system permission
      Set<ResourceCreatePermission> resourceCreatePermissions_pre = new HashSet<>();
      resourceCreatePermissions_pre.add(createPerm_inherit);

      // attempt to set create permissions without *CREATE system permission
      try {
         accessControlContext.setResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           resourceCreatePermissions_pre);
         fail("setting create-permissions without *CREATE system permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("*create must be specified"));
      }
   }

   @Test
   public void setResourceCreatePermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // define an empty set of create permissions
      Set<ResourceCreatePermission> resourceCreatePermissions_nullElement = new HashSet<>();
      resourceCreatePermissions_nullElement.add(null);

      // define a set of create permissions
      Set<ResourceCreatePermission> resourceCreatePermissions_pre = new HashSet<>();
      resourceCreatePermissions_pre.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre.add(createPerm_inherit);

      // attempt to set create permissions with null parameters
      try {
         accessControlContext.setResourceCreatePermissions(null,
                                                           resourceClassName,
                                                           domainName,
                                                           resourceCreatePermissions_pre);
         fail("setting create-permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.setResourceCreatePermissions(Resources.getInstance(null),
                                                           resourceClassName,
                                                           domainName,
                                                           resourceCreatePermissions_pre);
         fail("setting create-permissions with null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.setResourceCreatePermissions(accessorResource,
                                                           null,
                                                           domainName,
                                                           resourceCreatePermissions_pre);
         fail("setting create-permissions with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.setResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           null);
         fail("setting create-permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.setResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           resourceCreatePermissions_nullElement);
         fail("setting create-permissions with null element in permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("set of permissions contains null element"));
      }

      try {
         accessControlContext.setResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           null,
                                                           resourceCreatePermissions_pre);
         fail("setting create-permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void setResourceCreatePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_invalid
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance("invalid_permission"));
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // define a valid set of create permissions
      Set<ResourceCreatePermission> resourceCreatePermissions_valid = new HashSet<>();
      resourceCreatePermissions_valid.add(createPerm_create_withGrant);

      // define a set of create permissions that includes an invalid permission reference
      Set<ResourceCreatePermission> resourceCreatePermissions_invalid = new HashSet<>();
      resourceCreatePermissions_invalid.add(createPerm_create_withGrant);
      resourceCreatePermissions_invalid.add(createPerm_invalid);

      // attempt to set create permissions with invalid references
      try {
         accessControlContext.setResourceCreatePermissions(invalidResource,
                                                           resourceClassName,
                                                           domainName,
                                                           resourceCreatePermissions_valid);
         fail("setting create-permissions with reference to non-existent accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.setResourceCreatePermissions(invalidExternalResource,
                                                           resourceClassName,
                                                           domainName,
                                                           resourceCreatePermissions_valid);
         fail("setting create-permissions with reference to non-existent external accessor resource id should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.setResourceCreatePermissions(mismatchedResource,
                                                           resourceClassName,
                                                           domainName,
                                                           resourceCreatePermissions_valid);
         fail("setting create-permissions with reference to mismatched internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
      try {
         accessControlContext.setResourceCreatePermissions(accessorResource,
                                                           "invalid_resource_class",
                                                           domainName,
                                                           resourceCreatePermissions_valid);
         fail("setting create-permissions with reference to non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.setResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           "invalid_resource_domain",
                                                           resourceCreatePermissions_valid);
         fail("setting create-permissions with reference to non-existent domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
      try {
         accessControlContext.setResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           resourceCreatePermissions_invalid);
         fail("setting create-permissions with reference to non-existent permission name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }

   @Test
   public void setResourceCreatePermissions_notAuthorized_shouldFail() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(resourcePermission_inherit_withGrant);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant);

      // set up the grantorResource
      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(createPerm_create);
      grantorPermissions.add(createPerm_inherit);

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
      grantQueryPermission(grantorResource, accessorResource);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre = new HashSet<>();
      resourceCreatePermissions_pre.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      resourceCreatePermissions_pre.add(createPerm_inherit_withGrant);

      // attempt to set create permissions
      try {
         accessControlContext.setResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           resourceCreatePermissions_pre);
         fail("setting create permissions without having rights to grant should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(grantorResource).toLowerCase()
                                                                       + " is not authorized"));
         assertThat(e.getMessage().toLowerCase(), containsString("not authorized"));
      }
   }
}
