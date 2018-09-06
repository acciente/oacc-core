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
import java.util.Map;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_grantGlobalResourcePermissions extends TestAccessControlBase {
   @Test
   public void grantGlobalResourcePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // create dummy domain and class - to check if there were any side-effects later on
      generateDomain();
      generateResourceClass(true, false);

      // grant permissions and verify
      final String permissionName = generateResourceClassPermission(authenticatableResourceClassName);
      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(permissionName));

      accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                          authenticatableResourceClassName,
                                                          domainName,
                                                          ResourcePermissions
                                                                .getInstance(ResourcePermissions.IMPERSONATE),
                                                          ResourcePermissions
                                                                .getInstance(permissionName));

      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName, domainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      // verify no other global permissions were set (i.e. no side-effects)
      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(domainName).size(), is(1));
      assertThat(permissions_post_all.get(domainName).get(authenticatableResourceClassName), is(permissions_pre));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveDomainPermissionsMap(accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, SYS_RESOURCE).isEmpty(), is(true));

      // test set-based version
      final Resource accessorResource2 = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource2).isEmpty(), is(true));

      accessControlContext.grantGlobalResourcePermissions(accessorResource2,
                                                          authenticatableResourceClassName,
                                                          domainName,
                                                          setOf(ResourcePermissions
                                                                      .getInstance(ResourcePermissions.IMPERSONATE),
                                                                ResourcePermissions
                                                                      .getInstance(permissionName)));

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2,
                                                                            authenticatableResourceClassName,
                                                                            domainName),
                 is(permissions_pre));
   }

   @Test
   public void grantGlobalResourcePermissions_withExtId() {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final String externalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // create dummy domain and class - to check if there were any side-effects later on
      generateDomain();
      generateResourceClass(true, false);

      // grant permissions and verify
      final String permissionName = generateResourceClassPermission(authenticatableResourceClassName);
      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(permissionName));

      accessControlContext.grantGlobalResourcePermissions(Resources.getInstance(externalId),
                                                          authenticatableResourceClassName,
                                                          domainName,
                                                          ResourcePermissions
                                                                .getInstance(ResourcePermissions.IMPERSONATE),
                                                          ResourcePermissions
                                                                .getInstance(permissionName));

      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName, domainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      // test set-based version
      final String externalId2 = generateUniqueExternalId();
      final Resource accessorResource2 = generateUnauthenticatableResourceWithExtId(externalId2);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource2).isEmpty(), is(true));

      accessControlContext.grantGlobalResourcePermissions(Resources.getInstance(externalId2),
                                                          authenticatableResourceClassName,
                                                          domainName,
                                                          setOf(ResourcePermissions
                                                                      .getInstance(ResourcePermissions.IMPERSONATE),
                                                                ResourcePermissions
                                                                      .getInstance(permissionName)));

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2,
                                                                            authenticatableResourceClassName,
                                                                            domainName),
                 is(permissions_pre));
   }

   @Test
   public void grantGlobalResourcePermissions_samePermissionNameAsOtherResourceClass_shouldSucceed() {
      authenticateSystemResource();

      // generate permissions with same name for two separate resource classes
      final String resourceClassName = generateResourceClass(false, false);
      final String otherResourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateUniquePermissionName();
      // note the order we create permissions in; prevent RDBMS silently picking first permission by name when there are multiple
      final String[] orderedResourceClassNames = {otherResourceClassName, resourceClassName};
      for (String rcName: orderedResourceClassNames) {
         accessControlContext.createResourcePermission(rcName, customPermissionName);
      }

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // grant permissions and verify
      Set<ResourcePermission> permissions_pre = setOf(ResourcePermissions.getInstance(customPermissionName));

      accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          ResourcePermissions
                                                                .getInstance(customPermissionName));

      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveDomainPermissionsMap(accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, SYS_RESOURCE).isEmpty(), is(true));

      // test set-based version
      final Resource accessorResource2 = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource2).isEmpty(), is(true));

      accessControlContext.grantGlobalResourcePermissions(accessorResource2,
                                                          resourceClassName,
                                                          domainName,
                                                          setOf(ResourcePermissions
                                                                      .getInstance(customPermissionName)));

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2,
                                                                            resourceClassName,
                                                                            domainName),
                 is(permissions_pre));
   }

   @Test
   public void grantGlobalResourcePermissions_inheritSystemPermission_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to grant *INHERIT system permission
      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT));
         fail("granting *INHERIT system permission as a global permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid in this context"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(ResourcePermissions
                                                                         .getInstance(ResourcePermissions.INHERIT)));
         fail("granting *INHERIT system permission as a global permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid in this context"));
      }
   }

   @Test
   public void grantGlobalResourcePermissions_resetCredentialsPermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to grant *RESET_CREDENTIALS system permission
      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourcePermissions
                                                                   .getInstance(ResourcePermissions.RESET_CREDENTIALS));
         fail("granting *RESET_CREDENTIALS system permission globally to an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(ResourcePermissions
                                                                         .getInstance(ResourcePermissions.RESET_CREDENTIALS)));
         fail("granting *RESET_CREDENTIALS system permission globally to an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void grantGlobalResourcePermissions_impersonatePermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to grant *IMPERSONATE system permission
      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourcePermissions
                                                                   .getInstance(ResourcePermissions.IMPERSONATE));
         fail("granting *IMPERSONATE system permission globally to an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(ResourcePermissions
                                                                         .getInstance(ResourcePermissions.IMPERSONATE)));
         fail("granting *IMPERSONATE system permission globally to an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void grantGlobalResourcePermissions_validAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.IMPERSONATE));
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(customPermissionName));

      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(customPermissionName));

      // setup grantor permissions
      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant global permissions as grantor and verify
      accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          ResourcePermissions
                                                                .getInstance(ResourcePermissions.IMPERSONATE),
                                                          ResourcePermissions.getInstance(customPermissionName));

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_pre));

      // test set-based version
      final Resource accessorResource2 = generateUnauthenticatableResource();
      grantQueryPermission(grantorResource, accessorResource2);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource2).isEmpty(), is(true));

      accessControlContext.grantGlobalResourcePermissions(accessorResource2,
                                                          resourceClassName,
                                                          domainName,
                                                          setOf(ResourcePermissions
                                                                      .getInstance(ResourcePermissions.IMPERSONATE),
                                                                ResourcePermissions.getInstance(customPermissionName)));

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName),
                 is(permissions_pre));
   }

   @Test
   public void grantGlobalResourcePermissions_regrantPermissions() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      final String permissionName = generateResourceClassPermission(resourceClassName);
      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(permissionName));

      // grant permissions and verify
      accessControlContext.grantGlobalResourcePermissions(accessorResource, resourceClassName,
                                                          domainName,
                                                          ResourcePermissions
                                                                .getInstanceWithGrantOption(ResourcePermissions.IMPERSONATE),
                                                          ResourcePermissions
                                                                .getInstance(permissionName));

      final Set<ResourcePermission> permissions_post1 = accessControlContext.getEffectiveGlobalResourcePermissions(
            accessorResource,
            resourceClassName,
            domainName);
      assertThat(permissions_post1, is(permissions_pre));

      // regrant permission and verify nothing changed
      accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          ResourcePermissions
                                                                .getInstance(permissionName));

      final Set<ResourcePermission> permissions_post2 = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post2, is(permissions_pre));

      // regrant via set-based method
      accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          setOf(ResourcePermissions
                                                                      .getInstance(permissionName)));

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName),
                 is(permissions_pre));
   }

   @Test
   public void grantGlobalResourcePermissions_addPermission_withUnauthorizedPermissionsGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String grantablePermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantablePermissionName = ResourcePermissions.IMPERSONATE;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(ungrantablePermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantablePermissionName));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourcePermissions.getInstance(grantablePermissionName),
                                                             ResourcePermissions.getInstance(ungrantablePermissionName));
         fail("granting existing global permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(ResourcePermissions.getInstance(
                                                                   grantablePermissionName),
                                                                   ResourcePermissions.getInstance(
                                                                         ungrantablePermissionName)));
         fail("granting existing global permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
   }

   @Test
   public void grantGlobalResourcePermissions_downgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          ResourcePermissions.getInstance(grantedPermissionName));

      final Set<ResourcePermission> permissions_post
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(accessorPermissions_pre));

      // test set-based version
      final Resource accessorResource2 = generateUnauthenticatableResource();
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.setGlobalResourcePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      accessControlContext.grantGlobalResourcePermissions(accessorResource2,
                                                          resourceClassName,
                                                          domainName,
                                                          setOf(ResourcePermissions.getInstance(grantedPermissionName)));

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName),
                 is(accessorPermissions_pre));
   }

   @Test
   public void grantGlobalResourcePermissions_downgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantedPermissionName = ResourcePermissions.IMPERSONATE;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstanceWithGrantOption(ungrantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourcePermissions.getInstance(grantedPermissionName),
                                                             ResourcePermissions.getInstance(ungrantedPermissionName));
         fail("Downgrading (=removal of granting rights) of global permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(ResourcePermissions
                                                                         .getInstance(grantedPermissionName),
                                                                   ResourcePermissions.getInstance(
                                                                         ungrantedPermissionName)));
         fail("Downgrading (=removal of granting rights) of global permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void grantGlobalResourcePermissions_upgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      final Set<ResourcePermission> permissions_post
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));

      // test set-based version
      final Resource accessorResource2 = generateUnauthenticatableResource();
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.setGlobalResourcePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      accessControlContext.grantGlobalResourcePermissions(accessorResource2,
                                                          resourceClassName,
                                                          domainName,
                                                          setOf(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName)));

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName),
                 is(permissions_expected));
   }

   @Test
   public void grantGlobalResourcePermissions_upgradeGrantingRights_samePermissionNameAsOtherResourceClass_shouldSucceed() {
      authenticateSystemResource();

      // generate permissions with same name for two separate resource classes
      final String resourceClassName = generateResourceClass(false, false);
      final String otherResourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateUniquePermissionName();
      // note the order we create permissions in; prevent RDBMS silently picking first permission by name when there are multiple
      final String[] orderedResourceClassNames = {otherResourceClassName, resourceClassName};
      for (String rcName: orderedResourceClassNames) {
         accessControlContext.createResourcePermission(rcName, customPermissionName);
      }

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(customPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // grant upgraded permissions and verify
      accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          ResourcePermissions.getInstanceWithGrantOption(customPermissionName));

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstanceWithGrantOption(customPermissionName));

      final Set<ResourcePermission> permissions_post
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));

      // test set-based version
      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      accessControlContext.grantGlobalResourcePermissions(accessorResource2,
                                                          resourceClassName,
                                                          domainName,
                                                          setOf(ResourcePermissions.getInstanceWithGrantOption(customPermissionName)));

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName),
                 is(permissions_expected));
   }

   @Test
   public void grantGlobalResourcePermissions_upgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantedPermissionName = ResourcePermissions.IMPERSONATE;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourcePermissions.getInstance(grantedPermissionName),
                                                             ResourcePermissions.getInstanceWithGrantOption(ungrantedPermissionName));
         fail("Upgrading (=addition of granting rights) of global permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(ResourcePermissions
                                                                         .getInstance(grantedPermissionName),
                                                                   ResourcePermissions.getInstanceWithGrantOption(
                                                                         ungrantedPermissionName)));
         fail("Upgrading (=addition of granting rights) of global permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void grantGlobalResourcePermissions_duplicatePermissionNames_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      final String permissionName = generateResourceClassPermission(resourceClassName);

      // attempt to grant permissions with duplicate permission names
      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourcePermissions
                                                                   .getInstance(ResourcePermissions.IMPERSONATE),
                                                             ResourcePermissions.getInstanceWithGrantOption(permissionName),
                                                             ResourcePermissions.getInstance(permissionName));
         fail("granting global permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(ResourcePermissions
                                                                         .getInstance(ResourcePermissions.IMPERSONATE),
                                                                   ResourcePermissions
                                                                         .getInstanceWithGrantOption(permissionName),
                                                                   ResourcePermissions
                                                                         .getInstance(permissionName)));
         fail("granting global permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void grantGlobalResourcePermissions_duplicateIdenticalPermissions_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      final String permissionName = generateResourceClassPermission(resourceClassName);

      // attempt to grant permissions with duplicate permission names
      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourcePermissions.getInstance(permissionName),
                                                             ResourcePermissions.getInstance(permissionName));
         fail("granting global resource permissions with duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void grantGlobalResourcePermissions_whitespaceConsistent() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String domainName_whitespaced = " " + domainName + "\t";
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // grant permissions and verify
      final String permissionName1 = generateResourceClassPermission(resourceClassName);
      Set<ResourcePermission> permissions1
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(permissionName1));

      accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                          resourceClassName_whitespaced,
                                                          domainName_whitespaced,
                                                          ResourcePermissions
                                                                .getInstance(ResourcePermissions.IMPERSONATE),
                                                          ResourcePermissions.getInstance(permissionName1));

      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post_specific, is(permissions1));

      // test set-based version
      final Resource accessorResource2 = generateUnauthenticatableResource();

      accessControlContext.grantGlobalResourcePermissions(accessorResource2,
                                                          resourceClassName_whitespaced,
                                                          domainName_whitespaced,
                                                          setOf(ResourcePermissions
                                                                      .getInstance(ResourcePermissions.IMPERSONATE),
                                                                ResourcePermissions.getInstance(permissionName1)));

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName),
                 is(permissions1));
   }

   @Test
   public void grantGlobalResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      final ResourcePermission permission_valid = ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE);

      // attempt to grant global permissions with null references
      try {
         accessControlContext.grantGlobalResourcePermissions(null, resourceClassName, domainName, permission_valid);
         fail("granting permissions for null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.grantGlobalResourcePermissions(Resources.getInstance(null), resourceClassName, domainName, permission_valid);
         fail("granting permissions for null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource, null, domainName, permission_valid);
         fail("granting permissions for null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             (ResourcePermission) null);
         fail("granting permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             permission_valid,
                                                             null);
         fail("granting permissions with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             (String) null,
                                                             permission_valid);
         fail("granting permissions with null domain should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(null, resourceClassName, domainName, setOf(permission_valid));
         fail("granting permissions for null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.grantGlobalResourcePermissions(Resources.getInstance(null), resourceClassName, domainName, setOf(permission_valid));
         fail("granting permissions for null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource, null, domainName, setOf(permission_valid));
         fail("granting permissions for null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             (Set<ResourcePermission>) null);
         fail("granting permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(permission_valid, null));
         fail("granting permissions with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("null element"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             (String) null,
                                                             setOf(permission_valid));
         fail("granting permissions with null domain should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void grantGlobalResourcePermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to grant global permissions with null references
      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             Collections.<ResourcePermission>emptySet());
         fail("granting permissions with null permission set should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void grantGlobalResourcePermissions_mismatchedResourceClassAndPermission_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName1 = generateResourceClass(true, false);
      final String resourceClassName2 = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      final String permissionName1 = generateResourceClassPermission(resourceClassName1);

      // attempt to grant global permissions for mismatched resource class and permission
      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName2,
                                                             domainName,
                                                             ResourcePermissions.getInstance(permissionName1));
         fail("granting global permissions with mismatched resource class and permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName2,
                                                             domainName,
                                                             setOf(ResourcePermissions.getInstance(permissionName1)));
         fail("granting global permissions with mismatched resource class and permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }

   @Test
   public void grantGlobalResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      final ResourcePermission invalid_permission = ResourcePermissions.getInstance("invalid_permission");
      final ResourcePermission permission_valid
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName));

      // attempt to grant permissions with non-existent references
      try {
         accessControlContext.grantGlobalResourcePermissions(invalidResource,
                                                             resourceClassName,
                                                             domainName,
                                                             permission_valid);
         fail("granting permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantGlobalResourcePermissions(invalidExternalResource,
                                                             resourceClassName,
                                                             domainName,
                                                             permission_valid);
         fail("granting permissions with non-existent external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantGlobalResourcePermissions(mismatchedResource,
                                                             resourceClassName,
                                                             domainName,
                                                             permission_valid);
         fail("granting permissions with mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             "invalid_resourceClass",
                                                             domainName,
                                                             permission_valid);
         fail("granting permissions with non-existent resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             "invalid_domain",
                                                             permission_valid);
         fail("granting permissions with non-existent domain should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             invalid_permission);
         fail("granting permissions with non-existent permission name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(invalidResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(permission_valid));
         fail("granting permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantGlobalResourcePermissions(invalidExternalResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(permission_valid));
         fail("granting permissions with non-existent external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantGlobalResourcePermissions(mismatchedResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(permission_valid));
         fail("granting permissions with mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             "invalid_resourceClass",
                                                             domainName,
                                                             setOf(permission_valid));
         fail("granting permissions with non-existent resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             "invalid_domain",
                                                             setOf(permission_valid));
         fail("granting permissions with non-existent domain should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }

      try {
         accessControlContext.grantGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(invalid_permission));
         fail("granting permissions with non-existent permission name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }
}
