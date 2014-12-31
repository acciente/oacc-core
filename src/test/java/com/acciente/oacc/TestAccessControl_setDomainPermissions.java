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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_setDomainPermissions extends TestAccessControlBase {
   @Test
   public void setDomainPermissions_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();
      final DomainPermission domainPermission_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domainPermission_child_withGrant = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                              true);

      final String domainName = generateDomain();
      final Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName).isEmpty(), is(true));

      Set<DomainPermission> domainPermissions_pre = new HashSet<>();
      domainPermissions_pre.add(domainPermission_superUser);
      domainPermissions_pre.add(domainPermission_child_withGrant);

      // set domain permissions and verify
      accessControlContext.setDomainPermissions(accessorResource, domainName, domainPermissions_pre);

      final Set<DomainPermission> domainPermissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_pre));
   }

   @Test
   public void setDomainPermissions_validAsAuthorized() throws AccessControlException {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName = generateDomain();

      // set up an authenticatable resource
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      final Set<DomainPermission> domainPermissions_granter = new HashSet<>();
      domainPermissions_granter.add(domPerm_superuser_withGrant);
      domainPermissions_granter.add(domPerm_child_withGrant);

      // set domain permissions and verify
      accessControlContext.setDomainPermissions(authenticatableResource, domainName, domainPermissions_granter);

      Set<DomainPermission> domainPermissions_post;
      domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(authenticatableResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_granter));

      // now create a new resource and try to grant domainPermissions as the authenticatable resource
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissionsMap(accessorResource).isEmpty(), is(true));

      Set<DomainPermission> domainPermissions_pre = new HashSet<>();
      domainPermissions_pre.add(domPerm_superuser);
      domainPermissions_pre.add(domPerm_child_withGrant);
      assertThat(domainPermissions_pre, is(not(domainPermissions_granter)));

      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      accessControlContext.setDomainPermissions(accessorResource, domainName, domainPermissions_pre);

      domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_pre));
   }

   @Test
   public void setDomainPermissions_authorizedAsSuperUserWithoutGrant() throws AccessControlException {
      // Note: SuperUser privilege is enough to grant permissions on a domain, i.e. the 'with grant' option is meaningless for super users

      authenticateSystemResource();
      final DomainPermission domCreatePerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domCreatePerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      final Set<DomainPermission> domainPermissions_granter = new HashSet<>();
      domainPermissions_granter.add(domCreatePerm_superuser);

      final String domainName = generateDomain();

      // set domain permissions without granting rights and verify
      accessControlContext.setDomainPermissions(authenticatableResource, domainName, domainPermissions_granter);

      Set<DomainPermission> domainPermissions_post;
      domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(authenticatableResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_granter));

      // now create a new resource and try to grant domainPermissions as the authenticatable resource
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissionsMap(accessorResource).isEmpty(), is(true));

      Set<DomainPermission> domainPermissions_pre = new HashSet<>();
      domainPermissions_pre.add(domCreatePerm_superuser_withGrant);
      domainPermissions_pre.add(domCreatePerm_child);
      assertThat(domainPermissions_pre, is(not(domainPermissions_granter)));

      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      accessControlContext.setDomainPermissions(accessorResource, domainName, domainPermissions_pre);
      domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_pre));
   }

   @Test
   public void setDomainPermissions_resetPermissions() throws AccessControlException {
      authenticateSystemResource();
      final DomainPermission domainPermission_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domainPermission_child = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domainPermission_child_withGrant = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                              true);

      final String domainName = generateDomain();
      final Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName).isEmpty(), is(true));

      Set<DomainPermission> domainPermissions_pre = new HashSet<>();
      domainPermissions_pre.add(domainPermission_superUser);
      domainPermissions_pre.add(domainPermission_child_withGrant);

      // initialize domain permissions and verify
      accessControlContext.setDomainPermissions(accessorResource, domainName, domainPermissions_pre);

      final Set<DomainPermission> domainPermissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_pre));

      // reset domain permissions and verify that only the latest set of permissions applies
      Set<DomainPermission> domainPermissions_pre2 = new HashSet<>();
      domainPermissions_pre2.add(domainPermission_child);

      accessControlContext.setDomainPermissions(accessorResource, domainName, domainPermissions_pre2);

      final Set<DomainPermission> domainPermissions_post2
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post2, is(domainPermissions_pre2));

      // reset domain permissions to empty set (i.e. remove all) and verify
      accessControlContext.setDomainPermissions(accessorResource, domainName, Collections.EMPTY_SET);

      final Set<DomainPermission> domainPermissions_post3
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post3.isEmpty(), is(true));
   }

   @Test
   public void setDomainPermission_addPermission_withUnauthorizedPermissionsGrantedElsewhere_shouldSucceedAsAuthorized() throws AccessControlException {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainPermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(DomainPermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setDomainPermissions(accessorResource, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainPermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(grantorResource, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainPermissions(grantorResource, domainName), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<DomainPermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(DomainPermissions.getInstance(grantedPermissionName));
      requestedPermissions.add(DomainPermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setDomainPermissions(accessorResource, domainName, requestedPermissions);

      Set<DomainPermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainPermissions.getInstance(grantedPermissionName, false));
      permissions_expected.add(DomainPermissions.getInstance(ungrantedPermissionName, false));

      final Set<DomainPermission> permissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setDomainPermission_removePermission_withUnauthorizedPermissionsGrantedElsewhere_shouldSucceedAsAuthorized() throws AccessControlException {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainPermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(DomainPermissions.getInstance(grantedPermissionName));
      accessorPermissions_pre.add(DomainPermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setDomainPermissions(accessorResource, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainPermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(grantorResource, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainPermissions(grantorResource, domainName), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<DomainPermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(DomainPermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setDomainPermissions(accessorResource, domainName, requestedPermissions);

      Set<DomainPermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainPermissions.getInstance(ungrantedPermissionName, false));

      final Set<DomainPermission> permissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setDomainPermission_downgradeGrantingRights_shouldSucceedAsAuthorized() throws AccessControlException {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainPermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(accessorResource, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainPermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(grantorResource, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainPermissions(grantorResource, domainName), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<DomainPermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(DomainPermissions.getInstance(grantedPermissionName));

      accessControlContext.setDomainPermissions(accessorResource, domainName, requestedPermissions);

      Set<DomainPermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainPermissions.getInstance(grantedPermissionName, false));

      final Set<DomainPermission> permissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setDomainPermission_downgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainPermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(DomainPermissions.getInstance(ungrantedPermissionName, true));

      accessControlContext.setDomainPermissions(accessorResource, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainPermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(grantorResource, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainPermissions(grantorResource, domainName), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<DomainPermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(DomainPermissions.getInstance(ungrantedPermissionName));

      try {
         accessControlContext.setDomainPermissions(accessorResource, domainName, requestedPermissions);
         fail("Downgrading (=removal of granting rights) of domain permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authorized"));
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void setDomainPermission_upgradeGrantingRights_shouldSucceedAsAuthorized() throws AccessControlException {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainPermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(DomainPermissions.getInstance(grantedPermissionName));

      accessControlContext.setDomainPermissions(accessorResource, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainPermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(grantorResource, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainPermissions(grantorResource, domainName), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<DomainPermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(accessorResource, domainName, requestedPermissions);

      Set<DomainPermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainPermissions.getInstance(grantedPermissionName, true));

      final Set<DomainPermission> permissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setDomainPermission_upgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainPermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(DomainPermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setDomainPermissions(accessorResource, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainPermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(grantorResource, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainPermissions(grantorResource, domainName), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<DomainPermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(DomainPermissions.getInstance(ungrantedPermissionName, true));

      try {
         accessControlContext.setDomainPermissions(accessorResource, domainName, requestedPermissions);
         fail("Upgrading (=addition of granting rights) of domain permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authorized"));
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void setDomainPermissions_whitespaceConsistent() throws AccessControlException {
      authenticateSystemResource();

      final DomainPermission domCreatePerm_superuser_trailingspaces
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER + " \t");
      final DomainPermission domCreatePerm_child_withGrant
            = DomainPermissions.getInstance(" \t" + DomainPermissions.CREATE_CHILD_DOMAIN, true);

      // todo: arguably, system permissions should match in name exactly, but the API uses Strings, not Enums, and is otherwise whitespace-consistent
      //       this could pose some complications depending on if the system permission name is persisted from the passed string or derived from an authoritative source
      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissionsMap(accessorResource).isEmpty(), is(true));

      Set<DomainPermission> domainPermissions_pre = new HashSet<>();
      domainPermissions_pre.add(domCreatePerm_superuser_trailingspaces);
      domainPermissions_pre.add(domCreatePerm_child_withGrant);

      // set domain permissions and verify
      accessControlContext.setDomainPermissions(accessorResource, domainName_whitespaced, domainPermissions_pre);

      final Set<DomainPermission> domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post.size(), is(2));
      assertThat(domainPermissions_post, hasItem(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));
      assertThat(domainPermissions_post, hasItem(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                               true)));
   }

   // the DomainPermission object prevents creation with invalid system permission names, hence we don't test
   // for case-sensitivity consistency of the setDomainPermission() method here;
   // similarly, we currently can't set duplicate permissions because the API only allows sets of unique domain permissions,
   // hence we don't test for duplicate permissions (until the api changes, e.g. with variable argument lists instead of sets)

   @Test
   public void setDomainPermissions_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      Set<DomainPermission> domainPermissions = new HashSet<>();
      domainPermissions.add(domCreatePerm_child_withGrant);

      Set<DomainPermission> domainPermission_nullElement = new HashSet<>();
      domainPermission_nullElement.add(null);

      final String domainName = generateDomain();
      Resource accessorResource = generateUnauthenticatableResource();

      // attempt to set domain permissions with nulls
      try {
         accessControlContext.setDomainPermissions(null, domainName, domainPermissions);
         fail("setting domain create permissions with null accessor resource should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.setDomainPermissions(accessorResource, null, domainPermissions);
         fail("setting domain create permissions with null domain name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.setDomainPermissions(accessorResource, domainName, null);
         fail("setting domain create permissions with null domain permission set should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.setDomainPermissions(accessorResource, domainName, domainPermission_nullElement);
         fail("setting domain create permissions with null element in domain permission set should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
   }

   @Test
   public void setDomainPermissions_notAuthorized_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      final Set<DomainPermission> domainPermissions_granter = new HashSet<>();
      domainPermissions_granter.add(domCreatePerm_child);

      final String dmainName = generateDomain();

      // set domain permissions without granting rights and verify
      accessControlContext.setDomainPermissions(authenticatableResource, dmainName, domainPermissions_granter);

      Set<DomainPermission> domainPermissions_post;
      domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(authenticatableResource, dmainName);
      assertThat(domainPermissions_post, is(domainPermissions_granter));

      // now create a new resource and try to grant domainPermissions as the authenticatable resource
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissionsMap(accessorResource).isEmpty(), is(true));

      Set<DomainPermission> domainPermissions_pre = new HashSet<>();
      domainPermissions_pre.add(domCreatePerm_child);
      domainPermissions_pre.add(domCreatePerm_superuser);
      assertThat(domainPermissions_pre, is(not(domainPermissions_granter)));

      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.setDomainPermissions(accessorResource, dmainName, domainPermissions_pre);
         fail("setting domain create permissions without having rights to grant should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authorized"));
      }

      // attempt again, but for permission that we neither have with nor without granting rights
      domainPermissions_pre.clear();
      domainPermissions_pre.add(domCreatePerm_superuser);
      assertThat(domainPermissions_pre, is(not(domainPermissions_granter)));

      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.setDomainPermissions(accessorResource, dmainName, domainPermissions_pre);
         fail("setting domain create permissions without having rights to grant should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authorized"));
      }
   }
}
