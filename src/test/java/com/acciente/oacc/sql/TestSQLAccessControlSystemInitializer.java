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
package com.acciente.oacc.sql;

import com.acciente.oacc.AccessControlContext;
import com.acciente.oacc.DomainCreatePermission;
import com.acciente.oacc.DomainCreatePermissions;
import com.acciente.oacc.DomainPermission;
import com.acciente.oacc.DomainPermissions;
import com.acciente.oacc.helper.Constants;
import com.acciente.oacc.helper.OACC_Domain;
import com.acciente.oacc.helper.OACC_Grant_DomCreatePerm_PostCreate_Sys;
import com.acciente.oacc.helper.OACC_Grant_DomCreatePerm_Sys;
import com.acciente.oacc.helper.OACC_Grant_Global_ResPerm;
import com.acciente.oacc.helper.OACC_Grant_Global_ResPerm_Sys;
import com.acciente.oacc.helper.OACC_Grant_ResCreatePerm;
import com.acciente.oacc.helper.OACC_Grant_ResCreatePerm_PostCreate_Sys;
import com.acciente.oacc.helper.OACC_Grant_ResPerm;
import com.acciente.oacc.helper.OACC_Grant_ResPerm_Sys;
import com.acciente.oacc.helper.OACC_Resource;
import com.acciente.oacc.helper.OACC_ResourceClassPermission;
import com.acciente.oacc.helper.OACC_Grant_DomPerm_Sys;
import com.acciente.oacc.helper.OACC_ResourceClass;
import com.acciente.oacc.helper.OACC_ResourcePassword;
import com.acciente.oacc.helper.SQLAccessControlSystemResetUtil;
import com.acciente.oacc.helper.TestDataSourceFactory;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class TestSQLAccessControlSystemInitializer {
   private static Connection con;

   static {
      try {
         con = TestDataSourceFactory.getDataSource().getConnection();
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
   }

   @AfterClass
   public static void tearDownOnce() throws Exception {
      con.close();
   }

   @Before
   public void setUp() throws Exception {
      SQLAccessControlSystemResetUtil.deleteAllOACCData(con, Constants.DB_SCHEMA);

      assertThat(OACC_Domain.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(OACC_Resource.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(OACC_ResourceClass.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(OACC_ResourceClassPermission.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));

      assertThat(OACC_Grant_DomPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(OACC_Grant_ResPerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(OACC_Grant_ResPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(OACC_Grant_Global_ResPerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(OACC_Grant_Global_ResPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));

      assertThat(OACC_Grant_DomCreatePerm_PostCreate_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(OACC_Grant_ResCreatePerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(OACC_Grant_ResCreatePerm_PostCreate_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
   }

   @Test
   public void initializeOACC() throws SQLException, InterruptedException {
      SQLAccessControlSystemInitializer.initializeOACC(con, Constants.DB_SCHEMA, Constants.OACC_ROOT_PWD);
      assertThatOACCIsInInitializedState();
   }

   @Test
   public void reInitializeOACC() throws SQLException, InterruptedException {
      SQLAccessControlSystemInitializer.initializeOACC(con, Constants.DB_SCHEMA, Constants.OACC_ROOT_PWD);
      assertThatOACCIsInInitializedState();

      SQLAccessControlSystemInitializer.initializeOACC(con, Constants.DB_SCHEMA, Constants.OACC_ROOT_PWD);
      assertThatOACCIsInInitializedState();
   }

   private void assertThatOACCIsInInitializedState() throws SQLException {
      // verify system-domain
      OACC_Domain sysDomain = new OACC_Domain.Builder(0L)
            .domainName(AccessControlContext.SYSTEM_DOMAIN)
            .build();
      assertThat(OACC_Domain.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      assertThat(OACC_Domain.Finder.findByID(con, Constants.DB_SCHEMA, 0), is(sysDomain));

      // verify system-resourceClass
      OACC_ResourceClass sysResourceClass = new OACC_ResourceClass.Builder(0L)
            .resourceClassName(AccessControlContext.SYSTEM_RESOURCE_CLASS)
            .isAuthenticatable(true)
            .isUnauthenticatedCreateAllowed(false)
            .build();
      assertThat(OACC_ResourceClass.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      assertThat(OACC_ResourceClass.Finder.findByID(con, Constants.DB_SCHEMA, 0), is(sysResourceClass));

      // verify system-resource
      OACC_Resource sysResource = new OACC_Resource.Builder(0L)
            .resourceClassID(sysResourceClass.getResourceClassID())
            .domainID(sysDomain.getDomainID())
            .build();
      assertThat(OACC_Resource.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      assertThat(OACC_Resource.Finder.findByID(con, Constants.DB_SCHEMA, 0), is(sysResource));

      // verify system-resource password
      OACC_ResourcePassword sysResourcePassword = new OACC_ResourcePassword.Builder(0L)
            .password_plaintext(Constants.OACC_ROOT_PWD)
            .build();
      assertThat(OACC_ResourcePassword.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      assertThat(OACC_ResourcePassword.Finder.findByID(con, Constants.DB_SCHEMA, 0), is(sysResourcePassword));

      // verify system-resource's permissions on system-domain
      final DomainPermission sysDomainPermission_SuperUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);

      OACC_Grant_DomPerm_Sys sysDomainSuperUserPermission
            = new OACC_Grant_DomPerm_Sys.Builder(sysResource.getResourceID(),
            sysDomain.getDomainID(),
            sysDomainPermission_SuperUser.getSystemPermissionId())
            .isWithGrant(true)
            .grantorResourceID(sysResource.getResourceID())
            .build();

      assertThat(OACC_Grant_DomPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      final List<OACC_Grant_DomPerm_Sys> permissions
            = OACC_Grant_DomPerm_Sys.Finder.findByAccessorIDAndAccessedID(con,
            Constants.DB_SCHEMA,
            sysResource.getResourceID(),
            sysDomain.getDomainID());
      assertThat(permissions.size(), is(1));
      assertThat(permissions, hasItems(sysDomainSuperUserPermission));

      // verify system-resource's create-permissions on system-domain
      final DomainCreatePermission sysDomainCreatePermission_Create = DomainCreatePermissions.getInstance(
            DomainCreatePermissions.CREATE);
      final DomainPermission sysDomainPermission_CreateChildDomain = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission sysDomainPermission_Delete = DomainPermissions.getInstance(DomainPermissions.DELETE);

      OACC_Grant_DomCreatePerm_PostCreate_Sys createSysDomainSuperUserPermission
            = new OACC_Grant_DomCreatePerm_PostCreate_Sys.Builder(sysResource.getResourceID(),
            sysDomainPermission_SuperUser.getSystemPermissionId())
            .postCreateIsWithGrant(true)
            .isWithGrant(true)
            .grantorResourceID(sysResource.getResourceID())
            .build();

      OACC_Grant_DomCreatePerm_Sys createSysDomainCreatePermission
            = new OACC_Grant_DomCreatePerm_Sys.Builder(sysResource.getResourceID(),
            sysDomainCreatePermission_Create.getSystemPermissionId())
            .isWithGrant(true)
            .grantorResourceID(sysResource.getResourceID())
            .build();

      OACC_Grant_DomCreatePerm_PostCreate_Sys createSysDomainCreateChildPermission
            = new OACC_Grant_DomCreatePerm_PostCreate_Sys.Builder(sysResource.getResourceID(),
            sysDomainPermission_CreateChildDomain.getSystemPermissionId())
            .postCreateIsWithGrant(true)
            .isWithGrant(true)
            .grantorResourceID(sysResource.getResourceID())
            .build();

      OACC_Grant_DomCreatePerm_PostCreate_Sys createSysDomainDeletePermission
            = new OACC_Grant_DomCreatePerm_PostCreate_Sys.Builder(sysResource.getResourceID(),
            sysDomainPermission_Delete.getSystemPermissionId())
            .postCreateIsWithGrant(true)
            .isWithGrant(true)
            .grantorResourceID(sysResource.getResourceID())
            .build();

      assertThat(OACC_Grant_DomCreatePerm_PostCreate_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(3));
      final List<OACC_Grant_DomCreatePerm_PostCreate_Sys> createPostCreatePermissions
            = OACC_Grant_DomCreatePerm_PostCreate_Sys.Finder.findByAccessorID(con, Constants.DB_SCHEMA, sysResource.getResourceID());
      assertThat(createPostCreatePermissions.size(), is(3));
      assertThat(createPostCreatePermissions, hasItems(createSysDomainSuperUserPermission, createSysDomainCreateChildPermission, createSysDomainDeletePermission));

      assertThat(OACC_Grant_DomCreatePerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      final List<OACC_Grant_DomCreatePerm_Sys> createSysPermissions
            = OACC_Grant_DomCreatePerm_Sys.Finder.findByAccessorID(con, Constants.DB_SCHEMA, sysResource.getResourceID());
      assertThat(createSysPermissions.size(), is(1));
      assertThat(createSysPermissions, hasItems(createSysDomainCreatePermission));

      // verify all other tables are empty
      assertThat(OACC_ResourceClassPermission.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));

      assertThat(OACC_Grant_ResPerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(OACC_Grant_ResPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(OACC_Grant_Global_ResPerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(OACC_Grant_Global_ResPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));

      assertThat(OACC_Grant_ResCreatePerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(OACC_Grant_ResCreatePerm_PostCreate_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
   }


}
