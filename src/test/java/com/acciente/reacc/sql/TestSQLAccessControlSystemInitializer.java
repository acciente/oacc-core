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
package com.acciente.reacc.sql;

import com.acciente.reacc.AccessControlContext;
import com.acciente.reacc.DomainCreatePermission;
import com.acciente.reacc.DomainPermission;
import com.acciente.reacc.helper.Constants;
import com.acciente.reacc.helper.REACC_Domain;
import com.acciente.reacc.helper.REACC_Grant_DomCreatePerm_PostCreate_Sys;
import com.acciente.reacc.helper.REACC_Grant_DomCreatePerm_Sys;
import com.acciente.reacc.helper.REACC_Grant_DomPerm_Sys;
import com.acciente.reacc.helper.REACC_Grant_Global_ResPerm;
import com.acciente.reacc.helper.REACC_Grant_Global_ResPerm_Sys;
import com.acciente.reacc.helper.REACC_Grant_ResCreatePerm;
import com.acciente.reacc.helper.REACC_Grant_ResCreatePerm_PostCreate_Sys;
import com.acciente.reacc.helper.REACC_Grant_ResPerm;
import com.acciente.reacc.helper.REACC_Grant_ResPerm_Sys;
import com.acciente.reacc.helper.REACC_Resource;
import com.acciente.reacc.helper.REACC_ResourceClass;
import com.acciente.reacc.helper.REACC_ResourceClassPermission;
import com.acciente.reacc.helper.SQLAccessControlSystemResetUtil;
import com.acciente.reacc.helper.TestDataSourceFactory;
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
      SQLAccessControlSystemResetUtil.deleteAllREACCData(con, Constants.DB_SCHEMA);

      assertThat(REACC_Domain.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(REACC_Resource.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(REACC_ResourceClass.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(REACC_ResourceClassPermission.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));

      assertThat(REACC_Grant_DomPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(REACC_Grant_ResPerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(REACC_Grant_ResPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(REACC_Grant_Global_ResPerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(REACC_Grant_Global_ResPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));

      assertThat(REACC_Grant_DomCreatePerm_PostCreate_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(REACC_Grant_ResCreatePerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(REACC_Grant_ResCreatePerm_PostCreate_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
   }

   @Test
   public void initializeREACC() throws SQLException, InterruptedException {
      SQLAccessControlSystemInitializer.initializeREACC(con, Constants.DB_SCHEMA, Constants.REACC_ROOT_PWD);
      assertThatREACCIsInInitializedState();
   }

   @Test
   public void reInitializeREACC() throws SQLException, InterruptedException {
      SQLAccessControlSystemInitializer.initializeREACC(con, Constants.DB_SCHEMA, Constants.REACC_ROOT_PWD);
      assertThatREACCIsInInitializedState();

      SQLAccessControlSystemInitializer.initializeREACC(con, Constants.DB_SCHEMA, Constants.REACC_ROOT_PWD);
      assertThatREACCIsInInitializedState();
   }

   private void assertThatREACCIsInInitializedState() throws SQLException {
      // verify system-domain
      REACC_Domain sysDomain = new REACC_Domain.Builder(0L)
            .domainName(AccessControlContext.SYSTEM_DOMAIN)
            .build();
      assertThat(REACC_Domain.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      assertThat(REACC_Domain.Finder.findByID(con, Constants.DB_SCHEMA, 0), is(sysDomain));

      // verify system-resourceClass
      REACC_ResourceClass sysResourceClass = new REACC_ResourceClass.Builder(0L)
            .resourceClassName(AccessControlContext.SYSTEM_RESOURCE_CLASS)
            .isAuthenticatable(true)
            .isUnauthenticatedCreateAllowed(false)
            .build();
      assertThat(REACC_ResourceClass.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      assertThat(REACC_ResourceClass.Finder.findByID(con, Constants.DB_SCHEMA, 0), is(sysResourceClass));

      // verify system-resource
      REACC_Resource sysResource = new REACC_Resource.Builder(0L)
            .resourceClassID(sysResourceClass.getResourceClassID())
            .domainID(sysDomain.getDomainID())
            .password_plaintext(Constants.REACC_ROOT_PWD)
            .build();
      assertThat(REACC_Resource.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      assertThat(REACC_Resource.Finder.findByID(con, Constants.DB_SCHEMA, 0), is(sysResource));

      // verify system-resource's permissions on system-domain
      final DomainPermission sysDomainPermission_SuperUser = DomainPermission.getInstance(DomainPermission.SUPER_USER);

      REACC_Grant_DomPerm_Sys sysDomainSuperUserPermission
            = new REACC_Grant_DomPerm_Sys.Builder(sysResource.getResourceID(),
            sysDomain.getDomainID(),
            sysDomainPermission_SuperUser.getSystemPermissionId())
            .isWithGrant(true)
            .grantorResourceID(sysResource.getResourceID())
            .build();

      assertThat(REACC_Grant_DomPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      final List<REACC_Grant_DomPerm_Sys> permissions
            = REACC_Grant_DomPerm_Sys.Finder.findByAccessorIDAndAccessedID(con,
            Constants.DB_SCHEMA,
            sysResource.getResourceID(),
            sysDomain.getDomainID());
      assertThat(permissions.size(), is(1));
      assertThat(permissions, hasItems(sysDomainSuperUserPermission));

      // verify system-resource's create-permissions on system-domain
      final DomainCreatePermission sysDomainCreatePermission_Create = DomainCreatePermission.getInstance(DomainCreatePermission.CREATE);
      final DomainPermission sysDomainPermission_CreateChildDomain = DomainPermission.getInstance(DomainPermission.CREATE_CHILD_DOMAIN);

      REACC_Grant_DomCreatePerm_PostCreate_Sys createSysDomainSuperUserPermission
            = new REACC_Grant_DomCreatePerm_PostCreate_Sys.Builder(sysResource.getResourceID(),
            sysDomainPermission_SuperUser.getSystemPermissionId())
            .postCreateIsWithGrant(true)
            .isWithGrant(true)
            .grantorResourceID(sysResource.getResourceID())
            .build();

      REACC_Grant_DomCreatePerm_Sys createSysDomainCreatePermission
            = new REACC_Grant_DomCreatePerm_Sys.Builder(sysResource.getResourceID(),
            sysDomainCreatePermission_Create.getSystemPermissionId())
            .isWithGrant(true)
            .grantorResourceID(sysResource.getResourceID())
            .build();

      REACC_Grant_DomCreatePerm_PostCreate_Sys createSysDomainCreateChildPermission
            = new REACC_Grant_DomCreatePerm_PostCreate_Sys.Builder(sysResource.getResourceID(),
            sysDomainPermission_CreateChildDomain.getSystemPermissionId())
            .postCreateIsWithGrant(true)
            .isWithGrant(true)
            .grantorResourceID(sysResource.getResourceID())
            .build();

      assertThat(REACC_Grant_DomCreatePerm_PostCreate_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(2));
      final List<REACC_Grant_DomCreatePerm_PostCreate_Sys> createPostCreatePermissions
            = REACC_Grant_DomCreatePerm_PostCreate_Sys.Finder.findByAccessorID(con, Constants.DB_SCHEMA, sysResource.getResourceID());
      assertThat(createPostCreatePermissions.size(), is(2));
      assertThat(createPostCreatePermissions, hasItems(createSysDomainSuperUserPermission, createSysDomainCreateChildPermission));

      assertThat(REACC_Grant_DomCreatePerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      final List<REACC_Grant_DomCreatePerm_Sys> createSysPermissions
            = REACC_Grant_DomCreatePerm_Sys.Finder.findByAccessorID(con, Constants.DB_SCHEMA, sysResource.getResourceID());
      assertThat(createSysPermissions.size(), is(1));
      assertThat(createSysPermissions, hasItems(createSysDomainCreatePermission));

      // verify all other tables are empty
      assertThat(REACC_ResourceClassPermission.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));

      assertThat(REACC_Grant_ResPerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(REACC_Grant_ResPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(REACC_Grant_Global_ResPerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(REACC_Grant_Global_ResPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));

      assertThat(REACC_Grant_ResCreatePerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(REACC_Grant_ResCreatePerm_PostCreate_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
   }


}
