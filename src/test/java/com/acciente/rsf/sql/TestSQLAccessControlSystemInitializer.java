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
package com.acciente.rsf.sql;

import com.acciente.rsf.AccessControlContext;
import com.acciente.rsf.DomainCreatePermission;
import com.acciente.rsf.DomainPermission;
import com.acciente.rsf.helper.Constants;
import com.acciente.rsf.helper.RSF_Domain;
import com.acciente.rsf.helper.RSF_Grant_DomCreatePerm_PostCreate_Sys;
import com.acciente.rsf.helper.RSF_Grant_DomCreatePerm_Sys;
import com.acciente.rsf.helper.RSF_Grant_DomPerm_Sys;
import com.acciente.rsf.helper.RSF_Grant_Global_ResPerm;
import com.acciente.rsf.helper.RSF_Grant_Global_ResPerm_Sys;
import com.acciente.rsf.helper.RSF_Grant_ResCreatePerm;
import com.acciente.rsf.helper.RSF_Grant_ResCreatePerm_PostCreate_Sys;
import com.acciente.rsf.helper.RSF_Grant_ResPerm;
import com.acciente.rsf.helper.RSF_Grant_ResPerm_Sys;
import com.acciente.rsf.helper.RSF_Resource;
import com.acciente.rsf.helper.RSF_ResourceClass;
import com.acciente.rsf.helper.RSF_ResourceClassPermission;
import com.acciente.rsf.helper.SQLAccessControlSystemResetUtil;
import com.acciente.rsf.helper.TestDataSourceFactory;
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
      SQLAccessControlSystemResetUtil.deleteAllRSFData(con, Constants.DB_SCHEMA);

      assertThat(RSF_Domain.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(RSF_Resource.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(RSF_ResourceClass.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(RSF_ResourceClassPermission.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));

      assertThat(RSF_Grant_DomPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(RSF_Grant_ResPerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(RSF_Grant_ResPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(RSF_Grant_Global_ResPerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(RSF_Grant_Global_ResPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));

      assertThat(RSF_Grant_DomCreatePerm_PostCreate_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(RSF_Grant_ResCreatePerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(RSF_Grant_ResCreatePerm_PostCreate_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
   }

   @Test
   public void initializeRSF() throws SQLException, InterruptedException {
      SQLAccessControlSystemInitializer.initializeRSF(con, Constants.DB_SCHEMA, Constants.RSF_ROOT_PWD);
      assertThatRSFIsInInitializedState();
   }

   @Test
   public void reInitializeRSF() throws SQLException, InterruptedException {
      SQLAccessControlSystemInitializer.initializeRSF(con, Constants.DB_SCHEMA, Constants.RSF_ROOT_PWD);
      assertThatRSFIsInInitializedState();

      SQLAccessControlSystemInitializer.initializeRSF(con, Constants.DB_SCHEMA, Constants.RSF_ROOT_PWD);
      assertThatRSFIsInInitializedState();
   }

   private void assertThatRSFIsInInitializedState() throws SQLException {
      // verify system-domain
      RSF_Domain sysDomain = new RSF_Domain.Builder(0L)
            .domainName(AccessControlContext.SYSTEM_DOMAIN)
            .build();
      assertThat(RSF_Domain.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      assertThat(RSF_Domain.Finder.findByID(con, Constants.DB_SCHEMA, 0), is(sysDomain));

      // verify system-resourceClass
      RSF_ResourceClass sysResourceClass = new RSF_ResourceClass.Builder(0L)
            .resourceClassName(AccessControlContext.SYSTEM_RESOURCE_CLASS)
            .isAuthenticatable(true)
            .isUnauthenticatedCreateAllowed(false)
            .build();
      assertThat(RSF_ResourceClass.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      assertThat(RSF_ResourceClass.Finder.findByID(con, Constants.DB_SCHEMA, 0), is(sysResourceClass));

      // verify system-resource
      RSF_Resource sysResource = new RSF_Resource.Builder(0L)
            .resourceClassID(sysResourceClass.getResourceClassID())
            .domainID(sysDomain.getDomainID())
            .password_plaintext(Constants.RSF_ROOT_PWD)
            .build();
      assertThat(RSF_Resource.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      assertThat(RSF_Resource.Finder.findByID(con, Constants.DB_SCHEMA, 0), is(sysResource));

      // verify system-resource's permissions on system-domain
      final DomainPermission sysDomainPermission_SuperUser = DomainPermission.getInstance(DomainPermission.SUPER_USER);

      RSF_Grant_DomPerm_Sys sysDomainSuperUserPermission
            = new RSF_Grant_DomPerm_Sys.Builder(sysResource.getResourceID(),
            sysDomain.getDomainID(),
            sysDomainPermission_SuperUser.getSystemPermissionId())
            .isWithGrant(true)
            .grantorResourceID(sysResource.getResourceID())
            .build();

      assertThat(RSF_Grant_DomPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      final List<RSF_Grant_DomPerm_Sys> permissions
            = RSF_Grant_DomPerm_Sys.Finder.findByAccessorIDAndAccessedID(con,
            Constants.DB_SCHEMA,
            sysResource.getResourceID(),
            sysDomain.getDomainID());
      assertThat(permissions.size(), is(1));
      assertThat(permissions, hasItems(sysDomainSuperUserPermission));

      // verify system-resource's create-permissions on system-domain
      final DomainCreatePermission sysDomainCreatePermission_Create = DomainCreatePermission.getInstance(DomainCreatePermission.CREATE);
      final DomainPermission sysDomainPermission_CreateChildDomain = DomainPermission.getInstance(DomainPermission.CREATE_CHILD_DOMAIN);

      RSF_Grant_DomCreatePerm_PostCreate_Sys createSysDomainSuperUserPermission
            = new RSF_Grant_DomCreatePerm_PostCreate_Sys.Builder(sysResource.getResourceID(),
            sysDomainPermission_SuperUser.getSystemPermissionId())
            .postCreateIsWithGrant(true)
            .isWithGrant(true)
            .grantorResourceID(sysResource.getResourceID())
            .build();

      RSF_Grant_DomCreatePerm_Sys createSysDomainCreatePermission
            = new RSF_Grant_DomCreatePerm_Sys.Builder(sysResource.getResourceID(),
            sysDomainCreatePermission_Create.getSystemPermissionId())
            .isWithGrant(true)
            .grantorResourceID(sysResource.getResourceID())
            .build();

      RSF_Grant_DomCreatePerm_PostCreate_Sys createSysDomainCreateChildPermission
            = new RSF_Grant_DomCreatePerm_PostCreate_Sys.Builder(sysResource.getResourceID(),
            sysDomainPermission_CreateChildDomain.getSystemPermissionId())
            .postCreateIsWithGrant(true)
            .isWithGrant(true)
            .grantorResourceID(sysResource.getResourceID())
            .build();

      assertThat(RSF_Grant_DomCreatePerm_PostCreate_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(2));
      final List<RSF_Grant_DomCreatePerm_PostCreate_Sys> createPostCreatePermissions
            = RSF_Grant_DomCreatePerm_PostCreate_Sys.Finder.findByAccessorID(con, Constants.DB_SCHEMA, sysResource.getResourceID());
      assertThat(createPostCreatePermissions.size(), is(2));
      assertThat(createPostCreatePermissions, hasItems(createSysDomainSuperUserPermission, createSysDomainCreateChildPermission));

      assertThat(RSF_Grant_DomCreatePerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(1));
      final List<RSF_Grant_DomCreatePerm_Sys> createSysPermissions
            = RSF_Grant_DomCreatePerm_Sys.Finder.findByAccessorID(con, Constants.DB_SCHEMA, sysResource.getResourceID());
      assertThat(createSysPermissions.size(), is(1));
      assertThat(createSysPermissions, hasItems(createSysDomainCreatePermission));

      // verify all other tables are empty
      assertThat(RSF_ResourceClassPermission.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));

      assertThat(RSF_Grant_ResPerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(RSF_Grant_ResPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(RSF_Grant_Global_ResPerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(RSF_Grant_Global_ResPerm_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));

      assertThat(RSF_Grant_ResCreatePerm.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
      assertThat(RSF_Grant_ResCreatePerm_PostCreate_Sys.Finder.getNumberOfRows(con, Constants.DB_SCHEMA), is(0));
   }


}
