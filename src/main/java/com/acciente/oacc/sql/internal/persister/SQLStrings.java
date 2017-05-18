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
package com.acciente.oacc.sql.internal.persister;

import com.acciente.oacc.ResourcePermission;
import com.acciente.oacc.ResourcePermissions;
import com.acciente.oacc.sql.SQLDialect;
import com.acciente.oacc.sql.SQLProfile;

import java.io.Serializable;

public class SQLStrings implements Serializable {
   private static final long serialVersionUID = 1L;

   // SQL string constants

   // ResourceClass - common
   public final String SQL_findInResourceClass_ResourceClassID_BY_ResourceClassName;
   public final String SQL_findInResourceClass_ResourceClassID_ResourceClassName_IsAuthenticatable_IsUnauthenticatedCreateAllowed_BY_ResourceClassName;
   public final String SQL_findInResourceClass_ResourceClassID_ResourceClassName_IsAuthenticatable_IsUnauthenticatedCreateAllowed_BY_ResourceID;
   public final String SQL_findInResourceClass_ResourceClassName_BY_ALL;
   public final String SQL_createInResourceClass_WITH_ResourceClassName_IsAuthenticatable_IsUnauthenticatedCreateAllowed;

   // ResourceClassPermission - common
   public final String SQL_findInResourceClassPermission_PermissionID_BY_ResourceClassID_PermissionName;
   public final String SQL_findInResourceClassPermission_PermissionName_BY_ResourceClassName;
   public final String SQL_createInResourceClassPermission_WITH_ResourceClassID_PermissionName;

   // Domain - common
   public final String SQL_findInDomain_DomainID_BY_ResourceDomainName;
   public final String SQL_findInDomain_ResourceDomainName_BY_ResourceID;
   public final String SQL_createInDomain_WITH_ResourceDomainName;
   public final String SQL_createInDomain_WITH_ResourceDomainName_ParentDomainID;
   public final String SQL_removeInDomain_BY_DomainID;
   // Domain - recursive
   public final String SQL_findInDomain_DescendantResourceDomainName_BY_ResourceDomainName;
   public final String SQL_findInDomain_DescendantResourceDomainID_BY_DomainID_ORDERBY_DomainLevel;
   public final String SQL_removeInDomain_withDescendants_BY_DomainID;
   // Domain - non-recursive
   public final String SQL_findInDomain_DirectDescendantResourceDomainName_BY_ResourceDomainName;
   public final String SQL_findInDomain_DirectDescendantResourceDomainName_BY_DomainID;
   public final String SQL_findInDomain_ParentResourceDomainName_BY_DomainID;

   // GrantDomainCreatePermissionSys - common
   public final String SQL_findInGrantDomainCreatePermissionSys_withoutInheritance_SysPermissionID_BY_AccessorID;
   public final String SQL_createInGrantDomainCreatePermissionSys_WITH_AccessorID_GrantorID_IsWithGrant_SysPermissionID;
   public final String SQL_updateInGrantDomainCreatePermissionSys_SET_GrantorID_IsWithGrant_BY_AccessorID_SysPermissionID;
   public final String SQL_removeInGrantDomainCreatePermissionSys_BY_AccessorID;
   public final String SQL_removeInGrantDomainCreatePermissionSys_BY_AccessorID_SysPermissionID;
   // GrantDomainCreatePermissionSys - recursive
   public final String SQL_findInGrantDomainCreatePermissionSys_SysPermissionID_IsWithGrant_BY_AccessorID;

   // GrantDomainCreatePermissionPostCreateSys - common
   public final String SQL_findInGrantDomainCreatePermissionPostCreateSys_withoutInheritance_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID;
   public final String SQL_removeInGrantDomainCreatePermissionPostCreateSys_BY_AccessorID;
   public final String SQL_removeInGrantDomainCreatePermissionPostCreateSys_BY_AccessorID_PostCreateSysPermissionID;
   public final String SQL_createInGrantDomainCreatePermissionPostCreateSys_WITH_AccessorID_GrantorID_IsWithGrant_PostCreateIsWithGrant_PostCreateSysPermissionID;
   public final String SQL_updateInGrantDomainCreatePermissionPostCreateSys_SET_GrantorID_IsWithGrant_PostCreateIsWithGrant_BY_AccessorID_PostCreateSysPermissionID;
   // GrantDomainCreatePermissionPostCreateSys - recursive
   public final String SQL_findInGrantDomainCreatePermissionPostCreateSys_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID;

   // GrantDomainPermissionSys - common
   public final String SQL_findInGrantDomainPermissionSys_withoutInheritance_SysPermissionID_IsWithGrant_BY_AccessorID_DomainID;
   public final String SQL_findInGrantDomainPermissionSys_withoutInheritance_ResourceDomainName_SysPermissionID_IsWithGrant_BY_AccessorID;
   public final String SQL_createInGrantDomainPermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_SysPermissionID;
   public final String SQL_updateInGrantDomainPermissionSys_SET_GrantorID_IsWithGrant_BY_AccessorID_AccessedDomainID_SysPermissionID;
   public final String SQL_removeInGrantDomainPermissionSys_BY_AccessorID;
   public final String SQL_removeInGrantDomainPermissionSys_BY_AccessedDomainID;
   public final String SQL_removeInGrantDomainPermissionSys_BY_AccessorID_AccessedDomainID;
   public final String SQL_removeInGrantDomainPermissionSys_BY_AccessorID_AccessedDomainID_SysPermissionID;
   // GrantDomainPermissionSys - recursive
   public final String SQL_findInGrantDomainPermissionSys_ResourceID_ExternalId_BY_AccessorID_SysPermissionID_IsWithGrant_ResourceClassID;
   public final String SQL_findInGrantDomainPermissionSys_ResourceID_ExternalID_BY_AccessorID_DomainID_SysPermissionID_IsWithGrant_ResourceClassID;
   public final String SQL_findInGrantDomainPermissionSys_SysPermissionID_IsWithGrant_BY_AccessorID_DomainID;
   public final String SQL_findInGrantDomainPermissionSys_ResourceDomainName_SysPermissionID_IsWithGrant_BY_AccessorID;
   public final String SQL_removeInGrantDomainPermissionSys_withDescendants_BY_AccessedDomainID;
   // GrantDomainPermissionSys - non-recursive
   public final String SQL_findInGrantDomainPermissionSys_withoutInheritance_ResourceDomainId_BY_AccessorID_SysPermissionID_IsWithGrant;

   // Resource - common
   public final String SQL_findInResource_COUNTResourceID_BY_ResourceClassID_DomainID;
   public final String SQL_createInResource_WITH_ResourceID_ResourceClassID_DomainID;
   public final String SQL_createInResource_WITH_ResourceClassID_DomainID;
   public final String SQL_removeInResource_BY_ResourceID;
   public final String SQL_findInResource_ResourceId_BY_ResourceID;
   public final String SQL_findInResource_ResourceId_ExternalId_BY_ResourceID;
   public final String SQL_findInResource_DomainID_BY_ResourceID;
   public final String SQL_findInResource_withoutInheritance_ResourceId_ExternalId_BY_ResourceClassID_DomainID;
   public final String SQL_createInResourceExternalId_WITH_ResourceID_ExternalID;
   public final String SQL_removeInResourceExternalId_BY_ResourceID;
   public final String SQL_findInResourceExternalId_ResourceId_ExternalId_BY_ExternalID;
   // Resource - recursive
   public final String SQL_findInResource_COUNTResourceID_BY_DomainID;
   // Resource - non-recursive
   public final String SQL_findInResource_withoutInheritance_COUNTResourceID_BY_DomainID;

   // GrantResourceCreatePermissionSys - common
   public final String SQL_findInGrantResourceCreatePermissionSys_withoutInheritance_SysPermissionId_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantResourceCreatePermissionSys_withoutInheritance_ResourceDomainName_ResourceClassName_SysPermissionId_IsWithGrant_BY_AccessorID;
   public final String SQL_createInGrantResourceCreatePermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_SysPermissionId;
   public final String SQL_updateInGrantResourceCreatePermissionSys_SET_GrantorID_IsWithGrant_BY__AccessorID_AccessedDomainID_ResourceClassID_SysPermissionId;
   public final String SQL_removeInGrantResourceCreatePermissionSys_BY_AccessorID;
   public final String SQL_removeInGrantResourceCreatePermissionSys_BY_AccessedDomainId;
   public final String SQL_removeInGrantResourceCreatePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_removeInGrantResourceCreatePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID_SysPermissionID;
   // GrantResourceCreatePermissionSys - recursive
   public final String SQL_findInGrantResourceCreatePermissionSys_SysPermissionId_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantResourceCreatePermissionSys_ResourceDomainName_ResourceClassName_SysPermissionId_IsWithGrant_BY_AccessorID;
   public final String SQL_removeInGrantResourceCreatePermissionSys_withDescendants_BY_AccessedDomainId;

   // GrantResourceCreatePermissionPostCreateSys - common
   public final String SQL_findInGrantResourceCreatePermissionPostCreateSys_withoutInheritance_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantResourceCreatePermissionPostCreateSys_withoutInheritance_ResourceDomainName_ResourceClassName_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID;
   public final String SQL_createInGrantResourceCreatePermissionPostCreateSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_PostCreateIsWithGrant_ResourceClassID_PostCreateSysPermissionID;
   public final String SQL_updateInGrantResourceCreatePermissionPostCreateSys_SET_GrantorID_IsWithGrant_PostCreateIsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID_PostCreateSysPermissionID;
   public final String SQL_removeInGrantResourceCreatePermissionPostCreateSys_BY_AccessorID;
   public final String SQL_removeInGrantResourceCreatePermissionPostCreateSys_BY_AccessedDomainID;
   public final String SQL_removeInGrantResourceCreatePermissionPostCreateSys_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_removeInGrantResourceCreatePermissionPostCreateSys_BY_AccessorID_AccessedDomainID_ResourceClassID_PostCreateSysPermissionID;
   // GrantResourceCreatePermissionPostCreateSys - recursive
   public final String SQL_findInGrantResourceCreatePermissionPostCreateSys_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantResourceCreatePermissionPostCreateSys_ResourceDomainName_ResourceClassName_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID;
   public final String SQL_removeInGrantResourceCreatePermissionPostCreateSys_withDescendants_BY_AccessedDomainID;

   // GrantResourceCreatePermissionPostCreate - common
   public final String SQL_findInGrantResourceCreatePermissionPostCreate_withoutInheritance_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantResourceCreatePermissionPostCreate_withoutInheritance_ResourceDomainName_ResourceClassName_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID;
   public final String SQL_createInGrantResourceCreatePermissionPostCreate_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_PostCreateIsWithGrant_ResourceClassID_PostCreatePermissionName;
   public final String SQL_updateInGrantResourceCreatePermissionPostCreate_SET_GrantorID_IsWithGrant_PostCreateIsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID_PostCreatePermissionName;
   public final String SQL_removeInGrantResourceCreatePermissionPostCreate_BY_AccessorID;
   public final String SQL_removeInGrantResourceCreatePermissionPostCreate_BY_AccessedDomainId;
   public final String SQL_removeInGrantResourceCreatePermissionPostCreate_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_removeInGrantResourceCreatePermissionPostCreate_BY_AccessorID_AccessedDomainID_ResourceClassID_PostCreatePermissionName;
   // GrantResourceCreatePermissionPostCreate - recursive
   public final String SQL_findInGrantResourceCreatePermissionPostCreate_ResourceClassName_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantResourceCreatePermissionPostCreate_ResourceDomainName_ResourceClassName_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID;
   public final String SQL_removeInGrantResourceCreatePermissionPostCreate_withDescendants_BY_AccessedDomainId;

   // GrantResourcePermissionSys - common
   public final String SQL_findInGrantResourcePermissionSys_ResourceID_ExternalID_BY_AccessedID_ResourceClassID_SysPermissionID_IsWithGrant;
   public final String SQL_findInGrantResourcePermissionSys_withoutInheritance_ResourceClassName_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedID;
   public final String SQL_createInGrantResourcePermissionSys_WITH_AccessorID_GrantorID_AccessedID_IsWithGrant_ResourceClassID_SysPermissionID;
   public final String SQL_updateInGrantResourcePermissionSys_SET_GrantorID_IsWithGrant_BY_AccessorID_AccessedID_ResourceClassID_SysPermissionID;
   public final String SQL_removeInGrantResourcePermissionSys_BY_AccessorID_OR_AccessedID;
   public final String SQL_removeInGrantResourcePermissionSys_BY_AccessorID_AccessedID;
   public final String SQL_removeInGrantResourcePermissionSys_BY_AccessorID_AccessedID_ResourceClassID_SysPermissionID;
   // GrantResourcePermissionSys - recursive
   public final String SQL_findInGrantResourcePermissionSys_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant;
   public final String SQL_findInGrantResourcePermissionSys_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant;
   public final String SQL_findInGrantResourcePermissionSys_ResourceClassName_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedID;
   // GrantResourcePermissionSys - non-recursive
   public final String SQL_findInGrantResourcePermissionSys_directInheritance_ResourceID_BY_AccessorID;
   public final String SQL_findInGrantResourcePermissionSys_withoutInheritance_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant;
   public final String SQL_findInGrantResourcePermissionSys_withoutInheritance_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant;

   // GrantResourcePermission - common
   public final String SQL_findInGrantResourcePermission_ResourceID_ExternalID_BY_AccessedID_ResourceClassID_PermissionID_IsWithGrant;
   public final String SQL_findInGrantResourcePermission_withoutInheritance_ResourceClassName_PermissionName_IsWithGrant_BY_AccessorID_AccessedID;
   public final String SQL_createInGrantResourcePermission_WITH_AccessorID_GrantorID_AccessedID_IsWithGrant_ResourceClassID_PermissionName;
   public final String SQL_updateInGrantResourcePermission_SET_GrantorID_IsWithGrant_BY_AccessorID_AccessedID_ResourceClassID_PermissionName;
   public final String SQL_removeInGrantResourcePermission_BY_AccessorID_OR_AccessedID;
   public final String SQL_removeInGrantResourcePermission_BY_AccessorID_AccessedID;
   public final String SQL_removeInGrantResourcePermission_BY_AccessorID_AccessedID_ResourceClassID_PermissionName;
   // GrantResourcePermission - recursive
   public final String SQL_findInGrantResourcePermission_ResourceClassName_PermissionName_IsWithGrant_BY_AccessorID_AccessedID;
   public final String SQL_findInGrantResourcePermission_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_PermissionID_IsWithGrant;
   public final String SQL_findInGrantResourcePermission_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_PermissionID_IsWithGrant;
   // GrantResourcePermission - non-recursive
   public final String SQL_findInGrantResourcePermission_withoutInheritance_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_PermissionID_IsWithGrant;
   public final String SQL_findInGrantResourcePermission_withoutInheritance_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_PermissionID_IsWithGrant;

   // GrantGlobalResourcePermissionSys - common
   public final String SQL_findInGrantGlobalResourcePermissionSys_withoutInheritance_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantGlobalResourcePermissionSys_withoutInheritance_ResourceDomainName_ResourceClassName_SysPermissionID_IsWithGrant_BY_AccessorID;
   public final String SQL_createInGrantGlobalResourcePermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_SysPermissionID;
   public final String SQL_updateInGrantGlobalResourcePermissionSys_SET_GrantorID_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID_SysPermissionID;
   public final String SQL_removeInGrantGlobalResourcePermissionSys_BY_AccessorID;
   public final String SQL_removeInGrantGlobalResourcePermissionSys_BY_AccessedDomainId;
   public final String SQL_removeInGrantGlobalResourcePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_removeInGrantGlobalResourcePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID_SysPermissionID;
   // GrantGlobalResourcePermissionSys - recursive
   public final String SQL_findInGrantGlobalResourcePermissionSys_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant_ResourceClassID;
   public final String SQL_findInGrantGlobalResourcePermissionSys_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant_ResourceClassID;
   public final String SQL_findInGrantGlobalResourcePermissionSys_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantGlobalResourcePermissionSys_ResourceDomainName_ResourceClassName_SysPermissionID_IsWithGrant_BY_AccessorID;
   public final String SQL_removeInGrantGlobalResourcePermissionSys_withDescendants_BY_AccessedDomainId;
   // GrantGlobalResourcePermissionSys - non-recursive
   public final String SQL_findInGrantGlobalResourcePermissionSys_withoutInheritance_ResourceDomainID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant;

   // GrantGlobalResourcePermission - common
   public final String SQL_findInGrantGlobalResourcePermission_withoutInheritance_PermissionName_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantGlobalResourcePermission_withoutInheritance_ResourceDomainName_ResourceClassName_PermissionName_IsWithGrant_BY_AccessorID;
   public final String SQL_createInGrantGlobalResourcePermission_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_PermissionName;
   public final String SQL_updateInGrantGlobalResourcePermission_SET_GrantorID_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID_PermissionName;
   public final String SQL_removeInGrantGlobalResourcePermission_BY_AccessorID;
   public final String SQL_removeInGrantGlobalResourcePermission_BY_AccessedDomainId;
   public final String SQL_removeInGrantGlobalResourcePermission_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_removeInGrantGlobalResourcePermission_BY_AccessorID_AccessedDomainID_ResourceClassID_PermissionName;
   // GrantGlobalResourcePermission - recursive
   public final String SQL_findInGrantGlobalResourcePermission_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_PermissionID_IsWithGrant_ResourceClassID;
   public final String SQL_findInGrantGlobalResourcePermission_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_PermissionID_IsWithGrant_ResourceClassID;
   public final String SQL_findInGrantGlobalResourcePermission_PermissionName_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantGlobalResourcePermission_ResourceDomainName_ResourceClassName_PermissionName_IsWithGrant_BY_AccessorID;
   public final String SQL_removeInGrantGlobalResourcePermission_withDescendants_BY_AccessedDomainId;
   // GrantGlobalResourcePermission - non-recursive
   public final String SQL_findInGrantGlobalResourcePermission_withoutInheritance_ResourceDomainID_BY_AccessorID_ResourceClassID_PermissionID_IsWithGrant;

   // Key generators
   public final String SQL_nextResourceID;

   private final SQLProfile sqlProfile;

   // resource permissions constants
   private static final ResourcePermission ResourcePermission_INHERIT = ResourcePermissions.getInstance(ResourcePermissions.INHERIT);

   public static SQLStrings getSQLStrings(String schemaName,
                                          SQLProfile sqlProfile) {
      return new SQLStrings(schemaName, sqlProfile, DialectSpecificSQLGenerator.getInstance(sqlProfile
                                                                                                  .getSqlDialect()));
   }

   private SQLStrings(String schemaName,
                      SQLProfile sqlProfile,
                      DialectSpecificSQLGenerator dialectSpecificSQLGenerator) {
      this.sqlProfile = sqlProfile;
      final String withClause = dialectSpecificSQLGenerator.getWithClause();
      final String unionClause = dialectSpecificSQLGenerator.getUnionClause();
      final String schemaNameAndTablePrefix = schemaName != null ? schemaName + ".OAC_" : "OAC_";
      // recursive query to compute all the resource ids that a given accessor is equivalent to as a
      // result of having the INHERIT permission
      final String SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            = withClause + " N( AccessorResourceId ) AS "
            + "( SELECT ResourceId FROM "
            + schemaNameAndTablePrefix
            + "Resource WHERE ResourceId = ? " + unionClause + " SELECT Nplus1.AccessedResourceId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys Nplus1, N "
            + "WHERE Nplus1.AccessorResourceId = N.AccessorResourceId AND Nplus1.SysPermissionId = "
            + ResourcePermission_INHERIT.getSystemPermissionId()
            + " ) ";

      // recursive query to compute all ancestors of a given an domain
      final String SQL_findAncestorsRecursiveInDomain_DomainID_BY_DomainID
            = ", R( DomainId, ParentDomainId ) AS "
            + "( SELECT DomainId, ParentDomainId FROM "
            + schemaNameAndTablePrefix
            + "Domain WHERE DomainId = ? " + unionClause + " SELECT Rplus1.DomainId, Rplus1.ParentDomainId FROM "
            + schemaNameAndTablePrefix
            + "Domain Rplus1, R "
            + "WHERE R.ParentDomainId IS NOT NULL AND Rplus1.DomainId = R.ParentDomainId ) ";

      // recursive query to compute all descendants of a given an domain
      final String SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
            = "S( DomainId ) AS "
            + "( SELECT DomainId FROM "
            + schemaNameAndTablePrefix
            + "Domain WHERE DomainId = ? " + unionClause + " SELECT Splus1.DomainId FROM "
            + schemaNameAndTablePrefix
            + "Domain Splus1, S "
            + "WHERE Splus1.ParentDomainId IS NOT NULL AND Splus1.ParentDomainId = S.DomainId ) ";

      // ResourceClass
      SQL_findInResourceClass_ResourceClassID_BY_ResourceClassName
            = "SELECT ResourceClassId FROM "
            + schemaNameAndTablePrefix
            + "ResourceClass WHERE ResourceClassName = ?";

      SQL_findInResourceClass_ResourceClassID_ResourceClassName_IsAuthenticatable_IsUnauthenticatedCreateAllowed_BY_ResourceClassName
            = "SELECT ResourceClassId, ResourceClassName, IsAuthenticatable, IsUnauthenticatedCreateAllowed FROM "
            + schemaNameAndTablePrefix
            + "ResourceClass WHERE ResourceClassName = ?";

      SQL_findInResourceClass_ResourceClassID_ResourceClassName_IsAuthenticatable_IsUnauthenticatedCreateAllowed_BY_ResourceID
            = "SELECT ResourceClassId, ResourceClassName, IsAuthenticatable, IsUnauthenticatedCreateAllowed FROM "
            + schemaNameAndTablePrefix
            + "ResourceClass WHERE ResourceClassId = ( SELECT ResourceClassId FROM "
            + schemaNameAndTablePrefix
            + "Resource WHERE ResourceId = ? )";

      SQL_findInResourceClass_ResourceClassName_BY_ALL
            = "SELECT ResourceClassName FROM "
            + schemaNameAndTablePrefix
            + "ResourceClass WHERE ResourceClassId <> 0";  // <> 0 filters out the SYSOBJECT class

      SQL_createInResourceClass_WITH_ResourceClassName_IsAuthenticatable_IsUnauthenticatedCreateAllowed
            = sqlProfile.isSequenceEnabled()
              ? "INSERT INTO "
                    + schemaNameAndTablePrefix
                    + "ResourceClass ( ResourceClassId, ResourceClassName, IsAuthenticatable, IsUnauthenticatedCreateAllowed ) "
                    + "VALUES ( "
                    + dialectSpecificSQLGenerator.nextSequenceValueFragment(schemaNameAndTablePrefix + "ResourceClassId")
                    + ", ?, ?, ? )"
              : "INSERT INTO "
                    + schemaNameAndTablePrefix
                    + "ResourceClass ( ResourceClassName, IsAuthenticatable, IsUnauthenticatedCreateAllowed ) "
                    + "VALUES ( ?, ?, ? )";

      // ResourceClassPermission
      SQL_findInResourceClassPermission_PermissionID_BY_ResourceClassID_PermissionName
            = "SELECT PermissionId FROM "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission WHERE ResourceClassId = ? AND PermissionName = ?";

      SQL_findInResourceClassPermission_PermissionName_BY_ResourceClassName
            = "SELECT PermissionName FROM "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission WHERE ResourceClassId = ( SELECT ResourceClassId FROM "
            + schemaNameAndTablePrefix
            + "ResourceClass WHERE ResourceClassName = ? )";

      SQL_createInResourceClassPermission_WITH_ResourceClassID_PermissionName
            = sqlProfile.isSequenceEnabled()
              ? "INSERT INTO "
                    + schemaNameAndTablePrefix
                    + "ResourceClassPermission ( ResourceClassId, PermissionId, PermissionName ) VALUES ( ?, "
                    + dialectSpecificSQLGenerator.nextSequenceValueFragment(schemaNameAndTablePrefix + "PermissionId")
                    + ", ? )"
              : "INSERT INTO "
                    + schemaNameAndTablePrefix
                    + "ResourceClassPermission ( ResourceClassId, PermissionName ) VALUES ( ?, ? )";

      // Domain - common
      SQL_findInDomain_DomainID_BY_ResourceDomainName
            = "SELECT DomainId FROM "
            + schemaNameAndTablePrefix
            + "Domain WHERE DomainName = ?";

      SQL_findInDomain_ResourceDomainName_BY_ResourceID
            = "SELECT DomainName FROM "
            + schemaNameAndTablePrefix
            + "Domain WHERE DomainId = ( SELECT DomainId FROM "
            + schemaNameAndTablePrefix
            + "Resource WHERE ResourceId = ? )";

      SQL_createInDomain_WITH_ResourceDomainName
            = sqlProfile.isSequenceEnabled()
              ? "INSERT INTO "
                    + schemaNameAndTablePrefix
                    + "Domain ( DomainId, DomainName ) VALUES ( "
                    + dialectSpecificSQLGenerator.nextSequenceValueFragment(schemaNameAndTablePrefix + "DomainId")
                    + ", ? )"
              : "INSERT INTO "
                    + schemaNameAndTablePrefix
                    + "Domain ( DomainName ) VALUES ( ? )";

      SQL_createInDomain_WITH_ResourceDomainName_ParentDomainID
            = sqlProfile.isSequenceEnabled()
              ? "INSERT INTO "
                    + schemaNameAndTablePrefix
                    + "Domain ( DomainId, DomainName, ParentDomainId ) VALUES ( "
                    + dialectSpecificSQLGenerator.nextSequenceValueFragment(schemaNameAndTablePrefix + "DomainId")
                    + ", ?, ? )"
              : "INSERT INTO "
                    + schemaNameAndTablePrefix
                    + "Domain ( DomainName, ParentDomainId ) VALUES ( ?, ? )";

      SQL_removeInDomain_BY_DomainID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Domain WHERE DomainId = ?";

      // Domain - recursive
      // recursive query to return all descendants domain names of the specified domain names
      SQL_findInDomain_DescendantResourceDomainName_BY_ResourceDomainName
            = withClause + " S( DomainId, DomainName ) AS "
            + "( SELECT DomainId, DomainName FROM "
            + schemaNameAndTablePrefix
            + "Domain WHERE DomainName = ? "
            + unionClause + " "
            + "SELECT Splus1.DomainId, Splus1.DomainName FROM "
            + schemaNameAndTablePrefix
            + "Domain Splus1, S "
            + "WHERE Splus1.ParentDomainId IS NOT NULL AND Splus1.ParentDomainId = S.DomainId ) "
            + "SELECT DomainId, DomainName FROM S";

      SQL_findInDomain_DescendantResourceDomainID_BY_DomainID_ORDERBY_DomainLevel
            = withClause + " S( DomainId, DomainName, DomainLevel ) AS "
            + "( SELECT DomainId, DomainName, 0 FROM "
            + schemaNameAndTablePrefix
            + "Domain WHERE DomainId = ? "
            + unionClause + " "
            + "SELECT Splus1.DomainId, Splus1.DomainName, S.DomainLevel + 1 FROM "
            + schemaNameAndTablePrefix
            + "Domain Splus1, S "
            + "WHERE Splus1.ParentDomainId IS NOT NULL AND Splus1.ParentDomainId = S.DomainId ) "
            + "SELECT DomainId, DomainName FROM S ORDER BY DomainLevel";

      SQL_removeInDomain_withDescendants_BY_DomainID
            = sqlProfile.isRecursiveDeleteEnabled()
              ? (SQLDialect.Oracle_11_2.equals(sqlProfile.getSqlDialect()))
                ? "DELETE FROM "
                      + schemaNameAndTablePrefix
                      + "Domain WHERE DomainId IN ( "
                      + withClause + " "
                      + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
                      + "SELECT DomainId FROM S )"
                : withClause + " "
                      + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
                      + "DELETE FROM "
                      + schemaNameAndTablePrefix
                      + "Domain WHERE DomainId IN ( SELECT DomainId FROM S )"
              : null;

      // Domain - non-recursive
      // non-recursive query to return only direct (first-level) descendants domain names of the specified domain
      SQL_findInDomain_DirectDescendantResourceDomainName_BY_ResourceDomainName
            = "SELECT d1.DomainId, d1.DomainName FROM "
            + schemaNameAndTablePrefix
            + "Domain d0 JOIN "
            + schemaNameAndTablePrefix
            + "Domain d1 on d1.ParentDomainId=d0.DomainId WHERE d0.DomainName = ?";

      SQL_findInDomain_DirectDescendantResourceDomainName_BY_DomainID
            = "SELECT DomainId, DomainName FROM "
            + schemaNameAndTablePrefix
            + "Domain WHERE ParentDomainId = ?";

      SQL_findInDomain_ParentResourceDomainName_BY_DomainID
            = "SELECT d1.DomainId, d1.DomainName FROM "
            + schemaNameAndTablePrefix
            + "Domain d0 JOIN "
            + schemaNameAndTablePrefix
            + "Domain d1 ON d1.DomainId = d0.ParentDomainId WHERE d0.DomainId = ?";

      // GrantDomainCreatePermissionSys - common
      SQL_findInGrantDomainCreatePermissionSys_withoutInheritance_SysPermissionID_BY_AccessorID
            = "SELECT A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_Sys A "
            + "WHERE A.AccessorResourceId = ?";

      SQL_createInGrantDomainCreatePermissionSys_WITH_AccessorID_GrantorID_IsWithGrant_SysPermissionID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_Sys ( AccessorResourceId, GrantorResourceId, IsWithGrant, SysPermissionId ) "
            + "VALUES( ?, ?, ?, ? )";

      SQL_updateInGrantDomainCreatePermissionSys_SET_GrantorID_IsWithGrant_BY_AccessorID_SysPermissionID
            = "UPDATE "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_Sys SET GrantorResourceId = ?, IsWithGrant = ? "
            + "WHERE AccessorResourceId = ? AND SysPermissionId = ?";

      SQL_removeInGrantDomainCreatePermissionSys_BY_AccessorID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_Sys WHERE AccessorResourceId = ?";

      SQL_removeInGrantDomainCreatePermissionSys_BY_AccessorID_SysPermissionID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_Sys WHERE AccessorResourceId = ? AND SysPermissionId = ?";

      // GrantDomainCreatePermissionSys - recursive
      SQL_findInGrantDomainCreatePermissionSys_SysPermissionID_IsWithGrant_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + "SELECT A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId ";

      // GrantDomainCreatePermissionPostCreateSys - common
      SQL_findInGrantDomainCreatePermissionPostCreateSys_withoutInheritance_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID
            = "SELECT A.PostCreateSysPermissionId, A.PostCreateIsWithGrant, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_PostCr_Sys A "
            + "WHERE A.AccessorResourceId = ?";

      SQL_createInGrantDomainCreatePermissionPostCreateSys_WITH_AccessorID_GrantorID_IsWithGrant_PostCreateIsWithGrant_PostCreateSysPermissionID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_PostCr_Sys ( AccessorResourceId, GrantorResourceId, IsWithGrant, PostCreateIsWithGrant, PostCreateSysPermissionId ) "
            + "VALUES( ?, ?, ?, ?, ? )";

      SQL_updateInGrantDomainCreatePermissionPostCreateSys_SET_GrantorID_IsWithGrant_PostCreateIsWithGrant_BY_AccessorID_PostCreateSysPermissionID
            = "UPDATE "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_PostCr_Sys SET GrantorResourceId = ?, IsWithGrant = ?, PostCreateIsWithGrant = ? "
            + "WHERE AccessorResourceId = ? AND PostCreateSysPermissionId  = ?";

      SQL_removeInGrantDomainCreatePermissionPostCreateSys_BY_AccessorID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_PostCr_Sys WHERE AccessorResourceId = ?";

      SQL_removeInGrantDomainCreatePermissionPostCreateSys_BY_AccessorID_PostCreateSysPermissionID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_PostCr_Sys WHERE AccessorResourceId = ? AND PostCreateSysPermissionId = ?";

      // GrantDomainCreatePermissionPostCreateSys - recursive
      SQL_findInGrantDomainCreatePermissionPostCreateSys_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + "SELECT A.PostCreateSysPermissionId, A.PostCreateIsWithGrant, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_PostCr_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId ";

      // GrantDomainPermissionSys - common
      SQL_findInGrantDomainPermissionSys_withoutInheritance_SysPermissionID_IsWithGrant_BY_AccessorID_DomainID
            = "SELECT A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys A "
            + "WHERE A.AccessorResourceId = ? AND A.AccessedDomainId = ?";

      SQL_findInGrantDomainPermissionSys_withoutInheritance_ResourceDomainName_SysPermissionID_IsWithGrant_BY_AccessorID
            = "SELECT B.DomainName, A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys A JOIN "
            + schemaNameAndTablePrefix
            + "Domain B ON B.DomainId = A.AccessedDomainId "
            + "WHERE A.AccessorResourceId = ?";

      SQL_createInGrantDomainPermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_SysPermissionID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys ( AccessorResourceId, GrantorResourceId, AccessedDomainId, IsWithGrant, SysPermissionId ) VALUES ( ?, ?, ?, ?, ? )";

      SQL_updateInGrantDomainPermissionSys_SET_GrantorID_IsWithGrant_BY_AccessorID_AccessedDomainID_SysPermissionID
            = "UPDATE "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys SET GrantorResourceId = ?, IsWithGrant = ? "
            + "WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND SysPermissionId = ?";

      SQL_removeInGrantDomainPermissionSys_BY_AccessorID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys WHERE AccessorResourceId = ?";

      SQL_removeInGrantDomainPermissionSys_BY_AccessedDomainID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys WHERE AccessedDomainId = ?";

      SQL_removeInGrantDomainPermissionSys_BY_AccessorID_AccessedDomainID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys WHERE AccessorResourceId = ? AND AccessedDomainId = ?";

      SQL_removeInGrantDomainPermissionSys_BY_AccessorID_AccessedDomainID_SysPermissionID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND SysPermissionId = ?";

      // GrantDomainPermissionSys - recursive

      // query returns the resources that the accessor has access to via super user permission
      SQL_findInGrantDomainPermissionSys_ResourceID_ExternalId_BY_AccessorID_SysPermissionID_IsWithGrant_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + ", R( DomainId ) AS "
            // this sub query is the starting set for the domain recursion, it returns all the direct
            // resources domains that the accessor has the specified system permission on (currently super-user)
            + "( SELECT AccessedDomainId FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys G "
            + "JOIN N ON N.AccessorResourceId = G.AccessorResourceId "
            + "WHERE G.SysPermissionId = ? AND ( ? IN ( 0, G.IsWithGrant ) ) "
            // now we find the nested domains that the accessor can reach from the direct set above
            + unionClause + " SELECT Rplus1.DomainId FROM "
            + schemaNameAndTablePrefix
            + "Domain Rplus1, R "
            + "WHERE Rplus1.ParentDomainId IS NOT NULL AND Rplus1.ParentDomainId = R.DomainId ) "
            // finally we get the resources of the specified type in the domains we computed above
            + "SELECT A.ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Resource A "
            + "JOIN R ON R.DomainId = A.DomainId LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = A.ResourceId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantDomainPermissionSys_ResourceID_ExternalID_BY_AccessorID_DomainID_SysPermissionID_IsWithGrant_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + ", " + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
            + ", R( DomainId ) AS "
            // this sub query is the starting set for the domain recursion, it returns all the direct
            // resources domains that the accessor has the specified system permission on (currently super-user)
            + "( SELECT AccessedDomainId FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys G "
            + "JOIN N ON N.AccessorResourceId = G.AccessorResourceId "
            + "WHERE G.SysPermissionId = ? AND ( ? IN ( 0, G.IsWithGrant ) ) "
            // now we find the nested domains that the accessor can reach from the direct set above
            + unionClause + " SELECT Rplus1.DomainId FROM "
            + schemaNameAndTablePrefix
            + "Domain Rplus1, R "
            + "WHERE Rplus1.ParentDomainId IS NOT NULL AND Rplus1.ParentDomainId = R.DomainId ) "
            // finally we get the resources of the specified type in the domains we computed above
            + "SELECT A.ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Resource A "
            + "JOIN R ON R.DomainId = A.DomainId "
            + "JOIN S ON S.DomainId = A.DomainId LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = A.ResourceId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantDomainPermissionSys_SysPermissionID_IsWithGrant_BY_AccessorID_DomainID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + SQL_findAncestorsRecursiveInDomain_DomainID_BY_DomainID
            + "SELECT A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "JOIN R ON R.DomainId = A.AccessedDomainId ";

      SQL_findInGrantDomainPermissionSys_ResourceDomainName_SysPermissionID_IsWithGrant_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + ", P( AccessedDomainId, SysPermissionId, IsWithGrant ) AS "
            + "( SELECT A.AccessedDomainId, A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + unionClause + " "
            + "SELECT Pplus1.DomainId, P.SysPermissionId, P.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Domain Pplus1, P "
            + "WHERE Pplus1.ParentDomainId IS NOT NULL AND Pplus1.ParentDomainId = P.AccessedDomainId ) "
            + "SELECT B.DomainName, P.SysPermissionId, P.IsWithGrant FROM P JOIN "
            + schemaNameAndTablePrefix
            + "Domain B ON B.DomainId = P.AccessedDomainId";

      SQL_removeInGrantDomainPermissionSys_withDescendants_BY_AccessedDomainID
            = sqlProfile.isRecursiveDeleteEnabled()
              ? (SQLDialect.Oracle_11_2.equals(sqlProfile.getSqlDialect()))
                ? "DELETE FROM "
                      + schemaNameAndTablePrefix
                      + "Grant_DomPerm_Sys WHERE AccessedDomainId IN ( "
                      + withClause + " "
                      + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
                      + "SELECT DomainId FROM S )"
                : withClause + " "
                      + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
                      + "DELETE FROM "
                      + schemaNameAndTablePrefix
                      + "Grant_DomPerm_Sys WHERE AccessedDomainId IN ( SELECT DomainId FROM S )"
              : null;

      // GrantDomainPermissionSys - non-recursive
      SQL_findInGrantDomainPermissionSys_withoutInheritance_ResourceDomainId_BY_AccessorID_SysPermissionID_IsWithGrant
            = "SELECT AccessedDomainID FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys "
            + "WHERE AccessorResourceId = ? AND SysPermissionId = ? AND ( ? IN ( 0, IsWithGrant ) )";

      // Resource: finder methods used getAccessorResourcesByResourcePermission()
      SQL_findInGrantResourcePermissionSys_ResourceID_ExternalID_BY_AccessedID_ResourceClassID_SysPermissionID_IsWithGrant
            = "SELECT A.AccessorResourceId ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys A LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = A.AccessorResourceId "
            + "WHERE A.AccessedResourceId = ? AND A.ResourceClassId = ? AND A.SysPermissionId = ? AND ( ? IN ( 0, A.IsWithGrant ) )";

      // Resource - common
      SQL_findInResource_COUNTResourceID_BY_ResourceClassID_DomainID
            = "SELECT COUNT( ResourceId ) COUNTResourceID FROM "
            + schemaNameAndTablePrefix
            + "Resource WHERE ResourceClassId = ? AND DomainId = ?";

      SQL_createInResource_WITH_ResourceID_ResourceClassID_DomainID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Resource ( ResourceId, ResourceClassId, DomainId ) VALUES ( ?, ?, ? )";

      SQL_createInResource_WITH_ResourceClassID_DomainID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Resource ( ResourceClassId, DomainId ) VALUES ( ?, ? )";

      SQL_removeInResource_BY_ResourceID
            = "DELETE FROM " + schemaNameAndTablePrefix + "Resource WHERE ResourceId = ?";

      SQL_findInResource_ResourceId_BY_ResourceID
            = "SELECT ResourceId FROM " + schemaNameAndTablePrefix + "Resource WHERE ResourceId = ?";

      SQL_findInResource_ResourceId_ExternalId_BY_ResourceID
            = "SELECT A.ResourceId, B.ExternalId FROM "
            + schemaNameAndTablePrefix + "Resource A LEFT JOIN "
            + schemaNameAndTablePrefix + "ResourceExternalID B ON B.ResourceID = A.ResourceID WHERE A.ResourceId = ?";

      SQL_findInResource_DomainID_BY_ResourceID
            = "SELECT DomainId FROM " + schemaNameAndTablePrefix + "Resource WHERE ResourceId = ? ";

      SQL_findInResource_withoutInheritance_ResourceId_ExternalId_BY_ResourceClassID_DomainID
            = "SELECT A.ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix + "Resource A  LEFT JOIN "
            + schemaNameAndTablePrefix + "ResourceExternalID E ON E.ResourceId = A.ResourceId "
            + "WHERE A.ResourceClassId = ? AND A.DomainId = ?";

      SQL_createInResourceExternalId_WITH_ResourceID_ExternalID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "ResourceExternalID ( ResourceId, ExternalId ) VALUES ( ?, ? )";

      SQL_removeInResourceExternalId_BY_ResourceID
            = "DELETE FROM " + schemaNameAndTablePrefix + "ResourceExternalID WHERE ResourceId = ?";

      SQL_findInResourceExternalId_ResourceId_ExternalId_BY_ExternalID
            = "SELECT ResourceId, ExternalId FROM "
            + schemaNameAndTablePrefix + "ResourceExternalID WHERE ExternalId = ?";

      // Resource - recursive
      SQL_findInResource_COUNTResourceID_BY_DomainID
            = withClause + " "
            + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
            + "SELECT COUNT( ResourceId ) COUNTResourceID FROM "
            + schemaNameAndTablePrefix
            + "Resource C JOIN S ON S.DomainId = C.DomainId";

      // Resource - non-recursive
      SQL_findInResource_withoutInheritance_COUNTResourceID_BY_DomainID
            = "SELECT COUNT( ResourceId ) COUNTResourceID FROM "
            + schemaNameAndTablePrefix
            + "Resource WHERE DomainId = ?";

     // GrantResourceCreatePermissionSys - common
      SQL_findInGrantResourceCreatePermissionSys_withoutInheritance_SysPermissionId_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "SELECT A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys A "
            + "WHERE A.AccessorResourceId = ? AND A.AccessedDomainId = ? AND A.ResourceClassId = ?";

      SQL_findInGrantResourceCreatePermissionSys_withoutInheritance_ResourceDomainName_ResourceClassName_SysPermissionId_IsWithGrant_BY_AccessorID
            = "SELECT C.DomainName, B.ResourceClassName, A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass B ON B.ResourceClassId = A.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain C ON C.DomainId = A.AccessedDomainId "
            + "WHERE A.AccessorResourceId = ?";

      SQL_createInGrantResourceCreatePermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_SysPermissionId
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys ( AccessorResourceId, GrantorResourceId, AccessedDomainId, IsWithGrant, ResourceClassId, SysPermissionId ) "
            + "VALUES( ?, ?, ?, ?, ?, ? )";

      SQL_updateInGrantResourceCreatePermissionSys_SET_GrantorID_IsWithGrant_BY__AccessorID_AccessedDomainID_ResourceClassID_SysPermissionId
            = "UPDATE "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys SET GrantorResourceId = ?, IsWithGrant = ? "
            + "WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ? AND SysPermissionId = ?";

      SQL_removeInGrantResourceCreatePermissionSys_BY_AccessorID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys WHERE AccessorResourceId = ?";

      SQL_removeInGrantResourceCreatePermissionSys_BY_AccessedDomainId
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys WHERE AccessedDomainId = ?";

      SQL_removeInGrantResourceCreatePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ?";

      SQL_removeInGrantResourceCreatePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID_SysPermissionID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ? AND SysPermissionId = ?";

      // GrantResourceCreatePermissionSys - recursive
      SQL_findInGrantResourceCreatePermissionSys_SysPermissionId_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + SQL_findAncestorsRecursiveInDomain_DomainID_BY_DomainID
            + "SELECT A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "JOIN R ON R.DomainId = A.AccessedDomainId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantResourceCreatePermissionSys_ResourceDomainName_ResourceClassName_SysPermissionId_IsWithGrant_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + ", P( AccessedDomainId, ResourceClassId, SysPermissionId, IsWithGrant ) AS "
            + "( SELECT A.AccessedDomainId, A.ResourceClassId, A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + unionClause + " "
            + "SELECT Pplus1.DomainId, P.ResourceClassId, P.SysPermissionId, P.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Domain Pplus1, P "
            + "WHERE Pplus1.ParentDomainId IS NOT NULL AND Pplus1.ParentDomainId = P.AccessedDomainId ) "
            + "SELECT C.DomainName, B.ResourceClassName, P.SysPermissionId, P.IsWithGrant FROM P JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass B ON B.ResourceClassId = P.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain C ON C.DomainId = P.AccessedDomainId";

      SQL_removeInGrantResourceCreatePermissionSys_withDescendants_BY_AccessedDomainId
            = sqlProfile.isRecursiveDeleteEnabled()
              ? (SQLDialect.Oracle_11_2.equals(sqlProfile.getSqlDialect()))
                ? "DELETE FROM "
                      + schemaNameAndTablePrefix
                      + "Grant_ResCrPerm_Sys WHERE AccessedDomainId IN ( "
                      + withClause + " "
                      + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
                      + "SELECT DomainId FROM S )"
                : withClause + " "
                      + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
                      + "DELETE FROM "
                      + schemaNameAndTablePrefix
                      + "Grant_ResCrPerm_Sys WHERE AccessedDomainId IN ( SELECT DomainId FROM S )"
              : null;

      // GrantResourceCreatePermissionPostCreateSys - common
      SQL_findInGrantResourceCreatePermissionPostCreateSys_withoutInheritance_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "SELECT A.PostCreateSysPermissionId, A.PostCreateIsWithGrant, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys A "
            + "WHERE A.AccessorResourceId = ? AND A.AccessedDomainId = ? AND A.ResourceClassId = ?";

      SQL_findInGrantResourceCreatePermissionPostCreateSys_withoutInheritance_ResourceDomainName_ResourceClassName_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID
            = "SELECT C.DomainName, B.ResourceClassName, A.PostCreateSysPermissionId, A.PostCreateIsWithGrant, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass B ON B.ResourceClassId = A.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain C ON C.DomainId = A.AccessedDomainId "
            + "WHERE A.AccessorResourceId = ?";

      SQL_createInGrantResourceCreatePermissionPostCreateSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_PostCreateIsWithGrant_ResourceClassID_PostCreateSysPermissionID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys ( AccessorResourceId, GrantorResourceId, AccessedDomainId, IsWithGrant, PostCreateIsWithGrant, ResourceClassId, PostCreateSysPermissionId ) "
            + "VALUES( ?, ?, ?, ?, ?, ?, ? )";

      SQL_updateInGrantResourceCreatePermissionPostCreateSys_SET_GrantorID_IsWithGrant_PostCreateIsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID_PostCreateSysPermissionID
            = "UPDATE "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys SET GrantorResourceId = ?, IsWithGrant = ?, PostCreateIsWithGrant = ? "
            + "WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ? AND PostCreateSysPermissionId = ?";

      SQL_removeInGrantResourceCreatePermissionPostCreateSys_BY_AccessorID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys WHERE AccessorResourceId = ?";

      SQL_removeInGrantResourceCreatePermissionPostCreateSys_BY_AccessedDomainID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys WHERE AccessedDomainId = ?";

      SQL_removeInGrantResourceCreatePermissionPostCreateSys_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ?";

      SQL_removeInGrantResourceCreatePermissionPostCreateSys_BY_AccessorID_AccessedDomainID_ResourceClassID_PostCreateSysPermissionID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ? AND PostCreateSysPermissionId = ?";

      // GrantResourceCreatePermissionPostCreateSys - recursive
      SQL_findInGrantResourceCreatePermissionPostCreateSys_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + SQL_findAncestorsRecursiveInDomain_DomainID_BY_DomainID
            + "SELECT A.PostCreateSysPermissionId, A.PostCreateIsWithGrant, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "JOIN R ON R.DomainId = A.AccessedDomainId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantResourceCreatePermissionPostCreateSys_ResourceDomainName_ResourceClassName_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + ", P( AccessedDomainId, ResourceClassId, PostCreateSysPermissionId, PostCreateIsWithGrant, IsWithGrant ) AS "
            + "( SELECT A.AccessedDomainId, A.ResourceClassId, A.PostCreateSysPermissionId, A.PostCreateIsWithGrant, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + unionClause + " "
            + "SELECT Pplus1.DomainId, P.ResourceClassId, P.PostCreateSysPermissionId, P.PostCreateIsWithGrant, P.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Domain Pplus1, P "
            + "WHERE Pplus1.ParentDomainId IS NOT NULL AND Pplus1.ParentDomainId = P.AccessedDomainId ) "
            + "SELECT C.DomainName, B.ResourceClassName, P.PostCreateSysPermissionId, P.PostCreateIsWithGrant, P.IsWithGrant FROM P JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass B ON B.ResourceClassId = P.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain C ON C.DomainId = P.AccessedDomainId";

      SQL_removeInGrantResourceCreatePermissionPostCreateSys_withDescendants_BY_AccessedDomainID
            = sqlProfile.isRecursiveDeleteEnabled()
              ? (SQLDialect.Oracle_11_2.equals(sqlProfile.getSqlDialect()))
                ? "DELETE FROM "
                      + schemaNameAndTablePrefix
                      + "Grant_ResCrPerm_PostCr_Sys WHERE AccessedDomainId IN ( "
                      + withClause + " "
                      + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
                      + "SELECT DomainId FROM S )"
                : withClause + " "
                      + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
                      + "DELETE FROM "
                      + schemaNameAndTablePrefix
                      + "Grant_ResCrPerm_PostCr_Sys WHERE AccessedDomainId IN ( SELECT DomainId FROM S )"
              : null;

      // GrantResourceCreatePermissionPostCreate - common
      SQL_findInGrantResourceCreatePermissionPostCreate_withoutInheritance_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "SELECT B.PermissionName PostCreatePermissionName, A.PostCreateIsWithGrant, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = A.ResourceClassId AND B.PermissionId = A.PostCreatePermissionId "
            + "WHERE A.AccessorResourceId = ? AND A.AccessedDomainId = ? AND A.ResourceClassId = ?";

      SQL_findInGrantResourceCreatePermissionPostCreate_withoutInheritance_ResourceDomainName_ResourceClassName_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID
            = "SELECT D.DomainName, C.ResourceClassName, B.PermissionName PostCreatePermissionName, A.PostCreateIsWithGrant, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = A.ResourceClassId AND B.PermissionId = A.PostCreatePermissionId JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass C ON C.ResourceClassId = A.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain D ON D.DomainId = A.AccessedDomainId "
            + "WHERE A.AccessorResourceId = ?";

      SQL_createInGrantResourceCreatePermissionPostCreate_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_PostCreateIsWithGrant_ResourceClassID_PostCreatePermissionName
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr ( AccessorResourceId, GrantorResourceId, AccessedDomainId, IsWithGrant, PostCreateIsWithGrant, ResourceClassId, PostCreatePermissionId ) "
            + "SELECT ?, ?, ?, ?, ?, A.ResourceClassId, A.PermissionId FROM "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission A WHERE A.ResourceClassId = ? AND A.PermissionName = ?";

      SQL_updateInGrantResourceCreatePermissionPostCreate_SET_GrantorID_IsWithGrant_PostCreateIsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID_PostCreatePermissionName
            = "UPDATE "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr SET GrantorResourceId = ?, IsWithGrant = ?, PostCreateIsWithGrant = ? "
            + "WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ? AND PostCreatePermissionId = ( "
            + "SELECT A.PermissionId FROM "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission A WHERE A.ResourceClassId = ResourceClassId AND A.PermissionName = ? )";

      SQL_removeInGrantResourceCreatePermissionPostCreate_BY_AccessorID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr WHERE AccessorResourceId = ?";

      SQL_removeInGrantResourceCreatePermissionPostCreate_BY_AccessedDomainId
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr WHERE AccessedDomainId = ?";

      SQL_removeInGrantResourceCreatePermissionPostCreate_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ?";

      SQL_removeInGrantResourceCreatePermissionPostCreate_BY_AccessorID_AccessedDomainID_ResourceClassID_PostCreatePermissionName
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ? AND PostCreatePermissionId = ( "
            + "SELECT A.PermissionId FROM "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission A WHERE A.ResourceClassId = ResourceClassId AND A.PermissionName = ? )";

      // GrantResourceCreatePermissionPostCreate - recursive
      SQL_findInGrantResourceCreatePermissionPostCreate_ResourceClassName_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + SQL_findAncestorsRecursiveInDomain_DomainID_BY_DomainID
            + "SELECT C.ResourceClassName, B.PermissionName PostCreatePermissionName, A.PostCreateIsWithGrant, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = A.ResourceClassId AND B.PermissionId = A.PostCreatePermissionId JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass C ON C.ResourceClassId = A.ResourceClassId "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "JOIN R ON R.DomainId = A.AccessedDomainId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantResourceCreatePermissionPostCreate_ResourceDomainName_ResourceClassName_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + ", P( AccessedDomainId, ResourceClassId, PostCreatePermissionId, PostCreateIsWithGrant, IsWithGrant ) AS "
            + "( SELECT A.AccessedDomainId, A.ResourceClassId, A.PostCreatePermissionId, A.PostCreateIsWithGrant, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + unionClause + " "
            + "SELECT Pplus1.DomainId, P.ResourceClassId, P.PostCreatePermissionId, P.PostCreateIsWithGrant, P.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Domain Pplus1, P "
            + "WHERE Pplus1.ParentDomainId IS NOT NULL AND Pplus1.ParentDomainId = P.AccessedDomainId ) "
            + "SELECT D.DomainName, C.ResourceClassName, B.PermissionName PostCreatePermissionName, P.PostCreateIsWithGrant, P.IsWithGrant FROM P JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = P.ResourceClassId AND B.PermissionId = P.PostCreatePermissionId JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass C ON C.ResourceClassId = P.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain D ON D.DomainId = P.AccessedDomainId";

      SQL_removeInGrantResourceCreatePermissionPostCreate_withDescendants_BY_AccessedDomainId
            = sqlProfile.isRecursiveDeleteEnabled()
              ? (SQLDialect.Oracle_11_2.equals(sqlProfile.getSqlDialect()))
                ? "DELETE FROM "
                      + schemaNameAndTablePrefix
                      + "Grant_ResCrPerm_PostCr WHERE AccessedDomainId IN ( "
                      + withClause + " "
                      + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
                      + "SELECT DomainId FROM S )"
                : withClause + " "
                      + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
                      + "DELETE FROM "
                      + schemaNameAndTablePrefix
                      + "Grant_ResCrPerm_PostCr WHERE AccessedDomainId IN ( SELECT DomainId FROM S )"
              : null;

      // GrantResourcePermissionSys - common
      SQL_findInGrantResourcePermissionSys_withoutInheritance_ResourceClassName_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedID
            = "SELECT B.ResourceClassName, A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass B ON B.ResourceClassId = A.ResourceClassId "
            + "WHERE A.AccessorResourceId = ? AND A.AccessedResourceId = ?";

      SQL_createInGrantResourcePermissionSys_WITH_AccessorID_GrantorID_AccessedID_IsWithGrant_ResourceClassID_SysPermissionID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys ( AccessorResourceId, GrantorResourceId, AccessedResourceId, IsWithGrant, ResourceClassId, SysPermissionId ) "
            + "VALUES ( ?, ?, ?, ?, ?, ? )";

      SQL_updateInGrantResourcePermissionSys_SET_GrantorID_IsWithGrant_BY_AccessorID_AccessedID_ResourceClassID_SysPermissionID
            = "UPDATE "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys SET GrantorResourceId = ?, IsWithGrant = ? "
            + "WHERE AccessorResourceId = ? AND AccessedResourceId = ? AND ResourceClassId = ? AND SysPermissionId = ?";

      SQL_removeInGrantResourcePermissionSys_BY_AccessorID_OR_AccessedID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys WHERE AccessorResourceId = ? OR AccessedResourceId = ?";

      SQL_removeInGrantResourcePermissionSys_BY_AccessorID_AccessedID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys WHERE AccessorResourceId = ? AND AccessedResourceId = ?";

      SQL_removeInGrantResourcePermissionSys_BY_AccessorID_AccessedID_ResourceClassID_SysPermissionID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys WHERE AccessorResourceId = ? AND AccessedResourceId = ? AND ResourceClassId = ? AND SysPermissionId = ?";

      // GrantResourcePermissionSys - recursive
      SQL_findInGrantResourcePermissionSys_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + "SELECT B.AccessedResourceId ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys B "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = B.AccessedResourceId "
            + "WHERE B.ResourceClassId = ? AND B.SysPermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) )";

      SQL_findInGrantResourcePermissionSys_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + ", " + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
            + "SELECT B.AccessedResourceId ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys B JOIN "
            + schemaNameAndTablePrefix
            + "Resource C ON C.ResourceId = B.AccessedResourceId "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId "
            + "JOIN S ON S.DomainId = C.DomainId LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = B.AccessedResourceId "
            + "WHERE B.ResourceClassId = ? AND B.SysPermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) )";

      SQL_findInGrantResourcePermissionSys_ResourceClassName_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + "SELECT B.ResourceClassName, A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass B ON B.ResourceClassId = A.ResourceClassId "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "WHERE A.AccessedResourceId = ?";

      // GrantResourcePermissionSys - non-recursive
      SQL_findInGrantResourcePermissionSys_directInheritance_ResourceID_BY_AccessorID
            = "SELECT AccessedResourceId ResourceId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys "
            + "WHERE AccessorResourceId = ? AND SysPermissionId = "
            + ResourcePermission_INHERIT.getSystemPermissionId();

      SQL_findInGrantResourcePermissionSys_withoutInheritance_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant
            = "SELECT B.AccessedResourceId ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys B LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = B.AccessedResourceId "
            + "WHERE B.AccessorResourceId = ? AND B.ResourceClassId = ? AND B.SysPermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) )";

      SQL_findInGrantResourcePermissionSys_withoutInheritance_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant
            = "SELECT B.AccessedResourceId ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys B JOIN "
            + schemaNameAndTablePrefix
            + "Resource C ON C.ResourceId = B.AccessedResourceId LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = B.AccessedResourceId "
            + "WHERE B.AccessorResourceId = ? AND C.DomainId = ? AND B.ResourceClassId = ? AND B.SysPermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) )";

      // GrantResourcePermission - common
      SQL_findInGrantResourcePermission_ResourceID_ExternalID_BY_AccessedID_ResourceClassID_PermissionID_IsWithGrant
            = "SELECT A.AccessorResourceId ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm A LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = A.AccessorResourceId "
            + "WHERE A.AccessedResourceId = ? AND A.ResourceClassId = ? AND A.PermissionId = ? AND ( ? IN ( 0, A.IsWithGrant ) )";

      SQL_findInGrantResourcePermission_withoutInheritance_ResourceClassName_PermissionName_IsWithGrant_BY_AccessorID_AccessedID
            = "SELECT C.ResourceClassName, B.PermissionName, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = A.ResourceClassId AND B.PermissionId = A.PermissionId JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass C ON C.ResourceClassId = A.ResourceClassId "
            + "WHERE A.AccessorResourceId = ? AND A.AccessedResourceId = ?";

      SQL_createInGrantResourcePermission_WITH_AccessorID_GrantorID_AccessedID_IsWithGrant_ResourceClassID_PermissionName
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm ( AccessorResourceId, GrantorResourceId, AccessedResourceId, IsWithGrant, ResourceClassId, PermissionId ) "
            + "SELECT ?, ?, ?, ?, A.ResourceClassId, A.PermissionId FROM "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission A WHERE A.ResourceClassId = ? AND A.PermissionName = ?";

      SQL_updateInGrantResourcePermission_SET_GrantorID_IsWithGrant_BY_AccessorID_AccessedID_ResourceClassID_PermissionName
            = "UPDATE "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm SET GrantorResourceId = ?, IsWithGrant = ? "
            + "WHERE AccessorResourceId = ? AND AccessedResourceId = ? AND ResourceClassId = ? AND PermissionId = ( "
            + "SELECT A.PermissionId FROM "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission A WHERE A.ResourceClassId = ResourceClassId AND A.PermissionName = ? )";

      SQL_removeInGrantResourcePermission_BY_AccessorID_OR_AccessedID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm WHERE AccessorResourceId = ? OR AccessedResourceId = ?";

      SQL_removeInGrantResourcePermission_BY_AccessorID_AccessedID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm WHERE AccessorResourceId = ? AND AccessedResourceId = ?";

      SQL_removeInGrantResourcePermission_BY_AccessorID_AccessedID_ResourceClassID_PermissionName
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm WHERE AccessorResourceId = ? AND AccessedResourceId = ? AND ResourceClassId = ? AND PermissionId = ( "
            + "SELECT A.PermissionId FROM "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission A WHERE A.ResourceClassId = ResourceClassId AND A.PermissionName = ? )";

      // GrantResourcePermission - recursive
      SQL_findInGrantResourcePermission_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_PermissionID_IsWithGrant
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + "SELECT B.AccessedResourceId ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm B "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = B.AccessedResourceId "
            + "WHERE B.ResourceClassId = ? AND B.PermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) )";

      SQL_findInGrantResourcePermission_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_PermissionID_IsWithGrant
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + ", " + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
            + "SELECT B.AccessedResourceId ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm B JOIN "
            + schemaNameAndTablePrefix
            + "Resource C ON C.ResourceId = B.AccessedResourceId "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId "
            + "JOIN S ON S.DomainId = C.DomainId LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = B.AccessedResourceId "
            + "WHERE B.ResourceClassId = ? AND B.PermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) )";

      SQL_findInGrantResourcePermission_ResourceClassName_PermissionName_IsWithGrant_BY_AccessorID_AccessedID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + "SELECT C.ResourceClassName, B.PermissionName, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = A.ResourceClassId AND B.PermissionId = A.PermissionId JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass C ON C.ResourceClassId = A.ResourceClassId "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "WHERE A.AccessedResourceId = ?";

      // GrantResourcePermission - non-recursive
      SQL_findInGrantResourcePermission_withoutInheritance_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_PermissionID_IsWithGrant
            = "SELECT A.AccessedResourceId ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm A LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = A.AccessedResourceId "
            + "WHERE A.AccessorResourceId = ? AND A.ResourceClassId = ? AND A.PermissionId = ? AND ( ? IN ( 0, A.IsWithGrant ) )";

      SQL_findInGrantResourcePermission_withoutInheritance_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_PermissionID_IsWithGrant
            = "SELECT A.AccessedResourceId ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm A JOIN "
            + schemaNameAndTablePrefix
            + "Resource B ON A.AccessedResourceId=B.ResourceId LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = A.AccessedResourceId "
            + "WHERE A.AccessorResourceId = ? AND B.DomainId = ? AND A.ResourceClassId = ? AND A.PermissionId = ? AND ( ? IN ( 0, A.IsWithGrant ) )";

      // GrantGlobalResourcePermissionSys - common
      SQL_findInGrantGlobalResourcePermissionSys_withoutInheritance_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "SELECT A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys A "
            + "WHERE A.AccessorResourceId = ? AND A.AccessedDomainId = ? AND A.ResourceClassId = ?";

      SQL_findInGrantGlobalResourcePermissionSys_withoutInheritance_ResourceDomainName_ResourceClassName_SysPermissionID_IsWithGrant_BY_AccessorID
            = "SELECT C.DomainName, B.ResourceClassName, A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass B ON B.ResourceClassId = A.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain C ON C.DomainId = A.AccessedDomainId "
            + "WHERE A.AccessorResourceId = ?";

      SQL_createInGrantGlobalResourcePermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_SysPermissionID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys ( AccessorResourceId, GrantorResourceId, AccessedDomainId, IsWithGrant, ResourceClassId, SysPermissionId ) "
            + "VALUES ( ?, ?, ?, ?, ?, ? )";

      SQL_updateInGrantGlobalResourcePermissionSys_SET_GrantorID_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID_SysPermissionID
            = "UPDATE "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys SET GrantorResourceId = ?, IsWithGrant = ? "
            + "WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ? AND SysPermissionId = ?";

      SQL_removeInGrantGlobalResourcePermissionSys_BY_AccessorID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys WHERE AccessorResourceId = ?";

      SQL_removeInGrantGlobalResourcePermissionSys_BY_AccessedDomainId
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys WHERE AccessedDomainId = ?";

      SQL_removeInGrantGlobalResourcePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ?";

      SQL_removeInGrantGlobalResourcePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID_SysPermissionID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ? AND SysPermissionId = ?";

      // GrantGlobalResourcePermissionSys - recursive
      SQL_findInGrantGlobalResourcePermissionSys_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + ", R( DomainId ) AS "
            // this sub query is the starting set for the domain recursion, it returns all the direct
            // resources domains that the accessor has the specified system permission on
            + "( SELECT B.AccessedDomainId FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys B "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId "
            + "WHERE B.ResourceClassId = ? AND B.SysPermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) ) "
            // now we find the nested domains that the accessor can reach from the direct set above
            + unionClause + " SELECT Rplus1.DomainId FROM "
            + schemaNameAndTablePrefix
            + "Domain Rplus1, R "
            + "WHERE Rplus1.ParentDomainId IS NOT NULL AND Rplus1.ParentDomainId = R.DomainId ) "
            // finally we get the resources of the specified type in the domains we computed above
            + "SELECT A.ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Resource A "
            + "JOIN R ON R.DomainId = A.DomainId LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = A.ResourceId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantGlobalResourcePermissionSys_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + ", " + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
            + ", R( DomainId ) AS "
            // this sub query is the starting set for the domain recursion, it returns all the direct
            // resources domains that the accessor has the specified system permission on
            + "( SELECT B.AccessedDomainId FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys B "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId "
            + "WHERE B.ResourceClassId = ? AND B.SysPermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) ) "
            // now we find the nested domains that the accessor can reach from the direct set above
            + unionClause + " SELECT Rplus1.DomainId FROM "
            + schemaNameAndTablePrefix
            + "Domain Rplus1, R "
            + "WHERE Rplus1.ParentDomainId IS NOT NULL AND Rplus1.ParentDomainId = R.DomainId ) "
            // finally we get the resources of the specified type in the domains we computed above
            + "SELECT A.ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Resource A "
            + "JOIN R ON R.DomainId = A.DomainId "
            + "JOIN S ON S.DomainId = A.DomainId LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = A.ResourceId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantGlobalResourcePermissionSys_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + SQL_findAncestorsRecursiveInDomain_DomainID_BY_DomainID
            + "SELECT A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "JOIN R ON R.DomainId = A.AccessedDomainId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantGlobalResourcePermissionSys_ResourceDomainName_ResourceClassName_SysPermissionID_IsWithGrant_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + ", P( AccessedDomainId, ResourceClassId, SysPermissionId, IsWithGrant ) AS "
            + "( SELECT A.AccessedDomainId, A.ResourceClassId, A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + unionClause + " "
            + "SELECT Pplus1.DomainId, P.ResourceClassId, P.SysPermissionId, P.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Domain Pplus1, P "
            + "WHERE Pplus1.ParentDomainId IS NOT NULL AND Pplus1.ParentDomainId = P.AccessedDomainId ) "
            + "SELECT C.DomainName, B.ResourceClassName, P.SysPermissionId, P.IsWithGrant FROM P JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass B ON B.ResourceClassId = P.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain C ON C.DomainId = P.AccessedDomainId";

      SQL_removeInGrantGlobalResourcePermissionSys_withDescendants_BY_AccessedDomainId
            = sqlProfile.isRecursiveDeleteEnabled()
              ? (SQLDialect.Oracle_11_2.equals(sqlProfile.getSqlDialect()))
                ? "DELETE FROM "
                      + schemaNameAndTablePrefix
                      + "Grant_Global_ResPerm_Sys WHERE AccessedDomainId IN ( "
                      + withClause + " "
                      + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
                      + "SELECT DomainId FROM S )"
                : withClause + " "
                      + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
                      + "DELETE FROM "
                      + schemaNameAndTablePrefix
                      + "Grant_Global_ResPerm_Sys WHERE AccessedDomainId IN ( SELECT DomainId FROM S )"
              : null;

      // GrantGlobalResourcePermissionSys - non-recursive
      SQL_findInGrantGlobalResourcePermissionSys_withoutInheritance_ResourceDomainID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant
            = "SELECT AccessedDomainId DomainId FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys "
            + "WHERE AccessorResourceId = ? AND ResourceClassId = ? AND SysPermissionId = ? AND ( ? IN ( 0, IsWithGrant ) )";

      // GrantGlobalResourcePermission - common
      SQL_findInGrantGlobalResourcePermission_withoutInheritance_PermissionName_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "SELECT B.PermissionName, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = A.ResourceClassId AND B.PermissionId = A.PermissionId "
            + "WHERE A.AccessorResourceId = ? AND A.AccessedDomainId = ? AND A.ResourceClassId = ?";

      SQL_findInGrantGlobalResourcePermission_withoutInheritance_ResourceDomainName_ResourceClassName_PermissionName_IsWithGrant_BY_AccessorID
            = "SELECT D.DomainName, C.ResourceClassName, B.PermissionName, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = A.ResourceClassId AND B.PermissionId = A.PermissionId JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass C ON C.ResourceClassId = A.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain D ON D.DomainId = A.AccessedDomainId "
            + "WHERE A.AccessorResourceId = ?";

      SQL_createInGrantGlobalResourcePermission_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_PermissionName
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm ( AccessorResourceId, GrantorResourceId, AccessedDomainId, IsWithGrant, ResourceClassId, PermissionId ) "
            + "SELECT ?, ?, ?, ?, A.ResourceClassId, A.PermissionId FROM "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission A WHERE A.ResourceClassId = ? AND A.PermissionName = ?";

      SQL_updateInGrantGlobalResourcePermission_SET_GrantorID_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID_PermissionName
            = "UPDATE "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm SET GrantorResourceId = ?, IsWithGrant = ? "
            + "WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ? AND PermissionId = ( "
            + "SELECT A.PermissionId FROM "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission A WHERE A.ResourceClassId = ResourceClassId AND A.PermissionName = ? )";

      SQL_removeInGrantGlobalResourcePermission_BY_AccessorID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm WHERE AccessorResourceId = ?";

      SQL_removeInGrantGlobalResourcePermission_BY_AccessedDomainId
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm WHERE AccessedDomainId = ?";

      SQL_removeInGrantGlobalResourcePermission_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ?";

      SQL_removeInGrantGlobalResourcePermission_BY_AccessorID_AccessedDomainID_ResourceClassID_PermissionName
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ? AND PermissionId = ( "
            + "SELECT A.PermissionId FROM "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission A WHERE A.ResourceClassId = ResourceClassId AND A.PermissionName = ? )";

      // GrantGlobalResourcePermission - recursive
      SQL_findInGrantGlobalResourcePermission_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_PermissionID_IsWithGrant_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + ", R( DomainId ) AS "
            // this sub query is the starting set for the domain recursion, it returns all the direct
            // resources domains that the accessor has the specified system permission on
            + "( SELECT B.AccessedDomainId FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm B "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId "
            + "WHERE B.ResourceClassId = ? AND B.PermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) ) "
            // now we find the nested domains that the accessor can reach from the direct set above
            + unionClause + " SELECT Rplus1.DomainId FROM "
            + schemaNameAndTablePrefix
            + "Domain Rplus1, R "
            + "WHERE Rplus1.ParentDomainId IS NOT NULL AND Rplus1.ParentDomainId = R.DomainId ) "
            // finally we get the resources of the specified type in the domains we computed above
            + "SELECT A.ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Resource A "
            + "JOIN R ON R.DomainId = A.DomainId LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = A.ResourceId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantGlobalResourcePermission_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_PermissionID_IsWithGrant_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + ", " + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
            + ", R( DomainId ) AS "
            // this sub query is the starting set for the domain recursion, it returns all the direct
            // resources domains that the accessor has the specified system permission on
            + "( SELECT B.AccessedDomainId FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm B "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId "
            + "WHERE B.ResourceClassId = ? AND B.PermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) ) "
            // now we find the nested domains that the accessor can reach from the direct set above
            + unionClause + " SELECT Rplus1.DomainId FROM "
            + schemaNameAndTablePrefix
            + "Domain Rplus1, R "
            + "WHERE Rplus1.ParentDomainId IS NOT NULL AND Rplus1.ParentDomainId = R.DomainId ) "
            // finally we get the resources of the specified type in the domains we computed above
            + "SELECT A.ResourceId, E.ExternalId FROM "
            + schemaNameAndTablePrefix
            + "Resource A "
            + "JOIN R ON R.DomainId = A.DomainId "
            + "JOIN S ON S.DomainId = A.DomainId LEFT JOIN "
            + schemaNameAndTablePrefix
            + "ResourceExternalID E ON E.ResourceId = A.ResourceId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantGlobalResourcePermission_PermissionName_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + SQL_findAncestorsRecursiveInDomain_DomainID_BY_DomainID
            + "SELECT B.PermissionName, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = A.ResourceClassId AND B.PermissionId = A.PermissionId "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "JOIN R ON R.DomainId = A.AccessedDomainId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantGlobalResourcePermission_ResourceDomainName_ResourceClassName_PermissionName_IsWithGrant_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_BY_AccessorID
            + ", P( AccessedDomainId, ResourceClassId, PermissionId, IsWithGrant ) AS "
            + "( SELECT A.AccessedDomainId, A.ResourceClassId, A.PermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + unionClause + " "
            + "SELECT Pplus1.DomainId, P.ResourceClassId, P.PermissionId, P.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Domain Pplus1, P "
            + "WHERE Pplus1.ParentDomainId IS NOT NULL AND Pplus1.ParentDomainId = P.AccessedDomainId ) "
            + "SELECT D.DomainName, C.ResourceClassName, B.PermissionName, P.IsWithGrant FROM P JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = P.ResourceClassId AND B.PermissionId = P.PermissionId JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass C ON C.ResourceClassId = P.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain D ON D.DomainId = P.AccessedDomainId";

      SQL_removeInGrantGlobalResourcePermission_withDescendants_BY_AccessedDomainId
            = sqlProfile.isRecursiveDeleteEnabled()
              ? (SQLDialect.Oracle_11_2.equals(sqlProfile.getSqlDialect()))
                ? "DELETE FROM "
                      + schemaNameAndTablePrefix
                      + "Grant_Global_ResPerm WHERE AccessedDomainId IN ( "
                      + withClause + " "
                      + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
                      + "SELECT DomainId FROM S )"
                : withClause + " "
                      + SQL_findDescendantsRecursiveInDomain_DomainID_BY_DomainID
                      + "DELETE FROM "
                      + schemaNameAndTablePrefix
                      + "Grant_Global_ResPerm WHERE AccessedDomainId IN ( SELECT DomainId FROM S )"
              : null;

      // GrantGlobalResourcePermission - non-recursive
      SQL_findInGrantGlobalResourcePermission_withoutInheritance_ResourceDomainID_BY_AccessorID_ResourceClassID_PermissionID_IsWithGrant
            = "SELECT AccessedDomainId DomainId FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm "
            + "WHERE AccessorResourceId = ? AND ResourceClassId = ? AND PermissionId = ? AND ( ? IN ( 0, IsWithGrant ) )";

      // Key generators
      SQL_nextResourceID
            = dialectSpecificSQLGenerator.nextSequenceValueStatement(schemaNameAndTablePrefix + "ResourceId");
   }

   public SQLProfile getSqlProfile() {
      return sqlProfile;
   }

   public SQLDialect getSqlDialect() {
      return sqlProfile.getSqlDialect();
   }
}
