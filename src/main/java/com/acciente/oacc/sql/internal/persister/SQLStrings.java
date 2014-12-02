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
package com.acciente.oacc.sql.internal.persister;

import com.acciente.oacc.AccessControlException;
import com.acciente.oacc.ResourcePermission;
import com.acciente.oacc.sql.SQLDialect;

import java.io.Serializable;

public class SQLStrings implements Serializable {
   // SQL string constants

   // ResourceClass
   public final String SQL_findInResourceClass_ResourceClassID_BY_ResourceClassName;
   public final String SQL_findInResourceClass_ResourceClassID_ResourceClassName_IsAuthenticatable_IsUnauthenticatedCreateAllowed_BY_ResourceClassName;
   public final String SQL_findInResourceClass_ResourceClassID_ResourceClassName_IsAuthenticatable_IsUnauthenticatedCreateAllowed_BY_ResourceID;
   public final String SQL_findInResourceClass_ResourceClassName_BY_ALL;
   public final String SQL_createInResourceClass_WITH_ResourceClassName_IsAuthenticatable_IsUnauthenticatedCreateAllowed;
   // ResourceClassPermission
   public final String SQL_findInResourceClassPermission_PermissionID_BY_ResourceClassID_PermissionName;
   public final String SQL_findInResourceClassPermission_PermissionName_BY_ResourceClassName;
   public final String SQL_createInResourceClassPermission_WITH_ResourceClassID_PermissionName;

   // Domain
   public final String SQL_findInDomain_DomainID_BY_ResourceDomainName;
   public final String SQL_findInDomain_ResourceDomainName_BY_ResourceID;
   public final String SQL_findInDomain_DescendantResourceDomainName_BY_ResourceDomainName;
   public final String SQL_createInDomain_WITH_ResourceDomainName;
   public final String SQL_createInDomain_WITH_ResourceDomainName_ParentDomainID;

   // GrantDomainCreatePermissionSys
   public final String SQL_findInGrantDomainCreatePermissionSys_SysPermissionID_IsWithGrant_InheritLevel_BY_AccessorID;
   public final String SQL_removeInGrantDomainCreatePermissionSys_BY_AccessorID;
   public final String SQL_createInGrantDomainCreatePermissionSys_WITH_AccessorID_GrantorID_IsWithGrant_SysPermissionID;
   // GrantDomainCreatePermissionPostCreateSys
   public final String SQL_findInGrantDomainCreatePermissionPostCreateSys_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_InheritLevel_BY_AccessorID;
   public final String SQL_removeInGrantDomainCreatePermissionPostCreateSys_BY_AccessorID;
   public final String SQL_createInGrantDomainCreatePermissionPostCreateSys_WITH_AccessorID_GrantorID_IsWithGrant_PostCreateIsWithGrant_PostCreateSysPermissionID;

   // GrantDomainPermissionSys
   public final String SQL_findInGrantDomainPermissionSys_SysPermissionID_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_DomainID;
   public final String SQL_findInGrantDomainPermissionSys_ResourceDomainName_SysPermissionID_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID;
   public final String SQL_createInGrantDomainPermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_SysPermissionID;
   public final String SQL_removeInGrantDomainPermissionSys_BY_AccessorID_AccessedDomainID;

   // GrantResourcePermissionSys
   public final String SQL_findInGrantResourcePermissionSys_ResourceID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant;
   public final String SQL_findInGrantResourcePermissionSys_ResourceID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant;

   // GrantGlobalResourcePermissionSys
   public final String SQL_findInGrantGlobalResourcePermissionSys_ResourceID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant;
   public final String SQL_findInGrantGlobalResourcePermissionSys_ResourceID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant;

   // GrantResourcePermission
   public final String SQL_findInGrantResourcePermission_ResourceID_BY_AccessorID_ResourceClassID_PermissionID_IsWithGrant;
   public final String SQL_findInGrantResourcePermission_ResourceID_BY_AccessorID_DomainID_ResourceClassID_PermissionID_IsWithGrant;

   // GrantGlobalResourcePermission
   public final String SQL_findInGrantGlobalResourcePermission_ResourceID_BY_AccessorID_ResourceClassID_PermissionID_IsWithGrant_ResourceClassID;
   public final String SQL_findInGrantGlobalResourcePermission_ResourceID_BY_AccessorID_DomainID_ResourceClassID_PermissionID_IsWithGrant_ResourceClassID;

   // GrantDomainPermissionSys
   public final String SQL_findInGrantDomainPermissionSys_ResourceID_BY_AccessorID_SysPermissionID_IsWithGrant_ResourceClassID;
   public final String SQL_findInGrantDomainPermissionSys_ResourceID_BY_AccessorID_DomainID_SysPermissionID_IsWithGrant_ResourceClassID;

   // GrantResourcePermissionSys
   public final String SQL_findInGrantResourcePermissionSys_ResourceID_BY_AccessedID_ResourceClassID_SysPermissionID_IsWithGrant;

   // GrantResourcePermission
   public final String SQL_findInGrantResourcePermission_ResourceID_BY_AccessedID_ResourceClassID_PermissionID_IsWithGrant;

   // Resource
   public final String SQL_findInResource_COUNTResourceID_BY_ResourceClassID_DomainID;
   public final String SQL_createInResource_WITH_ResourceID_ResourceClassID_DomainID;
   public final String SQL_findInResource_ResourceId_BY_ResourceID;
   public final String SQL_findInResource_DomainID_BY_ResourceID;

   // GrantResourceCreatePermissionSys
   public final String SQL_findInGrantResourceCreatePermissionSys_SysPermissionId_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantResourceCreatePermissionSys_withoutInheritance_SysPermissionId_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantResourceCreatePermissionSys_ResourceDomainName_ResourceClassName_SysPermissionId_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID;
   public final String SQL_createInGrantResourceCreatePermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_SysPermissionId;
   public final String SQL_removeInGrantResourceCreatePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID;
   // GrantResourceCreatePermissionPostCreateSys
   public final String SQL_findInGrantResourceCreatePermissionPostCreateSys_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantResourceCreatePermissionPostCreateSys_withoutInheritance_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantResourceCreatePermissionPostCreateSys_ResourceDomainName_ResourceClassName_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID;
   public final String SQL_createInGrantResourceCreatePermissionPostCreateSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_PostCreateIsWithGrant_ResourceClassID_PostCreateSysPermissionID;
   public final String SQL_removeInGrantResourceCreatePermissionPostCreateSys_BY_AccessorID_AccessedDomainID_ResourceClassID;
   // GrantResourceCreatePermissionPostCreate
   public final String SQL_findInGrantResourceCreatePermissionPostCreate_ResourceClassName_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantResourceCreatePermissionPostCreate_withoutInheritance_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantResourceCreatePermissionPostCreate_ResourceDomainName_ResourceClassName_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID;
   public final String SQL_createInGrantResourceCreatePermissionPostCreate_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_PostCreateIsWithGrant_ResourceClassID_PostCreatePermissionName;
   public final String SQL_removeInGrantResourceCreatePermissionPostCreate_BY_AccessorID_AccessedDomainID_ResourceClassID;

   // GrantResourcePermissionSys
   public final String SQL_findInGrantResourcePermissionSys_ResourceClassName_SysPermissionID_IsWithGrant_InheritLevel_BY_AccessorID_AccessedID;
   public final String SQL_findInGrantResourcePermissionSys_withoutInheritance_ResourceClassName_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedID;
   public final String SQL_createInGrantResourcePermissionSys_WITH_AccessorID_GrantorID_AccessedID_IsWithGrant_ResourceClassID_SysPermissionID;
   public final String SQL_removeInGrantResourcePermissionSys_BY_AccessorID_AccessedID;
   // GrantResourcePermission
   public final String SQL_findInGrantResourcePermission_ResourceClassName_PermissionName_IsWithGrant_InheritLevel_BY_AccessorID_AccessedID;
   public final String SQL_findInGrantResourcePermission_withoutInheritance_ResourceClassName_PermissionName_IsWithGrant_BY_AccessorID_AccessedID;
   public final String SQL_createInGrantResourcePermission_WITH_AccessorID_GrantorID_AccessedID_IsWithGrant_ResourceClassID_PermissionName;
   public final String SQL_removeInGrantResourcePermission_BY_AccessorID_AccessedID;

   // GrantGlobalResourcePermissionSys
   public final String SQL_findInGrantGlobalResourcePermissionSys_SysPermissionID_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantGlobalResourcePermissionSys_withoutInheritance_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantGlobalResourcePermissionSys_ResourceDomainName_ResourceClassName_SysPermissionID_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID;
   public final String SQL_createInGrantGlobalResourcePermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_SysPermissionID;
   public final String SQL_removeInGrantGlobalResourcePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID;
   // GrantGlobalResourcePermission
   public final String SQL_findInGrantGlobalResourcePermission_PermissionName_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantGlobalResourcePermission_withoutInheritance_PermissionName_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID;
   public final String SQL_findInGrantGlobalResourcePermission_ResourceDomainName_ResourceClassName_PermissionName_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID;
   public final String SQL_createInGrantGlobalResourcePermission_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_PermissionName;
   public final String SQL_removeInGrantGlobalResourcePermission_BY_AccessorID_AccessedDomainID_ResourceClassID;

   // Key generators
   public final String SQL_nextResourceID;

   // resource permissions constants
   private static final ResourcePermission ResourcePermission_INHERIT = ResourcePermission.getInstance(
         ResourcePermission.INHERIT,
         false);

   public static SQLStrings getSQLStrings(String schemaName, SQLDialect sqlDialect) throws AccessControlException {
      return new SQLStrings(schemaName, DialectSpecificSQLGenerator.getInstance(sqlDialect));
   }

   private SQLStrings(String schemaName, DialectSpecificSQLGenerator dialectSpecificSQLGenerator) {
      final String withClause = dialectSpecificSQLGenerator.getWithClause();
      final String unionClause = dialectSpecificSQLGenerator.getUnionClause();
      final String schemaNameAndTablePrefix = schemaName != null ? schemaName + ".OAC_" : "OAC_";
      // recursive query to compute all the resource ids that a given accessor is equivalent to as a
      // result of having the INHERIT permission
      final String SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            = withClause + " N( AccessorResourceId, InheritLevel ) AS "
            + "( SELECT ResourceId, 0 FROM "
            + schemaNameAndTablePrefix
            + "Resource WHERE ResourceId = ? " + unionClause + " SELECT Nplus1.AccessedResourceId, N.InheritLevel + 1 FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys Nplus1, N "
            + "WHERE Nplus1.AccessorResourceId = N.AccessorResourceId AND Nplus1.SysPermissionId = "
            + ResourcePermission_INHERIT.getSystemPermissionId()
            + " ) ";

      // recursive query to compute all ancestors of a given an domain
      final String SQL_findAncestorsRecursiveInDomain_DomainID_DomainLevel_BY_DomainID
            = ", R( DomainId, ParentDomainId, DomainLevel ) AS "
            + "( SELECT DomainId, ParentDomainId, 0 FROM "
            + schemaNameAndTablePrefix
            + "Domain WHERE DomainId = ? " + unionClause + " SELECT Rplus1.DomainId, Rplus1.ParentDomainId, R.DomainLevel + 1 FROM "
            + schemaNameAndTablePrefix
            + "Domain Rplus1, R "
            + "WHERE R.ParentDomainId IS NOT NULL AND Rplus1.DomainId = R.ParentDomainId ) ";

      // recursive query to compute all descendants of a given an domain
      final String SQL_findDescendantsRecursiveInDomain_DomainID_DomainLevel_BY_DomainID
            = ", S( DomainId, DomainLevel ) AS "
            + "( SELECT DomainId, 0 FROM "
            + schemaNameAndTablePrefix
            + "Domain WHERE DomainId = ? " + unionClause + " SELECT Splus1.DomainId, S.DomainLevel + 1 FROM "
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
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "ResourceClass ( ResourceClassId, ResourceClassName, IsAuthenticatable, IsUnauthenticatedCreateAllowed ) "
            + "VALUES ( "
            + dialectSpecificSQLGenerator.nextSequenceValueFragment(schemaNameAndTablePrefix + "ResourceClassId")
            + ", ?, ?, ? )";

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
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission ( ResourceClassId, PermissionId, PermissionName ) VALUES ( ?, "
            + dialectSpecificSQLGenerator.nextSequenceValueFragment(schemaNameAndTablePrefix + "PermissionId")
            + ", ? )";

      // Domain
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

      // recursive query to return all descendants domain names of the specified domain names
      SQL_findInDomain_DescendantResourceDomainName_BY_ResourceDomainName
            = withClause + " S( DomainId, DomainName, DomainLevel ) AS "
            + "( SELECT DomainId, DomainName, 0 FROM "
            + schemaNameAndTablePrefix
            + "Domain WHERE DomainName = ? "
            + unionClause + " "
            + "SELECT Splus1.DomainId, Splus1.DomainName, S.DomainLevel + 1 FROM "
            + schemaNameAndTablePrefix
            + "Domain Splus1, S "
            + "WHERE Splus1.ParentDomainId IS NOT NULL AND Splus1.ParentDomainId = S.DomainId ) "
            + "SELECT DomainId, DomainName FROM S";

      SQL_createInDomain_WITH_ResourceDomainName
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Domain ( DomainId, DomainName ) VALUES ( "
            + dialectSpecificSQLGenerator.nextSequenceValueFragment(schemaNameAndTablePrefix + "DomainId")
            + ", ? )";

      SQL_createInDomain_WITH_ResourceDomainName_ParentDomainID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Domain ( DomainId, DomainName, ParentDomainId ) VALUES ( "
            + dialectSpecificSQLGenerator.nextSequenceValueFragment(schemaNameAndTablePrefix + "DomainId")
            + ", ?, ? )";

      // GrantDomainCreatePermissionSys
      SQL_findInGrantDomainCreatePermissionSys_SysPermissionID_IsWithGrant_InheritLevel_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + "SELECT A.SysPermissionId, A.IsWithGrant, N.InheritLevel FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId ";

      SQL_createInGrantDomainCreatePermissionSys_WITH_AccessorID_GrantorID_IsWithGrant_SysPermissionID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_Sys ( AccessorResourceId, GrantorResourceId, IsWithGrant, SysPermissionId ) "
            + "VALUES( ?, ?, ?, ? )";

      SQL_removeInGrantDomainCreatePermissionSys_BY_AccessorID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_Sys WHERE AccessorResourceId = ?";

      // GrantDomainCreatePermissionPostCreateSys
      SQL_findInGrantDomainCreatePermissionPostCreateSys_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_InheritLevel_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + "SELECT A.PostCreateSysPermissionId, A.PostCreateIsWithGrant, A.IsWithGrant, N.InheritLevel FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_PostCr_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId ";

      SQL_createInGrantDomainCreatePermissionPostCreateSys_WITH_AccessorID_GrantorID_IsWithGrant_PostCreateIsWithGrant_PostCreateSysPermissionID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_PostCr_Sys ( AccessorResourceId, GrantorResourceId, IsWithGrant, PostCreateIsWithGrant, PostCreateSysPermissionId ) "
            + "VALUES( ?, ?, ?, ?, ? )";

      SQL_removeInGrantDomainCreatePermissionPostCreateSys_BY_AccessorID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomCrPerm_PostCr_Sys WHERE AccessorResourceId = ?";

      // GrantDomainPermissionSys
      SQL_findInGrantDomainPermissionSys_SysPermissionID_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_DomainID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + SQL_findAncestorsRecursiveInDomain_DomainID_DomainLevel_BY_DomainID
            + "SELECT A.SysPermissionId, A.IsWithGrant, N.InheritLevel, R.DomainLevel FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "JOIN R ON R.DomainId = A.AccessedDomainId ";

      SQL_findInGrantDomainPermissionSys_ResourceDomainName_SysPermissionID_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + ", P( AccessedDomainId, SysPermissionId, IsWithGrant, InheritLevel, DomainLevel ) AS "
            + "( SELECT A.AccessedDomainId, A.SysPermissionId, A.IsWithGrant, N.InheritLevel, 0 FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + unionClause + " "
            + "SELECT Pplus1.DomainId, P.SysPermissionId, P.IsWithGrant, P.InheritLevel, P.DomainLevel + 1 FROM "
            + schemaNameAndTablePrefix
            + "Domain Pplus1, P "
            + "WHERE Pplus1.ParentDomainId IS NOT NULL AND Pplus1.ParentDomainId = P.AccessedDomainId ) "
            + "SELECT B.DomainName, P.SysPermissionId, P.IsWithGrant, P.InheritLevel, P.DomainLevel FROM P JOIN "
            + schemaNameAndTablePrefix
            + "Domain B ON B.DomainId = P.AccessedDomainId";

      SQL_createInGrantDomainPermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_SysPermissionID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys ( AccessorResourceId, GrantorResourceId, AccessedDomainId, IsWithGrant, SysPermissionId ) VALUES ( ?, ?, ?, ?, ? )";

      SQL_removeInGrantDomainPermissionSys_BY_AccessorID_AccessedDomainID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys WHERE AccessorResourceId = ? AND AccessedDomainId = ?";

      // Resource: finder methods used getResourcesByResourcePermission()
      SQL_findInGrantResourcePermissionSys_ResourceID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + "SELECT B.AccessedResourceId ResourceId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys B "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId "
            + "WHERE B.ResourceClassId = ? AND B.SysPermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) )";

      SQL_findInGrantResourcePermissionSys_ResourceID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + SQL_findDescendantsRecursiveInDomain_DomainID_DomainLevel_BY_DomainID
            + "SELECT B.AccessedResourceId ResourceId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys B JOIN "
            + schemaNameAndTablePrefix
            + "Resource C ON C.ResourceId = B.AccessedResourceId "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId "
            + "JOIN S ON S.DomainId = C.DomainId "
            + "WHERE B.ResourceClassId = ? AND B.SysPermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) )";

      SQL_findInGrantGlobalResourcePermissionSys_ResourceID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + "SELECT A.ResourceId FROM "
            + schemaNameAndTablePrefix
            + "Resource A "
            + "WHERE A.DomainId IN "
            + "( SELECT B.AccessedDomainId FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys B "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId "
            + "WHERE B.ResourceClassId = ? AND B.SysPermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) ) )";

      SQL_findInGrantGlobalResourcePermissionSys_ResourceID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + SQL_findDescendantsRecursiveInDomain_DomainID_DomainLevel_BY_DomainID
            + "SELECT A.ResourceId FROM "
            + schemaNameAndTablePrefix
            + "Resource A "
            + "WHERE A.DomainId IN "
            + "( SELECT B.AccessedDomainId FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys B "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId "
            + "JOIN S ON S.DomainId = B.AccessedDomainId "
            + "WHERE B.ResourceClassId = ? AND B.SysPermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) ) )";

      SQL_findInGrantResourcePermission_ResourceID_BY_AccessorID_ResourceClassID_PermissionID_IsWithGrant
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + "SELECT B.AccessedResourceId ResourceId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm B "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId "
            + "WHERE B.ResourceClassId = ? AND B.PermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) )";

      SQL_findInGrantResourcePermission_ResourceID_BY_AccessorID_DomainID_ResourceClassID_PermissionID_IsWithGrant
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + SQL_findDescendantsRecursiveInDomain_DomainID_DomainLevel_BY_DomainID
            + "SELECT B.AccessedResourceId ResourceId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm B JOIN "
            + schemaNameAndTablePrefix
            + "Resource C ON C.ResourceId = B.AccessedResourceId "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId "
            + "JOIN S ON S.DomainId = C.DomainId "
            + "WHERE B.ResourceClassId = ? AND B.PermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) )";

      SQL_findInGrantGlobalResourcePermission_ResourceID_BY_AccessorID_ResourceClassID_PermissionID_IsWithGrant_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + ", R( DomainId, DomainLevel ) AS "
            // this sub query is the starting set for the domain recursion, it returns all the direct
            // resources domains that the accessor has the specified system permission on
            + "( SELECT B.AccessedDomainId, 0 FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm B "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId "
            + "WHERE B.ResourceClassId = ? AND B.PermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) ) "
            // now we find the nested domains that the accessor can reach from the direct set above
            + unionClause + " SELECT Rplus1.DomainId, R.DomainLevel + 1 FROM "
            + schemaNameAndTablePrefix
            + "Domain Rplus1, R "
            + "WHERE Rplus1.ParentDomainId IS NOT NULL AND Rplus1.ParentDomainId = R.DomainId ) "
            // finally we get the resources of the specified type in the domains we computed above
            + "SELECT A.ResourceId FROM "
            + schemaNameAndTablePrefix
            + "Resource A "
            + "JOIN R ON R.DomainId = A.DomainId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantGlobalResourcePermission_ResourceID_BY_AccessorID_DomainID_ResourceClassID_PermissionID_IsWithGrant_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + SQL_findDescendantsRecursiveInDomain_DomainID_DomainLevel_BY_DomainID
            + ", R( DomainId, DomainLevel ) AS "
            // this sub query is the starting set for the domain recursion, it returns all the direct
            // resources domains that the accessor has the specified system permission on
            + "( SELECT B.AccessedDomainId, 0 FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm B "
            + "JOIN N ON N.AccessorResourceId = B.AccessorResourceId "
            + "WHERE B.ResourceClassId = ? AND B.PermissionId = ? AND ( ? IN ( 0, B.IsWithGrant ) ) "
            // now we find the nested domains that the accessor can reach from the direct set above
            + unionClause + " SELECT Rplus1.DomainId, R.DomainLevel + 1 FROM "
            + schemaNameAndTablePrefix
            + "Domain Rplus1, R "
            + "WHERE Rplus1.ParentDomainId IS NOT NULL AND Rplus1.ParentDomainId = R.DomainId ) "
            // finally we get the resources of the specified type in the domains we computed above
            + "SELECT A.ResourceId FROM "
            + schemaNameAndTablePrefix
            + "Resource A "
            + "JOIN R ON R.DomainId = A.DomainId "
            + "JOIN S ON S.DomainId = A.DomainId "
            + "WHERE A.ResourceClassId = ?";

      // query returns the resources that the accessor has access to via super user permission
      SQL_findInGrantDomainPermissionSys_ResourceID_BY_AccessorID_SysPermissionID_IsWithGrant_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + ", R( DomainId, DomainLevel ) AS "
            // this sub query is the starting set for the domain recursion, it returns all the direct
            // resources domains that the accessor has the specified system permission on (currently super-user)
            + "( SELECT AccessedDomainId, 0 FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys G "
            + "JOIN N ON N.AccessorResourceId = G.AccessorResourceId "
            + "WHERE G.SysPermissionId = ? AND ( ? IN ( 0, G.IsWithGrant ) ) "
            // now we find the nested domains that the accessor can reach from the direct set above
            + unionClause + " SELECT Rplus1.DomainId, R.DomainLevel + 1 FROM "
            + schemaNameAndTablePrefix
            + "Domain Rplus1, R "
            + "WHERE Rplus1.ParentDomainId IS NOT NULL AND Rplus1.ParentDomainId = R.DomainId ) "
            // finally we get the resources of the specified type in the domains we computed above
            + "SELECT A.ResourceId FROM "
            + schemaNameAndTablePrefix
            + "Resource A "
            + "JOIN R ON R.DomainId = A.DomainId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantDomainPermissionSys_ResourceID_BY_AccessorID_DomainID_SysPermissionID_IsWithGrant_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + SQL_findDescendantsRecursiveInDomain_DomainID_DomainLevel_BY_DomainID
            + ", R( DomainId, DomainLevel ) AS "
            // this sub query is the starting set for the domain recursion, it returns all the direct
            // resources domains that the accessor has the specified system permission on (currently super-user)
            + "( SELECT AccessedDomainId, 0 FROM "
            + schemaNameAndTablePrefix
            + "Grant_DomPerm_Sys G "
            + "JOIN N ON N.AccessorResourceId = G.AccessorResourceId "
            + "WHERE G.SysPermissionId = ? AND ( ? IN ( 0, G.IsWithGrant ) ) "
            // now we find the nested domains that the accessor can reach from the direct set above
            + unionClause + " SELECT Rplus1.DomainId, R.DomainLevel + 1 FROM "
            + schemaNameAndTablePrefix
            + "Domain Rplus1, R "
            + "WHERE Rplus1.ParentDomainId IS NOT NULL AND Rplus1.ParentDomainId = R.DomainId ) "
            // finally we get the resources of the specified type in the domains we computed above
            + "SELECT A.ResourceId FROM "
            + schemaNameAndTablePrefix
            + "Resource A "
            + "JOIN R ON R.DomainId = A.DomainId "
            + "JOIN S ON S.DomainId = A.DomainId "
            + "WHERE A.ResourceClassId = ?";

      // Resource: finder methods used getAccessorResourcesByResourcePermission()
      SQL_findInGrantResourcePermissionSys_ResourceID_BY_AccessedID_ResourceClassID_SysPermissionID_IsWithGrant
            = "SELECT AccessorResourceId ResourceId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys "
            + "WHERE AccessedResourceId = ? AND ResourceClassId = ? AND SysPermissionId = ? AND ( ? IN ( 0, IsWithGrant ) )";

      SQL_findInGrantResourcePermission_ResourceID_BY_AccessedID_ResourceClassID_PermissionID_IsWithGrant
            = "SELECT AccessorResourceId ResourceId FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm "
            + "WHERE AccessedResourceId = ? AND ResourceClassId = ? AND PermissionId = ? AND ( ? IN ( 0, IsWithGrant ) )";

      // Resource: finder methods used by getSingletonResource()
      SQL_findInResource_COUNTResourceID_BY_ResourceClassID_DomainID
            = "SELECT COUNT( ResourceId ) COUNTResourceID FROM "
            + schemaNameAndTablePrefix
            + "Resource WHERE ResourceClassId = ? AND DomainId = ?";

      SQL_createInResource_WITH_ResourceID_ResourceClassID_DomainID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Resource ( ResourceId, ResourceClassId, DomainId ) VALUES ( ?, ?, ? )";

      // Resource
      SQL_findInResource_ResourceId_BY_ResourceID
            = "SELECT ResourceId FROM " + schemaNameAndTablePrefix + "Resource WHERE ResourceId = ?";

      SQL_findInResource_DomainID_BY_ResourceID
            = "SELECT DomainId FROM " + schemaNameAndTablePrefix + "Resource WHERE ResourceId = ? ";

      // GrantResourceCreatePermissionSys
      SQL_findInGrantResourceCreatePermissionSys_SysPermissionId_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_AccessedDomainID_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + SQL_findAncestorsRecursiveInDomain_DomainID_DomainLevel_BY_DomainID
            + "SELECT A.SysPermissionId, A.IsWithGrant, N.InheritLevel, R.DomainLevel FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "JOIN R ON R.DomainId = A.AccessedDomainId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantResourceCreatePermissionSys_withoutInheritance_SysPermissionId_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "SELECT A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys A "
            + "WHERE A.AccessorResourceId = ? AND A.AccessedDomainId = ? AND A.ResourceClassId = ?";

      SQL_findInGrantResourceCreatePermissionSys_ResourceDomainName_ResourceClassName_SysPermissionId_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + ", P( AccessedDomainId, ResourceClassId, SysPermissionId, IsWithGrant, InheritLevel, DomainLevel ) AS "
            + "( SELECT A.AccessedDomainId, A.ResourceClassId, A.SysPermissionId, A.IsWithGrant, N.InheritLevel, 0 FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + unionClause + " "
            + "SELECT Pplus1.DomainId, P.ResourceClassId, P.SysPermissionId, P.IsWithGrant, P.InheritLevel, P.DomainLevel + 1 FROM "
            + schemaNameAndTablePrefix
            + "Domain Pplus1, P "
            + "WHERE Pplus1.ParentDomainId IS NOT NULL AND Pplus1.ParentDomainId = P.AccessedDomainId ) "
            + "SELECT C.DomainName, B.ResourceClassName, P.SysPermissionId, P.IsWithGrant, P.InheritLevel, P.DomainLevel FROM P JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass B ON B.ResourceClassId = P.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain C ON C.DomainId = P.AccessedDomainId";

      SQL_createInGrantResourceCreatePermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_SysPermissionId
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys ( AccessorResourceId, GrantorResourceId, AccessedDomainId, IsWithGrant, ResourceClassId, SysPermissionId ) "
            + "VALUES( ?, ?, ?, ?, ?, ? )";

      SQL_removeInGrantResourceCreatePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_Sys WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ?";

      // GrantResourceCreatePermissionPostCreateSys
      SQL_findInGrantResourceCreatePermissionPostCreateSys_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_AccessedDomainID_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + SQL_findAncestorsRecursiveInDomain_DomainID_DomainLevel_BY_DomainID
            + "SELECT A.PostCreateSysPermissionId, A.PostCreateIsWithGrant, A.IsWithGrant, N.InheritLevel, R.DomainLevel FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "JOIN R ON R.DomainId = A.AccessedDomainId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantResourceCreatePermissionPostCreateSys_withoutInheritance_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "SELECT A.PostCreateSysPermissionId, A.PostCreateIsWithGrant, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys A "
            + "WHERE A.AccessorResourceId = ? AND A.AccessedDomainId = ? AND A.ResourceClassId = ?";

      SQL_findInGrantResourceCreatePermissionPostCreateSys_ResourceDomainName_ResourceClassName_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + ", P( AccessedDomainId, ResourceClassId, PostCreateSysPermissionId, PostCreateIsWithGrant, IsWithGrant, InheritLevel, DomainLevel ) AS "
            + "( SELECT A.AccessedDomainId, A.ResourceClassId, A.PostCreateSysPermissionId, A.PostCreateIsWithGrant, A.IsWithGrant, N.InheritLevel, 0 FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + unionClause + " "
            + "SELECT Pplus1.DomainId, P.ResourceClassId, P.PostCreateSysPermissionId, P.PostCreateIsWithGrant, P.IsWithGrant, P.InheritLevel, P.DomainLevel + 1 FROM "
            + schemaNameAndTablePrefix
            + "Domain Pplus1, P "
            + "WHERE Pplus1.ParentDomainId IS NOT NULL AND Pplus1.ParentDomainId = P.AccessedDomainId ) "
            + "SELECT C.DomainName, B.ResourceClassName, P.PostCreateSysPermissionId, P.PostCreateIsWithGrant, P.IsWithGrant, P.InheritLevel, P.DomainLevel FROM P JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass B ON B.ResourceClassId = P.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain C ON C.DomainId = P.AccessedDomainId";

      SQL_createInGrantResourceCreatePermissionPostCreateSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_PostCreateIsWithGrant_ResourceClassID_PostCreateSysPermissionID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys ( AccessorResourceId, GrantorResourceId, AccessedDomainId, IsWithGrant, PostCreateIsWithGrant, ResourceClassId, PostCreateSysPermissionId ) "
            + "VALUES( ?, ?, ?, ?, ?, ?, ? )";

      SQL_removeInGrantResourceCreatePermissionPostCreateSys_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr_Sys WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ?";

      // GrantResourceCreatePermissionPostCreate
      SQL_findInGrantResourceCreatePermissionPostCreate_ResourceClassName_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_AccessedDomainID_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + SQL_findAncestorsRecursiveInDomain_DomainID_DomainLevel_BY_DomainID
            + "SELECT C.ResourceClassName, B.PermissionName PostCreatePermissionName, A.PostCreateIsWithGrant, A.IsWithGrant, N.InheritLevel, R.DomainLevel FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = A.ResourceClassId AND B.PermissionId = A.PostCreatePermissionId JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass C ON C.ResourceClassId = A.ResourceClassId "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "JOIN R ON R.DomainId = A.AccessedDomainId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantResourceCreatePermissionPostCreate_withoutInheritance_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "SELECT B.PermissionName PostCreatePermissionName, A.PostCreateIsWithGrant, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = A.ResourceClassId AND B.PermissionId = A.PostCreatePermissionId "
            + "WHERE A.AccessorResourceId = ? AND A.AccessedDomainId = ? AND A.ResourceClassId = ?";

      SQL_findInGrantResourceCreatePermissionPostCreate_ResourceDomainName_ResourceClassName_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + ", P( AccessedDomainId, ResourceClassId, PostCreatePermissionId, PostCreateIsWithGrant, IsWithGrant, InheritLevel, DomainLevel ) AS "
            + "( SELECT A.AccessedDomainId, A.ResourceClassId, A.PostCreatePermissionId, A.PostCreateIsWithGrant, A.IsWithGrant, N.InheritLevel, 0 FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + unionClause + " "
            + "SELECT Pplus1.DomainId, P.ResourceClassId, P.PostCreatePermissionId, P.PostCreateIsWithGrant, P.IsWithGrant, P.InheritLevel, P.DomainLevel + 1 FROM "
            + schemaNameAndTablePrefix
            + "Domain Pplus1, P "
            + "WHERE Pplus1.ParentDomainId IS NOT NULL AND Pplus1.ParentDomainId = P.AccessedDomainId ) "
            + "SELECT D.DomainName, C.ResourceClassName, B.PermissionName PostCreatePermissionName, P.PostCreateIsWithGrant, P.IsWithGrant, P.InheritLevel, P.DomainLevel FROM P JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = P.ResourceClassId AND B.PermissionId = P.PostCreatePermissionId JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass C ON C.ResourceClassId = P.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain D ON D.DomainId = P.AccessedDomainId";

      SQL_createInGrantResourceCreatePermissionPostCreate_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_PostCreateIsWithGrant_ResourceClassID_PostCreatePermissionName
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr ( AccessorResourceId, GrantorResourceId, AccessedDomainId, IsWithGrant, PostCreateIsWithGrant, ResourceClassId, PostCreatePermissionId ) "
            + "SELECT ?, ?, ?, ?, ?, A.ResourceClassId, A.PermissionId FROM "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission A WHERE A.ResourceClassId = ? AND A.PermissionName = ?";

      SQL_removeInGrantResourceCreatePermissionPostCreate_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResCrPerm_PostCr WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ?";

      // ResourceSysPermission
      SQL_findInGrantResourcePermissionSys_ResourceClassName_SysPermissionID_IsWithGrant_InheritLevel_BY_AccessorID_AccessedID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + "SELECT B.ResourceClassName, A.SysPermissionId, A.IsWithGrant, N.InheritLevel FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass B ON B.ResourceClassId = A.ResourceClassId "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "WHERE A.AccessedResourceId = ?";

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

      SQL_removeInGrantResourcePermissionSys_BY_AccessorID_AccessedID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm_Sys WHERE AccessorResourceId = ? AND AccessedResourceId = ?";

      // GrantResourcePermission
      SQL_findInGrantResourcePermission_ResourceClassName_PermissionName_IsWithGrant_InheritLevel_BY_AccessorID_AccessedID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + "SELECT C.ResourceClassName, B.PermissionName, A.IsWithGrant, N.InheritLevel FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = A.ResourceClassId AND B.PermissionId = A.PermissionId JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass C ON C.ResourceClassId = A.ResourceClassId "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "WHERE A.AccessedResourceId = ?";

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

      SQL_removeInGrantResourcePermission_BY_AccessorID_AccessedID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_ResPerm WHERE AccessorResourceId = ? AND AccessedResourceId = ?";

      // GrantGlobalResourcePermissionSys
      SQL_findInGrantGlobalResourcePermissionSys_SysPermissionID_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_AccessedDomainID_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + SQL_findAncestorsRecursiveInDomain_DomainID_DomainLevel_BY_DomainID
            + "SELECT A.SysPermissionId, A.IsWithGrant, N.InheritLevel, R.DomainLevel FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "JOIN R ON R.DomainId = A.AccessedDomainId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantGlobalResourcePermissionSys_withoutInheritance_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "SELECT A.SysPermissionId, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys A "
            + "WHERE A.AccessorResourceId = ? AND A.AccessedDomainId = ? AND A.ResourceClassId = ?";

      SQL_findInGrantGlobalResourcePermissionSys_ResourceDomainName_ResourceClassName_SysPermissionID_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + ", P( AccessedDomainId, ResourceClassId, SysPermissionId, IsWithGrant, InheritLevel, DomainLevel ) AS "
            + "( SELECT A.AccessedDomainId, A.ResourceClassId, A.SysPermissionId, A.IsWithGrant, N.InheritLevel, 0 FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + unionClause + " "
            + "SELECT Pplus1.DomainId, P.ResourceClassId, P.SysPermissionId, P.IsWithGrant, P.InheritLevel, P.DomainLevel + 1 FROM "
            + schemaNameAndTablePrefix
            + "Domain Pplus1, P "
            + "WHERE Pplus1.ParentDomainId IS NOT NULL AND Pplus1.ParentDomainId = P.AccessedDomainId ) "
            + "SELECT C.DomainName, B.ResourceClassName, P.SysPermissionId, P.IsWithGrant, P.InheritLevel, P.DomainLevel FROM P JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass B ON B.ResourceClassId = P.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain C ON C.DomainId = P.AccessedDomainId";

      SQL_createInGrantGlobalResourcePermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_SysPermissionID
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys ( AccessorResourceId, GrantorResourceId, AccessedDomainId, IsWithGrant, ResourceClassId, SysPermissionId ) "
            + "VALUES ( ?, ?, ?, ?, ?, ? )";

      SQL_removeInGrantGlobalResourcePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm_Sys WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ?";

      // GrantGlobalResourcePermission
      SQL_findInGrantGlobalResourcePermission_PermissionName_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_AccessedDomainID_ResourceClassID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + SQL_findAncestorsRecursiveInDomain_DomainID_DomainLevel_BY_DomainID
            + "SELECT B.PermissionName, A.IsWithGrant, N.InheritLevel, R.DomainLevel FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = A.ResourceClassId AND B.PermissionId = A.PermissionId "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + "JOIN R ON R.DomainId = A.AccessedDomainId "
            + "WHERE A.ResourceClassId = ?";

      SQL_findInGrantGlobalResourcePermission_withoutInheritance_PermissionName_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "SELECT B.PermissionName, A.IsWithGrant FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm A JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = A.ResourceClassId AND B.PermissionId = A.PermissionId "
            + "WHERE A.AccessorResourceId = ? AND A.AccessedDomainId = ? AND A.ResourceClassId = ?";

      SQL_findInGrantGlobalResourcePermission_ResourceDomainName_ResourceClassName_PermissionName_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID
            = SQL_findRecursiveInGrantResourcePermissionSys_AccessorID_InheritLevel_BY_AccessorID
            + ", P( AccessedDomainId, ResourceClassId, PermissionId, IsWithGrant, InheritLevel, DomainLevel ) AS "
            + "( SELECT A.AccessedDomainId, A.ResourceClassId, A.PermissionId, A.IsWithGrant, N.InheritLevel, 0 FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm A "
            + "JOIN N ON N.AccessorResourceId = A.AccessorResourceId "
            + unionClause + " "
            + "SELECT Pplus1.DomainId, P.ResourceClassId, P.PermissionId, P.IsWithGrant, P.InheritLevel, P.DomainLevel + 1 FROM "
            + schemaNameAndTablePrefix
            + "Domain Pplus1, P "
            + "WHERE Pplus1.ParentDomainId IS NOT NULL AND Pplus1.ParentDomainId = P.AccessedDomainId ) "
            + "SELECT D.DomainName, C.ResourceClassName, B.PermissionName, P.IsWithGrant, P.InheritLevel, P.DomainLevel FROM P JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission B ON B.ResourceClassId = P.ResourceClassId AND B.PermissionId = P.PermissionId JOIN "
            + schemaNameAndTablePrefix
            + "ResourceClass C ON C.ResourceClassId = P.ResourceClassId JOIN "
            + schemaNameAndTablePrefix
            + "Domain D ON D.DomainId = P.AccessedDomainId";

      SQL_createInGrantGlobalResourcePermission_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_PermissionName
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm ( AccessorResourceId, GrantorResourceId, AccessedDomainId, IsWithGrant, ResourceClassId, PermissionId ) "
            + "SELECT ?, ?, ?, ?, A.ResourceClassId, A.PermissionId FROM "
            + schemaNameAndTablePrefix
            + "ResourceClassPermission A WHERE A.ResourceClassId = ? AND A.PermissionName = ?";

      SQL_removeInGrantGlobalResourcePermission_BY_AccessorID_AccessedDomainID_ResourceClassID
            = "DELETE FROM "
            + schemaNameAndTablePrefix
            + "Grant_Global_ResPerm WHERE AccessorResourceId = ? AND AccessedDomainId = ? AND ResourceClassId = ?";

      // Key generators
      SQL_nextResourceID
            = dialectSpecificSQLGenerator.nextSequenceValueStatement(schemaNameAndTablePrefix + "ResourceId");
   }
}
