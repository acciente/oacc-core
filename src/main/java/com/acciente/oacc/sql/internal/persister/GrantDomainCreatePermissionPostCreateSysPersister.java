package com.acciente.oacc.sql.internal.persister;

import com.acciente.oacc.DomainCreatePermission;
import com.acciente.oacc.Resource;

import java.util.Set;

public interface GrantDomainCreatePermissionPostCreateSysPersister {
   Set<DomainCreatePermission> getDomainCreatePostCreateSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                       Resource accessorResource);

   Set<DomainCreatePermission> getDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                                       Resource accessorResource);

   void removeDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                   Resource accessorResource);

   void removeDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                   Resource accessorResource,
                                                   Set<DomainCreatePermission> domainCreatePermissions);

   void addDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                Resource accessorResource,
                                                Resource grantorResource,
                                                Set<DomainCreatePermission> domainCreatePermissions);

   void updateDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                   Resource accessorResource,
                                                   Resource grantorResource,
                                                   Set<DomainCreatePermission> domainCreatePermissions);
}
