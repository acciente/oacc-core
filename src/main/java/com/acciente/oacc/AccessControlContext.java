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

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The interface with which to define and control access to OACC resources.
 * <p/>
 * An instance of this session is used to both define the OACC resources and the security privileges to them,
 * as well as to query the security system in order to implement access control to these resources.
 * <p/>
 * Definitions:
 * <dl>
 * <dt> "session"
 * <dd> An instance of this interface that has been {@link #authenticate authenticated},
 * that is, security credentials have been associated with this session
 * <dt> "authenticated resource"
 * <dd> The resource that authenticated this session,
 * that is, the resource that logged into this session with a call to one of the <code>authenticate</code> methods
 * <dt> "session resource"
 * <dd> The resource whose security credentials are associated with this session.
 * This is the same as the authenticated resource, unless another resource is being {@link #impersonate impersonated}.
 * </dl>
 * Unless a session is authenticated, all attempts to call any methods other than <code>authenticate</code>,
 * <code>unauthenticate</code>, <code>unimpersonate</code> or a special case of <code>createResource</code>, will fail
 * with a {@link com.acciente.oacc.NotAuthenticatedException}.
 * <p/>
 * In general, all methods should throw the following unchecked exceptions as described below:
 * <dl>
 * <dd>{@link java.lang.NullPointerException} - if a null object reference is passed in any method parameter
 *                                              (in general, all parameters are required)
 * <dd>{@link java.lang.IllegalArgumentException} - if a method parameter is empty or blank, or
 *                                                  if a set or sequence of arguments contains null or duplicate elements
 * </dl>
 * Unchecked exceptions explicitly thrown for other reasons are described at the method-level.
 */
public interface AccessControlContext {
   String SYSTEM_DOMAIN         = "SYSDOMAIN";
   String SYSTEM_RESOURCE_CLASS = "SYSOBJECT";

   /**
    * Authenticates this security session.
    * <p/>
    * The security credentials for this session will be those of the specified and authenticated resource.
    * <p/>
    * Note: Unless a session is authenticated, all attempts to call any other methods (except <code>authenticate</code>) will fail.
    *
    * @param resource the resource to be authenticated
    * @param credentials the credentials to authenticate the resource
    * @throws java.lang.IllegalArgumentException        if the resource does not exist or is not of an authenticatable resource class
    * @throws com.acciente.oacc.AuthenticationException if authentication fails
    */
   void authenticate(Resource resource, Credentials credentials);

   /**
    * Authenticates this security session against an {@link AuthenticationProvider} without
    * specifying authentication credentials, if that AuthenticationProvider supports such an operation.
    * <p/>
    * The security credentials for this session will be those of the specified and authenticated resource.
    * <p/>
    * Note: Unless a session is authenticated, all attempts to call any other methods (except <code>authenticate</code>) will fail.
    *
    * @param resource the resource to be authenticated
    * @throws java.lang.IllegalArgumentException if the resource does not exist or is not of an authenticatable resource class
    */
   void authenticate(Resource resource);

   /**
    * Logs out of this session, to be specific, disassociates any security credentials from this session.
    * <p/>
    * If no resource is currently authenticated, this call has no effect.
    */
   void unauthenticate();

   /**
    * Returns the resource that is currently authenticated in this session.
    *
    * @return a resource
    * @throws com.acciente.oacc.NotAuthenticatedException if no resource is authenticated
    */
   Resource getAuthenticatedResource();

   /**
    * Switches the security credentials of this session to those of the specified resource.
    * <p/>
    * The currently authenticated resource has to have IMPERSONATE permissions to the specified resource.
    * <p/>
    * Note that this method is idempotent and will use the authorization credentials of
    * the originally authenticated resource, and not those of any currently impersonated resource.
    *
    * @param resource the resource to be impersonated
    * @throws java.lang.IllegalArgumentException       if the resource does not exist, or
    *                                                  if the resource is not of an authenticatable resource class
    * @throws com.acciente.oacc.NotAuthorizedException if the authenticated resource does not have permission to
    *                                                  impersonate the specified resource
    */
   void impersonate(Resource resource);

   /**
    * Unimpersonates the currently impersonated resource.
    * <p/>
    * Restores the session to the credentials of the authenticated resource.
    * <p/>
    * If no resource is currently being impersonated, this call has no effect.
    */
   void unimpersonate();

   /**
    * Returns the session resource, that is, the resource whose security credentials are
    * associated with this session.
    * <p/>
    * The session resource is the same as the authenticated resource, unless another resource
    * is being {@link #impersonate impersonated}.
    *
    * @return a resource
    * @throws com.acciente.oacc.NotAuthenticatedException if no resource is authenticated
    */
   Resource getSessionResource();

   /**
    * Sets the authentication credentials of the specified authenticatable resource (= a resource of a
    * resource class that has been defined with the <code>isAuthenticatable</code> flag set to true).
    * <p/>
    * One of the following has to be true for this method to succeed:
    * <ul>
    * <li> the specified resource has to either be the currently authenticated resource or
    * <li> the currently authenticated resource has to have SUPER-USER permission on the domain
    * that contains the specified resource or
    * <li> the currently authenticated resource has to have RESET-CREDENTIALS permission on the specified resource.
    * </ul>
    * Note that this method uses the permissions granted to the originally authenticated resource - and not those of
    * any currently impersonated resource - to check the items listed above. This method will actually throw an exception
    * if called while impersonating another resource, in order to prevent any way of setting another resource's credentials
    * without having the explicit RESET-CREDENTIALS or SUPER-USER permissions.
    *
    * @param resource    the resource for which the credentials should be updated. The resource for which the credentials are
    *                    to be changed must be the current auth resource, or the current auth resource must have SUPER-USER permissions
    *                    to the domain containing the resource whose credentials are to be changed or must have RESET-CREDENTIALS
    *                    permissions to the resource whose credentials are to be changed, otherwise an exception is thrown.
    * @param newCredentials the new credentials for the resource
    * @throws java.lang.IllegalArgumentException            if the resource does not exist, or
    *                                                       if the resource is not of an authenticatable resource class
    * @throws java.lang.IllegalStateException               if called while impersonating another resource
    * @throws com.acciente.oacc.InvalidCredentialsException if newCredentials is invalid
    * @throws com.acciente.oacc.NotAuthorizedException      if the authenticated resource does not have permission to
    *                                                       reset the credentials of the specified resource
    */
   void setCredentials(Resource resource, Credentials newCredentials);

   /**
    * Checks if the specified accessor resource has the specified domain permissions on
    * the specified domain.
    * This method takes into account any direct domain permissions, inherited domain permissions
    * and any domain permissions the accessor may have to ancestors of the specified domain, as well
    * as any super-user privileges.
    *
    * @param accessorResource  the resource on which access is being checked
    * @param domainName        the domain for which the permission should be checked
    * @param domainPermissions the permissions to be checked
    * @throws java.lang.IllegalArgumentException       if the accessorResource does not exist, or
    *                                                  if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the accessor resource <strong>does not</strong> have the
    *                                                  specified domain permissions, or
    *                                                  if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   void assertDomainPermissions(Resource accessorResource,
                                String domainName,
                                Set<DomainPermission> domainPermissions);

   /**
    * Checks if the specified accessor resource has the specified domain permissions on
    * the specified domain.
    * This method takes into account any direct domain permissions, inherited domain permissions
    * and any domain permissions the accessor may have to ancestors of the specified domain, as well
    * as any super-user privileges.
    *
    * @param accessorResource  the resource on which access is being checked
    * @param domainName        the domain for which the permission should be checked
    * @param domainPermission  the permission to be checked
    * @param domainPermissions the other (optional) permissions to be checked
    * @throws java.lang.IllegalArgumentException       if the accessorResource does not exist, or
    *                                                  if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the accessor resource <strong>does not</strong> have the
    *                                                  specified domain permissions, or
    *                                                  if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   void assertDomainPermissions(Resource accessorResource,
                                String domainName,
                                DomainPermission domainPermission,
                                DomainPermission... domainPermissions);

   /**
    * Checks if the specified accessor resource has the specified domain permissions on
    * the specified domain.
    * This method takes into account any direct domain permissions, inherited domain permissions
    * and any domain permissions the accessor may have to ancestors of the specified domain, as well
    * as any super-user privileges.
    *
    * @param accessorResource  the resource on which access is being checked
    * @param domainName        the domain for which the permission should be checked
    * @param domainPermissions the permissions to be checked
    * @return  <strong>true</strong> if the accessor resource has the specified domain permissions,
    *          <strong>false</strong> otherwise or if the accessor resource does not exist
    * @throws java.lang.IllegalArgumentException if the accessorResource does not exist, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   boolean hasDomainPermissions(Resource accessorResource,
                                String domainName,
                                Set<DomainPermission> domainPermissions);

   /**
    * Checks if the specified accessor resource has the specified domain permissions on
    * the specified domain.
    * This method takes into account any direct domain permissions, inherited domain permissions
    * and any domain permissions the accessor may have to ancestors of the specified domain, as well
    * as any super-user privileges.
    *
    * @param accessorResource  the resource on which access is being checked
    * @param domainName        the domain for which the permission should be checked
    * @param domainPermission  the permission to be checked
    * @param domainPermissions the other (optional) permissions to be checked
    * @return  <strong>true</strong> if the accessor resource has the specified domain permissions,
    *          <strong>false</strong> otherwise or if the accessor resource does not exist
    * @throws java.lang.IllegalArgumentException if the accessorResource does not exist, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   boolean hasDomainPermissions(Resource accessorResource,
                                String domainName,
                                DomainPermission domainPermission,
                                DomainPermission... domainPermissions);

   /**
    * Checks if the specified accessor resource has the specified domain create permissions.
    * This method takes into account any direct and inherited domain create permissions.
    *
    * @param accessorResource        the resource on which access is being checked
    * @param domainCreatePermissions the domain create permissions to be checked
    * @throws IllegalArgumentException                 if the accessorResource does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the accessor resource <strong>does not</strong> have the
    *                                                  specified domain create permissions, or
    *                                                  if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   void assertDomainCreatePermissions(Resource accessorResource,
                                      Set<DomainCreatePermission> domainCreatePermissions);

   /**
    * Checks if the specified accessor resource has the specified domain create permissions.
    * This method takes into account any direct and inherited domain create permissions.
    *
    * @param accessorResource        the resource on which access is being checked
    * @param domainCreatePermission  the domain create permission to be checked
    * @param domainCreatePermissions the other (optional) domain create permissions to be checked
    * @throws IllegalArgumentException                 if the accessorResource does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the accessor resource <strong>does not</strong> have the
    *                                                  specified domain create permissions, or
    *                                                  if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   void assertDomainCreatePermissions(Resource accessorResource,
                                      DomainCreatePermission domainCreatePermission,
                                      DomainCreatePermission... domainCreatePermissions);

   /**
    * Checks if the specified accessor resource has the specified domain create permissions.
    * This method takes into account any direct and inherited domain create permissions.
    *
    * @param accessorResource        the resource on which access is being checked
    * @param domainCreatePermissions the domain create permissions to be checked
    * @return  <strong>true</strong> if the accessor resource has the specified domain create permissions,
    *          <strong>false</strong> otherwise
    * @throws IllegalArgumentException if the accessorResource does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   boolean hasDomainCreatePermissions(Resource accessorResource,
                                      Set<DomainCreatePermission> domainCreatePermissions);

   /**
    * Checks if the specified accessor resource has the specified domain create permissions.
    * This method takes into account any direct and inherited domain create permissions.
    *
    * @param accessorResource        the resource on which access is being checked
    * @param domainCreatePermission  the domain create permission to be checked
    * @param domainCreatePermissions the other (optional) domain create permissions to be checked
    * @return  <strong>true</strong> if the accessor resource has the specified domain create permissions,
    *          <strong>false</strong> otherwise
    * @throws IllegalArgumentException if the accessorResource does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   boolean hasDomainCreatePermissions(Resource accessorResource,
                                      DomainCreatePermission domainCreatePermission,
                                      DomainCreatePermission... domainCreatePermissions);

   /**
    * Checks if the specified accessor resource would receive the specified domain permissions, if the accessor
    * were to create a domain.
    * The method takes into account any direct and inherited domain create permissions the accessor might have, as well
    * as any super-user privileges.
    *
    * @param accessorResource  the resource requesting the access
    * @param domainPermissions the permissions to be checked
    * @throws IllegalArgumentException                 if the accessorResource does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the accessor resource would <strong>not</strong> receive the
    *                                                  specified permissions after creating a domain, or
    *                                                  if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   void assertPostCreateDomainPermissions(Resource accessorResource,
                                          Set<DomainPermission> domainPermissions);

   /**
    * Checks if the specified accessor resource would receive the specified domain permissions, if the accessor
    * were to create a domain.
    * The method takes into account any direct and inherited domain create permissions the accessor might have, as well
    * as any super-user privileges.
    *
    * @param accessorResource  the resource requesting the access
    * @param domainPermission  the permission to be checked
    * @param domainPermissions the other (optional) permissions to be checked
    * @throws IllegalArgumentException                 if the accessorResource does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the accessor resource would <strong>not</strong> receive the
    *                                                  specified permissions after creating a domain, or
    *                                                  if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   void assertPostCreateDomainPermissions(Resource accessorResource,
                                          DomainPermission domainPermission,
                                          DomainPermission... domainPermissions);

   /**
    * Checks if the specified accessor resource would receive the specified domain permissions, if the accessor
    * were to create a domain.
    * The method takes into account any direct and inherited domain create permissions the accessor might have, as well
    * as any super-user privileges.
    *
    * @param accessorResource  the resource requesting the access
    * @param domainPermissions the permissions to be checked
    * @return <strong>true</strong> if the accessor resource would receive the specified permissions after creating a domain
    * @throws IllegalArgumentException if the accessorResource does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   boolean hasPostCreateDomainPermissions(Resource accessorResource,
                                          Set<DomainPermission> domainPermissions);

   /**
    * Checks if the specified accessor resource would receive the specified domain permissions, if the accessor
    * were to create a domain.
    * The method takes into account any direct and inherited domain create permissions the accessor might have, as well
    * as any super-user privileges.
    *
    * @param accessorResource  the resource requesting the access
    * @param domainPermission  the permission to be checked
    * @param domainPermissions the other (optional) permissions to be checked
    * @return <strong>true</strong> if the accessor resource would receive the specified permissions after creating a domain
    * @throws IllegalArgumentException if the accessorResource does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   boolean hasPostCreateDomainPermissions(Resource accessorResource,
                                          DomainPermission domainPermission,
                                          DomainPermission... domainPermissions);

   /**
    * Checks if the specified accessor resource has the specified global resource permissions on
    * the specified resource class in the specified domain.
    * This method takes into account any global permissions that the accessor resource may have, as well
    * as any super-user privileges.
    *
    * @param accessorResource    the resource on which access is being checked
    * @param resourceClassName   a string resource class name
    * @param domainName          the domain in which the permissions should be checked
    * @param resourcePermissions the permissions to be checked
    * @throws java.lang.IllegalArgumentException if the accessorResource does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if any resourcePermission is invalid for the resource class, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the accessor resource <strong>does not</strong> have the
    *                                                  specified global permissions, or
    *                                                  if the accessor resource does not exist, or
    *                                                  if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   void assertGlobalResourcePermissions(Resource accessorResource,
                                        String resourceClassName,
                                        String domainName,
                                        Set<ResourcePermission> resourcePermissions);

   /**
    * Checks if the specified accessor resource has the specified global resource permissions on
    * the specified resource class in the specified domain.
    * This method takes into account any global permissions that the accessor resource may have, as well
    * as any super-user privileges.
    *
    * @param accessorResource    the resource on which access is being checked
    * @param resourceClassName   a string resource class name
    * @param domainName          the domain in which the permissions should be checked
    * @param resourcePermission  the permission to be checked
    * @param resourcePermissions the other (optional) permissions to be checked
    * @throws java.lang.IllegalArgumentException if the accessorResource does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if any resourcePermission is invalid for the resource class, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the accessor resource <strong>does not</strong> have the
    *                                                  specified global permissions, or
    *                                                  if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   void assertGlobalResourcePermissions(Resource accessorResource,
                                        String resourceClassName,
                                        String domainName,
                                        ResourcePermission resourcePermission,
                                        ResourcePermission... resourcePermissions);

   /**
    * Checks if the specified accessor resource has the specified global resource permissions on
    * the specified resource class in the specified domain.
    * This method takes into account any global permissions that the accessor resource may have, as well
    * as any super-user privileges.
    *
    * @param accessorResource    the resource on which access is being checked
    * @param resourceClassName   a string resource class name
    * @param domainName          the domain in which the permissions should be checked
    * @param resourcePermissions the permissions to be checked
    * @return <strong>true</strong> if the accessor resource has the specified global permissions,
    *         <strong>false</strong> otherwise
    * @throws java.lang.IllegalArgumentException if the accessorResource does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if any resourcePermission is invalid for the resource class, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   boolean hasGlobalResourcePermissions(Resource accessorResource,
                                        String resourceClassName,
                                        String domainName,
                                        Set<ResourcePermission> resourcePermissions);

   /**
    * Checks if the specified accessor resource has the specified global resource permissions on
    * the specified resource class in the specified domain.
    * This method takes into account any global permissions that the accessor resource may have, as well
    * as any super-user privileges.
    *
    * @param accessorResource    the resource on which access is being checked
    * @param resourceClassName   a string resource class name
    * @param domainName          the domain in which the permissions should be checked
    * @param resourcePermission  the permission to be checked
    * @param resourcePermissions the other (optional) permissions to be checked
    * @return <strong>true</strong> if the accessor resource has the specified global permissions,
    *         <strong>false</strong> otherwise
    * @throws java.lang.IllegalArgumentException if the accessorResource does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if any resourcePermission is invalid for the resource class, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   boolean hasGlobalResourcePermissions(Resource accessorResource,
                                        String resourceClassName,
                                        String domainName,
                                        ResourcePermission resourcePermission,
                                        ResourcePermission... resourcePermissions);

   /**
    * Checks if the specified accessor resource has the specified resource permissions
    * to the specified accessed resource.
    * This method takes into account direct, inherited and global permissions of accessor resource, as well
    * as any super-user privileges.
    *
    * @param accessorResource    the resource requesting the access
    * @param accessedResource    the resource on which access is being requested
    * @param resourcePermissions the permissions to be checked
    * @throws java.lang.IllegalArgumentException if the accessorResource or the accessedResource does not exist, or
    *                                            if any resourcePermission is invalid for the resource class of accessedResource
    * @throws com.acciente.oacc.NotAuthorizedException if the accessor resource <strong>does not</strong> have the
    *                                                  specified permissions, or
    *                                                  if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   void assertResourcePermissions(Resource accessorResource,
                                  Resource accessedResource,
                                  Set<ResourcePermission> resourcePermissions);

   /**
    * Checks if the specified accessor resource has the specified resource permissions
    * to the specified accessed resource.
    * This method takes into account direct, inherited and global permissions of accessor resource, as well
    * as any super-user privileges.
    *
    * @param accessorResource    the resource requesting the access
    * @param accessedResource    the resource on which access is being requested
    * @param resourcePermission  the permission to be checked
    * @param resourcePermissions the other (optional) permissions to be checked
    * @throws java.lang.IllegalArgumentException if the accessorResource or the accessedResource does not exist, or
    *                                            if any resourcePermission is invalid for the resource class of accessedResource
    * @throws com.acciente.oacc.NotAuthorizedException if the accessor resource <strong>does not</strong> have the
    *                                                  specified permissions, or
    *                                                  if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   void assertResourcePermissions(Resource accessorResource,
                                  Resource accessedResource,
                                  ResourcePermission resourcePermission,
                                  ResourcePermission... resourcePermissions);

   /**
    * Checks if the specified accessor resource has the specified resource permissions
    * to the specified accessed resource.
    * This method takes into account direct, inherited and global permissions of accessor resource, as well
    * as any super-user privileges.
    *
    * @param accessorResource    the resource requesting the access
    * @param accessedResource    the resource on which access is being requested
    * @param resourcePermissions the permissions to be checked
    * @return <strong>true</strong> if the accessor resource has the specified permissions
    * @throws java.lang.IllegalArgumentException if the accessorResource or the accessedResource does not exist, or
    *                                            if any resourcePermission is invalid for the resource class of accessedResource
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   boolean hasResourcePermissions(Resource accessorResource,
                                  Resource accessedResource,
                                  Set<ResourcePermission> resourcePermissions);

   /**
    * Checks if the specified accessor resource has the specified resource permissions
    * to the specified accessed resource.
    * This method takes into account direct, inherited and global permissions of accessor resource, as well
    * as any super-user privileges.
    *
    * @param accessorResource    the resource requesting the access
    * @param accessedResource    the resource on which access is being requested
    * @param resourcePermission  the permission to be checked
    * @param resourcePermissions the other (optional) permissions to be checked
    * @return <strong>true</strong> if the accessor resource has the specified permissions
    * @throws java.lang.IllegalArgumentException if the accessorResource or the accessedResource does not exist, or
    *                                            if any resourcePermission is invalid for the resource class of accessedResource
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   boolean hasResourcePermissions(Resource accessorResource,
                                  Resource accessedResource,
                                  ResourcePermission resourcePermission,
                                  ResourcePermission... resourcePermissions);

   /**
    * Checks if the specified accessor resource has the specified create permissions on an object of
    * the specified class in the specified domain.
    * The method takes into account any any direct and inherited resource create permissions of the
    * specified accessor resource, as well as any super-user privileges.
    *
    * @param accessorResource          the resource requesting the access
    * @param resourceClassName         a string resource class name
    * @param domainName                the domain in which the permissions should be checked
    * @param resourceCreatePermissions the create permissions to be checked
    * @throws java.lang.IllegalArgumentException       if the accessorResource does not exist, or
    *                                                  if no resource class of resourceClassName exists, or
    *                                                  if any resourceCreatePermission is invalid for the resource class, or
    *                                                  if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the accessor resource does <strong>not</strong> have the
    *                                                  specified resource create permissions for the specified class
    *                                                  in the specified domain, or
    *                                                  if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   void assertResourceCreatePermissions(Resource accessorResource,
                                        String resourceClassName,
                                        String domainName,
                                        Set<ResourceCreatePermission> resourceCreatePermissions);

   /**
    * Checks if the specified accessor resource has the specified create permissions on an object of
    * the specified class in the specified domain.
    * The method takes into account any any direct and inherited resource create permissions of the
    * specified accessor resource, as well as any super-user privileges.
    *
    * @param accessorResource          the resource requesting the access
    * @param resourceClassName         a string resource class name
    * @param domainName                the domain in which the permissions should be checked
    * @param resourceCreatePermission  the create permission to be checked
    * @param resourceCreatePermissions the other (optional) create permissions to be checked
    * @throws java.lang.IllegalArgumentException       if the accessorResource does not exist, or
    *                                                  if no resource class of resourceClassName exists, or
    *                                                  if any resourceCreatePermission is invalid for the resource class, or
    *                                                  if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the accessor resource does <strong>not</strong> have the
    *                                                  specified resource create permissions for the specified class
    *                                                  in the specified domain, or
    *                                                  if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   void assertResourceCreatePermissions(Resource accessorResource,
                                        String resourceClassName,
                                        String domainName,
                                        ResourceCreatePermission resourceCreatePermission,
                                        ResourceCreatePermission... resourceCreatePermissions);

   /**
    * Checks if the specified accessor resource has the specified create permissions on an object of
    * the specified class in the specified domain.
    * The method takes into account any any direct and inherited resource create permissions of the
    * specified accessor resource, as well as any super-user privileges.
    *
    * @param accessorResource          the resource requesting the access
    * @param resourceClassName         a string resource class name
    * @param domainName                the domain in which the permissions should be checked
    * @param resourceCreatePermissions the create permissions to be checked
    * @return <strong>true</strong> if the accessor resource has the specified resource create permissions for the
    *         specified resource class in the specified domain,
    *         <strong>false</strong> otherwise
    * @throws java.lang.IllegalArgumentException if the accessorResource does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if any resourceCreatePermission is invalid for the resource class, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   boolean hasResourceCreatePermissions(Resource accessorResource,
                                        String resourceClassName,
                                        String domainName,
                                        Set<ResourceCreatePermission> resourceCreatePermissions);

   /**
    * Checks if the specified accessor resource has the specified create permissions on an object of
    * the specified class in the specified domain.
    * The method takes into account any any direct and inherited resource create permissions of the
    * specified accessor resource, as well as any super-user privileges.
    *
    * @param accessorResource          the resource requesting the access
    * @param resourceClassName         a string resource class name
    * @param domainName                the domain in which the permissions should be checked
    * @param resourceCreatePermission  the create permission to be checked
    * @param resourceCreatePermissions the other (optional) create permissions to be checked
    * @return <strong>true</strong> if the accessor resource has the specified resource create permissions for the
    *         specified resource class in the specified domain,
    *         <strong>false</strong> otherwise
    * @throws java.lang.IllegalArgumentException if the accessorResource does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if any resourceCreatePermission is invalid for the resource class, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   boolean hasResourceCreatePermissions(Resource accessorResource,
                                        String resourceClassName,
                                        String domainName,
                                        ResourceCreatePermission resourceCreatePermission,
                                        ResourceCreatePermission... resourceCreatePermissions);

   /**
    * Checks if the specified accessor resource would receive the specified permissions on an object of
    * the specified class in the specified domain, if it were to create such an object.
    * The method takes into account any resource create permissions and global resource permissions
    * of the specified accessor resource.
    *
    * @param accessorResource    the resource requesting the access
    * @param resourceClassName   a string resource class name
    * @param domainName          the domain in which the permissions should be checked
    * @param resourcePermissions the permissions to be checked
    * @throws java.lang.IllegalArgumentException       if the accessorResource does not exist, or
    *                                                  if no resource class of resourceClassName exists, or
    *                                                  if no domain of domainName exists, or
    *                                                  if any resourcePermission is invalid for the resource class
    * @throws com.acciente.oacc.NotAuthorizedException if the accessor resource would <strong>not</strong> receive the
    *                                                  specified permissions after creating a resource of the specified
    *                                                  class in the specified domain, or
    *                                                  if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   void assertPostCreateResourcePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            String domainName,
                                            Set<ResourcePermission> resourcePermissions);

   /**
    * Checks if the specified accessor resource would receive the specified permissions on an object of
    * the specified class in the specified domain, if it were to create such an object.
    * The method takes into account any resource create permissions and global resource permissions
    * of the specified accessor resource, as well as any super-user privileges, as well as any super-user privileges.
    *
    * @param accessorResource    the resource requesting the access
    * @param resourceClassName   a string resource class name
    * @param domainName          the domain in which the permissions should be checked
    * @param resourcePermission  the permission to be checked
    * @param resourcePermissions the other (optional) permissions to be checked
    * @throws java.lang.IllegalArgumentException       if the accessorResource does not exist, or
    *                                                  if no resource class of resourceClassName exists, or
    *                                                  if no domain of domainName exists, or
    *                                                  if any resourcePermission is invalid for the resource class
    * @throws com.acciente.oacc.NotAuthorizedException if the accessor resource would <strong>not</strong> receive the
    *                                                  specified permissions after creating a resource of the specified
    *                                                  class in the specified domain, or
    *                                                  if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   void assertPostCreateResourcePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            String domainName,
                                            ResourcePermission resourcePermission,
                                            ResourcePermission... resourcePermissions);

   /**
    * Checks if the specified accessor resource would receive the specified permissions on an object of
    * the specified class in the specified domain, if it were to create such an object.
    * The method takes into account any resource create permissions and global resource permissions
    * of the specified accessor resource, as well as any super-user privileges.
    *
    * @param accessorResource    the resource requesting the access
    * @param resourceClassName   a string resource class name
    * @param domainName          the domain in which the permissions should be checked
    * @param resourcePermissions the permissions to be checked
    * @return <strong>true</strong> if the accessor resource would receive the specified permissions after creating a
    *         resource of the specified class in the specified domain,
    *         <strong>false</strong> otherwise
    * @throws java.lang.IllegalArgumentException if the accessorResource does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists, or
    *                                            if any resourcePermission is invalid for the resource class
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   boolean hasPostCreateResourcePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            String domainName,
                                            Set<ResourcePermission> resourcePermissions);

   /**
    * Checks if the specified accessor resource would receive the specified permissions on an object of
    * the specified class in the specified domain, if it were to create such an object.
    * The method takes into account any resource create permissions and global resource permissions
    * of the specified accessor resource, as well as any super-user privileges.
    *
    * @param accessorResource    the resource requesting the access
    * @param resourceClassName   a string resource class name
    * @param domainName          the domain in which the permissions should be checked
    * @param resourcePermission  the permission to be checked
    * @param resourcePermissions the other (optional) permissions to be checked
    * @return <strong>true</strong> if the accessor resource would receive the specified permissions after creating a
    *         resource of the specified class in the specified domain,
    *         <strong>false</strong> otherwise
    * @throws java.lang.IllegalArgumentException if the accessorResource does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists, or
    *                                            if any resourcePermission is invalid for the resource class
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   boolean hasPostCreateResourcePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            String domainName,
                                            ResourcePermission resourcePermission,
                                            ResourcePermission... resourcePermissions);

   /**
    * Returns a set of resources (of the specified resource class) on which
    * the specified accessor resource has the specified permissions, regardless of domain.
    * <p/>
    * The method takes into account direct, inherited and global permissions, as well as
    * resources that are reachable as a result of SUPER-USER permissions.
    *
    * @param accessorResource    the resource relative to which the set of accessible resources is computed
    * @param resourceClassName   a string resource class name
    * @param resourcePermissions the permissions to check
    * @return a set of resources
    * @throws java.lang.IllegalArgumentException if accessorResource does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if any resourcePermission is invalid for the specified resource class
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<Resource> getResourcesByResourcePermissions(Resource accessorResource,
                                                   String resourceClassName,
                                                   Set<ResourcePermission> resourcePermissions);

   /**
    * Returns a set of resources (of the specified resource class) on which
    * the specified accessor resource has the specified permissions, regardless of domain.
    * <p/>
    * The method takes into account direct, inherited and global permissions, as well as
    * resources that are reachable as a result of SUPER-USER permissions.
    *
    * @param accessorResource    the resource relative to which the set of accessible resources is computed
    * @param resourceClassName   a string resource class name
    * @param resourcePermission  the permission to check
    * @param resourcePermissions the other (optional) permissions to check
    * @return a set of resources
    * @throws java.lang.IllegalArgumentException if accessorResource does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if any resourcePermission is invalid for the specified resource class
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<Resource> getResourcesByResourcePermissions(Resource accessorResource,
                                                   String resourceClassName,
                                                   ResourcePermission resourcePermission,
                                                   ResourcePermission... resourcePermissions);

   /**
    * Returns a set of resources (of the specified resource class) on which
    * the specified accessor resource has the specified permissions, within the
    * specified domain or within any descendant domains.
    * <p/>
    * The method takes into account direct, inherited and global permissions, as well as
    * resources that are reachable as a result of SUPER-USER permissions.
    *
    * @param accessorResource    the resource relative to which the set of accessible resources is computed
    * @param resourceClassName   a string resource class name
    * @param domainName          a domain name
    * @param resourcePermissions the permissions to check
    * @return a set of resources
    * @throws java.lang.IllegalArgumentException if accessorResource does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists, or
    *                                            if any resourcePermission is invalid for the specified resource class
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<Resource> getResourcesByResourcePermissionsAndDomain(Resource accessorResource,
                                                            String resourceClassName,
                                                            String domainName,
                                                            Set<ResourcePermission> resourcePermissions);

   /**
    * Returns a set of resources (of the specified resource class) on which
    * the specified accessor resource has the specified permissions, within the
    * specified domain or within any descendant domains.
    * <p/>
    * The method takes into account direct, inherited and global permissions, as well as
    * resources that are reachable as a result of SUPER-USER permissions.
    *
    * @param accessorResource    the resource relative to which the set of accessible resources is computed
    * @param resourceClassName   a string resource class name
    * @param domainName          a domain name
    * @param resourcePermission  the permission to check
    * @param resourcePermissions the other (optional) permissions to check
    * @return a set of resources
    * @throws java.lang.IllegalArgumentException if accessorResource does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists, or
    *                                            if any resourcePermission is invalid for the specified resource class
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<Resource> getResourcesByResourcePermissionsAndDomain(Resource accessorResource,
                                                            String resourceClassName,
                                                            String domainName,
                                                            ResourcePermission resourcePermission,
                                                            ResourcePermission... resourcePermissions);

   /**
    * Returns a set of resources that have the specified permissions to the specified accessed resource.
    * <p/>
    * This method works in the reverse direction of the {@link #getResourcesByResourcePermissions} method, but
    * unlike <code>getResourcesByResourcePermissions</code> it only takes into account direct permissions.
    * In other words, this method ignores accessors that can reach the specified accessed resource
    * via inherited permissions, global permissions and SUPER-USER privileges.
    *
    * @param accessedResource    the resource relative to which accessor resources are sought
    * @param resourceClassName   a string resource class name
    * @param resourcePermissions the permissions to check
    * @return a set of accessor resources to the accessedResource
    * @throws java.lang.IllegalArgumentException if accessorResource does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if any resourcePermission is invalid for the specified resource class
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessed resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessed resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<Resource> getAccessorResourcesByResourcePermissions(Resource accessedResource,
                                                           String resourceClassName,
                                                           Set<ResourcePermission> resourcePermissions);

   /**
    * Returns a set of resources that have the specified permissions to the specified accessed resource.
    * <p/>
    * This method works in the reverse direction of the {@link #getResourcesByResourcePermissions} method, but
    * unlike <code>getResourcesByResourcePermissions</code> it only takes into account direct permissions.
    * In other words, this method ignores accessors that can reach the specified accessed resource
    * via inherited permissions, global permissions and SUPER-USER privileges.
    *
    * @param accessedResource    the resource relative to which accessor resources are sought
    * @param resourceClassName   a string resource class name
    * @param resourcePermission  the permission to check
    * @param resourcePermissions the other (optional) permissions to check
    * @return a set of accessor resources to the accessedResource
    * @throws java.lang.IllegalArgumentException if accessorResource does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if any resourcePermission is invalid for the specified resource class
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessed resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessed resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<Resource> getAccessorResourcesByResourcePermissions(Resource accessedResource,
                                                           String resourceClassName,
                                                           ResourcePermission resourcePermission,
                                                           ResourcePermission... resourcePermissions);

   /**
    * Returns the domain to which the specified resource belongs.
    *
    * @param resource the resource for which to retrieve the domain name
    * @return a string domain name
    * @throws java.lang.IllegalArgumentException if resource does not exists
    */
   String getDomainNameByResource(Resource resource);

   /**
    * Returns the domains which are descendants of the specified domain.
    * The returned set includes the specified domain (unless the specified domain does not exist);
    * in other words, a domain is considered its own descendant
    * <p/>
    * Note that this returns not just the names of direct first-level descendant domains, but the names of all descendant
    * domains, regardless of level
    *
    * @param domainName a domain name for which to retrieve the descendants
    * @return a set of unique string domain names, including the domain queried about, or an empty set if the specified domain does not exist
    */
   Set<String> getDomainDescendants(String domainName);

   /**
    * Returns information about the specified resource class.
    *
    * @param resourceClassName a string resource class name about which to retrieve information
    * @return a ResourceClassInfo object containing information about the resource class
    * @throws java.lang.IllegalArgumentException if no resource class of resourceClassName exists
    */
   ResourceClassInfo getResourceClassInfo(String resourceClassName);

   /**
    * Returns information about the resource class to which the specified resource belongs.
    *
    * @param resource a resource about whose resource class to retrieve information
    * @return returns a ResourceClassInfo object containing information about the resource class of the specified resource
    * @throws java.lang.IllegalArgumentException if the specified resource reference does not exist
    */
   ResourceClassInfo getResourceClassInfoByResource(Resource resource);

   /**
    * Returns the list of names of all resource classes defined in the system
    *
    * @return a list of string resource class names
    */
   List<String> getResourceClassNames();

   /**
    * Returns the list of all resource permission names defined for the specified resource class name,
    * including the applicable system permissions as well as any custom permissions
    *
    * @param resourceClassName the resource class name for which the permissions should be retrieved
    * @return a list of string permission names
    * @throws java.lang.IllegalArgumentException if no resource class of resourceClassName exists
    */
   List<String> getResourcePermissionNames(String resourceClassName);

   /**
    * Creates a new resource class.
    * <p/>
    * Note that creating a resource is only allowed when this session is authenticated with
    * the system-resource (resourceId=0)
    *
    * @param resourceClassName            a string resource class name
    * @param authenticatable              indicates if resources of this resource class are authenticatable.
    *                                     Typically only resource classes that represent users will be marked as authenticatable.
    * @param unauthenticatedCreateAllowed if true, a resource of this resource class may be created from an
    *                                     unauthenticated session, otherwise the session must be authenticated
    *                                     to create resources of this class.
    * @throws java.lang.IllegalArgumentException       if a resource class of resourceClassName already exists
    * @throws com.acciente.oacc.NotAuthorizedException if the authenticated resource is not the system resource
    */
   void createResourceClass(String resourceClassName,
                            boolean authenticatable,
                            boolean unauthenticatedCreateAllowed);

   /**
    * Creates a new resource permission that may be applied to objects of the specified resource class.
    * <p/>
    * Note that creating a resource permission is only allowed when this session is authenticated with
    * the system-resource (resourceId=0) and that the new permissionName may not start with an asterisk ('*')
    *
    * @param resourceClassName a string resource class name
    * @param permissionName    the string representing the name of this permission.
    *                          Samples of typical permission names:
    *                          READ, WRITE, UPDATE, VIEW, POST, EDIT, etc.
    * @throws java.lang.IllegalArgumentException       if no resource class of resourceClassName exists, or
    *                                                  if a resource permission of permissionName already exists, or
    *                                                  if the permissionName is prefixed with an asterisk ('*')
    * @throws com.acciente.oacc.NotAuthorizedException if the authenticated resource is not the system resource
    */
   void createResourcePermission(String resourceClassName, String permissionName);

   /**
    * Creates a new domain (at the root level of the domain hierarchy).
    *
    * @param domainName a string domain name
    * @throws java.lang.IllegalArgumentException       if a domain of domainName already exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to create domains
    */
   void createDomain(String domainName);

   /**
    * Creates a new domain under the specified parent domain.
    *
    * @param domainName       a string domain name
    * @param parentDomainName the domain name of the parent domain
    * @throws java.lang.IllegalArgumentException       if no domain of parentDomain exists, or
    *                                                  if a domain of domainName already exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to create
    *                                                  child domains under the specified parent domain
    */
   void createDomain(String domainName, String parentDomainName);

   /**
    * Deletes the specified domain (and any nested child domains).
    * <p/>
    * Note this method performs a cascading delete of any permissions any resource has as an accessor resource to
    * this domain or to a resource class-domain tuple, before the specified domain is itself deleted.
    *
    * @param domainName a string domain name
    * @return <strong>true</strong> if the domain was deleted as a result of this call,
    *         <strong>false</strong> if the specified domain did not exist
    * @throws java.lang.IllegalArgumentException       if the specified domain contains any resources
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to delete the
    *                                                  specified domain
    */
   boolean deleteDomain(String domainName);

   /**
    * Creates a new resource of the specified resource class within the specified domain.
    * <p/>
    * Note that a custom {@link AuthenticationProvider} implementation is required to support
    * creation of an authenticatable resource without providing explicit credentials
    *
    * @param resourceClassName a string resource class name
    * @param domainName        a string domain name
    * @return the resource reference of the newly created resource
    * @throws java.lang.IllegalArgumentException if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to create a new resource
    *                                                  of the specified resource class in the specified domain
    * @throws com.acciente.oacc.OaccException          if creating the new resource would introduce a cycle between the
    *                                                  session resource and new resource via permission inheritance
    */
   Resource createResource(String resourceClassName, String domainName);

   /**
    * Creates a new authenticatable resource of the specified resource class within the specified domain.
    *
    * @param resourceClassName a string resource class name
    * @param domainName        a string domain name
    * @param credentials       the credentials to authenticate the new resource
    * @return the resource reference of the newly created resource
    * @throws java.lang.IllegalArgumentException if no resource class of resourceClassName exists, or
    *                                            if resource class is not authenticatable, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to create a new resource
    *                                                  of the specified resource class in the specified domain
    * @throws com.acciente.oacc.OaccException          if creating the new resource would introduce a cycle between the
    *                                                  session resource and new resource via permission inheritance
    */
   Resource createResource(String resourceClassName, String domainName, Credentials credentials);

   /**
    * Creates a new resource of the specified resource class within the specified domain, with the specified external id.
    * <p/>
    * Note that a custom {@link AuthenticationProvider} implementation is required to support
    * creation of an authenticatable resource without providing explicit credentials
    *
    * @param resourceClassName a string resource class name
    * @param domainName        a string domain name
    * @param externalId        a unique string identifier for the new resource
    * @return the resource reference of the newly created resource
    * @throws java.lang.IllegalArgumentException if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists, or
    *                                            if a resource with externalId already exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to create a new resource
    *                                                  of the specified resource class in the specified domain
    * @throws com.acciente.oacc.OaccException          if creating the new resource would introduce a cycle between the
    *                                                  session resource and new resource via permission inheritance
    */
   Resource createResource(String resourceClassName, String domainName, String externalId);

   /**
    * Creates a new authenticatable resource of the specified resource class within the specified domain, with
    * the specified external id.
    *
    * @param resourceClassName a string resource class name
    * @param domainName        a string domain name
    * @param externalId        a unique string identifier for the new resource
    * @param credentials       the credentials to authenticate the new resource
    * @return the resource reference of the newly created resource
    * @throws java.lang.IllegalArgumentException if no resource class of resourceClassName exists, or
    *                                            if resource class is not authenticatable, or
    *                                            if no domain of domainName exists, or
    *                                            if a resource with externalId already exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to create a new resource
    *                                                  of the specified resource class in the specified domain
    * @throws com.acciente.oacc.OaccException          if creating the new resource would introduce a cycle between the
    *                                                  session resource and new resource via permission inheritance
    */
   Resource createResource(String resourceClassName, String domainName, String externalId, Credentials credentials);

   /**
    * Sets the external id of the specified resource as an alternative resource identifier, if none was previously set.
    * <p/>
    * The externalId has to be globally unique, i.e. it has to be unique across all resource classes and domains.
    *
    * @param resource   the resource for which to set the alternative identifier
    * @param externalId a globally unique string identifier for the resource
    * @return the fully resolved resource reference of the updated resource, i.e. with both resourceId and externalId
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to set the specified
    *                                                  resource's externalId by having the *CREATE system permission
    * @throws java.lang.IllegalArgumentException if another resource with externalId already exists, or
    *                                            if the specified resource has previously been associated with another externalId
    */
   Resource setExternalId(Resource resource, String externalId);

   /**
    * Deletes the specified resource.
    * <p/>
    * Note this method performs a cascading delete of any permissions the obsolete resource has as
    * an accessor resource OR as an accessed resource, before the specified resource is itself deleted.
    *
    * @param obsoleteResource the resource to be deleted
    * @return <strong>true</strong> if the resource was deleted as a result of this call,
    *         <strong>false</strong> if the specified resource did not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to delete the
    *                                                  specified obsolete resource
    */
   boolean deleteResource(Resource obsoleteResource);

   /**
    * Sets the domain permissions the specified accessor resource will receive if it created a domain.
    * <p/>
    * Note that the system-defined CREATE permission needs to be included in the specified set of
    * domain create permissions, unless all permissions should be revoked.
    * <p/>
    * Also note that this method replaces any <em>direct</em> domain create permissions previously
    * granted, but does not affect any domain create permissions the specified accessor resource
    * receives via <em>inheritance</em>.
    *
    * @param accessorResource        the resource to which the privilege should be granted
    * @param domainCreatePermissions the permissions to be granted to the specified domain
    * @throws java.lang.IllegalArgumentException if domainCreatePermissions does not contain the *CREATE permission, or
    *                                            if accessorResource reference does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to set
    *                                                  domain create permissions on the specified accessor resource
    */
   void setDomainCreatePermissions(Resource accessorResource,
                                   Set<DomainCreatePermission> domainCreatePermissions);

   /**
    * Adds to the set of domain permissions the specified accessor resource will receive if it created a domain.
    * <p/>
    * Note that the system-defined CREATE permission needs to be included in the specified set of
    * domain create permissions, <em>unless</em> the accessor has already been directly granted that privilege beforehand.
    * <p/>
    * This method does <em>not</em> replace any domain create permissions previously granted, but can only add to the
    * set, or upgrade an existing permission's granting rights. Furthermore, removing the 'withGrant' option from an
    * existing permission is not possible with this method alone - revoke the permission first, then re-grant without
    * the 'withGrant' option, or use {@link #setDomainCreatePermissions} to specify all direct create permissions.
    * <p/>
    * If the accessor resource already has privileges that exceed the requested permission, the requested grant has
    * no effect on the existing permission. If the accessor resource has an existing permission that is <em>incompatible</em>
    * with the requested permission - a request for an ungrantable create permission with grantable post-create "(perm /G)"
    * when accessor already has grantable create permission with ungrantable post-create "(perm) /G", or vice versa - this
    * method will throw an IllegalArgumentException.
    *
    * @param accessorResource        the resource to which the privilege should be granted
    * @param domainCreatePermissions the permissions to be granted to the specified domain
    * @throws java.lang.IllegalArgumentException if domainCreatePermissions does not contain the *CREATE permission when
    *                                            the accessor resource does not have direct *CREATE permission already, or
    *                                            if accessorResource reference does not exist, or
    *                                            if domainCreatePermissions is empty, or
    *                                            if domainCreatePermissions contains multiple instances of the same
    *                                            system or post-create permission that only differ in the 'withGrant' attribute, or
    *                                            if a requested domain create permission is incompatible with an already
    *                                            existing permission as described above
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to set
    *                                                  domain create permissions on the specified accessor resource
    */
   void grantDomainCreatePermissions(Resource accessorResource,
                                     Set<DomainCreatePermission> domainCreatePermissions);

   /**
    * Adds to the set of domain permissions the specified accessor resource will receive if it created a domain.
    * <p/>
    * Note that the system-defined CREATE permission needs to be included in the specified set of
    * domain create permissions, <em>unless</em> the accessor has already been directly granted that privilege beforehand.
    * <p/>
    * This method does <em>not</em> replace any domain create permissions previously granted, but can only add to the
    * set, or upgrade an existing permission's granting rights. Furthermore, removing the 'withGrant' option from an
    * existing permission is not possible with this method alone - revoke the permission first, then re-grant without
    * the 'withGrant' option, or use {@link #setDomainCreatePermissions} to specify all direct create permissions.
    * <p/>
    * If the accessor resource already has privileges that exceed the requested permission, the requested grant has
    * no effect on the existing permission. If the accessor resource has an existing permission that is <em>incompatible</em>
    * with the requested permission - a request for an ungrantable create permission with grantable post-create "(perm /G)"
    * when accessor already has grantable create permission with ungrantable post-create "(perm) /G", or vice versa - this
    * method will throw an IllegalArgumentException.
    *
    * @param accessorResource        the resource to which the privilege should be granted
    * @param domainCreatePermission  the permission to be granted to the specified domain
    * @param domainCreatePermissions the other (optional) permissions to be granted to the specified domain
    * @throws java.lang.IllegalArgumentException if domainCreatePermissions does not contain the *CREATE permission when
    *                                            the accessor resource does not have direct *CREATE permission already, or
    *                                            if accessorResource reference does not exist, or
    *                                            if domainCreatePermissions contains multiple instances of the same
    *                                            system or post-create permission that only differ in the 'withGrant' attribute, or
    *                                            if a requested domain create permission is incompatible with an already
    *                                            existing permission as described above
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to set
    *                                                  domain create permissions on the specified accessor resource
    */
   void grantDomainCreatePermissions(Resource accessorResource,
                                     DomainCreatePermission domainCreatePermission,
                                     DomainCreatePermission... domainCreatePermissions);

   /**
    * Revokes the specified direct domain permissions from set the specified accessor resource will receive if it
    * created a domain.
    * <p/>
    * This call does not change <em>inherited</em> domain create permissions the specified accessor resource currently is
    * privileged to.
    * Note that this method revokes the specified permission regardless of any specified granting right and regardless
    * of the granting right the accessor has for the permission currently!
    * <p/>
    * Also note that after revoking the specified permissions, the remaining set of direct permissions <em>must</em> still
    * contain the *CREATE system permission. Attempting to revoke a proper subset of the current direct permissions that
    * includes the *CREATE permission will result in an IllegalArgumentException.
    * <p/>
    * This method is idempotent, that is, when a specified permission is no longer granted, repeated calls to
    * this method will have no effect.
    *
    * @param accessorResource        the resource from which the privilege should be revoked
    * @param domainCreatePermissions the create permissions to be revoked
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist, or
    *                                            if domainCreatePermissions is empty, or
    *                                            if domainCreatePermissions contains multiple instances of the same
    *                                            system or post-create permission that only differ in the 'withGrant' attribute, or
    *                                            if domainCreatePermissions contains *CREATE system permission and is a
    *                                            proper subset of the currently granted direct domain create permissions
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant (in this case
    *                                                  revoke) domain create permissions on the specified accessor resource
    */
   void revokeDomainCreatePermissions(Resource accessorResource,
                                      Set<DomainCreatePermission> domainCreatePermissions);

   /**
    * Revokes the specified direct domain permissions from set the specified accessor resource will receive if it
    * created a domain.
    * <p/>
    * This call does not change <em>inherited</em> domain create permissions the specified accessor resource currently is
    * privileged to.
    * Note that this method revokes the specified permission regardless of any specified granting right and regardless
    * of the granting right the accessor has for the permission currently!
    * <p/>
    * Also note that after revoking the specified permissions, the remaining set of direct permissions <em>must</em> still
    * contain the *CREATE system permission. Attempting to revoke a proper subset of the current direct permissions that
    * includes the *CREATE permission will result in an IllegalArgumentException.
    * <p/>
    * This method is idempotent, that is, when a specified permission is no longer granted, repeated calls to
    * this method will have no effect.
    *
    * @param accessorResource        the resource from which the privilege should be revoked
    * @param domainCreatePermission  the create permission to be revoked
    * @param domainCreatePermissions the other (optional) create permissions to be revoked
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist, or
    *                                            if domainCreatePermissions contains multiple instances of the same
    *                                            system or post-create permission that only differ in the 'withGrant' attribute, or
    *                                            if domainCreatePermissions contains *CREATE system permission and is a
    *                                            proper subset of the currently granted direct domain create permissions
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant (in this case
    *                                                  revoke) domain create permissions on the specified accessor resource
    */
   void revokeDomainCreatePermissions(Resource accessorResource,
                                      DomainCreatePermission domainCreatePermission,
                                      DomainCreatePermission... domainCreatePermissions);

   /**
    * Gets all direct domain create permissions the specified accessor resource has.
    * <p/>
    * This method only takes into account direct domain create permissions and does not return the
    * domain create permissions the specified accessor resource inherits from another resource.
    *
    * @param accessorResource the accessor resource relative which permissions should be returned
    * @return a set of direct domain create permission the accessor resource has
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<DomainCreatePermission> getDomainCreatePermissions(Resource accessorResource);

   /**
    * Gets all effective domain create permissions the specified accessor resource has, both directly
    * and inherited (from other resources).
    *
    * @param accessorResource the accessor resource relative which permissions should be returned
    * @return a set of effective domain create permission the accessor resource has
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<DomainCreatePermission> getEffectiveDomainCreatePermissions(Resource accessorResource);

   /**
    * Sets the direct domain permissions the specified accessor resource has on the specified domain.
    * <p/>
    * Note that this method overwrites any <em>direct</em> domain permissions to the specified domain that
    * the accessor has, <em>including permissions granted by other resources</em>.
    * <p/>
    * This call does not change <em>inherited</em> domain permissions the specified accessor resource has
    * on the specified domain, or any domain permissions already granted on <em>ancestors</em> of the domain.
    *
    * @param accessorResource  the resource to which the privilege should be granted
    * @param domainName        a string domain name
    * @param domainPermissions the permissions to be granted on the specified domain
    * @throws java.lang.IllegalArgumentException       if accessorResource reference does not exist, or
    *                                                  if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to set
    *                                                  domain permissions on the specified domain
    */
   void setDomainPermissions(Resource accessorResource,
                             String domainName,
                             Set<DomainPermission> domainPermissions);

   /**
    * Adds to the direct domain permissions the specified accessor resource has on the specified domain.
    * <p/>
    * This call does not change <em>inherited</em> domain permissions the specified accessor resource has
    * on the specified domain, or any domain permissions already granted on <em>ancestors</em> of the domain.
    *
    * This method does <em>not</em> replace any domain permissions previously granted, but can only add to the set.
    * Furthermore, removing the 'withGrant' option from an existing permission is not possible with this method
    * alone - revoke the permission first, then re-grant without the 'withGrant' option, or use {@link
    * #setDomainPermissions} to specify all direct permissions
    *
    * @param accessorResource  the resource to which the privilege should be granted
    * @param domainName        a string domain name
    * @param domainPermissions the permissions to be granted on the specified domain
    * @throws java.lang.IllegalArgumentException       if accessorResource reference does not exist, or
    *                                                  if no domain of domainName exists, or
    *                                                  if domainPermissions is empty, or
    *                                                  if domainPermissions contains multiple instances of the same
    *                                                  permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to set
    *                                                  domain permissions on the specified domain
    */
   void grantDomainPermissions(Resource accessorResource,
                               String domainName,
                               Set<DomainPermission> domainPermissions);

   /**
    * Adds to the direct domain permissions the specified accessor resource has on the specified domain.
    * <p/>
    * This call does not change <em>inherited</em> domain permissions the specified accessor resource has
    * on the specified domain, or any domain permissions already granted on <em>ancestors</em> of the domain.
    *
    * This method does <em>not</em> replace any domain permissions previously granted, but can only add to the set.
    * Furthermore, removing the 'withGrant' option from an existing permission is not possible with this method
    * alone - revoke the permission first, then re-grant without the 'withGrant' option, or use {@link
    * #setDomainPermissions} to specify all direct permissions
    *
    * @param accessorResource  the resource to which the privilege should be granted
    * @param domainName        a string domain name
    * @param domainPermission  the permission to be granted on the specified domain
    * @param domainPermissions the other (optional) permissions to be granted on the specified domain
    * @throws java.lang.IllegalArgumentException       if accessorResource reference does not exist, or
    *                                                  if no domain of domainName exists, or
    *                                                  if domainPermissions contains multiple instances of the same
    *                                                  permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to set
    *                                                  domain permissions on the specified domain
    */
   void grantDomainPermissions(Resource accessorResource,
                               String domainName,
                               DomainPermission domainPermission,
                               DomainPermission... domainPermissions);

   /**
    * Revokes the direct domain permissions from set the specified accessor resource has on the specified domain.
    * <p/>
    * This call does not change <em>inherited</em> domain permissions the specified accessor resource has
    * on the specified domain, or any domain permissions already granted on <em>ancestors</em> of the domain.
    *
    * Note that this method revokes the specified permission regardless of any specified granting right and regardless
    * of the granting right the accessor has on the accessed resource!
    * This method is idempotent, that is, when a specified permission is no longer granted, repeated calls to
    * this method will have no effect.
    *
    * @param accessorResource  the resource from which the privilege should be revoked
    * @param domainName        a string domain name
    * @param domainPermissions the permission to be revoked on the specified domain
    * @throws java.lang.IllegalArgumentException       if accessorResource reference does not exist, or
    *                                                  if no domain of domainName exists, or
    *                                                  if domainPermissions is empty, or
    *                                                  if domainPermissions contains multiple instances of the same
    *                                                  permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant (or in this
    *                                                  case revoke) domain permissions on the specified domain
    */
   void revokeDomainPermissions(Resource accessorResource,
                                String domainName,
                                Set<DomainPermission> domainPermissions);

   /**
    * Revokes the direct domain permissions from set the specified accessor resource has on the specified domain.
    * <p/>
    * This call does not change <em>inherited</em> domain permissions the specified accessor resource has
    * on the specified domain, or any domain permissions already granted on <em>ancestors</em> of the domain.
    *
    * Note that this method revokes the specified permission regardless of any specified granting right and regardless
    * of the granting right the accessor has on the accessed resource!
    * This method is idempotent, that is, when a specified permission is no longer granted, repeated calls to
    * this method will have no effect.
    *
    * @param accessorResource  the resource from which the privilege should be revoked
    * @param domainName        a string domain name
    * @param domainPermission  the permission to be revoked on the specified domain
    * @param domainPermissions the other (optional) permissions to be revoked on the specified domain
    * @throws java.lang.IllegalArgumentException       if accessorResource reference does not exist, or
    *                                                  if no domain of domainName exists, or
    *                                                  if domainPermissions contains multiple instances of the same
    *                                                  permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant (or in this
    *                                                  case revoke) domain permissions on the specified domain
    */
   void revokeDomainPermissions(Resource accessorResource,
                                String domainName,
                                DomainPermission domainPermission,
                                DomainPermission... domainPermissions);

   /**
    * Gets all domain permissions the accessor resource has directly to the specified domain.
    * <p/>
    * This method only takes into account direct domain permissions, but not any inherited
    * domain permissions and not any domain permissions the accessor may have to ancestors of
    * the specified domain.
    *
    * @param accessorResource the accessor resource relative which permissions should be returned
    * @param domainName       a string domain name
    * @return the set of all direct domain permission the accessor resource has to the domain
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<DomainPermission> getDomainPermissions(Resource accessorResource,
                                              String domainName);

   /**
    * Gets all domain permissions the accessor resource has directly to any domain, mapped by domain name.
    * <p/>
    * This method only takes into account direct domain permissions, but not any inherited domain
    * permissions and not any domain permissions the accessor may have to ancestors of each domain.
    * The result is returned as a map keyed by the domain name, where each value is the
    * set of direct permissions for the domain name of the key.
    *
    * @param accessorResource the accessor resource relative which permissions should be returned
    * @return the sets of direct domain permission the accessor resource has to any domain, mapped by domain name
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Map<String, Set<DomainPermission>> getDomainPermissionsMap(Resource accessorResource);

   /**
    * Gets all effective domain permissions the accessor resource has to the specified domain.
    * <p/>
    * This method takes into account direct domain permissions, inherited domain permissions
    * and any domain permissions the accessor may have to ancestors of the specified domain, as well
    * as any super-user privileges.
    * In other words, this method will return the domain permissions the specified accessor
    * resource has to the specified domain as a result of the permissions the accessor has on
    * any ancestor (parent, or grandparent, etc.) of that domain.
    *
    * @param accessorResource the accessor resource relative which permissions should be returned
    * @param domainName       a string domain name
    * @return the set of all effective domain permission the accessor resource has to the domain
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<DomainPermission> getEffectiveDomainPermissions(Resource accessorResource,
                                                       String domainName);

   /**
    * Gets all effective domain permissions the accessor resource has to any domain, mapped by domain name.
    * <p/>
    * This method takes into account direct domain permissions, inherited domain permissions
    * and any domain permissions the accessor may have to ancestors of each domain, as well
    * as any super-user privileges.
    * The result is returned as a map keyed by the domain name, where each value is the
    * set of permissions for the domain name of the key.
    *
    * @param accessorResource the accessor resource relative which permissions should be returned
    * @return the sets of effective domain permission the accessor resource has to any domain, mapped by domain name
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Map<String, Set<DomainPermission>> getEffectiveDomainPermissionsMap(Resource accessorResource);

   /**
    * Sets the resource permissions the specified accessor resource will receive directly, if it
    * created a resource of the specified resource class in the specified domain.
    * <p/>
    * Note that the system-defined CREATE permission must be included in the specified set of
    * resource create permissions, unless all permissions should be revoked.
    * <p/>
    * Including the CREATE permission allows the accessor resource to create resources of the
    * specified resource class and domain. But if the CREATE permission is the <em>only</em> one specified,
    * then the accessor would not receive <em>any</em> direct permissions on the newly created resource.
    * This is appropriate, for example, if the accessor would already obtain privileges to
    * the newly created resource via global resource permissions, or if indeed the accessor
    * should not receive any direct access to the newly created resource.
    * <p/>
    * Also note that this method replaces any <em>direct</em> resource create permissions previously
    * granted, but does not affect any resource create permissions the specified accessor resource
    * receives via <em>inheritance</em> or from the specified domain's <em>ancestors</em>.
    *
    * @param accessorResource          the resource to which the privilege should be granted
    * @param resourceClassName         a string resource class name
    * @param domainName                a string representing a valid domain name
    * @param resourceCreatePermissions a set of resource create permissions to be granted
    * @throws java.lang.IllegalArgumentException if accessorResource reference is invalid, or
    *                                            if no domain of domainName exists, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if resourceCreatePermissions does not contain *CREATE permission, or
    *                                            if resourceCreatePermissions contains post-create permissions invalid for
    *                                            the specified resource class (incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourceCreatePermissions contains multiple instances of the same
    *                                            post-create permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to set
    *                                                  resource create permissions on the specified accessor resource
    */
   void setResourceCreatePermissions(Resource accessorResource,
                                     String resourceClassName,
                                     String domainName,
                                     Set<ResourceCreatePermission> resourceCreatePermissions);

   /**
    * Adds to the set of resource permissions the specified accessor resource will receive directly, if it
    * created a resource of the specified resource class in the specified domain.
    * <p/>
    * Note that the system-defined CREATE permission must be included in the specified set of
    * resource create permissions, <em>unless</em> the accessor has already been directly granted that privilege beforehand.
    * <p/>
    * Granting the CREATE permission allows the accessor resource to create resources of the
    * specified resource class and domain. But if the CREATE permission is the <em>only</em> directly granted one,
    * then the accessor would not receive <em>any</em> direct permissions on the newly created resource.
    * This is appropriate, for example, if the accessor would already obtain privileges to
    * the newly created resource via global resource permissions, or if indeed the accessor
    * should not receive any direct access to the newly created resource.
    * <p/>
    * This method does <em>not</em> replace any resource create permissions previously granted, but can only add to the
    * set, or upgrade an existing permission's granting rights. Furthermore, removing the 'withGrant' option from an
    * existing permission is not possible with this method alone - revoke the permission first, then re-grant without
    * the 'withGrant' option, or use {@link #setResourceCreatePermissions} to specify all direct create permissions
    * <p/>
    * If the accessor resource already has privileges that exceed the requested permission, the requested grant has
    * no effect on the existing permission. If the accessor resource has an existing permission that is <em>incompatible</em>
    * with the requested permission - a request for an ungrantable create permission with grantable post-create "(perm /G)"
    * when accessor already has grantable create permission with ungrantable post-create "(perm) /G", or vice versa - this
    * method will throw an IllegalArgumentException.
    *
    * @param accessorResource          the resource to which the privilege should be granted
    * @param resourceClassName         a string resource class name
    * @param domainName                a string representing a valid domain name
    * @param resourceCreatePermissions the resource create permissions to be granted
    * @throws java.lang.IllegalArgumentException if accessorResource reference is invalid, or
    *                                            if no domain of domainName exists, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if resourceCreatePermissions is empty, or
    *                                            if resourceCreatePermissions does not contain *CREATE permission when
    *                                            the accessor resource does not have direct *CREATE permission already, or
    *                                            if resourceCreatePermissions contains post-create permissions invalid for
    *                                            the specified resource class (incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourceCreatePermissions contains multiple instances of the same
    *                                            post-create permission that only differ in the 'withGrant' attribute, or
    *                                            if a requested resource create permission is incompatible with an already
    *                                            existing permission as described above
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to set
    *                                                  resource create permissions on the specified accessor resource
    */
   void grantResourceCreatePermissions(Resource accessorResource,
                                       String resourceClassName,
                                       String domainName,
                                       Set<ResourceCreatePermission> resourceCreatePermissions);
   /**
    * Adds to the set of resource permissions the specified accessor resource will receive directly, if it
    * created a resource of the specified resource class in the specified domain.
    * <p/>
    * Note that the system-defined CREATE permission must be included in the specified set of
    * resource create permissions, <em>unless</em> the accessor has already been directly granted that privilege beforehand.
    * <p/>
    * Granting the CREATE permission allows the accessor resource to create resources of the
    * specified resource class and domain. But if the CREATE permission is the <em>only</em> directly granted one,
    * then the accessor would not receive <em>any</em> direct permissions on the newly created resource.
    * This is appropriate, for example, if the accessor would already obtain privileges to
    * the newly created resource via global resource permissions, or if indeed the accessor
    * should not receive any direct access to the newly created resource.
    * <p/>
    * This method does <em>not</em> replace any resource create permissions previously granted, but can only add to the
    * set, or upgrade an existing permission's granting rights. Furthermore, removing the 'withGrant' option from an
    * existing permission is not possible with this method alone - revoke the permission first, then re-grant without
    * the 'withGrant' option, or use {@link #setResourceCreatePermissions} to specify all direct create permissions
    * <p/>
    * If the accessor resource already has privileges that exceed the requested permission, the requested grant has
    * no effect on the existing permission. If the accessor resource has an existing permission that is <em>incompatible</em>
    * with the requested permission - a request for an ungrantable create permission with grantable post-create "(perm /G)"
    * when accessor already has grantable create permission with ungrantable post-create "(perm) /G", or vice versa - this
    * method will throw an IllegalArgumentException.
    *
    * @param accessorResource          the resource to which the privilege should be granted
    * @param resourceClassName         a string resource class name
    * @param domainName                a string representing a valid domain name
    * @param resourceCreatePermission  the resource create permission to be granted
    * @param resourceCreatePermissions the other (optional) resource create permissions to be granted
    * @throws java.lang.IllegalArgumentException if accessorResource reference is invalid, or
    *                                            if no domain of domainName exists, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if resourceCreatePermissions does not contain *CREATE permission when
    *                                            the accessor resource does not have direct *CREATE permission already, or
    *                                            if resourceCreatePermissions contains post-create permissions invalid for
    *                                            the specified resource class (incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourceCreatePermissions contains multiple instances of the same
    *                                            post-create permission that only differ in the 'withGrant' attribute, or
    *                                            if a requested resource create permission is incompatible with an already
    *                                            existing permission as described above
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to set
    *                                                  resource create permissions on the specified accessor resource
    */
   void grantResourceCreatePermissions(Resource accessorResource,
                                       String resourceClassName,
                                       String domainName,
                                       ResourceCreatePermission resourceCreatePermission,
                                       ResourceCreatePermission... resourceCreatePermissions);

   /**
    * Revokes the specified permissions from the set of resource permissions the specified accessor resource will
    * receive directly, if it created a resource of the specified resource class in the specified domain.
    * <p/>
    * This call does not change <em>inherited</em> resource create permissions the specified accessor resource currently is
    * privileged to.
    * Note that this method revokes the specified permission regardless of any specified granting right and regardless
    * of the granting right the accessor has for the permission currently!
    * <p/>
    * Also note that after revoking the specified permissions, the remaining set of direct permissions <em>must</em> still
    * contain the *CREATE system permission. Attempting to revoke a proper subset of the current direct permissions that
    * includes the *CREATE permission will result in an IllegalArgumentException.
    * <p/>
    * This method is idempotent, that is, when a specified permission is no longer granted, repeated calls to
    * this method will have no effect.
    *
    * @param accessorResource          the resource from which the privilege should be revoked
    * @param resourceClassName         a string resource class name
    * @param domainName                a string representing a valid domain name
    * @param resourceCreatePermissions the resource create permissions to be revoked
    * @throws java.lang.IllegalArgumentException if accessorResource reference is invalid, or
    *                                            if no domain of domainName exists, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if resourceCreatePermissions is empty, or
    *                                            if resourceCreatePermissions contains *CREATE system permission and is a
    *                                            proper subset of the currently granted direct resource create permissions, or
    *                                            if resourcePermissions contains permissions invalid for the specified
    *                                            resource class (incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourceCreatePermissions contains multiple instances of the same
    *                                            post-create permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant (or in this case
    *                                                  revoke) resource create permissions on the specified accessor resource
    */
   void revokeResourceCreatePermissions(Resource accessorResource,
                                        String resourceClassName,
                                        String domainName,
                                        Set<ResourceCreatePermission> resourceCreatePermissions);

   /**
    * Revokes the specified permissions from the set of resource permissions the specified accessor resource will
    * receive directly, if it created a resource of the specified resource class in the specified domain.
    * <p/>
    * This call does not change <em>inherited</em> resource create permissions the specified accessor resource currently is
    * privileged to.
    * Note that this method revokes the specified permission regardless of any specified granting right and regardless
    * of the granting right the accessor has for the permission currently!
    * <p/>
    * Also note that after revoking the specified permissions, the remaining set of direct permissions <em>must</em> still
    * contain the *CREATE system permission. Attempting to revoke a proper subset of the current direct permissions that
    * includes the *CREATE permission will result in an IllegalArgumentException.
    * <p/>
    * This method is idempotent, that is, when a specified permission is no longer granted, repeated calls to
    * this method will have no effect.
    *
    * @param accessorResource          the resource from which the privilege should be revoked
    * @param resourceClassName         a string resource class name
    * @param domainName                a string representing a valid domain name
    * @param resourceCreatePermission  the resource create permission to be revoked
    * @param resourceCreatePermissions the other (optional) resource create permissions to be revoked
    * @throws java.lang.IllegalArgumentException if accessorResource reference is invalid, or
    *                                            if no domain of domainName exists, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if resourceCreatePermissions contains *CREATE system permission and is a
    *                                            proper subset of the currently granted direct resource create permissions, or
    *                                            if resourcePermissions contains permissions invalid for the specified
    *                                            resource class (incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourceCreatePermissions contains multiple instances of the same
    *                                            post-create permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant (or in this case
    *                                                  revoke) resource create permissions on the specified accessor resource
    */
   void revokeResourceCreatePermissions(Resource accessorResource,
                                        String resourceClassName,
                                        String domainName,
                                        ResourceCreatePermission resourceCreatePermission,
                                        ResourceCreatePermission... resourceCreatePermissions);

   /**
    * Gets all direct resource create permissions the accessor resource has to the specified
    * resource class in the specified domain (which define a subset of the resource permissions
    * the accessor resource would receive directly, if it created a resource of the specified
    * resource class in the specified domain).
    * <p/>
    * This method only takes into account direct resource create permissions, but not inherited
    * resource create permissions and not any resource create permissions the accessor may have to
    * ancestors of the specified domain.
    *
    * @param accessorResource  the accessor resource relative which permissions should be returned
    * @param resourceClassName a string resource class name
    * @param domainName        a string representing a valid domain name
    * @return a set of direct resource create permissions
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<ResourceCreatePermission> getResourceCreatePermissions(Resource accessorResource,
                                                              String resourceClassName,
                                                              String domainName);

   /**
    * Gets all effective resource create permissions the accessor resource has to the specified
    * resource class in the specified domain (which effectively define the resource permissions
    * the accessor resource will receive directly, if it created a resource of the specified
    * resource class in the specified domain).
    * <p/>
    * This method takes into account direct resource create permissions, inherited
    * resource create permissions and any resource create permissions the accessor may have to
    * ancestors of the specified domain, as well as any super-user privileges.
    *
    * @param accessorResource  the accessor resource relative which permissions should be returned
    * @param resourceClassName a string resource class name
    * @param domainName        a string representing a valid domain name
    * @return a set of effective resource create permissions
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<ResourceCreatePermission> getEffectiveResourceCreatePermissions(Resource accessorResource,
                                                                       String resourceClassName,
                                                                       String domainName);

   /**
    * Gets all direct resource create permissions the accessor resource has to any resource class in
    * any domain, mapped by domain name and resource class name.
    * <p/>
    * Direct resource create permissions make up a subset of the resource permissions the accessor resource
    * will receive directly, if it created a resource of a resource class in a domain.
    * <p/>
    * This method only takes into account direct resource create permissions, but not inherited
    * resource create permissions and not any resource create permissions the accessor may have to
    * ancestors of each domain.
    * <p/>
    * The result is returned as a map keyed by the domain name, where each value is another
    * map keyed by resource class name, in which each value is the set of direct resource create permissions
    * for the resource class and domain name of the respective keys.
    *
    * @param accessorResource the accessor resource relative which permissions should be returned
    * @return a map of maps of direct resource create permissions, keyed by domain name and resource class name
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Map<String, Map<String, Set<ResourceCreatePermission>>> getResourceCreatePermissionsMap(Resource accessorResource);

   /**
    * Gets all effective resource create permissions the accessor resource has to any resource class in
    * any domain, mapped by domain name and resource class name.
    * <p/>
    * Resource create permissions effectively define the resource permissions the accessor resource
    * will receive directly, if it created a resource of a resource class in a domain.
    * <p/>
    * This method takes into account direct resource create permissions, inherited
    * resource create permissions and any resource create permissions the accessor may have to
    * ancestors of each domain, as well as any super-user privileges.
    * <p/>
    * The result is returned as a map keyed by the domain name, where each value is another
    * map keyed by resource class name, in which each value is the set of resource create permissions
    * for the resource class and domain name of the respective keys.
    *
    * @param accessorResource the accessor resource relative which permissions should be returned
    * @return a map of maps of effective resource create permissions, keyed by domain name and resource class name
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Map<String, Map<String, Set<ResourceCreatePermission>>> getEffectiveResourceCreatePermissionsMap(Resource accessorResource);

   /**
    * Sets the specified resource permissions that the specified accessor resource has to the
    * specified accessed resource directly, that is not via inheritance or globally.
    * <p/>
    * This method replaces any <em>direct</em> resource permissions previously granted, but
    * does not affect any resource permissions the specified accessor resource receives via
    * <em>inheritance</em>.
    *
    * @param accessorResource    the resource to which the privilege should be granted
    * @param accessedResource    the resource on which the privilege is granted
    * @param resourcePermissions a set of resource permissions to be granted
    * @throws java.lang.IllegalArgumentException if accessorResource or accessedResource reference does not exist, or
    *                                            if resourcePermissions contains permissions invalid for resource class
    *                                            of the accessedResource(incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourcePermissions contains multiple instances of the same
    *                                            permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant the
    *                                                  specified permissions or revoke the current permissions on the
    *                                                  specified accessed resource
    * @throws com.acciente.oacc.OaccException          if granting the specified permissions would introduce a cycle
    *                                                  between accessor and accessed resource via permission inheritance
    */
   void setResourcePermissions(Resource accessorResource,
                               Resource accessedResource,
                               Set<ResourcePermission> resourcePermissions);

   /**
    * Adds the specified resource permissions to the set of permissions that the specified accessor resource
    * has to the specified accessed resource directly, that is not via inheritance or globally.
    * <p/>
    * This method does <em>not</em> replace any direct resource permissions previously granted, but
    * can only add to the set. Furthermore, removing the 'withGrant' option from an existing permission is not
    * possible with this method alone - revoke the permission first, then re-grant without the 'withGrant' option,
    * or use {@link #setResourcePermissions} to specify all direct permissions
    *
    * @param accessorResource    the resource to which the privilege should be granted
    * @param accessedResource    the resource on which the privilege is granted
    * @param resourcePermissions  the resource permission to be granted
    * @throws java.lang.IllegalArgumentException if accessorResource or accessedResource reference does not exist, or
    *                                            if resourcePermissions is empty, or
    *                                            if resourcePermissions contains permissions invalid for resource class
    *                                            of the accessedResource(incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourcePermissions contains multiple instances of the same
    *                                            permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant the
    *                                                  specified permissions on the specified accessed resource
    * @throws com.acciente.oacc.OaccException          if granting the specified permissions would introduce a cycle
    *                                                  between accessor and accessed resource via permission inheritance
    */
   void grantResourcePermissions(Resource accessorResource,
                                 Resource accessedResource,
                                 Set<ResourcePermission> resourcePermissions);

   /**
    * Adds the specified resource permissions to the set of permissions that the specified accessor resource
    * has to the specified accessed resource directly, that is not via inheritance or globally.
    * <p/>
    * This method does <em>not</em> replace any direct resource permissions previously granted, but
    * can only add to the set. Furthermore, removing the 'withGrant' option from an existing permission is not
    * possible with this method alone - revoke the permission first, then re-grant without the 'withGrant' option,
    * or use {@link #setResourcePermissions} to specify all direct permissions
    *
    * @param accessorResource    the resource to which the privilege should be granted
    * @param accessedResource    the resource on which the privilege is granted
    * @param resourcePermission  the resource permission to be granted
    * @param resourcePermissions  the other (optional) resource permissions to be granted
    * @throws java.lang.IllegalArgumentException if accessorResource or accessedResource reference does not exist, or
    *                                            if resourcePermissions contains permissions invalid for resource class
    *                                            of the accessedResource(incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourcePermissions contains multiple instances of the same
    *                                            permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant the
    *                                                  specified permissions on the specified accessed resource
    * @throws com.acciente.oacc.OaccException          if granting the specified permissions would introduce a cycle
    *                                                  between accessor and accessed resource via permission inheritance
    */
   void grantResourcePermissions(Resource accessorResource,
                                 Resource accessedResource,
                                 ResourcePermission resourcePermission,
                                 ResourcePermission... resourcePermissions);

   /**
    * Revokes the specified resource permissions from the set of permissions that the specified accessor resource
    * has to the specified accessed resource directly, that is not via inheritance or globally.
    * <p/>
    * Note that this method revokes the specified permission regardless of any specified granting right and regardless
    * of the granting right the accessor has on the accessed resource!
    * This method is idempotent, that is, when a specified permission is no longer granted, repeated calls to
    * this method will have no effect.
    *
    * @param accessorResource    the resource from which the privilege should be revoked
    * @param accessedResource    the resource on which the privilege was originally granted
    * @param resourcePermissions the resource permissions to be revoked
    * @throws java.lang.IllegalArgumentException if accessorResource or accessedResource reference does not exist, or
    *                                            if resourcePermissions is empty, or
    *                                            if resourcePermissions contains permissions invalid for resource class
    *                                            of the accessedResource(incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourcePermissions contains multiple instances of the same
    *                                            permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant (or in this case
    *                                                  revoke) the specified permissions on the specified accessed resource
    */
   void revokeResourcePermissions(Resource accessorResource,
                                  Resource accessedResource,
                                  Set<ResourcePermission> resourcePermissions);

   /**
    * Revokes the specified resource permissions from the set of permissions that the specified accessor resource
    * has to the specified accessed resource directly, that is not via inheritance or globally.
    * <p/>
    * Note that this method revokes the specified permission regardless of any specified granting right and regardless
    * of the granting right the accessor has on the accessed resource!
    * This method is idempotent, that is, when a specified permission is no longer granted, repeated calls to
    * this method will have no effect.
    *
    * @param accessorResource    the resource from which the privilege should be revoked
    * @param accessedResource    the resource on which the privilege was originally granted
    * @param resourcePermission  the resource permission to be revoked
    * @param resourcePermissions  the other (optional) resource permissions to be revoked
    * @throws java.lang.IllegalArgumentException if accessorResource or accessedResource reference does not exist, or
    *                                            if resourcePermissions contains permissions invalid for resource class
    *                                            of the accessedResource(incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourcePermissions contains multiple instances of the same
    *                                            permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant (or in this case
    *                                                  revoke) the specified permissions on the specified accessed resource
    */
   void revokeResourcePermissions(Resource accessorResource,
                                  Resource accessedResource,
                                  ResourcePermission resourcePermission,
                                  ResourcePermission... resourcePermissions);

   /**
    * Gets the resource permissions that the specified accessor resource has directly to the
    * specified accessed resource.
    * <p/>
    * This method only takes into account direct permissions, but not inherited and not global permissions
    * of the specified accessor resource.
    *
    * @param accessorResource the resource relative to which the permissions should be returned
    * @param accessedResource the resource on which the privileges were granted
    * @return a set of direct resource permissions
    * @throws java.lang.IllegalArgumentException if accessorResource or accessedResource does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<ResourcePermission> getResourcePermissions(Resource accessorResource,
                                                  Resource accessedResource);

   /**
    * Gets the effective resource permissions that the specified accessor resource has to the
    * specified accessed resource.
    * <p/>
    * This method takes into account direct, inherited and global permissions of the specified accessor resource,
    * as well as any super-user privileges.
    *
    * @param accessorResource the resource relative to which the permissions should be returned
    * @param accessedResource the resource on which the privileges were granted
    * @return a set of effective resource permissions
    * @throws java.lang.IllegalArgumentException if accessorResource or accessedResource does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<ResourcePermission> getEffectiveResourcePermissions(Resource accessorResource,
                                                           Resource accessedResource);

   /**
    * Sets the global resource permissions a resource has on any resource of the specified
    * resource class in the specified domain.
    * <p/>
    * Global resource permissions are resource permissions that are defined on a resource class for
    * a given domain and thus apply to any and all resources of that resource class and domain.
    * They are <strong>not</strong> associated directly with <em>every</em> individual resource of
    * that resource class and domain!
    * <p/>
    * Note that the system-defined CREATE resource permission can <strong>NOT</strong>
    * be set as a global resource permission, because it would be nonsensical.
    * Currently the system-defined INHERIT resource permission may also <strong>not</strong> be
    * set as a global resource permission.
    * <p/>
    * This method replaces any <em>direct</em> global resource permissions previously granted, but
    * does not affect any global resource permissions the specified accessor resource receives via
    * <em>inheritance</em> or from the specified domain's <em>ancestors</em>.
    *
    * @param accessorResource    the resource to which the privilege should be granted
    * @param resourceClassName   a string resource class name
    * @param domainName          a string domain name
    * @param resourcePermissions the set of resource permissions to be granted globally to
    *                            the specified resource class and domain
    * @throws java.lang.IllegalArgumentException if accessorResource reference is invalid, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists, or
    *                                            if resourcePermissions contains INHERIT permission, or
    *                                            if resourcePermissions contains permissions invalid for the specified
    *                                            resource class (incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourcePermissions contains multiple instances of the same
    *                                            permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to set
    *                                                  global resource permissions for the specified accessor resource
    */
   void setGlobalResourcePermissions(Resource accessorResource,
                                     String resourceClassName,
                                     String domainName,
                                     Set<ResourcePermission> resourcePermissions);

   /**
    * Adds the global resource permissions a resource has on any resource of the specified
    * resource class in the specified domain.
    * <p/>
    * Global resource permissions are resource permissions that are defined on a resource class for
    * a given domain and thus apply to any and all resources of that resource class and domain.
    * They are <strong>not</strong> associated directly with <em>every</em> individual resource of
    * that resource class and domain!
    * <p/>
    * Note that the system-defined CREATE resource permission can <strong>NOT</strong>
    * be set as a global resource permission, because it would be nonsensical.
    * Currently the system-defined INHERIT resource permission may also <strong>not</strong> be
    * set as a global resource permission.
    * <p/>
    * This method does <em>not</em> replace any global resource permissions previously granted, but
    * can only add to the set. Furthermore, removing the 'withGrant' option from an existing permission is not
    * possible with this method alone - revoke the permission first, then re-grant without the 'withGrant' option,
    * or use {@link #setGlobalResourcePermissions} to specify all direct permissions
    *
    * @param accessorResource    the resource to which the privilege should be granted
    * @param resourceClassName   a string resource class name
    * @param domainName          a string domain name
    * @param resourcePermissions the resource permission to be granted globally to
    *                            the specified resource class and domain
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists, or
    *                                            if resourcePermissions is empty, or
    *                                            if resourcePermissions contains INHERIT permission, or
    *                                            if resourcePermissions contains permissions invalid for the specified
    *                                            resource class (incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourcePermissions contains multiple instances of the same
    *                                            permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant the
    *                                                  specified permissions on the specified resource class and domain
    */
   void grantGlobalResourcePermissions(Resource accessorResource,
                                       String resourceClassName,
                                       String domainName,
                                       Set<ResourcePermission> resourcePermissions);

   /**
    * Adds the global resource permissions a resource has on any resource of the specified
    * resource class in the specified domain.
    * <p/>
    * Global resource permissions are resource permissions that are defined on a resource class for
    * a given domain and thus apply to any and all resources of that resource class and domain.
    * They are <strong>not</strong> associated directly with <em>every</em> individual resource of
    * that resource class and domain!
    * <p/>
    * Note that the system-defined CREATE resource permission can <strong>NOT</strong>
    * be set as a global resource permission, because it would be nonsensical.
    * Currently the system-defined INHERIT resource permission may also <strong>not</strong> be
    * set as a global resource permission.
    * <p/>
    * This method does <em>not</em> replace any global resource permissions previously granted, but
    * can only add to the set. Furthermore, removing the 'withGrant' option from an existing permission is not
    * possible with this method alone - revoke the permission first, then re-grant without the 'withGrant' option,
    * or use {@link #setGlobalResourcePermissions} to specify all direct permissions
    *
    * @param accessorResource    the resource to which the privilege should be granted
    * @param resourceClassName   a string resource class name
    * @param domainName          a string domain name
    * @param resourcePermission  the resource permission to be granted globally to
    *                            the specified resource class and domain
    * @param resourcePermissions the other (optional) resource permissions to be granted globally
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists, or
    *                                            if resourcePermissions contains INHERIT permission, or
    *                                            if resourcePermissions contains permissions invalid for the specified
    *                                            resource class (incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourcePermissions contains multiple instances of the same
    *                                            permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant the
    *                                                  specified permissions on the specified resource class and domain
    */
   void grantGlobalResourcePermissions(Resource accessorResource,
                                       String resourceClassName,
                                       String domainName,
                                       ResourcePermission resourcePermission,
                                       ResourcePermission... resourcePermissions);

   /**
    * Revokes the global resource permissions a resource has on any resource of the specified
    * resource class in the specified domain.
    * <p/>
    * Note that this method revokes the specified permission(s) regardless of any specified granting right and regardless
    * of the granting right the accessor currently has on the specified global permission!
    * This method is idempotent, that is, when a specified permission is no longer granted, repeated calls to
    * this method will have no effect.
    *
    * @param accessorResource    the resource from which the privilege should be revoked
    * @param resourceClassName   a string resource class name
    * @param domainName          a string domain name
    * @param resourcePermissions the resource permissions to be revoked globally from
    *                            the specified resource class and domain
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists, or
    *                                            if resourcePermissions is empty, or
    *                                            if resourcePermissions contains permissions invalid for the specified
    *                                            resource class (incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourcePermissions contains multiple instances of the same
    *                                            permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant (or in this case
    *                                                  revoke) the specified permissions on the specified resource class and domain
    */
   void revokeGlobalResourcePermissions(Resource accessorResource,
                                        String resourceClassName,
                                        String domainName,
                                        Set<ResourcePermission> resourcePermissions);

   /**
    * Revokes the global resource permissions a resource has on any resource of the specified
    * resource class in the specified domain.
    * <p/>
    * Note that this method revokes the specified permission(s) regardless of any specified granting right and regardless
    * of the granting right the accessor currently has on the specified global permission!
    * This method is idempotent, that is, when a specified permission is no longer granted, repeated calls to
    * this method will have no effect.
    *
    * @param accessorResource    the resource from which the privilege should be revoked
    * @param resourceClassName   a string resource class name
    * @param domainName          a string domain name
    * @param resourcePermission  the resource permission to be revoked globally from
    *                            the specified resource class and domain
    * @param resourcePermissions the other (optional) resource permissions to be revoked globally
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists, or
    *                                            if resourcePermissions contains permissions invalid for the specified
    *                                            resource class (incl. RESET-CREDENTIALS or IMPERSONATE for
    *                                            unauthenticatable resource classes), or
    *                                            if resourcePermissions contains multiple instances of the same
    *                                            permission that only differ in the 'withGrant' attribute
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not authorized to grant (or in this case
    *                                                  revoke) the specified permissions on the specified resource class and domain
    */
   void revokeGlobalResourcePermissions(Resource accessorResource,
                                        String resourceClassName,
                                        String domainName,
                                        ResourcePermission resourcePermission,
                                        ResourcePermission... resourcePermissions);

   /**
    * Gets the global resource permissions the specified accessor resource has directly to the resources of
    * the specified resource class in the specified domain.
    * <p/>
    * This method only takes into account direct global resource permissions, but not inherited
    * global resource permissions and not any global resource permissions the accessor may have to
    * ancestors of the specified domain.
    *
    * @param accessorResource  the resource relative to which the permissions should be returned
    * @param resourceClassName a string resource class name
    * @param domainName        a string domain name
    * @return a set of direct global resource permissions the accessor resource has to resources in the
    *         specified resource class and domain
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<ResourcePermission> getGlobalResourcePermissions(Resource accessorResource,
                                                        String resourceClassName,
                                                        String domainName);

   /**
    * Gets the effective global resource permissions the specified accessor resource has to the resources of
    * the specified resource class in the specified domain.
    * <p/>
    * This method takes into account direct global resource permissions, inherited
    * global resource permissions and any global resource permissions the accessor may have to
    * ancestors of the specified domain, as well as any super-user privileges.
    *
    * @param accessorResource  the resource relative to which the permissions should be returned
    * @param resourceClassName a string resource class name
    * @param domainName        a string domain name
    * @return a set of effective global resource permissions the accessor resource has to resources in the
    *         specified resource class and domain
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist, or
    *                                            if no resource class of resourceClassName exists, or
    *                                            if no domain of domainName exists
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Set<ResourcePermission> getEffectiveGlobalResourcePermissions(Resource accessorResource,
                                                                 String resourceClassName,
                                                                 String domainName);

   /**
    * Gets all global resource permissions the specified accessor resource has directly to any resources
    * of any resource class in any domain, mapped by domain name and resource class name.
    * <p/>
    * This method only takes into account direct global resource permissions, but not inherited
    * global resource permissions and not any global resource permissions the accessor may have to
    * ancestors of each domain.
    * <p/>
    * The result is returned as a map keyed by the domain name, where each value is another
    * map keyed by resource class name, in which each value is the set of global resource permissions
    * for the resource class and domain name of the respective keys.
    *
    * @param accessorResource the resource relative to which the permissions should be returned
    * @return a map of maps of all direct global resource permissions the accessor resource has, keyed
    *         by domain name and resource class name
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Map<String, Map<String, Set<ResourcePermission>>> getGlobalResourcePermissionsMap(Resource accessorResource);

   /**
    * Gets all effective global resource permissions the specified accessor resource has to the resources of
    * the any resource class in any domain, mapped by domain name and resource class name.
    * <p/>
    * This method takes into account direct global resource permissions, inherited
    * global resource permissions and any global resource permissions the accessor may have to
    * ancestors of each domain, as well as any super-user privileges.
    * <p/>
    * The result is returned as a map keyed by the domain name, where each value is another
    * map keyed by resource class name, in which each value is the set of global resource permissions
    * for the resource class and domain name of the respective keys.
    *
    * @param accessorResource the resource relative to which the permissions should be returned
    * @return a map of maps of all effective global resource permissions the accessor resource has, keyed
    *         by domain name and resource class name
    * @throws java.lang.IllegalArgumentException if accessorResource reference does not exist
    * @throws com.acciente.oacc.NotAuthorizedException if the session resource is not the accessor resource and
    *                                                  the session resource does not have query authorization on
    *                                                  the accessor resource (explicitly via QUERY or implicitly via
    *                                                  IMPERSONATE permissions)
    */
   Map<String, Map<String, Set<ResourcePermission>>> getEffectiveGlobalResourcePermissionsMap(Resource accessorResource);
}