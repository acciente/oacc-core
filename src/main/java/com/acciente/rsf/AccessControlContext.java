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
package com.acciente.rsf;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The interface with which to define and control access to RSF resources.
 * <p/>
 * An instance of this session is used to both define the RSF resources and the security privileges to them,
 * as well as to query the security system in order to implement access control to these resources.
 * <p/>
 * Definitions:
 * <dl>
 * <dt> "session"
 * <dd> An instance of this interface that has been {@link #authenticate authenticated},
 * that is, security credentials have been associated with this session
 * <dt> "authenticated resource"
 * <dd> The resource that authenticated this session,
 * that is, the resource that logged into this session with a password, using the <code>authenticate</code> method
 * <dt> "session resource"
 * <dd> The resource whose security credentials are associated with this session.
 * This is the same as the authenticated resource, unless another resource is being {@link #impersonate impersonated}.
 * </dl>
 * Unless a session is authenticated, all attempts to call any methods other than <code>authenticate</code> or
 * the special {@link #setResourcePassword(Resource, AuthenticationProvider, String)} will fail.
 *
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
    * @param password the password associated with the resource
    * @throws AccessControlException if an error occurs
    */
   public void authenticate(Resource resource, String password)
         throws AccessControlException;

   /**
    * Logs out of this session, to be specific, disassociates any security credentials from this session.
    *
    * @throws AccessControlException if no resource is currently authenticated, or if an error occurs
    */
   public void unauthenticate()
         throws AccessControlException;

   /**
    * Switches the security credentials of this session to those of the specified resource.
    * <p/>
    * The currently authenticated resource has to have IMPERSONATE permissions to the specified resource.
    * <p/>
    * Note that this method itself will use the credentials of the originally authenticated resource,
    * and not those of any currently impersonated resource.
    *
    * @param resource the resource to be impersonated
    * @throws AccessControlException if an error occurs
    */
   public void impersonate(Resource resource)
         throws AccessControlException;

   /**
    * Unimpersonates the currently impersonated resource.
    * <p/>
    * Restores the session to the credentials of the authenticated resource.
    * <p/>
    * If no resource is currently being impersonated, this call has no effect.
    *
    * @throws AccessControlException if an error occurs
    */
   public void unimpersonate()
         throws AccessControlException;

   /**
    * Sets the password of the currently authenticated resource
    * <p/>
    * Note that this method uses the credentials of the originally authenticated resource,
    * and not those of any currently impersonated resource.
    *
    * @param newPassword a new password for the currently authenticated resource
    * @throws AccessControlException if an error occurs
    */
   public void setAuthenticatedResourcePassword(String newPassword)
         throws AccessControlException;

   /**
    * Sets the password of the specified authenticatable resource (= a resource of a resource class
    * that has been defined with the <code>isAuthenticatable</code> flag set).
    * <p/>
    * One of the following has to be true for this method to succeed:
    * <ul>
    * <li> the specified resource has to either be the currently authenticated resource or
    * <li> the currently authenticated resource has to have SUPER-USER permission on the domain
    * that contains the specified resource or
    * <li> the currently authenticated resource has to have RESET-PASSWORD permission on the specified resource.
    * </ul>
    * Note that this method uses the credentials of the originally authenticated resource,
    * and not those of any currently impersonated resource.
    *
    * @param resource    the resource for which the password should be changed. The resource for which the password is
    *                    to be changed must be the current auth resource, or the current auth resource must have SUPER-USER permissions
    *                    to the domain containing the resource whose password is to be changed or must have RESET-PASSWORD
    *                    permissions to the resource whose password is to be changed, otherwise an exception is thrown.
    * @param newPassword the new password for the resource
    * @throws AccessControlException if an error occurs
    */
   public void setResourcePassword(Resource resource, String newPassword)
         throws AccessControlException;

   /**
    * Sets the password of the specified authenticatable resource (= a resource of a resource class
    * that has been defined with the <code>isAuthenticatable</code> flag set) by means of an <em>alternate
    * specified authentication provider to this session</em>.
    * <p/>
    * Note that this method requires this session to be <strong>unauthenticated</strong>.
    * <p/>
    * This method is provided to allow for certain use cases, like a "forgotten password" reset,
    * when a resource representing a "user" can not authenticate to this session.
    * The specified alternate authentication provider provides a callback via the
    * {@link AuthenticationProvider#isAuthenticated(Resource) isAuthenticated} method that allows this session
    * to temporarily authenticate, for purposes of resetting the specified resource's password.
    *
    * @param resource               the resource for which the password should be changed.
    * @param authenticationProvider a callback that allows RSF to hook into the alternate authentication mechanism
    *                               used to clear the password reset.
    * @param newPassword            the new password for the resource
    * @throws AccessControlException if an error occurs
    */
   public void setResourcePassword(Resource resource,
                                   AuthenticationProvider authenticationProvider,
                                   String newPassword)
         throws AccessControlException;

   /**
    * Checks if the current session resource has the specified global resource permission on
    * the specified resource class in the session resource's domain.
    * This method takes into account any global permissions that the session resource may have.
    *
    * @param resourceClassName  a string resource class name
    * @param resourcePermission the permission to be checked
    * @throws AccessControlException if the session resource <strong>does not</strong> have the
    *                                specified global permission, or if an error occurs
    */
   public void assertGlobalResourcePermission(String resourceClassName, ResourcePermission resourcePermission)
         throws AccessControlException;

   /**
    * Checks if the current session resource has the specified global resource permission on
    * the specified resource class in the specified domain.
    * This method takes into account any global permissions that the session resource may have.
    *
    * @param resourceClassName  a string resource class name
    * @param resourcePermission the permission to be checked
    * @param domainName         the domain in which the permission should be checked
    * @throws AccessControlException if the session resource <strong>does not</strong> have the
    *                                specified global permission, or if an error occurs
    */
   public void assertGlobalResourcePermission(String resourceClassName,
                                              ResourcePermission resourcePermission,
                                              String domainName)
         throws AccessControlException;

   /**
    * Checks if the current session resource has the specified resource permission to
    * the specified accessed resource.
    * This method takes into account direct, inherited and global permissions of the session resource.
    *
    * @param accessedResource   the resource on which access is being checked
    * @param resourcePermission the permission to be checked
    * @throws AccessControlException if the session resource <strong>does not</strong> have the
    *                                specified permission, or if an error occurs
    */
   public void assertResourcePermission(Resource accessedResource, ResourcePermission resourcePermission)
         throws AccessControlException;

   /**
    * Checks if the specified accessor resource has the specified resource permission
    * to the specified accessed resource.
    * This method takes into account direct, inherited and global permissions of accessor resource.
    *
    * @param accessorResource   the resource requesting the access
    * @param accessedResource   the resource on which access is being requested
    * @param resourcePermission the permission to be checked
    * @throws AccessControlException if the accessor resource <strong>does not</strong> have the
    *                                specified permission, or if an error occurs
    */
   public void assertResourcePermission(Resource accessorResource,
                                        Resource accessedResource,
                                        ResourcePermission resourcePermission)
         throws AccessControlException;

   /**
    * Checks if the current session resource would receive the specified permission on an object of
    * the specified class in the session resource's domain, if were to create such an object.
    * The method takes into account any resource create permissions and global resource permissions
    * of the session resource.
    *
    * @param resourceClassName  a string resource class name
    * @param resourcePermission the permission to be checked
    * @throws AccessControlException if the session resource would <strong>not</strong> receive the
    *                                specified permission after creating a resource of the specified class in the current session domain,
    *                                or if an error occurs
    */
   public void assertPostCreateResourcePermission(String resourceClassName, ResourcePermission resourcePermission)
         throws AccessControlException;

   /**
    * Checks if the current session resource would receive the specified permission on an object of
    * the specified class in the specified domain, if were to create such an object.
    * The method takes into account any resource create permissions and global resource permissions
    * of the session resource.
    *
    * @param resourceClassName  a string resource class name
    * @param resourcePermission the permission to be checked
    * @param domainName         the domain in which the permission should be checked
    * @throws AccessControlException if the session resource would <strong>not</strong> receive the
    *                                specified permission after creating a resource of the specified class in the specified domain,
    *                                or if an error occurs
    */
   public void assertPostCreateResourcePermission(String resourceClassName,
                                                  ResourcePermission resourcePermission,
                                                  String domainName)
         throws AccessControlException;

   /**
    * Returns the domain to which the specified resource belongs.
    *
    * @param resource the resource for which to retrieve the domain name
    * @return a string domain name
    * @throws AccessControlException if an error occurs
    */
   public String getDomainNameByResource(Resource resource)
         throws AccessControlException;

   /**
    * Returns the domains which are descendants of the specified domain.
    * The returned set includes the specified domain; in other words, a domain
    * is considered its own descendant
    *
    * @param domainName a domain name for which to retrieve the descendants
    * @return a set of unique string domain names, including the domain queried about
    * @throws AccessControlException if an error occurs
    */
   public Set<String> getDomainDescendants(String domainName)
         throws AccessControlException;

   /**
    * Returns information about the specified resource class.
    *
    * @param resourceClassName a string resource class name about which to retrieve information
    * @return a ResourceClassInfo object containing information about the resource class
    * @throws AccessControlException if an error occurs
    */
   public ResourceClassInfo getResourceClassInfo(String resourceClassName)
         throws AccessControlException;

   /**
    * Returns information about the resource class to which the specified resource belongs.
    *
    * @param resource a resource about whose resource class to retrieve information
    * @return returns a ResourceClassInfo object containing information about the resource class of the specified resource
    * @throws AccessControlException if an error occurs
    */
   public ResourceClassInfo getResourceClassInfoByResource(Resource resource)
         throws AccessControlException;

   /**
    * Returns a set of resources (of the specified resource class) on which
    * the current session resource has the specified permission.
    * <p/>
    * The method takes into account direct, inherited and global permissions, as well as
    * resources that are reachable as a result of SUPER-USER permissions.
    *
    * @param resourceClassName  a string resource class name
    * @param resourcePermission the permission to check
    * @return a set of resources
    * @throws AccessControlException if an error occurs
    */
   public Set<Resource> getResourcesByResourcePermission(String resourceClassName,
                                                         ResourcePermission resourcePermission)
         throws AccessControlException;

   /**
    * Returns a set of resources (of the specified resource class) on which
    * the specified accessor resource has the specified permission, regardless of domain.
    * <p/>
    * The method takes into account direct, inherited and global permissions, as well as
    * resources that are reachable as a result of SUPER-USER permissions.
    *
    * @param accessorResource   the resource relative to which the set of accessible resources is computed
    * @param resourceClassName  a string resource class name
    * @param resourcePermission the permission to check
    * @return a set of resources
    * @throws AccessControlException if an error occurs
    */
   public Set<Resource> getResourcesByResourcePermission(Resource accessorResource,
                                                         String resourceClassName,
                                                         ResourcePermission resourcePermission)
         throws AccessControlException;

   /**
    * Returns a set of resources (of the specified resource class) on which
    * the current session resource has the specified permission, within the specified domain
    * or within any descendant domains.
    * <p/>
    * The method takes into account direct, inherited and global permissions, as well as
    * resources that are reachable as a result of SUPER-USER permissions.
    *
    * @param resourceClassName  a string resource class name
    * @param resourcePermission the permission to check
    * @param domainName         a domain name
    * @return a set of resources
    * @throws AccessControlException if an error occurs
    */
   public Set<Resource> getResourcesByResourcePermission(String resourceClassName,
                                                         ResourcePermission resourcePermission,
                                                         String domainName)
         throws AccessControlException;

   /**
    * Returns a set of resources (of the specified resource class) on which
    * the specified accessor resource has the specified permission, within the
    * specified domain or within any descendant domains.
    * <p/>
    * The method takes into account direct, inherited and global permissions, as well as
    * resources that are reachable as a result of SUPER-USER permissions.
    *
    * @param accessorResource   the resource relative to which the set of accessible resources is computed
    * @param resourceClassName  a string resource class name
    * @param resourcePermission the permission to check
    * @param domainName         a domain name
    * @return a set of resources
    * @throws AccessControlException if an error occurs
    */
   public Set<Resource> getResourcesByResourcePermission(Resource accessorResource,
                                                         String resourceClassName,
                                                         ResourcePermission resourcePermission,
                                                         String domainName)
         throws AccessControlException;

   /**
    * Returns a set of resources that have the specified permission to the specified accessed resource.
    * <p/>
    * This method works in the reverse direction of the {@link #getResourcesByResourcePermission} method, but
    * unlike <code>getResourcesByResourcePermission</code> it only takes into account direct permissions.
    * In other words, this method ignores accessors that can reach the specified accessed resource
    * via inherited permissions, global permissions and SUPER-USER privileges.
    *
    * @param accessedResource   the resource relative to which accessor resources are sought
    * @param resourceClassName  a string resource class name
    * @param resourcePermission the permission to check
    * @return a set of resources
    * @throws AccessControlException if an error occurs
    */
   public Set<Resource> getAccessorResourcesByResourcePermission(Resource accessedResource,
                                                                 String resourceClassName,
                                                                 ResourcePermission resourcePermission)
         throws AccessControlException;

   /**
    * Returns the resource that is currently authenticated in this session.
    *
    * @return a resource
    * @throws AccessControlException if no resource is authenticated
    */
   public Resource getAuthenticatedResource()
         throws AccessControlException;

   /**
    * Returns the session resource, that is, the resource whose security credentials are
    * associated with this session.
    * <p/>
    * The session resource is the same as the authenticated resource, unless another resource
    * is being {@link #impersonate impersonated}.
    *
    * @return a resource
    * @throws AccessControlException if no resource is authenticated
    */
   public Resource getSessionResource()
         throws AccessControlException;

   /**
    * Creates a new resource class.
    * <p/>
    * Note that creating a resource is only allowed when this session is authenticated with
    * the system-resource (resourceId=0)
    *
    * @param resourceClassName           a string resource class name
    * @param authenticatable             indicates if resources of this resource class are authenticatable.
    *                                    Typically only resource classes that represent users will be marked as authenticatable.
    * @param unuthenticatedCreateAllowed if true, a resource of this resource class may be created from an
    *                                    unauthenticated session, otherwise the session must be authenticated
    *                                    to create resources of this class.
    * @throws AccessControlException if an error occurs
    */
   public void createResourceClass(String resourceClassName,
                                   boolean authenticatable,
                                   boolean unuthenticatedCreateAllowed)
         throws AccessControlException;

   /**
    * Creates a new resource permission that may be applied to objects of the specified resource class.
    * <p/>
    * Note that creating a resource permission is only allowed when this session is authenticated with
    * the system-resource (resourceId=0)
    *
    * @param resourceClassName a string resource class name
    * @param permissionName    the string representing the name of this permission.
    *                          Samples of typical permission names:
    *                          CREATE, READ, WRITE, UPDATE, VIEW, POST, EDIT, etc.
    * @throws AccessControlException if an error occurs
    */
   public void createResourcePermission(String resourceClassName, String permissionName)
         throws AccessControlException;

   /**
    * Creates a new domain (at the root level of the domain hierarchy).
    *
    * @param domainName a string domain name
    * @throws AccessControlException if an error occurs
    */
   public void createDomain(String domainName)
         throws AccessControlException;

   /**
    * Creates a new domain under the specified parent domain.
    *
    * @param domainName       a string domain name
    * @param parentDomainName the domain name of the parent domain
    * @throws AccessControlException if an error occurs
    */
   public void createDomain(String domainName, String parentDomainName)
         throws AccessControlException;

   /**
    * Creates a new resource class in the same domain as this session resource.
    *
    * @param resourceClassName a string resource class name
    * @return the integer resourceId of the newly created resource
    * @throws AccessControlException if an error occurs
    */
   public Resource createResource(String resourceClassName)
         throws AccessControlException;

   /**
    * Creates a new resource class within the specified domain.
    * <p/>
    * Note that the session resource must be member of the specified domain or
    * have SUPER-USER privileges to the specified domain.
    *
    * @param resourceClassName a string resource class name
    * @param domainName        a string domain name
    * @return the integer resourceId of the newly created resource
    * @throws AccessControlException if an error occurs
    */
   public Resource createResource(String resourceClassName, String domainName)
         throws AccessControlException;

   /**
    * Creates a new authenticatable resource in the same domain as the session resource.
    *
    * @param resourceClassName a string resource class name
    * @param password          a string password with at least 6 characters and no leading or trailing spaces
    * @return the integer resourceId of the newly created resource
    * @throws AccessControlException if an error occurs
    */
   public Resource createAuthenticatableResource(String resourceClassName, String password)
         throws AccessControlException;

   /**
    * Creates a new authenticatable resource within the specified domain.
    * <p/>
    * Note that the session resource must be member of the specified domain or
    * have SUPER-USER privileges to the specified domain.
    *
    * @param resourceClassName a string resource class name
    * @param domainName        a string domain name
    * @param password          a string password with at least 6 characters and no leading or trailing spaces
    * @return the integer resourceId of the newly created resource
    * @throws AccessControlException if an error occurs
    */
   public Resource createAuthenticatableResource(String resourceClassName, String domainName, String password)
         throws AccessControlException;

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
    * @throws AccessControlException if an error occurs
    */
   public void setDomainCreatePermissions(Resource accessorResource,
                                          Set<DomainCreatePermission> domainCreatePermissions)
         throws AccessControlException;

   /**
    * Gets all effective domain create permissions the specified accessor resource has, both directly
    * and inherited (from other resources).
    *
    * @param accessorResource the accessor resource relative which permissions should be returned
    * @return a set of effective domain create permission the accessor resource has
    * @throws AccessControlException if an error occurs
    */
   public Set<DomainCreatePermission> getEffectiveDomainCreatePermissions(Resource accessorResource)
         throws AccessControlException;

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
    * @throws AccessControlException if an error occurs
    */
   public void setDomainPermissions(Resource accessorResource,
                                    String domainName,
                                    Set<DomainPermission> domainPermissions)
         throws AccessControlException;

   /**
    * Gets all effective domain permissions the accessor resource has to the specified domain.
    * <p/>
    * This method takes into account direct domain permissions, inherited domain permissions
    * and any domain permissions the accessor may have to ancestors of the specified domain.
    * In other words, this method will return the domain permissions the specified accessor
    * resource has to the specified domain as a result of the permissions the accessor has on
    * any ancestor (parent, or grandparent, etc.) of that domain.
    *
    * @param accessorResource the accessor resource relative which permissions should be returned
    * @param domainName       a string domain name
    * @return the set of all effective domain permission the accessor resource has to the domain
    * @throws AccessControlException if an error occurs
    */
   public Set<DomainPermission> getEffectiveDomainPermissions(Resource accessorResource,
                                                              String domainName)
         throws AccessControlException;

   /**
    * Gets all effective domain permissions the accessor resource has to any domain, mapped by domain name.
    * <p/>
    * This method takes into account direct domain permissions, inherited domain permissions
    * and any domain permissions the accessor may have to ancestors of each domain.
    * The result is returned as a map keyed by the domain name, where each value is the
    * set of permissions for the domain name of the key.
    *
    * @param accessorResource the accessor resource relative which permissions should be returned
    * @return the sets of effective domain permission the accessor resource has to any domain, mapped by domain name
    * @throws AccessControlException if an error occurs
    */
   public Map<String, Set<DomainPermission>> getEffectiveDomainPermissionsMap(Resource accessorResource)
         throws AccessControlException;

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
    * @param resourceCreatePermissions a set of resource create permissions to be granted
    * @param domainName                a string representing a valid domain name
    * @throws AccessControlException if an error occurs
    */
   public void setResourceCreatePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourceCreatePermission> resourceCreatePermissions,
                                            String domainName)
         throws AccessControlException;

   /**
    * Gets all effective resource create permissions the accessor resource has to the specified
    * resource class in the specified domain (which effectively define the resource permissions
    * the accessor resource will receive directly, if it created a resource of the specified
    * resource class in the specified domain).
    * <p/>
    * This method takes into account direct resource create permissions, inherited
    * resource create permissions and any resource create permissions the accessor may have to
    * ancestors of the specified domain.
    *
    * @param accessorResource  the accessor resource relative which permissions should be returned
    * @param resourceClassName a string resource class name
    * @param domainName        a string representing a valid domain name
    * @return a set of effective resource create permissions
    * @throws AccessControlException if an error occurs
    */
   public Set<ResourceCreatePermission> getEffectiveResourceCreatePermissions(Resource accessorResource,
                                                                              String resourceClassName,
                                                                              String domainName)
         throws AccessControlException;

   /**
    * Sets the resource permissions the specified accessor resource will receive directly, if it
    * created a resource of the specified resource class in the current session resource's domain.
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
    * receives via <em>inheritance</em> or from any <em>ancestor</em> of the current session resource's domain.
    *
    * @param accessorResource          the resource to which the privilege should be granted
    * @param resourceClassName         a string resource class name
    * @param resourceCreatePermissions a set of resource create permissions to be granted
    * @throws AccessControlException if an error occurs
    */
   public void setResourceCreatePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourceCreatePermission> resourceCreatePermissions)
         throws AccessControlException;

   /**
    * Gets all effective resource create permissions the accessor resource has to the specified
    * resource class in the the current session resource's domain (which effectively define
    * the resource permissions the accessor resource will receive directly, if it created
    * a resource of the specified resource class in the current session resource's domain).
    * <p/>
    * This method takes into account direct resource create permissions, inherited
    * resource create permissions and any resource create permissions the accessor may have to
    * ancestors of the current session resource's domain.
    *
    * @param accessorResource  the accessor resource relative which permissions should be returned
    * @param resourceClassName a string resource class name
    * @return a set of effective resource create permissions
    * @throws AccessControlException if an error occurs
    */
   public Set<ResourceCreatePermission> getEffectiveResourceCreatePermissions(Resource accessorResource,
                                                                              String resourceClassName)
         throws AccessControlException;

   /**
    * Gets all effective resource create permissions the accessor resource has to any resource class in
    * any domain, mapped by domain name and resource class name.
    * <p/>
    * Resource create permissions effectively define the resource permissions the accessor resource
    * will receive directly, if it created a resource of a resource class in a domain.
    * <p/>
    * This method takes into account direct resource create permissions, inherited
    * resource create permissions and any resource create permissions the accessor may have to
    * ancestors of each domain.
    * <p/>
    * The result is returned as a map keyed by the domain name, where each value is another
    * map keyed by resource class name, in which each value is the set of resource create permissions
    * for the resource class and domain name of the respective keys.
    *
    * @param accessorResource the accessor resource relative which permissions should be returned
    * @return a map of maps of effective resource create permissions, keyed by domain name and resource class name
    * @throws AccessControlException if an error occurs
    */
   public Map<String, Map<String, Set<ResourceCreatePermission>>> getEffectiveResourceCreatePermissionsMap(Resource accessorResource)
         throws AccessControlException;

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
    * @throws AccessControlException if an error occurs
    */
   public void setResourcePermissions(Resource accessorResource,
                                      Resource accessedResource,
                                      Set<ResourcePermission> resourcePermissions)
         throws AccessControlException;

   /**
    * Gets the effective resource permissions that the specified accessor resource has to the
    * specified accessed resource both directly and inherited, but does not take into
    * account any global resource permissions.
    *
    * @param accessorResource the resource relative to which the permissions should be returned
    * @param accessedResource the resource on which the privilege is granted
    * @return a set of effective resource permissions
    * @throws AccessControlException if an error occurs
    */
   public Set<ResourcePermission> getEffectiveResourcePermissions(Resource accessorResource,
                                                                  Resource accessedResource)
         throws AccessControlException;

   /**
    * Sets the global resource permissions a resource has on any resource of the specified
    * resource class in the specified domain.
    * <p/>
    * Global resource permissions are resource permissions that are defined on a resource class for
    * a given resource domain and thus apply to any and all resources of that resource class and domain.
    * They are <strong>not</strong> associated directly with <em>every</em> individual resource of
    * that resource class and domain!
    * <p/>
    * Note that the system-defined CREATE resource permission may <strong>NOT</strong>
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
    * @param resourcePermissions the set of resource permissions to be granted globally to
    *                            the specified resource class and domain
    * @param domainName          a string domain name
    * @throws AccessControlException if an error occurs
    */
   public void setGlobalResourcePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourcePermission> resourcePermissions,
                                            String domainName)
         throws AccessControlException;

   /**
    * Gets the effective global resource permissions the specified accessor resource has to the resources of
    * the specified resource class in the specified domain.
    * <p/>
    * This method takes into account direct global resource permissions, inherited
    * global resource permissions and any global resource permissions the accessor may have to
    * ancestors of the specified domain.
    *
    * @param accessorResource  the resource relative to which the permissions should be returned
    * @param resourceClassName a string resource class name
    * @param domainName        a string domain name
    * @return a set of effective global resource permissions the accessor resource has to resources in the
    *         specified resource class and domain
    * @throws AccessControlException if an error occurs
    */
   public Set<ResourcePermission> getEffectiveGlobalResourcePermissions(Resource accessorResource,
                                                                        String resourceClassName,
                                                                        String domainName)
         throws AccessControlException;

   /**
    * Sets the global resource permissions a resource has on any resource of the specified
    * resource class in the current session resource's domain.
    * <p/>
    * Global resource permissions are resource permissions that are defined on a resource class for
    * a given resource domain and thus apply to any and all resources of that resource class and domain.
    * They are <strong>not</strong> associated directly with <em>every</em> individual resource of
    * that resource class and domain!
    * <p/>
    * Note that the system-defined CREATE resource permission may <strong>NOT</strong>
    * be set as a global resource permission, because it would be nonsensical.
    * Currently the system-defined INHERIT resource permission may also <strong>not</strong> be
    * set as a global resource permission.
    * <p/>
    * This method replaces any <em>direct</em> global resource permissions previously granted, but
    * does not affect any global resource permissions the specified accessor resource receives via
    * <em>inheritance</em> or from any <em>ancestors</em> of the current session resource's domain.
    *
    * @param accessorResource    the resource to which the privilege should be granted
    * @param resourceClassName   a string resource class name
    * @param resourcePermissions the set of resource permissions to be granted globally to the
    *                            specified resource class and session resource's domain
    * @throws AccessControlException if an error occurs
    */
   public void setGlobalResourcePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourcePermission> resourcePermissions)
         throws AccessControlException;

   /**
    * Gets the effective global resource permissions the specified accessor resource has to the resources of
    * the specified resource class in the current session resource's domain.
    * <p/>
    * This method takes into account direct global resource permissions, inherited
    * global resource permissions and any global resource permissions the accessor may have to
    * ancestors of the current session resource's domain.
    *
    * @param accessorResource  the resource relative to which the permissions should be returned
    * @param resourceClassName a string resource class name
    * @return the set of effective global resource permissions the accessor resource has to resources of
    *         the specified resource class in the current session resource's domain
    * @throws AccessControlException if an error occurs
    */
   public Set<ResourcePermission> getEffectiveGlobalResourcePermissions(Resource accessorResource,
                                                                        String resourceClassName)
         throws AccessControlException;

   /**
    * Gets all effective global resource permissions the specified accessor resource has to the resources of
    * the any resource class in any domain, mapped by domain name and resource class name.
    * <p/>
    * This method takes into account direct global resource permissions, inherited
    * global resource permissions and any global resource permissions the accessor may have to
    * ancestors of each domain.
    * <p/>
    * The result is returned as a map keyed by the domain name, where each value is another
    * map keyed by resource class name, in which each value is the set of global resource permissions
    * for the resource class and domain name of the respective keys.
    *
    * @param accessorResource the resource relative to which the permissions should be returned
    * @return a map of maps of all effective global resource permissions the accessor resource has, keyed
    *         by domain name and resource class name
    * @throws AccessControlException if an error occurs
    */
   public Map<String, Map<String, Set<ResourcePermission>>> getEffectiveGlobalResourcePermissionsMap(Resource accessorResource)
         throws AccessControlException;

   /**
    * Returns the list of names of all resource classes defined in the system
    *
    * @return a list of string resource class names
    * @throws AccessControlException if an error occurs
    */
   public List<String> getResourceClassNames() throws AccessControlException;

   /**
    * Returns the list of all resource permission names defined for the specified resource class name
    *
    * @param resourceClassName the resource class name for which the permissions should be retrieved
    * @return a list of string permission names
    * @throws AccessControlException if an error occurs
    */
   public List<String> getResourcePermissionNames(String resourceClassName) throws AccessControlException;
}
