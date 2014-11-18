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

/**
 * Provides the mechanism to authenticate a resource based on specified credentials and to update those credentials.
 * <p/>
 * An application can provide an implementation of this interface to provide a custom authentication
 * mechanism for resources. Such a custom authentication provider is free to use password, biometric or
 * any other means for authentication.
 */
public interface AuthenticationProvider {
   /**
    * Authenticates the specified resource using the supplied credentials.
    *
    * @param resource the resource to be authenticated
    * @param credentials the credentials to authenticate the resource
    * @throws AccessControlException if authentication failed or an error occurs
    */
   void authenticate(Resource resource, Credentials credentials) throws AccessControlException;

   /**
    * Verifies that the specified resource is authenticated.
    * <p/>
    * The authentication provider implementation should throw an AccessControlException if the
    * specified resource is currently NOT authenticated, or should throw an UnsupportedOperationException
    * if it does not support reporting of the authentication status without credentials.
    *
    * @param resource the resource to be authenticated
    * @throws AccessControlException if the resource is not authenticated or if an error occurs
    */
   void authenticate(Resource resource) throws AccessControlException;

   /**
    * Checks if the the authentication credentials are valid, for example this method may check if the credentials
    * satisfy the minimum strength requirements.
    *
    * @param credentials the authentication credentials to validate
    * @throws AccessControlException if the credentials are invalid.
    */
   void validateCredentials(Credentials credentials) throws AccessControlException;

   /**
    * Sets (or resets) the authentication credentials of the specified resource.
    *
    * @param resource the resource for which the credentials should be set
    * @param credentials the new authentication credentials for the resource
    * @throws AccessControlException if an error occurs.
    */
   void setCredentials(Resource resource, Credentials credentials) throws AccessControlException;
}
